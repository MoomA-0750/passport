#!/usr/bin/env node
'use strict';
// data/ のバックアップを取る。
//
//   node bin/backup.js [出力先ディレクトリ]
//
// 稼働中に取ってよい。Passport の書き込みはファイル単位で原子的（一時ファイル + rename）なので、
// 途中まで書かれた JSON を掴むことはない。書きかけの一時ファイル（*.tmp-*）は含めない。
//
// **マスターキーは含めない。** 含めると、バックアップが流出したときに暗号化の意味が無くなる。
// マスターキーは別の媒体へ、別の手順でバックアップすること（readme.md「バックアップと復旧」）。
//
// Node の標準ライブラリには tar が無いので、RHEL に入っている tar コマンドを呼ぶ。

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const config = require('../lib/config');

const dataDir = config.storage.dataDir;
const outDir = path.resolve(process.argv[2] || path.join(config.root, 'backups'));

if (!fs.existsSync(dataDir)) {
  console.error(`データディレクトリがありません: ${dataDir}`);
  process.exit(1);
}

// どの鍵の世代のデータかを、バックアップと一緒に記録しておく。
// 戻すときに、同じ世代のマスターキーと組み合わせているかを確かめるため。
const keycheckPath = path.join(dataDir, 'keycheck.json');
const keyFingerprint = fs.existsSync(keycheckPath)
  ? (JSON.parse(fs.readFileSync(keycheckPath, 'utf8')).fingerprint || null)
  : null;

function countJson(dir) {
  if (!fs.existsSync(dir)) return 0;
  return fs.readdirSync(dir).filter((n) => n.endsWith('.json') && !n.includes('.tmp-')).length;
}

const vaultsDir = path.join(dataDir, 'vaults');
const vaultIds = fs.existsSync(vaultsDir)
  ? fs.readdirSync(vaultsDir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name)
  : [];
const counts = {
  users: countJson(path.join(dataDir, 'users')),
  vaults: vaultIds.length,
  items: vaultIds.reduce((sum, id) => sum + countJson(path.join(vaultsDir, id, 'items')), 0),
  trashed: vaultIds.reduce((sum, id) => sum + countJson(path.join(vaultsDir, id, 'trash')), 0),
  groups: countJson(path.join(dataDir, 'groups')),
  tokens: countJson(path.join(dataDir, 'tokens'))
};

fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+$/, '').replace('T', '-');
const archive = path.join(outDir, `passport-data-${stamp}.tar.gz`);

try {
  execFileSync('tar', [
    '--create', '--gzip',
    '--file', archive,
    '--exclude', '*.tmp-*',
    '--directory', path.dirname(dataDir),
    path.basename(dataDir)
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
} catch (err) {
  console.error(`tar の実行に失敗しました: ${err.stderr ? err.stderr.toString() : err.message}`);
  console.error('RHEL なら dnf install tar で入ります。');
  process.exit(1);
}
fs.chmodSync(archive, 0o600);

const sha256 = crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex');
const manifest = {
  createdAt: new Date().toISOString(),
  archive: path.basename(archive),
  sha256,
  keyFingerprint,
  counts,
  note: 'マスターキーは含まれていません。同じ鍵の指紋のマスターキーと組み合わせて戻してください。'
};
fs.writeFileSync(`${archive}.json`, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });

console.log(`バックアップを作りました: ${archive}`);
console.log(`  ユーザー ${counts.users} / Vault ${counts.vaults} / アイテム ${counts.items} / ゴミ箱 ${counts.trashed} / グループ ${counts.groups} / 自動化トークン ${counts.tokens}`);
console.log(`  鍵の指紋: ${keyFingerprint || '(まだ記録されていません。一度サーバーを起動してください)'}`);
console.log(`  SHA-256:  ${sha256}`);
console.log('');
console.log('マスターキーは含まれていません。');
console.log(`この指紋（${keyFingerprint || '?'}）のマスターキーを、別の媒体に保管していることを確かめてください。`);
console.log('戻す前には `node bin/verify-backup.js <バックアップ> --key <マスターキー>` で組み合わせを確かめてください。');
