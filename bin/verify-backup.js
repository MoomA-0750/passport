#!/usr/bin/env node
'use strict';
// バックアップを、戻す前に確かめる。本番のデータには一切触らない。
//
//   node bin/verify-backup.js <passport-data-*.tar.gz> --key <マスターキーのファイル>
//
// 一時ディレクトリに展開し、そのマスターキーで実際に開けるかを確かめる:
//   ・鍵の指紋が、データを作ったときのものと一致するか
//   ・すべての Vault の鍵を開けられるか
//   ・アイテムの JSON が壊れていないか
//
// 「マスターキーとデータの世代を取り違えて戻し、ログインできないのでデータが壊れたと誤診して
// 作り直す」という、取り返しのつかない流れを、戻す前に止めるための道具。

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const args = process.argv.slice(2);
const archive = args.find((a) => !a.startsWith('--'));
const keyIndex = args.indexOf('--key');
const keyFile = keyIndex >= 0 ? args[keyIndex + 1] : null;
const passphraseMode = args.includes('--passphrase-from-env');

if (!archive || (!keyFile && !passphraseMode)) {
  console.error('使い方: node bin/verify-backup.js <バックアップ.tar.gz> --key <マスターキーのファイル>');
  console.error('   パスフレーズ運用なら: PASSPORT_MASTER_PASSPHRASE=... node bin/verify-backup.js <バックアップ> --passphrase-from-env');
  process.exit(2);
}
if (!fs.existsSync(archive)) {
  console.error(`バックアップがありません: ${archive}`);
  process.exit(2);
}

// 記録しておいたハッシュと一致するか（運んでいる間に壊れていないか）
const manifestPath = `${archive}.json`;
if (fs.existsSync(manifestPath)) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const actual = crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex');
  if (manifest.sha256 && manifest.sha256 !== actual) {
    console.error('✗ バックアップのファイルが、作ったときと違います（壊れているか、差し替えられています）');
    console.error(`  記録: ${manifest.sha256}`);
    console.error(`  実際: ${actual}`);
    process.exit(1);
  }
  console.log('✓ ファイルのハッシュが、作ったときの記録と一致');
}

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-verify-'));
try {
  execFileSync('tar', ['--extract', '--gzip', '--file', archive, '--directory', work], { stdio: 'pipe' });
  const extracted = fs.readdirSync(work).map((n) => path.join(work, n)).find((p) => fs.statSync(p).isDirectory());
  if (!extracted) throw new Error('展開したが、データのディレクトリが見つからない');

  // マスターキーのファイルモードの検査は、確かめる用途では緩める（コピーして 0400 にする）
  let keyCopy = null;
  if (keyFile) {
    keyCopy = path.join(work, 'master.key');
    fs.copyFileSync(keyFile, keyCopy);
    fs.chmodSync(keyCopy, 0o400);
  }

  // 本番と同じ仕組みで開けるかを、別のプロセスで確かめる（設定は環境変数で差し替える）
  const env = { ...process.env, PASSPORT_DATA_DIR: extracted };
  if (keyCopy) {
    env.PASSPORT_MASTER_KEY_FILE = keyCopy;
    delete env.PASSPORT_MASTER_PASSPHRASE;
  }
  const probe = `
    const store = require(${JSON.stringify(path.resolve(__dirname, '../lib/store'))});
    const keyring = require(${JSON.stringify(path.resolve(__dirname, '../lib/keyring'))});
    const integrity = require(${JSON.stringify(path.resolve(__dirname, '../lib/integrity'))});
    const vaults = require(${JSON.stringify(path.resolve(__dirname, '../lib/vaults'))});
    const result = { vaults: 0, vaultsOpened: 0, items: 0, brokenItems: 0, groups: 0, tokens: 0, brokenOther: [], missingGroups: [] };
    try {
      store.init();
      keyring.unlock();
      keyring.selfTest();
      integrity.checkOnStartup();
      for (const vault of vaults.list()) {
        result.vaults += 1;
        try { vaults.unwrapKey(vault).fill(0); result.vaultsOpened += 1; } catch {}
        const dir = store.resolveInData('vaults/' + vault.id + '/items');
        const fs = require('fs');
        if (fs.existsSync(dir)) {
          for (const name of fs.readdirSync(dir).filter((n) => n.endsWith('.json'))) {
            result.items += 1;
            try { JSON.parse(fs.readFileSync(dir + '/' + name, 'utf8')); } catch { result.brokenItems += 1; }
          }
        }
      }
      // グループと自動化トークンも、JSON として読めるかを確かめる（壊れていると、グループ経由の人が黙って入れなくなり、
      // cron が 401 になる）。Vault が参照しているグループが無いことも知らせる
      const fs2 = require('fs');
      const groupIds = new Set();
      for (const kind of ['groups', 'tokens']) {
        const dir = store.resolveInData(kind);
        if (!fs2.existsSync(dir)) continue;
        for (const name of fs2.readdirSync(dir).filter((n) => n.endsWith('.json') && !n.includes('.tmp-'))) {
          result[kind] += 1;
          try {
            const record = JSON.parse(fs2.readFileSync(dir + '/' + name, 'utf8'));
            if (kind === 'groups') groupIds.add(record.id);
          } catch { result.brokenOther.push(kind + '/' + name); }
        }
      }
      for (const vault of vaults.list()) {
        for (const g of (vault.groups || [])) if (!groupIds.has(g.groupId)) result.missingGroups.push(vault.name + ' → ' + g.groupId);
      }
      console.log(JSON.stringify({ ok: true, ...result }));
    } catch (err) {
      console.log(JSON.stringify({ ok: false, error: err.message }));
    }
  `;
  const run = spawnSync(process.execPath, ['-e', probe], { env, encoding: 'utf8' });
  const line = (run.stdout || '').trim().split('\n').filter((l) => l.startsWith('{')).pop();
  const result = line ? JSON.parse(line) : { ok: false, error: run.stderr || '確かめられませんでした' };

  if (!result.ok) {
    console.error('✗ このマスターキーでは、このバックアップを開けません');
    console.error(`  ${String(result.error).split('\n').join('\n  ')}`);
    console.error('');
    console.error('  このまま戻さないでください。別の世代のマスターキーを探してください。');
    process.exit(1);
  }

  console.log(`✓ マスターキーの世代が一致`);
  console.log(`✓ Vault ${result.vaultsOpened} / ${result.vaults} 個の鍵を開けられた`);
  console.log(`✓ アイテム ${result.items} 件（壊れた JSON ${result.brokenItems} 件）`);
  console.log(`✓ グループ ${result.groups} 件 / 自動化トークン ${result.tokens} 件`);
  for (const broken of result.brokenOther) console.error(`✗ 壊れた JSON: ${broken}`);
  for (const missing of result.missingGroups) console.error(`✗ Vault が参照しているグループがありません: ${missing}`);

  if (result.vaultsOpened !== result.vaults || result.brokenItems > 0 || result.brokenOther.length > 0 || result.missingGroups.length > 0) {
    console.error('');
    console.error('✗ 一部を開けませんでした。戻す前に原因を確かめてください');
    process.exit(1);
  }
  console.log('');
  console.log('このバックアップは、このマスターキーと組み合わせて戻せます。');
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}
