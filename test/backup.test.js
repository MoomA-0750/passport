'use strict';
// バックアップを取り、戻す前に確かめる道具のテスト。
// 「マスターキーの世代を取り違えて戻す」を、戻す前に止められるかを見る。

const test = require('node:test');
const assert = require('node:assert');
const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const REPO = path.resolve(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-backup-test-'));
const DATA = path.join(TMP, 'data');
const KEY = path.join(TMP, 'keys', 'master.key');
const OUT = path.join(TMP, 'backups');

let hasTar = true;
try {
  execFileSync('tar', ['--version'], { stdio: 'ignore' });
} catch {
  hasTar = false;
}

const env = { ...process.env, PASSPORT_DATA_DIR: DATA, PASSPORT_MASTER_KEY_FILE: KEY };
delete env.PASSPORT_MASTER_PASSPHRASE;

test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

let archive;

test('準備: データを作る', { skip: !hasTar }, () => {
  execFileSync('node', ['bin/init-master-key.js'], { cwd: REPO, env, stdio: 'ignore' });
  const script = `
    const store = require('./lib/store'); const keyring = require('./lib/keyring');
    const integrity = require('./lib/integrity'); const users = require('./lib/users');
    const vaults = require('./lib/vaults'); const items = require('./lib/items');
    store.init(); keyring.unlock(); integrity.checkOnStartup();
    const u = users.create({ username: 'owner', password: 'a-long-enough-pass', role: 'admin' });
    const v = vaults.create({ name: '本番', ownerId: u.id, actor: u.id });
    items.create(v.id, { title: 'DB', secrets: { password: 'backup-me' } }, { actor: u.id });
    const gone = items.create(v.id, { title: '消した', secrets: { password: 'in-trash' } }, { actor: u.id });
    items.remove(v.id, gone.id, { actor: u.id });
  `;
  execFileSync('node', ['-e', script], { cwd: REPO, env, stdio: 'ignore' });
  // 書きかけの一時ファイルを置いておく（バックアップに含めないことを見る）
  fs.writeFileSync(path.join(DATA, 'users', 'leftover.json.tmp-1-2'), 'half written');
});

test('バックアップ: 取れて、件数と鍵の指紋が記録される', { skip: !hasTar }, () => {
  const out = execFileSync('node', ['bin/backup.js', OUT], { cwd: REPO, env, encoding: 'utf8' });
  assert.match(out, /ユーザー 1 \/ Vault 1 \/ アイテム 1 \/ ゴミ箱 1/);
  archive = fs.readdirSync(OUT).filter((n) => n.endsWith('.tar.gz')).map((n) => path.join(OUT, n))[0];
  assert.ok(archive);
  assert.strictEqual(fs.statSync(archive).mode & 0o777, 0o600);

  const manifest = JSON.parse(fs.readFileSync(`${archive}.json`, 'utf8'));
  assert.ok(manifest.keyFingerprint);
  assert.strictEqual(manifest.sha256, crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex'));
});

test('バックアップ: マスターキーと書きかけの一時ファイルは含まない', { skip: !hasTar }, () => {
  const listing = execFileSync('tar', ['--list', '--gzip', '--file', archive], { encoding: 'utf8' });
  assert.ok(!/master\.key/.test(listing), 'マスターキーが含まれている');
  assert.ok(!/\.tmp-/.test(listing), '書きかけの一時ファイルが含まれている');
  assert.ok(/keycheck\.json/.test(listing));
  assert.ok(/trash\//.test(listing), 'ゴミ箱が含まれていない');
});

test('確かめる: 同じ世代のマスターキーなら「戻せる」と言う', { skip: !hasTar }, () => {
  const run = spawnSync('node', ['bin/verify-backup.js', archive, '--key', KEY], { cwd: REPO, encoding: 'utf8' });
  assert.strictEqual(run.status, 0, run.stdout + run.stderr);
  assert.match(run.stdout, /マスターキーの世代が一致/);
  assert.match(run.stdout, /Vault 1 \/ 1 個の鍵を開けられた/);
});

test('確かめる: 違うマスターキーなら「戻さないでください」と言って止める', { skip: !hasTar }, () => {
  const wrongKey = path.join(TMP, 'wrong.key');
  fs.writeFileSync(wrongKey, `${crypto.randomBytes(32).toString('base64')}\n`, { mode: 0o400 });
  const run = spawnSync('node', ['bin/verify-backup.js', archive, '--key', wrongKey], { cwd: REPO, encoding: 'utf8' });
  assert.notStrictEqual(run.status, 0);
  assert.match(run.stderr, /このマスターキーでは、このバックアップを開けません/);
  assert.match(run.stderr, /このまま戻さないでください/);
});

test('確かめる: 運ぶ途中で壊れたバックアップを見分ける', { skip: !hasTar }, () => {
  const broken = path.join(TMP, 'broken.tar.gz');
  const bytes = fs.readFileSync(archive);
  bytes[bytes.length - 10] ^= 0xff;
  fs.writeFileSync(broken, bytes);
  fs.copyFileSync(`${archive}.json`, `${broken}.json`);
  const run = spawnSync('node', ['bin/verify-backup.js', broken, '--key', KEY], { cwd: REPO, encoding: 'utf8' });
  assert.notStrictEqual(run.status, 0);
  assert.match(run.stderr, /作ったときと違います/);
});
