'use strict';
// 取り返しのつかない経路を塞いだことの確認。
// レビューで実際に再現した筋書きを、そのまま再現できないことを確かめる。

const os = require('os');
const path = require('path');
const fs = require('fs');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-integrity-test-'));
process.env.PASSPORT_DATA_DIR = path.join(TMP, 'data');
process.env.PASSPORT_MASTER_KEY_FILE = path.join(TMP, 'keys', 'master.key');
delete process.env.PASSPORT_MASTER_PASSPHRASE;

const test = require('node:test');
const assert = require('node:assert');

const store = require('../lib/store');
const keyring = require('../lib/keyring');
const envelope = require('../lib/envelope');
const users = require('../lib/users');
const vaults = require('../lib/vaults');
const integrity = require('../lib/integrity');
const audit = require('../lib/audit');

store.init();
keyring.unlock({ allowGenerate: true });

test.after(() => {
  // chmod 000 にしたファイルがあると消せないので戻してから消す
  const usersDir = path.join(TMP, 'data', 'users');
  if (fs.existsSync(usersDir)) {
    for (const name of fs.readdirSync(usersDir)) fs.chmodSync(path.join(usersDir, name), 0o600);
  }
  fs.rmSync(TMP, { recursive: true, force: true });
});

// --- セットアップの乗っ取り -------------------------------------------------

test('セットアップ: 何も無いときだけ許す', () => {
  assert.strictEqual(integrity.setupAllowed(), true);
  integrity.checkOnStartup(); // 新しいデータなので通り、鍵の目印ができる
  assert.ok(store.exists('keycheck.json'));
});

let owner;
let vault;

test('セットアップ: ユーザーと Vault ができたら許さない', () => {
  owner = users.create({ username: 'owner', password: 'a-long-enough-pass', role: 'admin' });
  vault = vaults.create({ name: '本番', ownerId: owner.id, actor: owner.id });
  assert.strictEqual(integrity.setupAllowed(), false);
});

test('セットアップ: ユーザーのファイルが読めなくても、0人とは数えない', () => {
  const file = store.resolveInData(`users/${owner.id}.json`);
  fs.chmodSync(file, 0o000);
  try {
    // 読み取りに頼る数え方だと 0 になる（これがレビューで実測された穴）
    assert.strictEqual(users.count(), 0);
    // セットアップの判断はディスク上のファイル名で行うので、許さない
    assert.strictEqual(integrity.setupAllowed(), false);
  } finally {
    fs.chmodSync(file, 0o600);
  }
});

test('セットアップ: ユーザーだけ失われた状態では、起動そのものを止める', () => {
  const usersDir = store.resolveInData('users');
  const backup = fs.mkdtempSync(path.join(TMP, 'users-backup-'));
  for (const name of fs.readdirSync(usersDir)) {
    fs.renameSync(path.join(usersDir, name), path.join(backup, name));
  }
  try {
    assert.strictEqual(integrity.setupAllowed(), false, 'Vault があるのでセットアップは開かない');
    assert.throws(
      () => integrity.checkOnStartup(),
      (err) => err instanceof integrity.IntegrityError && /ユーザーが1人も見つからない/.test(err.message)
    );
  } finally {
    for (const name of fs.readdirSync(backup)) {
      fs.renameSync(path.join(backup, name), path.join(usersDir, name));
    }
  }
});

test('セットアップ: 合言葉は、合っているときだけ通り、成功したら使い切る', () => {
  const token = integrity.issueSetupToken();
  assert.strictEqual(integrity.checkSetupToken('wrong'), false);
  assert.strictEqual(integrity.checkSetupToken(''), false);
  assert.strictEqual(integrity.checkSetupToken(token), true);
  // 入力ミスでは消えない（まだ使い切っていない）
  assert.strictEqual(integrity.checkSetupToken(token), true);
  integrity.consumeSetupToken();
  assert.strictEqual(integrity.checkSetupToken(token), false);
});

// --- マスターキーの取り違え -------------------------------------------------

test('鍵の世代: 同じ鍵なら通る', () => {
  integrity.checkOnStartup();
});

test('鍵の世代: 違う鍵で作られたデータなら、起動を止める', () => {
  const original = store.readJson('keycheck.json');
  // 別の鍵で封じた目印に差し替える（＝鍵を取り違えた状態）
  const otherKey = envelope.randomKey();
  store.writeJson('keycheck.json', {
    ...original,
    fingerprint: integrity.fingerprintOf(otherKey),
    envelope: envelope.seal(otherKey, 'passport/keycheck/v1', Buffer.from('passport/keycheck|v1', 'utf8'))
  });
  try {
    assert.throws(
      () => integrity.checkOnStartup(),
      (err) => err instanceof integrity.IntegrityError
        && /マスターキーが、このデータを作ったときのものと違います/.test(err.message)
        && /data\/ を消したり作り直したりしないでください/.test(err.message)
    );
  } finally {
    store.writeJson('keycheck.json', original);
  }
});

test('鍵の世代: 目印が無い既存データでは、Vault の鍵を開けられるか確かめてから作る', () => {
  const original = store.readJson('keycheck.json');
  store.deleteFile('keycheck.json');
  try {
    integrity.checkOnStartup(); // 同じ鍵なので Vault を開けられ、目印が作り直される
    assert.ok(store.exists('keycheck.json'));

    // Vault の鍵を開けられない状態（別の鍵で包まれている）では、目印を作らずに止める
    store.deleteFile('keycheck.json');
    const vaultPath = `vaults/${vault.id}/vault.json`;
    const saved = store.readJson(vaultPath);
    const otherKek = envelope.randomKey();
    store.writeJson(vaultPath, {
      ...saved,
      wrappedKeys: [{
        holder: 'server',
        method: 'server-kek-v1',
        envelope: envelope.sealKey(otherKek, envelope.randomKey(),
          Buffer.from(`passport/vault-key|${vault.id}|server`, 'utf8'))
      }]
    });
    try {
      assert.throws(() => integrity.checkOnStartup(), /1つも開けられません/);
      assert.ok(!store.exists('keycheck.json'), '違う鍵を正しいと記録していない');
    } finally {
      store.writeJson(vaultPath, saved);
    }
  } finally {
    store.writeJson('keycheck.json', original);
  }
});

// --- ログインの照合で止められない -------------------------------------------

test('照合: 保存されたパラメータが範囲外なら、計算せずに断る', () => {
  const stored = envelope.hashPassword('correct-password', keyring.pepper());
  for (const tampered of [
    { ...stored, p: 99 },
    { ...stored, r: 1024 },
    { ...stored, N: 2 ** 24 },
    { ...stored, N: 30000 },        // 2 の累乗でない
    { ...stored, dkLen: 4096 },
    { ...stored, p: 1.5 }
  ]) {
    const started = Date.now();
    assert.strictEqual(envelope.verifyPassword('correct-password', keyring.pepper(), tampered), false);
    assert.ok(Date.now() - started < 200, `範囲外なのに計算している: ${JSON.stringify(tampered).slice(0, 60)}`);
  }
  // 正しいものは通る
  assert.strictEqual(envelope.verifyPassword('correct-password', keyring.pepper(), stored), true);
});

test('照合: pepper が無いまま黙ってハッシュを作らない', () => {
  assert.throws(() => envelope.hashPassword('x'.repeat(20), undefined), /pepper がありません/);
  assert.throws(() => envelope.hashPassword('x'.repeat(20), Buffer.alloc(0)), /pepper がありません/);
});

// --- 監査ログにパスワードが流れ込まない -------------------------------------

test('監査ログ: 存在しないユーザー名で打ち込まれた文字列を、そのまま残さない', () => {
  // ユーザー名の欄にパスワードを打ち間違えた状況
  const mistyped = 'MyRealPassword-typed-into-username!';
  users.authenticate(mistyped, 'whatever');
  users.authenticate(mistyped, 'whatever-again');

  const entries = audit.recent({ limit: 50 }).filter((e) => e.event === 'login.fail' && e.result === 'no_such_user');
  assert.ok(entries.length >= 2);
  assert.ok(!JSON.stringify(entries).includes(mistyped), '打ち込まれた文字列が監査ログに残っている');

  // 同じ文字列の試行が続いていることは分かる
  const marks = entries.slice(0, 2).map((e) => e.note);
  assert.strictEqual(marks[0], marks[1]);
  assert.match(marks[0], /^試行の印 [0-9a-f]{12}$/);
});
