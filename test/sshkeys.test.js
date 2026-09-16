'use strict';
// SSH 鍵のテスト。ssh-keygen があれば、それと突き合わせる。
//
// 自前で OpenSSH の形式を組み立てている以上、「ssh-keygen が読めるか」を
// 確かめないと意味がない。単体で閉じたテストだけにはしない。

const os = require('os');
const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-ssh-test-'));
process.env.PASSPORT_DATA_DIR = path.join(TMP, 'data');
process.env.PASSPORT_MASTER_KEY_FILE = path.join(TMP, 'keys', 'master.key');
delete process.env.PASSPORT_MASTER_PASSPHRASE;

const test = require('node:test');
const assert = require('node:assert');

const ssh = require('../lib/sshkeys');
const store = require('../lib/store');
const keyring = require('../lib/keyring');
const users = require('../lib/users');
const vaults = require('../lib/vaults');
const items = require('../lib/items');

store.init();
keyring.unlock({ allowGenerate: true });

// ssh-keygen があるかどうか。無い環境では突き合わせだけ飛ばす。
let hasSshKeygen = true;
try {
  execFileSync('ssh-keygen', ['-?'], { stdio: 'ignore' });
} catch (err) {
  hasSshKeygen = err.status !== undefined; // -? は終了コード1で使い方を出す
}

test.after(() => {
  fs.rmSync(TMP, { recursive: true, force: true });
});

function writeKey(name, contents) {
  const file = path.join(TMP, name);
  fs.writeFileSync(file, contents, { mode: 0o600 });
  return file;
}

// --- 生成 -------------------------------------------------------------------

for (const type of ['ed25519', 'rsa-3072']) {
  test(`生成: ${type} の秘密鍵を ssh-keygen が読める`, { skip: !hasSshKeygen }, () => {
    const key = ssh.generate({ type, comment: 'passport@test' });
    const file = writeKey(`gen_${type}`, key.privateKey);

    // ssh-keygen に秘密鍵から公開鍵を作らせて、こちらの公開鍵と一致するか
    const derived = execFileSync('ssh-keygen', ['-y', '-f', file]).toString().trim();
    const ours = key.publicKey.split(' ').slice(0, 2).join(' ');
    assert.strictEqual(derived.split(' ').slice(0, 2).join(' '), ours);

    // フィンガープリントも ssh-keygen -l と一致するか
    const listed = execFileSync('ssh-keygen', ['-l', '-f', file]).toString().trim().split(/\s+/);
    assert.strictEqual(listed[0], String(key.bits));
    assert.strictEqual(listed[1], key.fingerprint);
  });
}

test('生成: コメントが公開鍵と秘密鍵の両方に入る', { skip: !hasSshKeygen }, () => {
  const key = ssh.generate({ type: 'ed25519', comment: 'mooma@workstation' });
  assert.ok(key.publicKey.endsWith(' mooma@workstation'));
  const file = writeKey('gen_comment', key.privateKey);
  // 秘密鍵側のコメントは、読み直したときに取れる
  assert.strictEqual(ssh.inspectPrivateKey(key.privateKey).comment, 'mooma@workstation');
  assert.ok(fs.existsSync(file));
});

test('生成: 毎回違う鍵になる', () => {
  const a = ssh.generate({ type: 'ed25519' });
  const b = ssh.generate({ type: 'ed25519' });
  assert.notStrictEqual(a.fingerprint, b.fingerprint);
});

test('生成: 知らない種別は断る', () => {
  assert.throws(() => ssh.generate({ type: 'dsa' }));
});

// --- 読み取り ---------------------------------------------------------------

test('読み取り: ssh-keygen が作った平文の鍵を読める', { skip: !hasSshKeygen }, () => {
  const base = path.join(TMP, 'from_keygen');
  execFileSync('ssh-keygen', ['-t', 'ed25519', '-N', '', '-C', 'made-by@keygen', '-f', base, '-q']);
  const info = ssh.inspectPrivateKey(fs.readFileSync(base, 'utf8'));

  assert.strictEqual(info.keyType, 'ssh-ed25519');
  assert.strictEqual(info.bits, 256);
  assert.strictEqual(info.encrypted, false);
  assert.strictEqual(info.comment, 'made-by@keygen');

  const expected = execFileSync('ssh-keygen', ['-l', '-f', `${base}.pub`]).toString().split(/\s+/)[1];
  assert.strictEqual(info.fingerprint, expected);
  // 公開鍵の本体（種別と base64）が .pub と一致すること
  const pub = fs.readFileSync(`${base}.pub`, 'utf8').trim().split(' ').slice(0, 2).join(' ');
  assert.strictEqual(info.publicKey.split(' ').slice(0, 2).join(' '), pub);
});

test('読み取り: パスフレーズ付きでも、パスフレーズ無しで公開鍵が取れる', { skip: !hasSshKeygen }, () => {
  const base = path.join(TMP, 'encrypted_key');
  execFileSync('ssh-keygen', ['-t', 'ed25519', '-N', 'a-passphrase', '-C', 'enc@test', '-f', base, '-q']);
  const info = ssh.inspectPrivateKey(fs.readFileSync(base, 'utf8'));

  assert.strictEqual(info.encrypted, true);
  assert.strictEqual(info.keyType, 'ssh-ed25519');
  const expected = execFileSync('ssh-keygen', ['-l', '-f', `${base}.pub`]).toString().split(/\s+/)[1];
  assert.strictEqual(info.fingerprint, expected);
  // 暗号化されているので、コメントまでは読めない（読めなくてよい）
  assert.strictEqual(info.comment, '');
});

test('読み取り: RSA も扱える', { skip: !hasSshKeygen }, () => {
  const base = path.join(TMP, 'rsa_key');
  execFileSync('ssh-keygen', ['-t', 'rsa', '-b', '2048', '-N', '', '-C', 'rsa@test', '-f', base, '-q']);
  const info = ssh.inspectPrivateKey(fs.readFileSync(base, 'utf8'));
  assert.strictEqual(info.keyType, 'ssh-rsa');
  assert.strictEqual(info.bits, 2048);
});

test('読み取り: 壊れた入力はちゃんと断る', () => {
  assert.throws(() => ssh.inspectPrivateKey(''), /空です/);
  assert.throws(() => ssh.inspectPrivateKey('これは鍵ではありません'));
  assert.throws(() => ssh.inspectPrivateKey(
    '-----BEGIN OPENSSH PRIVATE KEY-----\nZGVmaW5pdGVseS1ub3QtYS1rZXk=\n-----END OPENSSH PRIVATE KEY-----'
  ));
});

test('公開鍵: 文字列を読んでフィンガープリントを出せる', () => {
  const key = ssh.generate({ type: 'ed25519', comment: 'pub@test' });
  const parsed = ssh.parsePublicKey(key.publicKey);
  assert.strictEqual(parsed.fingerprint, key.fingerprint);
  assert.strictEqual(parsed.comment, 'pub@test');
  assert.strictEqual(parsed.bits, 256);
});

test('公開鍵: 種別と中身が食い違う行は断る', () => {
  const key = ssh.generate({ type: 'ed25519' });
  const base64 = key.publicKey.split(' ')[1];
  assert.throws(() => ssh.parsePublicKey(`ssh-rsa ${base64}`), /一致しません/);
  assert.throws(() => ssh.parsePublicKey('ssh-ed25519'), /形式ではありません/);
});

// --- Vault に入れたときの振る舞い -------------------------------------------

test('保管: 秘密鍵は暗号化され、公開鍵とフィンガープリントは平文で残る', () => {
  const owner = users.create({ username: 'sshowner', password: 'a-long-enough-pass', role: 'admin' });
  const vault = vaults.create({ name: 'SSH 鍵', ownerId: owner.id, actor: owner.id });
  const key = ssh.generate({ type: 'ed25519', comment: 'stored@test' });

  const item = items.create(vault.id, {
    type: 'sshkey',
    title: '踏み台サーバー',
    secrets: { privateKey: key.privateKey, passphrase: 'key-passphrase' }
  }, { actor: owner.id });

  // メタデータは秘密鍵から自動で割り出される
  assert.strictEqual(item.sshKey.keyType, 'ssh-ed25519');
  assert.strictEqual(item.sshKey.fingerprint, key.fingerprint);
  assert.strictEqual(item.sshKey.hasPrivateKey, true);
  assert.strictEqual(item.secrets.privateKey.present, true);

  const raw = fs.readFileSync(
    store.resolveInData(`vaults/${vault.id}/items/${item.id}.json`), 'utf8'
  );
  // 秘密鍵の中身とパスフレーズは平文で残っていない
  assert.ok(!raw.includes('OPENSSH PRIVATE KEY'), '秘密鍵が平文で保存されている');
  assert.ok(!raw.includes('key-passphrase'), 'パスフレーズが平文で保存されている');
  // 公開鍵とフィンガープリントは平文（これは公開してよいもの）
  assert.ok(raw.includes(key.fingerprint));
  assert.ok(raw.includes(key.publicKey.split(' ')[1]));

  // 取り出すと元の鍵に戻る
  const revealed = items.revealSecret(vault.id, item.id, 'privateKey', { actor: owner.id });
  assert.strictEqual(revealed, key.privateKey);
  assert.strictEqual(
    items.revealSecret(vault.id, item.id, 'passphrase', { actor: owner.id }),
    'key-passphrase'
  );
});

test('保管: 取り出した秘密鍵を ssh-keygen がそのまま使える', { skip: !hasSshKeygen }, () => {
  const owner = users.findByUsername('sshowner');
  const vault = vaults.list().find((v) => v.name === 'SSH 鍵');
  const item = items.list(vault.id, owner.id)[0];
  const revealed = items.revealSecret(vault.id, item.id, 'privateKey', { actor: owner.id });

  const file = writeKey('roundtrip', revealed);
  const derived = execFileSync('ssh-keygen', ['-y', '-f', file]).toString().trim();
  assert.strictEqual(
    derived.split(' ').slice(0, 2).join(' '),
    item.sshKey.publicKey.split(' ').slice(0, 2).join(' ')
  );
});

test('保管: 公開鍵だけの控えも作れる', () => {
  const owner = users.findByUsername('sshowner');
  const vault = vaults.list().find((v) => v.name === 'SSH 鍵');
  const key = ssh.generate({ type: 'ed25519', comment: 'public-only@test' });

  const item = items.create(vault.id, {
    type: 'sshkey',
    title: '本番サーバーに置いてある鍵',
    publicKey: key.publicKey
  }, { actor: owner.id });

  assert.strictEqual(item.sshKey.hasPrivateKey, false);
  assert.strictEqual(item.sshKey.fingerprint, key.fingerprint);
  assert.strictEqual(item.secrets.privateKey, undefined);
});

test('保管: 鍵が無いと作れない', () => {
  const owner = users.findByUsername('sshowner');
  const vault = vaults.list().find((v) => v.name === 'SSH 鍵');
  assert.throws(
    () => items.create(vault.id, { type: 'sshkey', title: '鍵なし' }, { actor: owner.id }),
    /どちらかを入れてください/
  );
  assert.throws(
    () => items.create(vault.id, {
      type: 'sshkey', title: '壊れた鍵', secrets: { privateKey: 'not-a-key' }
    }, { actor: owner.id })
  );
});

test('検索: フィンガープリントで引ける', () => {
  const owner = users.findByUsername('sshowner');
  const vault = vaults.list().find((v) => v.name === 'SSH 鍵');
  const item = items.list(vault.id, owner.id).find((i) => i.title === '踏み台サーバー');
  const hit = items.search(owner.id, item.sshKey.fingerprint.slice(7, 20));
  assert.ok(hit.some((r) => r.id === item.id));
});

test('authorized_keys: オプション付きの1行を作れる', () => {
  const key = ssh.generate({ type: 'ed25519', comment: 'authz@test' });
  const plain = ssh.authorizedKeysLine(key.publicKey);
  assert.strictEqual(plain, key.publicKey);
  const restricted = ssh.authorizedKeysLine(key.publicKey, {
    options: 'no-port-forwarding,from="192.168.1.0/24"'
  });
  assert.ok(restricted.startsWith('no-port-forwarding,from="192.168.1.0/24" ssh-ed25519 '));
});
