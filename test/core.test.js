'use strict';
// コア（暗号・ストア・ユーザー・Vault・アイテム）のテスト。
// Node 標準の node:test だけで動く。実行: node --test test/
//
// 設定は require より先に環境変数で差し替える。config.js は読み込み時に1回だけ読むため。

const os = require('os');
const path = require('path');
const fs = require('fs');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-test-'));
process.env.PASSPORT_DATA_DIR = path.join(TMP, 'data');
process.env.PASSPORT_MASTER_KEY_FILE = path.join(TMP, 'keys', 'master.key');
delete process.env.PASSPORT_MASTER_PASSPHRASE;

const test = require('node:test');
const assert = require('node:assert');

const envelope = require('../lib/envelope');
const keyring = require('../lib/keyring');
const store = require('../lib/store');
const users = require('../lib/users');
const vaults = require('../lib/vaults');
const items = require('../lib/items');
const totp = require('../lib/totp');

store.init();
keyring.unlock({ allowGenerate: true });

test.after(() => {
  fs.rmSync(TMP, { recursive: true, force: true });
});

// --- 暗号 -------------------------------------------------------------------

test('封筒: 同じ AAD なら復号できる', () => {
  const key = envelope.randomKey();
  const aad = envelope.buildAad({ vaultId: 'v1', itemId: 'i1', field: 'password', version: 1 });
  const sealed = envelope.seal(key, 'hunter2', aad);
  assert.strictEqual(envelope.open(key, sealed, aad), 'hunter2');
  // 暗号文に平文が残っていないこと
  assert.ok(!JSON.stringify(sealed).includes('hunter2'));
});

test('封筒: AAD が違うと復号できない（貼り替え防止）', () => {
  const key = envelope.randomKey();
  const aadA = envelope.buildAad({ vaultId: 'v1', itemId: 'i1', field: 'password', version: 1 });
  const sealed = envelope.seal(key, 'secret', aadA);

  for (const wrong of [
    { vaultId: 'v2', itemId: 'i1', field: 'password', version: 1 },  // 別 Vault
    { vaultId: 'v1', itemId: 'i2', field: 'password', version: 1 },  // 別アイテム
    { vaultId: 'v1', itemId: 'i1', field: 'note', version: 1 },      // 別フィールド
    { vaultId: 'v1', itemId: 'i1', field: 'password', version: 2 }   // 別世代（巻き戻し）
  ]) {
    assert.throws(() => envelope.open(key, sealed, envelope.buildAad(wrong)));
  }
});

test('封筒: 暗号文を1バイト変えると復号できない', () => {
  const key = envelope.randomKey();
  const aad = envelope.buildAad({ vaultId: 'v1', itemId: 'i1', field: 'password', version: 1 });
  const sealed = envelope.seal(key, 'tamper-me-please', aad);
  const bytes = Buffer.from(sealed.ct, 'base64');
  bytes[0] ^= 0xff;
  assert.throws(() => envelope.open(key, { ...sealed, ct: bytes.toString('base64') }, aad));
});

test('封筒: 鍵が違うと復号できない', () => {
  const aad = envelope.buildAad({ vaultId: 'v1', itemId: 'i1', field: 'password', version: 1 });
  const sealed = envelope.seal(envelope.randomKey(), 'secret', aad);
  assert.throws(() => envelope.open(envelope.randomKey(), sealed, aad));
});

test('封筒: 同じ平文でも毎回違う暗号文になる（IV が使い回されていない）', () => {
  const key = envelope.randomKey();
  const aad = envelope.buildAad({ vaultId: 'v1', itemId: 'i1', field: 'password', version: 1 });
  const a = envelope.seal(key, 'same', aad);
  const b = envelope.seal(key, 'same', aad);
  assert.notStrictEqual(a.iv, b.iv);
  assert.notStrictEqual(a.ct, b.ct);
});

test('パスワードハッシュ: 正しいパスワードだけ通る', () => {
  const pepper = keyring.pepper();
  const stored = envelope.hashPassword('correct horse battery', pepper);
  assert.ok(envelope.verifyPassword('correct horse battery', pepper, stored));
  assert.ok(!envelope.verifyPassword('correct horse batteri', pepper, stored));
  assert.ok(!envelope.verifyPassword('', pepper, stored));
});

test('パスワードハッシュ: pepper が違うと通らない（ユーザーファイル単体では総当たりできない）', () => {
  const stored = envelope.hashPassword('correct horse battery', keyring.pepper());
  assert.ok(!envelope.verifyPassword('correct horse battery', Buffer.alloc(32), stored));
});

test('keyring: 自己テストが通る', () => {
  assert.ok(keyring.selfTest());
});

// --- ストア -----------------------------------------------------------------

test('ストア: データディレクトリの外へは書けない', () => {
  assert.throws(() => store.readJson('../../../etc/passwd'));
  assert.throws(() => store.writeJson('../escape.json', {}));
  assert.throws(() => store.assertValidId('../evil'));
  assert.throws(() => store.assertValidId('a/b'));
});

test('ストア: version が合わないと更新を弾く（楽観ロック）', () => {
  store.writeJson('test/lock.json', { id: 'x', value: 1, version: 1 });
  store.updateJson('test/lock.json', 1, (cur) => ({ ...cur, value: 2 }));
  assert.strictEqual(store.readJson('test/lock.json').version, 2);
  assert.throws(
    () => store.updateJson('test/lock.json', 1, (cur) => ({ ...cur, value: 3 })),
    (err) => err.code === 'CONFLICT'
  );
});

// --- ユーザー ---------------------------------------------------------------

let admin;
let member;
let outsider;

test('ユーザー: 作成してログインできる', () => {
  admin = users.create({ username: 'mooma', password: 'a-long-enough-pass', role: 'admin' });
  member = users.create({ username: 'tanaka', password: 'another-long-pass', role: 'member' });
  outsider = users.create({ username: 'sato', password: 'third-long-password', role: 'member' });

  const ok = users.authenticate('mooma', 'a-long-enough-pass');
  assert.ok(ok.ok);
  assert.strictEqual(ok.user.username, 'mooma');

  const ng = users.authenticate('mooma', 'wrong-password-here');
  assert.ok(!ng.ok);
});

test('ユーザー: 公開用の形にハッシュが混ざらない', () => {
  const pub = users.toPublic(users.get(admin.id));
  assert.ok(!('passwordHash' in pub));
  assert.ok(!JSON.stringify(pub).includes('scrypt'));
});

test('ユーザー: 短いパスワードと重複ユーザー名は弾く', () => {
  assert.throws(() => users.create({ username: 'short', password: 'abc' }));
  assert.throws(() => users.create({ username: 'mooma', password: 'a-long-enough-pass' }));
  assert.throws(() => users.create({ username: 'Bad Name', password: 'a-long-enough-pass' }));
});

test('ユーザー: 失敗を重ねるとロックされる', () => {
  const target = users.create({ username: 'locktest', password: 'a-long-enough-pass' });
  for (let i = 0; i < 5; i += 1) users.authenticate('locktest', 'wrong-password');
  const result = users.authenticate('locktest', 'a-long-enough-pass'); // 正しくても通らない
  assert.strictEqual(result.reason, 'locked');
  assert.ok(users.isLocked(users.get(target.id)));
});

// --- Vault とアイテム -------------------------------------------------------

let vault;

test('Vault: 作成すると作成者が owner になる', () => {
  vault = vaults.create({ name: '共通インフラ', ownerId: admin.id, actor: admin.id });
  assert.strictEqual(vaults.roleOf(vault, admin.id), 'owner');
  assert.strictEqual(vaults.roleOf(vault, member.id), null);
});

test('Vault: Vault Key は KEK で包まれていて、平文では保存されない', () => {
  const raw = fs.readFileSync(store.resolveInData(`vaults/${vault.id}/vault.json`), 'utf8');
  assert.ok(raw.includes('server-kek-v1'));
  const key = vaults.unwrapKey(vaults.get(vault.id));
  assert.strictEqual(key.length, 32);
  assert.ok(!raw.includes(key.toString('base64')));
});

test('アイテム: 作成するとパスワードは暗号化されて保存される', () => {
  const item = items.create(vault.id, {
    title: 'vSphere 管理コンソール',
    username: 'administrator@vsphere.local',
    urls: ['https://vcenter.example.local'],
    tags: ['インフラ', 'vmware'],
    secrets: { password: 'P@ssw0rd-that-must-not-leak', note: '停電対応の手順書に記載' }
  }, { actor: admin.id });

  const raw = fs.readFileSync(store.resolveInData(`vaults/${vault.id}/items/${item.id}.json`), 'utf8');
  assert.ok(!raw.includes('P@ssw0rd-that-must-not-leak'), 'パスワードが平文で保存されている');
  assert.ok(!raw.includes('停電対応の手順書に記載'), 'メモが平文で保存されている');
  // 一覧に必要なメタデータは平文（設計どおり）
  assert.ok(raw.includes('vSphere 管理コンソール'));

  // 一覧・取得では秘密の中身を返さない
  assert.strictEqual(item.secrets.password.present, true);
  assert.strictEqual(item.secrets.password.value, undefined);

  const revealed = items.revealSecret(vault.id, item.id, 'password', { actor: admin.id });
  assert.strictEqual(revealed, 'P@ssw0rd-that-must-not-leak');
});

test('アイテム: 秘密を更新すると世代が上がり、古い暗号文へは戻せない', () => {
  const item = items.create(vault.id, {
    title: 'PostgreSQL 本番',
    secrets: { password: 'old-password' }
  }, { actor: admin.id });

  const stored = store.readJson(`vaults/${vault.id}/items/${item.id}.json`);
  const oldEnvelope = stored.secrets.password;

  const updated = items.update(vault.id, item.id, {
    version: item.version,
    secrets: { password: 'new-password' }
  }, { actor: admin.id });

  assert.strictEqual(items.revealSecret(vault.id, item.id, 'password', { actor: admin.id }), 'new-password');

  // 古い封筒を書き戻しても、AAD の世代が合わないので復号できない
  store.writeJson(`vaults/${vault.id}/items/${item.id}.json`, {
    ...store.readJson(`vaults/${vault.id}/items/${item.id}.json`),
    secrets: { password: { ...oldEnvelope, v: 2 } }
  });
  assert.throws(() => items.revealSecret(vault.id, item.id, 'password', { actor: admin.id }));
  assert.ok(updated.version > item.version);
});

test('アイテム: 別 Vault の暗号文を貼り付けても復号できない', () => {
  const other = vaults.create({ name: '別の金庫', ownerId: admin.id, actor: admin.id });
  const source = items.create(other.id, { title: 'コピー元', secrets: { password: 'cross-vault' } }, { actor: admin.id });
  const target = items.create(vault.id, { title: 'コピー先', secrets: { password: 'original' } }, { actor: admin.id });

  const sourceRecord = store.readJson(`vaults/${other.id}/items/${source.id}.json`).secrets.password;
  const targetPath = `vaults/${vault.id}/items/${target.id}.json`;
  store.writeJson(targetPath, { ...store.readJson(targetPath), secrets: { password: sourceRecord } });

  assert.throws(() => items.revealSecret(vault.id, target.id, 'password', { actor: admin.id }));
});

test('権限: メンバーでない人は見ることも書くこともできない', () => {
  assert.throws(() => items.list(vault.id, outsider.id), (e) => e.code === 'FORBIDDEN');
  assert.throws(
    () => items.create(vault.id, { title: 'x' }, { actor: outsider.id }),
    (e) => e.code === 'FORBIDDEN'
  );
});

test('権限: viewer は読めるが書けない', () => {
  vaults.addMember(vault.id, { userId: member.id, role: 'viewer', actor: admin.id });
  assert.ok(items.list(vault.id, member.id).length > 0);
  assert.throws(
    () => items.create(vault.id, { title: 'できないはず' }, { actor: member.id }),
    (e) => e.code === 'FORBIDDEN'
  );

  vaults.updateMember(vault.id, { userId: member.id, role: 'editor', actor: admin.id });
  const created = items.create(vault.id, { title: 'editor なら書ける' }, { actor: member.id });
  assert.ok(created.id);
});

test('権限: 最後の owner は外せない', () => {
  assert.throws(() => vaults.updateMember(vault.id, { userId: admin.id, role: 'viewer', actor: admin.id }));
  assert.throws(() => vaults.removeMember(vault.id, { userId: admin.id, actor: admin.id }));
});

test('権限: editor はメンバーを足せない', () => {
  assert.throws(
    () => vaults.addMember(vault.id, { userId: outsider.id, role: 'viewer', actor: member.id }),
    (e) => e.code === 'FORBIDDEN'
  );
});

test('共有: Vault に入れた人は同じ秘密を復号できる', () => {
  const shared = items.create(vault.id, { title: '共有される鍵', secrets: { password: 'shared-secret-value' } }, { actor: admin.id });
  const asMember = items.revealSecret(vault.id, shared.id, 'password', { actor: member.id });
  assert.strictEqual(asMember, 'shared-secret-value');
});

test('検索: 自分が入っている Vault だけが対象になる', () => {
  const mine = items.search(member.id, 'vSphere');
  assert.ok(mine.length > 0);
  const theirs = items.search(outsider.id, 'vSphere');
  assert.strictEqual(theirs.length, 0);
});

test('監査ログ: 秘密の閲覧が記録される', () => {
  const audit = require('../lib/audit');
  const entries = audit.recent({ limit: 500 });
  const viewed = entries.filter((e) => e.event === 'item.view_secret');
  assert.ok(viewed.length > 0);
  // ログに秘密そのものが載っていないこと
  const text = JSON.stringify(entries);
  assert.ok(!text.includes('P@ssw0rd-that-must-not-leak'));
  assert.ok(!text.includes('shared-secret-value'));
});

// --- TOTP -------------------------------------------------------------------

test('TOTP: RFC 6238 のテストベクタと一致する', () => {
  // RFC 6238 Appendix B: シークレット "12345678901234567890" (SHA1, 8桁)
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const at = 59 * 1000;
  const result = totp.generate(`otpauth://totp/test?secret=${secret}&digits=8`, { at });
  assert.strictEqual(result.code, '94287082');
});

test('TOTP: otpauth URI もそのまま貼れる', () => {
  const parsed = totp.parseSecret('otpauth://totp/Example:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example');
  assert.strictEqual(parsed.secret, 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(parsed.issuer, 'Example');
  assert.ok(totp.isValidSecret('JBSWY3DPEHPK3PXP'));
  assert.ok(!totp.isValidSecret('これはBase32ではない'));
});
