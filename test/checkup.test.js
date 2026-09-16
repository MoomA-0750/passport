'use strict';
// 点検とリマインドのテスト。
// 漏れは「見えてはいけないものが見えた」ことでしか分からないので、そこを中心に見る。

const os = require('os');
const path = require('path');
const fs = require('fs');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-checkup-test-'));
process.env.PASSPORT_DATA_DIR = path.join(TMP, 'data');
process.env.PASSPORT_MASTER_KEY_FILE = path.join(TMP, 'keys', 'master.key');
delete process.env.PASSPORT_MASTER_PASSPHRASE;

const test = require('node:test');
const assert = require('node:assert');

const keyring = require('../lib/keyring');
const store = require('../lib/store');
const users = require('../lib/users');
const vaults = require('../lib/vaults');
const items = require('../lib/items');
const checkup = require('../lib/checkup');
const audit = require('../lib/audit');
const activity = require('../lib/activity');
const groups = require('../lib/groups');

store.init();
keyring.unlock({ allowGenerate: true });
test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

const DAY = 24 * 60 * 60 * 1000;
const SHARED = 'Reused-Strong-Pass-8842!';
const PRIVATE_ONLY = 'Private-Other-Vault-7731#';

let alice; let bob;
let aliceVault; let bobVault; let sharedVault;
const ids = {};

function backdatePassword(vaultId, itemId, days) {
  const file = `vaults/${vaultId}/items/${itemId}.json`;
  const item = store.readJson(file);
  const at = new Date(Date.now() - days * DAY).toISOString();
  item.secrets.password.updatedAt = at;
  item.createdAt = at;
  store.writeJson(file, item);
}

test('準備', () => {
  alice = users.create({ username: 'alice', password: 'a-long-enough-pass' });
  bob = users.create({ username: 'bob', password: 'a-long-enough-pass' });
  aliceVault = vaults.create({ name: 'アリス', ownerId: alice.id, actor: alice.id });
  bobVault = vaults.create({ name: 'ボブ', ownerId: bob.id, actor: bob.id });
  sharedVault = vaults.create({ name: '共有', ownerId: bob.id, actor: bob.id });
  vaults.addMember(sharedVault.id, { userId: alice.id, role: 'editor', actor: bob.id });

  const add = (vault, actor, key, input) => { ids[key] = items.create(vault.id, input, { actor: actor.id }).id; };
  add(aliceVault, alice, 'weak', { title: '弱い', secrets: { password: 'abc123' } });
  add(aliceVault, alice, 'reuseA', { title: '使い回しA', secrets: { password: SHARED } });
  add(aliceVault, alice, 'reuseA2', { title: '使い回しA2', secrets: { password: SHARED } });
  add(sharedVault, bob, 'reuseB', { title: '使い回しB', secrets: { password: SHARED } });
  add(sharedVault, bob, 'reuseB2', { title: '使い回しB2', secrets: { password: SHARED } });
  // アリスが見られない Vault に、アリスのと同じパスワード
  add(bobVault, bob, 'hiddenSame', { title: 'ボブだけの同じ値', secrets: { password: SHARED } });
  add(bobVault, bob, 'hiddenWeak', { title: 'ボブだけの弱い値', secrets: { password: 'password' } });
  add(aliceVault, alice, 'old', { title: '古い', secrets: { password: 'Old-But-Strong-Pass-1947$' } });
  backdatePassword(aliceVault.id, ids.old, 400);
  add(aliceVault, alice, 'rotation', { title: '周期切れ', rotationDays: 90, secrets: { password: 'Rotate-Me-Strong-Pass-55%' } });
  backdatePassword(aliceVault.id, ids.rotation, 100);
  const soon = new Date(Date.now() + 10 * DAY).toISOString().slice(0, 10);
  add(aliceVault, alice, 'expiry', { title: '証明書', type: 'note', expiresAt: soon, secrets: { note: '証明書の置き場所' } });
  add(bobVault, bob, 'hiddenExpiry', { title: 'ボブの証明書', type: 'note', expiresAt: '2000-01-01' });
  add(aliceVault, alice, 'fine', { title: '問題なし', secrets: { password: PRIVATE_ONLY } });
});

test('周期と有効期限: 決まった値しか入らない', () => {
  assert.throws(() => items.create(aliceVault.id, { title: 'x', rotationDays: 7 }, { actor: alice.id }), /周期/);
  assert.throws(() => items.create(aliceVault.id, { title: 'x', expiresAt: '2026-02-30' }, { actor: alice.id }), /YYYY-MM-DD/);
  assert.throws(() => items.create(aliceVault.id, { title: 'x', expiresAt: 'tomorrow' }, { actor: alice.id }), /YYYY-MM-DD/);
});

test('リマインド: 見られる Vault の期限切れ・期限間近だけが出る（復号しない）', () => {
  const r = checkup.reminders(alice.id);
  const titles = r.items.map((d) => d.title);
  assert.ok(titles.includes('周期切れ'));
  assert.ok(titles.includes('証明書'));
  assert.ok(!titles.includes('ボブの証明書'), '見られない Vault の期限が出ている');
  assert.strictEqual(r.overdue, 1);
  assert.strictEqual(r.soon, 1);
  const rotation = r.items.find((d) => d.title === '周期切れ');
  assert.strictEqual(rotation.kind, 'rotation');
  assert.strictEqual(rotation.overdue, true);
});

let result;

test('点検: 弱い・使い回し・古いを見つける', () => {
  checkup._resetThrottle();
  result = checkup.run(alice.id);
  assert.ok(result.weak.some((w) => w.itemId === ids.weak));
  assert.ok(result.old.some((o) => o.itemId === ids.old));
  // 周期を決めているものは「古い」ではなく期限として出る
  assert.ok(!result.old.some((o) => o.itemId === ids.rotation));
  assert.ok(result.due.some((d) => d.itemId === ids.rotation));
  assert.ok(!result.weak.some((w) => w.itemId === ids.fine));

  // 同じ Vault の中の使い回しは見つける
  const group = result.reused.find((g) => g.some((r) => r.itemId === ids.reuseA));
  assert.ok(group, '使い回しが見つからない');
  assert.deepStrictEqual(group.map((r) => r.itemId).sort(), [ids.reuseA, ids.reuseA2].sort());
  // Vault をまたいだ一致は出さない（推測した値を置いて、ほかの Vault の値と同じかを確かめる道具にしない）
  assert.ok(result.reused.every((g) => new Set(g.map((r) => r.vaultId)).size === 1), 'Vault をまたいだ一致が出ている');
  assert.ok(!result.reused.some((g) => g.some((r) => r.itemId === ids.reuseA) && g.some((r) => r.itemId === ids.reuseB)));
});

test('点検: 見られない Vault のアイテムとの一致・弱さは出ない', () => {
  const text = JSON.stringify(result);
  for (const key of ['hiddenSame', 'hiddenWeak', 'hiddenExpiry']) assert.ok(!text.includes(ids[key]), `${key} が出ている`);
  assert.ok(!text.includes('ボブ'), '見られない Vault の名前が出ている');
});

test('点検: 結果に値もハッシュも含まれない', () => {
  const text = JSON.stringify(result);
  for (const value of [SHARED, PRIVATE_ONLY, 'abc123']) assert.ok(!text.includes(value));
  assert.ok(!/[A-Za-z0-9+/]{43}=/.test(text), 'ハッシュらしき値が含まれている');
});

test('点検: 比べるための指紋をファイルに残さない（監査ログ以外、data/ は1バイトも変わらない）', () => {
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true })
    .flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
  const snapshot = () => Object.fromEntries(walk(process.env.PASSPORT_DATA_DIR)
    .filter((f) => !f.includes(`${path.sep}audit${path.sep}`))
    .map((f) => [f, fs.readFileSync(f, 'utf8')]));
  const before = snapshot();
  checkup.run(alice.id, { now: Date.now() + 10 * 60 * 1000 });
  assert.deepStrictEqual(snapshot(), before);
  checkup._resetThrottle();
});

test('点検: Vault ごとに監査ログに残り、owner の履歴に出る（使い回しとして挙げたアイテムを含む）', () => {
  const entries = audit.recent({ limit: 50 }).filter((e) => e.event === 'vault.checkup' && e.actor === alice.id);
  const vaultIds = [...new Set(entries.map((e) => e.vaultId))].sort();
  assert.deepStrictEqual(vaultIds, [aliceVault.id, sharedVault.id].sort());
  const shared = entries.find((e) => e.vaultId === sharedVault.id);
  // 使い回しは ID を切り詰めずに全部書く（長いタイトルのおとりで押し出されないように）
  assert.ok(shared.note.includes(ids.reuseB) && shared.note.includes(ids.reuseB2), shared.note);
  // 共有 Vault の記録に、アリスの別の Vault のアイテム（使い回しA）は載らない
  assert.ok(!entries.filter((e) => e.vaultId === sharedVault.id).some((e) => e.note.includes(ids.reuseA)));
  // 共有 Vault の owner（ボブ）は、アリスが点検したことを自分の履歴で見られる
  assert.ok(activity.forUser(bob.id).some((e) => e.event === 'vault.checkup' && e.relation === 'vault' && e.actorName === 'alice'));
  // 見られないボブの Vault には記録しない
  assert.ok(!entries.some((e) => e.vaultId === bobVault.id));
});

test('点検: 続けて実行すると断られる', () => {
  checkup._resetThrottle();
  checkup.run(alice.id);
  assert.throws(() => checkup.run(alice.id), (e) => e.status === 429);
  // 時間が経てばできる
  assert.ok(checkup.run(alice.id, { now: Date.now() + checkup.RUN_INTERVAL_MS + 1000 }));
});

test('点検: 巻き戻された値は「読めない」として出し、比較に使わない', () => {
  checkup._resetThrottle();
  const file = `vaults/${aliceVault.id}/items/${ids.fine}.json`;
  const before = store.readJson(file);
  items.update(aliceVault.id, ids.fine, { version: before.version, secrets: { password: SHARED } }, { actor: alice.id });
  const after = store.readJson(file);
  // 古い世代の封筒を貼り戻す
  store.writeJson(file, { ...after, secrets: { password: before.secrets.password } });
  const r = checkup.run(alice.id);
  assert.ok(r.unreadable.some((u) => u.itemId === ids.fine && u.reason === 'rollback'));
  assert.ok(!r.reused.some((g) => g.some((x) => x.itemId === ids.fine)));
});

test('点検: 監査ログに書けなければ結果を返さない', () => {
  checkup._resetThrottle();
  const auditDir = path.join(process.env.PASSPORT_DATA_DIR, 'audit');
  const files = fs.readdirSync(auditDir);
  for (const f of files) fs.chmodSync(path.join(auditDir, f), 0o400);
  try {
    if (process.getuid && process.getuid() === 0) return; // root は書けてしまうので確かめられない
    assert.throws(() => checkup.run(alice.id), /監査ログを書けない/);
  } finally {
    for (const f of files) fs.chmodSync(path.join(auditDir, f), 0o600);
  }
});

test('点検: viewer として入っている Vault（グループ経由を含む）は復号して調べない。期限のリマインドは出る', () => {
  checkup._resetThrottle();
  const admin = users.create({ username: 'admin', password: 'a-long-enough-pass', role: 'admin' });
  const carol = users.create({ username: 'carol', password: 'a-long-enough-pass' });
  const g = groups.create({ name: '閲覧係', actor: admin.id });
  groups.addMember(g.id, { userId: carol.id, actor: admin.id });
  vaults.addGroup(aliceVault.id, { groupId: g.id, role: 'viewer', actor: alice.id });
  const r = checkup.run(carol.id);
  assert.strictEqual(r.examined, 0);
  assert.deepStrictEqual([r.weak, r.reused, r.old], [[], [], []]);
  assert.ok(!audit.recent({ limit: 50 }).some((e) => e.event === 'vault.checkup' && e.actor === carol.id));
  assert.ok(checkup.reminders(carol.id).items.some((d) => d.title === '証明書'));
  // editor に上げれば調べられる
  vaults.updateGroup(aliceVault.id, { groupId: g.id, role: 'editor', actor: alice.id });
  checkup._resetThrottle();
  assert.ok(checkup.run(carol.id).examined > 0);
  vaults.removeGroup(aliceVault.id, { groupId: g.id, actor: alice.id });
});

test('点検: examinePasswords は中で権限を確かめる（呼び出し側の誤用で全件を出さない）', () => {
  assert.throws(() => items.examinePasswords(bobVault.id, { actor: alice.id }, () => {}), (e) => e.code === 'FORBIDDEN');
  assert.throws(() => items.examinePasswords(bobVault.id, {}, () => {}), /actor/);
});

test('点検: 暗号文が壊れたものは「復号できない」、Vault の鍵が壊れた Vault は「鍵を開けられない」として出し、ほかは続ける', () => {
  checkup._resetThrottle();
  const itemFile = `vaults/${aliceVault.id}/items/${ids.old}.json`;
  const originalItem = store.readJson(itemFile);
  const broken = JSON.parse(JSON.stringify(originalItem));
  const ct = Buffer.from(broken.secrets.password.envelope.ct, 'base64');
  ct[0] ^= 0xff;
  broken.secrets.password.envelope.ct = ct.toString('base64');
  store.writeJson(itemFile, broken);

  const vaultFile = `vaults/${sharedVault.id}/vault.json`;
  const originalVault = store.readJson(vaultFile);
  const badVault = JSON.parse(JSON.stringify(originalVault));
  const wrapped = badVault.wrappedKeys[0];
  const field = ['ct', 'ciphertext', 'wrapped'].find((k) => typeof (wrapped.envelope || wrapped)[k] === 'string');
  const holder = wrapped.envelope || wrapped;
  const bytes = Buffer.from(holder[field], 'base64');
  bytes[0] ^= 0xff;
  holder[field] = bytes.toString('base64');
  store.writeJson(vaultFile, badVault);
  try {
    const r = checkup.run(alice.id);
    assert.ok(r.unreadable.some((u) => u.itemId === ids.old && u.reason === 'tampered'));
    assert.ok(r.unreadable.some((u) => u.vaultId === sharedVault.id && u.reason === 'vault_key'));
    assert.ok(r.weak.some((w) => w.itemId === ids.weak), 'ほかの Vault の点検が止まった');
  } finally {
    store.writeJson(itemFile, { ...store.readJson(itemFile), secrets: originalItem.secrets });
    store.writeJson(vaultFile, { ...store.readJson(vaultFile), wrappedKeys: originalVault.wrappedKeys });
  }
});

test('点検: 失敗で終わっても、続けての実行は断られる', () => {
  checkup._resetThrottle();
  const auditDir = path.join(process.env.PASSPORT_DATA_DIR, 'audit');
  const files = fs.readdirSync(auditDir);
  if (process.getuid && process.getuid() === 0) return;
  for (const f of files) fs.chmodSync(path.join(auditDir, f), 0o400);
  try {
    assert.throws(() => checkup.run(alice.id), /監査ログ/);
  } finally {
    for (const f of files) fs.chmodSync(path.join(auditDir, f), 0o600);
  }
  assert.throws(() => checkup.run(alice.id), (e) => e.status === 429);
});

test('強さ: 判定の目安', () => {
  const strength = require('../lib/strength');
  assert.deepStrictEqual(strength.weaknesses('xK9#mQ2$vL8@pR4w'), []);
  assert.ok(strength.weaknesses('short1').includes('short'));
  assert.ok(strength.weaknesses('Password123!').includes('common'));
  assert.ok(strength.weaknesses('aaaaaaaaaaaa').includes('simple'));
});
