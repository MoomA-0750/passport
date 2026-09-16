'use strict';
// ログイン中の端末と、自分の履歴のテスト。
// 「見せてよい範囲」を越えないことを中心に見る。

const os = require('os');
const path = require('path');
const fs = require('fs');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-activity-test-'));
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
const groups = require('../lib/groups');
const session = require('../lib/session');
const activity = require('../lib/activity');

store.init();
keyring.unlock({ allowGenerate: true });

test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

let admin; let owner; let editor; let viewer; let stranger;
let ownedVault; let sharedVault; let ownedItem; let sharedItem;

test('準備', () => {
  admin = users.create({ username: 'admin', password: 'a-long-enough-pass', role: 'admin' });
  owner = users.create({ username: 'owner', password: 'a-long-enough-pass' });
  editor = users.create({ username: 'editor', password: 'a-long-enough-pass' });
  viewer = users.create({ username: 'viewer', password: 'a-long-enough-pass' });
  stranger = users.create({ username: 'stranger', password: 'a-long-enough-pass' });

  ownedVault = vaults.create({ name: '持っている金庫', ownerId: owner.id, actor: owner.id });
  ownedItem = items.create(ownedVault.id, { title: '持っている鍵', secrets: { password: 'p1' } }, { actor: owner.id });
  vaults.addMember(ownedVault.id, { userId: editor.id, role: 'editor', actor: owner.id });

  // editor が owner、owner は viewer として入っている金庫
  sharedVault = vaults.create({ name: '人の金庫', ownerId: editor.id, actor: editor.id });
  sharedItem = items.create(sharedVault.id, { title: '人の鍵', secrets: { password: 'p2' } }, { actor: editor.id });
  vaults.addMember(sharedVault.id, { userId: owner.id, role: 'viewer', actor: editor.id });
  // viewer はグループ経由で持っている金庫を見る
  const g = groups.create({ name: '見る係', actor: admin.id });
  groups.addMember(g.id, { userId: viewer.id, actor: admin.id });
  vaults.addGroup(ownedVault.id, { groupId: g.id, role: 'viewer', actor: owner.id });

  users.authenticate('owner', 'a-long-enough-pass', { ip: '10.9.0.1' });
  users.authenticate('owner', 'wrong-password-x', { ip: '203.0.113.7' });
  items.revealSecret(ownedVault.id, ownedItem.id, 'password', { actor: editor.id, ip: '10.9.9.9' });
  items.revealSecret(ownedVault.id, ownedItem.id, 'password', { actor: viewer.id, purpose: 'copy', ip: '10.9.9.8' });
  items.revealSecret(sharedVault.id, sharedItem.id, 'password', { actor: editor.id, ip: '10.9.9.9' });
  items.revealSecret(sharedVault.id, sharedItem.id, 'password', { actor: owner.id, ip: '10.9.0.1' });
  users.resetPassword(owner.id, 'reset-by-admin-123', { actor: admin.id });
  assert.throws(() => items.revealSecret(ownedVault.id, ownedItem.id, 'password', { actor: stranger.id })); // 記録は残る
});

test('履歴: 自分の操作が出て、接続元も見える', () => {
  const mine = activity.forUser(owner.id).filter((e) => e.relation === 'self');
  const view = mine.find((e) => e.event === 'item.view_secret' && e.vaultName === '人の金庫');
  assert.ok(view);
  assert.strictEqual(view.ip, '10.9.0.1');
  assert.strictEqual(view.itemTitle, '人の鍵');
  assert.ok(mine.some((e) => e.event === 'login.success'));
});

test('履歴: 自分のアカウントへのログイン失敗は、相手の接続元つきで出る', () => {
  const fail = activity.forUser(owner.id).find((e) => e.event === 'login.fail' && e.relation === 'self');
  // 存在するユーザーの失敗は actor が付くので self として出る
  assert.ok(fail);
  assert.strictEqual(fail.ip, '203.0.113.7');
});

test('履歴: 試行制限で止められたログイン（actor なし）も、自分のユーザー名なら出る', () => {
  for (let i = 0; i < 8; i += 1) users.authenticate('owner', 'wrong-password-y', { ip: '198.51.100.3' });
  const throttled = activity.forUser(owner.id).filter((e) => e.relation === 'account' && e.result === 'throttled');
  assert.ok(throttled.length > 0);
  assert.strictEqual(throttled[0].ip, '198.51.100.3');
  // ほかの人の履歴には出ない
  assert.ok(!activity.forUser(editor.id).some((e) => e.result === 'throttled'));
});

test('履歴: 管理者にパスワードをリセットされたことが出る（接続元は出さない）', () => {
  const reset = activity.forUser(owner.id).find((e) => e.event === 'user.password_change' && e.relation === 'account');
  assert.ok(reset);
  assert.strictEqual(reset.actorName, 'admin');
  assert.strictEqual(reset.ip, null);
});

test('履歴: 自分が owner の Vault で、ほかの人（グループ経由を含む）が見た・コピーした記録が出る', () => {
  const others = activity.forUser(owner.id).filter((e) => e.relation === 'vault');
  assert.ok(others.some((e) => e.event === 'item.view_secret' && e.actorName === 'editor'));
  assert.ok(others.some((e) => e.event === 'item.copy_secret' && e.actorName === 'viewer'));
  // 権限の無い人が試したことも出る
  assert.ok(others.some((e) => e.event === 'access.denied'));
  // ほかの人の接続元は出さない
  assert.ok(others.every((e) => e.ip === null));
});

test('履歴: viewer / editor として入っている Vault での、ほかの人の操作は出ない', () => {
  // owner は「人の金庫」の viewer。そこで editor が見た記録は出てはいけない
  // （自分がその Vault に入れられた、という自分のアカウントへの記録は出てよい）
  const leaked = activity.forUser(owner.id)
    .filter((e) => e.vaultName === '人の金庫' && e.actorName !== '自分' && e.relation !== 'account');
  assert.deepStrictEqual(leaked, []);
  assert.ok(!activity.forUser(owner.id).some((e) => e.vaultName === '人の金庫' && e.event === 'item.view_secret' && e.actorName === 'editor'));
  // グループ経由の viewer にも、持っている金庫でのほかの人の操作は出ない
  const viewerSees = activity.forUser(viewer.id);
  assert.ok(viewerSees.every((e) => e.relation !== 'vault'));
  assert.ok(!viewerSees.some((e) => e.actorName === 'editor'));
});

test('履歴: 今入っていない Vault の名前とアイテム名は出さない', () => {
  const seen = activity.forUser(stranger.id);
  const denied = seen.find((e) => e.event === 'access.denied');
  assert.ok(denied);
  assert.strictEqual(denied.vaultName, null);
  assert.strictEqual(denied.itemTitle, null);
});

test('履歴: 秘密の値は含まれない', () => {
  const text = JSON.stringify(activity.forUser(owner.id));
  assert.ok(!text.includes('"p1"') && !text.includes('"p2"'));
  assert.ok(!text.includes('reset-by-admin-123'));
});

test('端末: 一覧にセッション ID も CSRF トークンも含まれない', () => {
  const a = session.create(owner, { ip: '10.0.0.1', userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/140', kind: 'web' });
  const b = session.create(owner, { ip: '10.0.0.2', kind: 'extension' });
  const list = session.listForUser(owner.id, { currentSessionId: a.id });
  assert.strictEqual(list.length, 2);
  const text = JSON.stringify(list);
  for (const secret of [a.id, b.id, a.session.csrfToken, b.session.csrfToken]) assert.ok(!text.includes(secret));
  assert.strictEqual(list.find((s) => s.current).kind, 'web');
  session.destroyAllForUser(owner.id);
});

test('端末: 他人の handle では切れない', () => {
  const mine = session.create(owner, { kind: 'web' });
  const theirs = session.create(editor, { kind: 'web' });
  const theirHandle = session.listForUser(editor.id)[0].handle;
  assert.strictEqual(session.destroyByHandle(owner.id, theirHandle), null);
  assert.ok(session.get(theirs.id), '他人のセッションが切れてしまった');
  const myHandle = session.listForUser(owner.id)[0].handle;
  assert.strictEqual(session.destroyByHandle(owner.id, myHandle), mine.id);
  assert.strictEqual(session.get(mine.id), null);
  session.destroyAllForUser(editor.id);
});

test('端末: この端末以外をすべて切る', () => {
  const keep = session.create(owner, { kind: 'web' });
  session.create(owner, { kind: 'extension' });
  session.create(owner, { kind: 'cli' });
  const other = session.create(editor, { kind: 'web' });
  assert.strictEqual(session.destroyOthersForUser(owner.id, keep.id), 2);
  assert.ok(session.get(keep.id));
  assert.ok(session.get(other.id), '他人のセッションまで切れてしまった');
  session.destroyAllForUser(owner.id);
  session.destroyAllForUser(editor.id);
});

test('端末: 最後の操作の時刻と接続元が更新される', () => {
  const realNow = Date.now;
  let now = realNow();
  Date.now = () => now;
  try {
    const s = session.create(owner, { ip: '10.0.0.1', kind: 'web' });
    now += 60 * 1000;
    session.touch(s.id, { ip: '10.0.0.99' });
    const [row] = session.listForUser(owner.id);
    assert.strictEqual(row.ip, '10.0.0.1');
    assert.strictEqual(row.lastIp, '10.0.0.99');
    assert.strictEqual(row.lastSeenAt, new Date(now).toISOString());
  } finally {
    Date.now = realNow;
    session.destroyAllForUser(owner.id);
  }
});

test('履歴: Vault から外されたあとは、その Vault の記録の備考（アイテム名など）も出さない', () => {
  vaults.removeMember(ownedVault.id, { userId: editor.id, actor: owner.id });
  const mine = activity.forUser(editor.id).filter((e) => e.event === 'item.view_secret');
  const fromOwned = mine.filter((e) => e.note && e.note.includes('持っている鍵'));
  assert.deepStrictEqual(fromOwned, []);
});

test('強さの判定: とても長い値でも時間がかからない（点検でサーバーを止めない）', () => {
  const strength = require('../lib/strength');
  const started = Date.now();
  strength.weaknesses(`${'1'.repeat(250000)}a`);
  assert.ok(Date.now() - started < 500, `${Date.now() - started}ms かかった`);
});
