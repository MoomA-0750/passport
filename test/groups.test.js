'use strict';
// グループでの共有のテスト。
// 実効ロールの計算そのものを変えたので、「入れる」だけでなく「外したら入れなくなる」
// 「グループ経由では越えられない線」を中心に見る。

const os = require('os');
const path = require('path');
const fs = require('fs');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-groups-test-'));
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
const audit = require('../lib/audit');

store.init();
keyring.unlock({ allowGenerate: true });

test.after(() => {
  fs.rmSync(TMP, { recursive: true, force: true });
});

const forbidden = (e) => e.code === 'FORBIDDEN';

let admin;
let owner;
let alice;
let bob;
let vault;
let item;
let infra;

test('準備', () => {
  admin = users.create({ username: 'admin', password: 'a-long-enough-pass', role: 'admin' });
  owner = users.create({ username: 'owner', password: 'a-long-enough-pass' });
  alice = users.create({ username: 'alice', password: 'a-long-enough-pass' });
  bob = users.create({ username: 'bob', password: 'a-long-enough-pass' });
  vault = vaults.create({ name: 'インフラ', ownerId: owner.id, actor: owner.id });
  item = items.create(vault.id, {
    title: 'vCenter', urls: ['https://vcenter.example.local'], secrets: { password: 'group-shared-secret' }
  }, { actor: owner.id });
  infra = groups.create({ name: 'インフラ担当', actor: admin.id });
});

test('グループ: 名前は必須で、重複できない', () => {
  assert.throws(() => groups.create({ name: '  ', actor: admin.id }));
  assert.throws(() => groups.create({ name: 'インフラ担当', actor: admin.id }), /同じ名前/);
});

test('グループ: Vault に足していなければ、グループに入っていても何も見えない', () => {
  groups.addMember(infra.id, { userId: alice.id, actor: admin.id });
  assert.strictEqual(vaults.roleOf(vaults.get(vault.id), alice.id), null);
  assert.throws(() => items.list(vault.id, alice.id), forbidden);
});

test('グループ: Vault の owner しかグループを共有先に足せない', () => {
  assert.throws(() => vaults.addGroup(vault.id, { groupId: infra.id, role: 'viewer', actor: alice.id }), forbidden);
  // 管理者でも、Vault の owner でなければ足せない
  assert.throws(() => vaults.addGroup(vault.id, { groupId: infra.id, role: 'viewer', actor: admin.id }), forbidden);
});

test('グループ: 共有先に足すと、グループの人が見られる（一覧・検索・拡張の候補にも出る）', () => {
  vaults.addGroup(vault.id, { groupId: infra.id, role: 'viewer', actor: owner.id });
  const fresh = vaults.get(vault.id);
  assert.strictEqual(vaults.roleOf(fresh, alice.id), 'viewer');
  assert.strictEqual(items.revealSecret(vault.id, item.id, 'password', { actor: alice.id }), 'group-shared-secret');

  const listed = vaults.listForUser(alice.id).find((v) => v.id === vault.id);
  assert.ok(listed);
  assert.strictEqual(listed.viaGroup, true);
  assert.ok(items.search(alice.id, 'vCenter').length > 0);
  assert.ok(items.matchHost(alice.id, 'vcenter.example.local', { scheme: 'https' }).length > 0);

  // グループに入っていない人には出ない
  assert.strictEqual(vaults.listForUser(bob.id).length, 0);
  assert.strictEqual(items.search(bob.id, 'vCenter').length, 0);
});

test('グループ: viewer のグループでは書けない', () => {
  assert.throws(() => items.create(vault.id, { title: 'x' }, { actor: alice.id }), forbidden);
  assert.throws(() => vaults.addMember(vault.id, { userId: bob.id, role: 'viewer', actor: alice.id }), forbidden);
});

test('実効ロール: 個人とグループのうち強いほうになる', () => {
  // 個人では editor、グループは viewer → editor
  vaults.addMember(vault.id, { userId: alice.id, role: 'editor', actor: owner.id });
  assert.strictEqual(vaults.roleOf(vaults.get(vault.id), alice.id), 'editor');
  // 個人を viewer に下げ、グループを editor に上げる → editor
  vaults.updateMember(vault.id, { userId: alice.id, role: 'viewer', actor: owner.id });
  vaults.updateGroup(vault.id, { groupId: infra.id, role: 'editor', actor: owner.id });
  assert.strictEqual(vaults.roleOf(vaults.get(vault.id), alice.id), 'editor');
  const sources = vaults.roleSources(vaults.get(vault.id), alice.id);
  assert.deepStrictEqual(sources.map((s) => `${s.type}:${s.role}`).sort(), ['group:editor', 'user:viewer']);
  // 戻す
  vaults.updateGroup(vault.id, { groupId: infra.id, role: 'viewer', actor: owner.id });
  vaults.removeMember(vault.id, { userId: alice.id, actor: owner.id });
  assert.strictEqual(vaults.roleOf(vaults.get(vault.id), alice.id), 'viewer');
});

test('グループには owner を付けられない（管理者がグループで Vault を乗っ取れる人を作れないように）', () => {
  assert.throws(() => vaults.updateGroup(vault.id, { groupId: infra.id, role: 'owner', actor: owner.id }), /owner を付けられません/);
  const g = groups.create({ name: 'owner にしたい', actor: admin.id });
  assert.throws(() => vaults.addGroup(vault.id, { groupId: g.id, role: 'owner', actor: owner.id }), /owner を付けられません/);
  groups.remove(g.id, { actor: admin.id });
});

test('ファイルでグループに owner と書かれていても、editor として扱う', () => {
  const file = `vaults/${vault.id}/vault.json`;
  const original = store.readJson(file);
  store.writeJson(file, { ...original, groups: original.groups.map((g) => ({ ...g, role: 'owner' })) });
  try {
    assert.strictEqual(vaults.roleOf(vaults.get(vault.id), alice.id), 'editor');
    assert.throws(() => vaults.addMember(vault.id, { userId: alice.id, role: 'owner', actor: alice.id }), forbidden);
  } finally {
    store.writeJson(file, { ...store.readJson(file), groups: original.groups });
  }
});

test('グループ経由の editor は、完全削除・Vault の削除・共有の変更ができない', () => {
  vaults.updateGroup(vault.id, { groupId: infra.id, role: 'editor', actor: owner.id });
  try {
    const doomed = items.create(vault.id, { title: 'ゴミ箱へ' }, { actor: alice.id });
    items.remove(vault.id, doomed.id, { actor: alice.id });
    assert.throws(() => items.purge(vault.id, doomed.id, { actor: alice.id }), forbidden);
    assert.throws(() => vaults.remove(vault.id, { actor: alice.id }), forbidden);
    assert.throws(() => vaults.updateGroup(vault.id, { groupId: infra.id, role: 'viewer', actor: alice.id }), forbidden);
    assert.throws(() => vaults.removeGroup(vault.id, { groupId: infra.id, actor: alice.id }), forbidden);
    assert.throws(() => vaults.removeMember(vault.id, { userId: owner.id, actor: alice.id }), forbidden);
    items.restore(vault.id, doomed.id, { actor: owner.id });
    items.remove(vault.id, doomed.id, { actor: owner.id });
    items.purge(vault.id, doomed.id, { actor: owner.id });
  } finally {
    vaults.updateGroup(vault.id, { groupId: infra.id, role: 'viewer', actor: owner.id });
  }
});

test('最後の owner: 個人の owner が1人なら下げられない・外せない', () => {
  assert.throws(() => vaults.updateMember(vault.id, { userId: owner.id, role: 'viewer', actor: owner.id }), /最後の owner/);
  assert.throws(() => vaults.removeMember(vault.id, { userId: owner.id, actor: owner.id }), /最後の owner/);
});

test('グループから外すと、その場で入れなくなる', () => {
  assert.strictEqual(vaults.roleOf(vaults.get(vault.id), alice.id), 'viewer');
  groups.removeMember(infra.id, { userId: alice.id, actor: admin.id });
  assert.strictEqual(vaults.roleOf(vaults.get(vault.id), alice.id), null);
  assert.throws(() => items.revealSecret(vault.id, item.id, 'password', { actor: alice.id }), forbidden);
  assert.strictEqual(items.search(alice.id, 'vCenter').length, 0);
  assert.strictEqual(items.matchHost(alice.id, 'vcenter.example.local', { scheme: 'https' }).length, 0);
});

test('Vault からグループを外すと、グループの人は入れなくなる', () => {
  groups.addMember(infra.id, { userId: bob.id, actor: admin.id });
  assert.strictEqual(vaults.roleOf(vaults.get(vault.id), bob.id), 'viewer');
  vaults.removeGroup(vault.id, { groupId: infra.id, actor: owner.id });
  assert.strictEqual(vaults.roleOf(vaults.get(vault.id), bob.id), null);
  assert.throws(() => items.list(vault.id, bob.id), forbidden);
});

test('管理者は自分自身をグループに入れられない（緊急アクセスの迂回になるため）', () => {
  vaults.addGroup(vault.id, { groupId: infra.id, role: 'viewer', actor: owner.id });
  assert.throws(() => groups.addMember(infra.id, { userId: admin.id, actor: admin.id }), /自分自身/);
  assert.strictEqual(vaults.roleOf(vaults.get(vault.id), admin.id), null);
});

test('グループに人を入れると、見られるようになった Vault が監査ログに残る', () => {
  groups.addMember(infra.id, { userId: alice.id, actor: admin.id });
  const entry = audit.recent({ limit: 50 }).find((e) => e.event === 'group.member_add' && e.target === alice.id);
  assert.ok(entry);
  assert.match(entry.note, /インフラ\(viewer\)/);
});

test('管理者どうしなら入れられる（自分を入れられない制限は、うっかり防止のガードレール）', () => {
  const otherAdmin = users.create({ username: 'admin2', password: 'a-long-enough-pass', role: 'admin' });
  groups.addMember(infra.id, { userId: admin.id, actor: otherAdmin.id });
  assert.strictEqual(vaults.roleOf(vaults.get(vault.id), admin.id), 'viewer');
  groups.removeMember(infra.id, { userId: admin.id, actor: otherAdmin.id });
});

test('グループ: 無効化されているユーザーは入れられない', () => {
  const leaver = users.create({ username: 'leaver', password: 'a-long-enough-pass' });
  users.update(leaver.id, { status: 'disabled' }, { actor: admin.id });
  assert.throws(() => groups.addMember(infra.id, { userId: leaver.id, actor: admin.id }), /無効化/);
});

test('消えたグループの ID が Vault に残っていても、誰にも権限を与えず、owner が外せる', () => {
  const file = `vaults/${vault.id}/vault.json`;
  const ghost = '11111111-1111-4111-8111-111111111111';
  const current = store.readJson(file);
  store.writeJson(file, { ...current, groups: [...current.groups, { groupId: ghost, role: 'editor' }] });
  for (const u of [alice, bob, admin]) {
    assert.notStrictEqual(vaults.roleOf(vaults.get(vault.id), u.id), 'editor');
  }
  vaults.removeGroup(vault.id, { groupId: ghost, actor: owner.id });
  assert.ok(!vaults.get(vault.id).groups.some((g) => g.groupId === ghost));
});

test('グループ: 存在しないユーザーは入れられない', () => {
  assert.throws(() => groups.addMember(infra.id, { userId: '00000000-0000-4000-8000-000000000000', actor: admin.id }), /見つかりません/);
});

test('グループ: 共有先として使われているあいだは消せない', () => {
  assert.throws(() => groups.remove(infra.id, { actor: admin.id }), /Vault で使われています/);
  vaults.removeGroup(vault.id, { groupId: infra.id, actor: owner.id });
  assert.ok(groups.remove(infra.id, { actor: admin.id }));
  assert.strictEqual(groups.get(infra.id), null);
});

test('壊れたグループのファイルは読み飛ばし、権限は与えない', () => {
  const g = groups.create({ name: '壊れる', actor: admin.id });
  groups.addMember(g.id, { userId: bob.id, actor: admin.id });
  vaults.addGroup(vault.id, { groupId: g.id, role: 'editor', actor: owner.id });
  assert.strictEqual(vaults.roleOf(vaults.get(vault.id), bob.id), 'editor');
  fs.writeFileSync(path.join(process.env.PASSPORT_DATA_DIR, 'groups', `${g.id}.json`), '{ broken');
  assert.strictEqual(vaults.roleOf(vaults.get(vault.id), bob.id), null);
  assert.ok(vaults.listForUser(owner.id).some((v) => v.id === vault.id), '持ち主の一覧まで止まってしまう');
});
