'use strict';
// グループ。Vault の共有を、人ではなくグループ単位で行うためのもの。
// data/groups/<id>.json に1グループ1ファイル。
//
// グループそのものは「誰が入っているか」だけを持つ。
// どの Vault にどの権限で入っているかは、Vault 側（vault.json の groups）が持つ。
// 権限の判定は vaults.js の roleOf に閉じ、ここでは判定しない。
//
// グループを作る・人を出し入れする・消すのは管理者だけ。
// Vault の owner は、既にあるグループを自分の Vault の共有に足せる。

const crypto = require('crypto');
const store = require('./store');
const audit = require('./audit');

function groupPath(id) {
  store.assertValidId(id, 'グループID');
  return `groups/${id}.json`;
}

function list() {
  return store.listJson('groups').sort((a, b) => String(a.name || '').localeCompare(String(b.name || ''), 'ja'));
}

function get(id) {
  if (!store.isValidId(id)) return null;
  return store.readJson(groupPath(id));
}

// その人が入っているグループの ID。権限の判定で何度も使うので、
// 呼び出し側で1回だけ求めて使い回せるようにしてある（vaults.roleOf の第3引数）。
function groupIdsOfUser(userId) {
  if (!userId) return [];
  return list().filter((g) => (g.members || []).includes(userId)).map((g) => g.id);
}

function normalizeName(name) {
  const trimmed = String(name || '').trim();
  if (!trimmed) throw new Error('グループ名を入力してください');
  if (trimmed.length > 64) throw new Error('グループ名は64文字以内にしてください');
  return trimmed;
}

function create({ name, description = '', actor }) {
  const trimmed = normalizeName(name);
  if (list().some((g) => g.name === trimmed)) throw new Error('同じ名前のグループがあります');
  const now = new Date().toISOString();
  const group = {
    id: crypto.randomUUID(),
    name: trimmed,
    description: String(description || '').slice(0, 512),
    members: [],
    createdAt: now,
    createdBy: actor,
    updatedAt: now,
    version: 1
  };
  store.writeJson(groupPath(group.id), group);
  audit.record('group.create', { actor, target: group.id, note: trimmed });
  return group;
}

function update(id, patch, { actor }) {
  const group = get(id);
  if (!group) throw new Error('グループが見つかりません');
  const allowed = {};
  if (patch.name !== undefined) {
    const trimmed = normalizeName(patch.name);
    if (list().some((g) => g.name === trimmed && g.id !== id)) throw new Error('同じ名前のグループがあります');
    allowed.name = trimmed;
  }
  if (patch.description !== undefined) allowed.description = String(patch.description).slice(0, 512);
  const updated = store.updateJson(groupPath(id), null, (current) => ({ ...current, ...allowed }));
  audit.record('group.update', { actor, target: id, note: Object.keys(allowed).join(',') });
  return updated;
}

// 管理者が自分自身をグループに入れることはできない。
// グループが共有先になっている Vault に、緊急アクセス（理由が必須で、監査ログに大きく残る）を
// 通らずに入れてしまうため。入る必要があるなら、別の管理者に入れてもらう。
//
// これは境界ではなく「うっかり」を防ぐガードレール。管理者は、ユーザーを作ってそのユーザーを入れる、
// パスワードをリセットしてなりすます、別の管理者と入れ合う、で迂回できる。
// 管理者＝運用者本人を信頼する前提（docs/crypto.md）で受け入れている。
// どの経路でも監査ログには残る（user.create / user.password_reset / group.member_add）。
function addMember(id, { userId, actor }) {
  const group = get(id);
  if (!group) throw new Error('グループが見つかりません');
  const target = require('./users').get(userId);
  if (!target) throw new Error('そのユーザーが見つかりません');
  // 無効化中の人を入れておくと、有効化した瞬間に（グループの記録なしに）Vault に入れるようになる
  if (target.status !== 'active') throw new Error('無効化されているユーザーはグループに入れられません');
  if (userId === actor) {
    throw new Error('自分自身をグループに入れることはできません。別の管理者に入れてもらってください');
  }
  if ((group.members || []).includes(userId)) throw new Error('その人はすでにグループに入っています');
  // 入れたことで見られるようになる Vault を、名前で残す（後から「なぜ見られたか」を追えるように）
  const gained = require('./vaults').list()
    .filter((v) => (v.groups || []).some((g) => g.groupId === id))
    .map((v) => `${v.name}(${v.groups.find((g) => g.groupId === id).role})`);
  return audit.recordBefore('group.member_add', {
    actor, target: userId,
    note: `グループ ${group.name}${gained.length ? ` → ${gained.join('、')}` : ''}`
  }, () => store.updateJson(groupPath(id), null, (current) => ({
    ...current, members: [...new Set([...(current.members || []), userId])]
  })));
}

function removeMember(id, { userId, actor }) {
  const group = get(id);
  if (!group) throw new Error('グループが見つかりません');
  if (!(group.members || []).includes(userId)) throw new Error('その人はグループに入っていません');
  const updated = store.updateJson(groupPath(id), null, (current) => ({
    ...current, members: (current.members || []).filter((m) => m !== userId)
  }));
  // グループから外した瞬間に、グループ経由で入っていた Vault には入れなくなる
  // （権限は毎回グループを読み直して判定するため、キャッシュは無い）
  audit.record('group.member_remove', { actor, target: userId, note: `グループ ${group.name}` });
  return updated;
}

// 使われているグループは消させない。消すと、それで共有していた人が
// 知らないうちに Vault に入れなくなるので、先に Vault 側から外してもらう。
function remove(id, { actor }) {
  const group = get(id);
  if (!group) throw new Error('グループが見つかりません');
  const vaults = require('./vaults');
  const usedBy = vaults.list().filter((v) => (v.groups || []).some((g) => g.groupId === id));
  if (usedBy.length > 0) {
    throw new Error(`このグループは ${usedBy.length} 個の Vault で使われています（${usedBy.map((v) => v.name).join('、')}）。先に共有から外してください`);
  }
  store.deleteFile(groupPath(id));
  audit.record('group.delete', { actor, target: id, note: group.name });
  return true;
}

module.exports = { list, get, groupIdsOfUser, create, update, addMember, removeMember, remove };
