'use strict';
// Vault（金庫）とメンバーシップ。1Password の Vault 共有にあたる部分。
//
// 構造: data/vaults/<vaultId>/vault.json と data/vaults/<vaultId>/items/<itemId>.json
//
// 鍵の持ち方（docs/crypto.md）:
//   Vault ごとにランダムな 32 バイトの Vault Key を作り、KEK で包んで vault.json に置く。
//   包み方を wrappedKeys という配列にしてあるのは、将来 E2E へ移すときに
//   「ユーザーの公開鍵で包んだもの」を足していけるようにするため。今は holder="server" の1件だけ。
//
// 権限（Vault 単位）:
//   viewer … 見る（秘密の復号を含む）
//   editor … viewer + アイテムの作成・更新・削除
//   owner  … editor + Vault 設定の変更・メンバー管理・Vault の削除
//
// 人に直接付けるほか、グループにも付けられる（viewer / editor だけ。owner は人にしか付かない）。
// 実効ロールは、人に付いたロールと所属グループのロールのうち一番強いもの（roleOf）。
//
// owner を人にしか付けない理由: owner は「メンバー管理」と「取り返しのつかない操作（完全削除など）」を含む。
// グループの中身は管理者が決めるので、グループに owner を付けられると、管理者が緊急アクセスを通らずに
// 「Vault を乗っ取れる人」を作れてしまう（グループ経由の owner が自分を個人 owner に足し、元の owner を外す）。
// この決まりにより「owner = 個人で入っている owner」が常に成り立つ。後工程（履歴の閲覧範囲、
// 自動化トークンの発行者）はこれに乗ってよい。
//
// グローバルな admin は、他人の Vault に自動ではアクセスできない。
// 必要なときは自分を owner として追加できるが、その操作は監査ログに残る（break-glass）。

const crypto = require('crypto');
const store = require('./store');
const envelope = require('./envelope');
const keyring = require('./keyring');
const audit = require('./audit');
const log = require('./logger')('passport:store');

const ROLES = ['viewer', 'editor', 'owner'];
const ROLE_RANK = { viewer: 1, editor: 2, owner: 3 };
const GROUP_ROLES = ['viewer', 'editor'];

class AccessError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AccessError';
    this.code = 'FORBIDDEN';
  }
}

function vaultPath(vaultId) {
  store.assertValidId(vaultId, 'Vault ID');
  return `vaults/${vaultId}/vault.json`;
}

// Vault Key を包むときの AAD。この暗号文が「この Vault の、この持ち主の分」であることを縛る。
function vaultKeyAad(vaultId, holder) {
  return Buffer.from(`passport/vault-key|${vaultId}|${holder}`, 'utf8');
}

function list() {
  const out = [];
  for (const dir of store.listDirs('vaults')) {
    if (!store.isValidId(dir)) continue;
    // 壊れた vault.json が1つあっても、ほかの Vault は使えるようにする。
    // 以前はここで例外が外まで飛び、無関係な Vault しか使っていない人まで
    // 一覧・検索・拡張の候補が全部止まっていた。
    try {
      const vault = store.readJson(`vaults/${dir}/vault.json`);
      if (vault) out.push(vault);
    } catch (err) {
      log.error(`Vault を読み飛ばしました（直すまで、この Vault は使えません）: ${dir}: ${err.message}`);
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name, 'ja'));
}

function get(vaultId) {
  if (!store.isValidId(vaultId)) return null;
  return store.readJson(vaultPath(vaultId));
}

function memberOf(vault, userId) {
  if (!vault || !Array.isArray(vault.members)) return null;
  return vault.members.find((m) => m.userId === userId) || null;
}

// 実効ロール。個人に付いたロールと、所属グループに付いたロールのうち一番強いもの。
//
// 権限の判定はすべてここを通す（requireAccess → can → roleOf）。
// ほかの場所で「メンバーかどうか」を見て判定を作らないこと。
//
// groupIds を渡すと、グループの読み出しを省ける（一覧で Vault ごとに呼ぶときのため）。
// 渡さなければその場で読む。キャッシュはしない。グループから外した瞬間に効かせるため。
function roleOf(vault, userId, groupIds = null) {
  if (!vault || !userId) return null;
  let best = null;
  const consider = (role) => {
    if (ROLE_RANK[role] && (!best || ROLE_RANK[role] > ROLE_RANK[best])) best = role;
  };

  const member = memberOf(vault, userId);
  if (member) consider(member.role);

  const vaultGroups = Array.isArray(vault.groups) ? vault.groups : [];
  if (vaultGroups.length > 0) {
    const mine = groupIds || require('./groups').groupIdsOfUser(userId);
    for (const entry of vaultGroups) {
      // グループは owner にならない。ファイルに owner と書かれていても editor として扱う
      if (mine.includes(entry.groupId)) consider(entry.role === 'owner' ? 'editor' : entry.role);
    }
  }
  return best;
}

// どこから権限を得ているか（画面で「グループ経由」と見せるため）
function roleSources(vault, userId, groupIds = null) {
  const sources = [];
  const member = memberOf(vault, userId);
  if (member) sources.push({ type: 'user', role: member.role });
  const mine = groupIds || require('./groups').groupIdsOfUser(userId);
  for (const entry of (vault.groups || [])) {
    if (mine.includes(entry.groupId)) sources.push({ type: 'group', groupId: entry.groupId, role: entry.role });
  }
  return sources;
}

function can(vault, userId, needed, groupIds = null) {
  const role = roleOf(vault, userId, groupIds);
  if (!role) return false;
  return ROLE_RANK[role] >= ROLE_RANK[needed];
}

// 最後の owner を守るときに数えるのは「個人に付いた owner」だけ。
// グループには owner を付けられないので、実効 owner と同じになるはずだが、
// ファイルが書き換えられていても誰も管理できない Vault を作らないよう、ここでも個人だけを数える。
function directOwners(vault, excludeUserId = null) {
  return (vault.members || []).filter((m) => m.role === 'owner' && m.userId !== excludeUserId);
}

// 権限チェックの入口。足りなければ投げる。呼び出し側で握りつぶさない。
function requireAccess(vaultId, userId, needed, { actor = null } = {}) {
  const vault = get(vaultId);
  if (!vault) throw new AccessError('Vault が見つかりません');
  if (!can(vault, userId, needed)) {
    audit.record('access.denied', {
      actor: actor || userId, vaultId, note: `${needed} が必要（現在: ${roleOf(vault, userId) || 'なし'}）`
    });
    throw new AccessError('この Vault を操作する権限がありません');
  }
  return vault;
}

// その人が入っている Vault の一覧。
function listForUser(userId) {
  const groupIds = require('./groups').groupIdsOfUser(userId);
  return list()
    .filter((vault) => !!roleOf(vault, userId, groupIds))
    .map((vault) => ({
      id: vault.id,
      name: vault.name,
      description: vault.description || '',
      icon: vault.icon || '🔐',
      role: roleOf(vault, userId, groupIds),
      viaGroup: !memberOf(vault, userId),
      memberCount: vault.members.length,
      groupCount: (vault.groups || []).length,
      itemCount: countItems(vault.id),
      createdAt: vault.createdAt,
      updatedAt: vault.updatedAt
    }));
}

function countItems(vaultId) {
  const dir = store.resolveInData(`vaults/${vaultId}/items`);
  const fs = require('fs');
  if (!fs.existsSync(dir)) return 0;
  return fs.readdirSync(dir).filter((n) => n.endsWith('.json') && !n.includes('.tmp-')).length;
}

function create({ name, description = '', icon = '🔐', ownerId, actor = null }) {
  const trimmed = String(name || '').trim();
  if (!trimmed) throw new Error('Vault 名を入力してください');
  if (trimmed.length > 64) throw new Error('Vault 名は64文字以内にしてください');
  if (!ownerId) throw new Error('作成者が必要です');

  const id = crypto.randomUUID();
  const vaultKey = envelope.randomKey();
  const now = new Date().toISOString();

  const vault = {
    id,
    name: trimmed,
    description: String(description).slice(0, 512),
    icon: String(icon).slice(0, 8) || '🔐',
    // 将来 E2E へ移すときは、ここに holder=<userId>, method=user-x25519-v1 を足していく
    wrappedKeys: [{
      holder: 'server',
      method: 'server-kek-v1',
      envelope: envelope.sealKey(keyring.kek(), vaultKey, vaultKeyAad(id, 'server'))
    }],
    members: [{ userId: ownerId, role: 'owner', addedAt: now, addedBy: actor || ownerId }],
    createdBy: ownerId,
    createdAt: now,
    updatedAt: now,
    version: 1
  };

  vaultKey.fill(0); // Buffer は潰す（base64 の文字列は消せない。envelope.js の注意を読む）
  store.ensureDir(store.resolveInData(`vaults/${id}/items`));
  store.writeJson(vaultPath(id), vault);
  audit.record('vault.create', { actor: actor || ownerId, vaultId: id, note: trimmed });
  log.info(`Vault を作成しました: ${trimmed}`);
  return vault;
}

// Vault Key を取り出す。アイテムの暗号・復号のたびに呼ばれる。
// 戻り値の Buffer は呼び出し側で使い終わったら fill(0) すること。
function unwrapKey(vault) {
  const wrapped = (vault.wrappedKeys || []).find((w) => w.holder === 'server' && w.method === 'server-kek-v1');
  if (!wrapped) {
    throw new Error(`Vault ${vault.id} にサーバー用の鍵がありません`);
  }
  try {
    return envelope.openKey(keyring.kek(), wrapped.envelope, vaultKeyAad(vault.id, 'server'));
  } catch (err) {
    throw new Error(
      `Vault ${vault.id} の鍵を復号できません。マスターキーが起動時と違う可能性があります: ${err.message}`
    );
  }
}

function update(vaultId, patch, { actor }) {
  requireAccess(vaultId, actor, 'owner');
  const allowed = {};
  if (patch.name !== undefined) {
    const trimmed = String(patch.name).trim();
    if (!trimmed) throw new Error('Vault 名を入力してください');
    allowed.name = trimmed.slice(0, 64);
  }
  if (patch.description !== undefined) allowed.description = String(patch.description).slice(0, 512);
  if (patch.icon !== undefined) allowed.icon = String(patch.icon).slice(0, 8) || '🔐';

  const updated = store.updateJson(vaultPath(vaultId), patch.version, (current) => ({ ...current, ...allowed }));
  audit.record('vault.update', { actor, vaultId, note: Object.keys(allowed).join(',') });
  return updated;
}

function addMember(vaultId, { userId, role = 'viewer', actor }) {
  if (!ROLES.includes(role)) throw new Error(`role は ${ROLES.join(' / ')} のどれかです`);
  const vault = requireAccess(vaultId, actor, 'owner');
  if (memberOf(vault, userId)) throw new Error('その人はすでにメンバーです');

  const updated = store.updateJson(vaultPath(vaultId), null, (current) => ({
    ...current,
    members: [...current.members, { userId, role, addedAt: new Date().toISOString(), addedBy: actor }]
  }));
  audit.record('vault.member_add', { actor, vaultId, target: userId, note: role });
  return updated;
}

function updateMember(vaultId, { userId, role, actor }) {
  if (!ROLES.includes(role)) throw new Error(`role は ${ROLES.join(' / ')} のどれかです`);
  const vault = requireAccess(vaultId, actor, 'owner');
  if (!memberOf(vault, userId)) throw new Error('その人はメンバーではありません');

  // owner が居なくなる変更は拒否する。誰も管理できない Vault を作らない。
  // 検査は書き込む直前の内容に対して行う（読んでから書くまでの間に変わっていても破れないように）
  const updated = store.updateJson(vaultPath(vaultId), null, (current) => {
    if (role !== 'owner' && directOwners(current, userId).length === 0) {
      throw new Error('最後の owner の権限は下げられません。先に別の owner を追加してください');
    }
    return {
      ...current,
      members: current.members.map((m) => (m.userId === userId ? { ...m, role } : m))
    };
  });
  audit.record('vault.member_update', { actor, vaultId, target: userId, note: role });
  return updated;
}

function removeMember(vaultId, { userId, actor }) {
  const vault = requireAccess(vaultId, actor, 'owner');
  if (!memberOf(vault, userId)) throw new Error('その人はメンバーではありません');

  const updated = store.updateJson(vaultPath(vaultId), null, (current) => {
    if (directOwners(current, userId).length === 0) {
      throw new Error('最後の owner は外せません。先に別の owner を追加してください');
    }
    return { ...current, members: current.members.filter((m) => m.userId !== userId) };
  });
  audit.record('vault.member_remove', { actor, vaultId, target: userId });
  return updated;
}

// --- グループでの共有 --------------------------------------------------------

function checkGroupRole(role) {
  if (role === 'owner') throw new Error('グループには owner を付けられません（owner は人にだけ付けます）');
  if (!GROUP_ROLES.includes(role)) throw new Error(`グループの role は ${GROUP_ROLES.join(' / ')} のどちらかです`);
}

function addGroup(vaultId, { groupId, role = 'viewer', actor }) {
  checkGroupRole(role);
  const vault = requireAccess(vaultId, actor, 'owner');
  const group = require('./groups').get(groupId);
  if (!group) throw new Error('グループが見つかりません');
  if ((vault.groups || []).some((g) => g.groupId === groupId)) throw new Error('そのグループはすでに共有先です');

  const updated = store.updateJson(vaultPath(vaultId), null, (current) => ({
    ...current,
    groups: [...(current.groups || []), { groupId, role, addedAt: new Date().toISOString(), addedBy: actor }]
  }));
  audit.record('vault.group_add', { actor, vaultId, target: groupId, note: `${group.name} (${role})` });
  return updated;
}

function updateGroup(vaultId, { groupId, role, actor }) {
  checkGroupRole(role);
  const vault = requireAccess(vaultId, actor, 'owner');
  if (!(vault.groups || []).some((g) => g.groupId === groupId)) throw new Error('そのグループは共有先ではありません');
  const updated = store.updateJson(vaultPath(vaultId), null, (current) => ({
    ...current,
    groups: (current.groups || []).map((g) => (g.groupId === groupId ? { ...g, role } : g))
  }));
  audit.record('vault.group_update', { actor, vaultId, target: groupId, note: role });
  return updated;
}

function removeGroup(vaultId, { groupId, actor }) {
  const vault = requireAccess(vaultId, actor, 'owner');
  if (!(vault.groups || []).some((g) => g.groupId === groupId)) throw new Error('そのグループは共有先ではありません');
  const updated = store.updateJson(vaultPath(vaultId), null, (current) => ({
    ...current,
    groups: (current.groups || []).filter((g) => g.groupId !== groupId)
  }));
  audit.record('vault.group_remove', { actor, vaultId, target: groupId });
  return updated;
}

// 管理者の緊急アクセス。持ち主が辞めた・不在のときに使う想定。
// 黙ってできてしまわないよう、理由を必須にして監査ログへ大きく残す。
function adminTakeOwnership(vaultId, { actor, reason }) {
  if (!reason || String(reason).trim().length < 5) {
    throw new Error('緊急アクセスには理由（5文字以上）が必要です');
  }
  const vault = get(vaultId);
  if (!vault) throw new Error('Vault が見つかりません');

  const now = new Date().toISOString();
  const updated = store.updateJson(vaultPath(vaultId), null, (current) => {
    const existing = current.members.find((m) => m.userId === actor);
    if (existing) {
      // 既にメンバーだった場合も、緊急アクセスで上げたことを残す。
      // 以前は印が付かず、共有画面で普通の owner と見分けが付かなかった。
      return {
        ...current,
        members: current.members.map((m) => (m.userId === actor
          ? { ...m, role: 'owner', viaBreakGlass: true, roleBeforeBreakGlass: m.role, breakGlassAt: now }
          : m))
      };
    }
    return { ...current, members: [...current.members, { userId: actor, role: 'owner', addedAt: now, addedBy: actor, viaBreakGlass: true, breakGlassAt: now }] };
  });
  audit.record('vault.member_add', {
    actor, vaultId, target: actor, result: 'break_glass',
    note: `管理者による緊急アクセス: ${String(reason).slice(0, 200)}`
  });
  log.warn(`管理者による緊急アクセス: vault=${vaultId} actor=${actor} 理由=${reason}`);
  return updated;
}

// Vault の削除。中のアイテムごと消えるので、空であることを求める。
function remove(vaultId, { actor }) {
  const fs = require('fs');
  requireAccess(vaultId, actor, 'owner');
  const remaining = countItems(vaultId);
  if (remaining > 0) {
    throw new Error(`アイテムが ${remaining} 件残っています。先に空にしてください`);
  }
  // Vault を消すと鍵ごと消え、ゴミ箱の中身も二度と復号できなくなる
  const trashDir = store.resolveInData(`vaults/${vaultId}/trash`);
  const trashed = fs.existsSync(trashDir)
    ? fs.readdirSync(trashDir).filter((n) => n.endsWith('.json') && !n.includes('.tmp-')).length
    : 0;
  if (trashed > 0) {
    throw new Error(`ゴミ箱に ${trashed} 件残っています。Vault を消すと二度と戻せないので、先にゴミ箱を空にしてください`);
  }
  fs.rmSync(store.resolveInData(`vaults/${vaultId}`), { recursive: true, force: true });
  audit.record('vault.delete', { actor, vaultId });
  return true;
}

module.exports = {
  ROLES,
  ROLE_RANK,
  GROUP_ROLES,
  AccessError,
  list,
  get,
  listForUser,
  roleOf,
  roleSources,
  can,
  requireAccess,
  create,
  update,
  unwrapKey,
  addMember,
  updateMember,
  removeMember,
  addGroup,
  updateGroup,
  removeGroup,
  adminTakeOwnership,
  remove,
  countItems
};
