'use strict';
// 自分の履歴。監査ログのうち、本人に見せてよい分だけを切り出す。
//
// 見せるもの（relation）:
//   self    … 自分が行った操作（ログイン・閲覧・変更など全部）
//   account … 自分のアカウントに対して起きたこと
//             ・ほかの人が自分を対象に行った操作（パスワードのリセット、Vault やグループへの追加など）
//             ・自分のユーザー名へのログイン試行（試行制限で止められたものを含む）
//   vault   … 自分が owner の Vault で、ほかの人が行った操作（秘密の閲覧・コピー・入力・変更など）
//
// 見せないもの:
//   ・editor / viewer として入っている Vault での、ほかの人の操作（見せてよい範囲を owner に限る）
//   ・ほかの人の操作の接続元 IP（自分のアカウントへのログイン試行だけは見せる。狙われているかを知るため）
//
// owner は「個人で入っている owner」と同じ（グループには owner を付けられない。lib/vaults.js 冒頭）。

const audit = require('./audit');
const vaults = require('./vaults');
const users = require('./users');
const store = require('./store');

const LOGIN_EVENTS = new Set(['login.success', 'login.fail', 'login.locked']);
const VAULT_EVENT_PREFIXES = ['item.', 'vault.'];

function forUser(userId, { limit = 200, months = 3 } = {}) {
  const me = users.get(userId);
  if (!me) return [];
  const mark = `試行の印 ${users.attemptMark(me.username)}`;

  const accessible = new Map(); // vaultId -> role
  for (const v of vaults.listForUser(userId)) accessible.set(v.id, v.role);
  const owned = new Set([...accessible].filter(([, role]) => role === 'owner').map(([id]) => id));

  const relationOf = (entry) => {
    if (entry.actor === userId) return 'self';
    // 自分のユーザー名への試行。存在するユーザーの失敗は actor が付き、止められたものは印だけが残る
    if (LOGIN_EVENTS.has(entry.event) && !entry.actor && entry.note === mark) return 'account';
    if (entry.target === userId) return 'account';
    if (entry.vaultId && owned.has(entry.vaultId)
      && (VAULT_EVENT_PREFIXES.some((p) => entry.event.startsWith(p)) || entry.event === 'access.denied')) {
      return 'vault';
    }
    return null;
  };

  const entries = audit.scan({ limit, months, filter: (entry) => !!relationOf(entry) });

  const nameCache = new Map();
  const nameOf = (id) => {
    if (!id) return null;
    if (!nameCache.has(id)) {
      const u = users.get(id);
      nameCache.set(id, u ? (u.displayName || u.username) : '(削除されたユーザー)');
    }
    return nameCache.get(id);
  };
  const vaultNameCache = new Map();
  const vaultNameOf = (vaultId) => {
    if (!vaultId || !accessible.has(vaultId)) return null; // 今入っていない Vault の名前は出さない
    if (!vaultNameCache.has(vaultId)) vaultNameCache.set(vaultId, (vaults.get(vaultId) || {}).name || null);
    return vaultNameCache.get(vaultId);
  };
  const itemTitleCache = new Map();
  const itemTitleOf = (vaultId, itemId) => {
    if (!vaultId || !itemId || !accessible.has(vaultId)) return null;
    const key = `${vaultId}/${itemId}`;
    if (!itemTitleCache.has(key)) {
      let title = null;
      try {
        const item = store.readJson(`vaults/${vaultId}/items/${itemId}.json`)
          || store.readJson(`vaults/${vaultId}/trash/${itemId}.json`);
        title = item ? item.title : null;
      } catch {
        title = null;
      }
      itemTitleCache.set(key, title);
    }
    return itemTitleCache.get(key);
  };

  return entries.map((entry) => {
    const relation = relationOf(entry);
    const showIp = relation === 'self' || (relation === 'account' && LOGIN_EVENTS.has(entry.event));
    return {
      at: entry.at,
      event: entry.event,
      eventLabel: audit.EVENTS[entry.event] || entry.event,
      relation,
      actorName: entry.actor ? (entry.actor === userId ? '自分' : nameOf(entry.actor)) : null,
      ip: showIp ? entry.ip : null,
      result: entry.result,
      field: entry.field,
      vaultName: vaultNameOf(entry.vaultId),
      itemTitle: itemTitleOf(entry.vaultId, entry.itemId),
      note: entry.note
    };
  });
}

module.exports = { forUser };
