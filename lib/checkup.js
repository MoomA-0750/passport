'use strict';
// 点検とリマインド。
//
// reminders … 期限切れ・期限間近（ローテーション周期と有効期限）。平文のメタデータだけで数えるので復号しない。
//             ナビゲーションのバッジに使う。監査ログには残さない。
// run       … 弱い・使い回し・古い・期限。パスワードを復号して調べる。
//
// 守っている線（docs/crypto.md「点検」）:
//   ・復号して調べるのは、自分が editor 以上の Vault だけ（直せる人だけが見る。viewer は値を取り出せる立場だが、
//     アイテムごとの記録を残さずに「弱い」「同じ値」を一覧で知る道具にはしない）
//   ・**使い回しは同じ Vault の中だけで比べる。** Vault をまたいで比べると、自分が editor の Vault に推測した値を置き、
//     ほかの Vault（自分では値を読めないもの、または押し付けられて入った他人の Vault）の値と同じかを
//     アイテムごとの記録なしに確かめる道具になる（outer gate で Codex と横断レビューが指摘）
//   ・値は返さない。返すのはアイテムの組・タイトル・理由だけ
//   ・比べるための指紋をファイルに保存しない。点検のたびに、その場限りの乱数鍵で HMAC を取って比べ、捨てる
//     （盗まれた data/ に「この2つは同じ」「これは弱い」という手がかりを残さない）
//   ・監査ログに残す。Vault ごとに1行（owner が「自分の履歴」で気づけるように）。
//     使い回しの判定は「値を知っている別のアイテムと同じか」を確かめる道具にもなりうるため、
//     使い回しとして挙げたアイテムを記録に含め、連続実行も制限する
//   ・監査ログに残せないなら結果を返さない（秘密の取り出しと同じ扱い）

const crypto = require('crypto');
const vaults = require('./vaults');
const items = require('./items');
const audit = require('./audit');
const strength = require('./strength');
const store = require('./store');

const DAY_MS = 24 * 60 * 60 * 1000;
const SOON_DAYS = 30;
const DEFAULT_OLD_DAYS = 365;
const RUN_INTERVAL_MS = 30 * 1000;

const lastRunAt = new Map(); // userId -> 時刻

function daysBetween(fromMs, toMs) {
  return Math.floor((toMs - fromMs) / DAY_MS);
}

function passwordChangedAt(item) {
  const record = (item.secrets || {}).password;
  return (record && record.updatedAt) || item.createdAt || null;
}

// 1件の期限。無ければ空配列。
function dueOf(item, now = Date.now()) {
  const out = [];
  if (item.rotationDays && (item.secrets || {}).password) {
    const changed = Date.parse(passwordChangedAt(item));
    if (!Number.isNaN(changed)) {
      const dueAt = changed + item.rotationDays * DAY_MS;
      out.push({ kind: 'rotation', dueAt: new Date(dueAt).toISOString(), daysLeft: daysBetween(now, dueAt) });
    }
  }
  if (item.expiresAt) {
    // その日の終わりまで有効とみなす
    const dueAt = Date.parse(`${item.expiresAt}T23:59:59Z`);
    if (!Number.isNaN(dueAt)) out.push({ kind: 'expiry', dueAt: new Date(dueAt).toISOString(), daysLeft: daysBetween(now, dueAt) });
  }
  return out.filter((d) => d.daysLeft <= SOON_DAYS).map((d) => ({ ...d, overdue: d.daysLeft < 0 }));
}

function refOf(vault, item) {
  return { vaultId: vault.id, vaultName: vault.name, itemId: item.id, title: item.title, username: item.username || '' };
}

function accessibleVaults(userId) {
  return vaults.listForUser(userId).map((summary) => vaults.get(summary.id)).filter(Boolean);
}

function reminders(userId, { now = Date.now() } = {}) {
  const list = [];
  for (const vault of accessibleVaults(userId)) {
    for (const item of store.listJson(`vaults/${vault.id}/items`)) {
      for (const due of dueOf(item, now)) list.push({ ...refOf(vault, item), ...due });
    }
  }
  list.sort((a, b) => a.dueAt.localeCompare(b.dueAt));
  return {
    overdue: list.filter((d) => d.overdue).length,
    soon: list.filter((d) => !d.overdue).length,
    items: list
  };
}

class CheckupThrottled extends Error {
  constructor(seconds) {
    super(`点検は ${seconds} 秒ほど待ってからやり直してください`);
    this.status = 429;
  }
}

function run(userId, { ip = null, now = Date.now() } = {}) {
  const previous = lastRunAt.get(userId);
  if (previous && now - previous < RUN_INTERVAL_MS) {
    throw new CheckupThrottled(Math.ceil((RUN_INTERVAL_MS - (now - previous)) / 1000));
  }
  lastRunAt.set(userId, now);

  // その場限りの鍵。使い回しを見つけるための比較にだけ使い、関数を抜けたら捨てる
  const compareKey = crypto.randomBytes(32);
  const reused = [];
  const weak = [];
  const old = [];
  const unreadable = [];
  const due = [];
  const perVault = new Map(); // vaultId -> { examined, weak, old, unreadable }
  let examined = 0;

  try {
    for (const summary of vaults.listForUser(userId)) {
      if (vaults.ROLE_RANK[summary.role] < vaults.ROLE_RANK.editor) continue;
      const counts = { examined: 0, weak: 0, old: 0, unreadable: 0 };
      const byFingerprint = new Map(); // HMAC -> [ref]。Vault ごとに作り直す
      try {
        items.examinePasswords(summary.id, { actor: userId }, (item, value, problem) => {
          for (const d of dueOf(item, now)) due.push({ ...refOf(summary, item), ...d });
          if (value === undefined) return; // パスワードの無いアイテム
          const ref = refOf(summary, item);
          if (problem) {
            unreadable.push({ ...ref, reason: problem });
            counts.unreadable += 1;
            return;
          }
          examined += 1;
          counts.examined += 1;

          const reasons = strength.weaknesses(value);
          if (reasons.length) {
            weak.push({ ...ref, reasons });
            counts.weak += 1;
          }
          if (!item.rotationDays) {
            const changed = Date.parse(passwordChangedAt(item));
            if (!Number.isNaN(changed) && now - changed > DEFAULT_OLD_DAYS * DAY_MS) {
              old.push({ ...ref, changedAt: new Date(changed).toISOString(), ageDays: daysBetween(changed, now) });
              counts.old += 1;
            }
          }
          const fingerprint = crypto.createHmac('sha256', compareKey).update(value).digest('base64');
          if (!byFingerprint.has(fingerprint)) byFingerprint.set(fingerprint, []);
          byFingerprint.get(fingerprint).push(ref);
        });
      } catch (err) {
        if (err instanceof vaults.AccessError) continue; // 一覧に出た直後に外された
        if (!(err instanceof items.VaultKeyError)) throw err;
        // Vault の鍵を開けられない（マスターキーの取り違え・改ざん）。ほかの Vault の点検は続ける
        unreadable.push({ vaultId: summary.id, vaultName: summary.name, itemId: null, title: '(Vault の鍵を開けられません)', username: '', reason: 'vault_key' });
        counts.unreadable += 1;
      }
      for (const group of byFingerprint.values()) if (group.length > 1) reused.push(group);
      byFingerprint.clear();
      perVault.set(summary.id, counts);
    }
  } finally {
    compareKey.fill(0);
  }

  due.sort((a, b) => a.dueAt.localeCompare(b.dueAt));

  // 監査ログ。Vault ごとに1行、使い回しとして挙げたアイテムを含める
  const reusedIdsByVault = new Map();
  for (const group of reused) {
    for (const ref of group) {
      if (!reusedIdsByVault.has(ref.vaultId)) reusedIdsByVault.set(ref.vaultId, []);
      reusedIdsByVault.get(ref.vaultId).push(ref.itemId);
    }
  }
  for (const [vaultId, counts] of perVault) {
    if (counts.examined === 0 && counts.unreadable === 0) continue;
    const reusedIds = reusedIdsByVault.get(vaultId) || [];
    const logged = audit.record('vault.checkup', {
      actor: userId, vaultId, ip,
      note: `調べた ${counts.examined} / 弱い ${counts.weak} / 古い ${counts.old} / 読めない ${counts.unreadable}`
        // 切り詰めない。長いタイトルのおとりで狙ったアイテムを記録から押し出されないよう、ID だけを全部書く
        + (reusedIds.length ? ` / 使い回し: ${reusedIds.join(' ')}` : '')
    });
    if (!logged) throw new Error('監査ログを書けないため、点検の結果を出せません。管理者に連絡してください');
  }

  return {
    checkedAt: new Date(now).toISOString(),
    examined,
    weak,
    reused,
    old,
    due,
    unreadable
  };
}

module.exports = { reminders, run, dueOf, SOON_DAYS, DEFAULT_OLD_DAYS, RUN_INTERVAL_MS, _resetThrottle: () => lastRunAt.clear() };
