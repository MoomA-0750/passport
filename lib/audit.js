'use strict';
// 追記専用の監査ログ。data/audit/YYYY-MM.jsonl に1行1イベント。
// 金庫は「誰がいつ何の秘密を見たか」が後から追えないと運用に使えないので、
// 閲覧（view_secret）も必ず記録する。
//
// ログに秘密そのものは絶対に書かない。書くのは「どのアイテムのどのフィールドを見たか」まで。

const store = require('./store');
const config = require('./config');
const log = require('./logger')('passport:audit');

const EVENTS = {
  'login.success': 'ログイン成功',
  'login.fail': 'ログイン失敗',
  'login.locked': 'ログイン失敗によるロック',
  'logout': 'ログアウト',
  'user.create': 'ユーザー作成',
  'user.update': 'ユーザー更新',
  'user.password_change': 'パスワード変更',
  'user.disable': 'ユーザー無効化',
  'user.enable': 'ユーザー有効化',
  'vault.create': 'Vault 作成',
  'vault.update': 'Vault 更新',
  'vault.delete': 'Vault 削除',
  'vault.member_add': 'Vault メンバー追加',
  'vault.member_update': 'Vault メンバー権限変更',
  'vault.member_remove': 'Vault メンバー削除',
  'item.create': 'アイテム作成',
  'item.update': 'アイテム更新',
  'item.delete': 'アイテム削除',
  'item.view_secret': '秘密の閲覧',
  'item.copy_secret': '秘密のコピー',
  'access.denied': '権限のない操作',
  'server.start': 'サーバー起動',
  'setup.complete': '初期セットアップ完了'
};

function monthFile(date = new Date()) {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  return `audit/${y}-${m}.jsonl`;
}

function record(event, detail = {}) {
  if (!config.audit.enabled) return;
  if (!EVENTS[event]) {
    // 未知のイベント名は綴り間違いの可能性が高いので、落とさず警告して残す
    log.warn(`未知の監査イベント名です: ${event}`);
  }
  const entry = {
    at: new Date().toISOString(),
    event,
    actor: detail.actor || null,          // ユーザーID
    actorName: detail.actorName || null,  // 表示用。後でユーザーを消しても誰かが分かるように
    ip: detail.ip || null,
    vaultId: detail.vaultId || null,
    itemId: detail.itemId || null,
    field: detail.field || null,
    target: detail.target || null,        // 操作対象のユーザーIDなど
    result: detail.result || 'ok',
    note: detail.note || null
  };
  try {
    store.appendLine(monthFile(), JSON.stringify(entry));
  } catch (err) {
    // 監査ログが書けないことは重大だが、書けないからといって利用者の操作を落とすと
    // かえって運用が止まる。警告に留めて、起動時チェックで気づけるようにする。
    log.error(`監査ログを書けませんでした: ${err.message}`);
  }
  log.debug(`${event} actor=${entry.actor || '-'} ${entry.itemId || entry.vaultId || ''}`);
}

// 直近のイベントを新しい順に読む。監査ログ画面用。
function recent({ limit = 200, months = 3 } = {}) {
  const out = [];
  const now = new Date();
  for (let i = 0; i < months && out.length < limit; i += 1) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1));
    const rel = monthFile(d);
    if (!store.exists(rel)) continue;
    const full = store.resolveInData(rel);
    const lines = require('fs').readFileSync(full, 'utf8').split('\n').filter(Boolean);
    for (let j = lines.length - 1; j >= 0 && out.length < limit; j -= 1) {
      try {
        out.push(JSON.parse(lines[j]));
      } catch {
        // 壊れた行は飛ばす
      }
    }
  }
  return out;
}

module.exports = { record, recent, EVENTS };
