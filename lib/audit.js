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
  'vault.checkup': 'パスワードの点検',
  'vault.group_add': 'Vault にグループを追加',
  'vault.group_update': 'Vault のグループの権限変更',
  'vault.group_remove': 'Vault からグループを外す',
  'group.create': 'グループ作成',
  'group.update': 'グループ変更',
  'group.delete': 'グループ削除',
  'group.member_add': 'グループに人を追加',
  'group.member_remove': 'グループから人を外す',
  'item.create': 'アイテム作成',
  'item.update': 'アイテム更新',
  'item.delete': 'アイテム削除（ゴミ箱へ）',
  'item.restore': 'アイテムをゴミ箱から戻す',
  'item.purge': 'アイテムを完全に削除',
  'item.view_secret': '秘密の閲覧',
  'item.copy_secret': '秘密のコピー',
  'item.fill_secret': '秘密を入力欄へ入力',
  'item.verify_secret': '秘密の照合',
  'access.denied': '権限のない操作',
  'session.revoke': 'ログイン中の端末を切断',
  'session.revoke_others': 'ほかの端末をすべて切断',
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
  log.debug(`${event} actor=${entry.actor || '-'} ${entry.itemId || entry.vaultId || ''}`);
  try {
    store.appendLine(monthFile(), JSON.stringify(entry));
    return true;
  } catch (err) {
    // 書けたかどうかを返す。秘密の取り出しは、書けなければ値を返さない（items.js）。
    // それ以外の操作は止めない（止めるとかえって運用が止まるため）。
    log.error(`監査ログを書けませんでした: ${err.message}`);
    return false;
  }
}

// 起動時に、監査ログへ書けるかを確かめる。書けない状態で起動すると、
// 秘密の取り出しがすべて失敗するので、先に気づけるようにする。
function checkWritable() {
  if (!config.audit.enabled) return true;
  store.appendLine(monthFile(), JSON.stringify({
    at: new Date().toISOString(), event: 'server.start', actor: null, result: 'ok', note: '監査ログの書き込み確認'
  }));
  return true;
}

// 直近のイベントを新しい順に読む。監査ログ画面用。
function recent({ limit = 200, months = 3 } = {}) {
  return scan({ limit, months });
}

// 新しい順に読み、条件に合うものを limit 件まで集める。
// 「自分の履歴」のように、全体の一部だけを見せる画面用（先に件数で切ってから絞ると、
// ほかの人の操作が多いときに自分の記録が1件も出なくなる）。
function scan({ limit = 200, months = 3, filter = null } = {}) {
  const out = [];
  const now = new Date();
  for (let i = 0; i < months && out.length < limit; i += 1) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1));
    const rel = monthFile(d);
    if (!store.exists(rel)) continue;
    const full = store.resolveInData(rel);
    const lines = require('fs').readFileSync(full, 'utf8').split('\n').filter(Boolean);
    for (let j = lines.length - 1; j >= 0 && out.length < limit; j -= 1) {
      let entry;
      try {
        entry = JSON.parse(lines[j]);
      } catch {
        continue; // 壊れた行は飛ばす
      }
      if (!filter || filter(entry)) out.push(entry);
    }
  }
  return out;
}

module.exports = { record, recent, scan, checkWritable, EVENTS };
