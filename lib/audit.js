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
  'item.automation_read': '自動化トークンでの読み出し',
  'token.create': '自動化トークンの発行',
  'token.revoke': '自動化トークンの失効',
  'token.denied': '自動化トークンでの拒否',
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
  if (detail.suppressed) entry.suppressed = detail.suppressed; // 間引いて省いた同じ記録の数（recordSampled）
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

// 権限を与える操作（Vault やグループへの追加、権限の変更、緊急アクセス、トークンの発行）は、
// 先に監査ログへ書き、書けなければ操作そのものをしない。以前は変更を保存してから記録していたので、
// 監査ログに書けない状態だと「記録の無い権限の付与」が成立した（outer gate で Codex が指摘）。
// 操作が途中で失敗したら、失敗したことも書き足す（記録は「多い側」に倒す）。
function recordBefore(event, detail, action) {
  const logged = record(event, detail);
  if (logged === false) {
    throw new Error('監査ログを書けないため、この操作を止めました。管理者に連絡してください');
  }
  try {
    return action();
  } catch (err) {
    record(event, { ...detail, result: 'failed', note: `${detail.note || ''}（失敗: ${err.message}）` });
    throw err;
  }
}

// 認証の前に書かれる記録（ログイン失敗、CSRF で弾いた、セットアップの合言葉違い、トークンの拒否）を間引く。
// 秘密の取り出しは監査ログに書けないと止まる（fail-closed）ので、認証なしで監査ログを無制限に増やせると、
// ディスクを埋めて全員の取り出しを止められる。同じ key（接続元や対象ごと）の記録は interval に1行にし、
// 省いた回数を次の行に書く。
const SAMPLE_LIMIT = 10000;
const samples = new Map(); // key -> { at, suppressed }

function recordSampled(key, event, detail = {}, { intervalMs = 60 * 1000, now = Date.now() } = {}) {
  const last = samples.get(key);
  if (last && now - last.at < intervalMs) {
    last.suppressed += 1;
    return 'suppressed';
  }
  if (samples.size >= SAMPLE_LIMIT) samples.clear();
  const suppressed = last ? last.suppressed : 0;
  samples.set(key, { at: now, suppressed: 0 });
  // 省いた回数は備考に混ぜず、別の欄に書く（備考は照合に使われる。自分の履歴の「試行の印」など）
  return record(event, suppressed ? { ...detail, suppressed } : detail);
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
//
// ファイルは末尾から 1MiB ずつ読み、集まったらそこで止める。読むバイト数にも上限（maxBytes）を置く。
// 以前は月ファイルを丸ごと読んで行に分けていたので、監査ログが大きくなると
// 「自分の履歴」を開くたびに単一プロセスのサーバーが数秒止まり、数百 MB のメモリを使っていた。
const CHUNK = 1024 * 1024;

function scanWithInfo({ limit = 200, months = 3, filter = null, maxBytes = 64 * 1024 * 1024 } = {}) {
  const fs = require('fs');
  const out = [];
  let budget = maxBytes;
  let truncated = false;
  const now = new Date();
  for (let i = 0; i < months && out.length < limit; i += 1) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1));
    const rel = monthFile(d);
    if (!store.exists(rel)) continue;
    const fd = fs.openSync(store.resolveInData(rel), 'r');
    try {
      let position = fs.fstatSync(fd).size;
      let carry = Buffer.alloc(0); // 次に読む塊の後ろにつながる、行の途中
      while (position > 0 && out.length < limit) {
        if (budget <= 0) {
          truncated = true;
          break;
        }
        const length = Math.min(CHUNK, position);
        position -= length;
        budget -= length;
        const chunk = Buffer.alloc(length);
        fs.readSync(fd, chunk, 0, length, position);
        let buf = Buffer.concat([chunk, carry]);
        // 先頭の行は、もっと前の塊とつながっているかもしれないので残す（ファイルの先頭なら残さない）
        let firstNewline = position > 0 ? buf.indexOf(0x0a) : -1;
        if (position > 0 && firstNewline === -1) {
          carry = buf;
          continue;
        }
        carry = position > 0 ? buf.subarray(0, firstNewline) : Buffer.alloc(0);
        buf = position > 0 ? buf.subarray(firstNewline + 1) : buf;
        const lines = buf.toString('utf8').split('\n');
        for (let j = lines.length - 1; j >= 0 && out.length < limit; j -= 1) {
          if (!lines[j]) continue;
          let entry;
          try {
            entry = JSON.parse(lines[j]);
          } catch {
            continue; // 壊れた行は飛ばす
          }
          if (!filter || filter(entry)) out.push(entry);
        }
      }
    } finally {
      fs.closeSync(fd);
    }
    if (truncated) break;
  }
  return { entries: out, truncated };
}

function scan(options = {}) {
  return scanWithInfo(options).entries;
}

module.exports = { record, recordBefore, recordSampled, recent, scan, scanWithInfo, checkWritable, EVENTS, _resetSamples: () => samples.clear() };
