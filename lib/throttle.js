'use strict';
// ログイン試行の流量制限。
//
// 以前は「ユーザー単位で5回失敗したら、正しいパスワードでも15分入れない」だった。
// これだと、ユーザー名さえ知っていれば誰でも特定の人を締め出せる。
// 15分ごとに5回デタラメを送り続ければ永久に入れず、最後の管理者を狙われると
// 誰もリセットできなくなる（レビューの指摘）。
//
// そこで数え方を変える:
//
//   ・「ユーザー名 × 接続元 IP」の組み合わせで数える
//     → 攻撃者が自分の IP から失敗を重ねても、別の場所から正しく入る本人には効かない
//   ・存在しないユーザー名でも同じように数える
//     → 「ロックされるかどうか」でユーザー名の存在を当てられないようにする
//   ・接続元 IP 単位でも、ユーザー名をまたいだ総量を抑える
//     → ユーザー名を変えながらの総当たりと、scrypt によるサーバーの停止を抑える
//
// 記録はメモリに置く。再起動で消えるが、ディスクに書くと、そのファイル自体が
// 「誰がどこから失敗したか」の記録として残り続けるので避けた。監査ログには別途残る。
//
// 受け入れていること: 多数の IP から1人を狙う分散型の総当たりは、この仕組みだけでは止まらない。
// scrypt の計算コスト、パスワードの最低12文字、監査ログでの検知で抑える
// （docs/crypto.md の脅威モデルに書いてある）。

const config = require('./config');

const PAIR_LIMIT = () => config.auth.maxFailedAttempts;              // 既定 5
const PAIR_LOCK_MS = () => config.auth.lockoutMinutes * 60 * 1000;    // 既定 15分
const IP_LIMIT = 30;                                                  // IP あたり、窓の中で
const IP_WINDOW_MS = 15 * 60 * 1000;

const pairs = new Map(); // `${username}|${ip}` -> { failures, lockedUntil }
const ips = new Map();   // ip -> [失敗した時刻...]

function key(username, ip) {
  return `${String(username || '').trim().toLowerCase()}|${ip || 'unknown'}`;
}

function recentIpFailures(ip, now = Date.now()) {
  const list = (ips.get(ip) || []).filter((at) => now - at < IP_WINDOW_MS);
  ips.set(ip, list);
  return list;
}

// ログインを試してよいか。止める場合は理由を返すが、
// 利用者に返す文言では、ユーザーの存在を区別しないこと。
function check(username, ip) {
  const now = Date.now();
  if (recentIpFailures(ip, now).length >= IP_LIMIT) {
    return { allowed: false, reason: 'ip' };
  }
  const entry = pairs.get(key(username, ip));
  if (entry && entry.lockedUntil && entry.lockedUntil > now) {
    return { allowed: false, reason: 'pair', lockedUntil: entry.lockedUntil };
  }
  return { allowed: true };
}

function recordFailure(username, ip) {
  const now = Date.now();
  const k = key(username, ip);
  const entry = pairs.get(k) || { failures: 0, lockedUntil: 0 };
  entry.failures += 1;
  if (entry.failures >= PAIR_LIMIT()) {
    entry.lockedUntil = now + PAIR_LOCK_MS();
    entry.failures = 0;
  }
  pairs.set(k, entry);

  const list = recentIpFailures(ip, now);
  list.push(now);
  ips.set(ip, list);

  return { lockedNow: entry.lockedUntil > now };
}

function recordSuccess(username, ip) {
  pairs.delete(key(username, ip));
}

// 管理者がパスワードをリセットしたときなど、そのユーザーの記録を全部消す
function clearUser(username) {
  const prefix = `${String(username || '').trim().toLowerCase()}|`;
  for (const k of pairs.keys()) {
    if (k.startsWith(prefix)) pairs.delete(k);
  }
}

// メモリに溜め続けない
const sweeper = setInterval(() => {
  const now = Date.now();
  for (const [k, entry] of pairs) {
    if ((!entry.lockedUntil || entry.lockedUntil < now) && entry.failures === 0) pairs.delete(k);
  }
  for (const ip of ips.keys()) {
    if (recentIpFailures(ip, now).length === 0) ips.delete(ip);
  }
}, 10 * 60 * 1000);
sweeper.unref();

// テスト用
function reset() {
  pairs.clear();
  ips.clear();
}

module.exports = { check, recordFailure, recordSuccess, clearUser, reset, IP_LIMIT };
