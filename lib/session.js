'use strict';
// セッションと CSRF。セッションはインメモリ（プロセス再起動で全員ログアウト）。
//
// 金庫なので、再起動でログインが切れるのは欠点ではなく望ましい性質として受け入れる。
// 代わりにセッションの寿命は既定8時間、無操作なら画面側が自動ロックする。

const crypto = require('crypto');
const envelope = require('./envelope');
const config = require('./config');
const log = require('./logger')('passport:auth');

const COOKIE_NAME = 'passport_session';
const EXPIRE_MS = config.session.expireHours * 60 * 60 * 1000;
// 操作が続いていても、ログインからこの時間が経ったら切る。
// 以前は操作のたびに期限を延ばすだけだったので、8時間おきに1回叩き続ければ
// セッション（拡張の Bearer トークンを含む）が無期限に生きていた。
const ABSOLUTE_MAX_MS = Math.max(EXPIRE_MS, (config.session.absoluteMaxHours || 24) * 60 * 60 * 1000);

const sessions = new Map(); // sessionId -> { userId, csrfToken, kind, createdAt, lastSeenAt, expiresAt, ip, lastIp, userAgent }

const KINDS = ['web', 'extension', 'cli'];

// 「ログイン中の端末」の画面では、セッション ID そのものは返さない。
// ID は Cookie / Bearer トークンそのもので、画面の JavaScript や拡張の外に出すと、それだけで乗っ取れるため。
// 代わりに鍵付きハッシュの短い表示用 ID（handle）で指す。鍵はプロセスごとの乱数
// （セッション自体がインメモリで再起動で消えるので、handle も再起動で変わってよい）。
const HANDLE_KEY = crypto.randomBytes(32);

function handleOf(sessionId) {
  return crypto.createHmac('sha256', HANDLE_KEY).update(`passport/session-handle|${sessionId}`).digest('base64url').slice(0, 22);
}

function create(user, { ip = null, userAgent = null, kind = 'web' } = {}) {
  const id = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  sessions.set(id, {
    userId: user.id,
    username: user.username,
    csrfToken: envelope.randomToken(32),
    kind: KINDS.includes(kind) ? kind : 'web',
    createdAt: now,
    lastSeenAt: now,
    expiresAt: now + EXPIRE_MS,
    absoluteExpiresAt: now + ABSOLUTE_MAX_MS,
    ip,
    lastIp: ip,
    userAgent: userAgent ? String(userAgent).slice(0, 300) : null
  });
  log.debug(`セッション作成 user=${user.username} 有効期限=${new Date(now + EXPIRE_MS).toISOString()}`);
  return { id, session: sessions.get(id) };
}

function get(sessionId) {
  if (!sessionId) return null;
  const session = sessions.get(sessionId);
  if (!session) return null;
  const now = Date.now();
  if (now > session.expiresAt || now > session.absoluteExpiresAt) {
    sessions.delete(sessionId);
    return null;
  }
  return session;
}

// 操作があったら期限を延ばす（スライディング）。放置されたセッションだけが切れるように。
function touch(sessionId, { ip = null } = {}) {
  const session = get(sessionId);
  if (!session) return null;
  session.lastSeenAt = Date.now();
  if (ip) session.lastIp = ip;
  // 延ばすが、絶対寿命は越えない
  session.expiresAt = Math.min(Date.now() + EXPIRE_MS, session.absoluteExpiresAt);
  return session;
}

function destroy(sessionId) {
  return sessions.delete(sessionId);
}

// あるユーザーのセッションを全部切る。無効化やパスワード変更のときに使う。
function destroyAllForUser(userId) {
  let removed = 0;
  for (const [id, session] of sessions) {
    if (session.userId === userId) {
      sessions.delete(id);
      removed += 1;
    }
  }
  return removed;
}

// その人のセッションの一覧（表示用）。ID・CSRF トークンは含めない。
function listForUser(userId, { currentSessionId = null } = {}) {
  const out = [];
  for (const id of [...sessions.keys()]) {
    const s = get(id); // 期限切れはここで消える
    if (!s || s.userId !== userId) continue;
    out.push({
      handle: handleOf(id),
      kind: s.kind,
      current: id === currentSessionId,
      createdAt: new Date(s.createdAt).toISOString(),
      lastSeenAt: new Date(s.lastSeenAt).toISOString(),
      expiresAt: new Date(Math.min(s.expiresAt, s.absoluteExpiresAt)).toISOString(),
      ip: s.ip,
      lastIp: s.lastIp,
      userAgent: s.userAgent
    });
  }
  return out.sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt));
}

// handle で1つ切る。本人のセッションでなければ切らない（見つからない扱い）。
// 戻り値は切ったセッションの ID（今使っているものかを呼び出し側で判定するため）か null。
function destroyByHandle(userId, handle) {
  if (typeof handle !== 'string' || handle.length !== 22) return null;
  for (const [id, s] of sessions) {
    if (s.userId !== userId) continue;
    if (envelope.safeEqual(handleOf(id), handle)) {
      sessions.delete(id);
      return id;
    }
  }
  return null;
}

// 今使っているもの以外を全部切る。
function destroyOthersForUser(userId, keepSessionId) {
  let removed = 0;
  for (const [id, s] of sessions) {
    if (s.userId === userId && id !== keepSessionId) {
      sessions.delete(id);
      removed += 1;
    }
  }
  return removed;
}

function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  for (const part of String(cookieHeader).split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key) out[key] = decodeURIComponent(value);
  }
  return out;
}

function sessionIdFromRequest(req) {
  return parseCookies(req.headers.cookie)[COOKIE_NAME] || null;
}

// Secure 属性は HTTPS のときだけ付ける。HTTP で付けるとブラウザが Cookie を捨てるため、
// Nginx 前段構成（trustProxy）も考慮して判定する。
function isSecureRequest(req) {
  if (config.server.tls) return true;
  if (config.server.trustProxy) {
    return String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
  }
  return false;
}

function cookieHeader(sessionId, req) {
  const attrs = [
    `${COOKIE_NAME}=${sessionId}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(EXPIRE_MS / 1000)}`
  ];
  if (isSecureRequest(req)) attrs.push('Secure');
  return attrs.join('; ');
}

function logoutCookieHeader(req) {
  const attrs = [`${COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0'];
  if (isSecureRequest(req)) attrs.push('Secure');
  return attrs.join('; ');
}

// CSRF 対策は2重にする:
//   1. Origin / Referer がこのサーバー自身であること
//   2. セッションに紐づく CSRF トークンが一致すること
// SameSite=Strict も効いているが、ブラウザ任せにしない。
//
// ログインとセットアップはまだセッションが無いので requireToken: false で呼び、
// 1 のチェックだけを効かせる。
function checkCsrf(req, session, token, { requireToken = true } = {}) {
  const method = req.method.toUpperCase();
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return { ok: true };

  const origin = req.headers.origin;
  const host = req.headers.host;
  if (origin) {
    let originHost;
    try {
      originHost = new URL(origin).host;
    } catch {
      return { ok: false, reason: 'Origin ヘッダーが壊れています' };
    }
    if (originHost !== host) {
      return { ok: false, reason: `Origin が一致しません (${originHost} != ${host})` };
    }
  } else {
    // Origin が無い場合は Referer で代替。どちらも無い非 GET は拒否する。
    const referer = req.headers.referer;
    if (!referer) return { ok: false, reason: 'Origin も Referer もありません' };
    try {
      if (new URL(referer).host !== host) {
        return { ok: false, reason: 'Referer が一致しません' };
      }
    } catch {
      return { ok: false, reason: 'Referer ヘッダーが壊れています' };
    }
  }

  if (!requireToken) return { ok: true };

  if (!session) return { ok: false, reason: 'セッションがありません' };
  if (!envelope.safeEqual(token, session.csrfToken)) {
    return { ok: false, reason: 'CSRF トークンが一致しません' };
  }
  return { ok: true };
}

function stats() {
  return { active: sessions.size };
}

// 期限切れの掃除。メモリに残し続けない。
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  let removed = 0;
  for (const [id, session] of sessions) {
    if (now > session.expiresAt || now > session.absoluteExpiresAt) {
      sessions.delete(id);
      removed += 1;
    }
  }
  if (removed) log.debug(`期限切れセッションを ${removed} 件掃除しました`);
}, 10 * 60 * 1000);
cleanupTimer.unref(); // これがあると node が終了できなくなるので

module.exports = {
  COOKIE_NAME,
  create,
  get,
  touch,
  destroy,
  destroyAllForUser,
  destroyByHandle,
  destroyOthersForUser,
  listForUser,
  handleOf,
  KINDS,
  parseCookies,
  sessionIdFromRequest,
  cookieHeader,
  logoutCookieHeader,
  checkCsrf,
  isSecureRequest,
  stats
};
