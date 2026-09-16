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

const sessions = new Map(); // sessionId -> { userId, csrfToken, createdAt, expiresAt, ip, userAgent }

function create(user, { ip = null, userAgent = null } = {}) {
  const id = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  sessions.set(id, {
    userId: user.id,
    username: user.username,
    csrfToken: envelope.randomToken(32),
    createdAt: now,
    expiresAt: now + EXPIRE_MS,
    ip,
    userAgent
  });
  log.debug(`セッション作成 user=${user.username} 有効期限=${new Date(now + EXPIRE_MS).toISOString()}`);
  return { id, session: sessions.get(id) };
}

function get(sessionId) {
  if (!sessionId) return null;
  const session = sessions.get(sessionId);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }
  return session;
}

// 操作があったら期限を延ばす（スライディング）。放置されたセッションだけが切れるように。
function touch(sessionId) {
  const session = get(sessionId);
  if (!session) return null;
  session.expiresAt = Date.now() + EXPIRE_MS;
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
    if (now > session.expiresAt) {
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
  parseCookies,
  sessionIdFromRequest,
  cookieHeader,
  logoutCookieHeader,
  checkCsrf,
  isSecureRequest,
  stats
};
