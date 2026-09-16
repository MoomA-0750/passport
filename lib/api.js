'use strict';
// JSON API。画面（static/app.js）はここだけを叩く。
//
// 方針:
//   ・認可はすべて vaults.requireAccess / requireAdmin を通す。ルータ側で判断を自作しない
//   ・秘密の復号は reveal エンドポイントだけ。一覧や詳細では絶対に返さない
//   ・非 GET は必ず CSRF 検証を通す（server.js 側で一括）

const users = require('./users');
const vaults = require('./vaults');
const items = require('./items');
const audit = require('./audit');
const session = require('./session');
const totp = require('./totp');
const config = require('./config');
const http = require('./http');

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function requireAdmin(ctx) {
  if (!ctx.user || ctx.user.role !== 'admin') {
    audit.record('access.denied', { actor: ctx.user && ctx.user.id, note: '管理者専用の操作' });
    throw new ApiError(403, '管理者だけが実行できます');
  }
}

function requireLogin(ctx) {
  if (!ctx.user) throw new ApiError(401, 'ログインしてください');
}

// --- ルート定義 -------------------------------------------------------------
// [メソッド, パスのパターン, ハンドラ]。:name は1区切りにマッチする。

const routes = [];

function route(method, pattern, handler) {
  const names = [];
  const regexSource = pattern.replace(/:([A-Za-z]+)/g, (_, name) => {
    names.push(name);
    return '([^/]+)';
  });
  routes.push({ method, regex: new RegExp(`^${regexSource}$`), names, handler });
}

function match(method, pathname) {
  for (const r of routes) {
    if (r.method !== method) continue;
    const m = pathname.match(r.regex);
    if (!m) continue;
    const params = {};
    r.names.forEach((name, i) => { params[name] = decodeURIComponent(m[i + 1]); });
    return { handler: r.handler, params };
  }
  return null;
}

// --- セットアップとログイン -------------------------------------------------

// 初回だけ。ユーザーが1人も居ないときに最初の管理者を作る。
route('POST', '/api/setup', async (ctx) => {
  if (users.count() > 0) throw new ApiError(409, 'すでにセットアップは終わっています');
  const { username, password, displayName } = ctx.body;
  const created = users.create({ username, password, displayName, role: 'admin' });
  // 最初の個人用 Vault も一緒に作っておく。空の画面から始めさせない。
  vaults.create({ name: '個人', description: '自分だけの金庫', icon: '🔑', ownerId: created.id, actor: created.id });
  audit.record('setup.complete', { actor: created.id, actorName: created.username, ip: ctx.ip });
  return { user: created };
});

route('POST', '/api/login', async (ctx) => {
  const { username, password } = ctx.body;
  const result = users.authenticate(username, password, { ip: ctx.ip });
  if (!result.ok) {
    // 理由を細かく返さない。ロックだけは運用上必要なので伝える。
    if (result.reason === 'locked') {
      throw new ApiError(429, `ログインの試行が多すぎます。${config.auth.lockoutMinutes}分ほど待ってからやり直してください`);
    }
    throw new ApiError(401, 'ユーザー名かパスワードが違います');
  }
  const { id, session: created } = session.create(result.user, {
    ip: ctx.ip,
    userAgent: ctx.req.headers['user-agent'] || null
  });
  ctx.setCookie = session.cookieHeader(id, ctx.req);
  return {
    user: result.user,
    csrfToken: created.csrfToken,
    mustChangePassword: result.user.mustChangePassword
  };
});

route('POST', '/api/logout', async (ctx) => {
  if (ctx.sessionId) {
    audit.record('logout', { actor: ctx.user && ctx.user.id, actorName: ctx.user && ctx.user.username, ip: ctx.ip });
    session.destroy(ctx.sessionId);
  }
  ctx.setCookie = session.logoutCookieHeader(ctx.req);
  return { ok: true };
});

route('GET', '/api/me', async (ctx) => {
  requireLogin(ctx);
  return {
    user: ctx.user,
    csrfToken: ctx.session.csrfToken,
    idleLockMinutes: config.session.idleLockMinutes
  };
});

route('POST', '/api/me/password', async (ctx) => {
  requireLogin(ctx);
  const { currentPassword, newPassword } = ctx.body;
  users.changePassword(ctx.user.id, { currentPassword, newPassword, actor: ctx.user.id });
  // 変えたら、自分の今のセッション以外を切る
  session.destroyAllForUser(ctx.user.id);
  ctx.setCookie = session.logoutCookieHeader(ctx.req);
  return { ok: true, reloginRequired: true };
});

// --- Vault ------------------------------------------------------------------

route('GET', '/api/vaults', async (ctx) => {
  requireLogin(ctx);
  return { vaults: vaults.listForUser(ctx.user.id) };
});

route('POST', '/api/vaults', async (ctx) => {
  requireLogin(ctx);
  const vault = vaults.create({
    name: ctx.body.name,
    description: ctx.body.description,
    icon: ctx.body.icon,
    ownerId: ctx.user.id,
    actor: ctx.user.id
  });
  return { vault: vaults.listForUser(ctx.user.id).find((v) => v.id === vault.id) };
});

route('PUT', '/api/vaults/:vaultId', async (ctx) => {
  requireLogin(ctx);
  vaults.update(ctx.params.vaultId, ctx.body, { actor: ctx.user.id });
  return { ok: true };
});

route('DELETE', '/api/vaults/:vaultId', async (ctx) => {
  requireLogin(ctx);
  vaults.remove(ctx.params.vaultId, { actor: ctx.user.id });
  return { ok: true };
});

// メンバー一覧。ユーザー名を引くため users と突き合わせる。
route('GET', '/api/vaults/:vaultId/members', async (ctx) => {
  requireLogin(ctx);
  const vault = vaults.requireAccess(ctx.params.vaultId, ctx.user.id, 'viewer');
  const members = vault.members.map((m) => {
    const u = users.get(m.userId);
    return {
      userId: m.userId,
      username: u ? u.username : '(削除されたユーザー)',
      displayName: u ? (u.displayName || u.username) : '(削除されたユーザー)',
      role: m.role,
      addedAt: m.addedAt,
      viaBreakGlass: !!m.viaBreakGlass
    };
  });
  // owner なら、追加できる候補も返す
  const candidates = vaults.can(vault, ctx.user.id, 'owner')
    ? users.list()
      .filter((u) => u.status === 'active' && !vault.members.some((m) => m.userId === u.id))
      .map(users.toPublic)
    : [];
  return { members, candidates, myRole: vaults.roleOf(vault, ctx.user.id) };
});

route('POST', '/api/vaults/:vaultId/members', async (ctx) => {
  requireLogin(ctx);
  const target = users.get(ctx.body.userId);
  if (!target) throw new ApiError(404, 'そのユーザーが見つかりません');
  vaults.addMember(ctx.params.vaultId, { userId: target.id, role: ctx.body.role, actor: ctx.user.id });
  return { ok: true };
});

route('PUT', '/api/vaults/:vaultId/members/:userId', async (ctx) => {
  requireLogin(ctx);
  vaults.updateMember(ctx.params.vaultId, {
    userId: ctx.params.userId, role: ctx.body.role, actor: ctx.user.id
  });
  return { ok: true };
});

route('DELETE', '/api/vaults/:vaultId/members/:userId', async (ctx) => {
  requireLogin(ctx);
  vaults.removeMember(ctx.params.vaultId, { userId: ctx.params.userId, actor: ctx.user.id });
  return { ok: true };
});

// 管理者の緊急アクセス。理由が要る。監査ログに残る。
route('POST', '/api/vaults/:vaultId/break-glass', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  vaults.adminTakeOwnership(ctx.params.vaultId, { actor: ctx.user.id, reason: ctx.body.reason });
  return { ok: true };
});

// --- アイテム ---------------------------------------------------------------

route('GET', '/api/vaults/:vaultId/items', async (ctx) => {
  requireLogin(ctx);
  return { items: items.list(ctx.params.vaultId, ctx.user.id) };
});

route('POST', '/api/vaults/:vaultId/items', async (ctx) => {
  requireLogin(ctx);
  return { item: items.create(ctx.params.vaultId, ctx.body, { actor: ctx.user.id }) };
});

route('GET', '/api/vaults/:vaultId/items/:itemId', async (ctx) => {
  requireLogin(ctx);
  const item = items.get(ctx.params.vaultId, ctx.params.itemId, ctx.user.id);
  if (!item) throw new ApiError(404, 'アイテムが見つかりません');
  return { item };
});

route('PUT', '/api/vaults/:vaultId/items/:itemId', async (ctx) => {
  requireLogin(ctx);
  return { item: items.update(ctx.params.vaultId, ctx.params.itemId, ctx.body, { actor: ctx.user.id }) };
});

route('DELETE', '/api/vaults/:vaultId/items/:itemId', async (ctx) => {
  requireLogin(ctx);
  items.remove(ctx.params.vaultId, ctx.params.itemId, { actor: ctx.user.id });
  return { ok: true };
});

// 秘密を1つだけ復号して返す。ここだけが平文を返す口。
// GET にしないのは、URL や履歴・ログに残さないため。
route('POST', '/api/vaults/:vaultId/items/:itemId/reveal', async (ctx) => {
  requireLogin(ctx);
  const { field, purpose } = ctx.body;
  if (!items.isSecretField(field)) throw new ApiError(400, 'フィールド名が不正です');
  const value = items.revealSecret(ctx.params.vaultId, ctx.params.itemId, field, {
    actor: ctx.user.id,
    purpose: purpose === 'copy' ? 'copy' : 'view',
    ip: ctx.ip
  });
  return { field, value };
});

// TOTP の今のコード。シークレットそのものは返さない。
route('POST', '/api/vaults/:vaultId/items/:itemId/totp', async (ctx) => {
  requireLogin(ctx);
  const secret = items.revealSecret(ctx.params.vaultId, ctx.params.itemId, 'totp', {
    actor: ctx.user.id, purpose: 'view', ip: ctx.ip
  });
  try {
    return totp.generate(secret);
  } catch (err) {
    throw new ApiError(400, `TOTP シークレットを解釈できません: ${err.message}`);
  }
});

route('GET', '/api/search', async (ctx) => {
  requireLogin(ctx);
  const query = ctx.url.searchParams.get('q') || '';
  const vaultId = ctx.url.searchParams.get('vault') || null;
  return { results: items.search(ctx.user.id, query, { vaultId }) };
});

// --- 管理 -------------------------------------------------------------------

route('GET', '/api/users', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  return { users: users.list().map(users.toPublic) };
});

route('POST', '/api/users', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  const created = users.create({
    username: ctx.body.username,
    password: ctx.body.password,
    displayName: ctx.body.displayName,
    role: ctx.body.role === 'admin' ? 'admin' : 'member',
    mustChangePassword: true, // 管理者が決めた初期パスワードは本人に変えさせる
    actor: ctx.user.id
  });
  return { user: created };
});

route('PUT', '/api/users/:userId', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  const target = ctx.params.userId;
  // 自分で自分を管理者から降ろす / 無効化するのを防ぐ。最後の管理者も守る。
  if (target === ctx.user.id && (ctx.body.role === 'member' || ctx.body.status === 'disabled')) {
    throw new ApiError(400, '自分自身の管理者権限は外せません');
  }
  if ((ctx.body.role === 'member' || ctx.body.status === 'disabled') && users.countActiveAdmins(target) === 0) {
    throw new ApiError(400, '最後の管理者なので変更できません');
  }
  const updated = users.update(target, ctx.body, { actor: ctx.user.id });
  if (ctx.body.status === 'disabled') {
    const removed = session.destroyAllForUser(target);
    audit.record('user.disable', { actor: ctx.user.id, target, note: `セッション${removed}件を切断` });
  }
  return { user: updated };
});

route('POST', '/api/users/:userId/password', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  users.resetPassword(ctx.params.userId, ctx.body.newPassword, { actor: ctx.user.id });
  session.destroyAllForUser(ctx.params.userId);
  return { ok: true };
});

route('GET', '/api/audit', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  const limit = Math.min(parseInt(ctx.url.searchParams.get('limit') || '200', 10) || 200, 1000);
  const entries = audit.recent({ limit }).map((entry) => ({
    ...entry,
    eventLabel: audit.EVENTS[entry.event] || entry.event,
    actorName: entry.actorName || (entry.actor ? (users.get(entry.actor) || {}).username : null) || null
  }));
  return { entries, eventLabels: audit.EVENTS };
});

// --- ディスパッチ -----------------------------------------------------------

async function handle(ctx) {
  const found = match(ctx.req.method, ctx.url.pathname);
  if (!found) {
    http.sendJson(ctx.req, ctx.res, 404, { error: 'そのAPIはありません' });
    return;
  }
  ctx.params = found.params;
  try {
    const result = await found.handler(ctx);
    const headers = ctx.setCookie ? { 'Set-Cookie': ctx.setCookie } : {};
    http.sendJson(ctx.req, ctx.res, 200, result === undefined ? { ok: true } : result, headers);
  } catch (err) {
    const status = err.status
      || (err.code === 'FORBIDDEN' ? 403 : null)
      || (err.code === 'CONFLICT' ? 409 : null)
      || 400;
    if (status >= 500) {
      require('./logger')('passport:server').error(`${ctx.url.pathname}: ${err.stack}`);
    }
    const headers = ctx.setCookie ? { 'Set-Cookie': ctx.setCookie } : {};
    http.sendJson(ctx.req, ctx.res, status, { error: err.message }, headers);
  }
}

module.exports = { handle, ApiError };
