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
const sshkeys = require('./sshkeys');
const config = require('./config');
const http = require('./http');
const integrity = require('./integrity');
const groups = require('./groups');
const activity = require('./activity');
const checkup = require('./checkup');
const tokens = require('./tokens');

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
    try {
      r.names.forEach((name, i) => { params[name] = decodeURIComponent(m[i + 1]); });
    } catch {
      // %zz のような壊れたエンコード。以前は例外が外まで飛んで 500 になっていた
      return { badRequest: true };
    }
    return { handler: r.handler, params };
  }
  return null;
}

// --- セットアップとログイン -------------------------------------------------

// 初回だけ。ユーザーが1人も居ないときに最初の管理者を作る。
route('POST', '/api/setup', async (ctx) => {
  // 読めたユーザーの数ではなく、ディスク上の状態で判断する（integrity.js を読む）
  if (!integrity.setupAllowed()) throw new ApiError(409, 'すでにセットアップは終わっています');
  const { username, password, displayName, setupToken } = ctx.body;
  // 起動ログに出した合言葉を要求する。先回りして管理者を作られないように。
  if (!integrity.checkSetupToken(setupToken)) {
    audit.recordSampled(`setup|${ctx.ip}`, 'access.denied', { ip: ctx.ip, note: 'セットアップの合言葉が違う' });
    throw new ApiError(403, 'セットアップの合言葉が違います。サーバーの起動ログを確認してください');
  }
  const created = users.create({ username, password, displayName, role: 'admin' });
  // 最初の個人用 Vault も一緒に作っておく。空の画面から始めさせない。
  vaults.create({ name: '個人', description: '自分だけの金庫', icon: '🔑', ownerId: created.id, actor: created.id });
  integrity.consumeSetupToken(); // 成功したので使い切る
  audit.record('setup.complete', { actor: created.id, actorName: created.username, ip: ctx.ip });
  return { user: created };
});

route('POST', '/api/login', async (ctx) => {
  const { username, password } = ctx.body;
  const result = users.authenticate(username, password, { ip: ctx.ip });
  if (!result.ok) {
    // どの失敗でも同じ応答にする。以前は止められたときだけ 429 と専用の文言を返していたが、
    // 存在しないユーザー名は止められないため、429 が返るかどうかで実在するユーザーを
    // 機械的に選別できた。いまは存在しないユーザー名も同じように止めるが、念のため応答もそろえる。
    throw new ApiError(401,
      'ユーザー名かパスワードが違うか、試行が多すぎます。しばらく待ってからやり直してください');
  }
  // 「ログイン中の端末」の画面で見分けるための種類。拡張は許可した拡張の Origin で判定する。
  // CLI は自分で名乗る（本人のセッション一覧の表示にしか使わないので、偽っても得るものは無い）。
  const fromExtension = !!http.allowedExtensionOrigin(ctx.req.headers.origin);
  const fromCli = !fromExtension && String(ctx.req.headers['x-passport-client'] || '').toLowerCase() === 'cli';
  if (fromCli && !config.cli.enabled) {
    throw new ApiError(403, 'CLI からのログインはサーバーの設定で止めてあります');
  }
  const kind = fromExtension ? 'extension' : (fromCli ? 'cli' : 'web');
  const { id, session: created } = session.create(result.user, {
    ip: ctx.ip,
    userAgent: ctx.req.headers['user-agent'] || null,
    kind
  });
  // CLI には Cookie を渡さない（ブラウザではないので、Bearer トークンだけで足りる）
  if (!fromCli) ctx.setCookie = session.cookieHeader(id, ctx.req);

  const response = {
    user: result.user,
    csrfToken: created.csrfToken,
    mustChangePassword: result.user.mustChangePassword
  };

  // Chrome 拡張には、Authorization ヘッダーに載せるトークンを渡す。
  // 画面には返さない。画面は HttpOnly Cookie で動いており、
  // ここで JavaScript から読めるトークンを渡すと、その守りを自分で外すことになる。
  if (fromExtension || fromCli) {
    response.token = id;
    response.expiresInSeconds = Math.floor((created.expiresAt - Date.now()) / 1000);
  }
  return response;
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
  // 変えたら、自分の今のセッション以外を切り、自分が発行した自動化トークンも失効させる
  // （パスワードを変える理由の多くは「盗まれたかもしれない」なので、盗んだ側が作った入口を残さない）
  session.destroyAllForUser(ctx.user.id);
  tokens.revokeAllIssuedBy(ctx.user.id, { actor: ctx.user.id, reason: 'パスワードの変更', ip: ctx.ip });
  ctx.setCookie = session.logoutCookieHeader(ctx.req);
  return { ok: true, reloginRequired: true };
});

// --- ログイン中の端末 / 自分の履歴 ------------------------------------------

route('GET', '/api/me/sessions', async (ctx) => {
  requireLogin(ctx);
  return { sessions: session.listForUser(ctx.user.id, { currentSessionId: ctx.sessionId }) };
});

// 1つ切る。今使っているものを切った場合はログアウトと同じ
route('DELETE', '/api/me/sessions/:handle', async (ctx) => {
  requireLogin(ctx);
  const removedId = session.destroyByHandle(ctx.user.id, ctx.params.handle);
  if (!removedId) throw new ApiError(404, 'その端末は見つかりません（もう切れているかもしれません）');
  const current = removedId === ctx.sessionId;
  audit.record('session.revoke', { actor: ctx.user.id, ip: ctx.ip, note: current ? '今使っている端末' : null });
  if (current) ctx.setCookie = session.logoutCookieHeader(ctx.req);
  return { ok: true, loggedOut: current };
});

route('POST', '/api/me/sessions/revoke-others', async (ctx) => {
  requireLogin(ctx);
  const removed = session.destroyOthersForUser(ctx.user.id, ctx.sessionId);
  audit.record('session.revoke_others', { actor: ctx.user.id, ip: ctx.ip, note: `${removed}件` });
  return { ok: true, removed };
});

// --- 自動化トークンの管理（画面から。トークン自身では使えない） ---------------

route('GET', '/api/tokens', async (ctx) => {
  requireLogin(ctx);
  return { tokens: tokens.visibleTo(ctx.user).map((t) => tokens.toPublic(t, { viewer: ctx.user })), maxDays: tokens.MAX_DAYS, enabled: config.cli.tokens };
});

route('POST', '/api/tokens', async (ctx) => {
  requireLogin(ctx);
  const { name, vaultIds, expiresInDays, password } = ctx.body;
  // 長く効く入口を作るので、パスワードをもう一度確かめる（盗まれたセッションだけでは作れないように）
  if (!users.confirmPassword(ctx.user.id, password, { ip: ctx.ip })) {
    throw new ApiError(403, 'パスワードが違うか、試行が多すぎます');
  }
  const created = tokens.create({ name, vaultIds, expiresInDays, actor: ctx.user.id, ip: ctx.ip });
  // トークンそのものを返すのはこの1回だけ
  return { token: created.token, info: tokens.toPublic(created.info, { viewer: ctx.user }) };
});

route('DELETE', '/api/tokens/:tokenId', async (ctx) => {
  requireLogin(ctx);
  return { info: tokens.toPublic(tokens.revoke(ctx.params.tokenId, { user: ctx.user, ip: ctx.ip }), { viewer: ctx.user }) };
});

// --- 読み出し専用の API（CLI と自動化トークン） --------------------------------
//
// Bearer で来たものだけを受け付ける（Cookie では使えない）。
//   ・人の CLI: ログインで受け取ったセッションのトークン。権限はその人の権限
//   ・自動化トークン: 決めた Vault だけ。発行者の権限の範囲で、読み出しだけ
// 自動化トークンは、ここ以外の API には届かない（server.js）。

function requireReader(ctx) {
  if (ctx.automation) return { kind: 'token', userId: ctx.automation.issuerId, token: ctx.automation };
  if (ctx.user && ctx.viaBearer) {
    // 拡張のセッションはこの API を使わないので、通さない（届く範囲を狭くする）
    if (ctx.session && ctx.session.kind === 'extension') throw new ApiError(401, 'CLI のトークンか、自動化トークンが必要です');
    // 「CLI」「SSH エージェント」の印は自己申告（監査ログの表示を分けるためだけのもの）
    const client = String(ctx.req.headers['x-passport-client'] || '').toLowerCase() === 'cli-agent' ? 'cli-agent' : 'cli';
    if (!config.cli.enabled) throw new ApiError(403, 'CLI はサーバーの設定で止めてあります');
    return { kind: 'user', userId: ctx.user.id, token: null, client };
  }
  throw new ApiError(401, 'CLI のトークンか、自動化トークンが必要です');
}

function readerVault(reader, vaultId) {
  if (reader.kind === 'token' && !reader.token.vaultIds.includes(vaultId)) {
    throw new ApiError(403, 'このトークンでは、その Vault を読めません');
  }
  return vaults.requireAccess(vaultId, reader.userId, 'viewer');
}

function readerVia(reader, ctx) {
  const agent = String(ctx.req.headers['x-passport-client'] || '').toLowerCase() === 'cli-agent';
  return reader.kind === 'token'
    ? { tokenId: reader.token.id, tokenName: reader.token.name, agent }
    : { client: reader.client };
}

route('GET', '/api/automation/whoami', async (ctx) => {
  const reader = requireReader(ctx);
  if (reader.kind === 'token') {
    return { kind: 'token', name: reader.token.name, expiresAt: reader.token.expiresAt };
  }
  return { kind: 'user', username: ctx.user.username, displayName: ctx.user.displayName, expiresAt: new Date(ctx.session.absoluteExpiresAt).toISOString() };
});

route('GET', '/api/automation/vaults', async (ctx) => {
  const reader = requireReader(ctx);
  const list = vaults.listForUser(reader.userId)
    .filter((v) => reader.kind === 'user' || reader.token.vaultIds.includes(v.id));
  return { vaults: list.map((v) => ({ id: v.id, name: v.name, role: reader.kind === 'token' ? 'read' : v.role, itemCount: v.itemCount })) };
});

route('GET', '/api/automation/vaults/:vaultId/items', async (ctx) => {
  const reader = requireReader(ctx);
  readerVault(reader, ctx.params.vaultId);
  return {
    items: items.list(ctx.params.vaultId, reader.userId).map((item) => ({
      id: item.id,
      type: item.type,
      title: item.title,
      username: item.username,
      urls: item.urls,
      fields: Object.keys(item.secrets || {})
    }))
  };
});

route('POST', '/api/automation/vaults/:vaultId/items/:itemId/read', async (ctx) => {
  const reader = requireReader(ctx);
  readerVault(reader, ctx.params.vaultId);
  const { field } = ctx.body;
  if (!items.isSecretField(field)) throw new ApiError(400, 'フィールド名が不正です');
  const value = items.revealSecret(ctx.params.vaultId, ctx.params.itemId, field, {
    actor: reader.userId, purpose: 'view', ip: ctx.ip, via: readerVia(reader, ctx)
  });
  return { field, value };
});

route('POST', '/api/automation/vaults/:vaultId/items/:itemId/totp', async (ctx) => {
  const reader = requireReader(ctx);
  readerVault(reader, ctx.params.vaultId);
  const secret = items.revealSecret(ctx.params.vaultId, ctx.params.itemId, 'totp', {
    actor: reader.userId, purpose: 'view', ip: ctx.ip, via: readerVia(reader, ctx)
  });
  try {
    return totp.generate(secret);
  } catch (err) {
    throw new ApiError(400, `TOTP シークレットを解釈できません: ${err.message}`);
  }
});

// --- 点検 -------------------------------------------------------------------

// 期限切れ・期限間近の件数（ナビゲーションのバッジ）。復号しない
route('GET', '/api/checkup/reminders', async (ctx) => {
  requireLogin(ctx);
  return checkup.reminders(ctx.user.id);
});

// 弱い・使い回し・古い。復号して調べるので、監査ログに残し、連続実行を制限する
route('POST', '/api/checkup/run', async (ctx) => {
  requireLogin(ctx);
  return checkup.run(ctx.user.id, { ip: ctx.ip });
});

route('GET', '/api/me/activity', async (ctx) => {
  requireLogin(ctx);
  const limit = Math.min(parseInt(ctx.url.searchParams.get('limit') || '200', 10) || 200, 500);
  return activity.forUserWithInfo(ctx.user.id, { limit });
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
  const allGroups = groups.list();
  const isOwner = vaults.can(vault, ctx.user.id, 'owner');
  const vaultGroups = (vault.groups || []).map((entry) => {
    const group = allGroups.find((g) => g.id === entry.groupId);
    const view = {
      groupId: entry.groupId,
      name: group ? group.name : '(削除されたグループ)',
      memberCount: group ? (group.members || []).length : 0,
      role: entry.role,
      addedAt: entry.addedAt
    };
    // owner には、グループ経由で誰がこの Vault を見られるかを見せる（自分の Vault の露出範囲を把握するため）。
    // viewer / editor には人数だけ。
    if (isOwner && group) {
      view.members = (group.members || []).map((userId) => {
        const u = users.get(userId);
        return { userId, username: u ? u.username : '(削除されたユーザー)', displayName: u ? (u.displayName || u.username) : '' };
      });
    }
    return view;
  });
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
  // 共有相手の候補。Vault を1つ作れば誰でも owner になれるので、ここは実質「ログインした全員」が見られる。
  // 以前は toPublic をそのまま返していて、誰が管理者か・最終ログイン時刻まで取れた。
  // 選ぶのに要る分（ID・ユーザー名・表示名）だけにする。
  const candidates = isOwner
    ? users.list()
      .filter((u) => u.status === 'active' && !vault.members.some((m) => m.userId === u.id))
      .map((u) => ({ id: u.id, username: u.username, displayName: u.displayName || u.username }))
    : [];
  // 共有先に足せるグループ。足す前の段階では名前と人数だけ。
  // ただし owner は足せば中の人が見えるので、これは境界ではない（足した記録は監査ログに残る）
  const groupCandidates = isOwner
    ? allGroups
      .filter((g) => !(vault.groups || []).some((entry) => entry.groupId === g.id))
      .map((g) => ({ id: g.id, name: g.name, memberCount: (g.members || []).length }))
    : [];
  return {
    members,
    groups: vaultGroups,
    candidates,
    groupCandidates,
    myRole: vaults.roleOf(vault, ctx.user.id),
    mySources: vaults.roleSources(vault, ctx.user.id)
  };
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

route('POST', '/api/vaults/:vaultId/groups', async (ctx) => {
  requireLogin(ctx);
  vaults.addGroup(ctx.params.vaultId, { groupId: ctx.body.groupId, role: ctx.body.role, actor: ctx.user.id });
  return { ok: true };
});

route('PUT', '/api/vaults/:vaultId/groups/:groupId', async (ctx) => {
  requireLogin(ctx);
  vaults.updateGroup(ctx.params.vaultId, { groupId: ctx.params.groupId, role: ctx.body.role, actor: ctx.user.id });
  return { ok: true };
});

route('DELETE', '/api/vaults/:vaultId/groups/:groupId', async (ctx) => {
  requireLogin(ctx);
  vaults.removeGroup(ctx.params.vaultId, { groupId: ctx.params.groupId, actor: ctx.user.id });
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
    purpose: ['copy', 'fill'].includes(purpose) ? purpose : 'view',
    ip: ctx.ip
  });
  return { field, value };
});

// 過去の値（履歴）を1つ取り出す。今の値と同じく POST にし、監査ログに残す。
route('POST', '/api/vaults/:vaultId/items/:itemId/history/reveal', async (ctx) => {
  requireLogin(ctx);
  const { field, index } = ctx.body;
  if (!items.isSecretField(field)) throw new ApiError(400, 'フィールド名が不正です');
  const value = items.revealHistory(ctx.params.vaultId, ctx.params.itemId, field, index, {
    actor: ctx.user.id, ip: ctx.ip
  });
  return { field, index, value };
});

// --- ゴミ箱 ---

route('GET', '/api/vaults/:vaultId/trash', async (ctx) => {
  requireLogin(ctx);
  return { items: items.listTrash(ctx.params.vaultId, ctx.user.id) };
});

route('POST', '/api/vaults/:vaultId/trash/:itemId/restore', async (ctx) => {
  requireLogin(ctx);
  return { item: items.restore(ctx.params.vaultId, ctx.params.itemId, { actor: ctx.user.id }) };
});

route('DELETE', '/api/vaults/:vaultId/trash/:itemId', async (ctx) => {
  requireLogin(ctx);
  items.purge(ctx.params.vaultId, ctx.params.itemId, { actor: ctx.user.id });
  return { ok: true };
});

// 手元の値が保管してあるものと同じかを聞く。値は返さない。
// 拡張が「このログインはもう登録済みか」を判断するのに使う。
route('POST', '/api/vaults/:vaultId/items/:itemId/verify', async (ctx) => {
  requireLogin(ctx);
  const { field, value } = ctx.body;
  if (!items.isSecretField(field)) throw new ApiError(400, 'フィールド名が不正です');
  const matches = items.verifySecret(ctx.params.vaultId, ctx.params.itemId, field, value, {
    actor: ctx.user.id,
    ip: ctx.ip,
    note: ctx.viaBearer ? '拡張からの照合' : null
  });
  return { matches };
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

// --- SSH 鍵 -----------------------------------------------------------------

// 新しい鍵を作って返す。まだ保存はしない（画面のフォームに入れてから保存する）。
// パスフレーズは掛けない。Passport 側が保管時に暗号化するため。
// 取り出したあとに掛けたい場合は ssh-keygen -p を使ってもらう。
route('POST', '/api/ssh/generate', async (ctx) => {
  requireLogin(ctx);
  const { type = 'ed25519', comment = '' } = ctx.body;
  try {
    const key = sshkeys.generate({ type, comment });
    return { key };
  } catch (err) {
    throw new ApiError(400, err.message);
  }
});

// 貼られた鍵を読んで、種別・フィンガープリント・公開鍵を返す。保存はしない。
// 画面で「これで合っているか」を確かめてもらうため。
route('POST', '/api/ssh/inspect', async (ctx) => {
  requireLogin(ctx);
  const { privateKey, publicKey, passphrase } = ctx.body;
  try {
    if (privateKey) return { info: sshkeys.inspectPrivateKey(privateKey, { passphrase }) };
    if (publicKey) return { info: { ...sshkeys.parsePublicKey(publicKey), format: 'public-only' } };
    throw new ApiError(400, '秘密鍵か公開鍵を入れてください');
  } catch (err) {
    throw err instanceof ApiError ? err : new ApiError(400, err.message);
  }
});

// authorized_keys に貼る1行。公開鍵は秘密ではないので復号も監査も要らない。
route('GET', '/api/vaults/:vaultId/items/:itemId/authorized-key', async (ctx) => {
  requireLogin(ctx);
  const item = items.get(ctx.params.vaultId, ctx.params.itemId, ctx.user.id);
  if (!item || !item.sshKey) throw new ApiError(404, 'SSH 鍵のアイテムではありません');
  return {
    line: sshkeys.authorizedKeysLine(item.sshKey.publicKey, { options: ctx.url.searchParams.get('options') || '' }),
    fingerprint: item.sshKey.fingerprint
  };
});

// --- Chrome 拡張向け ---------------------------------------------------------

// 今見ているサイトに使えそうなアイテムを返す。
// 秘密は含めない（入力するときに reveal を別途叩く）。
route('GET', '/api/match', async (ctx) => {
  requireLogin(ctx);
  const host = ctx.url.searchParams.get('host') || '';
  const scheme = ctx.url.searchParams.get('scheme') || null;
  if (!host) throw new ApiError(400, 'host を指定してください');
  return { host, items: items.matchHost(ctx.user.id, host, { scheme }) };
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
    const revoked = tokens.revokeAllIssuedBy(target, { actor: ctx.user.id, reason: '発行者の無効化', ip: ctx.ip });
    audit.record('user.disable', { actor: ctx.user.id, target, note: `セッション${removed}件を切断・自動化トークン${revoked}件を失効` });
  }
  return { user: updated };
});

route('POST', '/api/users/:userId/password', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  users.resetPassword(ctx.params.userId, ctx.body.newPassword, { actor: ctx.user.id });
  session.destroyAllForUser(ctx.params.userId);
  tokens.revokeAllIssuedBy(ctx.params.userId, { actor: ctx.user.id, reason: '管理者によるパスワードのリセット', ip: ctx.ip });
  return { ok: true };
});

// --- グループ（管理者） -------------------------------------------------------

function groupView(group) {
  return {
    id: group.id,
    name: group.name,
    description: group.description || '',
    members: (group.members || []).map((userId) => {
      const u = users.get(userId);
      return { userId, username: u ? u.username : '(削除されたユーザー)', displayName: u ? (u.displayName || u.username) : '' };
    }),
    usedBy: vaults.list().filter((v) => (v.groups || []).some((g) => g.groupId === group.id))
      .map((v) => ({ id: v.id, name: v.name, role: v.groups.find((g) => g.groupId === group.id).role })),
    createdAt: group.createdAt
  };
}

route('GET', '/api/groups', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  return { groups: groups.list().map(groupView) };
});

route('POST', '/api/groups', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  return { group: groupView(groups.create({ name: ctx.body.name, description: ctx.body.description, actor: ctx.user.id })) };
});

route('PUT', '/api/groups/:groupId', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  return { group: groupView(groups.update(ctx.params.groupId, ctx.body, { actor: ctx.user.id })) };
});

route('DELETE', '/api/groups/:groupId', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  groups.remove(ctx.params.groupId, { actor: ctx.user.id });
  return { ok: true };
});

route('POST', '/api/groups/:groupId/members', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  const target = users.get(ctx.body.userId);
  if (!target) throw new ApiError(404, 'そのユーザーが見つかりません');
  return { group: groupView(groups.addMember(ctx.params.groupId, { userId: target.id, actor: ctx.user.id })) };
});

route('DELETE', '/api/groups/:groupId/members/:userId', async (ctx) => {
  requireLogin(ctx);
  requireAdmin(ctx);
  return { group: groupView(groups.removeMember(ctx.params.groupId, { userId: ctx.params.userId, actor: ctx.user.id })) };
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
  // 許可した拡張からの呼び出しにだけ CORS ヘッダーが付く（それ以外では空）
  const cors = http.corsHeaders(ctx.req);

  const found = match(ctx.req.method, ctx.url.pathname);
  if (found && found.badRequest) {
    http.sendJson(ctx.req, ctx.res, 400, { error: 'URL を解釈できません' }, cors);
    return;
  }
  if (!found) {
    http.sendJson(ctx.req, ctx.res, 404, { error: 'そのAPIはありません' }, cors);
    return;
  }
  ctx.params = found.params;
  try {
    const result = await found.handler(ctx);
    const headers = { ...cors, ...(ctx.setCookie ? { 'Set-Cookie': ctx.setCookie } : {}) };
    http.sendJson(ctx.req, ctx.res, 200, result === undefined ? { ok: true } : result, headers);
  } catch (err) {
    // 想定内の失敗（入力の誤り、権限、競合）と、プログラムの不具合を分ける。
    // 以前は何でも 400 にしていたので、TypeError の内部メッセージがそのまま利用者に出て、
    // サーバーのログには何も残らなかった（500 の枝に到達しなかった）。
    const programmingError = err instanceof TypeError || err instanceof RangeError
      || err instanceof ReferenceError || err instanceof SyntaxError;
    const status = err.status
      || (err.code === 'FORBIDDEN' ? 403 : null)
      || (err.code === 'CONFLICT' ? 409 : null)
      || (programmingError ? 500 : 400);
    if (status >= 500) {
      require('./logger')('passport:server').error(`${ctx.req.method} ${ctx.url.pathname}: ${err.stack}`);
      err.message = 'サーバー側で問題が起きました。管理者に連絡してください';
    }
    const headers = { ...cors, ...(ctx.setCookie ? { 'Set-Cookie': ctx.setCookie } : {}) };
    http.sendJson(ctx.req, ctx.res, status, { error: err.message }, headers);
  }
}

module.exports = { handle, ApiError };
