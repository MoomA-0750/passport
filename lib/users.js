'use strict';
// ユーザーアカウント。data/users/<id>.json に1人1ファイル。
//
// WordBox の管理画面は「パスワードを平文で比較する共有パスワード1個」だが、
// 金庫では通用しないので作り直している（scrypt + pepper + 失敗ロック + 定数時間比較）。

const crypto = require('crypto');
const store = require('./store');
const envelope = require('./envelope');
const keyring = require('./keyring');
const config = require('./config');
const audit = require('./audit');
const log = require('./logger')('passport:auth');

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{1,31}$/;

function userPath(id) {
  store.assertValidId(id, 'ユーザーID');
  return `users/${id}.json`;
}

function list() {
  return store.listJson('users').sort((a, b) => a.username.localeCompare(b.username));
}

function get(id) {
  if (!store.isValidId(id)) return null;
  return store.readJson(userPath(id));
}

function findByUsername(username) {
  const normalized = String(username || '').trim().toLowerCase();
  if (!normalized) return null;
  return list().find((u) => u.username === normalized) || null;
}

function count() {
  return store.listJson('users').length;
}

// 画面や API に返す形。ハッシュや内部カウンタは出さない。
function toPublic(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName || user.username,
    role: user.role,
    status: user.status,
    mustChangePassword: !!user.mustChangePassword,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt || null
  };
}

function validatePassword(password) {
  const min = config.auth.minPasswordLength;
  if (typeof password !== 'string' || password.length < min) {
    return `パスワードは${min}文字以上にしてください`;
  }
  if (password.length > 256) {
    return 'パスワードは256文字以内にしてください';
  }
  return null;
}

function validateUsername(username) {
  const normalized = String(username || '').trim().toLowerCase();
  if (!USERNAME_RE.test(normalized)) {
    return 'ユーザー名は英小文字・数字・. _ - で2〜32文字にしてください';
  }
  if (findByUsername(normalized)) {
    return 'そのユーザー名はすでに使われています';
  }
  return null;
}

function create({ username, password, displayName, role = 'member', mustChangePassword = false, actor = null }) {
  const usernameError = validateUsername(username);
  if (usernameError) throw new Error(usernameError);
  const passwordError = validatePassword(password);
  if (passwordError) throw new Error(passwordError);
  if (!['admin', 'member'].includes(role)) throw new Error('role は admin か member です');

  const now = new Date().toISOString();
  const user = {
    id: crypto.randomUUID(),
    username: String(username).trim().toLowerCase(),
    displayName: String(displayName || username).trim().slice(0, 64),
    role,
    status: 'active',
    passwordHash: envelope.hashPassword(password, keyring.pepper()),
    mustChangePassword: !!mustChangePassword,
    failedAttempts: 0,
    lockedUntil: null,
    lastLoginAt: null,
    createdAt: now,
    updatedAt: now,
    version: 1
  };
  store.writeJson(userPath(user.id), user);
  audit.record('user.create', { actor, target: user.id, note: `${user.username} (${role})` });
  log.info(`ユーザーを作成しました: ${user.username} (${role})`);
  return toPublic(user);
}

// 存在しないユーザー名での試行を、中身を残さずに見分けるための印。
function attemptMark(username) {
  return crypto.createHmac('sha256', keyring.pepper())
    .update(`passport/login-attempt|${String(username || '')}`)
    .digest('hex')
    .slice(0, 12);
}

function isLocked(user) {
  return !!(user.lockedUntil && Date.parse(user.lockedUntil) > Date.now());
}

// ログイン。戻り値は { ok, user, reason }。
// reason を画面にそのまま出さないこと（ユーザー名の存在を教えてしまう）。
function authenticate(username, password, { ip = null } = {}) {
  const user = findByUsername(username);

  if (!user) {
    // ユーザーが居ない場合も、居る場合と同じくらいの時間をかける。
    // 応答時間からユーザー名の存在を当てられないようにするため。
    envelope.verifyPassword(String(password || ''), keyring.pepper(), {
      alg: 'scrypt', N: envelope.SCRYPT.N, r: envelope.SCRYPT.r, p: envelope.SCRYPT.p, dkLen: 32,
      salt: Buffer.alloc(16).toString('base64'),
      hash: Buffer.alloc(32).toString('base64')
    });
    // 打ち込まれた文字列をそのまま残さない。ユーザー名の欄にパスワードを
    // 打ち間違える人は普通にいて、それが監査ログに平文で残ってしまうため。
    // 同じ文字列の試行が続いていることは分かるよう、pepper で鍵付きハッシュにする。
    audit.record('login.fail', { ip, result: 'no_such_user', note: `試行の印 ${attemptMark(username)}` });
    return { ok: false, reason: 'invalid' };
  }

  if (user.status !== 'active') {
    audit.record('login.fail', { actor: user.id, actorName: user.username, ip, result: 'disabled' });
    return { ok: false, reason: 'disabled' };
  }

  if (isLocked(user)) {
    audit.record('login.fail', { actor: user.id, actorName: user.username, ip, result: 'locked' });
    return { ok: false, reason: 'locked', lockedUntil: user.lockedUntil };
  }

  const ok = envelope.verifyPassword(String(password || ''), keyring.pepper(), user.passwordHash);

  if (!ok) {
    const failedAttempts = Number(user.failedAttempts || 0) + 1;
    const reachedLimit = failedAttempts >= config.auth.maxFailedAttempts;
    const lockedUntil = reachedLimit
      ? new Date(Date.now() + config.auth.lockoutMinutes * 60 * 1000).toISOString()
      : null;
    store.updateJson(userPath(user.id), null, (current) => ({
      ...current,
      failedAttempts: reachedLimit ? 0 : failedAttempts,
      lockedUntil: lockedUntil || current.lockedUntil
    }));
    audit.record(reachedLimit ? 'login.locked' : 'login.fail', {
      actor: user.id, actorName: user.username, ip, result: 'bad_password',
      note: reachedLimit ? `${config.auth.lockoutMinutes}分ロック` : `${failedAttempts}回目`
    });
    return { ok: false, reason: reachedLimit ? 'locked' : 'invalid', lockedUntil };
  }

  // 成功。失敗カウンタを戻し、必要ならハッシュのパラメータを上げ直す。
  const updated = store.updateJson(userPath(user.id), null, (current) => {
    const next = {
      ...current,
      failedAttempts: 0,
      lockedUntil: null,
      lastLoginAt: new Date().toISOString()
    };
    if (envelope.needsRehash(current.passwordHash)) {
      next.passwordHash = envelope.hashPassword(password, keyring.pepper());
      log.info(`パスワードハッシュを作り直しました: ${current.username}`);
    }
    return next;
  });

  audit.record('login.success', { actor: user.id, actorName: user.username, ip });
  return { ok: true, user: toPublic(updated) };
}

function changePassword(id, { currentPassword, newPassword, requireCurrent = true, actor = null }) {
  const user = get(id);
  if (!user) throw new Error('ユーザーが見つかりません');

  if (requireCurrent) {
    const ok = envelope.verifyPassword(String(currentPassword || ''), keyring.pepper(), user.passwordHash);
    if (!ok) throw new Error('現在のパスワードが違います');
  }

  const passwordError = validatePassword(newPassword);
  if (passwordError) throw new Error(passwordError);

  if (envelope.verifyPassword(newPassword, keyring.pepper(), user.passwordHash)) {
    throw new Error('今までと同じパスワードは使えません');
  }

  store.updateJson(userPath(id), null, (current) => ({
    ...current,
    passwordHash: envelope.hashPassword(newPassword, keyring.pepper()),
    mustChangePassword: false,
    failedAttempts: 0,
    lockedUntil: null
  }));
  audit.record('user.password_change', { actor: actor || id, target: id, actorName: user.username });
  return true;
}

// 管理者によるリセット。初回ログインで変更を強制する。
function resetPassword(id, newPassword, { actor = null } = {}) {
  const passwordError = validatePassword(newPassword);
  if (passwordError) throw new Error(passwordError);
  const user = get(id);
  if (!user) throw new Error('ユーザーが見つかりません');
  store.updateJson(userPath(id), null, (current) => ({
    ...current,
    passwordHash: envelope.hashPassword(newPassword, keyring.pepper()),
    mustChangePassword: true,
    failedAttempts: 0,
    lockedUntil: null
  }));
  audit.record('user.password_change', { actor, target: id, note: '管理者によるリセット' });
  return true;
}

function update(id, patch, { actor = null } = {}) {
  const user = get(id);
  if (!user) throw new Error('ユーザーが見つかりません');
  const allowed = {};
  if (patch.displayName !== undefined) allowed.displayName = String(patch.displayName).trim().slice(0, 64);
  if (patch.role !== undefined) {
    if (!['admin', 'member'].includes(patch.role)) throw new Error('role は admin か member です');
    allowed.role = patch.role;
  }
  if (patch.status !== undefined) {
    if (!['active', 'disabled'].includes(patch.status)) throw new Error('status は active か disabled です');
    allowed.status = patch.status;
  }
  const updated = store.updateJson(userPath(id), null, (current) => ({ ...current, ...allowed }));
  audit.record('user.update', { actor, target: id, note: Object.keys(allowed).join(',') });
  return toPublic(updated);
}

// 最後の管理者を消す / 落とすと誰も管理できなくなるので、呼び出し側でこれを使って防ぐ。
function countActiveAdmins(excludeId = null) {
  return list().filter((u) => u.role === 'admin' && u.status === 'active' && u.id !== excludeId).length;
}

module.exports = {
  list,
  get,
  findByUsername,
  count,
  toPublic,
  create,
  authenticate,
  changePassword,
  resetPassword,
  update,
  isLocked,
  validatePassword,
  validateUsername,
  countActiveAdmins
};
