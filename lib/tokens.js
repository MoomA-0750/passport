'use strict';
// 自動化トークン。cron やデプロイから、決めた Vault の秘密を読むためのもの。
// data/tokens/<id>.json に1トークン1ファイル。
//
// 形式: pp_<ID 24桁の16進>_<秘密 43文字>
//   サーバーには秘密そのものを置かず、pepper を鍵にした HMAC だけを置く（発行時に一度だけ見せる）。
//   盗まれた data/ からトークンを作り直せないように。
//
// できること（docs/crypto.md「CLI と自動化トークン」）:
//   ・決めた Vault の、アイテムの一覧と秘密の読み出しだけ。書き込み・管理・ほかの Vault はできない
//   ・/api/automation/ の下だけで使える（server.js）。ほかの API には届かない
//   ・期限は必須で、最長 365 日
//   ・発行できるのは、対象の Vault すべての owner（owner は人にだけ付く。lib/vaults.js 冒頭）
//   ・使うたびに、発行者が今も有効で、対象の Vault すべての owner かを確かめ直す。
//     外された人・無効化された人のトークンを生かさない
//   ・読み出しは発行者の操作として監査ログに残り、トークン名と ID が付く

const crypto = require('crypto');
const store = require('./store');
const keyring = require('./keyring');
const envelope = require('./envelope');
const vaults = require('./vaults');
const users = require('./users');
const audit = require('./audit');

const MAX_DAYS = 365;
const TOKEN_RE = /^pp_([0-9a-f]{24})_([A-Za-z0-9_-]{43})$/;
const DAY_MS = 24 * 60 * 60 * 1000;
const config = require('./config');
// 拒否の記録を間引く間隔。失効・期限切れのトークンを叩き続けて監査ログ（ディスク）を埋め、
// 監査ログに書けないことで全員の取り出しを止める、という使われ方をさせないため
const DENIED_LOG_MS = 60 * 1000;
// 使った時刻は、毎回書くとファイルの書き込みが増えるので、この間隔より空いたときだけ書く
const LAST_USED_WRITE_MS = 60 * 1000;

function tokenPath(id) {
  store.assertValidId(id, 'トークンID');
  return `tokens/${id}.json`;
}

function hashSecret(id, secret) {
  return crypto.createHmac('sha256', keyring.pepper())
    .update(`passport/automation-token/v1|${id}|${secret}`)
    .digest('hex');
}

function get(id) {
  if (!store.isValidId(id)) return null;
  return store.readJson(tokenPath(id));
}

function listAll() {
  return store.listJson('tokens').sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

// 緊急アクセス（break-glass）で owner になっている人。トークンの発行元にはしない
// （緊急アクセスは一時的な立ち入りで、自動化の持ち主にするためのものではない）
function breakGlassOwner(vault, userId) {
  return (vault.members || []).some((m) => m.userId === userId && m.viaBreakGlass);
}

// 今使えるか。使えない理由を返す（null なら使える）。ファイルが壊れていたら使えない側に倒す。
function problemOf(token, now = Date.now()) {
  if (!config.cli.tokens) return 'disabled';
  if (token.revokedAt) return 'revoked';
  if (!(Date.parse(token.expiresAt) > now)) return 'expired';
  if (!Array.isArray(token.vaultIds) || token.vaultIds.length === 0) return 'vault_missing';
  const issuer = users.get(token.createdBy);
  if (!issuer || issuer.status !== 'active') return 'issuer_disabled';
  for (const vaultId of token.vaultIds) {
    const vault = store.isValidId(vaultId) ? vaults.get(vaultId) : null;
    if (!vault) return 'vault_missing';
    if (vaults.roleOf(vault, token.createdBy) !== 'owner' || breakGlassOwner(vault, token.createdBy)) return 'issuer_not_owner';
  }
  return null;
}

function recordDenied(token, reason, ip, now) {
  audit.recordSampled(`token|${token.id}|${reason}`, 'token.denied', {
    actor: reason === 'bad_secret' ? null : token.createdBy,
    target: token.id, ip, result: reason, note: token.name
  }, { intervalMs: DENIED_LOG_MS, now });
}

const PROBLEM_LABELS = {
  disabled: 'サーバーの設定で止めてある',
  revoked: '失効済み',
  expired: '期限切れ',
  issuer_disabled: '発行者が無効',
  vault_missing: '対象の Vault が無い',
  issuer_not_owner: '発行者が対象の Vault の owner ではなくなった（緊急アクセスの owner を含む）'
};

function create({ name, vaultIds, expiresInDays, actor, ip = null }) {
  if (!config.cli.tokens) throw new Error('自動化トークンはサーバーの設定で止めてあります');
  const trimmed = String(name || '').trim();
  if (!trimmed) throw new Error('トークンの名前を入れてください（どこで使うかが分かる名前）');
  if (trimmed.length > 64) throw new Error('名前は64文字以内にしてください');
  const ids = [...new Set(Array.isArray(vaultIds) ? vaultIds : [])];
  if (ids.length === 0) throw new Error('読める Vault を1つ以上選んでください');
  if (ids.length > 20) throw new Error('Vault は20個までです');
  const days = Number(expiresInDays);
  if (!Number.isInteger(days) || days < 1 || days > MAX_DAYS) {
    throw new Error(`期限は 1〜${MAX_DAYS} 日で決めてください（無期限のトークンは作れません）`);
  }
  // 対象の Vault すべての owner であること
  const names = ids.map((vaultId) => {
    const vault = vaults.requireAccess(vaultId, actor, 'owner', { actor });
    if (breakGlassOwner(vault, actor)) {
      throw new Error(`「${vault.name}」には緊急アクセスで入っているため、自動化トークンを発行できません`);
    }
    return vault.name;
  });

  const id = crypto.randomBytes(12).toString('hex');
  const secret = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  const token = {
    id,
    name: trimmed,
    vaultIds: ids,
    secretHash: hashSecret(id, secret),
    createdBy: actor,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + days * DAY_MS).toISOString(),
    revokedAt: null,
    revokedBy: null,
    lastUsedAt: null,
    lastUsedIp: null,
    version: 1
  };
  // 先に監査ログへ書き、全部書けてから保存する（記録の無いトークンを作らない）。
  // 備考には、ほかの Vault の名前を入れない（その Vault の共同 owner の履歴に出るため）
  for (const vaultId of ids) {
    const logged = audit.record('token.create', {
      actor, ip, vaultId, target: id, note: `「${trimmed}」${days}日${ids.length > 1 ? ` / Vault ${ids.length} 個を対象` : ''}`
    });
    if (logged === false) throw new Error('監査ログを書けないため、トークンを発行できません。管理者に連絡してください');
  }
  store.writeJson(tokenPath(id), token);
  return { token: `pp_${id}_${secret}`, info: token };
}

// トークンで来たリクエストを確かめる。使えなければ null。
// 失敗の理由は呼び出し側へ返さない（401 にそろえる）。存在するトークンでの失敗だけ監査ログに残す。
function authenticate(bearer, { ip = null, now = Date.now() } = {}) {
  const match = TOKEN_RE.exec(String(bearer || ''));
  if (!match) return null;
  const [, id, secret] = match;
  let token;
  try {
    token = get(id);
  } catch {
    return null;
  }
  if (!token) return null;
  if (!envelope.safeEqual(hashSecret(id, secret), token.secretHash)) {
    recordDenied(token, 'bad_secret', ip, now);
    return null;
  }
  const problem = problemOf(token, now);
  if (problem) {
    recordDenied(token, problem, ip, now);
    return null;
  }
  if (!token.lastUsedAt || now - Date.parse(token.lastUsedAt) > LAST_USED_WRITE_MS || token.lastUsedIp !== ip) {
    try {
      store.updateJson(tokenPath(id), null, (current) => ({
        ...current, lastUsedAt: new Date(now).toISOString(), lastUsedIp: ip
      }));
    } catch {
      // 記録できなくても使うのは止めない（読み出しそのものは監査ログに残る）
    }
  }
  return { id: token.id, name: token.name, vaultIds: token.vaultIds, issuerId: token.createdBy, expiresAt: token.expiresAt };
}

// その人が発行したトークンを全部失効させる。侵害から回復する手順（パスワードの変更・リセット、無効化）で呼ぶ。
// 以前は「その場で発行者の状態を見る」だけだったので、無効化して戻す・パスワードを変えるという普通の回復手順のあとも、
// 盗まれたセッションで発行されたトークンが生き残り、有効化で黙って復活した。
function revokeAllIssuedBy(userId, { actor, reason, ip = null }) {
  let count = 0;
  for (const token of listAll().filter((t) => t.createdBy === userId && !t.revokedAt)) {
    store.updateJson(tokenPath(token.id), null, (current) => ({
      ...current, revokedAt: new Date().toISOString(), revokedBy: actor, revokedReason: reason
    }));
    audit.record('token.revoke', { actor, ip, target: token.id, note: `${token.name}（${reason}）` });
    count += 1;
  }
  return count;
}

// 本文を読み終えたあとに、もう一度使えるかを確かめる（server.js）。
// 認証してから本文を送り終えるまでの間に失効・権限の変更があっても、読ませないため。
function stillUsable(id, { now = Date.now() } = {}) {
  let token;
  try {
    token = get(id);
  } catch {
    return false;
  }
  return !!token && problemOf(token, now) === null;
}

// その人が見てよいトークン。管理者は全部、それ以外は自分が発行したものと、自分が owner の Vault を対象にしたもの。
function visibleTo(user) {
  if (!user) return [];
  const all = listAll();
  if (user.role === 'admin') return all;
  const owned = new Set(vaults.listForUser(user.id).filter((v) => v.role === 'owner').map((v) => v.id));
  return all.filter((t) => t.createdBy === user.id || (t.vaultIds || []).some((id) => owned.has(id)));
}

function canRevoke(user, token) {
  return visibleTo(user).some((t) => t.id === token.id);
}

function revoke(id, { user, ip = null }) {
  const token = get(id);
  if (!token || !canRevoke(user, token)) throw Object.assign(new Error('そのトークンは見つかりません'), { status: 404 });
  if (token.revokedAt) return token;
  const updated = store.updateJson(tokenPath(id), null, (current) => ({
    ...current, revokedAt: new Date().toISOString(), revokedBy: user.id
  }));
  audit.record('token.revoke', { actor: user.id, ip, target: id, note: token.name });
  return updated;
}

// 画面に返す形。秘密のハッシュは含めない。
// 管理者と発行者以外（対象の Vault のどれかの owner）には、入っていない Vault の名前と、使った接続元を伏せる。
function toPublic(token, { now = Date.now(), viewer = null } = {}) {
  const problem = problemOf(token, now);
  const issuer = users.get(token.createdBy);
  const full = !viewer || viewer.role === 'admin' || viewer.id === token.createdBy;
  const visibleVaults = full ? null : new Set(vaults.listForUser(viewer.id).map((v) => v.id));
  return {
    id: token.id,
    name: token.name,
    vaults: (token.vaultIds || []).map((vaultId) => (full || visibleVaults.has(vaultId)
      ? { id: vaultId, name: (store.isValidId(vaultId) && vaults.get(vaultId) || {}).name || '(削除された Vault)' }
      : { id: null, name: '（ほかの Vault）' })),
    createdBy: issuer ? issuer.username : '(削除されたユーザー)',
    createdAt: token.createdAt,
    expiresAt: token.expiresAt,
    revokedAt: token.revokedAt,
    lastUsedAt: token.lastUsedAt,
    lastUsedIp: full ? token.lastUsedIp : null,
    status: problem || 'active',
    statusLabel: problem ? PROBLEM_LABELS[problem] : '有効'
  };
}

module.exports = { create, authenticate, stillUsable, revokeAllIssuedBy, revoke, visibleTo, toPublic, get, MAX_DAYS, TOKEN_RE };
