'use strict';
// 暗号プリミティブ。Node.js 標準 crypto だけを使う。鍵はすべて引数で受け取り、
// このモジュールは状態を持たない（テストしやすさと、鍵の在処を1箇所に絞るため）。
// 設計の根拠は docs/crypto.md を読む。

const crypto = require('crypto');

const ALG = 'aes-256-gcm';
const ALG_LABEL = 'A256GCM';
const ENVELOPE_VERSION = 1;
const KEY_LEN = 32; // AES-256
const IV_LEN = 12;  // GCM の推奨 nonce 長
const TAG_LEN = 16;

// --- 鍵導出 -----------------------------------------------------------------

// HKDF-SHA256。Node の crypto.hkdfSync は ArrayBuffer を返すので Buffer に直す。
function hkdf(ikm, { salt = Buffer.alloc(0), info, length = KEY_LEN }) {
  if (!info) throw new Error('hkdf: info は必須です（鍵の用途を混ぜないため）');
  const derived = crypto.hkdfSync(
    'sha256',
    ikm,
    Buffer.isBuffer(salt) ? salt : Buffer.from(String(salt), 'utf8'),
    Buffer.from(info, 'utf8'),
    length
  );
  return Buffer.from(derived);
}

// アイテム鍵。Vault 鍵からアイテムごとに分ける。
// 同一鍵での GCM 暗号化回数を抑え、AAD と併せて暗号文の貼り替えを落とす。
function deriveItemKey(vaultKey, itemId) {
  return hkdf(vaultKey, { salt: itemId, info: 'passport/item/v1' });
}

// --- 封筒 -------------------------------------------------------------------

// AAD は「この暗号文がどこに属するか」を縛る文字列。
// 別アイテム・別フィールドの暗号文を貼り替えても復号に失敗するようにする。
function buildAad({ vaultId, itemId, field, version }) {
  if (!vaultId || !itemId || !field) {
    throw new Error('buildAad: vaultId / itemId / field は必須です');
  }
  return Buffer.from(`${vaultId}|${itemId}|${field}|${version == null ? '' : version}`, 'utf8');
}

// 平文 -> 封筒（docs/crypto.md の形式）
function seal(key, plaintext, aad) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_LEN) {
    throw new Error(`seal: 鍵は ${KEY_LEN} バイトの Buffer でなければなりません`);
  }
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALG, key, iv, { authTagLength: TAG_LEN });
  if (aad) cipher.setAAD(aad);
  const ct = Buffer.concat([
    cipher.update(Buffer.from(plaintext, 'utf8')),
    cipher.final()
  ]);
  return {
    v: ENVELOPE_VERSION,
    alg: ALG_LABEL,
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: cipher.getAuthTag().toString('base64')
  };
}

// 封筒 -> 平文。改竄・貼り替え・鍵違いはすべてここで例外になる。
function open(key, envelope, aad) {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('open: 封筒がありません');
  }
  if (envelope.v !== ENVELOPE_VERSION || envelope.alg !== ALG_LABEL) {
    throw new Error(`open: 未知の封筒形式です (v=${envelope.v}, alg=${envelope.alg})`);
  }
  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  if (iv.length !== IV_LEN || tag.length !== TAG_LEN) {
    throw new Error('open: iv または tag の長さが不正です');
  }
  const decipher = crypto.createDecipheriv(ALG, key, iv, { authTagLength: TAG_LEN });
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ct, 'base64')),
    decipher.final()
  ]);
  return plaintext.toString('utf8');
}

// Vault 鍵のような「鍵そのもの」を包む / 解く。平文が Buffer なので別関数にする。
//
// 注意: ここは base64 の**文字列**を経由するので、鍵の値が不変の JS 文字列として
// ヒープに残る。呼び出し側の `vaultKey.fill(0)` が消せるのは Buffer の方だけで、
// 文字列は消せない。「使い終わったら潰す」は気休め程度と考える
// （プロセスメモリを読める人は全部読める、という受け入れ済みの前提の範囲内）。
function sealKey(kek, keyBuffer, aad) {
  return seal(kek, keyBuffer.toString('base64'), aad);
}

function openKey(kek, envelope, aad) {
  return Buffer.from(open(kek, envelope, aad), 'base64');
}

// --- パスワードハッシュ -----------------------------------------------------

// scrypt のパラメータ。docs/crypto.md 参照。
// maxmem を明示しないと Node の既定 32MiB を超えて落ちる（必要量 = 128 * N * r = 33.5MiB）。消さない。
const SCRYPT = { N: 32768, r: 8, p: 1, dkLen: 32, maxmem: 64 * 1024 * 1024 };

function hashPassword(password, pepper, params = SCRYPT) {
  const salt = crypto.randomBytes(16);
  const hash = scrypt(password, pepper, salt, params);
  return {
    alg: 'scrypt',
    N: params.N,
    r: params.r,
    p: params.p,
    dkLen: params.dkLen,
    salt: salt.toString('base64'),
    hash: hash.toString('base64')
  };
}

function scrypt(password, pepper, salt, params) {
  // pepper（マスターキー由来）を混ぜるので、ユーザーファイルだけ盗まれても
  // オフラインで総当たりできない。
  // pepper が無いまま黙ってハッシュを作ると、pepper 無しのハッシュが混ざる。止める。
  if (!Buffer.isBuffer(pepper) || pepper.length === 0) {
    throw new Error('pepper がありません（keyring がアンロックされていない可能性があります）');
  }
  const material = Buffer.concat([Buffer.from(String(password), 'utf8'), pepper]);
  return crypto.scryptSync(material, salt, params.dkLen, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: params.maxmem || 64 * 1024 * 1024
  });
}

// 保存されたハッシュのパラメータとして受け入れる範囲。
// data/users/*.json を書き換えられると、p を巨大にするだけでログイン1回あたり
// 数秒〜数十秒サーバー全体が止まる（p を 1→99 にすると 6.7 秒止まることを実測）。
const SCRYPT_LIMITS = {
  N: { min: 2 ** 14, max: 2 ** 20 },
  r: { min: 1, max: 16 },
  p: { min: 1, max: 4 },
  dkLen: { min: 16, max: 64 }
};

function withinLimits(stored) {
  for (const [name, { min, max }] of Object.entries(SCRYPT_LIMITS)) {
    const value = name === 'dkLen' ? (stored.dkLen || 32) : stored[name];
    if (!Number.isInteger(value) || value < min || value > max) return false;
  }
  // N は 2 の累乗でなければならない（scrypt の仕様）
  return (stored.N & (stored.N - 1)) === 0;
}

function verifyPassword(password, pepper, stored) {
  if (!stored || stored.alg !== 'scrypt') return false;
  if (!withinLimits(stored)) return false;
  const params = {
    N: stored.N,
    r: stored.r,
    p: stored.p,
    dkLen: stored.dkLen || 32,
    maxmem: 64 * 1024 * 1024
  };
  let candidate;
  try {
    candidate = scrypt(password, pepper, Buffer.from(stored.salt, 'base64'), params);
  } catch {
    return false;
  }
  const expected = Buffer.from(stored.hash, 'base64');
  if (candidate.length !== expected.length) return false;
  return crypto.timingSafeEqual(candidate, expected);
}

// 保存済みハッシュが今のパラメータより弱いか。ログイン成功時に静かに作り直すため。
function needsRehash(stored, params = SCRYPT) {
  if (!stored || stored.alg !== 'scrypt') return true;
  return stored.N < params.N || stored.r < params.r || (stored.dkLen || 32) < params.dkLen;
}

// --- そのほか ---------------------------------------------------------------

function randomKey() {
  return crypto.randomBytes(KEY_LEN);
}

// URL に載せられるトークン（セッションID・招待コードなど）
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

// 文字列の定数時間比較。CSRF トークンなどに使う。
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a || ''), 'utf8');
  const bufB = Buffer.from(String(b || ''), 'utf8');
  if (bufA.length !== bufB.length || bufA.length === 0) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = {
  ALG_LABEL,
  ENVELOPE_VERSION,
  KEY_LEN,
  SCRYPT,
  SCRYPT_LIMITS,
  hkdf,
  deriveItemKey,
  buildAad,
  seal,
  open,
  sealKey,
  openKey,
  hashPassword,
  verifyPassword,
  needsRehash,
  randomKey,
  randomToken,
  safeEqual
};
