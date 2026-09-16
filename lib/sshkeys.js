'use strict';
// SSH 鍵の読み書き。Node 標準の crypto だけで、OpenSSH の形式を自前で組み立てる。
//
// なぜ自前かというと、Node は OpenSSH 形式の秘密鍵
// （-----BEGIN OPENSSH PRIVATE KEY-----）を読めないため
// （createPrivateKey が DECODER routines::unsupported で落ちる）。
// ただし鍵素材は JWK で取り出せるので、OpenSSH のワイヤ形式はこちらで組める。
//
// 大事な性質: OpenSSH 形式の秘密鍵は、**パスフレーズで暗号化されていても
// 公開鍵の部分は平文で入っている**。なので、パスフレーズを知らなくても
// 鍵種別・公開鍵・フィンガープリントは取り出せる。
// （暗号化された秘密鍵の中身を開くには bcrypt_pbkdf が要るが、それはやらない。
//   Passport 側で保管時に暗号化するので、中身を開く必要がない）

const crypto = require('crypto');

const OPENSSH_MAGIC = Buffer.from('openssh-key-v1\0', 'binary');

// --- ワイヤ形式の読み書き ---------------------------------------------------

function encodeString(buf) {
  const body = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf), 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(body.length, 0);
  return Buffer.concat([len, body]);
}

function encodeUint32(value) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(value >>> 0, 0);
  return buf;
}

// mpint: 先頭ビットが立っていたら 0x00 を足す（負の数と区別するため）
function encodeMpint(buf) {
  let body = buf;
  let i = 0;
  while (i < body.length - 1 && body[i] === 0) i += 1; // 余計な先頭ゼロは落とす
  body = body.subarray(i);
  if (body.length > 0 && (body[0] & 0x80)) {
    body = Buffer.concat([Buffer.from([0]), body]);
  }
  return encodeString(body);
}

class Reader {
  constructor(buf) {
    this.buf = buf;
    this.pos = 0;
  }

  readUint32() {
    if (this.pos + 4 > this.buf.length) throw new Error('鍵データが途中で終わっています');
    const value = this.buf.readUInt32BE(this.pos);
    this.pos += 4;
    return value;
  }

  readString() {
    const len = this.readUint32();
    if (this.pos + len > this.buf.length) throw new Error('鍵データが途中で終わっています');
    const out = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }

  get remaining() {
    return this.buf.length - this.pos;
  }
}

// --- 公開鍵 -----------------------------------------------------------------

// "SHA256:xxxx"（ssh-keygen -l と同じ形式。base64 のパディングは落とす）
function fingerprint(publicKeyBlob) {
  const hash = crypto.createHash('sha256').update(publicKeyBlob).digest('base64');
  return `SHA256:${hash.replace(/=+$/, '')}`;
}

// KeyObject → OpenSSH のワイヤ形式（バイナリ）
function publicKeyBlobFrom(keyObject) {
  const type = keyObject.asymmetricKeyType;
  const jwk = keyObject.export({ format: 'jwk' });

  if (type === 'ed25519') {
    return Buffer.concat([
      encodeString('ssh-ed25519'),
      encodeString(Buffer.from(jwk.x, 'base64url'))
    ]);
  }

  if (type === 'rsa') {
    return Buffer.concat([
      encodeString('ssh-rsa'),
      encodeMpint(Buffer.from(jwk.e, 'base64url')),
      encodeMpint(Buffer.from(jwk.n, 'base64url'))
    ]);
  }

  if (type === 'ec') {
    const curves = { 'P-256': 'nistp256', 'P-384': 'nistp384', 'P-521': 'nistp521' };
    const curve = curves[jwk.crv];
    if (!curve) throw new Error(`対応していない曲線です: ${jwk.crv}`);
    const point = Buffer.concat([
      Buffer.from([0x04]), // 非圧縮点
      Buffer.from(jwk.x, 'base64url'),
      Buffer.from(jwk.y, 'base64url')
    ]);
    return Buffer.concat([
      encodeString(`ecdsa-sha2-${curve}`),
      encodeString(curve),
      encodeString(point)
    ]);
  }

  throw new Error(`対応していない鍵種別です: ${type}`);
}

function formatPublicKey(blob, comment) {
  const base = `${readKeyType(blob)} ${blob.toString('base64')}`;
  return comment ? `${base} ${comment}` : base;
}

function readKeyType(blob) {
  return new Reader(blob).readString().toString('utf8');
}

// 鍵の強さ。ssh-keygen -l が出す数字に合わせる。
function bitsOf(blob) {
  const reader = new Reader(blob);
  const type = reader.readString().toString('utf8');
  if (type === 'ssh-ed25519') return 256;
  if (type === 'ssh-rsa') {
    reader.readString();            // e
    const n = reader.readString();  // n
    let i = 0;
    while (i < n.length && n[i] === 0) i += 1;
    return (n.length - i) * 8;
  }
  if (type.startsWith('ecdsa-sha2-nistp')) return parseInt(type.slice('ecdsa-sha2-nistp'.length), 10);
  return 0;
}

// "ssh-ed25519 AAAAC3... comment" を読む
function parsePublicKey(text) {
  const line = String(text || '').trim().split('\n')[0].trim();
  const parts = line.split(/\s+/);
  if (parts.length < 2) throw new Error('公開鍵の形式ではありません');
  const [declaredType, base64Part, ...commentParts] = parts;
  let blob;
  try {
    blob = Buffer.from(base64Part, 'base64');
  } catch {
    throw new Error('公開鍵の base64 を読めません');
  }
  let actualType;
  try {
    actualType = readKeyType(blob);
  } catch {
    throw new Error('公開鍵の中身を読めません');
  }
  if (actualType !== declaredType) {
    throw new Error(`公開鍵の種別が一致しません（${declaredType} と ${actualType}）`);
  }
  return {
    keyType: actualType,
    bits: bitsOf(blob),
    fingerprint: fingerprint(blob),
    comment: commentParts.join(' ') || '',
    publicKey: formatPublicKey(blob, commentParts.join(' '))
  };
}

// --- 秘密鍵の読み取り -------------------------------------------------------

// OpenSSH 形式（-----BEGIN OPENSSH PRIVATE KEY-----）の外側を読む。
// 暗号化されていても、公開鍵とコメントの一部はここまでで取れる。
function parseOpenSshPrivate(text) {
  const match = String(text).match(
    /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/
  );
  if (!match) return null;

  const body = Buffer.from(match[1].replace(/\s+/g, ''), 'base64');
  if (!body.subarray(0, OPENSSH_MAGIC.length).equals(OPENSSH_MAGIC)) {
    throw new Error('OpenSSH 秘密鍵のヘッダが壊れています');
  }

  const reader = new Reader(body.subarray(OPENSSH_MAGIC.length));
  const cipherName = reader.readString().toString('utf8');
  const kdfName = reader.readString().toString('utf8');
  reader.readString(); // kdfoptions
  const keyCount = reader.readUint32();
  if (keyCount !== 1) throw new Error(`鍵が ${keyCount} 個入っています。1個のものだけ扱えます`);
  const publicBlob = reader.readString();

  const encrypted = cipherName !== 'none' || kdfName !== 'none';
  let comment = '';
  if (!encrypted) {
    // 平文なら、秘密部分からコメントまで読める
    const privateSection = new Reader(reader.readString());
    const check1 = privateSection.readUint32();
    const check2 = privateSection.readUint32();
    if (check1 !== check2) throw new Error('秘密鍵の検査値が一致しません（壊れているか、形式が違います）');
    const innerType = privateSection.readString().toString('utf8');
    if (innerType === 'ssh-ed25519') {
      privateSection.readString(); // 公開鍵
      privateSection.readString(); // 秘密鍵
    } else if (innerType === 'ssh-rsa') {
      for (let i = 0; i < 6; i += 1) privateSection.readString();
    } else if (innerType.startsWith('ecdsa-sha2-')) {
      privateSection.readString();
      privateSection.readString();
      privateSection.readString();
    } else {
      // 知らない種別でもコメントは諦めるだけ。公開鍵は取れている
      return { publicBlob, encrypted, comment: '', format: 'openssh' };
    }
    comment = privateSection.readString().toString('utf8');
  }

  return { publicBlob, encrypted, comment, format: 'openssh' };
}

// 秘密鍵を読んで、公開鍵とフィンガープリントを割り出す。
// OpenSSH 形式（暗号化されていても可）と、PEM / PKCS#8 に対応する。
function inspectPrivateKey(text, { passphrase = null } = {}) {
  const source = String(text || '').trim();
  if (!source) throw new Error('秘密鍵が空です');

  const openssh = parseOpenSshPrivate(source);
  if (openssh) {
    const { publicBlob, encrypted, comment } = openssh;
    return {
      format: 'openssh',
      encrypted,
      keyType: readKeyType(publicBlob),
      bits: bitsOf(publicBlob),
      fingerprint: fingerprint(publicBlob),
      comment,
      publicKey: formatPublicKey(publicBlob, comment)
    };
  }

  // PEM / PKCS#8 は Node がそのまま読める
  let keyObject;
  try {
    keyObject = crypto.createPrivateKey(
      passphrase ? { key: source, passphrase } : source
    );
  } catch (err) {
    if (/bad decrypt|wrong final block|Malformed|bad password/i.test(err.message)) {
      throw new Error('パスフレーズが違うようです');
    }
    throw new Error(
      '秘密鍵を読めませんでした。OpenSSH 形式か PEM 形式の鍵を貼ってください' +
      (/DECODER/.test(err.message) ? '' : `（${err.message}）`)
    );
  }
  const publicKeyObject = crypto.createPublicKey(keyObject);
  const blob = publicKeyBlobFrom(publicKeyObject);
  return {
    format: 'pem',
    encrypted: false,
    keyType: readKeyType(blob),
    bits: bitsOf(blob),
    fingerprint: fingerprint(blob),
    comment: '',
    publicKey: formatPublicKey(blob, '')
  };
}

// --- 秘密鍵の書き出し（OpenSSH 形式、暗号化なし） ---------------------------

// パスフレーズを掛けないのは、Passport 側が保管時に暗号化するため。
// 掛けるには bcrypt_pbkdf が要り、標準ライブラリだけでは実装が重い。
// 取り出したあとに掛けたい場合は `ssh-keygen -p -f <file>` を案内する。
function encodeOpenSshPrivate(keyObject, publicBlob, comment) {
  const type = keyObject.asymmetricKeyType;
  const jwk = keyObject.export({ format: 'jwk' });
  const check = crypto.randomBytes(4);

  let keyFields;
  if (type === 'ed25519') {
    const pub = Buffer.from(jwk.x, 'base64url');
    const seed = Buffer.from(jwk.d, 'base64url');
    keyFields = Buffer.concat([
      encodeString('ssh-ed25519'),
      encodeString(pub),
      // OpenSSH の ed25519 秘密鍵は「シード + 公開鍵」の64バイト
      encodeString(Buffer.concat([seed, pub]))
    ]);
  } else if (type === 'rsa') {
    const b = (name) => Buffer.from(jwk[name], 'base64url');
    keyFields = Buffer.concat([
      encodeString('ssh-rsa'),
      encodeMpint(b('n')),
      encodeMpint(b('e')),
      encodeMpint(b('d')),
      encodeMpint(b('qi')), // iqmp = q^-1 mod p
      encodeMpint(b('p')),
      encodeMpint(b('q'))
    ]);
  } else {
    throw new Error(`書き出しに対応していない鍵種別です: ${type}`);
  }

  let privateSection = Buffer.concat([
    check, check, // checkint を2回。復号できたかの目印
    keyFields,
    encodeString(comment || '')
  ]);

  // 暗号化なしでもブロック長8に合わせて 1,2,3... で埋める決まり
  const blockSize = 8;
  const padLength = (blockSize - (privateSection.length % blockSize)) % blockSize;
  if (padLength > 0) {
    privateSection = Buffer.concat([
      privateSection,
      Buffer.from(Array.from({ length: padLength }, (_, i) => i + 1))
    ]);
  }

  const body = Buffer.concat([
    OPENSSH_MAGIC,
    encodeString('none'),  // ciphername
    encodeString('none'),  // kdfname
    encodeString(''),      // kdfoptions
    encodeUint32(1),       // 鍵の数
    encodeString(publicBlob),
    encodeString(privateSection)
  ]);

  const base64 = body.toString('base64').replace(/(.{70})/g, '$1\n');
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${base64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

// --- 鍵の生成 ---------------------------------------------------------------

const GENERATABLE = {
  ed25519: { label: 'ed25519（推奨）', bits: 256 },
  'rsa-3072': { label: 'RSA 3072', bits: 3072 },
  'rsa-4096': { label: 'RSA 4096', bits: 4096 }
};

function generate({ type = 'ed25519', comment = '' } = {}) {
  if (!GENERATABLE[type]) throw new Error(`作れない鍵種別です: ${type}`);

  let keyPair;
  if (type === 'ed25519') {
    keyPair = crypto.generateKeyPairSync('ed25519');
  } else {
    keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: GENERATABLE[type].bits,
      publicExponent: 0x10001
    });
  }

  const blob = publicKeyBlobFrom(keyPair.publicKey);
  const cleanComment = String(comment || '').replace(/[\r\n]/g, ' ').trim().slice(0, 128);

  return {
    keyType: readKeyType(blob),
    bits: bitsOf(blob),
    fingerprint: fingerprint(blob),
    comment: cleanComment,
    publicKey: formatPublicKey(blob, cleanComment),
    privateKey: encodeOpenSshPrivate(keyPair.privateKey, blob, cleanComment)
  };
}

// authorized_keys に貼る1行。制限オプションを付けられるようにしておく。
function authorizedKeysLine(publicKey, { options = '' } = {}) {
  const line = String(publicKey).trim();
  return options ? `${options} ${line}` : line;
}

module.exports = {
  GENERATABLE,
  fingerprint,
  parsePublicKey,
  inspectPrivateKey,
  generate,
  authorizedKeysLine,
  // テストと内部用
  publicKeyBlobFrom,
  formatPublicKey,
  encodeOpenSshPrivate,
  bitsOf
};
