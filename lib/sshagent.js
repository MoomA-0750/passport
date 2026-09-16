'use strict';
// SSH エージェント（手元の端末で動く側）。OpenSSH のエージェントプロトコルを話す。
// bin/passport の `passport ssh-agent` から使う。サーバーでは動かない。
//
// 本人の決定（docs/plans/運用機能.md）: 鍵を端末に持ってくる。
//   起動時に Passport から SSH 鍵を取り出してメモリに持ち、署名は手元で行う。
//   取り出しは鍵ごとに監査ログに残るが、個々の署名は残らない。
//
// 対応:
//   ・鍵: ed25519、RSA（rsa-sha2-256 / rsa-sha2-512。SHA-1 の ssh-rsa 署名は断る）、ECDSA（nistp256/384/521）
//   ・形式: 暗号化されていない OpenSSH 形式、PEM / PKCS#8（パスフレーズを預けてあれば暗号化 PEM も）
//   ・暗号化された OpenSSH 形式は読めない（bcrypt_pbkdf を実装しない方針）。読み飛ばして知らせる
//   ・メッセージ: 11 鍵の一覧 / 13 署名。それ以外（鍵の追加・削除・ロック・拡張）は 5 失敗で返す
//
// 参考: draft-miller-ssh-agent

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const sshkeys = require('./sshkeys');

const MSG = {
  FAILURE: 5,
  REQUEST_IDENTITIES: 11,
  IDENTITIES_ANSWER: 12,
  SIGN_REQUEST: 13,
  SIGN_RESPONSE: 14
};
const FLAG_RSA_SHA2_256 = 2;
const FLAG_RSA_SHA2_512 = 4;
// これより大きいメッセージは受け付けない（OpenSSH の ssh-agent と同じ上限）
const MAX_MESSAGE = 256 * 1024;

class SkipKey extends Error {}

// --- ワイヤ形式 ---------------------------------------------------------------

class Reader {
  constructor(buf) {
    this.buf = buf;
    this.pos = 0;
  }

  readUint32() {
    if (this.pos + 4 > this.buf.length) throw new Error('データが途中で終わっています');
    const v = this.buf.readUInt32BE(this.pos);
    this.pos += 4;
    return v;
  }

  readString() {
    const len = this.readUint32();
    if (this.pos + len > this.buf.length) throw new Error('データが途中で終わっています');
    const v = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return v;
  }
}

function str(value) {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(body.length, 0);
  return Buffer.concat([len, body]);
}

function uint32(value) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value >>> 0, 0);
  return b;
}

function mpint(buf) {
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0) i += 1;
  let body = buf.subarray(i);
  if (body.length && (body[0] & 0x80)) body = Buffer.concat([Buffer.from([0]), body]);
  return str(body);
}

// mpint → 符号なしの大きさ（先頭の 0 を落とす）
function unsigned(buf) {
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0) i += 1;
  return buf.subarray(i);
}

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const toBig = (buf) => BigInt(`0x${unsigned(buf).toString('hex') || '0'}`);
function fromBig(value, length = 0) {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const buf = Buffer.from(hex, 'hex');
  return length && buf.length < length ? Buffer.concat([Buffer.alloc(length - buf.length), buf]) : buf;
}

// --- 秘密鍵を読む ---------------------------------------------------------------

const CURVES = {
  nistp256: { crv: 'P-256', size: 32, hash: 'sha256' },
  nistp384: { crv: 'P-384', size: 48, hash: 'sha384' },
  nistp521: { crv: 'P-521', size: 66, hash: 'sha512' }
};

function loadOpenSsh(text) {
  const match = String(text).match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/);
  if (!match) return null;
  const body = Buffer.from(match[1].replace(/\s+/g, ''), 'base64');
  const magic = Buffer.from('openssh-key-v1\0', 'binary');
  if (!body.subarray(0, magic.length).equals(magic)) throw new SkipKey('OpenSSH 秘密鍵のヘッダが壊れています');
  const r = new Reader(body.subarray(magic.length));
  const cipher = r.readString().toString();
  const kdf = r.readString().toString();
  r.readString();
  if (r.readUint32() !== 1) throw new SkipKey('鍵が複数入った形式は扱えません');
  const publicBlob = r.readString();
  if (cipher !== 'none' || kdf !== 'none') {
    throw new SkipKey('パスフレーズで暗号化された OpenSSH 形式の鍵は読めません（ssh-keygen -p で外してから預け直すか、PEM 形式で預けてください）');
  }
  const p = new Reader(r.readString());
  if (p.readUint32() !== p.readUint32()) throw new SkipKey('秘密鍵の検査値が一致しません');
  const type = p.readString().toString();

  let key;
  if (type === 'ssh-ed25519') {
    const pub = p.readString();
    const priv = p.readString(); // シード32 + 公開鍵32
    key = crypto.createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: b64u(priv.subarray(0, 32)), x: b64u(pub) }, format: 'jwk' });
  } else if (type === 'ssh-rsa') {
    const n = p.readString();
    const e = p.readString();
    const d = p.readString();
    const iqmp = p.readString();
    const pp = p.readString();
    const q = p.readString();
    // OpenSSH の形式には dp / dq が無いので計算する（JWK では必須）
    const dBig = toBig(d);
    const dp = dBig % (toBig(pp) - 1n);
    const dq = dBig % (toBig(q) - 1n);
    key = crypto.createPrivateKey({
      key: {
        kty: 'RSA',
        n: b64u(unsigned(n)),
        e: b64u(unsigned(e)),
        d: b64u(unsigned(d)),
        p: b64u(unsigned(pp)),
        q: b64u(unsigned(q)),
        dp: b64u(fromBig(dp)),
        dq: b64u(fromBig(dq)),
        qi: b64u(unsigned(iqmp))
      },
      format: 'jwk'
    });
  } else if (type.startsWith('ecdsa-sha2-')) {
    const curveName = p.readString().toString();
    const curve = CURVES[curveName];
    if (!curve) throw new SkipKey(`対応していない曲線です: ${curveName}`);
    const point = p.readString();
    const scalar = p.readString();
    if (point[0] !== 0x04) throw new SkipKey('圧縮された点は扱えません');
    key = crypto.createPrivateKey({
      key: {
        kty: 'EC',
        crv: curve.crv,
        x: b64u(point.subarray(1, 1 + curve.size)),
        y: b64u(point.subarray(1 + curve.size)),
        d: b64u(fromBig(toBig(scalar), curve.size))
      },
      format: 'jwk'
    });
  } else {
    throw new SkipKey(`対応していない鍵種別です: ${type}`);
  }
  const comment = p.readString().toString();
  return { key, comment, publicBlob };
}

// 預けてある秘密鍵（とパスフレーズ）から、署名に使える鍵を作る。使えなければ SkipKey を投げる。
function loadPrivateKey(text, { passphrase = null, comment = '' } = {}) {
  let loaded;
  try {
    loaded = loadOpenSsh(text);
  } catch (err) {
    if (err instanceof SkipKey) throw err;
    throw new SkipKey(`秘密鍵を読めません: ${err.message}`);
  }
  if (!loaded) {
    let key;
    try {
      key = crypto.createPrivateKey(passphrase ? { key: String(text), passphrase } : String(text));
    } catch (err) {
      throw new SkipKey(/bad decrypt|bad password|interrupted or cancelled/i.test(err.message)
        ? 'パスフレーズが無いか違うため、秘密鍵を開けません'
        : `秘密鍵を読めません: ${err.message}`);
    }
    loaded = { key, comment: '', publicBlob: sshkeys.publicKeyBlobFrom(crypto.createPublicKey(key)) };
  }
  // 公開鍵が秘密鍵と合っているかを確かめる（壊れた・差し替えられた鍵で署名しない）
  const derived = sshkeys.publicKeyBlobFrom(crypto.createPublicKey(loaded.key));
  if (!derived.equals(loaded.publicBlob)) throw new SkipKey('秘密鍵と公開鍵が一致しません');
  if (!['ed25519', 'rsa', 'ec'].includes(loaded.key.asymmetricKeyType)) {
    throw new SkipKey(`対応していない鍵種別です: ${loaded.key.asymmetricKeyType}`);
  }
  const entry = {
    key: loaded.key,
    publicBlob: loaded.publicBlob,
    comment: comment || loaded.comment || '',
    fingerprint: sshkeys.fingerprint(loaded.publicBlob)
  };
  // 一度署名して、公開鍵で検証できるかを確かめる。上の比較は公開成分どうしなので、
  // RSA / ECDSA では秘密の成分が壊れていても通ってしまう
  const probe = crypto.randomBytes(32);
  const signature = sign(entry, probe, FLAG_RSA_SHA2_256);
  const publicKey = crypto.createPublicKey(loaded.key);
  const r = new Reader(signature);
  const alg = r.readString().toString();
  const blob = r.readString();
  let ok;
  if (alg === 'ssh-ed25519') {
    ok = crypto.verify(null, probe, publicKey, blob);
  } else if (alg === 'rsa-sha2-256') {
    ok = crypto.verify('sha256', probe, publicKey, blob);
  } else {
    const curve = CURVES[alg.replace('ecdsa-sha2-', '')];
    const sr = new Reader(blob);
    const pad = (b) => Buffer.concat([Buffer.alloc(Math.max(0, curve.size - unsigned(b).length)), unsigned(b)]);
    ok = crypto.verify(curve.hash, probe, { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.concat([pad(sr.readString()), pad(sr.readString())]));
  }
  if (!ok) throw new SkipKey('秘密鍵が壊れています（試しに署名した結果を検証できません）');
  return entry;
}

// --- 署名 -------------------------------------------------------------------

function sign(entry, data, flags) {
  const type = entry.key.asymmetricKeyType;
  if (type === 'ed25519') {
    return Buffer.concat([str('ssh-ed25519'), str(crypto.sign(null, data, entry.key))]);
  }
  if (type === 'rsa') {
    let alg;
    let hash;
    if (flags & FLAG_RSA_SHA2_512) {
      alg = 'rsa-sha2-512';
      hash = 'sha512';
    } else if (flags & FLAG_RSA_SHA2_256) {
      alg = 'rsa-sha2-256';
      hash = 'sha256';
    } else {
      return null; // SHA-1 の ssh-rsa 署名はしない
    }
    return Buffer.concat([str(alg), str(crypto.sign(hash, data, entry.key))]);
  }
  if (type === 'ec') {
    const curveName = new Reader(entry.publicBlob).readString().toString().replace('ecdsa-sha2-', '');
    const curve = CURVES[curveName];
    const raw = crypto.sign(curve.hash, data, { key: entry.key, dsaEncoding: 'ieee-p1363' });
    const half = raw.length / 2;
    const sigBlob = Buffer.concat([mpint(raw.subarray(0, half)), mpint(raw.subarray(half))]);
    return Buffer.concat([str(`ecdsa-sha2-${curveName}`), str(sigBlob)]);
  }
  return null;
}

// 1通のメッセージ（長さを除いた本体）を処理して、返事の本体を返す。
function handleMessage(keys, body) {
  const failure = Buffer.from([MSG.FAILURE]);
  if (!body.length) return failure;
  const type = body[0];
  try {
    if (type === MSG.REQUEST_IDENTITIES) {
      const list = keys.list();
      return Buffer.concat([
        Buffer.from([MSG.IDENTITIES_ANSWER]),
        uint32(list.length),
        ...list.flatMap((k) => [str(k.publicBlob), str(k.comment)])
      ]);
    }
    if (type === MSG.SIGN_REQUEST) {
      const r = new Reader(body.subarray(1));
      const blob = r.readString();
      const data = r.readString();
      const flags = r.pos < r.buf.length ? r.readUint32() : 0;
      const entry = keys.list().find((k) => k.publicBlob.equals(blob));
      if (!entry) return failure;
      const signature = sign(entry, data, flags);
      if (!signature) return failure;
      keys.onSign(entry);
      return Buffer.concat([Buffer.from([MSG.SIGN_RESPONSE]), str(signature)]);
    }
  } catch {
    return failure;
  }
  return failure;
}

// --- ソケット -------------------------------------------------------------------

// keys: { list(): [{ key, publicBlob, comment, fingerprint }], onSign(entry) }
function listen(socketPath, keys) {
  // Unix ソケットのパスは 108 バイトまで。長いと黙って切り詰められ、別の場所にソケットができる
  if (Buffer.byteLength(socketPath) > 100) {
    return Promise.reject(new Error(`ソケットのパスが長すぎます（${Buffer.byteLength(socketPath)} バイト。100 バイトまで）: ${socketPath}`));
  }
  const server = net.createServer((conn) => {
    let pending = Buffer.alloc(0);
    conn.on('data', (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      while (pending.length >= 4) {
        const len = pending.readUInt32BE(0);
        if (len > MAX_MESSAGE) {
          conn.destroy();
          return;
        }
        if (pending.length < 4 + len) break;
        const body = pending.subarray(4, 4 + len);
        pending = pending.subarray(4 + len);
        const reply = handleMessage(keys, body);
        conn.write(Buffer.concat([uint32(reply.length), reply]));
      }
    });
    conn.on('error', () => conn.destroy());
  });
  return new Promise((resolve, reject) => {
    const oldMask = process.umask(0o177); // ソケットを最初から 0600 で作る
    server.once('error', (err) => {
      process.umask(oldMask);
      reject(err);
    });
    // オブジェクトで渡す。文字列だと、数字だけの値が TCP のポートと解釈される
    server.listen({ path: socketPath }, () => {
      process.umask(oldMask);
      fs.chmodSync(socketPath, 0o600);
      resolve(server);
    });
  });
}

module.exports = { loadPrivateKey, handleMessage, listen, SkipKey, MSG, FLAG_RSA_SHA2_256, FLAG_RSA_SHA2_512, _encode: { str, uint32 } };
