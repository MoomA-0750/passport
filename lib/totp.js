'use strict';
// TOTP（RFC 6238）。Node 標準の crypto.createHmac だけで足りるので自前で持つ。
// シークレットは items.js の秘密フィールド "totp" として暗号化保存され、
// ここには復号済みの値が渡ってくる。

const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input) {
  const cleaned = String(input).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (!cleaned || /[^A-Z2-7]/.test(cleaned)) {
    throw new Error('TOTP シークレットが Base32 ではありません');
  }
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of cleaned) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// otpauth:// URI も受け取れるようにする。1Password や Google Authenticator からの貼り付け対応。
function parseSecret(raw) {
  const text = String(raw || '').trim();
  if (text.toLowerCase().startsWith('otpauth://')) {
    const url = new URL(text);
    const secret = url.searchParams.get('secret');
    if (!secret) throw new Error('otpauth URI に secret がありません');
    return {
      secret,
      digits: parseInt(url.searchParams.get('digits') || '6', 10),
      period: parseInt(url.searchParams.get('period') || '30', 10),
      algorithm: (url.searchParams.get('algorithm') || 'SHA1').toLowerCase().replace('-', ''),
      label: decodeURIComponent(url.pathname.replace(/^\/+/, '')) || null,
      issuer: url.searchParams.get('issuer') || null
    };
  }
  return { secret: text, digits: 6, period: 30, algorithm: 'sha1', label: null, issuer: null };
}

function generate(rawSecret, { at = Date.now() } = {}) {
  const { secret, digits, period, algorithm } = parseSecret(rawSecret);
  const key = base32Decode(secret);
  const counter = Math.floor(at / 1000 / period);

  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);

  const hmac = crypto.createHmac(algorithm === 'sha1' ? 'sha1' : algorithm, key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = ((hmac[offset] & 0x7f) << 24)
    | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8)
    | (hmac[offset + 3] & 0xff);

  const code = String(binary % 10 ** digits).padStart(digits, '0');
  const elapsed = Math.floor(at / 1000) % period;
  return { code, period, digits, remainingSeconds: period - elapsed };
}

function isValidSecret(raw) {
  try {
    generate(raw);
    return true;
  } catch {
    return false;
  }
}

module.exports = { generate, parseSecret, base32Decode, isValidSecret };
