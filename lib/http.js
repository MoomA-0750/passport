'use strict';
// HTTP のこまごました処理。Express は使えないので（オフライン環境・依存ゼロ方針）、
// 必要な分だけ自前で持つ。

const config = require('./config');

const MAX_BODY_BYTES = 256 * 1024; // 金庫にこれ以上大きな本文は来ない

// セキュリティヘッダー。パスワードを扱う画面なので、外部への流出経路を塞ぐ。
//   ・CSP は self のみ。外部 CDN も inline script も許さない（Bootstrap は自分で配信している）
//   ・frame-ancestors none で、他サイトに埋め込んでのクリックジャッキングを防ぐ
//   ・Referrer-Policy no-referrer で、URL が外に出ない
function securityHeaders(req) {
  const headers = {
    'Content-Security-Policy': [
      "default-src 'self'",
      // script は絶対に緩めない。ここが XSS に対する本丸。
      "script-src 'self'",
      // style だけは 'unsafe-inline' を許す。Bootstrap のモーダルや
      // パスワード強度メーターが element.style を書くため（属性スタイルは
      // ハッシュや nonce では許可できない）。script が閉じている限り、
      // ここを開けても任意コード実行にはつながらない。
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "form-action 'self'",
      "base-uri 'none'",
      "object-src 'none'",
      "frame-ancestors 'none'"
    ].join('; '),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
    // 金庫の画面はどこにもキャッシュさせない
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    Pragma: 'no-cache'
  };
  // 自己署名でも HSTS は付ける（社内でこのホストを常に HTTPS で使うため）。
  // includeSubDomains は社内の他サービスを巻き込むので付けない。
  if (config.server.tls || (config.server.trustProxy && req.headers['x-forwarded-proto'] === 'https')) {
    headers['Strict-Transport-Security'] = 'max-age=31536000';
  }
  return headers;
}

function send(req, res, status, body, extraHeaders = {}) {
  const headers = { ...securityHeaders(req), ...extraHeaders };
  res.writeHead(status, headers);
  if (req.method === 'HEAD') {
    res.end();
    return;
  }
  res.end(body);
}

function sendJson(req, res, status, data, extraHeaders = {}) {
  const body = JSON.stringify(data);
  send(req, res, status, body, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    ...extraHeaders
  });
}

function sendHtml(req, res, status, html, extraHeaders = {}) {
  send(req, res, status, html, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(html),
    ...extraHeaders
  });
}

function redirect(req, res, location, extraHeaders = {}) {
  send(req, res, 302, '', { Location: location, ...extraHeaders });
}

function sendError(req, res, status, message) {
  if ((req.headers.accept || '').includes('application/json') || req.url.startsWith('/api/')) {
    sendJson(req, res, status, { error: message });
    return;
  }
  const escaped = String(message).replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));
  sendHtml(req, res, status, `<!doctype html><meta charset="utf-8"><title>${status}</title>` +
    `<body style="font-family:system-ui;padding:2rem"><h1>${status}</h1><p>${escaped}</p>` +
    '<p><a href="/">最初の画面へ</a></p>');
}

// JSON 本文を読む。サイズ上限を超えたら即座に切る。
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('リクエストが大きすぎます'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      const text = Buffer.concat(chunks).toString('utf8');
      const type = String(req.headers['content-type'] || '');
      try {
        if (type.includes('application/x-www-form-urlencoded')) {
          resolve(Object.fromEntries(new URLSearchParams(text)));
        } else {
          resolve(JSON.parse(text));
        }
      } catch (err) {
        reject(new Error(`本文を解釈できません: ${err.message}`));
      }
    });
    req.on('error', reject);
  });
}

// --- Chrome 拡張向けの CORS -------------------------------------------------

// 許可した拡張の Origin かどうか。ID を突き合わせるので、
// 別の拡張が勝手に API を叩きに来ても弾かれる。
function allowedExtensionOrigin(origin) {
  if (!config.extension.enabled) return false;
  if (!origin || !origin.startsWith('chrome-extension://')) return false;
  const id = origin.slice('chrome-extension://'.length).replace(/\/$/, '');
  if (!/^[a-p]{32}$/.test(id)) return false;
  return config.extension.allowedIds.includes(id);
}

// CORS ヘッダー。Cookie は渡さない（拡張は Bearer トークンで認証する）ので
// Allow-Credentials は付けない。これにより、拡張以外のページから
// ログイン中の Cookie を使って API を叩かれる経路を作らずに済む。
function corsHeaders(req) {
  const origin = req.headers.origin;
  if (!allowedExtensionOrigin(origin)) return {};
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '600',
    Vary: 'Origin'
  };
}

// クライアント IP。Nginx 前段のときだけ X-Forwarded-For を信じる。
// 信頼しない設定で信じると、IP を偽装した監査ログを書かれてしまう。
function clientIp(req) {
  if (config.server.trustProxy) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) return String(forwarded).split(',')[0].trim();
  }
  return req.socket.remoteAddress || null;
}

module.exports = {
  MAX_BODY_BYTES,
  securityHeaders,
  allowedExtensionOrigin,
  corsHeaders,
  send,
  sendJson,
  sendHtml,
  redirect,
  sendError,
  readJsonBody,
  clientIp
};
