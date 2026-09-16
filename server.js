'use strict';
// Passport のサーバー。node server.js で起動する。
//
// WordBox と同じく、フレームワークを使わず Node 標準の http / https だけで組む。
// ビルドなし、再起動なしで動く（テンプレートと static はリクエストごとに読める）。

const fs = require('fs');
const path = require('path');
const url = require('url');

const config = require('./lib/config');
const log = require('./lib/logger')('passport:server');
const store = require('./lib/store');
const keyring = require('./lib/keyring');
const session = require('./lib/session');
const users = require('./lib/users');
const audit = require('./lib/audit');
const http = require('./lib/http');
const template = require('./lib/template');
const api = require('./lib/api');

const STATIC_DIR = path.join(__dirname, 'static');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.map': 'application/json'
};

// --- 静的ファイル -----------------------------------------------------------

function serveStatic(req, res, pathname) {
  const rel = decodeURIComponent(pathname.replace(/^\/static\//, ''));
  const full = path.join(STATIC_DIR, rel);
  // static ディレクトリの外へ出る要求は弾く
  if (!full.startsWith(STATIC_DIR + path.sep)) {
    http.sendError(req, res, 403, 'そのパスは開けません');
    return;
  }
  if (!fs.existsSync(full) || !fs.statSync(full).isFile()) {
    http.sendError(req, res, 404, 'ファイルがありません');
    return;
  }
  const body = fs.readFileSync(full);
  const type = MIME[path.extname(full).toLowerCase()] || 'application/octet-stream';
  // Bootstrap などは変わらないので、静的ファイルだけは短くキャッシュを許す。
  // 画面 HTML は no-store のまま（http.securityHeaders）。
  http.send(req, res, 200, body, {
    'Content-Type': type,
    'Content-Length': body.length,
    'Cache-Control': 'private, max-age=300'
  });
}

// Authorization: Bearer <トークン> を読む。Chrome 拡張がこれを使う。
function readBearerToken(req) {
  const header = req.headers.authorization;
  if (!header) return null;
  const match = String(header).match(/^Bearer\s+([A-Za-z0-9_-]{16,128})$/);
  return match ? match[1] : null;
}

// --- 画面 -------------------------------------------------------------------

function renderPage(req, res, name, vars) {
  http.sendHtml(req, res, 200, template.render(name, vars));
}

function handlePage(req, res, ctx) {
  const { pathname } = ctx.url;

  // ユーザーが1人も居ないうちは、必ずセットアップ画面へ送る
  const needsSetup = users.count() === 0;
  if (needsSetup && pathname !== '/setup') {
    http.redirect(req, res, '/setup');
    return;
  }
  if (!needsSetup && pathname === '/setup') {
    http.redirect(req, res, '/');
    return;
  }

  if (pathname === '/setup') {
    renderPage(req, res, 'setup', { title: 'Passport のセットアップ', bodyClass: 'page-centered' });
    return;
  }

  if (pathname === '/login') {
    if (ctx.user) {
      http.redirect(req, res, '/');
      return;
    }
    renderPage(req, res, 'login', { title: 'Passport にログイン', bodyClass: 'page-centered' });
    return;
  }

  if (!ctx.user) {
    http.redirect(req, res, '/login');
    return;
  }

  if (pathname === '/' || pathname === '/vaults') {
    renderPage(req, res, 'app', {
      title: 'Passport',
      bodyClass: 'page-app',
      bootstrapData: JSON.stringify({
        user: ctx.user,
        csrfToken: ctx.session.csrfToken,
        idleLockMinutes: config.session.idleLockMinutes,
        minPasswordLength: config.auth.minPasswordLength
      })
    });
    return;
  }

  if (pathname === '/admin') {
    if (ctx.user.role !== 'admin') {
      http.sendError(req, res, 403, '管理者だけが開けます');
      return;
    }
    renderPage(req, res, 'admin', {
      title: 'Passport の管理',
      bodyClass: 'page-app',
      bootstrapData: JSON.stringify({
        user: ctx.user,
        csrfToken: ctx.session.csrfToken,
        minPasswordLength: config.auth.minPasswordLength
      })
    });
    return;
  }

  http.sendError(req, res, 404, 'そのページはありません');
}

// --- リクエストの入口 -------------------------------------------------------

async function handleRequest(req, res) {
  const done = log.timer(`${req.method} ${req.url}`);
  try {
    const parsed = new url.URL(req.url, `http://${req.headers.host || 'localhost'}`);

    // 静的ファイルは認証前に返す（Bootstrap とログイン画面の JS のため）
    if (parsed.pathname.startsWith('/static/')) {
      serveStatic(req, res, parsed.pathname);
      done();
      return;
    }

    // 認証は2通り。
    //   ・画面     : Cookie（CSRF 対策が要る）
    //   ・Chrome拡張: Authorization: Bearer <トークン>（勝手に付いてこないので CSRF 対策が要らない）
    // どちらで来たかを覚えておく。Bearer のときだけ CSRF 検証を省く。
    const bearer = readBearerToken(req);
    const sessionId = bearer || session.sessionIdFromRequest(req);
    const current = session.touch(sessionId);
    const user = current ? users.toPublic(users.get(current.userId)) : null;

    // セッションはあるがユーザーが消えている / 無効化された場合は切る
    if (current && (!user || user.status !== 'active')) {
      session.destroy(sessionId);
      http.redirect(req, res, '/login', { 'Set-Cookie': session.logoutCookieHeader(req) });
      done();
      return;
    }

    const ctx = {
      req,
      res,
      url: parsed,
      sessionId,
      session: current,
      user,
      ip: http.clientIp(req),
      viaBearer: !!bearer,
      body: {},
      setCookie: null
    };

    // 拡張からの事前確認（プリフライト）。許可した拡張だけに応える。
    if (req.method === 'OPTIONS' && parsed.pathname.startsWith('/api/')) {
      const cors = http.corsHeaders(req);
      if (Object.keys(cors).length === 0) {
        http.sendError(req, res, 403, 'この Origin からは利用できません');
      } else {
        http.send(req, res, 204, '', { ...cors, 'Content-Length': 0 });
      }
      done();
      return;
    }

    if (parsed.pathname.startsWith('/api/')) {
      if (!['GET', 'HEAD'].includes(req.method)) {
        try {
          ctx.body = await http.readJsonBody(req);
        } catch (err) {
          http.sendJson(req, res, 400, { error: err.message });
          done();
          return;
        }

        // CSRF 検証。
        // Bearer で来たリクエストは対象外。Cookie と違って勝手には付いてこないので、
        // 他サイトに踏ませても攻撃者はトークンを付けられない。
        // ここを「Bearer があれば素通し」にしないよう、Cookie 認証のときだけ検証する。
        const isPreAuth = ['/api/setup', '/api/login'].includes(parsed.pathname);
        const isExtensionCall = ctx.viaBearer
          || (isPreAuth && http.allowedExtensionOrigin(req.headers.origin));
        const csrfResult = isExtensionCall
          ? { ok: true }
          : session.checkCsrf(req, current, req.headers['x-csrf-token'], { requireToken: !isPreAuth });
        if (!csrfResult.ok) {
          log.warn(`CSRF 検証で弾きました: ${parsed.pathname}: ${csrfResult.reason}`);
          audit.record('access.denied', {
            actor: user && user.id, ip: ctx.ip, note: `CSRF: ${csrfResult.reason}`
          });
          http.sendJson(req, res, 403, { error: 'リクエストを検証できませんでした。画面を再読み込みしてやり直してください' });
          done();
          return;
        }
      }
      await api.handle(ctx);
      done();
      return;
    }

    if (!['GET', 'HEAD'].includes(req.method)) {
      http.sendError(req, res, 405, 'そのメソッドは使えません');
      done();
      return;
    }

    handlePage(req, res, ctx);
    done();
  } catch (err) {
    log.error(`未処理の例外: ${err.stack}`);
    if (!res.headersSent) http.sendError(req, res, 500, 'サーバー側でエラーが起きました');
    done();
  }
}

// --- 起動 -------------------------------------------------------------------

function loadTlsOptions() {
  const { tlsKey, tlsCert } = config.server;
  for (const file of [tlsKey, tlsCert]) {
    if (!fs.existsSync(file)) {
      log.error(`TLS のファイルがありません: ${file}`);
      log.error('  自己署名の証明書は `node bin/make-cert.js` で作れます。');
      log.error('  Nginx で TLS を終端する構成なら passport.ini の [server] tls = off にしてください。');
      process.exit(1);
    }
  }
  return {
    key: fs.readFileSync(tlsKey),
    cert: fs.readFileSync(tlsCert),
    // 古いプロトコルは開けない
    minVersion: 'TLSv1.2'
  };
}

function start() {
  log.info('Passport を起動します');
  if (config.configPath) log.info(`設定ファイル: ${config.configPath}`);
  else log.info('設定ファイルなし（既定値で動きます）');

  store.init();
  keyring.unlock();
  keyring.selfTest();
  log.info('暗号の自己テスト: OK');

  if (!config.server.tls && !config.server.trustProxy) {
    log.warn('TLS が無効で、リバースプロキシも想定していません。');
    log.warn('この状態ではパスワードが平文でネットワークを流れます。社内でも HTTPS を用意してください。');
  }

  const server = config.server.tls
    ? require('https').createServer(loadTlsOptions(), handleRequest)
    : require('http').createServer(handleRequest);

  server.headersTimeout = 20 * 1000;
  server.requestTimeout = 60 * 1000;

  server.listen(config.server.port, config.server.host, () => {
    const scheme = config.server.tls ? 'https' : 'http';
    log.info(`待ち受け: ${scheme}://${config.server.host}:${config.server.port}`);
    if (users.count() === 0) {
      log.info('まだユーザーが居ません。ブラウザで開いて最初の管理者を作ってください。');
    }
    audit.record('server.start', { note: `${scheme}://${config.server.host}:${config.server.port}` });
  });

  const shutdown = (signal) => {
    log.info(`${signal} を受けたので終了します（セッション ${session.stats().active} 件を破棄）`);
    server.close(() => process.exit(0));
    // 接続が残っていても待ち続けない
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  return server;
}

if (require.main === module) {
  start();
}

module.exports = { start, handleRequest };
