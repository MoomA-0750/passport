'use strict';
// CLI と自動化トークンのテスト。サーバーを実際に起動し、bin/passport を子プロセスで動かす。
// 自動化トークンは新しい認証経路なので、「届いてはいけない API に届かない」ことを中心に見る。

const test = require('node:test');
const assert = require('node:assert');
const { spawn, spawnSync, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');

const REPO = path.resolve(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-cli-test-'));
const DATA = path.join(TMP, 'data');
const HOME = path.join(TMP, 'home');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let server;
let BASE;
let serverOutput = '';
const seed = {};

function freePort() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  });
}

const serverEnv = () => {
  const env = { ...process.env, PASSPORT_DATA_DIR: DATA, PASSPORT_MASTER_KEY_FILE: path.join(TMP, 'keys', 'master.key') };
  delete env.PASSPORT_MASTER_PASSPHRASE;
  return env;
};

// CLI を動かす。HOME を差し替えて、本人の ~/.config を触らない
function cli(args, { input = '', token = null, env = {} } = {}) {
  const e = { ...process.env, HOME, XDG_CONFIG_HOME: path.join(HOME, '.config'), ...env };
  delete e.PASSPORT_TOKEN;
  delete e.PASSPORT_URL;
  if (token) e.PASSPORT_TOKEN = token;
  const run = spawnSync(process.execPath, [path.join(REPO, 'bin', 'passport'), ...args], { input, env: e, encoding: 'utf8' });
  return { code: run.status, out: run.stdout, err: run.stderr };
}

function browser() {
  let cookie = '';
  let csrf = null;
  return {
    async call(pathname, { method = 'GET', body, headers = {} } = {}) {
      const h = { Origin: BASE, ...headers };
      if (body !== undefined) h['Content-Type'] = 'application/json';
      if (csrf && method !== 'GET') h['X-CSRF-Token'] = csrf;
      if (cookie) h.Cookie = cookie;
      const res = await fetch(BASE + pathname, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
      for (const c of res.headers.getSetCookie()) {
        const v = c.split(';')[0];
        if (v.startsWith('passport_session=')) cookie = v === 'passport_session=' ? '' : v;
      }
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch { /* */ }
      return { status: res.status, json, text, headers: res.headers };
    },
    async login(username, password) {
      const r = await this.call('/api/login', { method: 'POST', body: { username, password } });
      csrf = r.json && r.json.csrfToken;
      return r;
    }
  };
}

const bearer = (token, pathname, { method = 'GET', body, headers = {} } = {}) => fetch(BASE + pathname, {
  method,
  headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
  body: body ? JSON.stringify(body) : undefined
});

function auditEntries() {
  const dir = path.join(DATA, 'audit');
  return fs.readdirSync(dir).flatMap((f) => fs.readFileSync(path.join(dir, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)));
}

test.before(async () => {
  const env = serverEnv();
  execFileSync('node', ['bin/init-master-key.js'], { cwd: REPO, env, stdio: 'ignore' });
  const script = `
    const store=require('./lib/store'),keyring=require('./lib/keyring'),integrity=require('./lib/integrity'),
      users=require('./lib/users'),vaults=require('./lib/vaults'),items=require('./lib/items');
    store.init();keyring.unlock();integrity.checkOnStartup();
    const owner=users.create({username:'owner',password:'owner-password-123',role:'admin'});
    const other=users.create({username:'other',password:'other-password-123'});
    const ops=vaults.create({name:'運用',ownerId:owner.id,actor:owner.id});
    const secret=vaults.create({name:'秘密',ownerId:owner.id,actor:owner.id});
    const theirs=vaults.create({name:'よそ',ownerId:other.id,actor:other.id});
    vaults.addMember(theirs.id,{userId:owner.id,role:'viewer',actor:other.id});
    vaults.addMember(ops.id,{userId:other.id,role:'viewer',actor:owner.id});
    const db=items.create(ops.id,{title:'本番 DB',username:'app',secrets:{password:'db-pass-VALUE-1',note:'メモの中身'}},{actor:owner.id});
    items.create(ops.id,{title:'重複',secrets:{password:'x-1'}},{actor:owner.id});
    items.create(ops.id,{title:'重複',secrets:{password:'x-2'}},{actor:owner.id});
    items.create(ops.id,{title:'二段階',secrets:{totp:'JBSWY3DPEHPK3PXP'}},{actor:owner.id});
    items.create(secret.id,{title:'金庫の鍵',secrets:{password:'secret-vault-VALUE'}},{actor:owner.id});
    items.create(theirs.id,{title:'よその鍵',secrets:{password:'theirs-VALUE'}},{actor:other.id});
    console.log(JSON.stringify({ownerId:owner.id,otherId:other.id,ops:ops.id,secret:secret.id,theirs:theirs.id,db:db.id}));
  `;
  Object.assign(seed, JSON.parse(execFileSync('node', ['-e', script], { cwd: REPO, env, encoding: 'utf8' }).trim().split('\n').pop()));

  const port = await freePort();
  BASE = `http://127.0.0.1:${port}`;
  server = spawn('node', ['server.js'], {
    cwd: REPO,
    env: { ...env, PASSPORT_PORT: String(port), PASSPORT_HOST: '127.0.0.1', PASSPORT_TLS: 'off', PASSPORT_TRUST_PROXY: 'on' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  server.stdout.on('data', (d) => { serverOutput += d; });
  server.stderr.on('data', (d) => { serverOutput += d; });
  for (let i = 0; i < 50 && !/待ち受け/.test(serverOutput); i += 1) await sleep(100);
  assert.match(serverOutput, /待ち受け/, serverOutput);
});

test.after(async () => {
  if (server) server.kill('SIGTERM');
  await sleep(300);
  fs.rmSync(TMP, { recursive: true, force: true });
});

// --- 人の CLI ----------------------------------------------------------------

test('CLI: ログインすると、セッションが 0600 で保存され、Cookie は受け取らない', async () => {
  const r = cli(['login', '--url', BASE, '--user', 'owner'], { input: 'owner-password-123\n' });
  assert.strictEqual(r.code, 0, r.err);
  const dir = path.join(HOME, '.config', 'passport');
  assert.strictEqual(fs.statSync(dir).mode & 0o777, 0o700);
  assert.strictEqual(fs.statSync(path.join(dir, 'session.json')).mode & 0o777, 0o600);
  const saved = JSON.parse(fs.readFileSync(path.join(dir, 'session.json'), 'utf8'));
  assert.ok(saved.token && !saved.token.startsWith('pp_'));
  assert.ok(!fs.readFileSync(path.join(dir, 'config.json'), 'utf8').includes(saved.token));

  const raw = await fetch(`${BASE}/api/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: BASE, 'X-Passport-Client': 'cli' },
    body: JSON.stringify({ username: 'owner', password: 'owner-password-123' })
  });
  assert.strictEqual(raw.headers.getSetCookie().length, 0, 'CLI に Cookie を渡している');
});

test('CLI: 間違ったパスワードでは保存しない', () => {
  const home2 = cli(['login', '--url', BASE, '--user', 'owner'], { input: 'wrong-password-000\n', env: { XDG_CONFIG_HOME: path.join(TMP, 'other-home') } });
  assert.strictEqual(home2.code, 3);
  assert.ok(!fs.existsSync(path.join(TMP, 'other-home', 'passport', 'session.json')));
});

test('CLI: whoami / vaults / ls', () => {
  assert.match(cli(['whoami']).out, /^owner/);
  const vaults = cli(['vaults']);
  assert.strictEqual(vaults.code, 0, vaults.err);
  assert.match(vaults.out, /運用/);
  assert.match(vaults.out, /よそ/);
  const ls = cli(['ls', '運用']);
  assert.match(ls.out, /本番 DB\tapp\tpassword,note/);
  assert.ok(!ls.out.includes('db-pass-VALUE-1'), '一覧に秘密が出ている');
});

test('CLI: read は値だけを出し、パイプでは末尾に改行を付けない', () => {
  const r = cli(['read', '運用/本番 DB']);
  assert.strictEqual(r.code, 0, r.err);
  assert.strictEqual(r.out, 'db-pass-VALUE-1');
  assert.strictEqual(cli(['read', '運用/本番 DB/note']).out, 'メモの中身');
  assert.strictEqual(cli(['read', '運用/本番 DB/username']).out, 'app');
  assert.strictEqual(cli(['read', `${seed.ops}/${seed.db}`]).out, 'db-pass-VALUE-1', 'ID で指定できない');
});

test('CLI: 同じ名前が複数あると ID を求め、無いフィールドは分かるように断る', () => {
  const dup = cli(['read', '運用/重複']);
  assert.strictEqual(dup.code, 1);
  assert.match(dup.err, /2 個あります/);
  const missing = cli(['read', '運用/本番 DB/totp']);
  assert.match(missing.err, /totp はありません/);
  assert.strictEqual(cli(['read', '運用/無い']).code, 1);
});

test('CLI: totp はコードだけを出す', () => {
  const r = cli(['totp', '運用/二段階']);
  assert.strictEqual(r.code, 0, r.err);
  assert.match(r.out, /^\d{6}$/);
});

test('CLI: 読み出しは本人の閲覧として監査ログに残り、CLI と分かる', () => {
  const entry = auditEntries().find((e) => e.event === 'item.view_secret' && e.itemId === seed.db && /CLI/.test(e.note || ''));
  assert.ok(entry);
  assert.strictEqual(entry.actor, seed.ownerId);
});

test('CLI: 保存したセッションのファイルがほかの人から読めると、使わない', () => {
  const file = path.join(HOME, '.config', 'passport', 'session.json');
  fs.chmodSync(file, 0o644);
  try {
    const r = cli(['vaults']);
    assert.strictEqual(r.code, 1);
    assert.match(r.err, /chmod 600/);
  } finally {
    fs.chmodSync(file, 0o600);
  }
});

test('CLI: Cookie のセッションでは読み出し API を使えない', async () => {
  const b = browser();
  await b.login('owner', 'owner-password-123');
  assert.strictEqual((await b.call('/api/automation/vaults')).status, 401);
});

test('CLI: ログアウトすると、手元のファイルが消え、サーバーでもそのトークンが使えなくなる', async () => {
  const saved = JSON.parse(fs.readFileSync(path.join(HOME, '.config', 'passport', 'session.json'), 'utf8'));
  const r = cli(['logout']);
  assert.strictEqual(r.code, 0, r.err);
  assert.ok(!fs.existsSync(path.join(HOME, '.config', 'passport', 'session.json')));
  assert.strictEqual((await bearer(saved.token, '/api/automation/vaults')).status, 401);
  assert.strictEqual(cli(['vaults']).code, 3);
});

// --- 自動化トークン ------------------------------------------------------------

let ownerBrowser;
let token;
let tokenId;

test('トークン: 期限は必須で最長 365 日。owner でない Vault は対象にできない', async () => {
  ownerBrowser = browser();
  await ownerBrowser.login('owner', 'owner-password-123');
  const noExpiry = await ownerBrowser.call('/api/tokens', { method: 'POST', body: { name: 'x', vaultIds: [seed.ops] } });
  assert.strictEqual(noExpiry.status, 400);
  const tooLong = await ownerBrowser.call('/api/tokens', { method: 'POST', body: { name: 'x', vaultIds: [seed.ops], expiresInDays: 366 } });
  assert.strictEqual(tooLong.status, 400);
  const notOwner = await ownerBrowser.call('/api/tokens', { method: 'POST', body: { name: 'x', vaultIds: [seed.ops, seed.theirs], expiresInDays: 30 } });
  assert.strictEqual(notOwner.status, 403);
});

test('トークン: 発行すると一度だけトークンが返り、サーバーには秘密が残らない', async () => {
  const r = await ownerBrowser.call('/api/tokens', { method: 'POST', body: { name: '夜間バックアップ', vaultIds: [seed.ops], expiresInDays: 30 } });
  assert.strictEqual(r.status, 200, r.text);
  token = r.json.token;
  tokenId = r.json.info.id;
  assert.match(token, /^pp_[0-9a-f]{24}_[A-Za-z0-9_-]{43}$/);
  const secretPart = token.split('_').slice(2).join('_');
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
  for (const file of walk(DATA)) assert.ok(!fs.readFileSync(file, 'utf8').includes(secretPart), `${file} にトークンの秘密が残っている`);
  const list = await ownerBrowser.call('/api/tokens');
  assert.ok(!list.text.includes(secretPart));
  assert.ok(!/secretHash/.test(list.text));
});

test('トークン: 決めた Vault だけを読める（CLI から）', () => {
  const vaults = cli(['vaults'], { token });
  assert.strictEqual(vaults.code, 0, vaults.err);
  assert.match(vaults.out, /運用/);
  assert.ok(!/秘密|よそ/.test(vaults.out), '対象外の Vault が見えている');
  assert.strictEqual(cli(['read', '運用/本番 DB'], { token }).out, 'db-pass-VALUE-1');
  const other = cli(['read', `${seed.secret}/x`], { token });
  assert.strictEqual(other.code, 1);
  assert.match(cli(['whoami'], { token }).out, /夜間バックアップ/);
});

test('トークン: 対象外の Vault・ほかの API・書き込みには届かない', async () => {
  const forbiddenVault = await bearer(token, `/api/automation/vaults/${seed.secret}/items`);
  assert.strictEqual(forbiddenVault.status, 403);
  for (const [method, pathname, body] of [
    ['GET', '/api/vaults'],
    ['GET', `/api/vaults/${seed.ops}/items`],
    ['POST', `/api/vaults/${seed.ops}/items/${seed.db}/reveal`, { field: 'password' }],
    ['POST', `/api/vaults/${seed.ops}/items`, { title: '書けてはいけない' }],
    ['POST', '/api/tokens', { name: '増殖', vaultIds: [seed.ops], expiresInDays: 30 }],
    ['GET', '/api/tokens'],
    ['GET', '/api/me/sessions'],
    ['GET', '/api/audit'],
    ['GET', '/']
  ]) {
    const r = await bearer(token, pathname, { method, body });
    assert.strictEqual(r.status, 401, `${method} ${pathname} に届いた（${r.status}）`);
  }
  // 読み出し API にも書き込みの口は無い
  const write = await bearer(token, `/api/automation/vaults/${seed.ops}/items`, { method: 'POST', body: { title: 'x' } });
  assert.strictEqual(write.status, 404);
});

test('トークン: でたらめ・秘密違いのトークンは 401', async () => {
  assert.strictEqual((await bearer('pp_000000000000000000000000_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '/api/automation/vaults')).status, 401);
  const tampered = `${token.slice(0, -1)}${token.endsWith('A') ? 'B' : 'A'}`;
  assert.strictEqual((await bearer(tampered, '/api/automation/vaults')).status, 401);
  assert.ok(auditEntries().some((e) => e.event === 'token.denied' && e.target === tokenId && e.result === 'bad_secret'));
});

test('トークン: 読み出しは「トークン名」付きで監査ログに残り、最後に使った時刻が付く', async () => {
  const entry = auditEntries().find((e) => e.event === 'item.automation_read' && e.itemId === seed.db);
  assert.ok(entry);
  assert.strictEqual(entry.actorName, 'トークン「夜間バックアップ」');
  assert.strictEqual(entry.target, tokenId);
  const list = await ownerBrowser.call('/api/tokens');
  assert.ok(list.json.tokens.find((t) => t.id === tokenId).lastUsedAt);
});

test('トークン: 関係ない人には見えず、失効もできない', async () => {
  const other = browser();
  await other.login('other', 'other-password-123');
  const list = await other.call('/api/tokens');
  assert.ok(!list.json.tokens.some((t) => t.id === tokenId), 'viewer にトークンが見えている');
  assert.strictEqual((await other.call(`/api/tokens/${tokenId}`, { method: 'DELETE' })).status, 404);
  assert.strictEqual((await bearer(token, '/api/automation/vaults')).status, 200);
});

test('トークン: 発行者が owner でなくなると使えない（戻れば使える）', async () => {
  const file = path.join(DATA, 'vaults', seed.ops, 'vault.json');
  const original = fs.readFileSync(file, 'utf8');
  const vault = JSON.parse(original);
  vault.members = vault.members.map((m) => (m.userId === seed.ownerId ? { ...m, role: 'editor' } : m));
  fs.writeFileSync(file, JSON.stringify(vault));
  try {
    assert.strictEqual((await bearer(token, '/api/automation/vaults')).status, 401);
    assert.ok(auditEntries().some((e) => e.event === 'token.denied' && e.result === 'issuer_not_owner'));
  } finally {
    fs.writeFileSync(file, original);
  }
  assert.strictEqual((await bearer(token, '/api/automation/vaults')).status, 200);
});

test('トークン: 期限を過ぎると使えない', async () => {
  const r = await ownerBrowser.call('/api/tokens', { method: 'POST', body: { name: '短命', vaultIds: [seed.ops], expiresInDays: 1 } });
  const file = path.join(DATA, 'tokens', `${r.json.info.id}.json`);
  const t = JSON.parse(fs.readFileSync(file, 'utf8'));
  t.expiresAt = new Date(Date.now() - 1000).toISOString();
  fs.writeFileSync(file, JSON.stringify(t));
  assert.strictEqual((await bearer(r.json.token, '/api/automation/vaults')).status, 401);
});

test('トークン: 失効させると使えない', async () => {
  const r = await ownerBrowser.call(`/api/tokens/${tokenId}`, { method: 'DELETE' });
  assert.strictEqual(r.status, 200, r.text);
  assert.strictEqual(r.json.info.status, 'revoked');
  assert.strictEqual((await bearer(token, '/api/automation/vaults')).status, 401);
  assert.strictEqual(cli(['read', '運用/本番 DB'], { token }).code, 3);
});

test('トークン: 発行者が無効化されると使えない', async () => {
  const r = await ownerBrowser.call('/api/tokens', { method: 'POST', body: { name: '無効化の確認', vaultIds: [seed.ops], expiresInDays: 7 } });
  assert.strictEqual((await bearer(r.json.token, '/api/automation/vaults')).status, 200);
  const file = path.join(DATA, 'users', `${seed.ownerId}.json`);
  const original = fs.readFileSync(file, 'utf8');
  fs.writeFileSync(file, JSON.stringify({ ...JSON.parse(original), status: 'disabled' }));
  try {
    assert.strictEqual((await bearer(r.json.token, '/api/automation/vaults')).status, 401);
  } finally {
    fs.writeFileSync(file, original);
  }
});

// --- レビューで足したもの ---------------------------------------------------------

function rawRequest(method, rawPath, headers = {}) {
  return new Promise((resolve) => {
    const u = new URL(BASE);
    const req = require('http').request({ method, hostname: u.hostname, port: u.port, path: rawPath, headers }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.end();
  });
}

let liveToken;

test('トークン: パスの書き方を変えても /api/automation/ の外には届かない', async () => {
  const r = await ownerBrowser.call('/api/tokens', { method: 'POST', body: { name: 'パスの確認', vaultIds: [seed.ops], expiresInDays: 7 } });
  liveToken = r.json.token;
  const auth = { Authorization: `Bearer ${liveToken}` };
  for (const p of ['/api/automation/../vaults', '/api/automation/%2e%2e/vaults', '/api/automation/..%2fvaults', '/api/automation\\..\\vaults', '//api/vaults', '/api/automation/../../api/tokens']) {
    const status = await rawRequest('GET', p, auth);
    assert.ok([401, 404].includes(status), `${p} が ${status}`);
    assert.notStrictEqual(status, 200);
  }
});

test('Cookie と正しい CSRF トークンがあっても、読み出し API の POST は使えない', async () => {
  const r = await ownerBrowser.call(`/api/automation/vaults/${seed.ops}/items/${seed.db}/read`, { method: 'POST', body: { field: 'password' } });
  assert.strictEqual(r.status, 401);
});

test('トークン: 秘密違いで叩き続けても、拒否の記録は1分に1行に間引かれる', async () => {
  const tampered = `${liveToken.slice(0, -1)}${liveToken.endsWith('A') ? 'B' : 'A'}`;
  const id = liveToken.split('_')[1];
  const before = auditEntries().filter((e) => e.event === 'token.denied' && e.target === id).length;
  for (let i = 0; i < 30; i += 1) await bearer(tampered, '/api/automation/vaults');
  const after = auditEntries().filter((e) => e.event === 'token.denied' && e.target === id).length;
  assert.ok(after - before <= 1, `${after - before} 行書かれた`);
});

test('トークン: vault.json でグループに owner と書かれていても、グループ経由では発行者の owner と認めない', async () => {
  // owner を個人では editor に下げ、owner と書いたグループに入れておく
  const file = path.join(DATA, 'vaults', seed.ops, 'vault.json');
  const original = fs.readFileSync(file, 'utf8');
  const groupId = '0123456789abcdef0123456789abcdef';
  fs.mkdirSync(path.join(DATA, 'groups'), { recursive: true });
  fs.writeFileSync(path.join(DATA, 'groups', `${groupId}.json`), JSON.stringify({ id: groupId, name: '偽 owner', members: [seed.ownerId] }));
  const vault = JSON.parse(original);
  vault.members = vault.members.map((m) => (m.userId === seed.ownerId ? { ...m, role: 'editor' } : m));
  vault.groups = [{ groupId, role: 'owner' }];
  fs.writeFileSync(file, JSON.stringify(vault));
  try {
    assert.strictEqual((await bearer(liveToken, '/api/automation/vaults')).status, 401);
  } finally {
    fs.writeFileSync(file, original);
    fs.unlinkSync(path.join(DATA, 'groups', `${groupId}.json`));
  }
  assert.strictEqual((await bearer(liveToken, '/api/automation/vaults')).status, 200);
});

test('トークン: 複数 Vault のトークンは、片方の owner には入っていない Vault の名前と接続元を伏せる。管理者には全部見えて失効できる', async () => {
  // other が owner の「よそ」と、owner が owner の「運用」の両方を対象にしたいが、発行者は全部の owner が要る。
  // other を「運用」の個人 owner に上げて、other が両方を対象に発行する
  const file = path.join(DATA, 'vaults', seed.ops, 'vault.json');
  const original = fs.readFileSync(file, 'utf8');
  const vault = JSON.parse(original);
  vault.members = vault.members.map((m) => (m.userId === seed.otherId ? { ...m, role: 'owner' } : m));
  fs.writeFileSync(file, JSON.stringify(vault));
  try {
    const other = browser();
    await other.login('other', 'other-password-123');
    const made = await other.call('/api/tokens', { method: 'POST', body: { name: '二つの金庫', vaultIds: [seed.ops, seed.theirs], expiresInDays: 7 } });
    assert.strictEqual(made.status, 200, made.text);
    await bearer(made.json.token, '/api/automation/vaults');

    // owner は「よそ」の viewer なので名前は見える。見えないケースを作るため、「よそ」から外す
    const theirsFile = path.join(DATA, 'vaults', seed.theirs, 'vault.json');
    const theirsOriginal = fs.readFileSync(theirsFile, 'utf8');
    const theirs = JSON.parse(theirsOriginal);
    theirs.members = theirs.members.filter((m) => m.userId !== seed.ownerId);
    fs.writeFileSync(theirsFile, JSON.stringify(theirs));
    try {
      // owner は admin でもあるので、admin ではない見え方は lib で確かめる代わりに、admin 権限を一時的に外す
      const userFile = path.join(DATA, 'users', `${seed.ownerId}.json`);
      const userOriginal = fs.readFileSync(userFile, 'utf8');
      fs.writeFileSync(userFile, JSON.stringify({ ...JSON.parse(userOriginal), role: 'member' }));
      try {
        const seen = (await ownerBrowser.call('/api/tokens')).json.tokens.find((t) => t.id === made.json.info.id);
        assert.ok(seen, '自分が owner の Vault を対象にしたトークンが見えない');
        assert.deepStrictEqual(seen.vaults.map((v) => v.name).sort(), ['運用', '（ほかの Vault）'].sort());
        assert.strictEqual(seen.lastUsedIp, null);
      } finally {
        fs.writeFileSync(userFile, userOriginal);
      }
      const asAdmin = (await ownerBrowser.call('/api/tokens')).json.tokens.find((t) => t.id === made.json.info.id);
      assert.deepStrictEqual(asAdmin.vaults.map((v) => v.name).sort(), ['よそ', '運用'].sort());
      assert.ok(asAdmin.lastUsedIp);
      const revoked = await ownerBrowser.call(`/api/tokens/${made.json.info.id}`, { method: 'DELETE' });
      assert.strictEqual(revoked.status, 200);
    } finally {
      fs.writeFileSync(theirsFile, theirsOriginal);
    }
  } finally {
    fs.writeFileSync(file, original);
  }
});

test('トークン: 緊急アクセスで owner になった Vault を対象には発行できない', async () => {
  const other = browser();
  await other.login('other', 'other-password-123');
  // owner（admin）が other の「よそ」に緊急アクセスする
  const bg = await ownerBrowser.call(`/api/vaults/${seed.theirs}/break-glass`, { method: 'POST', body: { reason: 'トークンの確認のため' } });
  assert.strictEqual(bg.status, 200, bg.text);
  const r = await ownerBrowser.call('/api/tokens', { method: 'POST', body: { name: '緊急', vaultIds: [seed.theirs], expiresInDays: 7 } });
  assert.strictEqual(r.status, 400);
  assert.match(r.json.error, /緊急アクセス/);
});

test('CLI: 手元以外への http:// は --allow-http なしでは接続しない', () => {
  const r = cli(['vaults', '--url', 'http://passport.example.invalid'], { token: 'pp_000000000000000000000000_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
  assert.strictEqual(r.code, 2);
  assert.match(r.err, /平文/);
});
