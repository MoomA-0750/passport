'use strict';
// HTTP 経路のテスト。サーバーを実際に起動して、fetch で叩く。
//
// レビューで「HTTP 経路のテストが1つも無い」と指摘され、実際に
// CSRF・Bearer と Cookie の分岐・無効化されたユーザー・壊れた本文の不具合が
// すべてこの穴から出ていた。

const test = require('node:test');
const assert = require('node:assert');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');

const REPO = path.resolve(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-http-test-'));

let server;
let BASE;
let setupToken;
let serverOutput = '';

function freePort() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Cookie と CSRF トークンを持ち回る、ブラウザもどき
function client({ ip = null } = {}) {
  let cookie = '';
  let csrf = null;
  return {
    async call(pathname, { method = 'GET', body, headers = {}, raw = false } = {}) {
      const h = { Origin: BASE, ...headers };
      if (body !== undefined) h['Content-Type'] = 'application/json';
      if (csrf && method !== 'GET') h['X-CSRF-Token'] = csrf;
      if (cookie) h.Cookie = cookie;
      // 別の接続元のふりをする（サーバーは trustProxy で起動している）
      if (ip) h['X-Forwarded-For'] = ip;
      const res = await fetch(BASE + pathname, {
        method, headers: h, redirect: 'manual',
        body: body === undefined ? undefined : (raw ? body : JSON.stringify(body))
      });
      for (const c of (res.headers.getSetCookie ? res.headers.getSetCookie() : [])) {
        const v = c.split(';')[0];
        if (v.startsWith('passport_session=')) cookie = v === 'passport_session=' ? '' : v;
      }
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch { /* JSON でない */ }
      return { status: res.status, json, text, headers: res.headers };
    },
    async login(username, password) {
      const r = await this.call('/api/login', { method: 'POST', body: { username, password } });
      if (r.json && r.json.csrfToken) csrf = r.json.csrfToken;
      return r;
    }
  };
}

test.before(async () => {
  const port = await freePort();
  BASE = `http://127.0.0.1:${port}`;
  const env = {
    ...process.env,
    PASSPORT_PORT: String(port),
    PASSPORT_HOST: '127.0.0.1',
    PASSPORT_TLS: 'off',
    PASSPORT_TRUST_PROXY: 'on', // X-Forwarded-For で接続元を変えて試すため
    PASSPORT_DATA_DIR: path.join(TMP, 'data'),
    PASSPORT_MASTER_KEY_FILE: path.join(TMP, 'keys', 'master.key')
  };
  delete env.PASSPORT_MASTER_PASSPHRASE;
  execFileSync('node', ['bin/init-master-key.js'], { cwd: REPO, env, stdio: 'ignore' });

  server = spawn('node', ['server.js'], { cwd: REPO, env, stdio: ['ignore', 'pipe', 'pipe'] });
  server.stdout.on('data', (d) => { serverOutput += d; });
  server.stderr.on('data', (d) => { serverOutput += d; });

  for (let i = 0; i < 50; i += 1) {
    const match = serverOutput.match(/セットアップの合言葉: (\S+)/);
    if (match) { setupToken = match[1]; break; }
    await sleep(100);
  }
  assert.ok(setupToken, `サーバーが起動しませんでした:\n${serverOutput}`);
});

test.after(async () => {
  if (server) server.kill('SIGTERM');
  await sleep(300);
  fs.rmSync(TMP, { recursive: true, force: true });
});

// --- セットアップ ------------------------------------------------------------

test('セットアップ: 合言葉が無い・違うと作れない', async () => {
  const c = client();
  const none = await c.call('/api/setup', { method: 'POST', body: { username: 'intruder', password: 'intruder-password-1' } });
  assert.strictEqual(none.status, 403);
  const wrong = await c.call('/api/setup', {
    method: 'POST', body: { username: 'intruder', password: 'intruder-password-1', setupToken: 'wrong-token' }
  });
  assert.strictEqual(wrong.status, 403);
});

test('セットアップ: 入力ミスでは合言葉は消えず、やり直せる', async () => {
  const c = client();
  const tooShort = await c.call('/api/setup', {
    method: 'POST', body: { username: 'admin', password: 'short', setupToken }
  });
  assert.strictEqual(tooShort.status, 400);
  const ok = await c.call('/api/setup', {
    method: 'POST', body: { username: 'admin', password: 'admin-password-123', setupToken }
  });
  assert.strictEqual(ok.status, 200, JSON.stringify(ok.json));
});

test('セットアップ: 一度済んだら、合言葉を知っていても二度目はできない', async () => {
  const c = client();
  const again = await c.call('/api/setup', {
    method: 'POST', body: { username: 'second', password: 'second-password-12', setupToken }
  });
  assert.strictEqual(again.status, 409);
});

// --- ログインの締め出し ------------------------------------------------------

test('締め出し: 攻撃者の接続元から失敗を重ねても、別の場所の本人は入れる', async () => {
  const admin = client();
  await admin.login('admin', 'admin-password-123');
  await admin.call('/api/users', {
    method: 'POST', body: { username: 'victim', password: 'victim-password-12', role: 'member' }
  });

  const attacker = client({ ip: '10.0.0.66' });
  for (let i = 0; i < 8; i += 1) {
    await attacker.login('victim', 'not-the-password');
  }
  // 攻撃者の接続元からは、正しいパスワードでも止められている
  const blocked = await attacker.login('victim', 'victim-password-12');
  assert.strictEqual(blocked.status, 401);

  // 別の接続元にいる本人は、正しいパスワードで入れる
  const victim = client({ ip: '10.0.0.5' });
  const ok = await victim.login('victim', 'victim-password-12');
  assert.strictEqual(ok.status, 200, '別の場所の本人まで締め出されている');
});

test('存在の推測: 実在するユーザーと存在しないユーザーで、止められたときの応答が同じ', async () => {
  const probe = client({ ip: '10.0.0.77' });
  const responses = {};
  for (const username of ['victim', 'nobody-by-this-name']) {
    let last;
    for (let i = 0; i < 7; i += 1) last = await probe.login(username, 'wrong-password');
    responses[username] = { status: last.status, error: last.json && last.json.error };
  }
  assert.deepStrictEqual(responses.victim, responses['nobody-by-this-name'],
    `応答が違う: ${JSON.stringify(responses)}`);
  assert.notStrictEqual(responses.victim.status, 429, '429 で存在を区別していた頃に戻っている');
});

// --- 無効化されたユーザー ----------------------------------------------------

test('無効化: 無効化された人の API 呼び出しは、200 + HTML ではなく JSON の 401', async () => {
  const admin = client();
  await admin.login('admin', 'admin-password-123');
  const created = await admin.call('/api/users', {
    method: 'POST', body: { username: 'leaver', password: 'leaver-password-12', role: 'member' }
  });
  const leaver = client({ ip: '10.0.0.9' });
  const login = await leaver.login('leaver', 'leaver-password-12');
  assert.strictEqual(login.status, 200);

  await admin.call(`/api/users/${created.json.user.id}`, { method: 'PUT', body: { status: 'disabled' } });

  const after = await leaver.call('/api/vaults');
  assert.strictEqual(after.status, 401);
  assert.ok(after.json, `JSON ではない応答: ${after.text.slice(0, 60)}`);
  assert.ok(!/<!doctype html>/i.test(after.text));
});

// --- 本文とURLの異常 ---------------------------------------------------------

test('壊れた入力: 本文が null や配列なら 400 で、内部の例外文を出さない', async () => {
  const admin = client();
  await admin.login('admin', 'admin-password-123');
  for (const body of ['null', '[]', '"a string"', '42']) {
    const r = await admin.call('/api/vaults', { method: 'POST', body, raw: true });
    assert.strictEqual(r.status, 400, `本文 ${body}`);
    assert.ok(!/Cannot read properties/.test(r.text), `内部の例外文が出ている: ${r.text}`);
  }
});

test('壊れた入力: 壊れたパーセントエンコードは 500 ではなく 400', async () => {
  const admin = client();
  await admin.login('admin', 'admin-password-123');
  const api = await admin.call('/api/vaults/%zz/items');
  assert.strictEqual(api.status, 400);
  const stat = await admin.call('/static/%zz');
  assert.strictEqual(stat.status, 400);
});

// --- CSRF --------------------------------------------------------------------

test('CSRF: でたらめな Bearer を付けても、CSRF の検証は外れない', async () => {
  const admin = client();
  await admin.login('admin', 'admin-password-123');
  // Cookie は正しいが CSRF トークンは送らず、代わりにでたらめな Bearer を付ける
  const r = await fetch(`${BASE}/api/vaults`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      Origin: 'https://evil.test'
    },
    body: JSON.stringify({ name: 'CSRF で作られた金庫' })
  });
  assert.notStrictEqual(r.status, 200, 'でたらめな Bearer で CSRF の検証を外せてしまった');
});

test('CSRF: トークンの無い Cookie 認証の書き込みは弾く', async () => {
  const admin = client();
  const login = await admin.login('admin', 'admin-password-123');
  const cookie = login.headers.getSetCookie().map((c) => c.split(';')[0]).find((c) => c.startsWith('passport_session='));
  const r = await fetch(`${BASE}/api/vaults`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: BASE, Cookie: cookie },
    body: JSON.stringify({ name: 'トークン無し' })
  });
  assert.strictEqual(r.status, 403);
});

// --- グループ ---------------------------------------------------------------

test('グループ: 管理者以外はグループを作れず、一覧も見られない', async () => {
  const admin = client();
  await admin.login('admin', 'admin-password-123');
  await admin.call('/api/users', { method: 'POST', body: { username: 'plain', password: 'plain-password-12', role: 'member' } });
  const plain = client({ ip: '10.0.0.21' });
  await plain.login('plain', 'plain-password-12');
  // 初回ログインのパスワード変更を済ませる
  await plain.call('/api/me/password', { method: 'POST', body: { currentPassword: 'plain-password-12', newPassword: 'plain-password-34' } });
  await plain.login('plain', 'plain-password-34');

  assert.strictEqual((await plain.call('/api/groups')).status, 403);
  assert.strictEqual((await plain.call('/api/groups', { method: 'POST', body: { name: '勝手に' } })).status, 403);

  const made = await admin.call('/api/groups', { method: 'POST', body: { name: '運用' } });
  assert.strictEqual(made.status, 200, made.text);
  const groupId = made.json.group.id;
  assert.strictEqual((await plain.call(`/api/groups/${groupId}/members`, { method: 'POST', body: { userId: 'x' } })).status, 403);
  assert.strictEqual((await plain.call(`/api/groups/${groupId}`, { method: 'DELETE' })).status, 403);
});

test('グループ: Vault の共有画面では、グループの中の人は見えない（名前と人数だけ）', async () => {
  const admin = client();
  await admin.login('admin', 'admin-password-123');
  const vault = await admin.call('/api/vaults', { method: 'POST', body: { name: 'グループ共有' } });
  const vaultId = vault.json.vault.id;
  const { json } = await admin.call(`/api/vaults/${vaultId}/members`);
  assert.ok(Array.isArray(json.groupCandidates));
  for (const g of json.groupCandidates) assert.deepStrictEqual(Object.keys(g).sort(), ['id', 'memberCount', 'name']);
});

test('グループ: Vault の共有先の変更は owner だけ。owner は付けられず、owner にだけ中の人が見える', async () => {
  const admin = client();
  await admin.login('admin', 'admin-password-123');
  const made = await admin.call('/api/users', { method: 'POST', body: { username: 'gviewer', password: 'gviewer-password-12', role: 'member' } });
  const viewerId = made.json.user.id;
  const viewer = client({ ip: '10.0.0.22' });
  await viewer.login('gviewer', 'gviewer-password-12');
  await viewer.call('/api/me/password', { method: 'POST', body: { currentPassword: 'gviewer-password-12', newPassword: 'gviewer-password-34' } });
  await viewer.login('gviewer', 'gviewer-password-34');

  // 管理者は自分をグループに入れられないので、別の利用者（gviewer）を入れる
  const group = (await admin.call('/api/groups', { method: 'POST', body: { name: '閲覧係' } })).json.group;
  assert.strictEqual((await admin.call(`/api/groups/${group.id}/members`, { method: 'POST', body: { userId: viewerId } })).status, 200);
  const vaultId = (await admin.call('/api/vaults', { method: 'POST', body: { name: '閲覧係の金庫' } })).json.vault.id;

  const asOwner = await admin.call(`/api/vaults/${vaultId}/groups`, { method: 'POST', body: { groupId: group.id, role: 'owner' } });
  assert.strictEqual(asOwner.status, 400);
  assert.match(asOwner.json.error, /owner を付けられません/);
  assert.strictEqual((await admin.call(`/api/vaults/${vaultId}/groups`, { method: 'POST', body: { groupId: 'no-such-group', role: 'viewer' } })).status, 400);
  assert.strictEqual((await admin.call(`/api/vaults/${vaultId}/groups`, { method: 'POST', body: { groupId: group.id, role: 'viewer' } })).status, 200);

  // グループ経由の viewer は、共有先を変えられない
  assert.strictEqual((await viewer.call(`/api/vaults/${vaultId}/groups/${group.id}`, { method: 'PUT', body: { role: 'editor' } })).status, 403);
  assert.strictEqual((await viewer.call(`/api/vaults/${vaultId}/groups/${group.id}`, { method: 'DELETE' })).status, 403);

  // owner には中の人が見え、viewer には人数だけ
  const ownerView = (await admin.call(`/api/vaults/${vaultId}/members`)).json;
  assert.deepStrictEqual(ownerView.groups[0].members.map((m) => m.username), ['gviewer']);
  const viewerView = (await viewer.call(`/api/vaults/${vaultId}/members`)).json;
  assert.strictEqual(viewerView.groups[0].memberCount, 1);
  assert.ok(!('members' in viewerView.groups[0]));
  assert.deepStrictEqual(viewerView.groupCandidates, []);
});
