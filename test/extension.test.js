'use strict';
// Chrome 拡張まわり（ホスト照合と、受け入れる Origin の判定）のテスト。
//
// オートフィルの誤爆は「別のサイトへパスワードを差し出す」ことなので、
// 照合が緩くなっていないかをここで押さえる。

const os = require('os');
const path = require('path');
const fs = require('fs');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-ext-test-'));
process.env.PASSPORT_DATA_DIR = path.join(TMP, 'data');
process.env.PASSPORT_MASTER_KEY_FILE = path.join(TMP, 'keys', 'master.key');
process.env.PASSPORT_EXTENSION_IDS = 'abcdefghijklmnopabcdefghijklmnop';
delete process.env.PASSPORT_MASTER_PASSPHRASE;

const test = require('node:test');
const assert = require('node:assert');

const store = require('../lib/store');
const keyring = require('../lib/keyring');
const users = require('../lib/users');
const vaults = require('../lib/vaults');
const items = require('../lib/items');
const http = require('../lib/http');

store.init();
keyring.unlock({ allowGenerate: true });

test.after(() => {
  fs.rmSync(TMP, { recursive: true, force: true });
});

// --- ホストの照合 -----------------------------------------------------------

test('照合: 同じホストなら一致する', () => {
  assert.ok(items.hostMatches('git.example.local', 'git.example.local'));
  assert.strictEqual(items.hostMatches('git.example.local', 'git.example.local').kind, 'exact');
});

test('照合: 親ドメインの登録なら、その下のサブドメインで使える', () => {
  const result = items.hostMatches('example.local', 'git.example.local');
  assert.ok(result);
  assert.strictEqual(result.kind, 'subdomain');
});

test('照合: サブドメインの登録で親ドメインには使えない', () => {
  assert.strictEqual(items.hostMatches('git.example.local', 'example.local'), false);
});

test('照合: 別のドメインに吸い寄せられない', () => {
  // 後ろにくっつけただけの紛らわしいドメイン
  assert.strictEqual(items.hostMatches('example.local', 'example.local.attacker.test'), false);
  // 前にくっつけただけ
  assert.strictEqual(items.hostMatches('example.local', 'notexample.local'), false);
  // 部分一致
  assert.strictEqual(items.hostMatches('example.local', 'example.localhost'), false);
  assert.strictEqual(items.hostMatches('ample.local', 'example.local'), false);
  // 空
  assert.strictEqual(items.hostMatches('', 'example.local'), false);
  assert.strictEqual(items.hostMatches('example.local', ''), false);
});

test('照合: URL からホストを取り出せる', () => {
  assert.strictEqual(items.hostOf('https://git.example.local/path?a=1'), 'git.example.local');
  assert.strictEqual(items.hostOf('git.example.local:8443'), 'git.example.local');
  assert.strictEqual(items.hostOf('GIT.Example.Local'), 'git.example.local');
  assert.strictEqual(items.hostOf(''), '');
  assert.strictEqual(items.hostOf('http://'), '');
});

// --- 拡張へ返す一覧 ---------------------------------------------------------

test('一覧: このサイトで使えるものだけ、確からしい順に返る', () => {
  const owner = users.create({ username: 'extowner', password: 'a-long-enough-pass', role: 'admin' });
  const vault = vaults.create({ name: '拡張テスト', ownerId: owner.id, actor: owner.id });
  const make = (input) => items.create(vault.id, input, { actor: owner.id });

  const exact = make({
    type: 'login', title: 'Redmine', username: 'admin',
    urls: 'https://redmine.example.local', secrets: { password: 'p1' }
  });
  const sub = make({
    type: 'login', title: '親ドメイン登録', username: 'shared',
    urls: 'https://example.local', secrets: { password: 'p2' }
  });
  make({
    type: 'login', title: 'よその会社', username: 'other',
    urls: 'https://redmine.other.test', secrets: { password: 'p3' }
  });
  make({ type: 'note', title: 'ただのメモ', urls: 'https://redmine.example.local', secrets: { note: 'x' } });
  make({ type: 'login', title: 'パスワード無し', urls: 'https://redmine.example.local' });
  const sshItem = make({
    type: 'sshkey', title: 'SSH 鍵', urls: 'https://redmine.example.local',
    publicKey: require('../lib/sshkeys').generate({ type: 'ed25519' }).publicKey
  });

  const matched = items.matchHost(owner.id, 'redmine.example.local');
  const titles = matched.map((m) => m.title);

  assert.deepStrictEqual(titles, ['Redmine', '親ドメイン登録'], `返ってきたのは ${titles.join(',')}`);
  assert.strictEqual(matched[0].id, exact.id);
  assert.strictEqual(matched[0].matchKind, 'exact');
  assert.strictEqual(matched[1].id, sub.id);
  assert.strictEqual(matched[1].matchKind, 'subdomain');
  // SSH 鍵やメモ、パスワードの無いものはブラウザに入れようがないので返さない
  assert.ok(!matched.some((m) => m.id === sshItem.id));
});

test('一覧: 秘密の中身は含まれない', () => {
  const owner = users.findByUsername('extowner');
  const matched = items.matchHost(owner.id, 'redmine.example.local');
  const text = JSON.stringify(matched);
  assert.ok(!text.includes('p1'));
  assert.ok(!text.includes('p2'));
  assert.strictEqual(matched[0].secrets.password.present, true);
  assert.strictEqual(matched[0].secrets.password.value, undefined);
});

test('一覧: 入っていない Vault のものは返らない', () => {
  const stranger = users.create({ username: 'extstranger', password: 'a-long-enough-pass' });
  assert.deepStrictEqual(items.matchHost(stranger.id, 'redmine.example.local'), []);
});

// --- 受け入れる Origin ------------------------------------------------------

const ALLOWED = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop';

test('Origin: 許可した拡張ID だけ通す', () => {
  assert.strictEqual(http.allowedExtensionOrigin(ALLOWED), true);
  // ID が1文字違う
  assert.strictEqual(
    http.allowedExtensionOrigin('chrome-extension://abcdefghijklmnopabcdefghijklmnoq'), false
  );
  // 拡張ではない Origin
  assert.strictEqual(http.allowedExtensionOrigin('https://example.local'), false);
  assert.strictEqual(http.allowedExtensionOrigin('null'), false);
  assert.strictEqual(http.allowedExtensionOrigin(''), false);
  assert.strictEqual(http.allowedExtensionOrigin(undefined), false);
  // 拡張IDの形をしていない
  assert.strictEqual(http.allowedExtensionOrigin('chrome-extension://../../etc'), false);
  assert.strictEqual(http.allowedExtensionOrigin('chrome-extension://ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP'), false);
});

test('Origin: 許可した拡張には CORS ヘッダーが付き、Cookie は許さない', () => {
  const headers = http.corsHeaders({ headers: { origin: ALLOWED } });
  assert.strictEqual(headers['Access-Control-Allow-Origin'], ALLOWED);
  assert.strictEqual(headers.Vary, 'Origin');
  // Cookie を伴う越境リクエストは許さない（拡張は Bearer で認証する）
  assert.strictEqual(headers['Access-Control-Allow-Credentials'], undefined);
});

test('Origin: 許可していない相手には CORS ヘッダーを出さない', () => {
  assert.deepStrictEqual(http.corsHeaders({ headers: { origin: 'https://evil.test' } }), {});
  assert.deepStrictEqual(http.corsHeaders({ headers: {} }), {});
});
