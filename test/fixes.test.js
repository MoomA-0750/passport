'use strict';
// レビューで見つかった実装の不具合を、直ったことの確認として残す。

const os = require('os');
const path = require('path');
const fs = require('fs');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-fixes-test-'));
process.env.PASSPORT_DATA_DIR = path.join(TMP, 'data');
process.env.PASSPORT_MASTER_KEY_FILE = path.join(TMP, 'keys', 'master.key');
delete process.env.PASSPORT_MASTER_PASSPHRASE;

const test = require('node:test');
const assert = require('node:assert');

const store = require('../lib/store');
const keyring = require('../lib/keyring');
const users = require('../lib/users');
const vaults = require('../lib/vaults');
const items = require('../lib/items');
const sshkeys = require('../lib/sshkeys');
const totp = require('../lib/totp');
const audit = require('../lib/audit');

store.init();
keyring.unlock({ allowGenerate: true });

test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

const owner = users.create({ username: 'owner', password: 'a-long-enough-pass', role: 'admin' });
const vault = vaults.create({ name: '修正の確認', ownerId: owner.id, actor: owner.id });
const version = (itemId) => store.readJson(`vaults/${vault.id}/items/${itemId}.json`).version;

// --- SSH 鍵の編集 -----------------------------------------------------------

test('SSH鍵: タイトルだけ変えても「秘密鍵を持っている」情報が消えない', () => {
  const key = sshkeys.generate({ type: 'ed25519', comment: 'edit@test' });
  const item = items.create(vault.id, {
    type: 'sshkey', title: '編集前', secrets: { privateKey: key.privateKey }
  }, { actor: owner.id });
  assert.strictEqual(item.sshKey.hasPrivateKey, true);
  assert.strictEqual(item.sshKey.format, 'openssh');

  // 画面は編集のたびに、今の公開鍵をそのまま送り返してくる
  const updated = items.update(vault.id, item.id, {
    version: version(item.id), title: '編集後', publicKey: item.sshKey.publicKey, comment: 'edit@test'
  }, { actor: owner.id });

  assert.strictEqual(updated.title, '編集後');
  assert.strictEqual(updated.sshKey.hasPrivateKey, true, '「公開鍵のみ」に化けた');
  assert.strictEqual(updated.sshKey.format, 'openssh');
});

test('SSH鍵: 種別を変えて戻しても、鍵の情報は残っている', () => {
  const key = sshkeys.generate({ type: 'ed25519' });
  const item = items.create(vault.id, {
    type: 'sshkey', title: '種別の往復', secrets: { privateKey: key.privateKey }
  }, { actor: owner.id });

  items.update(vault.id, item.id, { version: version(item.id), type: 'note' }, { actor: owner.id });
  const back = items.update(vault.id, item.id, { version: version(item.id), type: 'sshkey' }, { actor: owner.id });
  assert.strictEqual(back.sshKey.fingerprint, key.fingerprint);
});

// --- TOTP の検証 ------------------------------------------------------------

test('TOTP: 使えない設定は保存させない', () => {
  const base = 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP';
  for (const [raw, pattern] of [
    [`${base}&digits=abc`, /桁数/],
    [`${base}&digits=12`, /桁数/],
    [`${base}&period=0`, /周期/],
    [`${base}&algorithm=MD5`, /アルゴリズム/],
    ['これはBase32ではない', /Base32/],
    ['JBSWY3DP', /短すぎます/]
  ]) {
    assert.throws(
      () => items.create(vault.id, { title: 'TOTP', secrets: { totp: raw } }, { actor: owner.id }),
      pattern, raw
    );
  }
});

test('TOTP: 正しい設定は保存でき、SHA-256 でも動く', () => {
  const ok = items.create(vault.id, {
    title: 'TOTP OK', secrets: { totp: 'otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8' }
  }, { actor: owner.id });
  assert.ok(ok.secrets.totp.present);
  const secret = items.revealSecret(vault.id, ok.id, 'totp', { actor: owner.id });
  assert.match(totp.generate(secret).code, /^\d{8}$/);
});

test('TOTP: ラベルの % が壊れていても落ちない', () => {
  assert.doesNotThrow(() => totp.parseSecret('otpauth://totp/%E0%A4%A?secret=JBSWY3DPEHPK3PXP'));
});

// --- オートフィルのスキーム -------------------------------------------------

test('照合: https で登録したものは、http のページには出さない', () => {
  items.create(vault.id, {
    type: 'login', title: 'https 登録', urls: 'https://bank.example.local', secrets: { password: 'x'.repeat(10) }
  }, { actor: owner.id });
  items.create(vault.id, {
    type: 'login', title: 'スキームなし登録', urls: 'wiki.example.local', secrets: { password: 'y'.repeat(10) }
  }, { actor: owner.id });

  assert.ok(items.matchHost(owner.id, 'bank.example.local', { scheme: 'https' }).some((i) => i.title === 'https 登録'));
  assert.ok(!items.matchHost(owner.id, 'bank.example.local', { scheme: 'http' }).some((i) => i.title === 'https 登録'),
    'https の登録が http のページに出ている');
  // スキームを書かずに登録したものは、どちらでも出す
  assert.ok(items.matchHost(owner.id, 'wiki.example.local', { scheme: 'http' }).some((i) => i.title === 'スキームなし登録'));
});

// --- 監査ログ ---------------------------------------------------------------

test('監査ログ: 入力に使ったことを、コピーと区別して残す', () => {
  const item = items.create(vault.id, { title: '入力', secrets: { password: 'fill-me-please' } }, { actor: owner.id });
  items.revealSecret(vault.id, item.id, 'password', { actor: owner.id, purpose: 'fill' });
  const entries = audit.recent({ limit: 20 });
  assert.ok(entries.some((e) => e.event === 'item.fill_secret' && e.itemId === item.id));
});

// --- 緊急アクセス -----------------------------------------------------------

test('緊急アクセス: 既にメンバーだった管理者でも、印と元の権限が残る', () => {
  const other = users.create({ username: 'other-owner', password: 'a-long-enough-pass' });
  const admin = users.create({ username: 'second-admin', password: 'a-long-enough-pass', role: 'admin' });
  const theirs = vaults.create({ name: 'よその金庫', ownerId: other.id, actor: other.id });
  vaults.addMember(theirs.id, { userId: admin.id, role: 'viewer', actor: other.id });

  vaults.adminTakeOwnership(theirs.id, { actor: admin.id, reason: '担当者不在のため' });
  const member = vaults.get(theirs.id).members.find((m) => m.userId === admin.id);
  assert.strictEqual(member.role, 'owner');
  assert.strictEqual(member.viaBreakGlass, true, '普通の owner と見分けが付かない');
  assert.strictEqual(member.roleBeforeBreakGlass, 'viewer');
});
