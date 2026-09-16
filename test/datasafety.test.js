'use strict';
// データを失わないための振る舞いのテスト（パスワード履歴・ゴミ箱・楽観ロック・壊れたデータ・監査ログ）。

const os = require('os');
const path = require('path');
const fs = require('fs');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-datasafety-test-'));
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

store.init();
keyring.unlock({ allowGenerate: true });

test.after(() => {
  const auditDir = path.join(TMP, 'data', 'audit');
  if (fs.existsSync(auditDir)) fs.chmodSync(auditDir, 0o700);
  fs.rmSync(TMP, { recursive: true, force: true });
});

const owner = users.create({ username: 'owner', password: 'a-long-enough-pass', role: 'admin' });
const editor = users.create({ username: 'editor', password: 'a-long-enough-pass' });
const vault = vaults.create({ name: '業務', ownerId: owner.id, actor: owner.id });
vaults.addMember(vault.id, { userId: editor.id, role: 'editor', actor: owner.id });

const itemFile = (itemId) => `vaults/${vault.id}/items/${itemId}.json`;
const current = (itemId) => store.readJson(itemFile(itemId));

// --- パスワード履歴 ---------------------------------------------------------

test('履歴: 上書きしても前の値を取り出せる', () => {
  const item = items.create(vault.id, { title: 'DB', secrets: { password: 'first' } }, { actor: owner.id });
  items.update(vault.id, item.id, { version: current(item.id).version, secrets: { password: 'second' } }, { actor: owner.id });
  items.update(vault.id, item.id, { version: current(item.id).version, secrets: { password: 'third' } }, { actor: owner.id });

  assert.strictEqual(items.revealSecret(vault.id, item.id, 'password', { actor: owner.id }), 'third');
  // 新しい順に並ぶ
  assert.strictEqual(items.revealHistory(vault.id, item.id, 'password', 0, { actor: owner.id }), 'second');
  assert.strictEqual(items.revealHistory(vault.id, item.id, 'password', 1, { actor: owner.id }), 'first');

  // 公開用の形には件数と日時だけが載り、封筒は載らない
  const pub = items.get(vault.id, item.id, owner.id);
  assert.strictEqual(pub.secretHistory.password.length, 2);
  assert.ok(!JSON.stringify(pub).includes('"ct"'), '履歴の暗号文が公開用の形に漏れている');
});

test('履歴: 削除した値も取り出せる', () => {
  const item = items.create(vault.id, { title: 'メモ', secrets: { note: 'important memo' } }, { actor: owner.id });
  items.update(vault.id, item.id, { version: current(item.id).version, secrets: { note: null } }, { actor: owner.id });
  assert.strictEqual(items.get(vault.id, item.id, owner.id).secrets.note, undefined);
  assert.strictEqual(items.revealHistory(vault.id, item.id, 'note', 0, { actor: owner.id }), 'important memo');
});

test('履歴: 上限を越えた古いものから捨てる', () => {
  const item = items.create(vault.id, { title: '上限', secrets: { password: 'v0' } }, { actor: owner.id });
  for (let i = 1; i <= items.HISTORY_LIMIT + 3; i += 1) {
    items.update(vault.id, item.id, { version: current(item.id).version, secrets: { password: `v${i}` } }, { actor: owner.id });
  }
  const history = current(item.id).secretHistory.password;
  assert.strictEqual(history.length, items.HISTORY_LIMIT);
  assert.strictEqual(items.revealHistory(vault.id, item.id, 'password', 0, { actor: owner.id }), `v${items.HISTORY_LIMIT + 2}`);
});

// --- 世代の巻き戻し（Fable が再現した筋書き） ---------------------------------

test('世代: 削除して入れ直しても世代は 1 に戻らない', () => {
  const item = items.create(vault.id, { title: '世代', secrets: { password: 'ORIGINAL' } }, { actor: owner.id });
  const firstEnvelope = JSON.parse(JSON.stringify(current(item.id).secrets.password));
  assert.strictEqual(firstEnvelope.v, 1);

  items.update(vault.id, item.id, { version: current(item.id).version, secrets: { password: null } }, { actor: owner.id });
  items.update(vault.id, item.id, { version: current(item.id).version, secrets: { password: 'NEW' } }, { actor: owner.id });
  assert.ok(current(item.id).secrets.password.v > 1, '削除して入れ直したら世代が 1 に戻った');
});

test('世代: 初代の暗号文を貼り戻すと、巻き戻しとして拒否する', () => {
  const item = items.create(vault.id, { title: '貼り戻し', secrets: { password: 'ORIGINAL-PASSWORD' } }, { actor: owner.id });
  const firstEnvelope = JSON.parse(JSON.stringify(current(item.id).secrets.password));
  items.update(vault.id, item.id, { version: current(item.id).version, secrets: { password: null } }, { actor: owner.id });
  items.update(vault.id, item.id, { version: current(item.id).version, secrets: { password: 'NEW-PASSWORD' } }, { actor: owner.id });

  // data/ を書き換えられる人が、初代の封筒を貼り戻す（カウンタは触らない）
  store.writeJson(itemFile(item.id), { ...current(item.id), secrets: { password: firstEnvelope } });

  assert.throws(
    () => items.revealSecret(vault.id, item.id, 'password', { actor: owner.id }),
    /巻き戻されています/
  );
});

// --- ゴミ箱 -----------------------------------------------------------------

test('ゴミ箱: 削除しても消えず、戻せる', () => {
  const item = items.create(vault.id, { title: '消す予定', secrets: { password: 'keep-me' } }, { actor: editor.id });
  items.remove(vault.id, item.id, { actor: editor.id });

  assert.ok(!items.list(vault.id, editor.id).some((i) => i.id === item.id), '一覧に残っている');
  const trashed = items.listTrash(vault.id, editor.id);
  assert.ok(trashed.some((i) => i.id === item.id && i.deletedBy === editor.id));

  items.restore(vault.id, item.id, { actor: editor.id });
  assert.ok(items.list(vault.id, editor.id).some((i) => i.id === item.id));
  assert.strictEqual(items.revealSecret(vault.id, item.id, 'password', { actor: editor.id }), 'keep-me');
});

test('ゴミ箱: 完全に消せるのは owner だけ', () => {
  const item = items.create(vault.id, { title: '完全削除', secrets: { password: 'x'.repeat(8) } }, { actor: editor.id });
  items.remove(vault.id, item.id, { actor: editor.id });
  assert.throws(() => items.purge(vault.id, item.id, { actor: editor.id }), (e) => e.code === 'FORBIDDEN');
  items.purge(vault.id, item.id, { actor: owner.id });
  assert.ok(!items.listTrash(vault.id, owner.id).some((i) => i.id === item.id));
});

test('ゴミ箱: 中身が残っている Vault は消せない（鍵ごと消えて戻せなくなるため）', () => {
  const other = vaults.create({ name: '消す Vault', ownerId: owner.id, actor: owner.id });
  const item = items.create(other.id, { title: 'ゴミ箱に残る' }, { actor: owner.id });
  items.remove(other.id, item.id, { actor: owner.id });
  assert.throws(() => vaults.remove(other.id, { actor: owner.id }), /ゴミ箱に 1 件残っています/);
  items.purge(other.id, item.id, { actor: owner.id });
  vaults.remove(other.id, { actor: owner.id });
});

// --- 楽観ロック -------------------------------------------------------------

test('楽観ロック: version を省いた更新は受け付けない', () => {
  const item = items.create(vault.id, { title: 'ロック', secrets: { password: 'a' } }, { actor: owner.id });
  assert.throws(
    () => items.update(vault.id, item.id, { secrets: { password: 'b' } }, { actor: owner.id }),
    /version が必要です/
  );
  assert.throws(
    () => items.update(vault.id, item.id, { version: null, secrets: { password: 'b' } }, { actor: owner.id }),
    /version が必要です/
  );
  assert.strictEqual(items.revealSecret(vault.id, item.id, 'password', { actor: owner.id }), 'a');
});

// --- 壊れたデータ -----------------------------------------------------------

test('壊れたデータ: vault.json が1つ壊れても、ほかの Vault は使える', () => {
  const broken = vaults.create({ name: '壊れる Vault', ownerId: owner.id, actor: owner.id });
  fs.writeFileSync(store.resolveInData(`vaults/${broken.id}/vault.json`), '{ this is not json');
  try {
    const listed = vaults.listForUser(owner.id);
    assert.ok(listed.some((v) => v.id === vault.id), '無関係な Vault まで見えなくなった');
    assert.ok(!listed.some((v) => v.id === broken.id));
    // 検索と拡張の候補も止まらない
    assert.doesNotThrow(() => items.search(owner.id, 'DB'));
    assert.doesNotThrow(() => items.matchHost(owner.id, 'example.local'));
  } finally {
    fs.rmSync(store.resolveInData(`vaults/${broken.id}`), { recursive: true, force: true });
  }
});

// --- 監査ログが書けないとき -------------------------------------------------

test('監査ログ: 書けないときは、秘密を返さない', () => {
  const item = items.create(vault.id, { title: '監査', secrets: { password: 'must-be-logged' } }, { actor: owner.id });
  const auditDir = store.resolveInData('audit');
  // 月のファイルを先に作ってから、ディレクトリとファイルを書けなくする
  const files = fs.readdirSync(auditDir);
  for (const f of files) fs.chmodSync(path.join(auditDir, f), 0o400);
  fs.chmodSync(auditDir, 0o500);
  try {
    assert.throws(
      () => items.revealSecret(vault.id, item.id, 'password', { actor: owner.id }),
      /監査ログを書けないため/
    );
  } finally {
    fs.chmodSync(auditDir, 0o700);
    for (const f of files) fs.chmodSync(path.join(auditDir, f), 0o600);
  }
  // 戻せばまた取り出せる
  assert.strictEqual(items.revealSecret(vault.id, item.id, 'password', { actor: owner.id }), 'must-be-logged');
});
