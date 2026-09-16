'use strict';
// オートフィルの宛先（urls）の完全性。
// data/ を書き換えて urls を攻撃者のホストに変えても、本物のパスワードが候補に出ないこと。

const os = require('os');
const path = require('path');
const fs = require('fs');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-urls-test-'));
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
const integrity = require('../lib/integrity');

store.init();
keyring.unlock({ allowGenerate: true });

test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

const owner = users.create({ username: 'owner', password: 'a-long-enough-pass', role: 'admin' });
const vault = vaults.create({ name: '宛先', ownerId: owner.id, actor: owner.id });
integrity.checkOnStartup();

const file = (itemId) => `vaults/${vault.id}/items/${itemId}.json`;
const titles = (host) => items.matchHost(owner.id, host, { scheme: 'https' }).map((i) => i.title);

test('宛先: 正規に登録したものは候補に出る', () => {
  items.create(vault.id, {
    type: 'login', title: '本物の銀行', urls: 'https://bank.example.local', secrets: { password: 'real-bank-password' }
  }, { actor: owner.id });
  assert.ok(titles('bank.example.local').includes('本物の銀行'));
});

test('宛先: urls を攻撃者のホストへ書き換えると、どちらのホストでも候補に出ない', () => {
  const item = items.list(vault.id, owner.id).find((i) => i.title === '本物の銀行');
  const saved = store.readJson(file(item.id));
  store.writeJson(file(item.id), { ...saved, urls: ['https://attacker.test'] });
  try {
    assert.ok(!titles('attacker.test').includes('本物の銀行'), '書き換えた先のホストに本物のパスワードが出ている');
    assert.ok(!titles('bank.example.local').includes('本物の銀行'));
  } finally {
    store.writeJson(file(item.id), saved);
  }
  assert.ok(titles('bank.example.local').includes('本物の銀行'), '戻したら出る');
});

test('宛先: 別のアイテムの印を貼り付けても通らない', () => {
  const attackerItem = items.create(vault.id, {
    type: 'login', title: '攻撃者が登録', urls: 'https://attacker.test', secrets: { password: 'attacker-pass' }
  }, { actor: owner.id });
  const bank = items.list(vault.id, owner.id).find((i) => i.title === '本物の銀行');
  const bankSaved = store.readJson(file(bank.id));
  const attackerSaved = store.readJson(file(attackerItem.id));

  // 本物の銀行の urls を攻撃者のホストにし、攻撃者のアイテムの（正しい）印を貼る
  store.writeJson(file(bank.id), { ...bankSaved, urls: attackerSaved.urls, urlsMac: attackerSaved.urlsMac });
  try {
    assert.ok(!titles('attacker.test').includes('本物の銀行'));
  } finally {
    store.writeJson(file(bank.id), bankSaved);
  }
});

test('宛先: 印を消しても通らない（移行が済んだあとは、無い＝改ざん）', () => {
  const bank = items.list(vault.id, owner.id).find((i) => i.title === '本物の銀行');
  const saved = store.readJson(file(bank.id));
  const { urlsMac, ...withoutMac } = saved;
  store.writeJson(file(bank.id), { ...withoutMac, urls: ['https://attacker.test'] });
  try {
    assert.ok(!titles('attacker.test').includes('本物の銀行'));
    // 起動し直しても、印を付け直して正規扱いにはしない
    integrity.checkOnStartup();
    assert.strictEqual(store.readJson(file(bank.id)).urlsMac, undefined, '再起動で改ざんが正規化された');
    assert.ok(!titles('attacker.test').includes('本物の銀行'));
  } finally {
    store.writeJson(file(bank.id), saved);
  }
  assert.ok(urlsMac);
});

test('宛先: 画面から urls を変えれば、新しい宛先で候補に出る', () => {
  const bank = items.list(vault.id, owner.id).find((i) => i.title === '本物の銀行');
  items.update(vault.id, bank.id, {
    version: store.readJson(file(bank.id)).version, urls: 'https://new-bank.example.local'
  }, { actor: owner.id });
  assert.ok(titles('new-bank.example.local').includes('本物の銀行'));
  assert.ok(!titles('bank.example.local').includes('本物の銀行'));
});

test('移行: 印の無い既存アイテムには、最初の一度だけ付ける', () => {
  const item = items.create(vault.id, {
    type: 'login', title: '移行前からある', urls: 'https://legacy.example.local', secrets: { password: 'legacy-pass' }
  }, { actor: owner.id });
  // この仕組みを入れる前のデータを再現する
  const { urlsMac, ...legacy } = store.readJson(file(item.id));
  store.writeJson(file(item.id), legacy);
  const record = store.readJson('keycheck.json');
  store.writeJson('keycheck.json', { ...record, urlsMacMigratedAt: null });

  assert.ok(!titles('legacy.example.local').includes('移行前からある'), '移行前は候補に出ない');
  integrity.checkOnStartup(); // 一度目: 付ける
  assert.ok(store.readJson(file(item.id)).urlsMac);
  assert.ok(titles('legacy.example.local').includes('移行前からある'));
  assert.ok(store.readJson('keycheck.json').urlsMacMigratedAt, '移行済みの記録が残る');
  assert.ok(urlsMac);
});
