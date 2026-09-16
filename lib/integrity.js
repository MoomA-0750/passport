'use strict';
// 起動時と、セットアップの判断に使う「データの状態の見極め」。
//
// ここは事故を攻撃に変えないための場所。レビューで次の2つが実際に再現した:
//
//   1. data/users/ だけが失われる／読めなくなると、セットアップ画面が復活して
//      誰でも管理者を作れ、緊急アクセスで全 Vault の秘密を読めた。
//      （部分リストア、ボリュームのマウント漏れ、設定ミス、chown ミスで起きる）
//
//   2. マスターキーを取り違えても、起動時の自己テストは通っていた。
//      その場で作った平文を同じ鍵で封じて開け直すだけだったため。
//      誤診して data/ を作り直すと、正しい鍵が見つかっても復旧できなくなる。

const fs = require('fs');
const crypto = require('crypto');
const store = require('./store');
const envelope = require('./envelope');
const keyring = require('./keyring');
const log = require('./logger')('passport:server');

const KEYCHECK_FILE = 'keycheck.json';
const KEYCHECK_PLAINTEXT = 'passport/keycheck/v1';
const KEYCHECK_AAD = Buffer.from('passport/keycheck|v1', 'utf8');

class IntegrityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'IntegrityError';
  }
}

// ディレクトリにある .json の「ファイル名の数」。中身は読まない。
// 読めないファイルも数に入れる。ここを中身の読み取りに頼ると、
// chmod 000 のファイルが「0人」に化ける（レビューで実測された）。
function countFilesOnDisk(relDir) {
  const full = store.resolveInData(relDir);
  if (!fs.existsSync(full)) return 0;
  return fs.readdirSync(full).filter((name) => name.endsWith('.json') && !name.includes('.tmp-')).length;
}

function countVaultDirsOnDisk() {
  const full = store.resolveInData('vaults');
  if (!fs.existsSync(full)) return 0;
  return fs.readdirSync(full, { withFileTypes: true }).filter((entry) => entry.isDirectory()).length;
}

// 初回セットアップを許してよい状態か。
//
// 許すのは「ユーザーのファイルも Vault も、ディスク上に1つも無い」ときだけ。
// ユーザーが読めないだけ、ユーザーだけ消えた、といった状態では絶対に開かない。
function setupAllowed() {
  return countFilesOnDisk('users') === 0 && countVaultDirsOnDisk() === 0;
}

// 起動時に呼ぶ。おかしな状態なら起動を止める。
function checkOnStartup() {
  const userFiles = countFilesOnDisk('users');
  const vaultDirs = countVaultDirsOnDisk();

  // Vault があるのにユーザーが1人もいない。データの一部が失われている。
  // ここで起動するとセットアップ画面が開いてしまうので、止める。
  if (userFiles === 0 && vaultDirs > 0) {
    throw new IntegrityError(
      `ユーザーが1人も見つからないのに、Vault が ${vaultDirs} 個あります。\n` +
      '  data/users/ が失われているか、マウント・設定の誤りで別の場所を見ている可能性があります。\n' +
      '  このまま起動すると誰でも管理者を作れてしまうので、起動を止めました。\n' +
      '  PASSPORT_DATA_DIR（または passport.ini の [storage] dataDir）と、バックアップを確認してください。'
    );
  }

  checkKeyGeneration(vaultDirs);
  migrateUrlsMacOnce();
  warnMissingGroups();
}

// Vault が共有先にしているグループが見つからない（消えた・壊れた・一部だけ戻した）。
// 安全側（その人たちは入れない）に倒れるので起動は止めないが、気づけるように大きく知らせる
function warnMissingGroups() {
  const vaults = require('./vaults');
  const groups = require('./groups');
  const known = new Set(groups.list().map((g) => g.id));
  for (const vault of vaults.list()) {
    for (const entry of (vault.groups || [])) {
      if (!known.has(entry.groupId)) {
        log.warn(`Vault「${vault.name}」が共有先にしているグループ ${entry.groupId} が見つかりません。`
          + 'グループ経由の人はこの Vault に入れません（data/groups を確認してください）');
      }
    }
  }
}

// 既存のアイテムに URL の HMAC を付ける。**一度だけ**行う。
//
// 「起動のたびに、無いものには付ける」にすると、攻撃者は HMAC を消して URL を書き換え、
// 再起動を待つだけで、書き換えた URL を正規のものとして HMAC 付きにできてしまう。
// そこで、移行が済んだことを鍵の目印に記録し、以後は「HMAC が無い＝改ざん」とみなす。
function migrateUrlsMacOnce() {
  const record = store.readJson(KEYCHECK_FILE);
  if (!record || record.urlsMacMigratedAt) return;

  const vaults = require('./vaults');
  const items = require('./items');
  let migrated = 0;
  for (const vault of vaults.list()) {
    let vaultKey;
    try {
      vaultKey = vaults.unwrapKey(vault);
    } catch {
      continue;
    }
    try {
      for (const item of store.listJson(`vaults/${vault.id}/items`)) {
        if (item.urlsMac) continue;
        // version は上げない（開いている編集画面に不要な競合を起こさないため）
        store.writeJson(`vaults/${vault.id}/items/${item.id}.json`, {
          ...item,
          urlsMac: items.computeUrlsMac(vaultKey, { vaultId: vault.id, itemId: item.id, urls: item.urls })
        });
        migrated += 1;
      }
    } finally {
      vaultKey.fill(0);
    }
  }

  store.writeJson(KEYCHECK_FILE, { ...record, urlsMacMigratedAt: new Date().toISOString() });
  if (migrated > 0) log.info(`既存のアイテム ${migrated} 件に、URL の完全性の印を付けました（一度だけの移行）`);
}

// マスターキーが、このデータを作ったときのものと同じかを確かめる。
function checkKeyGeneration(vaultDirs) {
  const kek = keyring.kek();

  if (store.exists(KEYCHECK_FILE)) {
    const record = store.readJson(KEYCHECK_FILE);
    let opened = null;
    try {
      opened = envelope.open(kek, record.envelope, KEYCHECK_AAD);
    } catch {
      opened = null;
    }
    if (opened !== KEYCHECK_PLAINTEXT) {
      throw new IntegrityError(
        'マスターキーが、このデータを作ったときのものと違います。\n' +
        '  取り違えたキーファイルを置いているか、キーを作り直した可能性があります。\n' +
        '  **data/ を消したり作り直したりしないでください。** 正しいキーが見つかれば、そのまま復旧できます。\n' +
        `  このデータの鍵の指紋: ${record.fingerprint || '(記録なし)'}\n` +
        `  いま読み込んだ鍵の指紋: ${fingerprintOf(kek)}`
      );
    }
    return;
  }

  // 目印がまだ無い。新しく始めるデータか、この仕組みを入れる前からあるデータ。
  // 前からあるデータなら、既存の Vault の鍵を実際に開けられるか確かめてから目印を作る。
  // 開けられないのに目印を作ると、違う鍵を「正しい」と記録してしまう。
  if (vaultDirs > 0) {
    const vaults = require('./vaults');
    const opened = vaults.list().some((vault) => {
      try {
        const key = vaults.unwrapKey(vault);
        key.fill(0);
        return true;
      } catch {
        return false;
      }
    });
    if (!opened) {
      throw new IntegrityError(
        '既存の Vault の鍵を、いまのマスターキーで1つも開けられません。\n' +
        '  マスターキーを取り違えている可能性があります。\n' +
        '  **data/ を消したり作り直したりしないでください。** 正しいキーで起動し直してください。'
      );
    }
  }

  store.writeJson(KEYCHECK_FILE, {
    createdAt: new Date().toISOString(),
    fingerprint: fingerprintOf(kek),
    envelope: envelope.seal(kek, KEYCHECK_PLAINTEXT, KEYCHECK_AAD),
    // 既存の Vault があるときは、このあと migrateUrlsMacOnce が付けて回る。
    // 新しいデータなら付けて回るものが無いので、最初から済んだことにする。
    urlsMacMigratedAt: vaultDirs > 0 ? null : new Date().toISOString()
  });
  log.info(`鍵の目印を作りました（指紋 ${fingerprintOf(kek)}）`);
}

// --- 初回セットアップの合言葉 ----------------------------------------------
//
// 「ユーザーが0人ならセットアップできる」だけだと、起動してから本人がブラウザを開くまでの間に、
// 社内ネットワークの誰かが先に管理者を作れてしまう。
// そこで、起動ログに1回だけ出す合言葉を要求する。サーバーのログを見られる人＝運用者だけが知っている。

let setupToken = null;

function issueSetupToken() {
  setupToken = crypto.randomBytes(9).toString('base64url'); // 12文字
  return setupToken;
}

// 合っているかだけを見る。まだ使い切らない。
// 入力ミス（パスワードが短いなど）で合言葉まで消えると、サーバーを起動し直さないと
// やり直せなくなるので、セットアップが成功してから使い切る。
function checkSetupToken(given) {
  if (!setupToken) return false;
  return envelope.safeEqual(String(given || '').trim(), setupToken);
}

function consumeSetupToken() {
  setupToken = null;
}

// 鍵そのものは出さず、取り違えに気づくための短い指紋だけを出す。
function fingerprintOf(key) {
  return crypto.createHash('sha256').update('passport/key-fingerprint|').update(key).digest('hex').slice(0, 16);
}

module.exports = {
  IntegrityError,
  setupAllowed,
  issueSetupToken,
  checkSetupToken,
  consumeSetupToken,
  checkOnStartup,
  countFilesOnDisk,
  fingerprintOf
};
