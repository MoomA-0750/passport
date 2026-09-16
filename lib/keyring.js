'use strict';
// マスターキーを抱える唯一の場所。ここ以外がマスターキーを触らない。
//
// 入手経路は2つ（docs/crypto.md）:
//   1. キーファイル（既定）: /etc/passport/master.key を 0400 で置く。systemd で自動起動できる
//   2. パスフレーズ: 環境変数 PASSPORT_MASTER_PASSPHRASE。起動ごとに人手でアンロックする運用
//
// KEK と AUTH_PEPPER はマスターキーから HKDF で分ける。用途の違う鍵を同じ値にしない。

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');
const envelope = require('./envelope');
const log = require('./logger')('passport:crypto');

// パスフレーズ運用のときの固定ソルト。
// パスフレーズはユーザーごとではなくサーバーに1つなので、ソルトを設定に持たせる意味がなく、
// 用途ラベルとして固定する。強度はパスフレーズの長さで確保する。
const PASSPHRASE_SALT = Buffer.from('passport/master-passphrase/v1', 'utf8');
const PASSPHRASE_SCRYPT = { N: 1048576, r: 8, p: 1, maxmem: 2048 * 1024 * 1024 };

let state = null; // { kek, pepper, source }

function generateMasterKeyFile(filePath) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const key = crypto.randomBytes(32);
  const fd = fs.openSync(filePath, 'wx', 0o400); // 既存なら失敗させる。上書きで鍵を失わない
  try {
    fs.writeFileSync(fd, key.toString('base64') + '\n', 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  return key;
}

function readMasterKeyFile(filePath) {
  const stat = fs.statSync(filePath);
  // 他人に読める鍵ファイルは、鍵が無いのと大差ないので止める
  const mode = stat.mode & 0o777;
  if (mode & 0o077) {
    throw new Error(
      `マスターキーのファイルモードが緩すぎます: ${filePath} は ${mode.toString(8)} です。` +
      'chmod 400 で直してください'
    );
  }
  const raw = fs.readFileSync(filePath, 'utf8').trim();
  const key = Buffer.from(raw, 'base64');
  if (key.length !== 32) {
    throw new Error(`マスターキーは base64 の32バイトでなければなりません: ${filePath}`);
  }
  return key;
}

function deriveFromPassphrase(passphrase) {
  if (String(passphrase).length < 16) {
    throw new Error('PASSPORT_MASTER_PASSPHRASE は16文字以上にしてください');
  }
  const done = log.timer('パスフレーズから鍵を導出');
  const key = crypto.scryptSync(
    Buffer.from(String(passphrase), 'utf8'),
    PASSPHRASE_SALT,
    32,
    PASSPHRASE_SCRYPT
  );
  done();
  return key;
}

// 起動時に1回だけ呼ぶ。マスターキーを解決して KEK と pepper を作り、マスターキーは捨てる。
function unlock({ allowGenerate = false } = {}) {
  if (state) return state;

  let master;
  let source;

  if (config.crypto.masterPassphrase) {
    master = deriveFromPassphrase(config.crypto.masterPassphrase);
    source = 'passphrase';
    // パスフレーズはソルトが固定なので、マスターキーそのものと等価。
    // 導出が済んだら、環境変数と設定から消しておく（/proc/<pid>/environ に残さない）。
    delete process.env.PASSPORT_MASTER_PASSPHRASE;
    config.crypto.masterPassphrase = null;
  } else {
    const file = config.crypto.masterKeyFile;
    if (!fs.existsSync(file)) {
      if (!allowGenerate) {
        throw new Error(
          `マスターキーがありません: ${file}\n` +
          '  初回は `node bin/init-master-key.js` で作ってください。\n' +
          '  このファイルを失うと保存済みのパスワードは復号できません。'
        );
      }
      master = generateMasterKeyFile(file);
      log.warn(`マスターキーを新規作成しました: ${file}`);
      log.warn('このファイルのバックアップを、Passport のデータとは別の場所に取ってください');
      source = 'file(new)';
    } else {
      master = readMasterKeyFile(file);
      source = 'file';
    }
  }

  state = {
    kek: envelope.hkdf(master, { info: 'passport/kek/v1' }),
    pepper: envelope.hkdf(master, { info: 'passport/pepper/v1' }),
    source
  };

  // マスターキー本体はもう要らないので、この Buffer は潰しておく
  master.fill(0);

  log.info(`鍵をアンロックしました (${source})`);
  return state;
}

function requireUnlocked() {
  if (!state) throw new Error('keyring がアンロックされていません。先に unlock() を呼んでください');
  return state;
}

function kek() {
  return requireUnlocked().kek;
}

function pepper() {
  return requireUnlocked().pepper;
}

function isUnlocked() {
  return state !== null;
}

// 起動時の健全性チェック。鍵が正しく動くことを、データを触る前に確かめる。
// マスターキーが差し替わっていた場合は、既存データの復号に失敗する前にここで気づける。
function selfTest() {
  const { kek: k } = requireUnlocked();
  const aad = envelope.buildAad({ vaultId: 'selftest', itemId: 'selftest', field: 'probe', version: 0 });
  const sealed = envelope.seal(k, 'passport-selftest', aad);
  const opened = envelope.open(k, sealed, aad);
  if (opened !== 'passport-selftest') {
    throw new Error('暗号の自己テストに失敗しました');
  }
  // AAD を変えたら必ず失敗すること（貼り替え防止が効いているか）
  let rejected = false;
  try {
    envelope.open(k, sealed, envelope.buildAad({
      vaultId: 'selftest', itemId: 'other', field: 'probe', version: 0
    }));
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error('AAD の検証が効いていません');
  return true;
}

module.exports = {
  unlock,
  isUnlocked,
  kek,
  pepper,
  selfTest,
  generateMasterKeyFile,
  readMasterKeyFile
};
