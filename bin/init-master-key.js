#!/usr/bin/env node
'use strict';
// マスターキーを作る。最初に1回だけ実行する。
//
//   node bin/init-master-key.js
//
// 既にファイルがある場合は何もしない（上書きすると保存済みの秘密を全部失うため）。

const fs = require('fs');
const config = require('../lib/config');
const keyring = require('../lib/keyring');

const file = config.crypto.masterKeyFile;

if (config.crypto.masterPassphrase) {
  console.log('KEYBOX_MASTER_PASSPHRASE が設定されています。');
  console.log('パスフレーズ運用ではキーファイルは要りません。');
  process.exit(0);
}

if (fs.existsSync(file)) {
  console.log(`すでにあります: ${file}`);
  console.log('上書きすると、保存済みのパスワードは二度と復号できません。');
  console.log('作り直したい場合は、先に手で退避してから消してください。');
  process.exit(1);
}

try {
  keyring.generateMasterKeyFile(file);
} catch (err) {
  console.error(`作成に失敗しました: ${err.message}`);
  if (err.code === 'EACCES') {
    console.error(`  ${file} を作る権限がありません。sudo で実行するか、`);
    console.error('  keybox.ini の [crypto] masterKeyFile を書き込める場所にしてください。');
  }
  process.exit(1);
}

console.log(`マスターキーを作りました: ${file}`);
console.log('');
console.log('必ずやること:');
console.log(`  1. chown ${process.env.SUDO_USER || 'keybox'} ${file}   （KeyBox を動かすユーザーが読めるように）`);
console.log(`  2. chmod 400 ${file}`);
console.log('  3. このファイルを、KeyBox のデータとは別の場所へバックアップする');
console.log('');
console.log('このファイルを失うと、保存したパスワードは誰にも復号できません。');
