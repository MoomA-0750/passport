#!/usr/bin/env node
'use strict';
// 自己署名の TLS 証明書を作る。
//
//   node bin/make-cert.js keybox.example.local 192.168.1.50
//
// Node の標準ライブラリだけでは証明書を発行できないので、RHEL に入っている
// openssl コマンドを呼ぶ（オフライン環境でも ISO レポジトリから入る）。
//
// 社内 CA の証明書が取れるなら、そちらを使ったほうがブラウザの警告が出ない。
// その場合はこのスクリプトは不要で、tls/server.key と tls/server.crt に置くだけでよい。

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const names = process.argv.slice(2);
if (names.length === 0) names.push(os.hostname());

const outDir = path.resolve(__dirname, '..', 'tls');
const keyFile = path.join(outDir, 'server.key');
const certFile = path.join(outDir, 'server.crt');

if (fs.existsSync(keyFile) || fs.existsSync(certFile)) {
  console.error(`すでにあります: ${outDir}`);
  console.error('作り直す場合は、先に手で退避してから消してください。');
  process.exit(1);
}

fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

// IP アドレスと DNS 名を SAN に振り分ける。
// 最近のブラウザは CN を見ないので、SAN に入れないと必ずエラーになる。
const isIp = (value) => /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
const san = names.map((n) => (isIp(n) ? `IP:${n}` : `DNS:${n}`)).join(',');

const configText = `
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no

[dn]
CN = ${names[0]}
O = KeyBox

[v3]
subjectAltName = ${san}
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
`;

const configFile = path.join(outDir, 'openssl.cnf');
fs.writeFileSync(configFile, configText, { mode: 0o600 });

try {
  execFileSync('openssl', [
    'req', '-x509', '-nodes',
    '-newkey', 'rsa:2048',
    '-keyout', keyFile,
    '-out', certFile,
    '-days', '825',            // ブラウザが受け付ける上限に合わせる
    '-sha256',
    '-config', configFile
  ], { stdio: 'inherit' });
} catch (err) {
  console.error(`openssl の実行に失敗しました: ${err.message}`);
  console.error('RHEL なら dnf install openssl で入ります。');
  process.exit(1);
}

fs.chmodSync(keyFile, 0o400);
fs.chmodSync(certFile, 0o444);
fs.unlinkSync(configFile);

console.log('');
console.log(`秘密鍵: ${keyFile}`);
console.log(`証明書: ${certFile}`);
console.log(`対象の名前: ${san}`);
console.log('');
console.log('自己署名なので、初回アクセス時にブラウザが警告を出します。');
console.log('利用者には、この証明書を「信頼されたルート証明機関」に入れてもらうか、');
console.log('警告画面で続行してもらってください。');
console.log('（警告を通したあとは HTTPS として扱われるので、クリップボードのコピーも動きます）');
