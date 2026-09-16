'use strict';
// SSH エージェント（lib/sshagent.js）のテスト。
// 本物の OpenSSH（ssh-keygen / ssh-add）に話させて、鍵の一覧と署名が通ることを確かめる。
// プロトコルの実装はテストで拾いにくいので、自作の検証ではなく OpenSSH 側の検証を正とする。

const test = require('node:test');
const assert = require('node:assert');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const crypto = require('crypto');

const agent = require('../lib/sshagent');

// ソケットのパスは短くないと作れないので /tmp の直下に置く
const TMP = fs.mkdtempSync(path.join('/tmp', 'ppagt-'));
test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

const hasOpenSsh = spawnSync('ssh-keygen', ['-V'], { encoding: 'utf8' }).error === undefined
  && spawnSync('ssh-add', ['-h'], { encoding: 'utf8' }).error === undefined;

function run(cmd, args, { env = process.env, input = null } = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.stdin.end(input || undefined);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

function keygen(name, args) {
  spawnSync('ssh-keygen', ['-q', ...args, '-C', `${name}-comment`, '-f', path.join(TMP, name)], { stdio: 'ignore' });
  return fs.readFileSync(path.join(TMP, name), 'utf8');
}

const entries = [];
let server;
let sock;
let signCount = 0;

test('準備: 鍵を作って読み込み、エージェントを立てる', { skip: !hasOpenSsh }, async () => {
  for (const [name, args] of [
    ['ed', ['-t', 'ed25519', '-N', '']],
    ['rsa', ['-t', 'rsa', '-b', '2048', '-N', '']],
    ['ec256', ['-t', 'ecdsa', '-b', '256', '-N', '']],
    ['ec521', ['-t', 'ecdsa', '-b', '521', '-N', '']]
  ]) {
    const e = agent.loadPrivateKey(keygen(name, args));
    const fp = spawnSync('ssh-keygen', ['-l', '-E', 'sha256', '-f', path.join(TMP, `${name}.pub`)], { encoding: 'utf8' }).stdout;
    assert.ok(fp.includes(e.fingerprint), `${name} の指紋が ssh-keygen と合わない`);
    assert.strictEqual(e.comment, `${name}-comment`);
    entries.push(e);
  }
  sock = path.join(TMP, 's');
  server = await agent.listen(sock, { list: () => entries, onSign: () => { signCount += 1; } });
  assert.strictEqual(fs.statSync(sock).mode & 0o777, 0o600);
});

test('ssh-add -l に全部の鍵が出る', { skip: !hasOpenSsh }, async () => {
  const r = await run('ssh-add', ['-l'], { env: { ...process.env, SSH_AUTH_SOCK: sock } });
  assert.strictEqual(r.status, 0, r.stderr);
  for (const e of entries) assert.ok(r.stdout.includes(e.fingerprint));
});

test('ed25519 / RSA（sha2）/ ECDSA の署名を、OpenSSH が検証できる', { skip: !hasOpenSsh }, async () => {
  const msg = path.join(TMP, 'msg.txt');
  fs.writeFileSync(msg, 'passport agent test');
  for (const name of ['ed', 'rsa', 'ec256', 'ec521']) {
    const pub = path.join(TMP, `${name}.pub`);
    const signed = await run('ssh-keygen', ['-Y', 'sign', '-n', 'file', '-f', pub, msg], { env: { ...process.env, SSH_AUTH_SOCK: sock } });
    assert.strictEqual(signed.status, 0, `${name}: ${signed.stderr}`);
    const allowed = path.join(TMP, 'allowed');
    fs.writeFileSync(allowed, `tester ${fs.readFileSync(pub, 'utf8')}`);
    const verified = await run('ssh-keygen', ['-Y', 'verify', '-f', allowed, '-I', 'tester', '-n', 'file', '-s', `${msg}.sig`], { input: fs.readFileSync(msg) });
    assert.strictEqual(verified.status, 0, `${name} の署名を検証できない: ${verified.stderr}`);
    fs.unlinkSync(`${msg}.sig`);
  }
  assert.strictEqual(signCount, 4);
});

// ここからは生のメッセージで確かめる
const { str, uint32 } = agent._encode;
function frame(body) {
  return Buffer.concat([uint32(body.length), body]);
}
function talk(payload) {
  return new Promise((resolve) => {
    const conn = net.createConnection(sock);
    let got = Buffer.alloc(0);
    conn.on('data', (d) => {
      got = Buffer.concat([got, d]);
      if (got.length >= 4 && got.length >= 4 + got.readUInt32BE(0)) { conn.end(); resolve(got.subarray(4)); }
    });
    conn.on('close', () => resolve(got.length ? got.subarray(4) : null));
    conn.write(payload);
  });
}

test('RSA で SHA-1（フラグなし）の署名を求められたら断る', { skip: !hasOpenSsh }, async () => {
  const rsa = entries.find((e) => e.key.asymmetricKeyType === 'rsa');
  const reply = await talk(frame(Buffer.concat([Buffer.from([agent.MSG.SIGN_REQUEST]), str(rsa.publicBlob), str('data'), uint32(0)])));
  assert.deepStrictEqual([...reply], [agent.MSG.FAILURE]);
});

test('持っていない鍵での署名・鍵の追加・ロックなどは失敗で返す', { skip: !hasOpenSsh }, async () => {
  const other = crypto.generateKeyPairSync('ed25519').publicKey;
  const blob = require('../lib/sshkeys').publicKeyBlobFrom(other);
  const unknown = await talk(frame(Buffer.concat([Buffer.from([agent.MSG.SIGN_REQUEST]), str(blob), str('data'), uint32(0)])));
  assert.deepStrictEqual([...unknown], [agent.MSG.FAILURE]);
  for (const type of [17, 18, 19, 22, 23, 27]) {
    const reply = await talk(frame(Buffer.from([type])));
    assert.deepStrictEqual([...reply], [agent.MSG.FAILURE], `メッセージ ${type}`);
  }
  // 壊れたメッセージでも落ちない
  const broken = await talk(frame(Buffer.from([agent.MSG.SIGN_REQUEST, 0, 0, 0, 99])));
  assert.deepStrictEqual([...broken], [agent.MSG.FAILURE]);
});

test('大きすぎるメッセージは接続を切る', { skip: !hasOpenSsh }, async () => {
  const reply = await talk(uint32(10 * 1024 * 1024));
  assert.strictEqual(reply, null);
  // エージェント自体は生きている
  const r = await run('ssh-add', ['-l'], { env: { ...process.env, SSH_AUTH_SOCK: sock } });
  assert.strictEqual(r.status, 0);
});

test('パスフレーズで暗号化された OpenSSH 形式は読み飛ばす（理由つき）', { skip: !hasOpenSsh }, () => {
  const text = keygen('enc', ['-t', 'ed25519', '-N', 'a-passphrase']);
  assert.throws(() => agent.loadPrivateKey(text, { passphrase: 'a-passphrase' }), (e) => e instanceof agent.SkipKey && /暗号化された OpenSSH/.test(e.message));
});

test('パスフレーズ付きの PEM は、預けたパスフレーズで開ける。無ければ読み飛ばす', () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'pem-pass' });
  assert.ok(agent.loadPrivateKey(pem, { passphrase: 'pem-pass' }).fingerprint.startsWith('SHA256:'));
  assert.throws(() => agent.loadPrivateKey(pem), (e) => e instanceof agent.SkipKey);
});

test('公開鍵の部分を差し替えた OpenSSH 形式は使わない', { skip: !hasOpenSsh }, () => {
  const a = fs.readFileSync(path.join(TMP, 'ed'), 'utf8');
  const other = keygen('ed2', ['-t', 'ed25519', '-N', '']);
  const decode = (t) => Buffer.from(t.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const bodyA = decode(a);
  const bodyB = decode(other);
  // 先頭の公開鍵ブロブ（magic + none + none + '' + count の後ろ）を B のものにする
  const offset = 15 + 8 + 8 + 4 + 4;
  const lenA = bodyA.readUInt32BE(offset);
  const lenB = bodyB.readUInt32BE(offset);
  const swapped = Buffer.concat([bodyA.subarray(0, offset), bodyB.subarray(offset, offset + 4 + lenB), bodyA.subarray(offset + 4 + lenA)]);
  const text = `-----BEGIN OPENSSH PRIVATE KEY-----\n${swapped.toString('base64')}\n-----END OPENSSH PRIVATE KEY-----\n`;
  assert.throws(() => agent.loadPrivateKey(text), (e) => e instanceof agent.SkipKey && /一致しません/.test(e.message));
});

test('ソケットのパスが長すぎると、黙って別の場所に作らずに断る', async () => {
  await assert.rejects(agent.listen(path.join(TMP, 'x'.repeat(120)), { list: () => [], onSign: () => {} }), /長すぎます/);
});

test('メッセージが1バイトずつ届いても、2通が1回で届いても、それぞれに答える', { skip: !hasOpenSsh }, async () => {
  const one = frame(Buffer.from([agent.MSG.REQUEST_IDENTITIES]));
  const replies = await new Promise((resolve) => {
    const conn = net.createConnection(sock);
    let got = Buffer.alloc(0);
    const bodies = [];
    conn.on('data', (d) => {
      got = Buffer.concat([got, d]);
      while (got.length >= 4 && got.length >= 4 + got.readUInt32BE(0)) {
        bodies.push(got.subarray(4, 4 + got.readUInt32BE(0)));
        got = got.subarray(4 + got.readUInt32BE(0));
      }
      if (bodies.length === 3) { conn.end(); resolve(bodies); }
    });
    (async () => {
      for (const byte of one) { conn.write(Buffer.from([byte])); await new Promise((r) => setTimeout(r, 2)); }
      conn.write(Buffer.concat([one, one]));
    })();
  });
  assert.strictEqual(replies.length, 3);
  for (const body of replies) {
    assert.strictEqual(body[0], agent.MSG.IDENTITIES_ANSWER);
    assert.strictEqual(body.readUInt32BE(1), entries.length);
  }
});

test('旧形式の暗号化 PEM（ssh-keygen -m PEM）の RSA / ECDSA も、預けたパスフレーズで開ける', { skip: !hasOpenSsh }, () => {
  for (const [name, args] of [['pemrsa', ['-t', 'rsa', '-b', '2048']], ['pemec', ['-t', 'ecdsa', '-b', '384']]]) {
    const text = keygen(name, [...args, '-m', 'PEM', '-N', 'old-pem-pass']);
    assert.match(text, /BEGIN (RSA|EC) PRIVATE KEY/);
    const e = agent.loadPrivateKey(text, { passphrase: 'old-pem-pass' });
    const fp = spawnSync('ssh-keygen', ['-l', '-E', 'sha256', '-f', path.join(TMP, `${name}.pub`)], { encoding: 'utf8' }).stdout;
    assert.ok(fp.includes(e.fingerprint));
    assert.throws(() => agent.loadPrivateKey(text), /パスフレーズが無いか違う/);
  }
});

test('秘密の成分が壊れた RSA 鍵は、公開鍵が合っていても使わない', () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = privateKey.export({ format: 'jwk' });
  // 署名は CRT の成分（dp / dq）で計算されるので、d と一緒にそちらも壊す
  const flip = (v) => { const b = Buffer.from(v, 'base64url'); b[b.length - 1] ^= 0x01; return b.toString('base64url'); };
  let broken;
  try {
    broken = crypto.createPrivateKey({ key: { ...jwk, d: flip(jwk.d), dp: flip(jwk.dp), dq: flip(jwk.dq) }, format: 'jwk' }).export({ type: 'pkcs8', format: 'pem' });
  } catch {
    return; // Node が取り込みの時点で弾くなら、それで十分
  }
  assert.throws(() => agent.loadPrivateKey(broken), (e) => e instanceof agent.SkipKey);
});

test('ソケットに数字だけのパスを渡しても、TCP のポートとして開かない', async () => {
  const cwd = process.cwd();
  process.chdir(TMP);
  try {
    const srv = await agent.listen(path.resolve('8931'), { list: () => [], onSign: () => {} });
    assert.ok(fs.statSync(path.join(TMP, '8931')).isSocket());
    const tcp = await new Promise((resolve) => {
      const c = net.createConnection({ port: 8931, host: '127.0.0.1' });
      c.on('connect', () => { c.destroy(); resolve(true); });
      c.on('error', () => resolve(false));
    });
    assert.strictEqual(tcp, false, 'TCP で開いている');
    srv.close();
  } finally {
    process.chdir(cwd);
  }
});

test('後片付け', { skip: !hasOpenSsh }, () => {
  server.close();
});
