'use strict';
// 設定の読み込み。優先順位は 環境変数 > keybox.ini > 既定値。
// WordBox は ini パッケージを使っているが、KeyBox は依存ゼロの方針なので
// 必要な範囲だけの ini パーサーを持つ（セクションと key = value、; と # のコメント）。

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

function parseIni(text) {
  const out = {};
  let section = '';
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith(';') || line.startsWith('#')) continue;
    const sectionMatch = line.match(/^\[(.+)\]$/);
    if (sectionMatch) {
      section = sectionMatch[1].trim();
      out[section] = out[section] || {};
      continue;
    }
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    // 値に付いた行末コメントを落とす（引用符の中は触らない）
    if (!value.startsWith('"') && !value.startsWith("'")) {
      const hash = value.search(/\s[;#]/);
      if (hash !== -1) value = value.slice(0, hash).trim();
    } else {
      value = value.slice(1, -1);
    }
    if (section) out[section][key] = value;
    else out[key] = value;
  }
  return out;
}

function toBool(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const v = String(value).toLowerCase();
  if (['on', 'true', 'yes', '1'].includes(v)) return true;
  if (['off', 'false', 'no', '0'].includes(v)) return false;
  return fallback;
}

function toInt(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

const iniPath = process.env.KEYBOX_CONFIG || path.join(ROOT, 'keybox.ini');
let ini = {};
if (fs.existsSync(iniPath)) {
  try {
    ini = parseIni(fs.readFileSync(iniPath, 'utf8'));
  } catch (err) {
    console.error(`[keybox] 設定ファイルを読めませんでした: ${iniPath}: ${err.message}`);
    process.exit(1);
  }
}

const s = ini.server || {};
const st = ini.storage || {};
const c = ini.crypto || {};
const se = ini.session || {};
const a = ini.auth || {};
const au = ini.audit || {};

function resolve(p) {
  return path.isAbsolute(p) ? p : path.resolve(ROOT, p);
}

const config = {
  root: ROOT,
  configPath: fs.existsSync(iniPath) ? iniPath : null,

  server: {
    port: toInt(process.env.KEYBOX_PORT || s.port, 3443),
    host: process.env.KEYBOX_HOST || s.host || '0.0.0.0',
    tls: toBool(process.env.KEYBOX_TLS !== undefined ? process.env.KEYBOX_TLS : s.tls, true),
    tlsKey: resolve(process.env.KEYBOX_TLS_KEY || s.tlsKey || './tls/server.key'),
    tlsCert: resolve(process.env.KEYBOX_TLS_CERT || s.tlsCert || './tls/server.crt'),
    trustProxy: toBool(process.env.KEYBOX_TRUST_PROXY !== undefined ? process.env.KEYBOX_TRUST_PROXY : s.trustProxy, false)
  },

  storage: {
    dataDir: resolve(process.env.KEYBOX_DATA_DIR || st.dataDir || './data')
  },

  crypto: {
    masterKeyFile: resolve(process.env.KEYBOX_MASTER_KEY_FILE || c.masterKeyFile || '/etc/keybox/master.key'),
    masterPassphrase: process.env.KEYBOX_MASTER_PASSPHRASE || null
  },

  session: {
    expireHours: toInt(process.env.KEYBOX_SESSION_EXPIRE_HOURS || se.expireHours, 8),
    idleLockMinutes: toInt(process.env.KEYBOX_IDLE_LOCK_MINUTES || se.idleLockMinutes, 15)
  },

  auth: {
    maxFailedAttempts: toInt(a.maxFailedAttempts, 5),
    lockoutMinutes: toInt(a.lockoutMinutes, 15),
    minPasswordLength: toInt(a.minPasswordLength, 12)
  },

  audit: {
    enabled: toBool(au.enabled, true)
  }
};

module.exports = config;
module.exports.parseIni = parseIni;
