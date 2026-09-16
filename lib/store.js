'use strict';
// 1レコード1ファイルの JSON ストア。DB は使わない（WordBox と同じ方針）。
//
// 金庫として外せない性質:
//   ・書き込みは一時ファイル + rename で原子的に行う。壊れた JSON を残さない
//   ・version による楽観ロック。2人が同じアイテムを同時に編集したら後の方を弾く
//   ・パスは必ず dataDir の中に閉じる（パストラバーサル対策）
//   ・新規ファイルのモードは 0600。ディレクトリは 0700

const fs = require('fs');
const path = require('path');
const config = require('./config');
const log = require('./logger')('passport:store');

const DATA_DIR = config.storage.dataDir;

class ConflictError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConflictError';
    this.code = 'CONFLICT';
  }
}

// ID として受け入れる形。ここを緩めるとパストラバーサルの入口になる。
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

function isValidId(id) {
  return typeof id === 'string' && ID_RE.test(id);
}

function assertValidId(id, what = 'ID') {
  if (!isValidId(id)) {
    throw new Error(`${what} の形式が不正です: ${JSON.stringify(id)}`);
  }
}

// 相対パスを dataDir の中に解決する。外に出ようとしたら投げる。
function resolveInData(...parts) {
  for (const part of parts) {
    if (typeof part !== 'string' || part.includes('\0')) {
      throw new Error('パスに使えない値が渡されました');
    }
  }
  const full = path.resolve(DATA_DIR, ...parts);
  const rel = path.relative(DATA_DIR, full);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`データディレクトリの外を指しています: ${parts.join('/')}`);
  }
  return full;
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
}

function readJson(relPath) {
  const full = resolveInData(relPath);
  if (!fs.existsSync(full)) return null;
  const text = fs.readFileSync(full, 'utf8');
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`JSON が壊れています: ${relPath}: ${err.message}`);
  }
}

// 一時ファイルへ書いて rename。途中で落ちても元のファイルは無傷。
function writeJson(relPath, data) {
  const full = resolveInData(relPath);
  ensureDir(path.dirname(full));
  const tmp = `${full}.tmp-${process.pid}-${Date.now()}`;
  const text = JSON.stringify(data, null, 2);
  const fd = fs.openSync(tmp, 'w', 0o600);
  try {
    fs.writeFileSync(fd, text, 'utf8');
    fs.fsyncSync(fd); // rename 前に中身をディスクへ落とす
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, full);
  return data;
}

// version による楽観ロック付きの更新。
// mutate(current) が返したオブジェクトを version+1 で書く。
function updateJson(relPath, expectedVersion, mutate) {
  const current = readJson(relPath);
  if (!current) throw new Error(`更新対象が見つかりません: ${relPath}`);
  if (expectedVersion !== undefined && expectedVersion !== null &&
      Number(current.version) !== Number(expectedVersion)) {
    throw new ConflictError(
      `ほかの誰かが先に更新しています（保存されているのは version ${current.version}、送られてきたのは ${expectedVersion}）`
    );
  }
  const next = mutate(current);
  next.version = Number(current.version || 0) + 1;
  next.updatedAt = new Date().toISOString();
  return writeJson(relPath, next);
}

function deleteFile(relPath) {
  const full = resolveInData(relPath);
  if (!fs.existsSync(full)) return false;
  fs.unlinkSync(full);
  return true;
}

// ディレクトリ内の .json を列挙して中身を返す。壊れた1件で全体を落とさない。
function listJson(relDir) {
  const full = resolveInData(relDir);
  if (!fs.existsSync(full)) return [];
  const out = [];
  for (const name of fs.readdirSync(full)) {
    if (!name.endsWith('.json') || name.includes('.tmp-')) continue;
    try {
      const record = readJson(path.join(relDir, name));
      if (record) out.push(record);
    } catch (err) {
      log.error(`読み飛ばしました: ${relDir}/${name}: ${err.message}`);
    }
  }
  return out;
}

function listDirs(relDir) {
  const full = resolveInData(relDir);
  if (!fs.existsSync(full)) return [];
  return fs.readdirSync(full, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name);
}

function exists(relPath) {
  return fs.existsSync(resolveInData(relPath));
}

// 追記専用。監査ログ用。
function appendLine(relPath, line) {
  const full = resolveInData(relPath);
  ensureDir(path.dirname(full));
  fs.appendFileSync(full, `${line}\n`, { encoding: 'utf8', mode: 0o600 });
}

function init() {
  ensureDir(DATA_DIR);
  log.info(`データディレクトリ: ${DATA_DIR}`);
}

module.exports = {
  init,
  isValidId,
  assertValidId,
  readJson,
  writeJson,
  updateJson,
  deleteFile,
  listJson,
  listDirs,
  exists,
  appendLine,
  resolveInData,
  ensureDir,
  ConflictError,
  DATA_DIR
};
