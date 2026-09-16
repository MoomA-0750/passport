'use strict';
// {{variable}} 置換だけの素朴なテンプレート。WordBox と同じ方式。
//
// 金庫なので、既定を「必ずエスケープする」にしてある。
// エスケープを外したいときだけ {{{raw}}} と書く（使う場所を数えられる程度に留める）。

const fs = require('fs');
const path = require('path');

const TEMPLATE_DIR = path.resolve(__dirname, '..', 'templates');
const cache = new Map();

function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// <script> の中へ JSON を埋めるときは、HTML エスケープではなくこちらを使う。
// </script> と HTML コメント開始で文書構造を壊されないようにする。
function jsonForScript(value) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    // 行区切り文字 (U+2028 / U+2029) は JS の行終端として解釈されるので必ず退避する。
    // ソースに生の文字を置かないよう、正規表現は文字列から組む。
    .replace(new RegExp('[\\u2028\\u2029]', 'g'), (c) => '\\u' + c.charCodeAt(0).toString(16));
}

function load(name) {
  if (process.env.NODE_ENV !== 'development' && cache.has(name)) return cache.get(name);
  const file = path.join(TEMPLATE_DIR, `${name}.html`);
  const text = fs.readFileSync(file, 'utf8');
  cache.set(name, text);
  return text;
}

function renderString(template, vars = {}) {
  return template
    // {{{raw}}} はエスケープしない
    .replace(/\{\{\{\s*([\w.]+)\s*\}\}\}/g, (_, key) => String(pick(vars, key) ?? ''))
    // {{var}} は必ずエスケープ
    .replace(/\{\{\s*([\w.]+)\s*\}\}/g, (_, key) => escapeHtml(pick(vars, key)));
}

function pick(vars, key) {
  return key.split('.').reduce((acc, part) => (acc == null ? undefined : acc[part]), vars);
}

// layout.html の {{{content}}} に中身を差し込んで返す。
function render(name, vars = {}, { layout = 'layout' } = {}) {
  const body = renderString(load(name), vars);
  if (!layout) return body;
  return renderString(load(layout), { ...vars, content: body });
}

module.exports = { render, renderString, escapeHtml, jsonForScript, load };
