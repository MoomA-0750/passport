'use strict';
// 名前空間つきの構造化ログ。DEBUG=passport:* で詳細を出す。
// WordBox は debug + ms + chalk を使っているが、Passport は依存ゼロなので同じ体裁を自前で出す。
// 金庫なので、ログに秘密（パスワード・平文・マスターキー）は絶対に載せない。

const NS_FILTER = (process.env.DEBUG || '').split(',').map((s) => s.trim()).filter(Boolean);

const COLORS = {
  passport: 36,
  'passport:server': 32,
  'passport:auth': 33,
  'passport:crypto': 35,
  'passport:store': 34,
  'passport:audit': 90
};
const ESC = String.fromCharCode(27);
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;

function enabled(ns) {
  if (NS_FILTER.length === 0) return false;
  return NS_FILTER.some((pattern) => {
    if (pattern === '*') return true;
    if (pattern.endsWith('*')) return ns.startsWith(pattern.slice(0, -1));
    return ns === pattern;
  });
}

function paint(text, code) {
  return useColor ? `${ESC}[${code}m${text}${ESC}[0m` : text;
}

function formatMs(ms) {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.round(ms / 60000)}m`;
}

// 所要時間の色分け（WordBox と同じ基準: 100ms以下=緑、1s以下=黄、それ以上=赤）
function paintDuration(ms) {
  const text = formatMs(ms);
  if (ms <= 100) return paint(text, 32);
  if (ms <= 1000) return paint(text, 33);
  return paint(text, 31);
}

function createLogger(ns) {
  const on = enabled(ns);
  const label = paint(ns, COLORS[ns] || 36);

  const debug = (...args) => {
    if (!on) return;
    console.error(`${label} ${args.join(' ')}`);
  };

  return {
    debug,
    // 常に出る。運用者が見るべきもの。
    info: (...args) => console.log(`${label} ${args.join(' ')}`),
    warn: (...args) => console.warn(`${label} ${paint('WARN', 33)} ${args.join(' ')}`),
    error: (...args) => console.error(`${label} ${paint('ERROR', 31)} ${args.join(' ')}`),
    // 処理時間つきのログ。const done = log.timer('x'); ... done();
    timer(name) {
      const start = Date.now();
      return (suffix = '') => debug(`${name} ${paintDuration(Date.now() - start)} ${suffix}`);
    },
    enabled: on
  };
}

module.exports = createLogger;
module.exports.formatMs = formatMs;
