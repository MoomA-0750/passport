'use strict';
// パスワードの強さの判定。点検（lib/checkup.js）で「弱い」を決めるのに使う。
// 画面の強度メーター（static/common.js の passwordStrength）と同じ計算に、
// よくある単語と短さの判定を足したもの。厳密な推定ではなく「直したほうがよいもの」を拾う目安。

const COMMON = [
  'password', 'passw0rd', 'p@ssw0rd', 'p@ssword', 'qwerty', 'asdfgh', 'zxcvbn', 'letmein', 'welcome',
  'admin', 'administrator', 'changeme', 'iloveyou', 'abc123', '123456', '12345678', '111111', '000000',
  'root', 'toor', 'master', 'secret', 'dragon', 'monkey', 'default', 'guest', 'test', 'pass'
];

function estimateBits(text) {
  let pool = 0;
  if (/[a-z]/.test(text)) pool += 26;
  if (/[A-Z]/.test(text)) pool += 26;
  if (/[0-9]/.test(text)) pool += 10;
  if (/[^A-Za-z0-9]/.test(text)) pool += 32;
  const bits = text.length * Math.log2(pool || 1);
  const penalty = (/(.)\1{2,}/.test(text) ? 10 : 0)
    + (/^(?:[0-9]+|[a-z]+|[A-Z]+)$/.test(text) ? 15 : 0);
  return Math.max(0, bits - penalty);
}

// 弱い理由の一覧を返す。空なら弱くない。
//   short  … 10 文字未満
//   simple … 推定 40 ビット未満（画面のメーターで「弱い」）
//   common … よくある単語・並びを含む（大文字小文字と、末尾の数字・記号を無視して比べる）
function weaknesses(password) {
  const text = String(password || '');
  const reasons = [];
  if (text.length < 10) reasons.push('short');
  if (estimateBits(text) < 40) reasons.push('simple');
  const core = text.toLowerCase().replace(/[0-9!@#$%^&*()_+\-=.?]+$/, '');
  if (COMMON.some((word) => core === word || (word.length >= 6 && core.includes(word)))) reasons.push('common');
  return reasons;
}

module.exports = { weaknesses, estimateBits };
