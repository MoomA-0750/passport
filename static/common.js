'use strict';
// 画面共通の部品。外部ライブラリは Bootstrap のバンドルだけ。
// CSP が script-src 'self' なので、インラインスクリプトは使わない。
//
// 中身は即時関数で閉じ、外へ出すのは window.KB と window.KBUtil だけにする。
// 素の <script> は同じグローバルを共有するので、閉じないと各画面の
// const { apiFetch } = window.KBUtil; と名前がぶつかって画面の JS が止まる。

(() => {
  // 初期データは <body data-bootstrap="..."> から受け取る
  const KB = {
    data: (() => {
      try {
        return JSON.parse(document.body.dataset.bootstrap || '{}');
      } catch {
        return {};
      }
    })(),
    csrfToken: null
  };
  KB.csrfToken = KB.data.csrfToken || null;

  // --- API --------------------------------------------------------------------

  async function apiFetch(path, { method = 'GET', body = null } = {}) {
    const headers = {};
    if (body !== null) headers['Content-Type'] = 'application/json';
    if (KB.csrfToken && method !== 'GET') headers['X-CSRF-Token'] = KB.csrfToken;

    const res = await fetch(path, {
      method,
      headers,
      body: body === null ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
      cache: 'no-store'
    });

    // セッションが切れたらログイン画面へ戻す
    if (res.status === 401 && !path.endsWith('/login')) {
      window.location.href = '/login';
      throw new Error('ログインが切れました');
    }

    let payload = {};
    try {
      payload = await res.json();
    } catch {
      // 本文が JSON でない場合はそのまま
    }
    if (!res.ok) {
      const err = new Error(payload.error || `通信に失敗しました (${res.status})`);
      err.status = res.status;
      throw err;
    }
    return payload;
  }

  // --- 表示のこまごま ---------------------------------------------------------

  function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  function showError(elementId, message) {
    const el = document.getElementById(elementId);
    if (!el) return;
    if (!message) {
      el.classList.add('d-none');
      el.textContent = '';
      return;
    }
    el.textContent = message;
    el.classList.remove('d-none');
  }

  function toast(message, variant = 'secondary') {
    const stack = document.getElementById('toast-stack');
    if (!stack) return;
    const el = document.createElement('div');
    el.className = `toast-item bg-${variant}`;
    el.textContent = message;
    stack.appendChild(el);
    // 出してから少し待って消す。画面を塞がない程度に短く。
    setTimeout(() => {
      el.classList.add('toast-out');
      setTimeout(() => el.remove(), 300);
    }, 2200);
  }

  function formatDateTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '—';
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function formatRelative(iso) {
    if (!iso) return '';
    const diff = Date.now() - new Date(iso).getTime();
    if (Number.isNaN(diff)) return '';
    const minutes = Math.floor(diff / 60000);
    if (minutes < 1) return 'たった今';
    if (minutes < 60) return `${minutes}分前`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}時間前`;
    const days = Math.floor(hours / 24);
    if (days < 31) return `${days}日前`;
    const months = Math.floor(days / 30.4);
    if (months < 12) return `${months}か月前`;
    return `${Math.floor(days / 365)}年前`;
  }

  // --- パスワード生成 ---------------------------------------------------------
  // crypto.getRandomValues は HTTPS でなくても使える（crypto.subtle と違う）。

  const CHARSETS = {
    upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
    lower: 'abcdefghijkmnopqrstuvwxyz',
    digit: '23456789',
    symbol: '!@#$%^&*()-_=+[]{};:,.?',
    ambiguousUpper: 'IO',
    ambiguousLower: 'l',
    ambiguousDigit: '01'
  };

  function randomInt(max) {
    // 剰余による偏りを避けるため、範囲外を引いたら引き直す
    const limit = Math.floor(0xffffffff / max) * max;
    const buf = new Uint32Array(1);
    let value;
    do {
      crypto.getRandomValues(buf);
      value = buf[0];
    } while (value >= limit);
    return value % max;
  }

  function generatePassword({ length = 20, upper = true, lower = true, digit = true, symbol = true, ambiguous = false } = {}) {
    const pools = [];
    if (upper) pools.push(CHARSETS.upper + (ambiguous ? CHARSETS.ambiguousUpper : ''));
    if (lower) pools.push(CHARSETS.lower + (ambiguous ? CHARSETS.ambiguousLower : ''));
    if (digit) pools.push(CHARSETS.digit + (ambiguous ? CHARSETS.ambiguousDigit : ''));
    if (symbol) pools.push(CHARSETS.symbol);
    if (pools.length === 0) pools.push(CHARSETS.lower);

    const all = pools.join('');
    const chars = [];
    // 選んだ種類を必ず1文字は含める
    for (const pool of pools) {
      if (chars.length < length) chars.push(pool[randomInt(pool.length)]);
    }
    while (chars.length < length) chars.push(all[randomInt(all.length)]);

    // Fisher-Yates で混ぜる（種類が先頭に固まらないように）
    for (let i = chars.length - 1; i > 0; i -= 1) {
      const j = randomInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
  }

  // 強度の目安。厳密なエントロピーではなく、利用者への合図として出す。
  function passwordStrength(password) {
    const text = String(password || '');
    if (!text) return { score: 0, label: '', percent: 0, variant: 'secondary' };

    let pool = 0;
    if (/[a-z]/.test(text)) pool += 26;
    if (/[A-Z]/.test(text)) pool += 26;
    if (/[0-9]/.test(text)) pool += 10;
    if (/[^A-Za-z0-9]/.test(text)) pool += 32;
    const bits = text.length * Math.log2(pool || 1);

    // 同じ文字の繰り返しや連番は割り引く
    const penalty = (/(.)\1{2,}/.test(text) ? 10 : 0)
      + (/^(?:[0-9]+|[a-z]+|[A-Z]+)$/.test(text) ? 15 : 0);
    const effective = Math.max(0, bits - penalty);

    if (effective < 40) return { score: 1, label: '弱い', percent: 25, variant: 'danger' };
    if (effective < 60) return { score: 2, label: 'ふつう', percent: 50, variant: 'warning' };
    if (effective < 90) return { score: 3, label: '強い', percent: 75, variant: 'success' };
    return { score: 4, label: 'とても強い', percent: 100, variant: 'success' };
  }

  function bindStrengthMeter(inputId, barId, textId) {
    const input = document.getElementById(inputId);
    const bar = document.getElementById(barId);
    const text = textId ? document.getElementById(textId) : null;
    if (!input || !bar) return;
    const original = text ? text.textContent : '';
    input.addEventListener('input', () => {
      const strength = passwordStrength(input.value);
      bar.style.width = `${strength.percent}%`;
      bar.className = `password-meter-bar bg-${strength.variant}`;
      if (text) {
        text.textContent = strength.label
          ? `${strength.label}（${input.value.length}文字）`
          : original;
      }
    });
  }

  // --- クリップボード ---------------------------------------------------------

  // navigator.clipboard は HTTPS（secure context）でしか使えないので、
  // HTTP で開かれた場合のために古い方法へ落とす。
  async function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch {
      ok = false;
    }
    area.remove();
    if (!ok) throw new Error('この環境ではコピーできませんでした。手で選択してください');
    return true;
  }

  // --- 表示切り替えボタン -----------------------------------------------------

  document.addEventListener('click', (event) => {
    const button = event.target.closest('[data-toggle-visibility]');
    if (!button) return;
    const input = document.getElementById(button.dataset.toggleVisibility);
    if (!input) return;
    const nowText = input.type === 'password';
    input.type = nowText ? 'text' : 'password';
    button.textContent = nowText ? '隠す' : '表示';
  });

  window.KB = KB;
  window.KBUtil = {
    apiFetch,
    escapeHtml,
    showError,
    toast,
    formatDateTime,
    formatRelative,
    generatePassword,
    passwordStrength,
    bindStrengthMeter,
    copyToClipboard
  };
})();
