// 入力欄のそばに出る候補メニュー。
//
// これはページの中で動く。既定では動かない。
// 本人が「このサイトで使う」か「すべてのサイトで使う」を選んだときだけ、
// background が chrome.scripting.registerContentScripts で登録する。
//
// 決めごと:
//   ・秘密はここに置かない。埋める瞬間に background から受け取り、欄へ入れたら忘れる
//   ・どのサイトの候補を出すかは background が sender の origin から決める。
//     ここから「このホストの分をくれ」と指定できないようにしてある（なりすまし防止）
//   ・メニューは closed な Shadow DOM の中に作る。ページ側の CSS と JS から触らせない
//   ・埋めるのは isTrusted な操作だけ。ページが script から click() を投げても動かない
//   ・勝手に送信しない

(() => {
  'use strict';

  // 二重に読み込まれたら何もしない（登録し直しのときなど）
  if (window.__passportInlineLoaded) return;
  window.__passportInlineLoaded = true;

  const HOST_ELEMENT_ID = 'passport-inline-host';
  const MENU_MAX_ITEMS = 8;

  let shadow = null;
  let hostElement = null;
  let anchorField = null;
  let candidates = null;      // null = まだ聞いていない
  let candidatesAt = 0;
  let locked = false;
  let dismissedFor = null;    // このフィールドでは出さない、という一時的な記憶
  let busy = false;

  const CACHE_MS = 30 * 1000;

  // --- 入力欄の見分け -------------------------------------------------------

  function isVisible(el) {
    if (!el || el.disabled || el.readOnly) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return false;
    const style = window.getComputedStyle(el);
    return style.visibility !== 'hidden' && style.display !== 'none' && Number(style.opacity) > 0.05;
  }

  function hay(el) {
    return `${el.name} ${el.id} ${el.autocomplete} ${el.placeholder} ${el.getAttribute('aria-label') || ''}`
      .toLowerCase();
  }

  function isPasswordField(el) {
    return el.tagName === 'INPUT' && el.type === 'password';
  }

  function isUsernameField(el) {
    if (el.tagName !== 'INPUT') return false;
    if (!['text', 'email', 'tel', ''].includes(el.type)) return false;
    if (/otp|totp|2fa|mfa|one.?time|verification|authenticator|ワンタイム|認証コード/.test(hay(el))) return false;
    // ユーザー名らしい名前か、同じフォームにパスワード欄があるか
    if (/user|login|account|email|mail|id\b|ユーザー|メール|アカウント/.test(hay(el))) return true;
    const scope = el.form || document;
    return [...scope.querySelectorAll('input[type="password"]')].some(isVisible);
  }

  function isLoginField(el) {
    return isVisible(el) && (isPasswordField(el) || isUsernameField(el));
  }

  // --- 値を入れる -----------------------------------------------------------

  // React / Vue は value を直接書き換えても気づかないので、
  // プロトタイプ側の setter を呼んでからイベントを出す
  function setValue(el, value) {
    const proto = el instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
    setter.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // フォーカスしていた欄が属するフォームの中だけを埋める。
  // 同じページにログインフォームが複数あっても、選んだ場所だけが埋まる。
  function fillNear(field, { username, password, totp }) {
    const scope = field.form || field.closest('form') || document;
    const inputs = [...scope.querySelectorAll('input')].filter(isVisible);
    const filled = [];

    const passwordFields = inputs.filter(isPasswordField);
    if (password && passwordFields.length > 0) {
      // パスワード変更画面のように欄が2つあるときは最初の1つだけ
      setValue(passwordFields[0], password);
      filled.push('パスワード');
    }

    if (username) {
      const passwordTop = passwordFields.length
        ? passwordFields[0].getBoundingClientRect().top
        : Number.POSITIVE_INFINITY;
      const texts = inputs.filter((el) => ['text', 'email', 'tel', ''].includes(el.type));
      const otpLike = (el) => /otp|totp|2fa|mfa|one.?time|verification|authenticator|ワンタイム|認証コード/.test(hay(el));
      const candidatesForName = texts.filter((el) => !otpLike(el));
      const target = candidatesForName.find((el) => /user|login|account|email|mail|id\b|ユーザー|メール|アカウント/.test(hay(el)))
        || candidatesForName.filter((el) => el.getBoundingClientRect().top <= passwordTop).pop()
        || candidatesForName[0];
      if (target) {
        setValue(target, username);
        filled.push('ユーザー名');
      }
    }

    if (totp) {
      const texts = inputs.filter((el) => ['text', 'tel', 'number', ''].includes(el.type));
      const target = texts.find((el) => /otp|totp|2fa|mfa|one.?time|verification|authenticator|ワンタイム|認証コード/.test(hay(el)))
        || inputs.find((el) => el.autocomplete === 'one-time-code');
      if (target) {
        setValue(target, totp);
        filled.push('ワンタイムパスワード');
      }
    }

    return filled;
  }

  // --- メニューの見た目 -----------------------------------------------------

  const STYLE = `
    :host { all: initial; }
    .menu {
      position: fixed;
      z-index: 2147483647;
      min-width: 15rem;
      max-width: 22rem;
      background: #fff;
      color: #1f2933;
      border: 1px solid #dee2e6;
      border-radius: .4rem;
      box-shadow: 0 .4rem 1.2rem rgba(0,0,0,.18);
      font: 13px/1.45 system-ui, -apple-system, "Noto Sans JP", sans-serif;
      overflow: hidden;
    }
    .head {
      display: flex; align-items: center; justify-content: space-between;
      padding: .35rem .55rem;
      background: #1f2933; color: #fff; font-size: .74rem;
    }
    .close {
      background: transparent; border: 0; color: #fff; cursor: pointer;
      font-size: .8rem; line-height: 1; padding: .1rem .25rem; border-radius: .2rem;
    }
    .close:hover { background: rgba(255,255,255,.2); }
    .list { list-style: none; margin: 0; padding: 0; max-height: 15rem; overflow-y: auto; }
    .row {
      display: flex; align-items: center; gap: .5rem; width: 100%;
      background: transparent; border: 0; border-top: 1px solid #f1f3f5;
      padding: .45rem .6rem; text-align: left; cursor: pointer; color: inherit;
      font: inherit;
    }
    .row:first-child { border-top: 0; }
    .row:hover, .row:focus { background: #e7f1ff; outline: none; }
    .icon { flex: 0 0 auto; font-size: 1rem; }
    .body { min-width: 0; flex: 1 1 auto; }
    .title { font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sub { color: #6b7680; font-size: .75rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .badge {
      display: inline-block; margin-left: .3rem; padding: 0 .25rem; border-radius: .2rem;
      background: #f1f3f5; color: #6b7680; font-size: .66rem; font-weight: 400;
    }
    .note { padding: .5rem .6rem; color: #6b7680; font-size: .76rem; }
    .note.error { color: #d6336c; }
    @media (prefers-color-scheme: dark) {
      .menu { background: #1b1f24; color: #e6e9ec; border-color: #333b44; }
      .row { border-top-color: #2a3139; }
      .row:hover, .row:focus { background: #243040; }
      .sub, .note { color: #9aa4ad; }
      .badge { background: #2a3139; color: #9aa4ad; }
    }
  `;

  function ensureShadow() {
    if (shadow) return shadow;
    hostElement = document.createElement('div');
    hostElement.id = HOST_ELEMENT_ID;
    // ページの CSS に巻き込まれないように、位置だけ持たせる
    hostElement.style.cssText = 'all: initial; position: static;';
    // closed にして、ページ側の JS から中身を触れないようにする
    shadow = hostElement.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = STYLE;
    shadow.append(style);
    (document.body || document.documentElement).append(hostElement);
    return shadow;
  }

  function hideMenu() {
    if (!shadow) return;
    const menu = shadow.querySelector('.menu');
    if (menu) menu.remove();
    anchorField = null;
  }

  function position(menu, field) {
    const rect = field.getBoundingClientRect();
    const width = Math.max(rect.width, 240);
    menu.style.width = `${Math.min(width, 360)}px`;
    // いったん出してから高さを測って、下に入らなければ上へ
    menu.style.left = '0px';
    menu.style.top = '0px';
    const height = menu.getBoundingClientRect().height || 120;
    const below = rect.bottom + 4;
    const fitsBelow = below + height <= window.innerHeight;
    menu.style.top = `${fitsBelow ? below : Math.max(4, rect.top - height - 4)}px`;
    menu.style.left = `${Math.max(4, Math.min(rect.left, window.innerWidth - width - 8))}px`;
  }

  const TYPE_ICONS = { login: '🔑', server: '🖥️' };

  function renderMenu(field) {
    const root = ensureShadow();
    hideMenu();
    anchorField = field;

    const menu = document.createElement('div');
    menu.className = 'menu';

    const head = document.createElement('div');
    head.className = 'head';
    const label = document.createElement('span');
    label.textContent = '🔐 Passport';
    const close = document.createElement('button');
    close.className = 'close';
    close.type = 'button';
    close.textContent = '×';
    close.title = '閉じる';
    close.addEventListener('click', (event) => {
      if (!event.isTrusted) return;
      dismissedFor = field;
      hideMenu();
    });
    head.append(label, close);
    menu.append(head);

    if (locked) {
      const note = document.createElement('div');
      note.className = 'note';
      note.textContent = 'ロックされています。ツールバーの Passport アイコンからログインしてください。';
      menu.append(note);
    } else if (!candidates || candidates.length === 0) {
      const note = document.createElement('div');
      note.className = 'note';
      note.textContent = 'このサイトに使えるものはありません。';
      menu.append(note);
    } else {
      const list = document.createElement('ul');
      list.className = 'list';
      for (const item of candidates.slice(0, MENU_MAX_ITEMS)) {
        const li = document.createElement('li');
        const row = document.createElement('button');
        row.className = 'row';
        row.type = 'button';

        const icon = document.createElement('span');
        icon.className = 'icon';
        icon.textContent = TYPE_ICONS[item.type] || '🔑';

        const body = document.createElement('div');
        body.className = 'body';
        const title = document.createElement('div');
        title.className = 'title';
        title.textContent = item.title;
        if (item.matchKind === 'subdomain') {
          const badge = document.createElement('span');
          badge.className = 'badge';
          badge.textContent = 'サブドメイン';
          title.append(badge);
        }
        const sub = document.createElement('div');
        sub.className = 'sub';
        sub.textContent = [item.username, item.vaultName].filter(Boolean).join(' · ');
        body.append(title, sub);

        row.append(icon, body);
        row.addEventListener('click', (event) => {
          // ページが script から click() を投げてきても動かさない
          if (!event.isTrusted) return;
          void choose(item, field);
        });
        li.append(row);
        list.append(li);
      }
      menu.append(list);

      const note = document.createElement('div');
      note.className = 'note';
      note.textContent = 'ほかを探すときはツールバーのアイコンから';
      menu.append(note);
    }

    root.append(menu);
    position(menu, field);
    return menu;
  }

  function showNote(text, isError = false) {
    if (!shadow) return;
    const menu = shadow.querySelector('.menu');
    if (!menu) return;
    const list = menu.querySelector('.list');
    if (list) list.remove();
    const notes = menu.querySelectorAll('.note');
    notes.forEach((n) => n.remove());
    const note = document.createElement('div');
    note.className = `note${isError ? ' error' : ''}`;
    note.textContent = text;
    menu.append(note);
  }

  // --- background とのやり取り ----------------------------------------------

  function ask(message) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(message, (response) => {
          if (chrome.runtime.lastError) {
            resolve({ error: chrome.runtime.lastError.message });
            return;
          }
          resolve(response || { error: '応答がありません' });
        });
      } catch (err) {
        resolve({ error: err.message });
      }
    });
  }

  async function loadCandidates() {
    if (candidates && Date.now() - candidatesAt < CACHE_MS) return candidates;
    // どのホストの分を返すかは background が sender から決める。ここからは指定しない。
    const response = await ask({ type: 'inline:candidates' });
    locked = !!response.locked;
    candidates = response.items || [];
    candidatesAt = Date.now();
    return candidates;
  }

  async function choose(item, field) {
    if (busy) return;
    busy = true;
    showNote('取り出しています…');
    const response = await ask({ type: 'inline:fill', vaultId: item.vaultId, itemId: item.id });
    busy = false;

    if (response.error) {
      showNote(response.error, true);
      return;
    }
    const filled = fillNear(field, response);
    if (filled.length === 0) {
      showNote('入力できる欄が見つかりませんでした', true);
      return;
    }
    hideMenu();
  }

  // --- きっかけ -------------------------------------------------------------

  async function onFocus(event) {
    const field = event.target;
    if (!(field instanceof HTMLInputElement)) return;
    if (!isLoginField(field)) return;
    if (dismissedFor === field) return;

    // まず枠だけ出して、候補が来たら描き直す
    await loadCandidates();
    if (document.activeElement !== field) return; // 待っている間に離れていたら出さない
    if (!locked && (!candidates || candidates.length === 0)) return; // 何も無いなら黙っている
    renderMenu(field);
  }

  document.addEventListener('focusin', (event) => {
    if (!event.isTrusted) return;
    void onFocus(event);
  }, true);

  document.addEventListener('focusout', (event) => {
    // メニューの中を押したときに閉じてしまわないよう、少し待つ
    setTimeout(() => {
      if (anchorField && document.activeElement !== anchorField) {
        const menu = shadow && shadow.querySelector('.menu');
        if (menu && !menu.matches(':hover')) hideMenu();
      }
    }, 180);
  }, true);

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && anchorField) {
      dismissedFor = anchorField;
      hideMenu();
    }
  }, true);

  window.addEventListener('scroll', () => {
    if (!anchorField || !shadow) return;
    const menu = shadow.querySelector('.menu');
    if (menu) position(menu, anchorField);
  }, true);

  window.addEventListener('resize', () => {
    if (!anchorField || !shadow) return;
    const menu = shadow.querySelector('.menu');
    if (menu) position(menu, anchorField);
  });

  // ロックしたら、開きっぱなしのメニューも閉じて候補を捨てる
  chrome.runtime.onMessage.addListener((message) => {
    if (message && message.type === 'inline:invalidate') {
      candidates = null;
      candidatesAt = 0;
      hideMenu();
    }
  });
})();
