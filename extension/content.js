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
//   ・メニューは closed な Shadow DOM の中に作る。ただし closed が守るのは
//     「中の要素を JS で掴むこと」だけで、ホスト要素自体はページの普通の div。
//     ページの !important に負けて透明化・移動させられるので、次の3枚で守る:
//       1. ホスト要素の危ない性質を、インラインの !important で毎回押さえ直す
//          （インラインの !important は、ページの !important にも勝つ）
//       2. メニューを開くのは、直前に本物の操作があったときだけ。
//          ページが element.focus() を呼んで出る focusin は isTrusted=true なので、
//          isTrusted だけでは「ページが勝手に開く」を止められない
//       3. 埋める直前に、その座標が本当に自分の行で、目に見える形で出ているかを確かめる
//   ・埋めるのは isTrusted な操作だけ。ページが script から click() を投げても動かない
//   ・勝手に送信しない
//   ・まだ登録の無いサイトでログインされたら「保存しますか」と聞く。
//     捉えた値はここには残さず background へ渡し、本人が決めるまでの間だけ預ける

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
  let lastCaptureKey = '';    // 同じ内容を何度も送らないための目印
  let lastUserGestureAt = 0;  // 本物の操作が最後にあった時刻

  const CACHE_MS = 30 * 1000;
  // 本物の操作からこの時間内に来たフォーカスだけを、利用者の意思とみなす
  const USER_GESTURE_WINDOW_MS = 1000;

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

    /* 「保存しますか」のバー */
    .bar {
      position: fixed;
      top: 12px; right: 12px;
      z-index: 2147483647;
      width: 20rem; max-width: calc(100vw - 24px);
      background: #fff; color: #1f2933;
      border: 1px solid #dee2e6; border-radius: .5rem;
      box-shadow: 0 .5rem 1.5rem rgba(0,0,0,.22);
      font: 13px/1.45 system-ui, -apple-system, "Noto Sans JP", sans-serif;
      overflow: hidden;
    }
    .bar-body { padding: .6rem .7rem; }
    .bar-title { font-weight: 600; margin-bottom: .2rem; }
    .bar-user { color: #6b7680; font-size: .78rem; word-break: break-all; margin-bottom: .5rem; }
    .bar label { display: block; font-size: .72rem; color: #6b7680; margin-bottom: .15rem; }
    .bar input, .bar select {
      width: 100%; box-sizing: border-box; font: inherit; color: inherit;
      padding: .3rem .4rem; margin-bottom: .45rem;
      background: #fff; border: 1px solid #dee2e6; border-radius: .25rem;
    }
    .bar-actions { display: flex; gap: .35rem; flex-wrap: wrap; }
    .bar button {
      font: inherit; padding: .3rem .6rem; border-radius: .25rem; cursor: pointer;
      border: 1px solid #dee2e6; background: transparent; color: inherit;
    }
    .bar button.primary { background: #0d6efd; border-color: #0d6efd; color: #fff; }
    .bar button.link { border-color: transparent; color: #6b7680; padding-left: .2rem; padding-right: .2rem; }
    .bar button:hover { filter: brightness(1.06); }
    .bar-result { padding: .6rem .7rem; }
    @media (prefers-color-scheme: dark) {
      .bar { background: #1b1f24; color: #e6e9ec; border-color: #333b44; }
      .bar input, .bar select { background: #12161a; border-color: #333b44; }
      .bar button { border-color: #333b44; }
      .bar-user, .bar label, .bar button.link { color: #9aa4ad; }
    }
    @media (prefers-color-scheme: dark) {
      .menu { background: #1b1f24; color: #e6e9ec; border-color: #333b44; }
      .row { border-top-color: #2a3139; }
      .row:hover, .row:focus { background: #243040; }
      .sub, .note { color: #9aa4ad; }
      .badge { background: #2a3139; color: #9aa4ad; }
    }
  `;

  // ページが #passport-inline-host に !important を当てて、
  // 透明にしたり別の場所へ動かしたりできないように押さえる性質。
  // インラインの !important は、ページの !important よりも強い。
  const PINNED_STYLES = {
    position: 'static',
    opacity: '1',
    transform: 'none',
    scale: 'none',
    rotate: 'none',
    translate: 'none',
    perspective: 'none',
    filter: 'none',
    'backdrop-filter': 'none',
    'mix-blend-mode': 'normal',
    visibility: 'visible',
    display: 'block',
    'pointer-events': 'auto',
    'clip-path': 'none',
    clip: 'auto',
    mask: 'none',
    contain: 'none',
    'content-visibility': 'visible',
    isolation: 'auto',
    zoom: '1',
    width: 'auto',
    height: 'auto',
    margin: '0',
    padding: '0',
    border: '0',
    overflow: 'visible',
    transition: 'none',
    animation: 'none',
    'will-change': 'auto'
  };

  function pinHostStyles() {
    if (!hostElement) return;
    for (const [property, value] of Object.entries(PINNED_STYLES)) {
      hostElement.style.setProperty(property, value, 'important');
    }
  }

  function ensureShadow() {
    // ページに消された場合は作り直す（消されたまま黙って動かなくならないように）
    if (shadow && hostElement && hostElement.isConnected) {
      pinHostStyles();
      return shadow;
    }
    if (!shadow) {
      hostElement = document.createElement('div');
      hostElement.id = HOST_ELEMENT_ID;
      // closed にして、ページ側の JS から中身を触れないようにする
      shadow = hostElement.attachShadow({ mode: 'closed' });
      const style = document.createElement('style');
      style.textContent = STYLE;
      shadow.append(style);
    }
    pinHostStyles();
    (document.body || document.documentElement).append(hostElement);
    return shadow;
  }

  // 3枚目: 埋める直前に「本当に見えている自分の行を押したのか」を確かめる。
  // ページは祖先（body など）に opacity や filter を掛けることでも隠せるので、
  // ホスト要素の性質を押さえるだけでは足りない。
  function isPresentedHonestly(rowElement, event) {
    if (!hostElement || !hostElement.isConnected || !rowElement) return false;

    // その座標を実際に占めているのが自分か
    if (document.elementFromPoint(event.clientX, event.clientY) !== hostElement) return false;

    // 押された点が、その行の矩形の中にあるか
    const rect = rowElement.getBoundingClientRect();
    if (event.clientX < rect.left || event.clientX > rect.right
      || event.clientY < rect.top || event.clientY > rect.bottom) return false;

    // 潰されていないか（押せる大きさが残っているか）
    if (rect.width < 24 || rect.height < 12) return false;

    // 祖先まで遡って、目に見える形で出ているか
    let node = hostElement;
    let opacity = 1;
    while (node && node.nodeType === 1) {
      const style = window.getComputedStyle(node);
      if (style.visibility === 'hidden' || style.display === 'none') return false;
      if (style.filter !== 'none') return false;
      if (style.backdropFilter && style.backdropFilter !== 'none') return false;
      if (style.mixBlendMode && style.mixBlendMode !== 'normal') return false;
      const value = Number(style.opacity);
      if (Number.isFinite(value)) opacity *= value;
      node = node.parentElement;
    }
    return opacity >= 0.9;
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
          // 透明化・移動・縮小されたメニューを踏まされていないか確かめる
          if (!isPresentedHonestly(row, event)) {
            showNote('この画面では安全に入力できません。ツールバーのアイコンから操作してください', true);
            return;
          }
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
    // ロック中や、取れなかったときの結果は覚えない。
    // 覚えてしまうと、別の画面でログインしても、こちらは
    // キャッシュが切れるまで「ロックされています」と言い続ける。
    const usable = candidates && !locked && Date.now() - candidatesAt < CACHE_MS;
    if (usable) return candidates;

    // どのホストの分を返すかは background が sender から決める。ここからは指定しない。
    const response = await ask({ type: 'inline:candidates' });
    locked = !!response.locked;
    candidates = response.items || [];
    candidatesAt = (locked || response.error) ? 0 : Date.now();
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

  // --- ログインの検知 --------------------------------------------------------

  // 送信されようとしている入力から、ユーザー名とパスワードを拾う。
  // ここで拾った値は変数に残さず、そのまま background へ渡す。
  function captureFrom(scopeElement) {
    const scope = scopeElement || document;
    const inputs = [...scope.querySelectorAll('input')].filter(isVisible);
    const passwords = inputs.filter(isPasswordField).filter((el) => el.value);
    if (passwords.length === 0) return null;

    // パスワード欄が2つ以上あって値が違うなら、新規登録か変更の画面。
    // どちらも「このサイトのログイン」として保存してよいものではないので見送る。
    if (passwords.length > 1) {
      const values = new Set(passwords.map((el) => el.value));
      if (values.size > 1) return null;
    }

    const password = passwords[0].value;
    if (password.length < 4) return null;

    const texts = inputs.filter((el) => ['text', 'email', 'tel', ''].includes(el.type));
    const otpLike = (el) => /otp|totp|2fa|mfa|one.?time|verification|authenticator|ワンタイム|認証コード/.test(hay(el));
    const named = texts.filter((el) => !otpLike(el) && el.value);
    const passwordTop = passwords[0].getBoundingClientRect().top;
    const usernameField = named.find((el) => /user|login|account|email|mail|id\b|ユーザー|メール|アカウント/.test(hay(el)))
      || named.filter((el) => el.getBoundingClientRect().top <= passwordTop).pop()
      || named[0];

    return {
      username: usernameField ? usernameField.value : '',
      password,
      title: (document.title || '').trim().slice(0, 64)
    };
  }

  async function capture(scopeElement) {
    const captured = captureFrom(scopeElement);
    if (!captured) return;

    // 同じ内容を続けて送らない（submit と click の両方が拾ったときなど）
    const key = `${captured.username}\u0000${captured.password.length}`;
    if (key === lastCaptureKey) return;
    lastCaptureKey = key;

    await ask({ type: 'save:captured', ...captured });
    // 遷移しない作りのページもあるので、少し待ってから自分で聞きに行く
    setTimeout(() => { void offerIfPending(); }, 1200);
  }

  document.addEventListener('submit', (event) => {
    if (!event.isTrusted) return;
    void capture(event.target);
  }, true);

  // submit を出さない作りのページ向け。ログインらしいボタンの押下でも拾う。
  document.addEventListener('click', (event) => {
    if (!event.isTrusted) return;
    const button = event.target.closest('button, input[type="submit"], input[type="button"], [role="button"]');
    if (!button) return;
    const text = `${button.textContent || ''} ${button.value || ''} ${button.id} ${button.name}`.toLowerCase();
    const looksLikeSubmit = button.type === 'submit'
      || /log.?in|sign.?in|ログイン|サインイン|認証|送信/.test(text);
    if (!looksLikeSubmit) return;
    void capture(button.form || button.closest('form') || document);
  }, true);

  document.addEventListener('keydown', (event) => {
    if (!event.isTrusted || event.key !== 'Enter') return;
    const field = event.target;
    if (!(field instanceof HTMLInputElement)) return;
    if (!isPasswordField(field) && !isUsernameField(field)) return;
    void capture(field.form || field.closest('form') || document);
  }, true);

  // --- 「保存しますか」のバー -------------------------------------------------

  function hideBar() {
    if (!shadow) return;
    const bar = shadow.querySelector('.bar');
    if (bar) bar.remove();
  }

  function renderBar(offer) {
    const root = ensureShadow();
    hideBar();

    const bar = document.createElement('div');
    bar.className = 'bar';

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
      void decide('dismiss');
    });
    head.append(label, close);

    const body = document.createElement('div');
    body.className = 'bar-body';

    const title = document.createElement('div');
    title.className = 'bar-title';
    title.textContent = offer.existingItemId
      ? 'このサイトの登録を更新しますか？'
      : 'このサイトのログイン情報を保存しますか？';

    const user = document.createElement('div');
    user.className = 'bar-user';
    user.textContent = `${offer.host}${offer.username ? ` / ${offer.username}` : ''}`;

    body.append(title, user);

    let titleInput = null;
    let vaultSelect = null;

    if (offer.existingItemId) {
      const note = document.createElement('div');
      note.className = 'bar-user';
      note.textContent = `既に「${offer.existingTitle}」として登録があります。パスワードを新しいものに差し替えます。`;
      body.append(note);
    } else {
      const titleLabel = document.createElement('label');
      titleLabel.textContent = 'タイトル';
      titleInput = document.createElement('input');
      titleInput.type = 'text';
      titleInput.value = offer.suggestedTitle || offer.host;
      titleInput.maxLength = 128;

      const vaultLabel = document.createElement('label');
      vaultLabel.textContent = '保存先';
      vaultSelect = document.createElement('select');
      for (const vault of offer.vaults) {
        const option = document.createElement('option');
        option.value = vault.id;
        option.textContent = `${vault.icon || ''} ${vault.name}`.trim();
        vaultSelect.append(option);
      }

      body.append(titleLabel, titleInput, vaultLabel, vaultSelect);
    }

    const actions = document.createElement('div');
    actions.className = 'bar-actions';

    const saveButton = document.createElement('button');
    saveButton.className = 'primary';
    saveButton.type = 'button';
    saveButton.textContent = offer.existingItemId ? '更新する' : '保存する';
    saveButton.addEventListener('click', (event) => {
      if (!event.isTrusted) return;
      if (!isPresentedHonestly(saveButton, event)) {
        showBarResult('この画面では安全に保存できません', true);
        return;
      }
      saveButton.disabled = true;
      void decide('save', {
        vaultId: vaultSelect ? vaultSelect.value : null,
        title: titleInput ? titleInput.value.trim() : null
      });
    });

    const laterButton = document.createElement('button');
    laterButton.type = 'button';
    laterButton.textContent = '今回はしない';
    laterButton.addEventListener('click', (event) => {
      if (!event.isTrusted) return;
      void decide('dismiss');
    });

    const neverButton = document.createElement('button');
    neverButton.className = 'link';
    neverButton.type = 'button';
    neverButton.textContent = 'このサイトでは聞かない';
    neverButton.addEventListener('click', (event) => {
      if (!event.isTrusted) return;
      void decide('never');
    });

    actions.append(saveButton, laterButton, neverButton);
    body.append(actions);
    bar.append(head, body);
    root.append(bar);
    return bar;
  }

  function showBarResult(text, isError = false) {
    if (!shadow) return;
    const bar = shadow.querySelector('.bar');
    if (!bar) return;
    const body = bar.querySelector('.bar-body');
    if (body) body.remove();
    const result = document.createElement('div');
    result.className = `bar-result${isError ? ' error' : ''}`;
    result.textContent = text;
    result.style.color = isError ? '#d6336c' : '';
    bar.append(result);
    // 失敗したときも閉じられるようにする（閉じるボタンは head に残っている）。
    // 何も操作されなければ、少し長めに置いてから自分で消える。
    setTimeout(hideBar, isError ? 8000 : 2500);
  }

  async function decide(action, extra = {}) {
    const response = await ask({ type: 'save:decide', action, ...extra });
    if (action !== 'save') {
      hideBar();
      return;
    }
    if (response.error) {
      showBarResult(response.error, true);
      return;
    }
    // 保存したら、このサイトの候補は取り直す
    candidates = null;
    candidatesAt = 0;
    if (response.alreadySaved) {
      showBarResult('すでに同じものが保存されていました');
      return;
    }
    showBarResult(response.updated ? '更新しました' : '保存しました');
  }

  async function offerIfPending() {
    const response = await ask({ type: 'save:pending' });
    if (!response || !response.offer) return;
    renderBar(response.offer);
  }

  // --- きっかけ -------------------------------------------------------------

  async function onFocus(event) {
    const field = event.target;
    if (!(field instanceof HTMLInputElement)) return;
    if (!isLoginField(field)) return;
    if (dismissedFor === field) return;

    // ページが element.focus() を呼んで発生する focusin も isTrusted は true になる。
    // 「利用者が自分で入力欄へ移った」ことを確かめるには、直前に本物の操作
    // （クリック・キー入力・タッチ）があったかを見るしかない。
    if (Date.now() - lastUserGestureAt > USER_GESTURE_WINDOW_MS) return;

    // まず枠だけ出して、候補が来たら描き直す
    await loadCandidates();
    if (document.activeElement !== field) return; // 待っている間に離れていたら出さない
    if (!locked && (!candidates || candidates.length === 0)) return; // 何も無いなら黙っている
    renderMenu(field);
  }

  for (const type of ['pointerdown', 'mousedown', 'keydown', 'touchstart']) {
    document.addEventListener(type, (event) => {
      if (event.isTrusted) lastUserGestureAt = Date.now();
    }, true);
  }

  document.addEventListener('focusin', (event) => {
    if (!event.isTrusted) return;
    void onFocus(event);
  }, true);

  // 既にフォーカスのある欄をもう一度押したときは focusin が出ない。
  // 利用者から見れば「押したのに出ない」なので、クリックからも開けるようにする。
  document.addEventListener('click', (event) => {
    if (!event.isTrusted) return;
    const field = event.target;
    if (!(field instanceof HTMLInputElement)) return;
    if (anchorField === field && shadow && shadow.querySelector('.menu')) return; // もう出ている
    void onFocus({ target: field });
  }, true);

  document.addEventListener('focusout', (event) => {
    // Escape で閉じたのは「今この欄にいる間は出さないで」という意味にする。
    // 一度離れて戻ってきたら、また出してよい（そうしないと、その欄では
    // 読み込み直すまで二度とメニューが出なくなる）。
    if (event.target === dismissedFor) dismissedFor = null;

    // メニューの中を押したときに閉じてしまわないよう、少し待つ
    setTimeout(() => {
      if (anchorField && document.activeElement !== anchorField) {
        const menu = shadow && shadow.querySelector('.menu');
        if (menu && !menu.matches(':hover')) hideMenu();
      }
    }, 180);
  }, true);

  document.addEventListener('keydown', (event) => {
    if (!event.isTrusted) return; // ページが合成 Escape で黙らせるのを防ぐ
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

  // 金庫の状態が変わったと知らされたら、持っている候補を捨てる。
  //   ・ロックされた → メニューもバーも閉じる
  //   ・ログインされた → 開いているメニューはその場で描き直す
  //     （利用者から見ると「ログインしたのに、まだロックと言われる」を無くすため）
  chrome.runtime.onMessage.addListener((message) => {
    if (!message || message.type !== 'inline:invalidate') return;
    candidates = null;
    candidatesAt = 0;
    locked = false;

    if (message.reason === 'unlocked') {
      const field = anchorField;
      hideBar();
      if (!field) return;
      void (async () => {
        await loadCandidates();
        // 描き直す間に別の欄へ移っていたら、そちらに任せる
        if (anchorField !== field && document.activeElement !== field) return;
        if (!locked && (!candidates || candidates.length === 0)) {
          hideMenu();
          return;
        }
        renderMenu(field);
      })();
      return;
    }

    hideMenu();
    hideBar();
  });

  // 送信のあと遷移した先で出す。読み込み直後に、預かっているものがないか聞く。
  setTimeout(() => { void offerIfPending(); }, 600);
})();
