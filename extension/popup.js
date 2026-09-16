// popup の中身。金庫のメイン画面を、ブラウザ用に削ったもの。
//
//   ・上に検索、下に「このページ」の候補
//   ・検索すると、すべての Vault を横断した結果に切り替わる
//   ・行を選ぶと入力。副ボタンでコピー・OTP・URL を開く
//
// 気をつけていること:
//   ・復号した値はその場で使って捨てる。変数にも DOM にも残さない
//   ・秘密を chrome.storage へ書かない（保存するのはトークンだけ）
//   ・入力は必ず人の操作から始める

import { getSettings, login, logout, getToken, api, ApiError } from './api.js';
import { fillCredentials } from './fill.js';

const views = {
  setup: document.getElementById('view-setup'),
  login: document.getElementById('view-login'),
  main: document.getElementById('view-main')
};

const TYPE_ICONS = { login: '🔑', server: '🖥️', card: '💳', note: '📝', sshkey: '🗝️' };

let activeTab = null;
let currentHost = '';
let currentOriginPattern = null;
let currentScheme = null;

function show(name) {
  for (const [key, el] of Object.entries(views)) el.hidden = key !== name;
  document.getElementById('lock').hidden = name !== 'main';
}

function status(message, kind = '') {
  const el = document.getElementById('status');
  el.textContent = message || '';
  el.className = `status ${kind}`;
  if (message) setTimeout(() => { if (el.textContent === message) el.textContent = ''; }, 4000);
}

function showError(id, message) {
  const el = document.getElementById(id);
  el.textContent = message || '';
  el.hidden = !message;
}

function handleError(err, errorId = 'main-error') {
  if (err instanceof ApiError && err.status === 401) {
    show('login');
    showError('login-error', 'もう一度ログインしてください');
    return;
  }
  showError(errorId, err.message);
}

// --- 行の組み立て -----------------------------------------------------------

// innerHTML は使わない。金庫の中身がそのまま DOM に入る場所なので。
function buildRow(item, { showVault = false } = {}) {
  const li = document.createElement('li');
  li.className = 'item';

  const icon = document.createElement('span');
  icon.className = 'item-icon';
  icon.textContent = TYPE_ICONS[item.type] || '🔑';

  const info = document.createElement('div');
  info.className = 'item-info';

  const title = document.createElement('div');
  title.className = 'item-title';
  title.textContent = item.title;
  if (item.matchKind === 'subdomain') {
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = 'サブドメイン';
    title.append(badge);
  }

  const sub = document.createElement('div');
  sub.className = 'item-sub';
  sub.textContent = [item.username, showVault ? item.vaultName : null].filter(Boolean).join(' · ');

  info.append(title, sub);

  const actions = document.createElement('div');
  actions.className = 'item-actions';

  const canFill = !!(item.secrets && item.secrets.password) && !!activeTab && !!currentHost;
  if (canFill) {
    const fillButton = document.createElement('button');
    fillButton.className = 'button small primary';
    fillButton.type = 'button';
    fillButton.textContent = '入力';
    fillButton.addEventListener('click', () => fillItem(item));
    actions.append(fillButton);
  }

  if (item.secrets && item.secrets.password) {
    const copyButton = document.createElement('button');
    copyButton.className = 'button small';
    copyButton.type = 'button';
    copyButton.textContent = 'コピー';
    copyButton.title = 'パスワードをクリップボードへ';
    copyButton.addEventListener('click', () => copySecret(item, 'password', 'パスワード'));
    actions.append(copyButton);
  }

  if (item.secrets && item.secrets.totp) {
    const totpButton = document.createElement('button');
    totpButton.className = 'button small';
    totpButton.type = 'button';
    totpButton.textContent = 'OTP';
    totpButton.title = 'ワンタイムパスワードをコピー';
    totpButton.addEventListener('click', () => copyTotp(item));
    actions.append(totpButton);
  }

  // SSH 鍵は入力するものではないので、公開鍵のコピーだけ出す
  if (item.type === 'sshkey' && item.sshKey) {
    const pubButton = document.createElement('button');
    pubButton.className = 'button small';
    pubButton.type = 'button';
    pubButton.textContent = '公開鍵';
    pubButton.title = '公開鍵をクリップボードへ';
    pubButton.addEventListener('click', async () => {
      await navigator.clipboard.writeText(item.sshKey.publicKey);
      status('公開鍵をコピーしました', 'ok');
    });
    actions.append(pubButton);
    sub.textContent = [item.sshKey.keyType, item.sshKey.fingerprint].filter(Boolean).join(' ');
  }

  li.append(icon, info, actions);
  return li;
}

function renderList(listId, emptyId, items, { showVault = false, emptyText = '' } = {}) {
  const list = document.getElementById(listId);
  const empty = document.getElementById(emptyId);
  list.textContent = '';

  if (!items.length) {
    empty.hidden = false;
    empty.textContent = emptyText;
    return;
  }
  empty.hidden = true;
  for (const item of items) list.append(buildRow(item, { showVault }));
}

// --- このページ -------------------------------------------------------------

async function loadPage() {
  document.getElementById('site-host').textContent = currentHost || '（このページでは使えません）';
  showError('main-error', null);

  if (!currentHost) {
    renderList('page-items', 'page-empty', [], {
      emptyText: 'このページでは使えません。上の欄から探せます。'
    });
    return;
  }

  try {
    const { items } = await api.match(currentHost, currentScheme);
    renderList('page-items', 'page-empty', items, {
      emptyText: 'このサイトに使えるものはありません。上の欄から探すか、金庫に URL を登録してください。'
    });
  } catch (err) {
    handleError(err);
  }
}

// --- 入力とコピー -----------------------------------------------------------

async function fillItem(item) {
  if (!activeTab) return;
  try {
    status('取り出しています…');
    const { value: password } = await api.reveal(item.vaultId, item.id, 'password', 'fill');

    let totp = null;
    if (item.secrets && item.secrets.totp) {
      try {
        const result = await api.totp(item.vaultId, item.id);
        totp = result.code;
      } catch {
        // ワンタイムパスワードが取れなくても、残りは入れる
      }
    }

    // 取り出している間にタブが別のサイトへ遷移しているかもしれない。
    // 遷移先のフォームへパスワードを入れてしまわないよう、注入の直前に確かめ直す。
    let currentTab;
    try {
      currentTab = await chrome.tabs.get(activeTab.id);
    } catch {
      status('タブが見つかりません', 'warn');
      return;
    }
    if (hostOfUrl(currentTab.url) !== currentHost) {
      status('ページが変わったので入力を取りやめました', 'warn');
      return;
    }

    const [injection] = await chrome.scripting.executeScript({
      target: { tabId: activeTab.id, allFrames: false },
      func: fillCredentials,
      args: [{ username: item.username || '', password, totp }]
    });

    const result = injection && injection.result;
    if (result && result.ok) {
      status(result.message, 'ok');
      // 入れ終わったらすぐ閉じる。画面に秘密を置いたままにしない
      setTimeout(() => window.close(), 900);
    } else {
      status((result && result.message) || '入力できませんでした', 'warn');
    }
  } catch (err) {
    handleError(err);
  }
}

async function copySecret(item, field, label) {
  try {
    const { value } = await api.reveal(item.vaultId, item.id, field, 'copy');
    await navigator.clipboard.writeText(value);
    status(`${label}をコピーしました（監査ログに残ります）`, 'ok');
  } catch (err) {
    handleError(err);
  }
}

async function copyTotp(item) {
  try {
    const { code, remainingSeconds } = await api.totp(item.vaultId, item.id);
    await navigator.clipboard.writeText(code);
    status(`ワンタイムパスワードをコピーしました（あと ${remainingSeconds} 秒）`, 'ok');
  } catch (err) {
    handleError(err);
  }
}

// --- 入力欄のそばのメニュー（許可まわり）------------------------------------

async function refreshInlineState() {
  const offer = document.getElementById('inline-offer');
  const on = document.getElementById('inline-on');
  offer.hidden = true;
  on.hidden = true;

  if (!currentOriginPattern) return;

  const granted = await chrome.permissions.contains({ origins: [currentOriginPattern] });
  if (granted) {
    on.hidden = false;
  } else {
    offer.hidden = false;
  }
}

async function enableInline() {
  if (!currentOriginPattern) return;
  const granted = await chrome.permissions.request({ origins: [currentOriginPattern] });
  if (!granted) {
    status('許可されませんでした', 'warn');
    return;
  }
  // 許可が増えたので、content script を登録し直してもらう
  await chrome.runtime.sendMessage({ type: 'inline:sync' });
  await refreshInlineState();
  status('有効にしました。ページを読み込み直すと使えます', 'ok');
  // 今開いているページにすぐ効かせる
  try {
    await chrome.tabs.reload(activeTab.id);
  } catch {
    // 読み込み直せなくても、次に開いたときには効く
  }
}

// --- 検索 -------------------------------------------------------------------

let searchTimer = null;

async function runSearch(query) {
  const pageSection = document.getElementById('page-section');
  const searchSection = document.getElementById('search-section');
  const clearButton = document.getElementById('clear-search');

  if (!query) {
    pageSection.hidden = false;
    searchSection.hidden = true;
    clearButton.hidden = true;
    return;
  }

  pageSection.hidden = true;
  searchSection.hidden = false;
  clearButton.hidden = false;

  try {
    const { results } = await api.search(query);
    document.getElementById('search-count').textContent = `${results.length}件`;
    renderList('search-items', 'search-empty', results, {
      showVault: true, emptyText: '見つかりませんでした'
    });
  } catch (err) {
    handleError(err);
  }
}

// --- 起動 -------------------------------------------------------------------

function hostOfUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

function originPatternOfUrl(url) {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    return `${parsed.protocol}//${parsed.host}/*`;
  } catch {
    return null;
  }
}

async function start() {
  const settings = await getSettings();
  document.getElementById('server-label').textContent = settings.serverUrl;

  if (!settings.serverUrl) {
    show('setup');
    return;
  }

  [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentHost = activeTab ? hostOfUrl(activeTab.url) : '';
  try {
    currentScheme = activeTab ? new URL(activeTab.url).protocol.replace(/:$/, '') : null;
  } catch {
    currentScheme = null;
  }
  currentOriginPattern = activeTab ? originPatternOfUrl(activeTab.url) : null;

  // 金庫の画面そのものにはメニューを出さないので、勧めない
  if (currentOriginPattern && settings.serverUrl.startsWith(`${new URL(settings.serverUrl).protocol}//`)) {
    try {
      const serverHost = new URL(settings.serverUrl).host;
      if (activeTab && new URL(activeTab.url).host === serverHost) currentOriginPattern = null;
    } catch {
      // 判定できなければそのまま
    }
  }

  const token = await getToken();
  if (!token) {
    show('login');
    document.getElementById('username').focus();
    return;
  }

  show('main');
  await Promise.all([loadPage(), refreshInlineState()]);
}

document.getElementById('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('login-error', null);
  const button = event.target.querySelector('button[type=submit]');
  button.disabled = true;
  try {
    await login(
      document.getElementById('username').value.trim(),
      document.getElementById('password').value
    );
    document.getElementById('password').value = '';
    // 開いているページが「ロックされている」と覚えたままなので、捨ててもらう。
    // これが無いと、ページを読み込み直すまでメニューがロック表示のままになる。
    try {
      await chrome.runtime.sendMessage({ type: 'inline:unlocked' });
    } catch {
      // service worker が寝ていても、次にページを開いたときには直る
    }
    show('main');
    await Promise.all([loadPage(), refreshInlineState()]);
  } catch (err) {
    showError('login-error', err.message);
  } finally {
    button.disabled = false;
  }
});

document.getElementById('lock').addEventListener('click', async () => {
  await logout();
  // 開いているページのメニューにも捨てさせる
  try {
    await chrome.runtime.sendMessage({ type: 'inline:locked' });
  } catch {
    // service worker が居なくても、トークンは消えているので実害はない
  }
  show('login');
  status('ロックしました');
});

document.getElementById('settings').addEventListener('click', () => chrome.runtime.openOptionsPage());
document.getElementById('open-options').addEventListener('click', () => chrome.runtime.openOptionsPage());
document.getElementById('enable-inline').addEventListener('click', enableInline);

document.getElementById('search').addEventListener('input', (event) => {
  const query = event.target.value.trim();
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => runSearch(query), 250);
});

document.getElementById('clear-search').addEventListener('click', () => {
  document.getElementById('search').value = '';
  runSearch('');
});

start().catch((err) => showError('main-error', err.message));
