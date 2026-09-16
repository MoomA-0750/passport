// popup の中身。
//
// 気をつけていること:
//   ・復号した値は表示中の1件だけ変数に持ち、popup を閉じれば消える
//   ・秘密を chrome.storage へ書かない（トークン以外は何も保存しない）
//   ・入力は必ず人の操作から始める。ページを開いただけでは何もしない

import { getSettings, login, logout, getToken, api, ApiError } from './api.js';
import { fillCredentials } from './fill.js';

const views = {
  setup: document.getElementById('view-setup'),
  login: document.getElementById('view-login'),
  list: document.getElementById('view-list')
};

let activeTab = null;
let currentHost = '';

function show(name) {
  for (const [key, el] of Object.entries(views)) el.hidden = key !== name;
  document.getElementById('lock').hidden = name !== 'list';
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

function hostOfUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

// --- 一覧 -------------------------------------------------------------------

function renderItems(items, { searching = false } = {}) {
  const list = document.getElementById('items');
  const empty = document.getElementById('empty');
  list.textContent = '';

  if (!items.length) {
    empty.hidden = false;
    empty.textContent = searching
      ? '見つかりませんでした'
      : 'このサイトに使えるものは見つかりませんでした。上の欄で探すか、金庫に URL を登録してください。';
    return;
  }
  empty.hidden = true;

  for (const item of items) {
    // innerHTML を使わず組み立てる。金庫の中身がそのまま DOM に入る場所なので。
    const li = document.createElement('li');
    li.className = 'item';

    const info = document.createElement('div');
    info.className = 'item-info';

    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = item.title;
    if (item.matchKind === 'subdomain') {
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = 'サブドメイン';
      title.appendChild(badge);
    }

    const sub = document.createElement('div');
    sub.className = 'item-sub';
    sub.textContent = [item.username, item.vaultName].filter(Boolean).join(' · ');

    info.append(title, sub);

    const actions = document.createElement('div');
    actions.className = 'item-actions';

    const fillButton = document.createElement('button');
    fillButton.className = 'button small primary';
    fillButton.type = 'button';
    fillButton.textContent = '入力';
    fillButton.addEventListener('click', () => fillItem(item));

    const copyButton = document.createElement('button');
    copyButton.className = 'button small';
    copyButton.type = 'button';
    copyButton.textContent = 'コピー';
    copyButton.title = 'パスワードをクリップボードへ';
    copyButton.addEventListener('click', () => copyPassword(item));

    actions.append(fillButton, copyButton);

    if (item.secrets && item.secrets.totp) {
      const totpButton = document.createElement('button');
      totpButton.className = 'button small';
      totpButton.type = 'button';
      totpButton.textContent = 'OTP';
      totpButton.title = 'ワンタイムパスワードをコピー';
      totpButton.addEventListener('click', () => copyTotp(item));
      actions.append(totpButton);
    }

    li.append(info, actions);
    list.append(li);
  }
}

async function loadForCurrentSite() {
  document.getElementById('site-host').textContent = currentHost || '（このページでは使えません）';
  showError('list-error', null);
  if (!currentHost) {
    renderItems([]);
    return;
  }
  try {
    const { items } = await api.match(currentHost);
    document.getElementById('site-count').textContent = items.length ? `${items.length}件` : '';
    renderItems(items);
  } catch (err) {
    handleError(err, 'list-error');
  }
}

// --- 入力とコピー -----------------------------------------------------------

async function fillItem(item) {
  if (!activeTab) return;
  try {
    status('取り出しています…');
    const { value: password } = await api.reveal(item.vaultId, item.id, 'password', 'copy');

    let totp = null;
    if (item.secrets && item.secrets.totp) {
      try {
        const result = await api.totp(item.vaultId, item.id);
        totp = result.code;
      } catch {
        // ワンタイムパスワードが取れなくても、ユーザー名とパスワードは入れる
      }
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
    handleError(err, 'list-error');
  }
}

async function copyPassword(item) {
  try {
    const { value } = await api.reveal(item.vaultId, item.id, 'password', 'copy');
    await navigator.clipboard.writeText(value);
    status('パスワードをコピーしました（監査ログに残ります）', 'ok');
  } catch (err) {
    handleError(err, 'list-error');
  }
}

async function copyTotp(item) {
  try {
    const { code, remainingSeconds } = await api.totp(item.vaultId, item.id);
    await navigator.clipboard.writeText(code);
    status(`ワンタイムパスワードをコピーしました（あと ${remainingSeconds} 秒）`, 'ok');
  } catch (err) {
    handleError(err, 'list-error');
  }
}

function handleError(err, errorId) {
  if (err instanceof ApiError && err.status === 401) {
    show('login');
    showError('login-error', 'もう一度ログインしてください');
    return;
  }
  showError(errorId, err.message);
}

// --- 起動 -------------------------------------------------------------------

async function start() {
  const settings = await getSettings();
  document.getElementById('server-label').textContent = settings.serverUrl;

  if (!settings.serverUrl) {
    show('setup');
    return;
  }

  [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentHost = activeTab ? hostOfUrl(activeTab.url) : '';

  const token = await getToken();
  if (!token) {
    show('login');
    document.getElementById('username').focus();
    return;
  }

  show('list');
  await loadForCurrentSite();
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
    show('list');
    await loadForCurrentSite();
  } catch (err) {
    showError('login-error', err.message);
  } finally {
    button.disabled = false;
  }
});

document.getElementById('lock').addEventListener('click', async () => {
  await logout();
  show('login');
  status('ロックしました');
});

document.getElementById('settings').addEventListener('click', () => chrome.runtime.openOptionsPage());
document.getElementById('open-options').addEventListener('click', () => chrome.runtime.openOptionsPage());

let searchTimer = null;
document.getElementById('search').addEventListener('input', (event) => {
  const query = event.target.value.trim();
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(async () => {
    if (!query) {
      await loadForCurrentSite();
      return;
    }
    try {
      const { results } = await api.search(query);
      renderItems(results.filter((r) => r.secrets && r.secrets.password), { searching: true });
    } catch (err) {
      handleError(err, 'list-error');
    }
  }, 250);
});

start().catch((err) => showError('list-error', err.message));
