// 設定画面。サーバーの URL を決めて、そこへ通信する許可をもらう。
//
// host_permissions を manifest に固定で書かず、ここで都度もらう形にしている。
// 「この拡張はすべてのサイトのデータを読み取れます」と出さずに済ませるため。

import { getSettings, saveSettings } from './api.js';

const input = document.getElementById('server-url');
const message = document.getElementById('message');

document.getElementById('extension-id').textContent = chrome.runtime.id;

function show(text, kind = 'hint') {
  message.textContent = text;
  message.className = kind === 'error' ? 'error' : 'hint';
  message.hidden = !text;
}

getSettings().then((settings) => {
  input.value = settings.serverUrl || '';
});

// --- 入力欄のそばのメニュー ---------------------------------------------------

const ALL_SITES = '<all_urls>';
const inlineToggle = document.getElementById('inline-all');
const inlineStatus = document.getElementById('inline-status');

async function refreshInline() {
  const granted = await chrome.permissions.contains({ origins: [ALL_SITES] });
  inlineToggle.checked = granted;

  const all = await chrome.permissions.getAll();
  const sites = (all.origins || []).filter((o) => o !== ALL_SITES);
  if (granted) {
    inlineStatus.textContent = 'すべてのサイトで出ます。';
  } else if (sites.length) {
    inlineStatus.textContent = `個別に許可したサイト: ${sites.join(' , ')}`;
  } else {
    inlineStatus.textContent = 'いまは、どのサイトでも出ません。';
  }
}

inlineToggle.addEventListener('change', async () => {
  if (inlineToggle.checked) {
    const granted = await chrome.permissions.request({ origins: [ALL_SITES] });
    if (!granted) inlineToggle.checked = false;
  } else {
    await chrome.permissions.remove({ origins: [ALL_SITES] });
  }
  // 権限が変わったので、content script を登録し直してもらう
  try {
    await chrome.runtime.sendMessage({ type: 'inline:sync' });
  } catch {
    // service worker が寝ていても、permissions の変化で起きて同期される
  }
  await refreshInline();
});

refreshInline();

document.getElementById('settings-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  show('');

  const raw = input.value.trim().replace(/\/+$/, '');
  let url;
  try {
    url = new URL(raw);
  } catch {
    show('URL として読めません', 'error');
    return;
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    show('http:// か https:// を使ってください', 'error');
    return;
  }
  if (url.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(url.hostname)) {
    show('http は localhost のときだけです。社内サーバーには https を使ってください', 'error');
    return;
  }

  // このサーバーへ通信する許可をもらう（ここで Chrome のダイアログが出る）
  const pattern = `${url.protocol}//${url.host}/*`;
  const granted = await chrome.permissions.request({ origins: [pattern] });
  if (!granted) {
    show('許可されなかったので、このサーバーへは接続できません', 'error');
    return;
  }

  await saveSettings({ serverUrl: raw });

  // 金庫の画面自体にはメニューを出さないので、登録し直してもらう
  try {
    await chrome.runtime.sendMessage({ type: 'inline:sync' });
  } catch {
    // 寝ていても次の機会に同期される
  }

  // 実際に届くか確かめる。ログイン前でも /login は開くので、それで到達性を見る。
  try {
    const res = await fetch(`${raw}/login`, { method: 'GET', credentials: 'omit', cache: 'no-store' });
    if (res.ok) {
      show('保存しました。接続できています。ツールバーのアイコンからログインしてください。');
    } else {
      show(`保存しました。ただしサーバーが ${res.status} を返しています`, 'error');
    }
  } catch {
    show(
      '保存しました。ただし接続できませんでした。' +
      'サーバーが動いているか、自己署名の証明書なら一度タブで開いて警告を通したかを確認してください。',
      'error'
    );
  }
});
