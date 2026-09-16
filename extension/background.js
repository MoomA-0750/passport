// service worker。やることは2つ。
//   1. content script（入力欄のそばに出るメニュー）を、許可のあるサイトにだけ登録する
//   2. content script からの問い合わせに答える
//
// 金庫の中身はここに溜めない。service worker は止まったり動いたりするので、
// 秘密の置き場には向かない。必要なときにサーバーへ取りに行く。

import { clearToken, getSettings, api, ApiError } from './api.js';

const INLINE_SCRIPT_ID = 'passport-inline';

// --- content script の登録 ---------------------------------------------------

// Passport 自身の画面にはメニューを出さない（金庫の画面で金庫のメニューが出ても邪魔なだけ）
async function serverOriginPattern() {
  const { serverUrl } = await getSettings();
  if (!serverUrl) return null;
  try {
    const url = new URL(serverUrl);
    return `${url.protocol}//${url.host}/*`;
  } catch {
    return null;
  }
}

// 許可されている origin を調べて、そこにだけ content script を登録し直す。
// 権限が増減したときと、起動時に呼ぶ。
async function syncInlineScripts() {
  const granted = await chrome.permissions.getAll();
  const serverPattern = await serverOriginPattern();
  const matches = (granted.origins || []).filter((pattern) => pattern !== serverPattern);

  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [INLINE_SCRIPT_ID] })
    .catch(() => []);

  if (matches.length === 0) {
    if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: [INLINE_SCRIPT_ID] });
    return { registered: false, matches };
  }

  const definition = {
    id: INLINE_SCRIPT_ID,
    js: ['content.js'],
    matches,
    runAt: 'document_idle',
    // ログインフォームが iframe の中にあることは珍しくない。
    // どのサイトの候補を出すかは各フレーム自身の origin で決まるので、入れても広がらない。
    allFrames: true,
    persistAcrossSessions: true
  };

  if (existing.length) {
    await chrome.scripting.updateContentScripts([definition]);
  } else {
    await chrome.scripting.registerContentScripts([definition]);
  }
  return { registered: true, matches };
}

chrome.runtime.onStartup.addListener(async () => {
  // ブラウザを立ち上げ直したらロックされた状態から始める
  await clearToken();
  await syncInlineScripts();
});

chrome.runtime.onInstalled.addListener(async (details) => {
  await syncInlineScripts();
  if (details.reason !== 'install') return;
  const { serverUrl } = await getSettings();
  if (!serverUrl) chrome.runtime.openOptionsPage();
});

chrome.permissions.onAdded.addListener(() => { void syncInlineScripts(); });
chrome.permissions.onRemoved.addListener(() => { void syncInlineScripts(); });

// --- content script からの問い合わせ -----------------------------------------

// どのサイトの候補を返すかは、content script の言い分ではなく sender から決める。
// ページ側が細工をしても、別のサイトの資格情報は引き出せない。
function hostOfSender(sender) {
  const source = sender.origin || sender.url || '';
  try {
    return new URL(source).hostname;
  } catch {
    return '';
  }
}

async function handleMessage(message, sender) {
  // 自分の拡張の中から来たものだけを相手にする
  if (!sender || sender.id !== chrome.runtime.id) {
    return { error: '受け付けられません' };
  }
  const host = hostOfSender(sender);
  if (!host) return { error: 'このページでは使えません' };

  try {
    if (message.type === 'inline:candidates') {
      const { items } = await api.match(host);
      return {
        locked: false,
        // 秘密は含まれていないが、拡張の画面で使う分だけに絞って渡す
        items: items.map((item) => ({
          id: item.id,
          vaultId: item.vaultId,
          vaultName: item.vaultName,
          title: item.title,
          username: item.username,
          type: item.type,
          matchKind: item.matchKind,
          hasTotp: !!(item.secrets && item.secrets.totp)
        }))
      };
    }

    if (message.type === 'inline:fill') {
      // 念のため、要求されたアイテムがこのホストの候補に入っているかを確かめる。
      // content script が別のアイテムIDを指してきても、関係ないものは渡さない。
      const { items } = await api.match(host);
      const target = items.find((i) => i.id === message.itemId && i.vaultId === message.vaultId);
      if (!target) return { error: 'このページでは使えないアイテムです' };

      const { value: password } = await api.reveal(target.vaultId, target.id, 'password', 'copy');
      let totp = null;
      if (target.secrets && target.secrets.totp) {
        try {
          const result = await api.totp(target.vaultId, target.id);
          totp = result.code;
        } catch {
          // ワンタイムパスワードが取れなくても、残りは入れる
        }
      }
      return { username: target.username || '', password, totp };
    }

    return { error: '知らない要求です' };
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      return { locked: true, items: [], error: 'Passport がロックされています' };
    }
    if (err instanceof ApiError && err.status === 0) {
      return { error: 'Passport サーバーに接続できません' };
    }
    return { error: err.message };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== 'string') return false;

  // popup から「登録し直して」と言われたとき
  if (message.type === 'inline:sync') {
    syncInlineScripts().then((result) => sendResponse(result), (err) => sendResponse({ error: err.message }));
    return true;
  }

  // ロックしたとき。開いているページのメニューを閉じさせ、持っている候補を捨てさせる
  if (message.type === 'inline:locked') {
    notifyAllTabs().then(() => sendResponse({ ok: true }), (err) => sendResponse({ error: err.message }));
    return true;
  }

  if (!message.type.startsWith('inline:')) return false;
  handleMessage(message, sender).then(sendResponse, (err) => sendResponse({ error: err.message }));
  return true; // 非同期で返す
});

// 開いているタブへ「捨てて」と伝える。
// content script が居ないタブでは届かないので、失敗は無視してよい。
async function notifyAllTabs() {
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.map((tab) => (
    chrome.tabs.sendMessage(tab.id, { type: 'inline:invalidate' }).catch(() => {})
  )));
}
