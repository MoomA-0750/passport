// service worker。やることは少ない。
//
// 金庫の中身はここで持たない。popup が必要なときにサーバーへ取りに行く。
// service worker は止まったり動いたりするので、秘密の置き場には向かない。

import { clearToken, getSettings } from './api.js';

// ブラウザを立ち上げ直したらロックされた状態から始める。
// chrome.storage.session はブラウザを閉じると消えるが、念のため明示的に捨てる。
chrome.runtime.onStartup.addListener(() => {
  clearToken();
});

// 入れた直後・更新直後は設定画面へ案内する
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason !== 'install') return;
  const { serverUrl } = await getSettings();
  if (!serverUrl) chrome.runtime.openOptionsPage();
});
