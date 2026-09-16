// service worker。やることは2つ。
//   1. content script（入力欄のそばに出るメニュー）を、許可のあるサイトにだけ登録する
//   2. content script からの問い合わせに答える
//
// 金庫の中身はここに溜めない。service worker は止まったり動いたりするので、
// 秘密の置き場には向かない。必要なときにサーバーへ取りに行く。

import { clearToken, getSettings, saveSettings, api, ApiError } from './api.js';

const INLINE_SCRIPT_ID = 'passport-inline';
const PENDING_KEY = 'passportPendingSave';
// 本人が決めるまでの猶予。過ぎたら捨てる。
const PENDING_TTL_MS = 2 * 60 * 1000;

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
  await clearAllPending();
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

// --- ログインを捉えたときの預かり ---------------------------------------------
//
// ページは送信直後に遷移して消えるので、本人が「保存する」を押すまでの間、
// 捉えた値をどこかに置いておく必要がある。
//
// 置き場は chrome.storage.session。ディスクには残らず、ブラウザを閉じれば消える。
// そのうえで 2分の期限を付け、保存か却下が決まった時点で消す。
// service worker は止まることがあるので、変数ではなくここに置く。

async function putPending(tabId, data) {
  const store = await chrome.storage.session.get(PENDING_KEY);
  const pending = store[PENDING_KEY] || {};
  pending[tabId] = { ...data, at: Date.now() };
  await chrome.storage.session.set({ [PENDING_KEY]: pending });
}

async function takePending(tabId, { remove = false } = {}) {
  const store = await chrome.storage.session.get(PENDING_KEY);
  const pending = store[PENDING_KEY] || {};

  // 期限切れはこの機会に片付ける
  let changed = false;
  for (const [key, value] of Object.entries(pending)) {
    if (Date.now() - value.at > PENDING_TTL_MS) {
      delete pending[key];
      changed = true;
    }
  }

  const entry = pending[tabId] || null;
  if (entry && remove) {
    delete pending[tabId];
    changed = true;
  }
  if (changed) await chrome.storage.session.set({ [PENDING_KEY]: pending });
  return entry;
}

async function clearAllPending() {
  await chrome.storage.session.remove(PENDING_KEY);
}

// 「このサイトでは聞かない」の一覧。秘密ではないので local でよい。
async function getIgnoredHosts() {
  const settings = await getSettings();
  return settings.ignoredHosts || [];
}

async function addIgnoredHost(host) {
  const hosts = await getIgnoredHosts();
  if (!hosts.includes(host)) await saveSettings({ ignoredHosts: [...hosts, host] });
}

// 同じユーザー名の登録を探す。大文字小文字は区別しない
// （MoomA@example.local と mooma@example.local を別物として二重に登録しない）。
function sameUsername(item, username) {
  return String(item.username || '').toLowerCase() === String(username || '').toLowerCase();
}

// このログインが「もう登録済み」かどうかを調べる。
//
//   already   … ユーザー名もパスワードも同じものがある。何も聞かない
//   outdated  … ユーザー名は同じだがパスワードが違う。更新を勧める
//   unknown   … 同じユーザー名が無い。保存を勧める
//
// パスワードの照合はサーバー側でやってもらい、保管してある平文は受け取らない。
async function classifyLogin(host, entry) {
  const { items } = await api.match(host);
  const sameUser = items.filter((item) => sameUsername(item, entry.username));
  if (sameUser.length === 0) return { state: 'unknown', item: null };

  for (const item of sameUser) {
    if (!item.secrets || !item.secrets.password) continue;
    try {
      const { matches } = await api.verify(item.vaultId, item.id, 'password', entry.password);
      if (matches) return { state: 'already', item };
    } catch (err) {
      // 照合できなかったものは「違う」とみなして先へ進む。
      // ここで諦めると、更新の機会まで失う。
      if (err instanceof ApiError && err.status === 401) throw err;
    }
  }
  return { state: 'outdated', item: sameUser[0] };
}

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

    // ログインを捉えた。まだ何も保存しない。預かるだけ。
    if (message.type === 'save:captured') {
      const settings = await getSettings();
      if (settings.saveOffer === false) return { ok: false };
      if ((await getIgnoredHosts()).includes(host)) return { ok: false };
      if (!sender.tab) return { ok: false };

      await putPending(sender.tab.id, {
        host,
        username: String(message.username || '').slice(0, 128),
        password: String(message.password || ''),
        suggestedTitle: String(message.title || '').slice(0, 128) || host
      });
      return { ok: true };
    }

    // 遷移した先（または同じページ）から「預かっているものはある?」
    if (message.type === 'save:pending') {
      if (!sender.tab) return { offer: null };
      const entry = await takePending(sender.tab.id);
      if (!entry) return { offer: null };

      // 捉えたのと同じサイトのときだけ出す。
      // 別のサイトへ遷移した先で、よそのパスワードの保存を勧めない。
      if (entry.host !== host) return { offer: null };

      let vaults = [];
      let classified = null;
      try {
        classified = await classifyLogin(host, entry);
        const vaultList = await api.vaults();
        // 書き込める Vault だけを選べるようにする
        vaults = vaultList.vaults.filter((v) => ['editor', 'owner'].includes(v.role));
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) return { offer: null, locked: true };
        throw err;
      }

      // もう同じものが入っているなら何も聞かない。預かっていた平文もここで捨てる。
      if (classified.state === 'already') {
        await takePending(sender.tab.id, { remove: true });
        return { offer: null, alreadySaved: true };
      }

      const existing = classified.state === 'outdated' ? classified.item : null;
      if (vaults.length === 0 && !existing) return { offer: null };

      return {
        offer: {
          host: entry.host,
          username: entry.username,
          suggestedTitle: entry.suggestedTitle,
          vaults,
          existingItemId: existing ? existing.id : null,
          existingVaultId: existing ? existing.vaultId : null,
          existingTitle: existing ? existing.title : null
        }
      };
    }

    // 本人が決めた
    if (message.type === 'save:decide') {
      if (!sender.tab) return { error: 'タブが分かりません' };

      if (message.action === 'never') {
        await addIgnoredHost(host);
        await takePending(sender.tab.id, { remove: true });
        return { ok: true };
      }
      if (message.action !== 'save') {
        await takePending(sender.tab.id, { remove: true });
        return { ok: true };
      }

      const entry = await takePending(sender.tab.id);
      if (!entry) return { error: '預かっていた内容が期限切れです。もう一度ログインしてください' };
      if (entry.host !== host) return { error: 'このページでは保存できません' };

      let classified;
      try {
        classified = await classifyLogin(host, entry);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) return { error: 'Passport がロックされています' };
        throw err;
      }

      // 決めるまでの間に、ほかの経路で同じものが入ったかもしれない
      if (classified.state === 'already') {
        await takePending(sender.tab.id, { remove: true });
        return { ok: true, alreadySaved: true };
      }
      const existing = classified.state === 'outdated' ? classified.item : null;

      try {
        if (existing) {
          await api.updateItem(existing.vaultId, existing.id, {
            version: existing.version,
            secrets: { password: entry.password }
          });
          await takePending(sender.tab.id, { remove: true });
          return { ok: true, updated: true };
        }

        const vaultId = message.vaultId;
        if (!vaultId) return { error: '保存先が選ばれていません' };
        await api.createItem(vaultId, {
          type: 'login',
          title: String(message.title || entry.suggestedTitle || host).slice(0, 128),
          username: entry.username,
          urls: `https://${host}`,
          secrets: { password: entry.password }
        });
        await takePending(sender.tab.id, { remove: true });
        return { ok: true, updated: false };
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) return { error: 'Passport がロックされています' };
        throw err;
      }
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
    // ロックしたら、預かっている平文も捨てる
    Promise.all([clearAllPending(), notifyAllTabs('locked')])
      .then(() => sendResponse({ ok: true }), (err) => sendResponse({ error: err.message }));
    return true;
  }

  // ログインしたとき。開いているページが持っている「ロックされている」という
  // 覚えを捨てさせる。これが無いと、ページを読み込み直すまで気づかない。
  if (message.type === 'inline:unlocked') {
    notifyAllTabs('unlocked')
      .then(() => sendResponse({ ok: true }), (err) => sendResponse({ error: err.message }));
    return true;
  }

  if (!message.type.startsWith('inline:') && !message.type.startsWith('save:')) return false;
  handleMessage(message, sender).then(sendResponse, (err) => sendResponse({ error: err.message }));
  return true; // 非同期で返す
});

// 開いているタブへ「捨てて」と伝える。
// content script が居ないタブでは届かないので、失敗は無視してよい。
// タブを閉じたら、そのタブの預かりは捨てる
chrome.tabs.onRemoved.addListener(async (tabId) => {
  await takePending(tabId, { remove: true });
});

async function notifyAllTabs(reason) {
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.map((tab) => (
    chrome.tabs.sendMessage(tab.id, { type: 'inline:invalidate', reason }).catch(() => {})
  )));
}
