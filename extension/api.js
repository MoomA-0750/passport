// Passport サーバーとのやり取り。popup と options と background で共有する。
//
// 認証は Authorization: Bearer <トークン>。Cookie は使わない。
// Cookie だと、ログイン中のブラウザで開いた別サイトから金庫の API を叩かれる経路が
// できてしまう（サーバー側は拡張からの呼び出しに CSRF 検証をしないため）。
// Bearer なら、トークンを持っている拡張からしか通らない。
//
// トークンの置き場は chrome.storage.session。ブラウザを閉じると消える。
// local に置くとディスクに残るので、金庫の鍵としては置かない。

const SETTINGS_KEY = 'passportSettings';
const TOKEN_KEY = 'passportToken';

export async function getSettings() {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  return {
    serverUrl: '',
    ...(stored[SETTINGS_KEY] || {})
  };
}

export async function saveSettings(settings) {
  const current = await getSettings();
  await chrome.storage.local.set({ [SETTINGS_KEY]: { ...current, ...settings } });
}

export async function getToken() {
  const stored = await chrome.storage.session.get(TOKEN_KEY);
  const entry = stored[TOKEN_KEY];
  if (!entry) return null;
  if (entry.expiresAt && Date.now() > entry.expiresAt) {
    await clearToken();
    return null;
  }
  return entry.token;
}

export async function setToken(token, expiresInSeconds) {
  await chrome.storage.session.set({
    [TOKEN_KEY]: {
      token,
      expiresAt: expiresInSeconds ? Date.now() + expiresInSeconds * 1000 : null
    }
  });
}

export async function clearToken() {
  await chrome.storage.session.remove(TOKEN_KEY);
}

function normalizeServerUrl(url) {
  const trimmed = String(url || '').trim().replace(/\/+$/, '');
  if (!trimmed) throw new Error('サーバーの URL が設定されていません');
  if (!/^https?:\/\//.test(trimmed)) throw new Error('URL は http:// か https:// から始めてください');
  return trimmed;
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

export async function call(path, { method = 'GET', body = null, auth = true } = {}) {
  const { serverUrl } = await getSettings();
  const base = normalizeServerUrl(serverUrl);

  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (auth) {
    const token = await getToken();
    if (!token) throw new ApiError('ログインしてください', 401);
    headers.Authorization = `Bearer ${token}`;
  }

  let res;
  try {
    res = await fetch(base + path, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      // Cookie は送らない。認証は Bearer だけにする
      credentials: 'omit',
      cache: 'no-store'
    });
  } catch (err) {
    // 証明書の警告を通していない、サーバーが落ちている、権限を許可していない、など
    throw new ApiError(
      `サーバーに接続できませんでした（${base}）。` +
      '自己署名の証明書なら、一度ブラウザでサーバーを開いて警告を通してください。',
      0
    );
  }

  if (res.status === 401) {
    await clearToken();
    throw new ApiError('ログインが切れました', 401);
  }

  let payload = {};
  try {
    payload = await res.json();
  } catch {
    // JSON でない応答
  }
  if (!res.ok) throw new ApiError(payload.error || `失敗しました (${res.status})`, res.status);
  return payload;
}

export async function login(username, password) {
  const result = await call('/api/login', {
    method: 'POST', body: { username, password }, auth: false
  });
  if (!result.token) {
    // サーバー側で拡張が許可されていないと、トークンが返ってこない
    throw new ApiError(
      'サーバーがこの拡張を許可していません。passport.ini の [extension] allowedIds を確認してください',
      403
    );
  }
  await setToken(result.token, result.expiresInSeconds);
  return result.user;
}

export async function logout() {
  try {
    await call('/api/logout', { method: 'POST' });
  } catch {
    // 通らなくてもトークンは捨てる
  }
  await clearToken();
}

export const api = {
  me: () => call('/api/me'),
  match: (host) => call(`/api/match?host=${encodeURIComponent(host)}`),
  search: (query) => call(`/api/search?q=${encodeURIComponent(query)}`),
  reveal: (vaultId, itemId, field, purpose = 'view') =>
    call(`/api/vaults/${vaultId}/items/${itemId}/reveal`, {
      method: 'POST', body: { field, purpose }
    }),
  totp: (vaultId, itemId) =>
    call(`/api/vaults/${vaultId}/items/${itemId}/totp`, { method: 'POST' })
};
