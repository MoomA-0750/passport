'use strict';
// 金庫のメイン画面。
//
// 守っているつもりのこと:
//   ・復号した秘密は表示中の1件だけ変数に持ち、画面を離れる・ロックする・切り替えるときに捨てる
//   ・秘密を localStorage / sessionStorage に入れない
//   ・DOM への差し込みは escapeHtml を通す

const {
  apiFetch, escapeHtml, showError, toast, formatDateTime, formatRelative,
  generatePassword, passwordStrength, bindStrengthMeter, copyToClipboard
} = window.KBUtil;

const state = {
  vaults: [],
  vaultId: null,
  items: [],
  itemId: null,
  searchQuery: '',
  members: null,
  // 表示中のアイテムで復号済みの値。画面を離れるときに捨てる。
  revealed: {},
  totpTimer: null,
  generatorTarget: null
};

const modals = {};

function modal(id) {
  if (!modals[id]) modals[id] = new bootstrap.Modal(document.getElementById(id));
  return modals[id];
}

// --- 秘密の後片付け ---------------------------------------------------------

function clearRevealed() {
  for (const key of Object.keys(state.revealed)) delete state.revealed[key];
  if (state.totpTimer) {
    clearInterval(state.totpTimer);
    state.totpTimer = null;
  }
}

// --- 読み込み ---------------------------------------------------------------

async function loadVaults() {
  const { vaults } = await apiFetch('/api/vaults');
  state.vaults = vaults;
  if (!state.vaultId || !vaults.some((v) => v.id === state.vaultId)) {
    state.vaultId = vaults.length ? vaults[0].id : null;
  }
  renderVaults();
}

async function loadItems() {
  clearRevealed();
  state.itemId = null;
  renderDetail(null);

  if (state.searchQuery) {
    const { results } = await apiFetch(`/api/search?q=${encodeURIComponent(state.searchQuery)}`);
    state.items = results;
    renderItems({ searching: true });
    return;
  }
  if (!state.vaultId) {
    state.items = [];
    renderItems({});
    return;
  }
  const { items } = await apiFetch(`/api/vaults/${state.vaultId}/items`);
  state.items = items;
  renderItems({});
}

function currentVault() {
  return state.vaults.find((v) => v.id === state.vaultId) || null;
}

function canEdit() {
  const vault = currentVault();
  return !!vault && (vault.role === 'editor' || vault.role === 'owner');
}

// --- 描画: Vault ------------------------------------------------------------

function renderVaults() {
  const list = document.getElementById('vault-list');
  if (!state.vaults.length) {
    list.innerHTML = '<li class="px-3 py-2 text-muted small">Vault がありません。＋ で作ってください</li>';
    return;
  }
  list.innerHTML = state.vaults.map((vault) => `
    <li>
      <button class="vault-item ${vault.id === state.vaultId && !state.searchQuery ? 'active' : ''}"
              type="button" data-vault-id="${escapeHtml(vault.id)}">
        <span class="vault-icon">${escapeHtml(vault.icon)}</span>
        <span class="vault-body">
          <span class="vault-name">${escapeHtml(vault.name)}</span>
          <span class="vault-meta">${vault.itemCount}件・${escapeHtml(vault.role)}${vault.viaGroup ? '（グループ）' : ''}${vault.memberCount > 1 ? `・${vault.memberCount}人` : ''}${vault.groupCount ? `・👥${vault.groupCount}` : ''}</span>
        </span>
      </button>
    </li>
  `).join('');
}

// --- 描画: アイテム一覧 -----------------------------------------------------

const TYPE_ICONS = { login: '🔑', server: '🖥️', card: '💳', note: '📝', sshkey: '🗝️' };

function renderItems({ searching = false }) {
  const vault = currentVault();
  const title = document.getElementById('list-title');
  const subtitle = document.getElementById('list-subtitle');

  if (searching) {
    title.textContent = `「${state.searchQuery}」の検索結果`;
    subtitle.textContent = `${state.items.length}件・自分が入っている Vault を横断`;
  } else if (vault) {
    title.textContent = `${vault.icon} ${vault.name}`;
    subtitle.textContent = vault.description || `${state.items.length}件・自分の権限は ${vault.role}`;
  } else {
    title.textContent = 'Vault がありません';
    subtitle.textContent = '';
  }

  document.getElementById('btn-new-item').disabled = searching || !canEdit();
  document.getElementById('btn-members').disabled = searching || !vault;
  document.getElementById('btn-trash').disabled = searching || !canEdit();

  const list = document.getElementById('item-list');
  if (!state.items.length) {
    list.innerHTML = `<li class="p-4 text-center text-muted small">${
      searching ? '見つかりませんでした' : 'まだアイテムがありません'
    }</li>`;
    return;
  }

  list.innerHTML = state.items.map((item) => `
    <li>
      <button class="item-row ${item.id === state.itemId ? 'active' : ''}" type="button"
              data-item-id="${escapeHtml(item.id)}" data-item-vault="${escapeHtml(item.vaultId)}">
        <span class="item-icon">${TYPE_ICONS[item.type] || '🔑'}</span>
        <span class="item-body">
          <span class="item-title">
            ${item.favorite ? '<span class="item-fav">★</span>' : ''}${escapeHtml(item.title)}
          </span>
          <span class="item-sub">
            ${escapeHtml(
              item.type === 'sshkey' && item.sshKey
                ? `${item.sshKey.keyType} ${item.sshKey.fingerprint}`
                : (item.username || (item.urls && item.urls[0]) || '')
            )}
            ${item.vaultName ? `<span class="badge bg-light text-dark ms-1">${escapeHtml(item.vaultName)}</span>` : ''}
          </span>
        </span>
      </button>
    </li>
  `).join('');
}

// --- 描画: 詳細 -------------------------------------------------------------

function secretRow(field, label, item, { monospace = true } = {}) {
  const record = item.secrets[field];
  if (!record) return '';
  const revealedValue = state.revealed[field];
  const shown = revealedValue !== undefined;
  return `
    <div class="detail-field" data-field="${escapeHtml(field)}">
      <div class="detail-label">${escapeHtml(label)}</div>
      <div class="detail-value ${monospace ? 'font-monospace' : ''} ${shown ? '' : 'masked'}">${
        shown ? escapeHtml(revealedValue).replace(/\n/g, '<br>') : '••••••••••••'
      }</div>
      <div class="detail-actions">
        <button class="btn btn-sm btn-outline-secondary" type="button"
                data-action="toggle-secret" data-field="${escapeHtml(field)}">${shown ? '隠す' : '表示'}</button>
        <button class="btn btn-sm btn-outline-secondary" type="button"
                data-action="copy-secret" data-field="${escapeHtml(field)}">コピー</button>
        ${field === 'privateKey'
          ? '<button class="btn btn-sm btn-outline-secondary" type="button" data-action="download-key">保存</button>'
          : ''}
      </div>
      ${record.updatedAt ? `<div class="detail-hint">最終更新 ${escapeHtml(formatDateTime(record.updatedAt))}</div>` : ''}
    </div>
    ${historyBlock(field, item)}
  `;
}

// 上書き・削除する前の値。取り出すと監査ログに残る。
function historyBlock(field, item) {
  const list = (item.secretHistory || {})[field] || [];
  if (!list.length) return '';
  const rows = list.map((entry) => {
    const key = `history:${field}:${entry.index}`;
    const shown = state.revealed[key] !== undefined;
    return `
      <li class="history-row">
        <span class="history-when">${escapeHtml(formatDateTime(entry.replacedAt))}
          ${entry.reason === 'deleted' ? '<span class="badge bg-secondary ms-1">削除</span>' : ''}</span>
        <span class="history-value font-monospace ${shown ? '' : 'masked'}">${
          shown ? escapeHtml(state.revealed[key]) : '••••••••'}</span>
        <span class="history-actions">
          <button class="btn btn-sm btn-link p-0" type="button" data-action="toggle-history"
                  data-field="${escapeHtml(field)}" data-index="${entry.index}">${shown ? '隠す' : '表示'}</button>
          <button class="btn btn-sm btn-link p-0 ms-2" type="button" data-action="copy-history"
                  data-field="${escapeHtml(field)}" data-index="${entry.index}">コピー</button>
        </span>
      </li>`;
  }).join('');
  return `
    <details class="history-block">
      <summary class="small text-muted">過去の値（${list.length}件）</summary>
      <ul class="list-unstyled mb-0">${rows}</ul>
    </details>
  `;
}

// SSH 鍵の公開側。公開鍵は秘密ではないので、復号も監査ログも要らずそのまま出せる。
function sshDetail(item) {
  const ssh = item.sshKey;
  return `
    <div class="detail-field">
      <div class="detail-label">SSH 鍵</div>
      <div class="detail-value detail-value-inline">
        <span class="detail-badges"><span class="badge bg-dark">${escapeHtml(ssh.keyType)}</span><span class="badge bg-secondary">${ssh.bits} bit</span>${ssh.hasPrivateKey
          ? (ssh.privateKeyEncrypted
            ? '<span class="badge bg-warning text-dark">パスフレーズ付き</span>'
            : '<span class="badge bg-success">パスフレーズなし</span>')
          : '<span class="badge bg-light text-dark">公開鍵のみ</span>'}</span>
        <div class="font-monospace small mt-2">${escapeHtml(ssh.fingerprint)}</div>${ssh.comment ? `<div class="small text-muted">${escapeHtml(ssh.comment)}</div>` : ''}
      </div>
      <div class="detail-actions">
        <button class="btn btn-sm btn-outline-secondary" type="button"
                data-action="copy-plain" data-value="${escapeHtml(ssh.fingerprint)}">FP をコピー</button>
      </div>
    </div>

    <div class="detail-field">
      <div class="detail-label">公開鍵</div>
      <div class="detail-value detail-value-inline font-monospace small">${escapeHtml(ssh.publicKey)}</div>
      <div class="detail-actions">
        <button class="btn btn-sm btn-outline-secondary" type="button"
                data-action="copy-plain" data-value="${escapeHtml(ssh.publicKey)}">コピー</button>
        <button class="btn btn-sm btn-outline-secondary" type="button"
                data-action="copy-authorized-key">authorized_keys 用</button>
      </div>
      <div class="detail-hint">公開鍵は秘密ではないので、伏せずにそのまま出しています</div>
    </div>
  `;
}

function renderDetail(item) {
  const empty = document.getElementById('detail-empty');
  const content = document.getElementById('detail-content');

  if (!item) {
    empty.classList.remove('d-none');
    content.classList.add('d-none');
    content.innerHTML = '';
    return;
  }
  empty.classList.add('d-none');
  content.classList.remove('d-none');

  const vault = state.vaults.find((v) => v.id === item.vaultId);
  const editable = vault && (vault.role === 'editor' || vault.role === 'owner');

  const urlsHtml = (item.urls || []).map((url) => {
    const safe = /^https?:\/\//i.test(url);
    return safe
      // rel=noreferrer は、遷移先に Passport の URL を渡さないため
      ? `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(url)}</a>`
      : escapeHtml(url);
  }).join('<br>');

  content.innerHTML = `
    <div class="detail-header">
      <div class="detail-title">
        <span class="detail-type">${TYPE_ICONS[item.type] || '🔑'}</span>
        <h2 class="h5 mb-0">${escapeHtml(item.title)}</h2>
      </div>
      <div class="btn-group btn-group-sm">
        <button class="btn btn-outline-secondary" type="button" data-action="edit-item"
                ${editable ? '' : 'disabled'}>編集</button>
        <button class="btn btn-outline-danger" type="button" data-action="delete-item"
                ${editable ? '' : 'disabled'}>削除</button>
      </div>
    </div>

    ${item.username ? `
      <div class="detail-field">
        <div class="detail-label">ユーザー名</div>
        <div class="detail-value font-monospace">${escapeHtml(item.username)}</div>
        <div class="detail-actions">
          <button class="btn btn-sm btn-outline-secondary" type="button"
                  data-action="copy-plain" data-value="${escapeHtml(item.username)}">コピー</button>
        </div>
      </div>` : ''}

    ${item.sshKey ? sshDetail(item) : ''}

    ${secretRow('password', 'パスワード', item)}

    ${item.secrets.totp ? `
      <div class="detail-field" data-field="totp">
        <div class="detail-label">ワンタイムパスワード</div>
        <div class="detail-value font-monospace" id="totp-value">— — —</div>
        <div class="detail-actions">
          <button class="btn btn-sm btn-outline-secondary" type="button" data-action="show-totp">出す</button>
          <button class="btn btn-sm btn-outline-secondary" type="button" data-action="copy-totp">コピー</button>
        </div>
        <div class="detail-hint" id="totp-countdown"></div>
      </div>` : ''}

    ${urlsHtml ? `
      <div class="detail-field">
        <div class="detail-label">URL・ホスト名</div>
        <div class="detail-value">${urlsHtml}</div>
      </div>` : ''}

    ${secretRow('privateKey', '秘密鍵', item)}
    ${secretRow('passphrase', '秘密鍵のパスフレーズ', item)}

    ${secretRow('note', 'セキュアメモ', item, { monospace: false })}

    ${(item.tags || []).length ? `
      <div class="detail-field">
        <div class="detail-label">タグ</div>
        <div class="detail-value">${item.tags.map((t) => `<span class="badge bg-secondary me-1">${escapeHtml(t)}</span>`).join('')}</div>
      </div>` : ''}

    <div class="detail-foot text-muted small">
      ${vault ? `Vault: ${escapeHtml(vault.icon)} ${escapeHtml(vault.name)}<br>` : ''}
      作成 ${escapeHtml(formatDateTime(item.createdAt))}
      / 更新 ${escapeHtml(formatDateTime(item.updatedAt))}（${escapeHtml(formatRelative(item.updatedAt))}）
      ${item.passwordUpdatedAt ? `<br>パスワードの最終変更 ${escapeHtml(formatRelative(item.passwordUpdatedAt))}` : ''}
      ${item.rotationDays ? `<br>パスワードを変える周期 ${item.rotationDays}日` : ''}
      ${item.expiresAt ? `<br>有効期限 ${escapeHtml(item.expiresAt)}` : ''}
    </div>
  `;
}

// --- 秘密の取り出し ---------------------------------------------------------

async function reveal(field, purpose) {
  const item = state.items.find((i) => i.id === state.itemId);
  if (!item) throw new Error('アイテムが選ばれていません');
  const { value } = await apiFetch(`/api/vaults/${item.vaultId}/items/${item.id}/reveal`, {
    method: 'POST',
    body: { field, purpose }
  });
  return value;
}

async function selectItem(vaultId, itemId) {
  clearRevealed();
  state.itemId = itemId;
  renderItems({ searching: !!state.searchQuery });
  const { item } = await apiFetch(`/api/vaults/${vaultId}/items/${itemId}`);
  renderDetail(item);
}

// --- TOTP -------------------------------------------------------------------

// コードの取得は最小限にして、残り時間はブラウザ側で数える。
// 毎秒サーバーへ取りに行くと、監査ログが「秘密の閲覧」で埋まってしまうため。
// 自動で引き直すのは1回だけ（合計で最大2周期）。それ以降は「出す」に戻す。
const TOTP_AUTO_REFRESH_LIMIT = 1;

async function showTotp() {
  const item = state.items.find((i) => i.id === state.itemId);
  if (!item) return;

  if (state.totpTimer) {
    clearInterval(state.totpTimer);
    state.totpTimer = null;
  }

  let refreshes = 0;
  let remaining = 0;

  const stop = (message) => {
    clearInterval(state.totpTimer);
    state.totpTimer = null;
    delete state.revealed.totpCode;
    const valueEl = document.getElementById('totp-value');
    const countEl = document.getElementById('totp-countdown');
    if (valueEl) valueEl.textContent = '— — —';
    if (countEl) countEl.textContent = message || '';
  };

  const fetchCode = async () => {
    const result = await apiFetch(`/api/vaults/${item.vaultId}/items/${item.id}/totp`, { method: 'POST' });
    state.revealed.totpCode = result.code;
    remaining = result.remainingSeconds;
    const valueEl = document.getElementById('totp-value');
    if (!valueEl) return false;
    // 3桁ずつ区切って読みやすくする
    valueEl.textContent = result.code.replace(/(\d{3})(?=\d)/g, '$1 ');
    return true;
  };

  try {
    if (!await fetchCode()) return;
  } catch (err) {
    toast(err.message, 'danger');
    return;
  }

  state.totpTimer = setInterval(async () => {
    const valueEl = document.getElementById('totp-value');
    const countEl = document.getElementById('totp-countdown');
    if (!valueEl) {
      // 別のアイテムに移った
      clearInterval(state.totpTimer);
      state.totpTimer = null;
      return;
    }
    remaining -= 1;
    if (remaining > 0) {
      if (countEl) countEl.textContent = `あと ${remaining} 秒`;
      return;
    }
    if (refreshes >= TOTP_AUTO_REFRESH_LIMIT) {
      stop('期限切れです。もう一度「出す」を押してください');
      return;
    }
    refreshes += 1;
    try {
      if (!await fetchCode()) {
        clearInterval(state.totpTimer);
        state.totpTimer = null;
      }
    } catch (err) {
      toast(err.message, 'danger');
      stop('');
    }
  }, 1000);
}

// --- アイテムの作成・編集 ---------------------------------------------------

let editingItem = null;

function openItemModal(item) {
  editingItem = item || null;
  showError('item-error', null);
  document.getElementById('item-modal-title').textContent = item ? 'アイテムを編集' : 'アイテムを追加';
  document.getElementById('item-type').value = item ? item.type : 'login';
  document.getElementById('item-title').value = item ? item.title : '';
  document.getElementById('item-username').value = item ? item.username : '';
  document.getElementById('item-urls').value = item ? (item.urls || []).join(' ') : '';
  document.getElementById('item-tags').value = item ? (item.tags || []).join(', ') : '';
  document.getElementById('item-rotation').value = item && item.rotationDays ? String(item.rotationDays) : '';
  document.getElementById('item-expires').value = item && item.expiresAt ? item.expiresAt : '';
  document.getElementById('item-favorite').checked = item ? item.favorite : false;

  // 既存の秘密は初期値に入れない（開いただけで復号しないため）。
  // 空のまま保存すれば、その秘密は変更されない。
  const password = document.getElementById('item-password');
  const totp = document.getElementById('item-totp');
  const note = document.getElementById('item-note');
  password.value = '';
  totp.value = '';
  note.value = '';
  password.type = 'password';

  const hint = document.getElementById('item-strength-text');
  if (item && item.secrets.password) {
    hint.textContent = 'すでにパスワードがあります。空のままにすると変更しません';
  } else {
    hint.textContent = '空のままにすると変更しません';
  }
  document.getElementById('item-strength-bar').style.width = '0%';

  totp.placeholder = item && item.secrets.totp
    ? '設定済み。変えるときだけ入力してください'
    : 'Base32 のシークレット、または otpauth:// から始まる文字列';

  // SSH 鍵の欄。既存の秘密鍵は入れない（開いただけで復号しないため）
  const privateKey = document.getElementById('item-privatekey');
  const passphrase = document.getElementById('item-passphrase');
  const publicKey = document.getElementById('item-publickey');
  const comment = document.getElementById('item-comment');
  privateKey.value = '';
  passphrase.value = '';
  publicKey.value = item && item.sshKey ? item.sshKey.publicKey : '';
  comment.value = item && item.sshKey ? item.sshKey.comment : '';
  privateKey.placeholder = item && item.secrets.privateKey
    ? '登録済み。差し替えるときだけ貼ってください'
    : '-----BEGIN OPENSSH PRIVATE KEY----- から始まる中身を貼る（PEM 形式も可）';
  showSshPreview(item && item.sshKey ? item.sshKey : null);
  applyTypeVisibility();
  note.placeholder = item && item.secrets.note
    ? '設定済み。変えるときだけ入力してください（消すには「－」と1文字だけ入れて保存）'
    : '手順、接続条件、注意点など。暗号化されます';

  modal('item-modal').show();
}

// 種別によって使わない欄を隠す。SSH 鍵にパスワードや TOTP を出しても混乱するだけなので。
function applyTypeVisibility() {
  const type = document.getElementById('item-type').value;
  const groups = {
    password: type !== 'sshkey',
    totp: type === 'login' || type === 'server',
    ssh: type === 'sshkey',
    note: true
  };
  for (const [name, visible] of Object.entries(groups)) {
    const el = document.querySelector(`[data-field-group="${name}"]`);
    if (el) el.classList.toggle('d-none', !visible);
  }
}

function showSshPreview(info) {
  const box = document.getElementById('ssh-preview');
  if (!info) {
    box.classList.add('d-none');
    box.textContent = '';
    return;
  }
  box.classList.remove('d-none');
  box.innerHTML = `
    <strong>${escapeHtml(info.keyType)}</strong> ${info.bits} bit
    ${info.encrypted || info.privateKeyEncrypted ? '<span class="badge bg-warning text-dark ms-1">パスフレーズ付き</span>' : ''}
    <div class="font-monospace mt-1">${escapeHtml(info.fingerprint)}</div>
  `;
}

// 貼られた鍵をサーバーに読ませて、公開鍵とフィンガープリントを埋める。
// 保存する前に「貼り間違っていないか」を見せるため。
async function inspectSshInput() {
  const privateKey = document.getElementById('item-privatekey').value.trim();
  const publicKeyField = document.getElementById('item-publickey');
  const passphrase = document.getElementById('item-passphrase').value;
  if (!privateKey && !publicKeyField.value.trim()) {
    showSshPreview(null);
    return;
  }
  try {
    const { info } = await apiFetch('/api/ssh/inspect', {
      method: 'POST',
      body: privateKey ? { privateKey, passphrase } : { publicKey: publicKeyField.value.trim() }
    });
    if (privateKey && info.publicKey) publicKeyField.value = info.publicKey;
    if (info.comment && !document.getElementById('item-comment').value) {
      document.getElementById('item-comment').value = info.comment;
    }
    showSshPreview(info);
    showError('item-error', null);
  } catch (err) {
    showSshPreview(null);
    showError('item-error', err.message);
  }
}

async function generateSshKey() {
  const type = document.getElementById('ssh-gen-type').value;
  const comment = document.getElementById('item-comment').value.trim();
  const existing = document.getElementById('item-privatekey').value.trim();
  if (existing && !window.confirm('入力済みの秘密鍵を上書きします。よろしいですか？')) return;
  try {
    const { key } = await apiFetch('/api/ssh/generate', { method: 'POST', body: { type, comment } });
    document.getElementById('item-privatekey').value = key.privateKey;
    document.getElementById('item-publickey').value = key.publicKey;
    if (!document.getElementById('item-comment').value) {
      document.getElementById('item-comment').value = key.comment;
    }
    if (!document.getElementById('item-title').value) {
      document.getElementById('item-title').value = `${key.keyType} ${key.comment || ''}`.trim();
    }
    document.getElementById('item-passphrase').value = '';
    showSshPreview(key);
    toast('鍵を作りました。保存するまでは保管されていません', 'success');
  } catch (err) {
    showError('item-error', err.message);
  }
}

// 秘密鍵をファイルとして保存する。ssh で使うにはファイルが要るため。
function downloadPrivateKey(item, contents) {
  const safeTitle = (item.title || 'id_key').replace(/[^\w.-]+/g, '_').slice(0, 48);
  const keyType = (item.sshKey && item.sshKey.keyType) || '';
  const name = keyType.includes('ed25519') ? `id_ed25519_${safeTitle}`
    : keyType.includes('rsa') ? `id_rsa_${safeTitle}`
      : safeTitle;
  const blob = new Blob([contents.endsWith('\n') ? contents : `${contents}\n`], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // 秘密鍵を指す URL を残さない
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast(`${name} として保存しました。chmod 600 を忘れずに`, 'success');
}

async function submitItem(event) {
  event.preventDefault();
  showError('item-error', null);

  const type = document.getElementById('item-type').value;
  const secrets = {};
  const password = document.getElementById('item-password').value;
  const totpSecret = document.getElementById('item-totp').value.trim();
  const note = document.getElementById('item-note').value;
  if (password) secrets.password = password;
  if (totpSecret) secrets.totp = totpSecret;
  if (note) secrets.note = note === '－' ? null : note; // 全角マイナス1文字で削除

  if (type === 'sshkey') {
    const privateKey = document.getElementById('item-privatekey').value.trim();
    const passphrase = document.getElementById('item-passphrase').value;
    if (privateKey) secrets.privateKey = privateKey;
    if (passphrase) secrets.passphrase = passphrase;
  }

  const payload = {
    type,
    title: document.getElementById('item-title').value,
    username: document.getElementById('item-username').value,
    urls: document.getElementById('item-urls').value,
    tags: document.getElementById('item-tags').value,
    favorite: document.getElementById('item-favorite').checked,
    rotationDays: document.getElementById('item-rotation').value || null,
    expiresAt: document.getElementById('item-expires').value || null,
    secrets
  };

  if (type === 'sshkey') {
    payload.publicKey = document.getElementById('item-publickey').value.trim();
    payload.comment = document.getElementById('item-comment').value.trim();
  }

  const button = event.target.querySelector('button[type=submit]');
  button.disabled = true;
  try {
    if (editingItem) {
      payload.version = editingItem.version;
      await apiFetch(`/api/vaults/${editingItem.vaultId}/items/${editingItem.id}`, { method: 'PUT', body: payload });
      toast('保存しました', 'success');
      modal('item-modal').hide();
      await loadVaults();
      await loadItems();
      refreshCheckupBadge();
      await selectItem(editingItem.vaultId, editingItem.id);
    } else {
      const { item } = await apiFetch(`/api/vaults/${state.vaultId}/items`, { method: 'POST', body: payload });
      toast('追加しました', 'success');
      modal('item-modal').hide();
      await loadVaults();
      await loadItems();
      refreshCheckupBadge();
      await selectItem(item.vaultId, item.id);
    }
  } catch (err) {
    if (err.status === 409 && editingItem) {
      // 誰かが先に保存していた。以前は version を更新しないまま同じ 409 を返し続け、
      // モーダルを閉じて開き直すしかなかった。最新の版を取り直し、入力はそのまま残す。
      try {
        const { item: latest } = await apiFetch(`/api/vaults/${editingItem.vaultId}/items/${editingItem.id}`);
        editingItem = latest;
        showError('item-error',
          'ほかの人が先に保存していました。最新の内容に合わせたので、入力を確かめてもう一度保存してください');
      } catch {
        showError('item-error', err.message);
      }
    } else {
      showError('item-error', err.message);
    }
  } finally {
    button.disabled = false;
  }
}

// --- Vault の作成 -----------------------------------------------------------

async function submitVault(event) {
  event.preventDefault();
  showError('vault-error', null);
  const button = event.target.querySelector('button[type=submit]');
  button.disabled = true;
  try {
    const { vault } = await apiFetch('/api/vaults', {
      method: 'POST',
      body: {
        name: document.getElementById('vault-name').value,
        icon: document.getElementById('vault-icon').value,
        description: document.getElementById('vault-description').value
      }
    });
    modal('vault-modal').hide();
    document.getElementById('vault-form').reset();
    document.getElementById('vault-icon').value = '🔐';
    state.vaultId = vault.id;
    state.searchQuery = '';
    document.getElementById('search-input').value = '';
    await loadVaults();
    await loadItems();
    toast('Vault を作りました', 'success');
  } catch (err) {
    showError('vault-error', err.message);
  } finally {
    button.disabled = false;
  }
}

// --- 共有（メンバー管理） ---------------------------------------------------

const ROLE_LABELS = {
  viewer: 'viewer（見るだけ）',
  editor: 'editor（追加・編集できる）',
  owner: 'owner（共有も管理できる）'
};

// グループに付けられるのは viewer / editor だけ（owner は人にだけ。lib/vaults.js の冒頭を参照）
const GROUP_ROLE_LABELS = { viewer: ROLE_LABELS.viewer, editor: ROLE_LABELS.editor };

async function openMembers() {
  const vault = currentVault();
  if (!vault) return;
  showError('members-error', null);
  document.getElementById('members-vault-name').textContent = `${vault.icon} ${vault.name}`;
  modal('members-modal').show();
  await renderMembers();
}

async function renderMembers() {
  const vault = currentVault();
  const data = await apiFetch(`/api/vaults/${vault.id}/members`);
  state.members = data;
  const isOwner = data.myRole === 'owner';

  document.getElementById('members-tbody').innerHTML = data.members.map((m) => `
    <tr data-user-id="${escapeHtml(m.userId)}">
      <td>
        ${escapeHtml(m.displayName)}
        <span class="text-muted small">@${escapeHtml(m.username)}</span>
        ${m.viaBreakGlass ? '<span class="badge bg-warning text-dark ms-1" title="管理者の緊急アクセスで追加">緊急</span>' : ''}
      </td>
      <td>
        ${isOwner ? `
          <select class="form-select form-select-sm" data-action="change-role">
            ${Object.entries(ROLE_LABELS).map(([value, label]) =>
              `<option value="${value}" ${m.role === value ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('')}
          </select>` : escapeHtml(m.role)}
      </td>
      <td class="text-end">
        ${isOwner ? '<button class="btn btn-sm btn-outline-danger" type="button" data-action="remove-member">外す</button>' : ''}
      </td>
    </tr>
  `).join('');

  document.getElementById('member-groups-tbody').innerHTML = data.groups.length ? data.groups.map((g) => `
    <tr data-group-id="${escapeHtml(g.groupId)}">
      <td>
        👥 ${escapeHtml(g.name)} <span class="text-muted small">${g.memberCount}人</span>
        ${g.members && g.members.length ? `<div class="text-muted small">${g.members.map((m) =>
          `${escapeHtml(m.displayName)} @${escapeHtml(m.username)}`).join('、')}</div>` : ''}
      </td>
      <td style="width:10rem">
        ${isOwner ? `
          <select class="form-select form-select-sm" data-action="change-group-role">
            ${Object.entries(GROUP_ROLE_LABELS).map(([value, label]) =>
              `<option value="${value}" ${g.role === value ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('')}
          </select>` : escapeHtml(g.role)}
      </td>
      <td class="text-end" style="width:5rem">
        ${isOwner ? '<button class="btn btn-sm btn-outline-danger" type="button" data-action="remove-member-group">外す</button>' : ''}
      </td>
    </tr>
  `).join('') : '<tr><td class="text-muted small">グループでの共有はありません</td></tr>';

  const groupAddArea = document.getElementById('member-groups-add-area');
  if (isOwner && data.groupCandidates.length) {
    groupAddArea.classList.remove('d-none');
    document.getElementById('member-group').innerHTML = data.groupCandidates.map((g) =>
      `<option value="${escapeHtml(g.id)}">${escapeHtml(g.name)}（${g.memberCount}人）</option>`).join('');
  } else {
    groupAddArea.classList.add('d-none');
  }

  const viaGroups = (data.mySources || []).filter((s) => s.type === 'group');
  document.getElementById('my-role-sources').textContent = viaGroups.length
    ? `あなたはグループ経由でも入っています（${viaGroups.map((s) => {
      const g = data.groups.find((x) => x.groupId === s.groupId);
      return `${g ? g.name : '?'}: ${s.role}`;
    }).join('、')}）`
    : '';

  const addArea = document.getElementById('members-add-area');
  if (isOwner && data.candidates.length) {
    addArea.classList.remove('d-none');
    document.getElementById('member-user').innerHTML = data.candidates.map((u) =>
      `<option value="${escapeHtml(u.id)}">${escapeHtml(u.displayName)} (@${escapeHtml(u.username)})</option>`).join('');
  } else {
    addArea.classList.add('d-none');
  }
}

// --- 点検 -------------------------------------------------------------------

const WEAK_REASON_LABELS = { short: '短い', simple: '単純', common: 'よくある語' };
const UNREADABLE_LABELS = { rollback: '古い世代に巻き戻されている', tampered: '復号できない', vault_key: 'Vault の鍵を開けられない' };

function checkupRef(ref, extra = '') {
  const clickable = ref.itemId
    ? `<a href="#" data-action="goto-item" data-vault-id="${escapeHtml(ref.vaultId)}" data-item-id="${escapeHtml(ref.itemId)}">${escapeHtml(ref.title)}</a>`
    : escapeHtml(ref.title);
  return `<li>${clickable}
    <span class="text-muted small">${escapeHtml(ref.vaultName)}${ref.username ? ` / ${escapeHtml(ref.username)}` : ''}</span>
    ${extra}</li>`;
}

function describeDue(d) {
  const what = d.kind === 'rotation' ? '変える時期' : '有効期限';
  const when = d.overdue ? `${-d.daysLeft}日過ぎています` : (d.daysLeft === 0 ? '今日まで' : `あと${d.daysLeft}日`);
  return `<span class="badge bg-${d.overdue ? 'danger' : 'warning text-dark'} ms-1">${what}: ${when}</span>`;
}

async function refreshCheckupBadge() {
  try {
    const { overdue, soon } = await apiFetch('/api/checkup/reminders');
    const badge = document.getElementById('checkup-badge');
    const total = overdue + soon;
    badge.hidden = total === 0;
    badge.textContent = String(total);
    badge.className = `badge rounded-pill ms-1 ${overdue ? 'bg-danger' : 'bg-warning text-dark'}`;
    badge.title = `期限切れ ${overdue}件 / 30日以内 ${soon}件`;
  } catch {
    // バッジが出ないだけ。ほかの操作は止めない
  }
}

async function openCheckup() {
  showError('checkup-error', null);
  modal('checkup-modal').show();
  const { items } = await apiFetch('/api/checkup/reminders');
  document.getElementById('checkup-due').innerHTML = items.length
    ? `<ul class="mb-0">${items.map((d) => checkupRef(d, describeDue(d))).join('')}</ul>`
    : '<p class="text-muted small mb-0">ありません</p>';
}

async function runCheckup() {
  showError('checkup-error', null);
  document.getElementById('checkup-status').textContent = '調べています…';
  const r = await apiFetch('/api/checkup/run', { method: 'POST' });
  document.getElementById('checkup-status').textContent = `${r.examined}件を調べました（${formatDateTime(r.checkedAt)}）`;
  const section = (title, body, empty) => `
    <h6 class="mt-3">${title}</h6>
    ${body || `<p class="text-muted small mb-0">${empty}</p>`}`;
  document.getElementById('checkup-result').innerHTML = [
    section(`使い回し（${r.reused.length}組）`, r.reused.length ? r.reused.map((group) => `
      <div class="border rounded p-2 mb-2"><div class="small text-muted mb-1">同じパスワードの ${group.length} 件</div>
      <ul class="mb-0">${group.map((ref) => checkupRef(ref)).join('')}</ul></div>`).join('') : '', 'ありません'),
    section(`弱い（${r.weak.length}件）`, r.weak.length ? `<ul>${r.weak.map((ref) => checkupRef(ref,
      ref.reasons.map((x) => `<span class="badge bg-warning text-dark ms-1">${escapeHtml(WEAK_REASON_LABELS[x] || x)}</span>`).join(''))).join('')}</ul>` : '', 'ありません'),
    section(`古い（周期を決めていないもので、1年以上変えていない: ${r.old.length}件）`, r.old.length
      ? `<ul>${r.old.map((ref) => checkupRef(ref, `<span class="badge bg-secondary ms-1">${ref.ageDays}日</span>`)).join('')}</ul>` : '', 'ありません'),
    r.unreadable.length ? section(`読めない（${r.unreadable.length}件）`, `<ul>${r.unreadable.map((ref) => checkupRef(ref,
      `<span class="badge bg-danger ms-1">${escapeHtml(UNREADABLE_LABELS[ref.reason] || ref.reason)}</span>`)).join('')}</ul>`, '') : ''
  ].join('');
}


// --- 自動化トークン -----------------------------------------------------------

function tokenRows(list, { admin = false } = {}) {
  return list.length ? list.map((t) => `
    <tr data-token-id="${escapeHtml(t.id)}">
      <td>${escapeHtml(t.name)}</td>
      <td>${t.vaults.map((v) => escapeHtml(v.name)).join('、')}</td>
      <td class="text-nowrap">${escapeHtml(t.createdBy)}<div class="text-muted">${escapeHtml(formatDateTime(t.createdAt))}</div></td>
      <td class="text-nowrap">${escapeHtml(formatDateTime(t.expiresAt))}</td>
      <td class="text-nowrap">${t.lastUsedAt ? `${escapeHtml(formatDateTime(t.lastUsedAt))}<div class="text-muted font-monospace">${escapeHtml(t.lastUsedIp || '')}</div>` : '<span class="text-muted">未使用</span>'}</td>
      <td><span class="badge bg-${t.status === 'active' ? 'success' : 'secondary'}">${escapeHtml(t.statusLabel)}</span></td>
      <td class="text-end">${t.revokedAt ? '' : '<button class="btn btn-sm btn-outline-danger" type="button" data-action="revoke-token">失効</button>'}</td>
    </tr>`).join('') : `<tr><td colspan="7" class="text-center text-muted py-3">${admin ? 'トークンはありません' : 'まだありません'}</td></tr>`;
}

async function renderTokens() {
  const { tokens } = await apiFetch('/api/tokens');
  document.getElementById('tokens-tbody').innerHTML = tokenRows(tokens);
}

async function openTokens() {
  showError('tokens-error', null);
  document.getElementById('token-issued').classList.add('d-none');
  document.getElementById('token-value').value = '';
  document.getElementById('token-form').reset();
  const owned = state.vaults.filter((v) => v.role === 'owner');
  document.getElementById('token-vaults').innerHTML = owned.length ? owned.map((v) => `
    <div class="form-check">
      <input class="form-check-input" type="checkbox" value="${escapeHtml(v.id)}" id="token-vault-${escapeHtml(v.id)}">
      <label class="form-check-label" for="token-vault-${escapeHtml(v.id)}">${escapeHtml(v.icon)} ${escapeHtml(v.name)}</label>
    </div>`).join('') : '<span class="text-muted">owner の Vault がありません</span>';
  modal('tokens-modal').show();
  await renderTokens();
}

// --- ログイン中の端末 / 自分の履歴 ------------------------------------------

const SESSION_KIND_LABELS = { web: '🖥 画面', extension: '🧩 Chrome 拡張', cli: '⌨ CLI' };

// User-Agent から、見分けるのに足りるだけの短い名前を作る（厳密でなくてよい）
function describeUserAgent(ua) {
  if (!ua) return '';
  const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox'
    : /Safari\//.test(ua) ? 'Safari' : /node|undici/i.test(ua) ? 'Node' : '';
  const osName = /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android'
    : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : '';
  return [browser, osName].filter(Boolean).join(' / ');
}

async function renderSessions() {
  const { sessions } = await apiFetch('/api/me/sessions');
  document.getElementById('sessions-tbody').innerHTML = sessions.map((s) => `
    <tr data-handle="${escapeHtml(s.handle)}">
      <td>
        ${escapeHtml(SESSION_KIND_LABELS[s.kind] || s.kind)}
        ${s.current ? '<span class="badge bg-success ms-1">この端末</span>' : ''}
        <div class="text-muted" title="${escapeHtml(s.userAgent || '')}">${escapeHtml(describeUserAgent(s.userAgent))}</div>
      </td>
      <td class="text-nowrap">${escapeHtml(formatDateTime(s.createdAt))}</td>
      <td class="text-nowrap">${escapeHtml(formatRelative(s.lastSeenAt) || formatDateTime(s.lastSeenAt))}</td>
      <td class="font-monospace">${escapeHtml(s.lastIp || s.ip || '')}${s.ip && s.lastIp && s.ip !== s.lastIp
        ? `<div class="text-muted">ログイン時 ${escapeHtml(s.ip)}</div>` : ''}</td>
      <td class="text-end">
        <button class="btn btn-sm btn-outline-danger" type="button" data-action="revoke-session">${s.current ? 'ログアウト' : '切る'}</button>
      </td>
    </tr>
  `).join('');
}

let activityEntries = [];
const RELATION_LABELS = { self: '自分', account: 'アカウント', vault: 'owner の Vault' };

async function renderActivity() {
  const { entries } = await apiFetch('/api/me/activity?limit=300');
  activityEntries = entries;
  drawActivity();
}

function drawActivity() {
  const active = document.querySelector('#activity-filter .active');
  const relation = active ? active.dataset.relation : '';
  const rows = activityEntries.filter((e) => !relation || e.relation === relation);
  document.getElementById('activity-tbody').innerHTML = rows.length ? rows.map((e) => `
    <tr>
      <td class="text-nowrap text-muted">${escapeHtml(formatDateTime(e.at))}</td>
      <td>
        ${escapeHtml(e.eventLabel)}
        ${e.result && e.result !== 'ok' ? `<span class="badge bg-warning text-dark ms-1">${escapeHtml(e.result)}</span>` : ''}
        ${e.field ? `<span class="badge bg-light text-dark ms-1">${escapeHtml(e.field)}</span>` : ''}
        <span class="badge bg-light text-muted border ms-1">${escapeHtml(RELATION_LABELS[e.relation] || '')}</span>
      </td>
      <td>${escapeHtml(e.actorName || '—')}${e.ip ? `<div class="text-muted font-monospace">${escapeHtml(e.ip)}</div>` : ''}</td>
      <td>${escapeHtml([e.vaultName, e.itemTitle].filter(Boolean).join(' / '))}</td>
      <td>${escapeHtml(e.note || '')}</td>
    </tr>
  `).join('') : '<tr><td colspan="5" class="text-center text-muted py-4">記録がありません</td></tr>';
}

// --- ゴミ箱 -----------------------------------------------------------------

async function openTrash() {
  const vault = currentVault();
  if (!vault) return;
  showError('trash-error', null);
  document.getElementById('trash-vault-name').textContent = `${vault.icon} ${vault.name}`;
  modal('trash-modal').show();
  await renderTrash();
}

async function renderTrash() {
  const vault = currentVault();
  const list = document.getElementById('trash-list');
  try {
    const { items: trashed } = await apiFetch(`/api/vaults/${vault.id}/trash`);
    if (!trashed.length) {
      list.innerHTML = '<li class="text-muted small">ゴミ箱は空です</li>';
      return;
    }
    const isOwner = vault.role === 'owner';
    list.innerHTML = trashed.map((item) => `
      <li class="trash-row" data-item-id="${escapeHtml(item.id)}">
        <span class="trash-title">${TYPE_ICONS[item.type] || '🔑'} ${escapeHtml(item.title)}
          <span class="text-muted small ms-1">${escapeHtml(item.username || '')}</span></span>
        <span class="trash-when text-muted small">${escapeHtml(formatDateTime(item.deletedAt))}に削除</span>
        <span class="trash-actions">
          <button class="btn btn-sm btn-outline-primary" type="button" data-action="restore-item">戻す</button>
          ${isOwner ? '<button class="btn btn-sm btn-outline-danger ms-1" type="button" data-action="purge-item">完全に削除</button>' : ''}
        </span>
      </li>
    `).join('');
  } catch (err) {
    showError('trash-error', err.message);
  }
}

// --- パスワード生成器 -------------------------------------------------------

function regenerate() {
  const password = generatePassword({
    length: Number(document.getElementById('gen-length').value),
    upper: document.getElementById('gen-upper').checked,
    lower: document.getElementById('gen-lower').checked,
    digit: document.getElementById('gen-digit').checked,
    symbol: document.getElementById('gen-symbol').checked,
    ambiguous: document.getElementById('gen-ambiguous').checked
  });
  document.getElementById('gen-output').value = password;
}

// --- 無操作ロック -----------------------------------------------------------

let idleTimer = null;

function lockScreen() {
  clearRevealed();
  // 表示されている秘密を DOM から消す
  const content = document.getElementById('detail-content');
  if (content) content.innerHTML = '';
  document.getElementById('detail-empty').classList.remove('d-none');
  state.itemId = null;
  renderItems({ searching: !!state.searchQuery });

  for (const id of Object.keys(modals)) modals[id].hide();
  document.getElementById('lock-overlay').classList.remove('d-none');
  document.getElementById('unlock-password').focus();
}

function resetIdleTimer() {
  if (idleTimer) clearTimeout(idleTimer);
  const minutes = KB.data.idleLockMinutes || 15;
  if (minutes <= 0) return;
  idleTimer = setTimeout(lockScreen, minutes * 60 * 1000);
}

async function unlock(event) {
  event.preventDefault();
  showError('unlock-error', null);
  const password = document.getElementById('unlock-password').value;
  try {
    // 本人確認のため、いまのユーザー名でログインし直す。新しいセッションに差し替わる。
    const result = await apiFetch('/api/login', {
      method: 'POST',
      body: { username: KB.data.user.username, password }
    });
    KB.csrfToken = result.csrfToken;
    document.getElementById('unlock-password').value = '';
    document.getElementById('lock-overlay').classList.add('d-none');
    resetIdleTimer();
    await loadVaults();
    await loadItems();
  } catch (err) {
    showError('unlock-error', err.message);
    document.getElementById('unlock-password').value = '';
  }
}

// --- 自分のパスワード変更 ---------------------------------------------------

async function submitPasswordChange(event) {
  event.preventDefault();
  showError('pw-error', null);
  const currentPassword = document.getElementById('pw-current').value;
  const newPassword = document.getElementById('pw-new').value;
  const confirm = document.getElementById('pw-confirm').value;
  if (newPassword !== confirm) {
    showError('pw-error', '新しいパスワードが一致しません');
    return;
  }
  try {
    await apiFetch('/api/me/password', { method: 'POST', body: { currentPassword, newPassword } });
    toast('変更しました。もう一度ログインしてください', 'success');
    setTimeout(() => { window.location.href = '/login'; }, 1200);
  } catch (err) {
    showError('pw-error', err.message);
  }
}

// --- イベントの配線 ---------------------------------------------------------

function wire() {
  document.getElementById('nav-username').textContent = KB.data.user.displayName || KB.data.user.username;
  if (KB.data.user.role === 'admin') {
    document.getElementById('nav-admin-item').classList.remove('d-none');
    document.getElementById('nav-admin-link').classList.remove('d-none');
  }

  // Vault の切り替え
  document.getElementById('vault-list').addEventListener('click', async (event) => {
    const button = event.target.closest('[data-vault-id]');
    if (!button) return;
    state.vaultId = button.dataset.vaultId;
    state.searchQuery = '';
    document.getElementById('search-input').value = '';
    renderVaults();
    await loadItems();
  });

  // アイテムの選択
  document.getElementById('item-list').addEventListener('click', async (event) => {
    const button = event.target.closest('[data-item-id]');
    if (!button) return;
    try {
      await selectItem(button.dataset.itemVault, button.dataset.itemId);
    } catch (err) {
      toast(err.message, 'danger');
    }
  });

  // 検索（打ち終わるのを少し待つ）
  let searchTimer = null;
  document.getElementById('search-input').addEventListener('input', (event) => {
    if (searchTimer) clearTimeout(searchTimer);
    const value = event.target.value.trim();
    searchTimer = setTimeout(async () => {
      state.searchQuery = value;
      renderVaults();
      await loadItems();
    }, 250);
  });
  document.getElementById('search-form').addEventListener('submit', (event) => event.preventDefault());

  // 詳細パネルの操作
  document.getElementById('detail-panel').addEventListener('click', async (event) => {
    const button = event.target.closest('[data-action]');
    if (!button) return;
    const action = button.dataset.action;
    try {
      if (action === 'toggle-secret') {
        const field = button.dataset.field;
        const item = state.items.find((i) => i.id === state.itemId);
        if (state.revealed[field] !== undefined) {
          delete state.revealed[field];
        } else {
          state.revealed[field] = await reveal(field, 'view');
        }
        const { item: fresh } = await apiFetch(`/api/vaults/${item.vaultId}/items/${item.id}`);
        renderDetail(fresh);
      } else if (action === 'copy-secret') {
        const value = await reveal(button.dataset.field, 'copy');
        await copyToClipboard(value);
        toast('コピーしました（監査ログに残ります）', 'success');
      } else if (action === 'toggle-history' || action === 'copy-history') {
        const item = state.items.find((i) => i.id === state.itemId);
        const field = button.dataset.field;
        const index = Number(button.dataset.index);
        const key = `history:${field}:${index}`;
        if (action === 'toggle-history' && state.revealed[key] !== undefined) {
          delete state.revealed[key];
        } else {
          const { value } = await apiFetch(`/api/vaults/${item.vaultId}/items/${item.id}/history/reveal`, {
            method: 'POST', body: { field, index }
          });
          if (action === 'copy-history') {
            await copyToClipboard(value);
            toast('過去の値をコピーしました（監査ログに残ります）', 'success');
            return;
          }
          state.revealed[key] = value;
        }
        const { item: fresh } = await apiFetch(`/api/vaults/${item.vaultId}/items/${item.id}`);
        renderDetail(fresh);
        const details = document.querySelector(`#detail-content details.history-block`);
        if (details) details.open = true;
      } else if (action === 'copy-plain') {
        await copyToClipboard(button.dataset.value);
        toast('コピーしました', 'success');
      } else if (action === 'copy-authorized-key') {
        const item = state.items.find((i) => i.id === state.itemId);
        const { line } = await apiFetch(
          `/api/vaults/${item.vaultId}/items/${item.id}/authorized-key`
        );
        await copyToClipboard(line);
        toast('authorized_keys 用の1行をコピーしました', 'success');
      } else if (action === 'download-key') {
        const item = state.items.find((i) => i.id === state.itemId);
        const contents = state.revealed.privateKey !== undefined
          ? state.revealed.privateKey
          : await reveal('privateKey', 'copy');
        downloadPrivateKey(item, contents);
      } else if (action === 'show-totp') {
        await showTotp();
      } else if (action === 'copy-totp') {
        if (state.revealed.totpCode === undefined) await showTotp();
        // showTotp は失敗してもトーストを出して普通に戻るので、ここで確かめる。
        // 以前はそのままコピーして、クリップボードに "undefined" が入り「コピーしました」まで出ていた。
        if (typeof state.revealed.totpCode !== 'string') return;
        await copyToClipboard(state.revealed.totpCode);
        toast('コピーしました', 'success');
      } else if (action === 'edit-item') {
        const item = state.items.find((i) => i.id === state.itemId);
        const { item: fresh } = await apiFetch(`/api/vaults/${item.vaultId}/items/${item.id}`);
        openItemModal(fresh);
      } else if (action === 'delete-item') {
        const item = state.items.find((i) => i.id === state.itemId);
        if (!window.confirm(`「${item.title}」をゴミ箱へ移します。あとでゴミ箱から戻せます。`)) return;
        await apiFetch(`/api/vaults/${item.vaultId}/items/${item.id}`, { method: 'DELETE' });
        toast('ゴミ箱へ移しました', 'success');
        await loadVaults();
        await loadItems();
      }
    } catch (err) {
      toast(err.message, 'danger');
    }
  });

  // ヘッダーとツールバー
  document.body.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-action]');
    if (!button) return;
    const action = button.dataset.action;
    try {
      if (action === 'logout') {
        await apiFetch('/api/logout', { method: 'POST' });
        window.location.href = '/login';
      } else if (action === 'lock-now') {
        lockScreen();
      } else if (action === 'open-password-change') {
        showError('pw-error', null);
        document.getElementById('password-form').reset();
        modal('password-modal').show();
      } else if (action === 'open-tokens') {
        await openTokens();
      } else if (action === 'revoke-token') {
        const row = button.closest('[data-token-id]');
        if (!window.confirm('このトークンを失効させます。使っている cron などは読めなくなります。よろしいですか？')) return;
        showError('tokens-error', null);
        await apiFetch(`/api/tokens/${encodeURIComponent(row.dataset.tokenId)}`, { method: 'DELETE' });
        await renderTokens();
        toast('失効させました', 'success');
      } else if (action === 'copy-token') {
        await copyToClipboard(document.getElementById('token-value').value);
        toast('コピーしました', 'success');
      } else if (action === 'open-checkup') {
        await openCheckup();
      } else if (action === 'run-checkup') {
        button.disabled = true;
        try {
          await runCheckup();
        } finally {
          button.disabled = false;
        }
      } else if (action === 'goto-item') {
        event.preventDefault();
        modal('checkup-modal').hide();
        state.vaultId = button.dataset.vaultId;
        state.searchQuery = '';
        document.getElementById('search-input').value = '';
        renderVaults();
        await loadItems();
        await selectItem(button.dataset.vaultId, button.dataset.itemId);
      } else if (action === 'open-sessions') {
        showError('sessions-error', null);
        modal('sessions-modal').show();
        await renderSessions();
      } else if (action === 'revoke-session') {
        const row = button.closest('[data-handle]');
        showError('sessions-error', null);
        const result = await apiFetch(`/api/me/sessions/${encodeURIComponent(row.dataset.handle)}`, { method: 'DELETE' });
        if (result.loggedOut) {
          window.location.href = '/login';
          return;
        }
        await renderSessions();
        toast('切りました', 'success');
      } else if (action === 'revoke-other-sessions') {
        if (!window.confirm('この端末以外のログインをすべて切ります（Chrome 拡張も含みます）。よろしいですか？')) return;
        showError('sessions-error', null);
        const { removed } = await apiFetch('/api/me/sessions/revoke-others', { method: 'POST' });
        await renderSessions();
        toast(`${removed}件切りました`, 'success');
      } else if (action === 'open-activity') {
        modal('activity-modal').show();
        await renderActivity();
      } else if (action === 'new-vault') {
        showError('vault-error', null);
        modal('vault-modal').show();
      } else if (action === 'new-item') {
        openItemModal(null);
      } else if (action === 'manage-members') {
        await openMembers();
      } else if (action === 'open-trash') {
        await openTrash();
      } else if (action === 'restore-item' || action === 'purge-item') {
        const row = button.closest('[data-item-id]');
        const itemId = row.dataset.itemId;
        if (action === 'purge-item'
          && !window.confirm('完全に削除します。パスワードも履歴も二度と戻せません。よろしいですか？')) return;
        showError('trash-error', null);
        if (action === 'restore-item') {
          await apiFetch(`/api/vaults/${state.vaultId}/trash/${itemId}/restore`, { method: 'POST' });
          toast('戻しました', 'success');
        } else {
          await apiFetch(`/api/vaults/${state.vaultId}/trash/${itemId}`, { method: 'DELETE' });
          toast('完全に削除しました', 'success');
        }
        await renderTrash();
        await loadVaults();
        await loadItems();
      } else if (action === 'generate-password') {
        state.generatorTarget = 'item-password';
        regenerate();
        modal('generator-modal').show();
      } else if (action === 'generate-ssh') {
        await generateSshKey();
      } else if (action === 'regenerate') {
        regenerate();
      } else if (action === 'use-generated') {
        const value = document.getElementById('gen-output').value;
        const target = document.getElementById(state.generatorTarget || 'item-password');
        if (target) {
          target.value = value;
          target.type = 'text';
          target.dispatchEvent(new Event('input'));
        }
        modal('generator-modal').hide();
      } else if (action === 'add-member') {
        showError('members-error', null);
        await apiFetch(`/api/vaults/${state.vaultId}/members`, {
          method: 'POST',
          body: {
            userId: document.getElementById('member-user').value,
            role: document.getElementById('member-role').value
          }
        });
        await renderMembers();
        await loadVaults();
        toast('メンバーを追加しました', 'success');
      } else if (action === 'add-member-group') {
        showError('members-error', null);
        await apiFetch(`/api/vaults/${state.vaultId}/groups`, {
          method: 'POST',
          body: {
            groupId: document.getElementById('member-group').value,
            role: document.getElementById('member-group-role').value
          }
        });
        await renderMembers();
        await loadVaults();
        toast('グループを追加しました', 'success');
      } else if (action === 'remove-member-group') {
        const row = button.closest('[data-group-id]');
        if (!window.confirm('このグループを Vault から外します。グループ経由で入っていた人は入れなくなります。')) return;
        showError('members-error', null);
        await apiFetch(`/api/vaults/${state.vaultId}/groups/${row.dataset.groupId}`, { method: 'DELETE' });
        await renderMembers();
        await loadVaults();
        toast('外しました', 'success');
      } else if (action === 'remove-member') {
        const row = button.closest('[data-user-id]');
        if (!window.confirm('この人を Vault から外します。よろしいですか？')) return;
        showError('members-error', null);
        await apiFetch(`/api/vaults/${state.vaultId}/members/${row.dataset.userId}`, { method: 'DELETE' });
        await renderMembers();
        await loadVaults();
        toast('外しました', 'success');
      }
    } catch (err) {
      if (action === 'revoke-token') {
        showError('tokens-error', err.message);
      } else if (action === 'run-checkup') {
        showError('checkup-error', err.message);
        document.getElementById('checkup-status').textContent = '';
      } else if (['revoke-session', 'revoke-other-sessions'].includes(action)) showError('sessions-error', err.message);
      else if (['add-member', 'remove-member', 'add-member-group', 'remove-member-group'].includes(action)) showError('members-error', err.message);
      else toast(err.message, 'danger');
    }
  });

  // メンバーの権限変更
  document.getElementById('members-tbody').addEventListener('change', async (event) => {
    const select = event.target.closest('[data-action="change-role"]');
    if (!select) return;
    const row = select.closest('[data-user-id]');
    try {
      showError('members-error', null);
      await apiFetch(`/api/vaults/${state.vaultId}/members/${row.dataset.userId}`, {
        method: 'PUT', body: { role: select.value }
      });
      await renderMembers();
      await loadVaults();
      toast('権限を変えました', 'success');
    } catch (err) {
      showError('members-error', err.message);
      await renderMembers();
    }
  });

  document.getElementById('member-groups-tbody').addEventListener('change', async (event) => {
    const select = event.target.closest('[data-action="change-group-role"]');
    if (!select) return;
    const row = select.closest('[data-group-id]');
    try {
      showError('members-error', null);
      await apiFetch(`/api/vaults/${state.vaultId}/groups/${row.dataset.groupId}`, {
        method: 'PUT', body: { role: select.value }
      });
      await renderMembers();
      await loadVaults();
      toast('権限を変えました', 'success');
    } catch (err) {
      showError('members-error', err.message);
      await renderMembers();
    }
  });

  document.getElementById('token-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    showError('tokens-error', null);
    try {
      const vaultIds = [...document.querySelectorAll('#token-vaults input:checked')].map((i) => i.value);
      const { token } = await apiFetch('/api/tokens', {
        method: 'POST',
        body: {
          name: document.getElementById('token-name').value.trim(),
          vaultIds,
          expiresInDays: Number(document.getElementById('token-days').value)
        }
      });
      document.getElementById('token-value').value = token;
      document.getElementById('token-issued').classList.remove('d-none');
      document.getElementById('token-form').reset();
      await renderTokens();
    } catch (err) {
      showError('tokens-error', err.message);
    }
  });
  // 閉じたら、表示していたトークンを画面から消す
  document.getElementById('tokens-modal').addEventListener('hidden.bs.modal', () => {
    document.getElementById('token-value').value = '';
    document.getElementById('token-issued').classList.add('d-none');
  });

  document.getElementById('activity-filter').addEventListener('click', (event) => {
    const button = event.target.closest('[data-relation]');
    if (!button) return;
    document.querySelectorAll('#activity-filter [data-relation]').forEach((b) => b.classList.toggle('active', b === button));
    drawActivity();
  });

  // フォーム
  document.getElementById('item-form').addEventListener('submit', submitItem);
  document.getElementById('vault-form').addEventListener('submit', submitVault);
  document.getElementById('password-form').addEventListener('submit', submitPasswordChange);
  document.getElementById('unlock-form').addEventListener('submit', unlock);

  // 生成器のスライダー
  document.getElementById('gen-length').addEventListener('input', (event) => {
    document.getElementById('gen-length-label').textContent = event.target.value;
    regenerate();
  });
  for (const id of ['gen-upper', 'gen-lower', 'gen-digit', 'gen-symbol', 'gen-ambiguous']) {
    document.getElementById(id).addEventListener('change', regenerate);
  }

  document.getElementById('item-type').addEventListener('change', applyTypeVisibility);

  // 鍵を貼ったら、少し待ってから読み取って公開鍵を埋める
  let sshInspectTimer = null;
  for (const id of ['item-privatekey', 'item-publickey', 'item-passphrase']) {
    document.getElementById(id).addEventListener('input', () => {
      if (sshInspectTimer) clearTimeout(sshInspectTimer);
      sshInspectTimer = setTimeout(inspectSshInput, 400);
    });
  }

  bindStrengthMeter('item-password', 'item-strength-bar', 'item-strength-text');
  bindStrengthMeter('pw-new', 'pw-strength-bar');

  // 無操作ロックの見張り
  for (const type of ['mousemove', 'keydown', 'click', 'scroll', 'touchstart']) {
    document.addEventListener(type, resetIdleTimer, { passive: true });
  }
  // タブを離れたら、表示中の秘密は消しておく
  // タブを離れたら、表示中の秘密を画面からも消す。
  // 以前は変数だけ消して DOM に平文を残していたので、戻ると平文が見えたままで、
  // しかも「隠す」を押すと逆に取り出し直して監査ログが1件余計に積まれていた。
  document.addEventListener('visibilitychange', async () => {
    if (!document.hidden) return;
    const hadSecrets = Object.keys(state.revealed).length > 0;
    clearRevealed();
    if (!hadSecrets || !state.itemId) return;
    const item = state.items.find((i) => i.id === state.itemId);
    if (!item) return;
    try {
      const { item: fresh } = await apiFetch(`/api/vaults/${item.vaultId}/items/${item.id}`);
      renderDetail(fresh);
    } catch {
      const content = document.getElementById('detail-content');
      if (content) content.innerHTML = '';
    }
  });
  resetIdleTimer();
}

// --- 起動 -------------------------------------------------------------------

(async () => {
  wire();
  try {
    await loadVaults();
    await loadItems();
    refreshCheckupBadge();
    if (KB.data.user.mustChangePassword) {
      toast('初期パスワードのままです。変更してください', 'warning');
      modal('password-modal').show();
    }
  } catch (err) {
    toast(err.message, 'danger');
  }
})();
