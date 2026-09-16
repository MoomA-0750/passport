'use strict';
// 管理画面。ユーザーの追加・権限変更、グループ、監査ログの閲覧。

const { apiFetch, escapeHtml, showError, toast, formatDateTime, generatePassword } = window.KBUtil;

const modals = {};
function modal(id) {
  if (!modals[id]) modals[id] = new bootstrap.Modal(document.getElementById(id));
  return modals[id];
}

let auditEntries = [];
let allUsers = [];
let myUserId = null;

// --- ユーザー ---------------------------------------------------------------

async function loadUsers() {
  const { users } = await apiFetch('/api/users');
  allUsers = users;
  document.getElementById('users-tbody').innerHTML = users.map((user) => `
    <tr data-user-id="${escapeHtml(user.id)}">
      <td class="font-monospace">${escapeHtml(user.username)}</td>
      <td>${escapeHtml(user.displayName)}</td>
      <td>
        <select class="form-select form-select-sm" data-action="change-role" style="width:8rem">
          <option value="member" ${user.role === 'member' ? 'selected' : ''}>member</option>
          <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>admin</option>
        </select>
      </td>
      <td>
        ${user.status === 'active'
          ? '<span class="badge bg-success">有効</span>'
          : '<span class="badge bg-secondary">無効</span>'}
        ${user.mustChangePassword ? '<span class="badge bg-warning text-dark ms-1">初期PW</span>' : ''}
      </td>
      <td class="small text-muted">${escapeHtml(formatDateTime(user.lastLoginAt))}</td>
      <td class="text-end">
        <div class="btn-group btn-group-sm">
          <button class="btn btn-outline-secondary" type="button" data-action="reset-password">PWリセット</button>
          <button class="btn btn-outline-${user.status === 'active' ? 'danger' : 'success'}" type="button"
                  data-action="toggle-status" data-status="${user.status}">
            ${user.status === 'active' ? '無効化' : '有効化'}
          </button>
        </div>
      </td>
    </tr>
  `).join('');
}

// --- グループ ---------------------------------------------------------------

async function loadGroups() {
  const { groups } = await apiFetch('/api/groups');
  const list = document.getElementById('groups-list');
  if (!groups.length) {
    list.innerHTML = '<p class="text-muted">グループはまだありません</p>';
    return;
  }
  list.innerHTML = groups.map((group) => {
    const inGroup = new Set(group.members.map((m) => m.userId));
    // 自分自身はグループに入れられない（サーバーでも断る。緊急アクセスの迂回になるため）
    const candidates = allUsers.filter((u) => u.status === 'active' && !inGroup.has(u.id) && u.id !== myUserId);
    return `
    <div class="card mb-3" data-group-id="${escapeHtml(group.id)}">
      <div class="card-header d-flex justify-content-between align-items-center">
        <div>
          <strong>${escapeHtml(group.name)}</strong>
          <span class="text-muted small ms-2">${escapeHtml(group.description)}</span>
        </div>
        <div class="btn-group btn-group-sm">
          <button class="btn btn-outline-secondary" type="button" data-action="edit-group">名前を変える</button>
          <button class="btn btn-outline-danger" type="button" data-action="delete-group">消す</button>
        </div>
      </div>
      <div class="card-body">
        <div class="mb-2 small">
          <span class="text-muted">共有先:</span>
          ${group.usedBy.length
            ? group.usedBy.map((v) => `<span class="badge bg-light text-dark border me-1">${escapeHtml(v.name)}（${escapeHtml(v.role)}）</span>`).join('')
            : '<span class="text-muted">どの Vault にも入っていません</span>'}
        </div>
        <ul class="list-group list-group-flush mb-2">
          ${group.members.length ? group.members.map((m) => `
            <li class="list-group-item d-flex justify-content-between align-items-center px-0" data-user-id="${escapeHtml(m.userId)}">
              <span>${escapeHtml(m.displayName)} <span class="text-muted small">@${escapeHtml(m.username)}</span></span>
              <button class="btn btn-sm btn-outline-danger" type="button" data-action="remove-group-member">外す</button>
            </li>`).join('') : '<li class="list-group-item px-0 text-muted">まだ誰もいません</li>'}
        </ul>
        ${candidates.length ? `
        <div class="input-group input-group-sm" style="max-width:28rem">
          <select class="form-select" data-role="group-member-candidate">
            ${candidates.map((u) => `<option value="${escapeHtml(u.id)}">${escapeHtml(u.displayName)} (@${escapeHtml(u.username)})</option>`).join('')}
          </select>
          <button class="btn btn-outline-primary" type="button" data-action="add-group-member">入れる</button>
        </div>` : ''}
      </div>
    </div>`;
  }).join('');
}

function openGroupModal(group) {
  showError('group-error', null);
  document.getElementById('group-modal-title').textContent = group ? 'グループを編集' : 'グループを作る';
  document.getElementById('group-id').value = group ? group.id : '';
  document.getElementById('group-name').value = group ? group.name : '';
  document.getElementById('group-description').value = group ? group.description : '';
  modal('group-modal').show();
}

// --- 自動化トークン -----------------------------------------------------------

async function loadTokens() {
  const { tokens } = await apiFetch('/api/tokens');
  document.getElementById('admin-tokens-tbody').innerHTML = tokens.length ? tokens.map((t) => `
    <tr data-token-id="${escapeHtml(t.id)}">
      <td>${escapeHtml(t.name)}</td>
      <td>${t.vaults.map((v) => escapeHtml(v.name)).join('、')}</td>
      <td class="text-nowrap">${escapeHtml(t.createdBy)}<div class="text-muted">${escapeHtml(formatDateTime(t.createdAt))}</div></td>
      <td class="text-nowrap">${escapeHtml(formatDateTime(t.expiresAt))}</td>
      <td class="text-nowrap">${t.lastUsedAt ? `${escapeHtml(formatDateTime(t.lastUsedAt))}<div class="text-muted font-monospace">${escapeHtml(t.lastUsedIp || '')}</div>` : '<span class="text-muted">未使用</span>'}</td>
      <td><span class="badge bg-${t.status === 'active' ? 'success' : 'secondary'}">${escapeHtml(t.statusLabel)}</span></td>
      <td class="text-end">${t.revokedAt ? '' : '<button class="btn btn-sm btn-outline-danger" type="button" data-action="revoke-token">失効</button>'}</td>
    </tr>`).join('') : '<tr><td colspan="7" class="text-center text-muted py-3">トークンはありません</td></tr>';
}

// --- 監査ログ ---------------------------------------------------------------

async function loadAudit() {
  const { entries, eventLabels } = await apiFetch('/api/audit?limit=500');
  auditEntries = entries;

  const filter = document.getElementById('audit-filter');
  if (filter.options.length <= 1) {
    const used = [...new Set(entries.map((e) => e.event))].sort();
    for (const event of used) {
      const option = document.createElement('option');
      option.value = event;
      option.textContent = eventLabels[event] || event;
      filter.appendChild(option);
    }
  }
  renderAudit();
}

const RESULT_BADGES = {
  bad_password: 'warning',
  no_such_user: 'warning',
  locked: 'danger',
  disabled: 'secondary',
  break_glass: 'danger'
};

function renderAudit() {
  const selected = document.getElementById('audit-filter').value;
  const rows = auditEntries.filter((e) => !selected || e.event === selected);

  document.getElementById('audit-tbody').innerHTML = rows.length ? rows.map((entry) => `
    <tr>
      <td class="text-nowrap text-muted">${escapeHtml(formatDateTime(entry.at))}</td>
      <td>
        ${escapeHtml(entry.eventLabel)}
        ${entry.result && entry.result !== 'ok'
          ? `<span class="badge bg-${RESULT_BADGES[entry.result] || 'secondary'} ms-1">${escapeHtml(entry.result)}</span>`
          : ''}
        ${entry.field ? `<span class="badge bg-light text-dark ms-1">${escapeHtml(entry.field)}</span>` : ''}
      </td>
      <td>${escapeHtml(entry.actorName || '—')}<br><span class="text-muted">${escapeHtml(entry.ip || '')}</span></td>
      <td class="font-monospace text-muted">${escapeHtml((entry.itemId || entry.vaultId || entry.target || '').slice(0, 8))}</td>
      <td>${escapeHtml(entry.note || '')}${entry.suppressed ? `<span class="badge bg-light text-dark border ms-1" title="同じ記録を間引いた数">ほか ${Number(entry.suppressed)} 件</span>` : ''}</td>
    </tr>
  `).join('') : '<tr><td colspan="5" class="text-center text-muted py-4">記録がありません</td></tr>';
}

// --- 操作 -------------------------------------------------------------------

document.body.addEventListener('click', async (event) => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const action = button.dataset.action;
  const row = button.closest('[data-user-id]');
  const groupCard = button.closest('[data-group-id]');
  const tokenRow = button.closest('[data-token-id]');

  try {
    if (action === 'new-user') {
      showError('user-error', null);
      document.getElementById('user-form').reset();
      document.getElementById('new-password').value = generatePassword({ length: 20 });
      modal('user-modal').show();
    } else if (action === 'generate-initial') {
      document.getElementById('new-password').value = generatePassword({ length: 20 });
    } else if (action === 'new-group') {
      openGroupModal(null);
    } else if (action === 'edit-group') {
      const { groups } = await apiFetch('/api/groups');
      openGroupModal(groups.find((g) => g.id === groupCard.dataset.groupId));
    } else if (action === 'delete-group') {
      if (!window.confirm('このグループを消します。よろしいですか？')) return;
      await apiFetch(`/api/groups/${groupCard.dataset.groupId}`, { method: 'DELETE' });
      toast('消しました', 'success');
      await loadGroups();
    } else if (action === 'add-group-member') {
      const userId = groupCard.querySelector('[data-role="group-member-candidate"]').value;
      await apiFetch(`/api/groups/${groupCard.dataset.groupId}/members`, { method: 'POST', body: { userId } });
      toast('グループに入れました', 'success');
      await loadGroups();
    } else if (action === 'remove-group-member') {
      if (!window.confirm('この人をグループから外します。グループ経由で入っていた Vault には入れなくなります。')) return;
      await apiFetch(`/api/groups/${groupCard.dataset.groupId}/members/${row.dataset.userId}`, { method: 'DELETE' });
      toast('外しました', 'success');
      await loadGroups();
    } else if (action === 'reload-tokens') {
      await loadTokens();
    } else if (action === 'revoke-token') {
      if (!window.confirm('このトークンを失効させます。よろしいですか？')) return;
      await apiFetch(`/api/tokens/${encodeURIComponent(tokenRow.dataset.tokenId)}`, { method: 'DELETE' });
      toast('失効させました', 'success');
      await loadTokens();
    } else if (action === 'reload-audit') {
      await loadAudit();
      toast('更新しました');
    } else if (action === 'reset-password') {
      const newPassword = generatePassword({ length: 20 });
      if (!window.confirm(
        `新しい初期パスワードを設定します。\n\n${newPassword}\n\n` +
        'この値を控えて、本人へ別の経路で伝えてください。OK を押すと確定します。'
      )) return;
      await apiFetch(`/api/users/${row.dataset.userId}/password`, { method: 'POST', body: { newPassword } });
      toast('リセットしました。本人は次のログインで変更を求められます', 'success');
      await loadUsers();
    } else if (action === 'toggle-status') {
      const next = button.dataset.status === 'active' ? 'disabled' : 'active';
      await apiFetch(`/api/users/${row.dataset.userId}`, { method: 'PUT', body: { status: next } });
      toast(next === 'disabled' ? '無効にしました（セッションも切りました）' : '有効にしました', 'success');
      await loadUsers();
    }
  } catch (err) {
    toast(err.message, 'danger');
  }
});

document.getElementById('users-tbody').addEventListener('change', async (event) => {
  const select = event.target.closest('[data-action="change-role"]');
  if (!select) return;
  const row = select.closest('[data-user-id]');
  try {
    await apiFetch(`/api/users/${row.dataset.userId}`, { method: 'PUT', body: { role: select.value } });
    toast('権限を変えました', 'success');
    await loadUsers();
  } catch (err) {
    toast(err.message, 'danger');
    await loadUsers();
  }
});

document.getElementById('audit-filter').addEventListener('change', renderAudit);

document.getElementById('group-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('group-error', null);
  const id = document.getElementById('group-id').value;
  const body = {
    name: document.getElementById('group-name').value.trim(),
    description: document.getElementById('group-description').value.trim()
  };
  try {
    if (id) await apiFetch(`/api/groups/${id}`, { method: 'PUT', body });
    else await apiFetch('/api/groups', { method: 'POST', body });
    modal('group-modal').hide();
    toast('保存しました', 'success');
    await loadGroups();
  } catch (err) {
    showError('group-error', err.message);
  }
});

document.getElementById('user-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('user-error', null);
  try {
    await apiFetch('/api/users', {
      method: 'POST',
      body: {
        username: document.getElementById('new-username').value.trim().toLowerCase(),
        displayName: document.getElementById('new-displayname').value.trim(),
        role: document.getElementById('new-role').value,
        password: document.getElementById('new-password').value
      }
    });
    modal('user-modal').hide();
    toast('追加しました。初期パスワードを本人へ伝えてください', 'success');
    await loadUsers();
  } catch (err) {
    showError('user-error', err.message);
  }
});

(async () => {
  try {
    myUserId = (await apiFetch('/api/me')).user.id;
    await loadUsers();
    await loadGroups();
    await loadTokens();
    await loadAudit();
  } catch (err) {
    toast(err.message, 'danger');
  }
})();
