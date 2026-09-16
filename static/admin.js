'use strict';
// 管理画面。ユーザーの追加・権限変更と、監査ログの閲覧。

const { apiFetch, escapeHtml, showError, toast, formatDateTime, generatePassword } = window.KBUtil;

const modals = {};
function modal(id) {
  if (!modals[id]) modals[id] = new bootstrap.Modal(document.getElementById(id));
  return modals[id];
}

let auditEntries = [];

// --- ユーザー ---------------------------------------------------------------

async function loadUsers() {
  const { users } = await apiFetch('/api/users');
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
      <td>${escapeHtml(entry.note || '')}</td>
    </tr>
  `).join('') : '<tr><td colspan="5" class="text-center text-muted py-4">記録がありません</td></tr>';
}

// --- 操作 -------------------------------------------------------------------

document.body.addEventListener('click', async (event) => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const action = button.dataset.action;
  const row = button.closest('[data-user-id]');

  try {
    if (action === 'new-user') {
      showError('user-error', null);
      document.getElementById('user-form').reset();
      document.getElementById('new-password').value = generatePassword({ length: 20 });
      modal('user-modal').show();
    } else if (action === 'generate-initial') {
      document.getElementById('new-password').value = generatePassword({ length: 20 });
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
    await loadUsers();
    await loadAudit();
  } catch (err) {
    toast(err.message, 'danger');
  }
})();
