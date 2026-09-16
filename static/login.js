'use strict';
// ログイン画面。

const { apiFetch, showError } = window.KBUtil;

document.getElementById('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('error', null);

  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;

  const button = event.target.querySelector('button[type=submit]');
  button.disabled = true;
  button.textContent = '確認中…';

  try {
    await apiFetch('/api/login', { method: 'POST', body: { username, password } });
    window.location.href = '/';
  } catch (err) {
    showError('error', err.message);
    document.getElementById('password').value = '';
    document.getElementById('password').focus();
    button.disabled = false;
    button.textContent = 'ログイン';
  }
});
