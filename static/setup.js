'use strict';
// 初回セットアップ画面。最初の管理者を作る。

const { apiFetch, showError, bindStrengthMeter } = window.KBUtil;

bindStrengthMeter('password', 'strength-bar', 'strength-text');

document.getElementById('setup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('error', null);

  const setupToken = document.getElementById('setupToken').value.trim();
  const username = document.getElementById('username').value.trim().toLowerCase();
  const displayName = document.getElementById('displayName').value.trim();
  const password = document.getElementById('password').value;
  const confirm = document.getElementById('passwordConfirm').value;

  if (password !== confirm) {
    showError('error', 'パスワードが一致しません');
    return;
  }

  const button = event.target.querySelector('button[type=submit]');
  button.disabled = true;
  button.textContent = '作成中…';

  try {
    await apiFetch('/api/setup', { method: 'POST', body: { username, password, displayName, setupToken } });
    // 作ったらそのままログインさせる
    await apiFetch('/api/login', { method: 'POST', body: { username, password } });
    window.location.href = '/';
  } catch (err) {
    showError('error', err.message);
    button.disabled = false;
    button.textContent = '作成してはじめる';
  }
});
