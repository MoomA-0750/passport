// ページに値を入れる処理。
//
// この関数は chrome.scripting.executeScript でページ側へ注入して動かす。
// 注入は popup を開いて「入力」を押したときだけ（activeTab 権限）。
// 拡張が常時どのページにも入り込むのは、金庫としては持たせたくない権限なので、
// content_scripts の常駐はしていない。
//
// 決めごと:
//   ・勝手に送信しない。入れるところまでで止める（誤送信は取り返しがつかない）
//   ・見えていない入力欄には入れない（隠しフォームで盗られるのを避ける）
//   ・React などが値の変化に気づくよう、ネイティブの setter を呼んでからイベントを出す

export function fillCredentials({ username, password, totp }) {
  const visible = (el) => {
    if (!el || el.disabled || el.readOnly) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return false;
    const style = window.getComputedStyle(el);
    return style.visibility !== 'hidden' && style.display !== 'none' && Number(style.opacity) > 0.05;
  };

  // React / Vue は value を直接書き換えても気づかないことがあるので、
  // プロトタイプ側の setter を呼んでからイベントを出す
  const setValue = (el, value) => {
    const proto = el instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
    setter.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };

  const all = [...document.querySelectorAll('input')].filter(visible);

  const passwordFields = all.filter((el) => el.type === 'password');
  const textFields = all.filter((el) => ['text', 'email', 'tel', ''].includes(el.type));

  const looksLikeUsername = (el) => {
    const hay = `${el.name} ${el.id} ${el.autocomplete} ${el.placeholder} ${el.getAttribute('aria-label') || ''}`.toLowerCase();
    return /user|login|account|email|mail|id\b|ユーザー|メール|アカウント/.test(hay);
  };

  const looksLikeTotp = (el) => {
    const hay = `${el.name} ${el.id} ${el.autocomplete} ${el.placeholder} ${el.getAttribute('aria-label') || ''}`.toLowerCase();
    return /otp|totp|2fa|mfa|one.?time|verification|authenticator|ワンタイム|認証コード/.test(hay);
  };

  const filled = [];

  // パスワード欄。複数あるときは最初の1つだけ
  // （「新しいパスワード」と「確認」が並ぶ変更画面で両方埋めない）
  if (password && passwordFields.length > 0) {
    setValue(passwordFields[0], password);
    filled.push('パスワード');
  }

  // ユーザー名欄。パスワード欄より前にあるものを優先する
  if (username && textFields.length > 0) {
    const passwordTop = passwordFields.length
      ? passwordFields[0].getBoundingClientRect().top
      : Number.POSITIVE_INFINITY;
    const candidates = textFields.filter((el) => !looksLikeTotp(el));
    const target = candidates.find((el) => looksLikeUsername(el))
      || candidates.filter((el) => el.getBoundingClientRect().top <= passwordTop).pop()
      || candidates[0];
    if (target) {
      setValue(target, username);
      filled.push('ユーザー名');
    }
  }

  // ワンタイムパスワード欄があれば入れる
  if (totp) {
    const target = textFields.find(looksLikeTotp)
      || all.find((el) => el.autocomplete === 'one-time-code');
    if (target) {
      setValue(target, totp);
      filled.push('ワンタイムパスワード');
    }
  }

  if (filled.length === 0) {
    return { ok: false, message: '入力できる欄が見つかりませんでした' };
  }
  return { ok: true, filled, message: `${filled.join('と')}を入れました（送信はしていません）` };
}
