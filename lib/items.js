'use strict';
// アイテム（ログイン情報・セキュアメモなど）。data/vaults/<vaultId>/items/<itemId>.json
//
// 何を暗号化して、何を平文で置くか（docs/crypto.md の「守らない」も読む）:
//   平文 … title / username / url / tags / メモの有無などのメタデータ。一覧と検索のため
//   暗号 … password / TOTP シークレット / セキュアメモ / 非表示のカスタムフィールド
//
// 秘密フィールドは1件ずつ独立した封筒に入れ、AAD で
// 「この Vault の、このアイテムの、このフィールドの、この世代」であることを縛る。

const crypto = require('crypto');
const store = require('./store');
const envelope = require('./envelope');
const vaults = require('./vaults');
const audit = require('./audit');
const sshkeys = require('./sshkeys');

const TYPES = ['login', 'note', 'card', 'server', 'sshkey'];

// 決まった名前の秘密フィールド。これ以外は custom:<uuid> になる。
// privateKey と passphrase は SSH 鍵用。
const NAMED_SECRETS = ['password', 'totp', 'note', 'privateKey', 'passphrase'];

function itemPath(vaultId, itemId) {
  store.assertValidId(vaultId, 'Vault ID');
  store.assertValidId(itemId, 'アイテムID');
  return `vaults/${vaultId}/items/${itemId}.json`;
}

function isSecretField(name) {
  return NAMED_SECRETS.includes(name) || /^custom:[A-Za-z0-9_-]{1,64}$/.test(name);
}

// 秘密1件を封筒に入れる。secretVersion は、そのフィールドが何度目の書き換えかを表す。
// これを AAD に入れることで、同じフィールドの古い暗号文に戻す攻撃も落ちる。
function sealSecret(vaultKey, { vaultId, itemId, field, secretVersion, value }) {
  const itemKey = envelope.deriveItemKey(vaultKey, itemId);
  try {
    const aad = envelope.buildAad({ vaultId, itemId, field, version: secretVersion });
    return {
      envelope: envelope.seal(itemKey, String(value), aad),
      v: secretVersion,
      updatedAt: new Date().toISOString()
    };
  } finally {
    itemKey.fill(0);
  }
}

function openSecret(vaultKey, { vaultId, itemId, field, record }) {
  const itemKey = envelope.deriveItemKey(vaultKey, itemId);
  try {
    const aad = envelope.buildAad({ vaultId, itemId, field, version: record.v });
    return envelope.open(itemKey, record.envelope, aad);
  } finally {
    itemKey.fill(0);
  }
}

// SSH 鍵の公開側メタデータを作る。
//
// 公開鍵・フィンガープリント・鍵種別は「公開してよいもの」なので平文で持つ。
// 一覧でフィンガープリントを見比べたり、authorized_keys へ貼ったりするのに
// いちいち復号したくないため。秘密鍵とパスフレーズだけが暗号化される。
//
// OpenSSH 形式はパスフレーズ付きでも公開鍵部分が平文なので、
// パスフレーズを預けなくてもここまでは埋まる。
function buildSshMeta({ privateKey, publicKey, passphrase, comment }) {
  // 秘密鍵があるなら、そこから割り出すのが一番確か（貼り間違いにも気づける）
  if (privateKey) {
    const info = sshkeys.inspectPrivateKey(privateKey, { passphrase: passphrase || null });
    return {
      keyType: info.keyType,
      bits: info.bits,
      fingerprint: info.fingerprint,
      publicKey: info.publicKey,
      comment: comment || info.comment || '',
      format: info.format,
      privateKeyEncrypted: info.encrypted,
      hasPrivateKey: true
    };
  }
  // 公開鍵だけの登録（サーバーに置いてある鍵の控えなど）
  if (publicKey) {
    const info = sshkeys.parsePublicKey(publicKey);
    return {
      keyType: info.keyType,
      bits: info.bits,
      fingerprint: info.fingerprint,
      publicKey: info.publicKey,
      comment: comment || info.comment || '',
      format: 'public-only',
      privateKeyEncrypted: false,
      hasPrivateKey: false
    };
  }
  return null;
}

// 画面と API に返す形。秘密は中身を返さず「ある / ない」と最終更新だけ返す。
function toPublic(item) {
  const secrets = {};
  for (const [field, record] of Object.entries(item.secrets || {})) {
    secrets[field] = {
      present: true,
      updatedAt: record.updatedAt || null,
      label: (item.fieldLabels || {})[field] || null
    };
  }
  return {
    id: item.id,
    vaultId: item.vaultId,
    type: item.type,
    title: item.title,
    username: item.username || '',
    urls: item.urls || [],
    tags: item.tags || [],
    favorite: !!item.favorite,
    sshKey: item.sshKey || null,
    secrets,
    createdAt: item.createdAt,
    createdBy: item.createdBy,
    updatedAt: item.updatedAt,
    updatedBy: item.updatedBy,
    passwordUpdatedAt: (item.secrets && item.secrets.password && item.secrets.password.updatedAt) || null,
    version: item.version
  };
}

function normalizeUrls(urls) {
  if (!urls) return [];
  const array = Array.isArray(urls) ? urls : String(urls).split(/[\s,]+/);
  return array.map((u) => String(u).trim()).filter(Boolean).slice(0, 10);
}

function normalizeTags(tags) {
  if (!tags) return [];
  const array = Array.isArray(tags) ? tags : String(tags).split(',');
  return [...new Set(array.map((t) => String(t).trim()).filter(Boolean))].slice(0, 20);
}

function list(vaultId, userId) {
  vaults.requireAccess(vaultId, userId, 'viewer');
  return store.listJson(`vaults/${vaultId}/items`)
    .map(toPublic)
    .sort((a, b) => {
      if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
      return a.title.localeCompare(b.title, 'ja');
    });
}

function get(vaultId, itemId, userId) {
  vaults.requireAccess(vaultId, userId, 'viewer');
  const item = store.readJson(itemPath(vaultId, itemId));
  return item ? toPublic(item) : null;
}

function create(vaultId, input, { actor }) {
  const vault = vaults.requireAccess(vaultId, actor, 'editor');
  const title = String(input.title || '').trim();
  if (!title) throw new Error('タイトルを入力してください');
  const type = TYPES.includes(input.type) ? input.type : 'login';

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const vaultKey = vaults.unwrapKey(vault);

  try {
    // SSH 鍵は保存する前に読めるか確かめる。
    // 貼り間違いをここで弾いておかないと、必要になったときに初めて気づくことになる。
    let sshKey = null;
    if (type === 'sshkey') {
      sshKey = buildSshMeta({
        privateKey: (input.secrets || {}).privateKey,
        publicKey: input.publicKey,
        passphrase: (input.secrets || {}).passphrase,
        comment: input.comment
      });
      if (!sshKey) throw new Error('秘密鍵か公開鍵のどちらかを入れてください');
    }

    const secrets = {};
    const fieldLabels = {};
    for (const [field, value] of Object.entries(input.secrets || {})) {
      if (!isSecretField(field)) throw new Error(`使えないフィールド名です: ${field}`);
      if (value === undefined || value === null || value === '') continue;
      secrets[field] = sealSecret(vaultKey, { vaultId, itemId: id, field, secretVersion: 1, value });
    }
    for (const [field, label] of Object.entries(input.fieldLabels || {})) {
      if (secrets[field]) fieldLabels[field] = String(label).slice(0, 64);
    }

    const item = {
      id,
      vaultId,
      type,
      title: title.slice(0, 128),
      username: String(input.username || '').trim().slice(0, 128),
      urls: normalizeUrls(input.urls),
      tags: normalizeTags(input.tags),
      favorite: !!input.favorite,
      sshKey,
      secrets,
      fieldLabels,
      createdAt: now,
      createdBy: actor,
      updatedAt: now,
      updatedBy: actor,
      version: 1
    };
    store.writeJson(itemPath(vaultId, id), item);
    audit.record('item.create', { actor, vaultId, itemId: id, note: item.title });
    return toPublic(item);
  } finally {
    vaultKey.fill(0);
  }
}

// 更新。secrets に入っているフィールドだけ暗号化し直す。
// 触らなかったフィールドの封筒はそのまま残す（無駄な再暗号化をしない）。
// 値を null にしたフィールドは削除する。
function update(vaultId, itemId, input, { actor }) {
  const vault = vaults.requireAccess(vaultId, actor, 'editor');
  const vaultKey = vaults.unwrapKey(vault);

  try {
    const updated = store.updateJson(itemPath(vaultId, itemId), input.version, (current) => {
      const next = { ...current };

      if (input.title !== undefined) {
        const title = String(input.title).trim();
        if (!title) throw new Error('タイトルを入力してください');
        next.title = title.slice(0, 128);
      }
      if (input.type !== undefined && TYPES.includes(input.type)) next.type = input.type;
      if (input.username !== undefined) next.username = String(input.username).trim().slice(0, 128);
      if (input.urls !== undefined) next.urls = normalizeUrls(input.urls);
      if (input.tags !== undefined) next.tags = normalizeTags(input.tags);
      if (input.favorite !== undefined) next.favorite = !!input.favorite;

      if (input.secrets) {
        const secrets = { ...(current.secrets || {}) };
        for (const [field, value] of Object.entries(input.secrets)) {
          if (!isSecretField(field)) throw new Error(`使えないフィールド名です: ${field}`);
          if (value === null) {
            delete secrets[field];
            continue;
          }
          if (value === undefined || value === '') continue;
          const secretVersion = Number((secrets[field] && secrets[field].v) || 0) + 1;
          secrets[field] = sealSecret(vaultKey, { vaultId, itemId, field, secretVersion, value });
        }
        next.secrets = secrets;
      }

      if (input.fieldLabels) {
        const labels = { ...(current.fieldLabels || {}) };
        for (const [field, label] of Object.entries(input.fieldLabels)) {
          if (label === null) delete labels[field];
          else labels[field] = String(label).slice(0, 64);
        }
        next.fieldLabels = labels;
      }

      // SSH 鍵は、秘密鍵か公開鍵を差し替えたときだけメタデータを作り直す。
      // 触っていないなら以前のものをそのまま残す（復号しないで済ませるため）。
      if (next.type === 'sshkey') {
        const newPrivate = input.secrets && input.secrets.privateKey;
        const newPublic = input.publicKey;
        if (newPrivate || newPublic) {
          next.sshKey = buildSshMeta({
            privateKey: newPrivate,
            publicKey: newPublic,
            passphrase: (input.secrets || {}).passphrase,
            comment: input.comment
          });
        } else if (input.comment !== undefined && next.sshKey) {
          next.sshKey = { ...next.sshKey, comment: String(input.comment).slice(0, 128) };
        }
        if (!next.sshKey) throw new Error('秘密鍵か公開鍵のどちらかを入れてください');
      } else if (current.type === 'sshkey') {
        // 種別を変えたら SSH のメタデータは連れていかない
        next.sshKey = null;
      }

      next.updatedBy = actor;
      return next;
    });

    audit.record('item.update', {
      actor, vaultId, itemId,
      note: input.secrets ? `秘密を更新: ${Object.keys(input.secrets).join(',')}` : 'メタデータのみ'
    });
    return toPublic(updated);
  } finally {
    vaultKey.fill(0);
  }
}

// 秘密を1つ復号して返す。ここが一番機微なので、必ず監査ログを残す。
function revealSecret(vaultId, itemId, field, { actor, purpose = 'view', ip = null }) {
  const vault = vaults.requireAccess(vaultId, actor, 'viewer');
  const item = store.readJson(itemPath(vaultId, itemId));
  if (!item) throw new Error('アイテムが見つかりません');
  const record = (item.secrets || {})[field];
  if (!record) throw new Error('そのフィールドはありません');

  const vaultKey = vaults.unwrapKey(vault);
  try {
    const value = openSecret(vaultKey, { vaultId, itemId, field, record });
    audit.record(purpose === 'copy' ? 'item.copy_secret' : 'item.view_secret', {
      actor, vaultId, itemId, field, ip, note: item.title
    });
    return value;
  } finally {
    vaultKey.fill(0);
  }
}

// 手元の値が、保管してあるものと同じかどうかだけを答える。
//
// なぜ「取り出して比べる」ではなくこれを用意するか:
// Chrome 拡張が「もう登録済みか」を判断するのに、保管してある平文まで渡す必要はない。
// 渡さずに済むなら渡さない。呼ぶ側は候補の値を既に持っているので、
// ここで真偽を返しても新しく漏れるものはない。
//
// 監査ログには閲覧とは別の種別で残す。閲覧の記録を薄めないため。
function verifySecret(vaultId, itemId, field, candidate, { actor, ip = null, note = null }) {
  const vault = vaults.requireAccess(vaultId, actor, 'viewer');
  const item = store.readJson(itemPath(vaultId, itemId));
  if (!item) throw new Error('アイテムが見つかりません');
  const record = (item.secrets || {})[field];
  if (!record) return false;

  const vaultKey = vaults.unwrapKey(vault);
  let matches = false;
  try {
    const stored = Buffer.from(openSecret(vaultKey, { vaultId, itemId, field, record }), 'utf8');
    const given = Buffer.from(String(candidate == null ? '' : candidate), 'utf8');
    matches = stored.length === given.length && crypto.timingSafeEqual(stored, given);
    stored.fill(0);
  } finally {
    vaultKey.fill(0);
  }

  audit.record('item.verify_secret', {
    actor, vaultId, itemId, field, ip,
    result: matches ? 'match' : 'differs',
    note: note || item.title
  });
  return matches;
}

function remove(vaultId, itemId, { actor }) {
  vaults.requireAccess(vaultId, actor, 'editor');
  const item = store.readJson(itemPath(vaultId, itemId));
  if (!item) return false;
  store.deleteFile(itemPath(vaultId, itemId));
  audit.record('item.delete', { actor, vaultId, itemId, note: item.title });
  return true;
}

// 平文のメタデータだけを対象にした横断検索。
// WordBox の重み付け検索と同じ考え方（タイトル > ユーザー名/URL > タグ）。
// 秘密は検索対象にしない（できない）。
function search(userId, query, { vaultId = null, limit = 100 } = {}) {
  const needle = String(query || '').trim().toLowerCase();
  const targets = vaults.listForUser(userId)
    .filter((v) => !vaultId || v.id === vaultId);

  const results = [];
  for (const vault of targets) {
    for (const item of store.listJson(`vaults/${vault.id}/items`)) {
      const pub = toPublic(item);
      if (!needle) {
        results.push({ ...pub, vaultName: vault.name, score: 0 });
        continue;
      }
      let score = 0;
      if (item.title.toLowerCase().includes(needle)) score += 10;
      if ((item.username || '').toLowerCase().includes(needle)) score += 5;
      if ((item.urls || []).some((u) => u.toLowerCase().includes(needle))) score += 5;
      if ((item.tags || []).some((t) => t.toLowerCase().includes(needle))) score += 3;
      // SSH 鍵はフィンガープリントとコメントでも引けるようにする。
      // 「このサーバーに入っている鍵はどれだ」を探すときに要る。
      if (item.sshKey) {
        if ((item.sshKey.fingerprint || '').toLowerCase().includes(needle)) score += 8;
        if ((item.sshKey.comment || '').toLowerCase().includes(needle)) score += 4;
        if ((item.sshKey.keyType || '').toLowerCase().includes(needle)) score += 2;
      }
      if (score > 0) results.push({ ...pub, vaultName: vault.name, score });
    }
  }

  results.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    return a.title.localeCompare(b.title, 'ja');
  });
  return results.slice(0, limit);
}

// --- ホストの照合（Chrome 拡張のオートフィル用）-----------------------------

// URL 文字列からホスト名を取り出す。
// "https://a.example.local/path"、"a.example.local:8443"、"a.example.local" のどれでも。
function hostOf(value) {
  const text = String(value || '').trim().toLowerCase();
  if (!text) return '';
  try {
    const url = new URL(text.includes('://') ? text : `https://${text}`);
    return url.hostname;
  } catch {
    return '';
  }
}

// 登録されたホストと、今見ているホストが「同じサイト」と言えるか。
//
// ここを緩くするとオートフィルが誤爆する。誤爆はただの不便ではなく、
// 別のサイトへパスワードを差し出すことなので、判定は厳しめに倒す。
//   ・完全一致は当然 OK
//   ・登録が親ドメインなら、その下のサブドメインは OK
//     （example.local に対する git.example.local）
//   ・逆は認めない（git.example.local の登録で example.local には入れない）
//   ・部分一致はしない（example.local.attacker.test は別物）
//   ・公開suffixの判定まではやらない。社内向けなので、登録側を親ドメインにするかは運用で決める
function hostMatches(registered, current) {
  if (!registered || !current) return false;
  if (registered === current) return { score: 100, kind: 'exact' };
  if (current.endsWith(`.${registered}`)) return { score: 60, kind: 'subdomain' };
  return false;
}

// 今見ているホストに使えそうなアイテムを、確からしい順に返す。
function matchHost(userId, host) {
  const current = hostOf(host);
  if (!current) return [];

  const results = [];
  for (const vault of vaults.listForUser(userId)) {
    for (const item of store.listJson(`vaults/${vault.id}/items`)) {
      // 入力できるものだけ。SSH 鍵やカードはブラウザの入力欄には入れない
      if (!['login', 'server'].includes(item.type)) continue;
      if (!item.secrets || !item.secrets.password) continue;

      let best = null;
      for (const url of item.urls || []) {
        const matched = hostMatches(hostOf(url), current);
        if (matched && (!best || matched.score > best.score)) best = matched;
      }
      if (!best) continue;

      results.push({
        ...toPublic(item),
        vaultName: vault.name,
        matchKind: best.kind,
        score: best.score + (item.favorite ? 5 : 0)
      });
    }
  }

  results.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.title.localeCompare(b.title, 'ja');
  });
  return results;
}

module.exports = {
  TYPES,
  NAMED_SECRETS,
  buildSshMeta,
  isSecretField,
  toPublic,
  list,
  get,
  create,
  update,
  revealSecret,
  verifySecret,
  remove,
  search,
  matchHost,
  hostMatches,
  hostOf
};
