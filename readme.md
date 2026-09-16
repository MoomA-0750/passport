# KeyBox

社内で使うパスワード金庫。1Password のような Vault と共有の仕組みを、
[WordBox](https://github.com/MoomA-0750/word-box) と同じ材料で作る。

## 材料（WordBox から引き継いだ制約）

- **完全オフラインの RHEL 10 サーバー**。npm からパッケージを取れない
- **Node.js v20.19.2 の標準ライブラリだけ**を使う
- ビルドプロセスなし。`node server.js` で起動して、ファイルを置けば反映される
- DB を使わない。1レコード1ファイルの JSON
- UI は Bootstrap 5 の静的ファイル（自分で配信）とバニラ JS

WordBox との違いは **`node_modules` を1つも使わない**こと。
WordBox は VS Code の `node_modules` から `fs-extra` や `uuid` などを抽出しているが、
金庫は持ち込む部品を減らしたいので標準ライブラリで置き換えた。

| WordBox が使っているもの | KeyBox での代わり |
|---|---|
| `uuid` | `crypto.randomUUID()`（標準） |
| `ini` | `lib/config.js` の小さな自前パーサー |
| `fs-extra` | `fs.mkdirSync({ recursive: true })` など標準の `fs` |
| `debug` / `ms` / `chalk` | `lib/logger.js`（同じ体裁を自前で出す） |
| `tar`（バックアップ） | RHEL の `tar` コマンドを呼ぶ予定（未実装） |

暗号は追加ライブラリなしで足りる。Node 標準の `crypto` に AES-256-GCM、HKDF、
scrypt、HMAC が入っているので、1Password 相当の鍵階層はこれで組める。

## できること

- ユーザーアカウント（アプリ内で完結。招待も初期パスワードの発行も管理画面から）
- 複数の Vault と、**Vault 単位の共有**（owner / editor / viewer）
- ログイン情報・サーバー・カード・セキュアメモの保存
- パスワード、TOTP シークレット、セキュアメモ、カスタムフィールドの暗号化
- TOTP（ワンタイムパスワード）の表示
- パスワード生成器と強度の目安
- タイトル・ユーザー名・URL・タグの横断検索
- 監査ログ（誰がいつどのアイテムのどのフィールドを見たか）
- 無操作での画面ロック

## まだ無いもの

- バックアップとリストアの仕組み（`tar` を呼ぶだけだが未実装）
- 1Password / CSV からのインポートと、エクスポート
- パスワードの使い回し・古さのチェック
- ブラウザ拡張や自動入力（作らない。社内の運用範囲を超える）
- E2E 暗号（今は採っていない。理由と将来の移行先は `docs/crypto.md`）

## セキュリティの立ち位置

**「サーバーは知っているが、盗まれたファイルは何も語らない」**

1Password のようなゼロ知識ではない。サーバーがマスターキーを持っているので、
稼働中のサーバーの root を取れる人は中身を読める。
そのかわり `data/` やバックアップが流出しても、パスワードは AES-256-GCM の暗号文でしかない。

受け入れたリスクと、それを選んだ理由は **`docs/crypto.md`** に全部書いてある。
実装を変える前に必ず読む。

要点だけ:

- マスターキーは `data/` の外（既定 `/etc/keybox/master.key`、モード 0400）
- Vault ごとの鍵を KEK で包み、アイテムごとに HKDF で鍵を分ける
- AAD で「この Vault の、このアイテムの、このフィールドの、この世代」を縛る
- パスワードは scrypt + マスターキー由来の pepper でハッシュ
- **タイトル・ユーザー名・URL・タグは平文**（一覧と検索のため）。秘密は必ず暗号化
- 通信は HTTPS 前提。HTTP で起動すると警告が出る

## 構成

```
key-box/
├── server.js               # HTTP(S) サーバーとルーティング
├── lib/
│   ├── config.js           # keybox.ini + 環境変数
│   ├── logger.js           # 名前空間つきログ（DEBUG=keybox:*）
│   ├── http.js             # セキュリティヘッダー、本文の読み取り
│   ├── template.js         # {{variable}} 置換（既定でエスケープ）
│   ├── store.js            # 原子的な JSON ストア、楽観ロック、パス封じ
│   ├── envelope.js         # AES-256-GCM 封筒、HKDF、scrypt ハッシュ
│   ├── keyring.js          # マスターキー → KEK と pepper
│   ├── users.js            # アカウントと認証
│   ├── session.js          # セッションと CSRF
│   ├── vaults.js           # Vault、鍵の包み、メンバーシップと権限
│   ├── items.js            # アイテムと秘密フィールド
│   ├── totp.js             # RFC 6238
│   ├── audit.js            # 追記専用の監査ログ
│   └── api.js              # JSON API
├── templates/              # layout / login / setup / app / admin
├── static/                 # style.css, common.js, app.js, admin.js, Bootstrap
├── bin/
│   ├── init-master-key.js  # マスターキーの作成
│   └── make-cert.js        # 自己署名証明書の作成（openssl を呼ぶ）
├── test/core.test.js       # node --test test/core.test.js
├── docs/crypto.md          # 暗号設計と脅威モデル
└── data/                   # 利用者のデータ（.gitignore 対象）
    ├── users/<id>.json
    ├── vaults/<vaultId>/vault.json
    ├── vaults/<vaultId>/items/<itemId>.json
    └── audit/YYYY-MM.jsonl
```

## 立ち上げ方

### 1. マスターキーを作る

```bash
sudo node bin/init-master-key.js
sudo chown keybox /etc/keybox/master.key
sudo chmod 400 /etc/keybox/master.key
```

**このファイルを失うと、保存したパスワードは誰にも復号できない。**
KeyBox のデータとは別の場所にバックアップを取る。

起動ごとに人手でアンロックしたい場合は、キーファイルの代わりに
`KEYBOX_MASTER_PASSPHRASE` を渡す（systemd での自動起動はできなくなる）。

### 2. TLS を用意する

```bash
node bin/make-cert.js keybox.example.local 192.168.1.50
```

社内 CA の証明書が取れるならそちらを使う（ブラウザの警告が出ない）。
Nginx で TLS を終端する場合は `keybox.ini` で `tls = off`、`trustProxy = on`、
`host = 127.0.0.1` にする。

HTTPS にしておく理由は2つ。通信の保護と、
`navigator.clipboard`（パスワードのコピー）が HTTPS でしか動かないこと。
自己署名でも、警告画面を通したあとは HTTPS として扱われるのでコピーは動く。

### 3. 設定して起動

```bash
cp keybox.ini.example keybox.ini
node server.js
```

ブラウザで開くとセットアップ画面になり、最初の管理者を作る。

### 環境変数

| 変数 | 意味 |
|---|---|
| `KEYBOX_PORT` / `KEYBOX_HOST` | 待ち受け |
| `KEYBOX_TLS` / `KEYBOX_TLS_KEY` / `KEYBOX_TLS_CERT` | TLS |
| `KEYBOX_DATA_DIR` | データの置き場所 |
| `KEYBOX_MASTER_KEY_FILE` | マスターキーのファイル |
| `KEYBOX_MASTER_PASSPHRASE` | パスフレーズ運用（キーファイルより優先） |
| `KEYBOX_CONFIG` | 設定ファイルの場所 |
| `DEBUG=keybox:*` | 詳細ログ（`keybox:auth`、`keybox:crypto` などで絞れる） |

## 権限

### Vault 単位

| ロール | できること |
|---|---|
| viewer | アイテムを見る（秘密の復号を含む） |
| editor | viewer + アイテムの作成・更新・削除 |
| owner | editor + Vault 設定の変更・メンバー管理・Vault の削除 |

### アプリ全体

| ロール | できること |
|---|---|
| member | 自分が入っている Vault だけ |
| admin | + ユーザー管理、監査ログの閲覧 |

**admin は他人の Vault に自動ではアクセスできない。**
持ち主が不在のときは「緊急アクセス」で自分を owner に加えられるが、
理由の入力が必須で、監査ログに `break_glass` として残る。

## テスト

```bash
node --test test/core.test.js
```

確かめているのは主にこれ:

- 別 Vault・別アイテム・別フィールド・古い世代の暗号文を貼り替えても復号できない
- 暗号文を1バイト変えると復号できない
- パスワードの平文・メモの平文がディスクに残らない
- pepper が違うとパスワード照合が通らない
- viewer は書けない、メンバーでない人は読めない、editor はメンバーを足せない
- 最後の owner は外せない
- 監査ログに秘密そのものが載らない
- TOTP が RFC 6238 のテストベクタと一致する

## 既知の制約

1. セッションはインメモリなので、サーバーを再起動すると全員ログアウトになる
   （金庫としては望ましい性質として受け入れている）
2. 単一プロセスで動かす前提。複数プロセスにするとセッションとファイルの直列化が壊れる
3. `style-src` は `'unsafe-inline'` を許している（Bootstrap のモーダルと強度メーターのため）。
   `script-src` は `'self'` のまま
4. アイテムのメタデータは平文。「どのサイトのアカウントを持っているか」は `data/` から読める
