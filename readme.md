# Passport

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

| WordBox が使っているもの | Passport での代わり |
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
- **SSH 鍵の管理**（貼り付け・生成・公開鍵とフィンガープリントの自動割り出し・authorized_keys 用の1行）
- **Chrome 拡張**（見ているサイトのログイン情報を探して入力、パスワードと TOTP のコピー）
- パスワード、TOTP シークレット、セキュアメモ、SSH 秘密鍵、カスタムフィールドの暗号化
- TOTP（ワンタイムパスワード）の表示
- パスワード生成器と強度の目安
- タイトル・ユーザー名・URL・タグの横断検索
- 監査ログ（誰がいつどのアイテムのどのフィールドを見たか）
- 無操作での画面ロック

## SSH 鍵

アイテムの種別に「SSH 鍵」がある。

- 手元の鍵を貼る（OpenSSH 形式・PEM 形式どちらでも）か、その場で作る（ed25519 / RSA 3072 / RSA 4096）
- 貼るか作るかすると、**鍵種別・ビット数・公開鍵・フィンガープリントが自動で埋まる**
- **パスフレーズが掛かったままの鍵でも登録できる。** OpenSSH 形式は暗号化されていても
  公開鍵の部分が平文なので、パスフレーズを預けなくてもフィンガープリントまで取れる
- 秘密鍵とパスフレーズは暗号化して保管。公開鍵とフィンガープリントは平文
  （公開してよいものだし、一覧で見比べたり authorized_keys へ貼るのに毎回復号したくない）
- 詳細画面から、公開鍵のコピー、authorized_keys 用の1行のコピー、秘密鍵のファイル保存ができる
- フィンガープリントで検索できる（「このサーバーに入っている鍵はどれだ」を探すため）

Node は OpenSSH 形式の秘密鍵を読めない（`createPrivateKey` が
`DECODER routines::unsupported` で落ちる）ので、`lib/sshkeys.js` で
OpenSSH のワイヤ形式を自前で読み書きしている。
作った鍵が本物として通用することは、`ssh-keygen -y` に読ませて公開鍵が一致するかで確かめている
（`test/sshkeys.test.js`）。

生成した鍵にパスフレーズは掛けていない。掛けるには bcrypt_pbkdf が要り、標準ライブラリだけでは重い。
Passport 側が保管時に暗号化しているので、掛けたい場合は取り出したあとに
`ssh-keygen -p -f <ファイル>` を使う。

## Chrome 拡張

`extension/` にある。見ているサイトのログイン情報を探して、フォームに入れる。

### 入れ方

1. Chrome で `chrome://extensions` を開き、右上の「デベロッパーモード」を入れる
2. 「パッケージ化されていない拡張機能を読み込む」で `extension/` を選ぶ
3. 拡張の ID が `iookbapfomcndnncbdohnhblclbhmfoc` になっていることを確認する
   （`manifest.json` の `key` で固定してあるので、この値になる）
4. 拡張の「⚙️」から Passport サーバーの URL を入れて保存する
   （そのサーバーへ通信する許可をここで求められる）
5. ツールバーのアイコン（または Ctrl+Shift+L）から金庫にログインする

サーバー側は `passport.ini` の `[extension] allowedIds` がこの ID を許可している必要がある。
既定値のままなら一致している。

> `--load-extension` のコマンドライン指定は、製品版 Chrome では無視される
> （`--load-extension is not allowed in Google Chrome` と出る）。
> 上の手順どおり画面から読み込むこと。自動テストは Chromium で動かしている。

### 認証のしかた

拡張は Cookie ではなく `Authorization: Bearer <トークン>` を使う。

Cookie にすると、金庫にログイン中のブラウザで開いた別サイトから API を叩ける経路ができてしまう
（サーバーは拡張からの呼び出しに CSRF 検証をしないため）。
Bearer なら、トークンを持っている拡張からしか通らない。

- トークンを返すのは、**許可した拡張の Origin から来たログインだけ**。画面には返さない
  （画面は HttpOnly Cookie で動いているので、JavaScript から読めるトークンを渡すとその守りを外すことになる）
- トークンの置き場は `chrome.storage.session`。ブラウザを閉じると消える
- CORS は許可した拡張 ID にだけ返し、`Allow-Credentials` は付けない

### この拡張がしないこと

- **ページを開いただけでは何もしない。** 入力はボタンを押したときだけ（`activeTab` 権限）。
  常駐する content script を置いていないので、拡張が勝手にページを読むことはない
- **フォームを勝手に送信しない。** 入れるところまでで止める
- **見えていない入力欄には入れない。** 隠しフォームで持っていかれるのを避けるため
- パスワードを拡張側に保存しない

### どのアイテムを出すか

今見ているホストと、アイテムに登録された URL のホストを突き合わせる。

| 登録された URL | 見ているサイト | 出るか |
|---|---|---|
| `example.local` | `example.local` | 出る（完全一致） |
| `example.local` | `git.example.local` | 出る（サブドメイン） |
| `git.example.local` | `example.local` | **出ない** |
| `example.local` | `example.local.attacker.test` | **出ない** |
| `example.local` | `notexample.local` | **出ない** |

誤爆は「別のサイトへパスワードを差し出すこと」なので、判定は厳しめに倒している。

## まだ無いもの

- バックアップとリストアの仕組み（`tar` を呼ぶだけだが未実装）
- 1Password / CSV からのインポートと、エクスポート
- パスワードの使い回し・古さのチェック
- 拡張からの新規保存（今は読み取りと入力だけ。金庫への登録は画面から）
- 拡張のショートカットからの直接入力（popup を開く操作を起点にしている。
  常時どのページにも入れる権限を持たせないため）
- E2E 暗号（今は採っていない。理由と将来の移行先は `docs/crypto.md`）

## セキュリティの立ち位置

**「サーバーは知っているが、盗まれたファイルは何も語らない」**

1Password のようなゼロ知識ではない。サーバーがマスターキーを持っているので、
稼働中のサーバーの root を取れる人は中身を読める。
そのかわり `data/` やバックアップが流出しても、パスワードは AES-256-GCM の暗号文でしかない。

受け入れたリスクと、それを選んだ理由は **`docs/crypto.md`** に全部書いてある。
実装を変える前に必ず読む。

要点だけ:

- マスターキーは `data/` の外（既定 `/etc/passport/master.key`、モード 0400）
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
│   ├── config.js           # passport.ini + 環境変数
│   ├── logger.js           # 名前空間つきログ（DEBUG=passport:*）
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
│   ├── sshkeys.js          # OpenSSH 形式の読み書き、鍵の生成、フィンガープリント
│   ├── audit.js            # 追記専用の監査ログ
│   └── api.js              # JSON API
├── templates/              # layout / login / setup / app / admin
├── static/                 # style.css, common.js, app.js, admin.js, Bootstrap
├── extension/              # Chrome 拡張（MV3）
│   ├── manifest.json       # key で拡張IDを固定している
│   ├── popup.html/.js/.css # ログインと一覧
│   ├── options.html/.js    # サーバーの場所の設定
│   ├── api.js              # Bearer トークンでのやり取り
│   ├── fill.js             # ページへ注入する入力処理
│   └── background.js       # service worker（起動時にロック）
├── bin/
│   ├── init-master-key.js  # マスターキーの作成
│   ├── make-cert.js        # 自己署名証明書の作成（openssl を呼ぶ）
│   └── make-icons.js       # 拡張のアイコン（PNG を自前で書き出す）
├── test/                   # node --test test/
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
sudo chown passport /etc/passport/master.key
sudo chmod 400 /etc/passport/master.key
```

**このファイルを失うと、保存したパスワードは誰にも復号できない。**
Passport のデータとは別の場所にバックアップを取る。

起動ごとに人手でアンロックしたい場合は、キーファイルの代わりに
`PASSPORT_MASTER_PASSPHRASE` を渡す（systemd での自動起動はできなくなる）。

### 2. TLS を用意する

```bash
node bin/make-cert.js passport.example.local 192.168.1.50
```

社内 CA の証明書が取れるならそちらを使う（ブラウザの警告が出ない）。
Nginx で TLS を終端する場合は `passport.ini` で `tls = off`、`trustProxy = on`、
`host = 127.0.0.1` にする。

HTTPS にしておく理由は2つ。通信の保護と、
`navigator.clipboard`（パスワードのコピー）が HTTPS でしか動かないこと。
自己署名でも、警告画面を通したあとは HTTPS として扱われるのでコピーは動く。

### 3. 設定して起動

```bash
cp passport.ini.example passport.ini
node server.js
```

ブラウザで開くとセットアップ画面になり、最初の管理者を作る。

### 環境変数

| 変数 | 意味 |
|---|---|
| `PASSPORT_PORT` / `PASSPORT_HOST` | 待ち受け |
| `PASSPORT_TLS` / `PASSPORT_TLS_KEY` / `PASSPORT_TLS_CERT` | TLS |
| `PASSPORT_DATA_DIR` | データの置き場所 |
| `PASSPORT_MASTER_KEY_FILE` | マスターキーのファイル |
| `PASSPORT_MASTER_PASSPHRASE` | パスフレーズ運用（キーファイルより優先） |
| `PASSPORT_CONFIG` | 設定ファイルの場所 |
| `DEBUG=passport:*` | 詳細ログ（`passport:auth`、`passport:crypto` などで絞れる） |

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
node --test
```

（`node --test test/` はディレクトリをモジュールとして読もうとして失敗する。
引数なしか `node --test test/*.test.js` を使う）

確かめているのは主にこれ:

- 別 Vault・別アイテム・別フィールド・古い世代の暗号文を貼り替えても復号できない
- 暗号文を1バイト変えると復号できない
- パスワードの平文・メモの平文がディスクに残らない
- pepper が違うとパスワード照合が通らない
- viewer は書けない、メンバーでない人は読めない、editor はメンバーを足せない
- 最後の owner は外せない
- 監査ログに秘密そのものが載らない
- TOTP が RFC 6238 のテストベクタと一致する
- 生成した SSH 秘密鍵を `ssh-keygen -y` が読めて、公開鍵とフィンガープリントが一致する
- パスフレーズ付きの鍵でも、パスフレーズ無しで公開鍵を取り出せる
- SSH 秘密鍵とパスフレーズがディスクに平文で残らない
- オートフィルの照合が、別ドメインや親子逆転に釣られない
- 許可していない拡張 ID には CORS ヘッダーを返さない

## 既知の制約

1. セッションはインメモリなので、サーバーを再起動すると全員ログアウトになる
   （金庫としては望ましい性質として受け入れている）
2. 単一プロセスで動かす前提。複数プロセスにするとセッションとファイルの直列化が壊れる
3. `style-src` は `'unsafe-inline'` を許している（Bootstrap のモーダルと強度メーターのため）。
   `script-src` は `'self'` のまま
4. アイテムのメタデータは平文。「どのサイトのアカウントを持っているか」は `data/` から読める
