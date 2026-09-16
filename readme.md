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
- 複数の Vault と、**Vault 単位の共有**（owner / editor / viewer）。人ごとにも、**グループ**ごとにも共有できる
- ログイン情報・サーバー・カード・セキュアメモの保存
- **SSH 鍵の管理**（貼り付け・生成・公開鍵とフィンガープリントの自動割り出し・authorized_keys 用の1行）
- **Chrome 拡張**（見ているサイトのログイン情報を探して入力、パスワードと TOTP のコピー）
- パスワード、TOTP シークレット、セキュアメモ、SSH 秘密鍵、カスタムフィールドの暗号化
- TOTP（ワンタイムパスワード）の表示
- パスワード生成器と強度の目安
- タイトル・ユーザー名・URL・タグの横断検索
- 監査ログ（誰がいつどのアイテムのどのフィールドを見たか）
- 無操作での画面ロック
- **ログイン中の端末**の一覧と切断（画面・Chrome 拡張・CLI の別、最後の操作、接続元）
- **CLI**（`bin/passport`。`passport read "Vault/アイテム"` で秘密を1つ出す）と、cron などから使う**自動化トークン**（Vault を限定・読み取りだけ・期限必須）
- **点検**（弱い・使い回し・1年以上変えていないパスワード、ローテーション周期と有効期限の期限切れ・期限間近。期限はナビのバッジにも出る）
- **自分の履歴**（自分の操作、自分のアカウントへのログイン試行やパスワードのリセット、自分が owner の Vault でほかの人が見た・コピーした記録）

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

### SSH エージェント

鍵をファイルに書き出さずに ssh したいときは、CLI の SSH エージェントを使う。

```bash
bin/passport login --url https://passport.example.local --ca tls/server.crt
eval "$(bin/passport ssh-agent)"          # 既定で 8 時間。--lifetime 30m / 2h など（最長 24h）。--vault 本番 で絞れる
ssh-add -l                                # 読める Vault の SSH 鍵が並ぶ
ssh user@server
eval "$(bin/passport ssh-agent -k)"       # 止める
```

- 起動時に、読める Vault の SSH 鍵を取り出して手元のメモリに持ち、署名は手元で行う。Passport が落ちていても使える
- 取り出しは鍵ごとに監査ログに残る。個々の署名は残らない
- 寿命が来たら鍵を捨てて終わる。その前に Passport で権限を外す・トークンを失効させる・鍵を差し替えても、起動中のエージェントの鍵は消えない（`-k` で止める）
- 対応: ed25519 / RSA（rsa-sha2-256・512）/ ECDSA。パスフレーズで暗号化された OpenSSH 形式の鍵は読めないので飛ばす
  （`ssh-keygen -p` で外してから預け直すか、PEM 形式で預ける）

## CLI と自動化トークン

`bin/passport` は Node の標準ライブラリだけで動く。サーバーと同じリポジトリを手元に置くか、
`bin/passport` だけをコピーして使う（SSH エージェントも使うなら `lib/sshagent.js` と `lib/sshkeys.js` も、`bin/` と `lib/` の並びのままコピーする）。

```bash
# 人: 対話ログイン（自己署名なら --ca で証明書を渡す）
bin/passport login --url https://passport.example.local --ca tls/server.crt
bin/passport vaults
bin/passport ls 共通インフラ
bin/passport read "共通インフラ/vCenter"            # password
bin/passport read "共通インフラ/vCenter/username"
bin/passport totp "共通インフラ/vCenter"
bin/passport logout

# スクリプトから（パイプでは末尾に改行を付けない）
export PGPASSWORD="$(bin/passport read '本番/DB')"
```

自動化（cron・デプロイ）は、金庫の画面の右上メニュー「自動化トークン」で発行したトークンを使う。
Vault を選び、期限（最長1年）を決める。発行できるのは、選んだ Vault すべての owner。

```bash
# トークンは 0600 のファイルに置いて渡す（コマンドラインに書くとシェルの履歴に残る）
install -m 600 /dev/null ~/.config/passport/deploy.token && vi ~/.config/passport/deploy.token
PASSPORT_URL=https://passport.example.local PASSPORT_CA=/etc/passport/ca.crt \
PASSPORT_TOKEN_FILE=~/.config/passport/deploy.token bin/passport read "本番/DB"
```

- 発行するときに、自分のパスワードをもう一度入れる
- トークンでできるのは、選んだ Vault の読み出しだけ（書き込み・ほかの Vault・管理はできない）
- 発行した人がパスワードを変える・管理者にリセットされる・無効化されると、その人のトークンは全部失効する
- 発行した人が、その Vault の owner でなくなる・無効化されると、トークンも使えなくなる
- 読み出しはトークンの名前付きで監査ログに残る。管理画面の「自動化トークン」で全部を見て失効させられる
- 使わないなら `passport.ini` の `[cli] enabled = off`（人の CLI）/ `tokens = off`（自動化トークン）で止める
  （`enabled = off` は利便のスイッチで、境界ではない。docs/crypto.md を読む）

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

### 入力欄のそばのメニュー

入力欄を選ぶと、そのそばに候補のメニューが出る。選ぶと **その欄が属するフォームだけ**が埋まる。
同じページにログインフォームが複数あっても、選んだ場所だけが入る。

これにはページの中で動く仕組み（content script）が要るので、**既定では動かない**。
使いたいときに本人が許可する。

- **サイトごと**: そのサイトを開いて、ツールバーの Passport アイコン →「有効にする」
- **すべてのサイト**: 拡張の設定画面のトグル（Chrome の権限表示が
  「すべてのサイトのデータの読み取りと変更」に変わる）

許可した origin にだけ `chrome.scripting.registerContentScripts` で登録する。
許可を外せば登録も外れる。

**金庫の画面自体は `excludeMatches` で外している。** ここに content script が載ると、
金庫のログイン画面で入力された**マスターパスワード**を「保存しますか」の預かりとして
拾ってしまうため。match pattern にポートは書けないので、除外はホスト名単位になる
（金庫のホストで別のサイトを動かしている場合、そちらでもメニューは出ない）。
念のため、background 側でも「送り主が金庫のホストなら答えない」を入れてある。

金庫がロックされているときは、メニューに「ロックされています」と出す。
**ツールバーからログインすると、開いているページはその場で候補に変わる**
（ページを読み込み直す必要はない）。ロックしたときも同じように伝わり、
開いているメニューは閉じる。

メニューまわりで効かせていること（**3枚重ねている**。1枚では足りないことが分かったため）:

1. **メニューは closed な Shadow DOM の中に作る。** ページ側の JS から中身を掴めない。
   ただし `closed` が守るのはそこまでで、**ホスト要素自体はページのツリーにいる普通の div** なので、
   ページの `!important` で透明化・移動できてしまう。そこで**ホスト要素の危ない性質
   （opacity / transform / filter / visibility など）を、インラインの `!important` で毎回押さえ直す**。
   インラインの `!important` は、ページの `!important` よりも強い
2. **メニューを開くのは、直前に本物の操作（クリック・キー・タッチ）があったときだけ。**
   ページが `element.focus()` を呼んで発生する focusin は `isTrusted === true` になるので、
   `isTrusted` を見るだけでは「ページが勝手に開く」を止められない
3. **埋める直前に、その座標が本当に自分の行で、目に見える形で出ているかを確かめる。**
   ページは祖先（body など）に opacity や filter を掛けることでも隠せるので、
   ホスト要素を押さえるだけでは足りない。祖先まで遡って実効的な不透明度を確かめ、
   `elementFromPoint` がその座標で自分を返すことも見る
- 埋めるのは **`isTrusted` な操作のときだけ**。ページが script からクリックを投げても動かない
- **どのサイトの候補を出すかは、content script の言い分ではなく sender の origin で決める。**
  ページが細工をしても、別のサイトの資格情報は引き出せない
- 入力を頼まれたときも、そのアイテムがそのホストの候補に入っているかを background 側で確かめる
- メニューに出るのはタイトルとユーザー名まで。パスワードは選んだ瞬間に取りに行く

### ログインの保存を勧める

まだ登録の無いサイトでログインすると、「保存しますか」のバーが出る。
保存先の Vault とタイトルを選んで保存できる。

判定は3つに分かれる。

| 金庫の中身 | どうするか |
|---|---|
| ユーザー名もパスワードも同じものがある | **何も聞かない** |
| ユーザー名は同じだが、パスワードが違う | 「更新しますか」（新しく作らず、そのアイテムのパスワードだけ差し替える） |
| 同じユーザー名が無い | 「保存しますか」 |

ユーザー名の突き合わせは大文字小文字を区別しない
（`MoomA@example.local` と `mooma@example.local` を別物として二重に登録しない）。

パスワードが同じかどうかは、**保管してある平文を拡張へ渡さずに確かめる**。
サーバーに「この値は保管してあるものと同じか」を聞く口（`/verify`）があり、
返るのは真偽だけ。呼ぶ側は候補の値を既に持っているので、これで新しく漏れるものはない。
監査ログには閲覧とは別の種別（`item.verify_secret`）で残るので、
「見た」記録を薄めない。

拾い方:

- フォームの `submit`
- ログインらしいボタンの押下（`submit` を出さない作りのページ向け）
- 入力欄での Enter

見送る場合:

- パスワード欄が2つあって値が違うとき（新規登録やパスワード変更の画面とみなす）
- 「このサイトでは聞かない」を選んだサイト（設定画面で一覧の確認と取り消しができる）
- 設定でこの機能を切っているとき

**預かりについて。** ページは送信直後に遷移して消えるので、本人が決めるまでの間、
入力された値をどこかに置いておく必要がある。置き場は `chrome.storage.session`
（ディスクに残らず、ブラウザを閉じれば消える）で、

- **2分で期限切れ**として扱う（期限の掃除は次に触ったときに行うので、
  何も触られなければタブを閉じるかブラウザを閉じるまで残る。ディスクには書かれない）
- 保存か却下が決まった時点で消す
- タブを閉じたら消す
- 金庫をロックしたら全部消す
- 捉えたのと**同じサイト**にいるときしか出さない（別のサイトへ遷移した先で、
  よそのパスワードの保存を勧めない）
- **いちばん外側のページからしか受け付けない。** iframe の中のログインフォームでは保存を勧めない
  （入力のメニューは出る）。広告などの iframe が、正規のページの預かりを上書きして提案を黙らせるのを防ぐため

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
| `https://bank.example.local` | `http://bank.example.local` | **出ない**（https の登録は http のページに出さない） |
| `bank.example.local`（スキームなし） | `http://bank.example.local` | 出る |

誤爆は「別のサイトへパスワードを差し出すこと」なので、判定は厳しめに倒している。

## 失ったものを戻す

- **パスワード履歴**: 秘密を上書き・削除すると、前の値をフィールドごとに最大10世代残す。
  詳細画面の「過去の値」から取り出せる（取り出すと監査ログに残る）
- **ゴミ箱**: アイテムを削除するとゴミ箱へ移る。戻すとパスワードも履歴もそのまま戻る。
  完全に削除できるのは Vault の owner だけ。ゴミ箱に残っている Vault は消せない
  （Vault を消すと鍵ごと消え、ゴミ箱の中身も二度と復号できなくなるため）
- **更新には version が必要**: 2人が同時に同じアイテムを編集したら、後の方は弾かれる。
  以前は version を省くと検査されず、黙って上書きされていた

## バックアップと復旧

**データとマスターキーは、必ず別々に、別の媒体へ保管する。**
同じ場所に置くと、バックアップが流出したときに暗号化の意味が無くなる。

### 取る

```bash
node bin/backup.js /path/to/backups
```

- 稼働中に取ってよい（書き込みはファイル単位で原子的なので、半端な JSON を掴まない）
- 出力は `passport-data-YYYYMMDD-HHMMSS.tar.gz` と、件数・鍵の指紋・SHA-256 を書いた `.json`
- **マスターキーは含まれない**
- 書きかけの一時ファイル（`*.tmp-*`）は含めない

マスターキー（`/etc/passport/master.key`）は、**初回に1回**、別の媒体へコピーしておく。
キーは作り直さない限り変わらないので、毎回取る必要はない。バックアップの `.json` に出る
「鍵の指紋」が、保管しているキーと同じかを時々確かめる。

### 戻す前に確かめる

```bash
node bin/verify-backup.js passport-data-XXXX.tar.gz --key /path/to/master.key
```

本番のデータには触らず、一時ディレクトリに展開して確かめる。

- ファイルが作ったときから変わっていないか（SHA-256）
- **そのマスターキーの世代が、データを作ったときのものと一致するか**
- すべての Vault の鍵を開けられるか、アイテムの JSON が壊れていないか

**「✗ このマスターキーでは開けません」と出たら、戻さないこと。**
マスターキーとデータの世代を取り違えて戻すと、全員のログインが失敗する。
そこで「データが壊れた」と誤診して作り直すと、正しいキーが後から見つかっても復旧できなくなる。

### 戻す

```bash
systemctl stop passport
mv /opt/passport/data /opt/passport/data.before-restore   # 消さずに退避する
tar --extract --gzip --file passport-data-XXXX.tar.gz --directory /opt/passport
chown -R passport: /opt/passport/data
systemctl start passport
```

起動時に、鍵の世代とデータの状態を点検する。合わなければ起動を止め、理由を出す
（`journalctl -u passport`）。Vault が共有先にしているグループが見つからないときは、起動は止めずに警告を出す。

**古いバックアップを戻すと、そのあとの変更も巻き戻る。** 失効させた自動化トークン、グループから外した人、
変えたパスワードも元に戻り、その記録（監査ログ）も `data/` の中なので一緒に巻き戻る。戻したら次を確かめる:

- 管理画面の「自動化トークン」で、戻した時点より後に失効させたはずのものを失効させ直す
- グループと Vault のメンバーを見直す
- 手がかりは、退避した `data.before-restore/audit/` に残っている

### systemd で動かす

`deploy/passport.service` に例がある。起動時の点検で止まった場合は、何度起動し直しても
同じなので、`RestartPreventExitStatus=1` で繰り返さないようにしてある。

## まだ無いもの

- 1Password / CSV からのインポートと、エクスポート
- 拡張からの SSH 鍵やセキュアメモの登録（保存を勧めるのはログイン情報だけ）
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
│   ├── popup.html/.js/.css # このページの候補と、全体の検索
│   ├── options.html/.js    # サーバーの場所と、インラインメニューの許可
│   ├── api.js              # Bearer トークンでのやり取り
│   ├── content.js          # 入力欄のそばのメニューと、保存を勧めるバー
│   ├── fill.js             # popup から注入する入力処理
│   └── background.js       # content script の登録と、その問い合わせ先
├── bin/
│   ├── init-master-key.js  # マスターキーの作成
│   ├── make-cert.js        # 自己署名証明書の作成（openssl を呼ぶ）
│   ├── backup.js           # data/ のバックアップ（tar を呼ぶ。マスターキーは含めない）
│   ├── verify-backup.js    # 戻す前に、マスターキーとの組み合わせを確かめる
│   └── make-icons.js       # 拡張のアイコン（PNG を自前で書き出す）
├── deploy/passport.service # systemd の unit の例
├── test/                   # node --test
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
| `PASSPORT_CLI` / `PASSPORT_AUTOMATION_TOKENS` | `[cli] enabled` / `tokens` の上書き（on / off） |
| `DEBUG=passport:*` | 詳細ログ（`passport:auth`、`passport:crypto` などで絞れる） |

CLI（`bin/passport`）が読む環境変数:

| 変数 | 意味 |
|---|---|
| `PASSPORT_URL` / `PASSPORT_CA` | 接続先と、自己署名の証明書（`--url` / `--ca` と同じ） |
| `PASSPORT_TOKEN_FILE` | 自動化トークンを書いた 0600 のファイル（勧める） |
| `PASSPORT_TOKEN` | 自動化トークンそのもの（シェルの履歴に残りやすい） |
| `PASSPORT_ALLOW_HTTP=1` | 手元以外への `http://` を許す（`--allow-http` と同じ） |
| `XDG_CONFIG_HOME` | 設定とセッションの置き場所（既定は `~/.config/passport/`） |
| `SSH_AGENT_PID` | `passport ssh-agent -k` が止める相手 |

## 権限

### Vault 単位

| ロール | できること |
|---|---|
| viewer | アイテムを見る（秘密の復号を含む） |
| editor | viewer + アイテムの作成・更新・削除 |
| owner | editor + Vault 設定の変更・メンバー管理・Vault の削除 |

人に直接付けたロールと、その人が入っているグループに付けたロールのうち、**一番強いもの**が効く。

### グループ

- グループを作る・人を出し入れする・消すのは **admin**。グループを Vault の共有先に足す・外すのは、その **Vault の owner**
- グループから人を外すと、そのグループ経由で入っていた Vault には、その場で入れなくなる
- 共有先として使われているグループは消せない（先に Vault 側から外す）
- **グループに付けられるのは viewer と editor だけ。owner は人にだけ付く。**
  グループの中身は admin が決めるので、グループに owner を付けられると、admin が緊急アクセスを通らずに
  「Vault を乗っ取れる人」（自分を個人の owner に足し、元の owner を外す）を作れてしまうため
- Vault の owner には、共有先のグループに誰が入っているかが見える（viewer / editor には人数だけ）
- **admin は自分自身をグループに入れられない。** 緊急アクセス（理由が必須）を通らずに Vault の中を
  見られてしまうため。ただしこれは「うっかり」を防ぐもので、境界ではない（ユーザーを作って入れる、
  別の admin と入れ合う、で迂回できる。admin を信頼する前提で受け入れている。どれも監査ログには残る）。
  グループに人を入れたときの監査ログには、見られるようになった Vault の名前が残る
- 無効化されているユーザーはグループに入れられない

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
- グループ経由でも見られる・検索に出る・拡張の候補に出て、グループから外すとその場で見えなくなる
- グループに owner は付けられず、ファイルに書かれていても editor として扱う。グループ経由の editor は
  完全削除・Vault の削除・共有の変更ができない
- admin は自分をグループに入れられない、使われているグループは消せない、消えたグループの ID は誰にも権限を与えない
- 自動化トークンが /api/automation/ の外（パスの書き方を変えても）・対象外の Vault・書き込みに届かない。失効・期限切れ・発行者の権限の変更・無効化で即座に使えなくなる。サーバーに秘密が残らない
- SSH エージェントの鍵の一覧と署名を、本物の ssh-add / ssh-keygen -Y verify が受け付ける（ed25519 / RSA / ECDSA）。SHA-1 の RSA 署名・鍵の追加・壊れたメッセージを断り、寿命と -k でソケットごと消える
- CLI のセッションファイルが 0600 で、ほかの人から読める権限なら使わない。自己署名の証明書を --ca なしでは信用しない
- 点検が、editor 以上の Vault だけを調べ、ほかの Vault との一致・値・ハッシュを出さず、data/ に何も残さない。監査ログに書けなければ結果を返さない
- ログイン中の端末の一覧にセッション ID が出ない、他人の端末は切れない、切った端末は 401 になる
- 自分の履歴に、editor / viewer として入っている Vault でのほかの人の操作や、ほかの人の接続元が出ない
- 監査ログに秘密そのものが載らない
- TOTP が RFC 6238 のテストベクタと一致する
- 生成した SSH 秘密鍵を `ssh-keygen -y` が読めて、公開鍵とフィンガープリントが一致する
- パスフレーズ付きの鍵でも、パスフレーズ無しで公開鍵を取り出せる
- SSH 秘密鍵とパスフレーズがディスクに平文で残らない
- オートフィルの照合が、別ドメインや親子逆転に釣られない
- 許可していない拡張 ID には CORS ヘッダーを返さない

拡張そのものは Chromium に読み込んで通しで確かめている（`--load-extension` が使えるため）。
インラインメニューが出ること、選んだフォームだけが埋まること、ページ側から
closed shadow の中を掴めないこと、ログインを捉えて保存のバーが出てから
実際に金庫へ登録されるところまで見ている。

## 既知の制約

1. セッションはインメモリなので、サーバーを再起動すると全員ログアウトになる
   （金庫としては望ましい性質として受け入れている）
2. 単一プロセスで動かす前提。複数プロセスにするとセッションとファイルの直列化が壊れる
3. `style-src` は `'unsafe-inline'` を許している（Bootstrap のモーダルと強度メーターのため）。
   `script-src` は `'self'` のまま
4. アイテムのメタデータは平文。「どのサイトのアカウントを持っているか」は `data/` から読める
