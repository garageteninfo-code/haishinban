# 配信番（SafeRollout）0.2.0 — 少しずつ配って、落ちたら止める・戻す

Windows の業務アプリ（WinForms / WPF など）を自社のサーバーから配っている方のための、**配信の安全セット（試作版）**です。
外部のクラウドを使わず、社内のネットワークの中だけで動きます。

> **試作版です。** 本物の利用者・本物の業務の環境での導入の実績はまだありません。最初は検証用の PC で試してください。
> これは認証・認定・保証ではありません。個人情報の検出は完全ではありません（下の「測った数字」と「限り」をご覧ください）。

- 提供：HARVEST（ハーベスト）／お問い合わせ：garageten.info@gmail.com（旧称 GARAGE TEN のときのアドレスです）
- 料金：無料（現在）
- ライセンス：**All rights reserved**（松岡颯大（HARVEST））。閲覧と、自分・自分の会社の中で道具として使うこと（仕事で使うことを含む）は無料です。写して配る・売る・変えて配る・ほかの製品に組み込むには、事前の書面の許可が要ります（お問い合わせは上のアドレスへ）→ [`LICENSE`](LICENSE)
- 利用条件：[`利用条件.md`](利用条件.md)（英語：[`TERMS-en.md`](TERMS-en.md)）
- 導入の手順：[`導入手順書.md`](導入手順書.md)

---

## だれのためか

- 自社のサーバーから Windows の業務アプリを配っている、小さな受託開発の会社・社内 SE
- 元請け・親会社の閉じたネットワークへアプリを納めていて、「安全な更新と戻しの手順」を先方に示す必要がある**下請けの開発会社**（導入手順書 10 章に、先方に示す表の例があります）
- 親会社の決まり（外部のクラウド不可・親会社の認証局の証明書・管理は決まった PC だけ）の中で社内アプリを配る**子会社の情報システム部門**
- 工場・病院・自治体のように、外のクラウドを使えないネットワークで配っている所

## 何をするか

| 部品 | すること |
|---|---|
| 更新の安全キット（C#・.NET の標準だけ）`csharp/UpdateSafetyKit/` | 署名つきの配信情報（通し番号・期限つき）を確かめる／段階配信（10% など）／取り下げた版を配らない／起動から 10 分以内に 2 回落ちたら前の版へ戻す判定／日本語の利用者名のパスでも動く適用・戻しの手順 |
| 報告の中継（Node.js だけ・`npm install` 不要）`server.mjs` | アプリからの不具合報告を受け、**個人情報・鍵が入っていれば受け取らずに断る**（422。中身は保存しない） |
| 管理画面 `console/` | 版ごとの「落ちる割合」を表示し、基準を超えたら知らせる。「配信を止める（0%）」「この版を取り下げる」の配信情報を**ブラウザの中で署名**して載せる（署名の秘密鍵はサーバーへ送らない）。合言葉でログイン |
| アプリ側の報告の送り手（C#）`CrashReporter` | 起動の知らせと落ちた報告を、**先に PC の中で伏せ字**にしてから送る。画面を止めない。断られたら欄を伏せて送り直す |
| 中継との通信（C#）`HaishinHttp` | https・証明書の指紋の固定（社内の認証局の証明書も可）。プロキシは使わない |
| WinForms のサンプル `sample-app/` | 架空の「在庫管理」アプリ。組み込み方の見本 |

## 動かし方

用意する物：Windows 10 / 11、Node.js 20 以上（試したのは 24）、アプリを作る PC に .NET 10 SDK、https を自己署名で行うなら openssl（Git for Windows に入っています）。外部のパッケージは使いません。

```
node server.mjs
```

→ この PC のブラウザで `http://127.0.0.1:38920/console/` を開き、初回は管理画面の合言葉（12 文字以上）を決めます。
https・社内の別の PC からの管理・アプリへの組み込みは [`導入手順書.md`](導入手順書.md) をご覧ください。設定の見本（`config.json`・`sample-app/sampleapp.example.json`）の値はすべて架空です。

### 試験

```
npm test
```

- `node --test` の試験です。.NET 10 SDK と openssl があれば、C# の部品と https も確かめます（無ければその部分を飛ばして、そう表示します）。
- 試験に使う鍵・証明書・合言葉は**実行のたびに作り、終わったら消します**（このリポジトリには鍵・証明書は入っていません）。試験のデータはすべて架空です。
- 「社内の別の PC から」の試験は、この PC の社内側の IP を使うため、環境変数 `HAISHIN_TEST_LAN=1` のときだけ行います（既定は飛ばします）。
- 利用者フォルダに入れた .NET を使う場合は、環境変数 `DOTNET_ROOT` を設定してください。

そのほか：

| 何 | コマンド | 備考 |
|---|---|---|
| 架空のアプリで最初から最後まで通す台本 | `node scenario/sample-scenario.mjs` | .NET 10 SDK を使う |
| C# キットの試験 | `cd csharp/kit-tests` → `node tests/xlang/make-vectors.mjs <作業フォルダ>/y.json` → `cd tests/UpdateSafetyKit.Tests` → `dotnet run -- <作業フォルダ>/y.json` | 環境変数 `USK_LIVE_DIR` を指定すると、そのフォルダで本物の cmd・robocopy の適用・戻しも試す |
| WinForms のサンプルの通しの試験 | `node scenario/e2e-gui.mjs` | **サンプルアプリの画面が何回も開いて閉じます**（最小化）。`npm test` には入れていません |

## 測った数字（開発中の PC の中で・2026-11-14〜15・データはすべて架空）

| 何を | 結果 |
|---|---|
| Node の試験（`npm test`） | 33 件中 32 件合格・1 件は既定で飛ばす（社内の IP を使う試験。開発中に社内側の IP で試したときは合格） |
| C# の送り手・伏せ字・指紋の固定の単体の試験 | 43 / 43 合格 |
| C# の送り手 → 本物の中継（https・同じ PC の中） | 4 / 4 合格（正しい指紋で届く／住所入りは 422 → 欄を伏せて送り直して届く／違う指紋では送らない・配信情報も取らない） |
| C# キットの試験 | 120 / 120 合格（本物の cmd と robocopy で、日本語・空白・`&` `'` `%` を含むフォルダでの適用→戻し 12 件を含む）。cmd・robocopy を使わない部分だけなら 108 / 108 |
| WinForms のサンプルの通しの試験 | 24 / 24 合格（画面つきのアプリを 18 回起動：10% に入る端末だけに「新しい版があります」→ 落ちた報告 → 基準超えの知らせ → 止める → 取り下げで戻しの判定 → 指紋の違うアプリは報告を送らない） |
| 報告の関門（個人情報・鍵の検出）を、別の人が作った初見の架空データ 130 件で | 断るべき 88 件中 **56 件（63.6%）** を断った・断ってはいけない 42 件中 **3 件（7.1%）** を誤って断った。**氏名は 19 件中 3 件（16%）しか見つけられない** |
| 無作為の業務の番号（各 2,000 件・3 回）を誤って断る割合 | 10・12・13・16 桁は 0%。11 桁は 0.1〜0.55%（「090」などで始まる番号を携帯電話と見るため） |

- 関門の測定に使ったデータは、このリポジトリには入っていません。
- 1 回だけ、何も組み立てていない状態からの初回の `npm test` で、C# の送り手の時間を見る試験（送り直しの待ち）が 1 件不合格になりました（組み立てで PC が重かったため）。続けて 4 回は合格しました。

## 限り（正直に）

- 本物の利用者・本物の業務の環境では試していません。
- サンプルで試したのは**判定と表示まで**です。ダウンロード → 適用 → 再起動 → 自動の戻しの一続きは、サンプルではまだつないでいません（適用と戻しは C# キットの試験だけ）。
- Windows だけです（適用・戻しの手順は cmd と robocopy）。WPF のサンプルはありません。
- 日本語の名前の本物の Windows アカウント、本物の別の PC からの管理画面は、試していません（日本語のフォルダ・同じ PC の社内側の IP で代わりに試しました）。
- **個人情報の検出は完全ではありません。** アプリ側の伏せ字は住所・敬称の無い氏名・生年月日を伏せません（中継が見つけたら 422 → 欄ごと伏せる、の 2 段構え）。中継の氏名の検出は 2 割前後です。例外の文に業務のデータ（顧客名など）を入れないコードの書き方が一番の対策です。
- 利用者の PC には .NET 10 デスクトップ ランタイムが要ります（自己完結の組み立ては試していません）。
- ログインは合言葉 1 つ・管理者 1 人です。複数の管理者・操作の記録・2 段階の確認はありません。中継を起動し直すと全員ログアウトします。
- 「配信を止める（0%）」は、すでにその版を入れた端末には効きません（戻すには「この版を取り下げる」）。
- https は任意です（既定は http）。http のままだと、社内の通信路で報告の中身や合言葉が読めます。
- 保存はファイルだけ（1 つの処理）。何千台の規模・同時の書き込みは試していません。
- 署名の鍵の入れ替え（複数の公開鍵）はありません。鍵をなくすと、その鍵を組み込んだアプリへ新しい配信情報を出せません。
- 証明書の期限切れの知らせ・自動の更新はありません。中継の Windows サービス化・バックアップの手順は未整備です。
- 端末を表す番号（`reporterId`）が、貴社の扱う個人情報の決まりでどう扱われるかは、貴社でご確認ください。この道具は法律の判断をしません。
- NuGet には登録していません（パッケージ名の予定：SafeRollout。中の名前空間は `UpdateSafetyKit`）。

## フォルダ

```
server.mjs / config.json   … 中継・更新の置き場・管理画面（node server.mjs）と設定
lib/                       … ログイン・関門（個人情報の検出）・報告の形・保存・配信情報の確かめ
console/                   … 管理画面（HTML・JS・CSS。外の読み込みなし）
tools/make-cert.mjs        … https 用の自己署名の証明書を作り、指紋を表示する（openssl を使う）
csharp/UpdateSafetyKit/    … C# の更新の安全キット・報告の送り手
csharp/HaishinVerify/      … 管理画面で署名した配信情報を C# のキットで確かめる小さな道具
csharp/kit-tests/          … C# の試験・共通の例・署名の道具
sample-app/                … WinForms のサンプル（架空の在庫管理）
scenario/                  … 台本（架空のデータで通す）と、試験から管理の口を使う道具
test/                      … node:test の試験
```

---

## English (summary)

*This English section was translated with AI.*

**Haishin-ban (SafeRollout) 0.2.0** is a prototype "safe rollout kit" for Windows line-of-business apps (WinForms/WPF) that companies distribute from their own servers, especially on closed networks where cloud services cannot be used.

- **What it does:** signed release manifests (sequence number + expiry), staged rollout (e.g. 10%), "halt (0%)" and "revoke this version", automatic rollback decision when a new version crashes twice within 10 minutes of start-up (C#, .NET standard library only). A small Node.js relay (no `npm install`, zero dependencies) receives crash reports and **refuses reports that contain personal data or secrets** (HTTP 422, content not stored). The browser console signs manifests in the browser; the private key is never sent to the server.
- **Who it is for:** small Japanese software contractors, subcontractors and subsidiary IT departments that ship Windows apps inside closed networks. The documentation is in Japanese.
- **How to run:** `node server.mjs`, then open `http://127.0.0.1:38920/console/` on the same PC. Tests: `npm test` (C# and HTTPS parts run only if the .NET 10 SDK and openssl are present). Keys and certificates for tests are generated at test time and deleted afterwards; all test data is fictional.
- **Measured (developer PC, fictional data):** Node tests 32/33 passed with 1 skipped by default (LAN test, opt-in with `HAISHIN_TEST_LAN=1`); C# reporter 43/43; C# kit 120/120 including real cmd/robocopy apply-and-rollback; WinForms end-to-end 24/24. The personal-data filter refused 56 of 88 items it should refuse (63.6%), wrongly refused 3 of 42 (7.1%), and **found only 3 of 19 personal names**.
- **Limits:** prototype, not used in production yet; Windows only; the sample stops at the decision/display stage (download-apply-restart-rollback is not wired into the sample); single admin password; file storage only; detection of personal data is incomplete.
- **Not a certification or guarantee.** Provided free of charge by HARVEST (Japan). Contact: garageten.info@gmail.com.
- **License: All rights reserved** (松岡颯大 / HARVEST). You may view the source and use the tool within yourself or your own company free of charge, including for work. Copying and distributing, selling, distributing modified versions or incorporating it into other products requires prior written permission. See [`LICENSE`](LICENSE) and [`TERMS-en.md`](TERMS-en.md).
