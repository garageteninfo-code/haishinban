// 関門（lib/guard.mjs）の試験。個人情報・鍵らしい物は実行のたびに乱数で作る（ファイルに書かない）。
import assert from 'node:assert/strict';
import test from 'node:test';
import { createGuard } from '../lib/guard.mjs';
import { fakeApiKey, fakeCard, fakeMobile, fakeMyNumber, randDigits } from '../scenario/fictional.mjs';

const g = createGuard();

test('個人情報・鍵が入っていれば断る（種類も合う）', () => {
  const my = fakeMyNumber();
  const cases = [
    ['name', '顧客 山田太郎様の伝票を保存中に失敗'],
    ['name', '氏名: 佐藤花子 の行で例外'],
    ['phone', `連絡先 ${fakeMobile()} のラベル印刷に失敗`],
    ['phone', `電話 03-${randDigits(4)}-${randDigits(4)} へ発信できません`],
    ['my_number', `マイナンバー ${my} の行で例外`],
    ['my_number', `${my.slice(0, 4)}-${my.slice(4, 8)}-${my.slice(8)} を読めません`],
    ['credit_card', `カード番号 ${fakeCard()} の確認で例外`],
    ['email', 'taro.yamada@example.co.jp に送れません'],
    ['address', '大阪府大阪市北区梅田1-2-3 の地図を開けません'],
    ['user_path', 'at C:\\Users\\tanaka\\AppData\\Local\\SampleApp\\app.log'],
    ['user_path', 'at C:\\Users\\佐藤\\AppData\\Local\\SampleApp\\settings.json'],
    ['unc_path', 'ファイルを開けません: \\\\fileserver01\\共有\\在庫.xlsx'],
    ['api_key', `接続に失敗 key=${fakeApiKey()}`],
    ['credential_assign', 'DB_PASSWORD=Hunter2Secret99'],
    ['private_key', '-----BEGIN PRIVATE KEY-----\nMIIBVQ\n-----END PRIVATE KEY-----'],
    ['url_host', 'https://erp.internal-sample.co.jp/api に接続できません'],
    ['ipv4', '192.168.10.25 に接続できません'],
  ];
  for (const [kind, text] of cases) {
    const got = g.check(text);
    assert.ok(got, `断るべき: ${kind}`);
    if (!['url_host', 'ipv4'].includes(kind)) assert.equal(got, kind, `種類: ${text.slice(0, 20)}…`);
  }
});

test('全角で書かれた個人情報も断る', () => {
  const toWide = (s) => s.replace(/[0-9-]/g, (c) => (c === '-' ? '－' : String.fromCharCode(c.charCodeAt(0) + 0xfee0)));
  assert.equal(g.check(`連絡先 ${toWide(fakeMobile())}`), 'phone');
  assert.equal(g.check(`マイナンバー ${toWide(fakeMyNumber())}`), 'my_number');
});

test('ふつうの不具合報告は断らない', () => {
  const clean = [
    'System.NullReferenceException: Object reference not set to an instance of an object.',
    '   at SampleApp.Inventory.SaveSlip(Slip s) in C:\\Users\\<user>\\src\\SampleApp\\Inventory.cs:line 214',
    '   at SampleApp.MainForm.OnSave() in %USERPROFILE%\\src\\MainForm.cs:line 88',
    '在庫の保存に失敗しました（タイムアウト 30 秒）',
    '印刷の待ち行列が空です',
    '設定ファイルの読み込みに失敗しました: 形式が正しくありません',
    'データベースへの接続に失敗しました（127.0.0.1:1433）',
    'http://localhost:38920/v1/health が応答しません',
    'commit 3f9a1c2b4d5e6f708192a3b4c5d6e7f8091a2b3c で発生',
    'sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 が合いません',
    'GUID 3f2504e0-4f89-11d3-9a0c-0305e82c3301 の画面で例外',
    '版 1.1.0 から 1.0.0 へ戻しました（2026-11-14 10:23:45）',
    '利用者様の画面で例外が発生しました',
    '担当者様へ: 再起動してください',
    'パスワードが短すぎます',
    'Invalid token: expired',
    'ファイルサイズ 1048576 バイトを超えました',
  ];
  for (const t of clean) assert.equal(g.check(t), null, `断ってはいけない: ${t}`);
});

test('無作為の業務の番号を誤って断る割合（各 2,000 件）', () => {
  const rates = {};
  for (const n of [10, 11, 12, 13, 16]) {
    let bad = 0;
    for (let i = 0; i < 2000; i++) if (g.check(`伝票番号 ${randDigits(n)} の保存中に例外`)) bad++;
    rates[n] = bad / 2000;
  }
  console.log(`  無作為の業務の番号を断った割合: ${Object.entries(rates).map(([n, r]) => `${n}桁 ${(r * 100).toFixed(2)}%`).join('・')}`);
  assert.equal(rates[12], 0, '12 桁（マイナンバーと同じ桁数）は 0%');
  for (const r of Object.values(rates)) assert.ok(r <= 0.01, '1% 以下');
});

test('設定：秘密そのものの種類は止められない・知らない種類は起動しない', () => {
  assert.throws(() => createGuard({ disabledKinds: ['api_key'] }), /止められない/);
  assert.throws(() => createGuard({ disabledKinds: ['credential_assign'] }), /止められない/);
  assert.throws(() => createGuard({ disabledKinds: ['ipv5'] }), /知らない種類/);
});

test('設定：種類を止める・通してよいホスト・足す規則・言葉なしのマイナンバー', () => {
  assert.equal(createGuard({ disabledKinds: ['ipv4'] }).check('192.168.10.25 に接続できません'), null);
  assert.equal(createGuard({ allowHosts: ['.internal-sample.co.jp'] }).check('https://erp.internal-sample.co.jp/api に接続できません'), null);
  assert.equal(createGuard({ extraRules: [{ kind: '社員番号', pattern: 'EMP-\\d{6}' }] }).check('EMP-123456 の画面'), '社員番号');
  const bare = fakeMyNumber();
  assert.equal(g.check(`番号 ${bare} で例外`), null, '既定では言葉が無い 12 桁は断らない');
  assert.equal(createGuard({ myNumberWithoutContext: true }).check(`番号 ${bare} で例外`), 'my_number');
  assert.throws(() => createGuard({ extraRules: [{ kind: 'x', pattern: '(' }] }));
});

test('見つけた中身は返さない（種類と欄の名前だけ）', () => {
  const phone = fakeMobile();
  const r = g.checkFields({ 'reports[0].title': '保存', 'reports[0].message': `連絡先 ${phone}` });
  assert.deepEqual(r, { field: 'reports[0].message', kind: 'phone' });
  assert.ok(!JSON.stringify(r).includes(phone));
});
