// 架空の Windows アプリ「SampleApp（在庫管理）」で、配信の安全セットを最初から最後まで通すサンプル。
//
//   node scenario/sample-scenario.mjs [--keep]
//
// 流れ:
//   1. 1.0.0 を全員に配る → 1.1.0 を 10% に配る（署名は管理画面と同じ manifest-core.js ＝ WebCrypto）
//   2. 架空の 200 台が起動の知らせを送る。どの端末が 1.1.0 を受け取るかは C# の UpdateSafetyKit が決める（.NET が無ければ Node で同じ計算）
//   3. 1.1.0 の端末から落ちた報告が来る。架空の個人情報入りの報告は中継が断る → 端末が伏せ字にして送り直す
//   4. 1.1.0 の落ちる割合が基準を超える → 中継が知らせる
//   5. 管理画面の「配信を止める（0%）」と同じ手順で、止める配信情報を作って署名して載せる
//   6. C# の UpdateSafetyKit で：1.0.0 の端末は 1.1.0 を受け取らない・古い 10% の配信情報の再送は拒否・書き換えた物も拒否
//   7. 「この版を取り下げる」（1.0.0 に戻す）→ 1.1.0 の端末は 1.0.0 へ戻す判定
//
// 作る物はすべて <この製品>\一時\scenario-<乱数>\ の中。最後に消す（--keep で残す）。秘密鍵はメモリの中だけでファイルに書かない。

import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from '../server.mjs';
import { draftHalt, draftRelease, draftRevoke, exportPublicPem, generateKeyPair, signManifest, verifyManifest } from '../console/manifest-core.js';
import { AdminClient } from './admin-client.mjs';
import { fakeCard, fakeInstallId, fakeMobile, fakeMyNumber, randDigits, reporterIdFor } from './fictional.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const DOMAIN = 'sample-app';

// ---------- .NET を探す（ダウンロードはしない） ----------
export function findDotnetVerifier() {
  const dll = path.join(ROOT, 'csharp', 'HaishinVerify', 'bin', 'Release', 'net10.0', 'HaishinVerify.dll');
  const candidates = [process.env.HAISHIN_DOTNET, path.join(os.homedir(), '.dotnet', process.platform === 'win32' ? 'dotnet.exe' : 'dotnet'), 'dotnet'].filter(Boolean);
  for (const exe of candidates) {
    const r = spawnSync(exe, ['--list-sdks'], { encoding: 'utf8' });
    if (r.status !== 0 || !/^10\./m.test(r.stdout || '')) continue;
    if (!fs.existsSync(dll)) {
      // オフラインの設定（csharp\nuget.config で置き場を空に）で組み立てる。外部パッケージは 0。
      const b = spawnSync(exe, ['build', '-c', 'Release', '--nologo'], { cwd: path.join(ROOT, 'csharp', 'HaishinVerify'), encoding: 'utf8', env: { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_NOLOGO: '1' } });
      if (b.status !== 0 || !fs.existsSync(dll)) return { ok: false, why: `組み立てに失敗: ${(b.stdout || '').split('\n').filter((l) => /error/i.test(l)).slice(0, 3).join(' / ')}` };
    }
    return { ok: true, exe, dll };
  }
  return { ok: false, why: '.NET 10 の SDK が見つからない（ダウンロードはしない決まり）' };
}

function runCsharp(v, request, workDir) {
  const f = path.join(workDir, `cs-request-${crypto.randomBytes(3).toString('hex')}.json`);
  fs.writeFileSync(f, JSON.stringify(request), 'utf8');
  const r = spawnSync(v.exe, [v.dll, f], { encoding: 'utf8', env: { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: '1' } });
  fs.rmSync(f, { force: true });
  if (r.status !== 0) throw new Error(`C# の確かめが失敗: ${r.stderr || r.stdout}`);
  return JSON.parse(r.stdout.trim().split('\n').pop());
}

/** C# の Rollout.Bucket と同じ計算（.NET が無いときの代わり）。 */
function nodeInCohort(installId, rollout) {
  if (!rollout || rollout.percent >= 100) return true;
  if (rollout.percent <= 0) return false;
  const h = crypto.createHash('sha256').update(installId + rollout.salt).digest();
  return ((h[0] << 8) | h[1]) % 100 < rollout.percent;
}

async function http(base, method, p, body, headers = {}) {
  const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

/**
 * @param {{ keep?: boolean, log?: (s: string) => void, devices?: number, useDotnet?: boolean }} [o]
 */
export async function runScenario({ keep = false, log = console.log, devices = 200, useDotnet = true } = {}) {
  const work = path.join(ROOT, '一時', `scenario-${crypto.randomBytes(4).toString('hex')}`);
  fs.mkdirSync(work, { recursive: true });
  const checks = [];
  const check = (name, ok, detail = '') => { checks.push({ name, ok: !!ok, detail }); log(`  ${ok ? '合格' : '不合格'}  ${name}${detail ? ' — ' + detail : ''}`); };
  let srv;
  try {
    // ---- 配る物（架空のファイル） ----
    const rel = path.join(work, 'release');
    for (const v of ['1.0.0', '1.1.0']) {
      fs.mkdirSync(path.join(rel, 'files', v), { recursive: true });
      fs.writeFileSync(path.join(rel, 'files', v, 'windows.zip'), crypto.randomBytes(64 * 1024));
    }
    // C# の道具は中継を起動する前に用意する（組み立ての間、この処理が止まり、中継との接続が切れるため）
    const verifier = useDotnet ? findDotnetVerifier() : { ok: false, why: '使わない設定' };
    const serverLog = [];
    srv = await startServer({
      domain: DOMAIN, host: '127.0.0.1', port: 0, dataDir: path.join(work, 'data'), releaseDir: rel,
      threshold: { minActiveInstalls: 10, minCrashInstalls: 3, maxCrashRate: 0.1, windowHours: 72 }, guard: {},
      limits: { reportsPerHour: 30, heartbeatsPerHour: 60 }, log: (m) => { serverLog.push(m); log(`    [中継] ${m}`); },
    });
    const base = srv.url;
    log(`■ 中継を ${base} で起動（この PC の中だけ）`);
    // 管理画面の合言葉は実行のたびに乱数で作る（ファイルには混ぜた値だけ・作業フォルダごと消す）
    const adminClient = new AdminClient(base);
    await adminClient.loginOrSetup(`scenario-${crypto.randomBytes(12).toString('base64url')}`);
    const admin = (_base, p, body) => adminClient.put(p, body);

    // ---- 鍵（管理画面と同じ WebCrypto・メモリの中だけ） ----
    const keys = await generateKeyPair();
    const publicKeyPem = await exportPublicPem(keys.publicKey);
    check('公開鍵をサーバーに登録できる', (await admin(base, '/api/admin/public-key', { pem: publicKeyPem })).status === 200);
    const status = async () => (await adminClient.get('/api/admin/status')).body;
    const signAndPublish = async (draft) => {
      const st = await status();
      const { manifest } = await signManifest({ draft, artifacts: st.artifacts[draft.version], domain: DOMAIN, privateKey: keys.privateKey });
      const why = await verifyManifest(manifest, DOMAIN, keys.publicKey);
      if (why) throw new Error(why);
      const r = await admin(base, '/api/admin/manifest', { manifest });
      if (r.status !== 200) throw new Error(`載せられない: ${JSON.stringify(r.body)}`);
      return manifest;
    };

    log('■ 1. 1.0.0 を全員に → 1.1.0 を 10% に');
    const m1 = await signAndPublish(draftRelease(null, { version: '1.0.0', percent: 100 }));
    const m2 = await signAndPublish(draftRelease(m1, { version: '1.1.0', percent: 10 }));
    check('1.1.0 を 10% で配る配信情報を署名して載せた', m2.seq === 2 && m2.rollout.percent === 10, `通し番号 ${m2.seq}`);

    // ---- 架空の端末 ----
    const fleet = Array.from({ length: devices }, () => ({ installId: fakeInstallId(), currentVersion: '1.0.0' }));
    let offered;
    if (verifier.ok) {
      const a = runCsharp(verifier, { domain: DOMAIN, publicKeyPem, manifests: [{ name: 'seq1', manifest: m1 }, { name: 'seq2', manifest: m2 }], fleet }, work);
      offered = a.results[1].decisions.map((k) => k === 'Offer');
      log(`  C# の UpdateSafetyKit（.NET ${a.runtime}）で、どの端末に 1.1.0 を出すかを判定`);
      check('C# が WebCrypto の署名を正しいと判定（1.0.0 全員）', a.results[0].signature === 'ok');
      check('C# が WebCrypto の署名を正しいと判定（1.1.0 を 10%）', a.results[1].signature === 'ok');
    } else {
      log(`  ⚠ C# では確かめられない（${verifier.why}）。同じ計算を Node で行う`);
      offered = fleet.map((d) => nodeInCohort(d.installId, m2.rollout));
    }
    const nNew = offered.filter(Boolean).length;
    fleet.forEach((d, i) => { if (offered[i]) d.currentVersion = '1.1.0'; });
    check('約 10% の端末だけが 1.1.0 を受け取る', nNew >= devices * 0.03 && nNew <= devices * 0.2, `${nNew} / ${devices} 台`);

    log('■ 2. 起動の知らせ（どの版が何台動いているか）');
    for (const d of fleet) await http(base, 'POST', '/v1/heartbeat', { reporterId: reporterIdFor(d.installId), appVersion: d.currentVersion, os: 'Windows 11 23H2' });

    log('■ 3. 落ちた報告（1.1.0 の約 4 割・1.0.0 は 2 台）。一部に架空の個人情報');
    const now = Date.now();
    const crash = (title, message, stack) => ({ fingerprint: `crash-${crypto.createHash('sha256').update(title).digest('hex').slice(0, 16)}`, kind: 'crash', title, message, stack, count: 1, firstSeen: now - 60000, lastSeen: now });
    const stackOk = 'System.NullReferenceException: Object reference not set to an instance of an object.\n   at SampleApp.Inventory.SaveSlip(Slip s) in C:\\Users\\<user>\\src\\SampleApp\\Inventory.cs:line 214\n   at SampleApp.MainForm.OnSave()';
    const leaks = [
      { kind: 'name', report: crash('保存で落ちた', '顧客 山田太郎様の伝票を保存中に失敗しました', stackOk) },
      { kind: 'user_path', report: crash('起動で落ちた', '設定ファイルを読めません', 'System.IO.IOException: 読み取れません\n   at C:\\Users\\佐藤\\AppData\\Local\\SampleApp\\settings.json') },
      { kind: 'phone', report: crash('印刷で落ちた', `連絡先 ${fakeMobile()} の宛名ラベルを印刷中に失敗`, stackOk) },
      { kind: 'my_number', report: crash('取り込みで落ちた', `マイナンバー ${fakeMyNumber().replace(/(\d{4})(\d{4})(\d{4})/, '$1 $2 $3')} の行で例外`, stackOk) },
      { kind: 'credit_card', report: crash('決済画面で落ちた', `カード番号 ${fakeCard()} の確認中に例外`, stackOk) },
    ];
    const newDevices = fleet.filter((d) => d.currentVersion === '1.1.0');
    const crashing = newDevices.slice(0, Math.max(3, Math.ceil(newDevices.length * 0.4)));
    let refused = 0; let refusedRight = 0; let accepted = 0; let resentOk = 0; let falseRefusal = 0;
    for (let i = 0; i < crashing.length; i++) {
      const d = crashing[i];
      const leak = i < leaks.length ? leaks[i] : null;
      // 個人情報の入っていない報告には、架空の 12 桁の伝票番号を入れる（業務の番号を誤って断らないかの確かめ）
      const report = leak ? leak.report : crash('保存で落ちた', `伝票番号 ${randDigits(12)} の保存中に例外`, stackOk);
      const body = { reporterId: reporterIdFor(d.installId), appVersion: d.currentVersion, os: 'Windows 11 23H2', reports: [report] };
      const r = await http(base, 'POST', '/v1/reports', body);
      if (r.status === 422) {
        refused++;
        if (leak && r.body.kind === leak.kind) refusedRight++;
        if (!leak) falseRefusal++;
        // 端末が伏せ字にして送り直す
        const fixed = { ...report, message: '[伏せ字] の処理中に例外', stack: stackOk };
        const r2 = await http(base, 'POST', '/v1/reports', { ...body, reports: [fixed] });
        if (r2.status === 200) resentOk++;
      } else if (r.status === 200) {
        accepted++;
        if (leak) log(`    ⚠ 個人情報入り（${leak.kind}）を受け取ってしまった`);
      }
    }
    for (const d of fleet.filter((x) => x.currentVersion === '1.0.0').slice(0, 2)) {
      await http(base, 'POST', '/v1/reports', { reporterId: reporterIdFor(d.installId), appVersion: '1.0.0', os: 'Windows 10 22H2', reports: [crash('まれな落ち', '印刷の待ち行列が空', stackOk)] });
    }
    const nLeaks = Math.min(leaks.length, crashing.length);
    check('個人情報入りの報告はすべて断った', refused - falseRefusal === nLeaks, `${refused - falseRefusal} / ${nLeaks} 件`);
    check('断った理由の種類が正しい', refusedRight === nLeaks, `${refusedRight} / ${nLeaks} 件`);
    check('伏せ字にして送り直した報告は受け取った', resentOk === refused);
    check('12 桁の伝票番号だけの報告は断らない', falseRefusal === 0, `誤って断った ${falseRefusal} 件`);
    const all = fs.readdirSync(path.join(work, 'data'), { recursive: true }).filter((f) => /\.(json|jsonl)$/.test(f)).map((f) => fs.readFileSync(path.join(work, 'data', f), 'utf8')).join('\n');
    check('断った報告の中身は保存されていない', !/山田太郎|佐藤\\\\AppData|佐藤\\AppData|マイナンバー|カード番号|090-\d{4}/.test(all));

    log('■ 4. 版ごとの落ちる割合');
    let st = await status();
    for (const v of st.versions) log(`    ${v.version}: 動いている ${v.activeInstalls} 台・落ちた ${v.crashInstalls} 台・割合 ${v.crashRate == null ? '—' : (v.crashRate * 100).toFixed(1) + '%'}・判定 ${v.status}`);
    const s11 = st.versions.find((v) => v.version === '1.1.0');
    const s10 = st.versions.find((v) => v.version === '1.0.0');
    check('1.1.0 が基準超えと判定された', s11 && s11.status === 'over');
    check('1.0.0 は基準超えではない', s10 && s10.status !== 'over');
    check('中継が知らせを出した', st.alerts.some((a) => a.version === '1.1.0') && serverLog.some((l) => l.includes('[警告] 版 1.1.0')));

    log('■ 5. 管理画面の「配信を止める（0%）」と同じ手順');
    const m3 = await signAndPublish(draftHalt(st.manifest));
    check('止める配信情報（0%・通し番号 3）を載せた', m3.seq === 3 && m3.rollout.percent === 0 && m3.version === '1.1.0');
    const replayUp = await admin(base, '/api/admin/manifest', { manifest: m2 });
    check('サーバーは古い 10% の配信情報の載せ直しを拒否', replayUp.status === 409, replayUp.body.error);
    const served = (await http(base, 'GET', '/updates/manifest.json')).body;
    check('端末が読む配信情報は 0% になっている', served.seq === 3 && served.rollout.percent === 0);
    const tampered = JSON.parse(JSON.stringify(m3));
    tampered.rollout.percent = 100;
    const tamperUp = await admin(base, '/api/admin/manifest', { manifest: { ...tampered, seq: 99 } });
    check('サーバーは書き換えた配信情報を拒否（署名が合わない）', tamperUp.status === 409 && String(tamperUp.body.error).startsWith('signature_mismatch'), tamperUp.body.error);

    log('■ 7. 「この版を取り下げる」（1.1.0 を取り下げ・1.0.0 を案内）');
    const m4 = await signAndPublish(draftRevoke(m3, { badVersion: '1.1.0', fallbackVersion: '1.0.0' }));
    check('取り下げの配信情報（通し番号 4）を載せた', m4.seq === 4 && m4.version === '1.0.0' && m4.rollback.badVersions.includes('1.1.0'));
    st = await status();

    let csharp = null;
    if (verifier.ok) {
      log('■ 6. C# の UpdateSafetyKit で確かめる（端末の判定）');
      const guardDev = fleet.find((d, i) => offered[i]);
      const dataDir = path.join(work, '利用者_山田 花子', 'AppData', 'Local', 'SampleApp');
      const appDir = path.join(work, 'Programs', 'Sample App');
      fs.mkdirSync(appDir, { recursive: true });
      const b = runCsharp(verifier, {
        domain: DOMAIN, publicKeyPem, fleet,
        guardDevice: { dataDir, appDir, installId: guardDev.installId, currentVersion: '1.0.0' },
        manifests: [
          { name: '1.0.0 全員（seq1）', manifest: m1 },
          { name: '1.1.0 を 10%（seq2）', manifest: m2 },
          { name: '止めた 0%（seq3）', manifest: m3 },
          { name: '古い 10% の再送（seq2）', manifest: m2 },
          { name: '書き換えた 100%（seq3 のまま）', manifest: tampered },
          { name: '1.1.0 を取り下げ・1.0.0 を案内（seq4）', manifest: m4 },
        ],
      }, work);
      csharp = b;
      const [r1, r2, r3, r4, r5, r6] = b.results;
      const offerAmong = (r, ver) => r.decisions.filter((k, i) => k === 'Offer' && fleet[i].currentVersion === ver).length;
      log(`    （.NET ${b.runtime}・端末 ${fleet.length} 台・入口の端末の状態は「利用者_山田 花子」という日本語のフォルダに保存）`);
      for (const r of b.results) log(`    ${r.name}: 署名 ${r.signature}・端末の判定 ${JSON.stringify(r.fleet)}・入口 ${r.guard.offer}${r.guard.error ? '（' + r.guard.error + '）' : ''}`);
      check('C#: 止めた 0%（seq3）の署名は正しい', r3.signature === 'ok');
      check('C#: 止めた後、1.0.0 の端末は 1 台も 1.1.0 を受け取らない', offerAmong(r3, '1.0.0') === 0, `Offer ${offerAmong(r3, '1.0.0')} 台`);
      check('C#: 止めた後の判定は NotInCohort（1.0.0 の端末すべて）', r3.decisions.filter((k, i) => fleet[i].currentVersion === '1.0.0').every((k) => k === 'NotInCohort'));
      check('C#: 古い 10% の再送は全端末で拒否（Replay）', r4.fleet.Unverified === fleet.length && r4.guard.error === 'Replay');
      check('C#: 書き換えた物は署名が合わず拒否', r5.signature === 'SignatureMismatch' && r5.fleet.Unverified === fleet.length);
      check('C#: 取り下げ後、1.1.0 の端末は 1.0.0 へ戻す判定（Offer）', offerAmong(r6, '1.1.0') === newDevices.length, `${offerAmong(r6, '1.1.0')} / ${newDevices.length} 台`);
      check('C#: 取り下げ後、1.0.0 の端末は何もしない（NotNewer）', r6.decisions.filter((k, i) => fleet[i].currentVersion === '1.0.0').every((k) => k === 'NotNewer'));
      check('C#: 入口（UpdateGuard・日本語のフォルダ）でも 止める前 Offer → 止めた後 NotInCohort', r2.guard.offer === 'Offer' && r3.guard.offer === 'NotInCohort');
      check('C#: 入口が通し番号を日本語のフォルダの状態ファイルに保存した', fs.existsSync(path.join(dataDir, 'update-state.txt')));
      void r1;
    } else {
      log(`■ 6. C# での確かめは飛ばした（${verifier.why}）`);
    }

    const passed = checks.filter((c) => c.ok).length;
    log(`■ 合計: ${passed} / ${checks.length} 合格${verifier.ok ? '' : '（C# の確かめは飛ばした）'}`);
    return { checks, passed, total: checks.length, csharp: verifier.ok, csharpRuntime: csharp?.runtime ?? null, newDevices: newDevices.length, stats: st.versions };
  } finally {
    if (srv) await srv.close();
    if (!keep) fs.rmSync(work, { recursive: true, force: true });
    else log(`（作業フォルダを残しました: ${work}）`);
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const r = await runScenario({ keep: process.argv.includes('--keep') });
  process.exit(r.passed === r.total ? 0 : 1);
}
