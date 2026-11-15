// 通しの試験：本物の WinForms のサンプルアプリ（sample-app\SampleApp.exe）を何台分も起動して、
// https＋ログインの中継 → 1.0 → 1.1 を 10% → 落ちる → 知らせ → 管理の口で「止める」→ アプリが 1.1 を出さない → 取り下げ → 戻しの判定、まで確かめる。
//
//   node scenario/e2e-gui.mjs [--keep]
//
// ・Windows と .NET 10 の SDK と openssl が要る（ダウンロードはしない）。画面は最小化して出し、自動で閉じる。
// ・証明書・鍵・合言葉・署名の鍵はすべて実行のたびに作り、<この製品>\一時\e2e-<乱数>\ の中だけに置いて最後に消す（署名の秘密鍵はメモリの中だけ）。
// ・データはすべて架空（名前・住所・電話は架空の物を乱数で作る）。
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from '../server.mjs';
import { draftHalt, draftRelease, draftRevoke, exportPublicPem, generateKeyPair, signManifest } from '../console/manifest-core.js';
import { findOpenssl, makeCert } from '../tools/make-cert.mjs';
import { AdminClient } from './admin-client.mjs';
import { fakeInstallId, fakeMobile } from './fictional.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const APP_DIR = path.join(ROOT, 'sample-app');
const EXE = path.join(APP_DIR, 'bin', 'Release', 'net10.0-windows', 'SampleApp.exe');
const DOMAIN = 'sample-app';

function findDotnet() {
  for (const exe of [process.env.HAISHIN_DOTNET, path.join(os.homedir(), '.dotnet', 'dotnet.exe'), 'dotnet'].filter(Boolean)) {
    const r = spawnSync(exe, ['--list-sdks'], { encoding: 'utf8' });
    if (r.status === 0 && /^10\./m.test(r.stdout || '')) return exe;
  }
  return null;
}

/** C# の Rollout.Bucket と同じ計算（どの架空の端末が 10% に入るかを先に決めるため）。 */
function inCohort(installId, rollout) {
  if (!rollout || rollout.percent >= 100) return true;
  if (rollout.percent <= 0) return false;
  const h = crypto.createHash('sha256').update(installId + rollout.salt).digest();
  return ((h[0] << 8) | h[1]) % 100 < rollout.percent;
}

function runApp(args, dotnetRoot, timeoutMs = 60000) {
  return new Promise((resolve) => {
    // 利用者フォルダに入れた .NET（~/.dotnet）を使うときは DOTNET_ROOT が要る（無いと「.NET を入れてください」の画面が出て止まる）
    const p = spawn(EXE, args, { windowsHide: false, env: { ...process.env, ...(dotnetRoot ? { DOTNET_ROOT: dotnetRoot } : {}) } });
    let out = '';
    p.stdout?.on('data', (d) => { out += d; });
    p.stderr?.on('data', (d) => { out += d; });
    const t = setTimeout(() => { p.kill(); }, timeoutMs);
    p.on('close', (code) => { clearTimeout(t); resolve({ code, out }); });
  });
}

export async function runE2E({ keep = false, log = console.log } = {}) {
  const checks = [];
  const check = (name, ok, detail = '') => { checks.push({ name, ok: !!ok, detail }); log(`  ${ok ? '合格' : '不合格'}  ${name}${detail ? ' — ' + detail : ''}`); };
  if (process.platform !== 'win32') return { skipped: 'Windows だけ', checks, passed: 0, total: 0 };
  const dotnet = findDotnet();
  const openssl = findOpenssl();
  if (!dotnet || !openssl) return { skipped: !dotnet ? '.NET 10 SDK なし' : 'openssl なし', checks, passed: 0, total: 0 };
  const dotnetRoot = path.isAbsolute(dotnet) ? path.dirname(dotnet) : process.env.DOTNET_ROOT;

  log('■ 0. サンプルアプリを組み立てる（オフライン・外部パッケージ 0）');
  const b = spawnSync(dotnet, ['build', '-c', 'Release', '--nologo'], { cwd: APP_DIR, encoding: 'utf8', env: { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_NOLOGO: '1' } });
  check('WinForms のサンプルアプリが組み立てられる', b.status === 0 && fs.existsSync(EXE), b.status === 0 ? '' : (b.stdout || '').split('\n').filter((l) => /error/.test(l)).slice(0, 3).join(' / '));
  if (b.status !== 0) return { checks, passed: 0, total: checks.length };

  const work = path.join(ROOT, '一時', `e2e-${crypto.randomBytes(4).toString('hex')}`);
  fs.mkdirSync(work, { recursive: true });
  let srv;
  try {
    // ---- 中継（https＋ログイン） ----
    const cert = makeCert({ outDir: path.join(work, 'certs'), openssl });
    const rel = path.join(work, 'release');
    for (const v of ['1.0.0', '1.1.0']) {
      fs.mkdirSync(path.join(rel, 'files', v), { recursive: true });
      fs.writeFileSync(path.join(rel, 'files', v, 'windows.zip'), crypto.randomBytes(32 * 1024));
    }
    const serverLog = [];
    srv = await startServer({
      domain: DOMAIN, host: '127.0.0.1', port: 0, dataDir: path.join(work, 'data'), releaseDir: rel,
      threshold: { minActiveInstalls: 3, minCrashInstalls: 2, maxCrashRate: 0.2, windowHours: 72 }, guard: {},
      limits: { reportsPerHour: 30, heartbeatsPerHour: 60 }, tls: { enabled: true, certFile: cert.certFile, keyFile: cert.keyFile },
      log: (m) => { serverLog.push(m); log(`    [中継] ${m}`); },
    });
    log(`■ 1. 中継を ${srv.url} で起動（https・証明書の指紋 ${srv.certFingerprint.hex.slice(0, 16)}…）`);
    const ca = fs.readFileSync(cert.certFile);
    const admin = new AdminClient(srv.url, { ca });
    const password = `e2e-${crypto.randomBytes(15).toString('base64url')}`;
    const anon = new AdminClient(srv.url, { ca });
    check('ログインしていないと管理の口は 401', (await anon.get('/api/admin/status')).status === 401);
    await admin.loginOrSetup(password);
    check('初回の合言葉の設定（この PC から）→ ログインできた', (await admin.get('/api/admin/status')).status === 200);

    const keys = await generateKeyPair();
    const pem = await exportPublicPem(keys.publicKey);
    fs.writeFileSync(path.join(work, 'public-key.pem'), pem);   // 公開鍵だけ（アプリが読む）。秘密鍵はメモリの中だけ
    check('公開鍵を登録', (await admin.put('/api/admin/public-key', { pem })).status === 200);
    const publish = async (draft) => {
      const st = (await admin.get('/api/admin/status')).json;
      const { manifest } = await signManifest({ draft, artifacts: st.artifacts[draft.version], domain: DOMAIN, privateKey: keys.privateKey });
      const r = await admin.put('/api/admin/manifest', { manifest });
      if (r.status !== 200) throw new Error(`載せられない: ${r.text}`);
      return manifest;
    };

    log('■ 2. 1.0.0 を全員に → 1.1.0 を 10% に');
    const m1 = await publish(draftRelease(null, { version: '1.0.0', percent: 100 }));
    const m2 = await publish(draftRelease(m1, { version: '1.1.0', percent: 10 }));
    check('1.1.0 を 10% で配る配信情報を署名して載せた', m2.rollout.percent === 10 && m2.seq === 2);

    // ---- 架空の端末（10% に入る 4 台・入らない 6 台） ----
    const inside = []; const outside = [];
    while (inside.length < 4 || outside.length < 6) {
      const id = fakeInstallId();
      if (inCohort(id, m2.rollout)) { if (inside.length < 4) inside.push(id); } else if (outside.length < 6) outside.push(id);
    }
    const devices = [...inside.map((id, i) => ({ name: `A${i + 1}`, id, inside: true })), ...outside.map((id, i) => ({ name: `B${i + 1}`, id, inside: false }))];
    const cfgFile = path.join(work, 'sampleapp.json');
    fs.writeFileSync(cfgFile, JSON.stringify({ domain: DOMAIN, relayUrl: `${srv.url}/`, pinnedCertSha256: [srv.certFingerprint.hex], publicKeyFile: path.join(work, 'public-key.pem') }, null, 2));
    for (const d of devices) {
      d.dataDir = path.join(work, 'installs', `端末 ${d.name}`);   // 日本語・空白入りのフォルダ
      fs.mkdirSync(d.dataDir, { recursive: true });
      fs.writeFileSync(path.join(d.dataDir, 'install-id.txt'), d.id + '\n');
    }
    const app = async (d, version, mode, extra = [], config = cfgFile) => {
      const result = path.join(work, `result-${d.name}-${crypto.randomBytes(3).toString('hex')}.json`);
      const r = await runApp(['--config', config, '--data-dir', d.dataDir, '--app-version', version, '--auto', mode, '--result', result, ...extra], dotnetRoot);
      let j = null;
      try { j = JSON.parse(fs.readFileSync(result, 'utf8')); } catch { j = null; }
      return { code: r.code, j };
    };

    log('■ 3. 10 台のサンプルアプリ（1.0.0）を起動して更新を確かめる（画面つき・最小化）');
    const first = [];
    for (let i = 0; i < devices.length; i += 5) first.push(...await Promise.all(devices.slice(i, i + 5).map((d) => app(d, '1.0.0', 'check'))));
    const offered = devices.filter((d, i) => first[i].j?.Kind === 'Offer' && first[i].j?.Latest === '1.1.0');
    check('10% に入る 4 台だけが「新しい版 1.1.0 があります」', offered.length === 4 && offered.every((d) => d.inside), `${offered.map((d) => d.name).join(',')}`);
    check('入らない 6 台は「一部の端末（10%）にだけ」', devices.filter((d) => !d.inside).every((d) => first[devices.indexOf(d)].j?.Kind === 'NotInCohort' && first[devices.indexOf(d)].j?.Percent === 10));
    check('どの起動も起動の知らせを送れた（報告の置き場が空）', first.every((r) => r.code === 0 && r.j?.stats?.Queued === 0 && r.j?.stats?.Sent >= 1), first.map((r) => r.code).join(','));

    log('■ 4. A1〜A3 が 1.1.0 になった体で起動 →「落ちたことにする」（A1 には架空の個人情報入りの例外）');
    const phone = fakeMobile();
    const leaky = `C:\\Users\\山田 花子\\Documents\\在庫.xlsx の保存で例外。配送先 大阪府大阪市北区梅田1丁目2-3、連絡先 ${phone}`;
    const crashes = await Promise.all([
      app(devices[0], '1.1.0', 'crash', ['--crash-message', leaky]),
      app(devices[1], '1.1.0', 'crash'),
      app(devices[2], '1.1.0', 'crash', ['--crash-message', '顧客 佐藤一郎様の伝票の保存で例外']),
    ]);
    check('3 台とも落ちて（終了コード 3）、報告が届いた', crashes.every((r) => r.code === 3 && r.j?.delivered === true), crashes.map((r) => `${r.code}/${r.j?.delivered}`).join(' '));
    check('A1 の報告は中継に断られ（住所）、端末が欄を伏せて送り直した', crashes[0].j?.stats?.Redacted >= 1 && crashes[0].j?.stats?.Refused >= 1, JSON.stringify(crashes[0].j?.stats));

    let st = (await admin.get('/api/admin/status')).json;
    const v11 = st.versions.find((v) => v.version === '1.1.0');
    log(`    1.1.0: 動いている ${v11.activeInstalls} 台・落ちた ${v11.crashInstalls} 台・割合 ${(v11.crashRate * 100).toFixed(0)}%・判定 ${v11.status}`);
    check('1.1.0 が基準超え・中継が知らせた', v11.status === 'over' && st.alerts.some((a) => a.version === '1.1.0') && serverLog.some((l) => l.includes('[警告] 版 1.1.0')));
    check('中継は住所入りを断った（種類だけ記録）', (st.refused.address ?? 0) >= 1, JSON.stringify(st.refused));
    const saved = fs.readdirSync(path.join(work, 'data'), { recursive: true }).filter((f) => /\.jsonl?$/.test(f)).map((f) => fs.readFileSync(path.join(work, 'data', f), 'utf8')).join('\n');
    check('中継のどのファイルにも 住所・電話・利用者名・顧客名 が無い', !/梅田|山田|佐藤一郎/.test(saved) && !saved.includes(phone) && !saved.includes(phone.replace(/-/g, '')));
    check('伏せ字の跡は残る（<name>・[伏せ字:…]）', saved.includes('<name>様') && saved.includes('[伏せ字:'));

    log('■ 5. 管理の口で「配信を止める（0%）」（ログイン＋CSRF の札が要る）');
    const haltDraft = draftHalt(st.manifest);
    const signedHalt = (await signManifest({ draft: haltDraft, artifacts: st.artifacts['1.1.0'], domain: DOMAIN, privateKey: keys.privateKey })).manifest;
    check('CSRF の札が無い「止める」は 403', (await admin.call('PUT', '/api/admin/manifest', { manifest: signedHalt }, { csrf: false })).status === 403);
    check('ログインしていない「止める」は 401', (await anon.put('/api/admin/manifest', { manifest: signedHalt })).status === 401);
    const hr = await admin.put('/api/admin/manifest', { manifest: signedHalt });
    check('ログイン＋札ありの「止める」は通る（通し番号 3・0%）', hr.status === 200 && signedHalt.seq === 3 && signedHalt.rollout.percent === 0, hr.text);
    check('古い 10% の配信情報の載せ直しは拒否', (await admin.put('/api/admin/manifest', { manifest: m2 })).status === 409);

    log('■ 6. まだ 1.0.0 の A4（10% に入っていた端末）を起動');
    const a4 = await app(devices[3], '1.0.0', 'check');
    check('A4 は 1.1.0 をもう出さない（「配信は止められています」）', a4.j?.Kind === 'NotInCohort' && a4.j?.Percent === 0 && /止められて/.test(a4.j?.Text ?? ''), a4.j?.Text);
    const b1 = await app(devices[4], '1.0.0', 'check');
    check('B1 も 1.1.0 を出さない', b1.j?.Kind === 'NotInCohort' && b1.j?.Percent === 0);

    log('■ 7. 「この版を取り下げる」（1.1.0 を取り下げ・1.0.0 を案内）');
    const m4 = await publish(draftRevoke(signedHalt, { badVersion: '1.1.0', fallbackVersion: '1.0.0' }));
    check('取り下げの配信情報（通し番号 4）を載せた', m4.seq === 4 && m4.version === '1.0.0');
    const a1 = await app(devices[0], '1.1.0', 'check');
    check('1.1.0 の A1 は「1.0.0 に戻します（戻しの判定）」', a1.j?.Kind === 'Offer' && a1.j?.RollbackTo === '1.0.0', a1.j?.Text);
    const b2 = await app(devices[5], '1.0.0', 'check');
    check('1.0.0 の B2 は「最新です」', b2.j?.Kind === 'NotNewer', b2.j?.Text);

    log('■ 8. 証明書の指紋が違うアプリ（なりすましの中継の代わり）');
    const badCfg = path.join(work, 'sampleapp-badpin.json');
    fs.writeFileSync(badCfg, JSON.stringify({ domain: DOMAIN, relayUrl: `${srv.url}/`, pinnedCertSha256: ['0'.repeat(64)], publicKeyFile: path.join(work, 'public-key.pem') }));
    const bad = await app(devices[6], '1.0.0', 'check', [], badCfg);
    check('指紋が違えば配信情報を取らず「証明書が違います」・報告も送らない', bad.j?.Fetch === 'CertificateRejected' && bad.j?.stats?.Sent === 0 && bad.j?.stats?.LastCertificateRejected === true, `${bad.j?.Fetch} ${JSON.stringify(bad.j?.stats)}`);

    st = (await admin.get('/api/admin/status')).json;
    const passed = checks.filter((c) => c.ok).length;
    log(`■ 合計: ${passed} / ${checks.length} 合格（サンプルアプリの起動 ${first.length + crashes.length + 5} 回）`);
    return { checks, passed, total: checks.length, launches: first.length + crashes.length + 5 };
  } finally {
    if (srv) await srv.close();
    if (!keep) fs.rmSync(work, { recursive: true, force: true });
    else log(`（作業フォルダを残しました: ${work}）`);
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const r = await runE2E({ keep: process.argv.includes('--keep') });
  if (r.skipped) { console.log(`飛ばしました: ${r.skipped}`); process.exit(0); }
  process.exit(r.passed === r.total ? 0 : 1);
}
