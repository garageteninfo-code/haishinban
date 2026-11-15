// C# の報告の送り手（CrashReporter）を、本物の中継（https・この PC の中）に向けて動かす試験。
// .NET 10 の SDK と openssl があるときだけ（無ければ飛ばす。ダウンロードはしない）。証明書・鍵・作業フォルダは最後に消す。
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startServer } from '../server.mjs';
import { AdminClient } from '../scenario/admin-client.mjs';
import { findOpenssl, makeCert } from '../tools/make-cert.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PROJ = path.join(ROOT, 'csharp', 'kit-tests', 'tests', 'Reporter.Tests');
const work = path.join(ROOT, '一時', `cs-reporter-${crypto.randomBytes(4).toString('hex')}`);
let srv;
after(async () => { if (srv) await srv.close(); fs.rmSync(work, { recursive: true, force: true }); });

export function findDotnet() {
  for (const exe of [process.env.HAISHIN_DOTNET, path.join(os.homedir(), '.dotnet', process.platform === 'win32' ? 'dotnet.exe' : 'dotnet'), 'dotnet'].filter(Boolean)) {
    const r = spawnSync(exe, ['--list-sdks'], { encoding: 'utf8' });
    if (r.status === 0 && /^10\./m.test(r.stdout || '')) return exe;
  }
  return null;
}
const dotnet = findDotnet();
const openssl = findOpenssl();
const env = { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_NOLOGO: '1' };

test('C# の CrashReporter：単体の試験（偽物の送り先）', { skip: dotnet ? false : '.NET 10 SDK なし', timeout: 300000 }, () => {
  const r = spawnSync(dotnet, ['run', '-c', 'Release'], { cwd: PROJ, encoding: 'utf8', env });
  const tail = (r.stdout || '').split('\n').filter((l) => /FAIL|合計/.test(l)).join('\n');
  console.log(`  ${tail.trim()}`);
  assert.equal(r.status, 0, tail || r.stderr);
});

test('C# の CrashReporter → 本物の中継（https・指紋の固定・422 で欄を伏せて送り直し）', { skip: dotnet && openssl ? false : '.NET 10 SDK か openssl なし', timeout: 300000 }, async () => {
  const c = makeCert({ outDir: path.join(work, 'certs'), openssl });
  srv = await startServer({ domain: 'sample-app', host: '127.0.0.1', port: 0, dataDir: path.join(work, 'data'), releaseDir: path.join(work, 'release'),
    threshold: {}, guard: {}, limits: { reportsPerHour: 30, heartbeatsPerHour: 60 }, tls: { enabled: true, certFile: c.certFile, keyFile: c.keyFile }, log: () => undefined });
  // 子プロセスの間も中継が答えられるよう、非同期で走らせる
  const { spawn } = await import('node:child_process');
  const out = await new Promise((resolve) => {
    const p = spawn(dotnet, ['run', '-c', 'Release', '--no-build', '--', '--relay', `${srv.url}/`, '--pin', srv.certFingerprint.hex, '--work', path.join(work, 'client')], { cwd: PROJ, env });
    let s = '';
    p.stdout.on('data', (d) => { s += d; });
    p.stderr.on('data', (d) => { s += d; });
    p.on('close', (code) => resolve({ code, s }));
  });
  console.log(out.s.split('\n').filter((l) => /PASS|FAIL|合計/.test(l)).map((l) => '  ' + l.trim()).join('\n'));
  assert.equal(out.code, 0, out.s);
  const a = new AdminClient(srv.url, { ca: fs.readFileSync(c.certFile) });
  await a.loginOrSetup(`t-${crypto.randomBytes(12).toString('base64url')}`);
  const st = (await a.get('/api/admin/status')).json;
  assert.ok(st.refused.address >= 1, '中継は住所入りを断った（種類だけ記録）');
  const v = st.versions.find((x) => x.version === '1.1.0');
  assert.equal(v.activeInstalls, 1);
  assert.equal(v.crashInstalls, 1);
  const saved = fs.readdirSync(path.join(work, 'data'), { recursive: true }).filter((f) => /\.jsonl?$/.test(f)).map((f) => fs.readFileSync(path.join(work, 'data', f), 'utf8')).join('\n');
  assert.ok(!saved.includes('梅田') && !saved.includes('山田'), '住所・利用者名はどこにも保存されていない');
  assert.ok(saved.includes('[伏せ字:address]'), '断られた欄は端末の側で丸ごと伏せてから届いた');
});
