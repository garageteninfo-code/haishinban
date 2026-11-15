// 中継サーバー（server.mjs）の試験。127.0.0.1 の空いている番号で起動し、最後に止めて一時フォルダを消す。
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { CSP, startServer } from '../server.mjs';
import * as core from '../console/manifest-core.js';
import { fakeInstallId, fakeMobile, reporterIdFor } from '../scenario/fictional.mjs';
import { AdminClient } from '../scenario/admin-client.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const work = path.join(ROOT, '一時', `server-test-${crypto.randomBytes(4).toString('hex')}`);
let srv; let base; let keys; let admin; const logs = [];
const PASSWORD = `test-${crypto.randomBytes(12).toString('base64url')}`;   // 実行のたびに作る（ファイルに残さない）

/** 生の http で送る（Host・Origin を自由に変えるため）。 */
function raw(method, p, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
    const req = http.request({ host: '127.0.0.1', port: srv.port, method, path: p, headers: { ...(data !== undefined ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } : {}), ...headers } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json; try { json = JSON.parse(text); } catch { json = undefined; }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('error', reject);
    if (data !== undefined) req.write(data);
    req.end();
  });
}
const adminPut = (p, body, extra = {}) => admin.call('PUT', p, body, { extra });
const report = (installId, version, message, extra = {}) => ({ reporterId: reporterIdFor(installId), appVersion: version, os: 'Windows 11', reports: [{ fingerprint: 'crash-save-0001', kind: 'crash', title: '保存で落ちた', message, stack: 'at SampleApp.Save()', count: 1, ...extra }] });

before(async () => {
  for (const v of ['1.0.0', '1.1.0']) {
    fs.mkdirSync(path.join(work, 'release', 'files', v), { recursive: true });
    fs.writeFileSync(path.join(work, 'release', 'files', v, 'windows.zip'), crypto.randomBytes(1024));
  }
  srv = await startServer({ domain: 'sample-app', host: '127.0.0.1', port: 0, dataDir: path.join(work, 'data'), releaseDir: path.join(work, 'release'),
    threshold: { minActiveInstalls: 5, minCrashInstalls: 2, maxCrashRate: 0.2, windowHours: 72 }, guard: {}, limits: { reportsPerHour: 5, heartbeatsPerHour: 60 }, log: (m) => logs.push(m) });
  base = srv.url;
  keys = await core.generateKeyPair();
  admin = new AdminClient(base);
  await admin.loginOrSetup(PASSWORD);
});
after(async () => { if (srv) await srv.close(); fs.rmSync(work, { recursive: true, force: true }); });

test('報告を受け取り、ファイルに置く', async () => {
  const r = await raw('POST', '/v1/reports', { body: report(fakeInstallId(), '1.0.0', '在庫の保存に失敗しました') });
  assert.equal(r.status, 200);
  const files = fs.readdirSync(path.join(work, 'data', 'reports', '1.0.0'), { recursive: true }).filter((f) => f.endsWith('.json'));
  assert.equal(files.length, 1);
  const saved = fs.readFileSync(path.join(work, 'data', 'reports', '1.0.0', files[0]), 'utf8');
  assert.ok(!saved.includes('reporterId'), '端末の番号はそのまま置かない（混ぜた番号だけ）');
});

test('個人情報入りは 422 で断り、中身は 1 文字も置かない', async () => {
  const phone = fakeMobile();
  const r = await raw('POST', '/v1/reports', { body: report(fakeInstallId(), '1.0.0', `連絡先 ${phone} の印刷で失敗`) });
  assert.equal(r.status, 422);
  assert.equal(r.json.kind, 'phone');
  assert.ok(!r.text.includes(phone), '返事にも中身を載せない');
  const all = fs.readdirSync(path.join(work, 'data'), { recursive: true }).filter((f) => /\.jsonl?$/.test(f)).map((f) => fs.readFileSync(path.join(work, 'data', f), 'utf8')).join('');
  assert.ok(!all.includes(phone.slice(4)));
  assert.ok(all.includes('"kind":"phone"'), '断った記録（種類だけ）は残る');
});

test('形の確かめ：知らない欄・JSON でない・大きすぎる・installId そのもの', async () => {
  const id = fakeInstallId();
  assert.equal((await raw('POST', '/v1/reports', { body: { ...report(id, '1.0.0', 'x'), userName: 'taro' } })).status, 400);
  assert.equal((await raw('POST', '/v1/reports', { body: 'hello', headers: { 'content-type': 'text/plain' } })).status, 415);
  assert.equal((await raw('POST', '/v1/reports', { body: '{', headers: {} })).status, 400);
  assert.equal((await raw('POST', '/v1/reports', { body: report(id, '1.0.0', 'x'.repeat(70000)) })).status, 413);
  assert.equal((await raw('POST', '/v1/reports', { body: { ...report(id, '1.0.0', 'x'), reporterId: id } })).status, 400, '32 桁の installId は受けない');
});

test('1 台からの送りすぎは 429', async () => {
  const id = fakeInstallId();
  const codes = [];
  for (let i = 0; i < 7; i++) codes.push((await raw('POST', '/v1/reports', { body: report(id, '1.0.0', 'タイムアウト') })).status);
  assert.deepEqual(codes.slice(0, 5), [200, 200, 200, 200, 200]);
  assert.equal(codes[6], 429);
});

test('落ちる割合が基準を超えたら 1 度だけ知らせる', async () => {
  const ids = Array.from({ length: 6 }, fakeInstallId);
  for (const id of ids) assert.equal((await raw('POST', '/v1/heartbeat', { body: { reporterId: reporterIdFor(id), appVersion: '1.1.0', os: 'Windows 11' } })).status, 200);
  await raw('POST', '/v1/reports', { body: report(ids[0], '1.1.0', '起動で例外') });
  let st = (await admin.get('/api/admin/status')).json;
  assert.equal(st.versions.find((v) => v.version === '1.1.0').status, 'ok');
  await raw('POST', '/v1/reports', { body: report(ids[1], '1.1.0', '起動で例外') });
  st = (await admin.get('/api/admin/status')).json;
  const v = st.versions.find((x) => x.version === '1.1.0');
  assert.equal(v.status, 'over');
  assert.equal(v.crashInstalls, 2);
  assert.equal(v.activeInstalls, 6);
  await raw('POST', '/v1/reports', { body: report(ids[2], '1.1.0', '起動で例外') });
  assert.equal(logs.filter((l) => l.includes('[警告] 版 1.1.0')).length, 1);
  assert.equal(st.alerts.filter((a) => a.version === '1.1.0').length, 1);
});

test('管理画面：CSP つきで配る・知らないファイルは出さない', async () => {
  const r = await raw('GET', '/console/');
  assert.equal(r.status, 200);
  assert.equal(r.headers['content-security-policy'], CSP);
  assert.match(CSP, /script-src 'self'/);
  assert.ok(!/unsafe-inline|unsafe-eval|https?:/.test(CSP));
  assert.equal((await raw('GET', '/console/console.js')).status, 200);
  assert.equal((await raw('GET', '/console/../server.mjs')).status, 404);
  assert.equal((await raw('GET', '/console/%2e%2e%2fserver.mjs')).status, 404);
  assert.equal((await raw('GET', '/updates/files/..%2f..%2fdata/salt.txt')).status, 404);
  const html = fs.readFileSync(path.join(ROOT, 'console', 'index.html'), 'utf8');
  assert.ok(!/<script(?![^>]*src=)/.test(html) && !/style=/.test(html) && !/https?:\/\//.test(html), 'HTML に直書きの script・style・外のURL が無い');
});

test('管理の口：Host 違い（DNS の付け替え）・ログイン無し・印の無い書き込み・別の Origin・CSRF の札違いは断る', async () => {
  assert.equal((await raw('GET', '/api/admin/status', { headers: { host: `evil.example:${srv.port}` } })).status, 403);
  assert.equal((await admin.call('GET', '/api/admin/status', undefined, { extra: { host: `evil.example:${srv.port}` } })).status, 403, 'ログインしていても Host 違いは断る');
  assert.equal((await raw('GET', '/api/admin/status')).status, 401, 'ログインしていない');
  assert.equal((await raw('PUT', '/api/admin/public-key', { body: { pem: 'x' } })).status, 401);
  assert.equal((await raw('PUT', '/api/admin/public-key', { body: { pem: 'x' }, headers: { cookie: admin.cookie, 'x-csrf-token': admin.csrf } })).status, 403, '印の見出しが無い');
  assert.equal((await adminPut('/api/admin/public-key', { pem: 'x' }, { origin: 'http://evil.example' })).status, 403);
  assert.equal((await admin.call('PUT', '/api/admin/public-key', { pem: 'x' }, { csrf: false })).status, 403, 'CSRF の札が無い');
  assert.equal((await admin.call('PUT', '/api/admin/public-key', { pem: 'x' }, { extra: { 'x-csrf-token': 'wrong-token' } })).status, 403, 'CSRF の札が違う');
});

test('公開鍵は 1 度だけ・配信情報は署名・通し番号・ファイルを確かめてから置く', async () => {
  const pem = await core.exportPublicPem(keys.publicKey);
  assert.equal((await adminPut('/api/admin/public-key', { pem })).status, 200);
  const other = await core.generateKeyPair();
  assert.equal((await adminPut('/api/admin/public-key', { pem: await core.exportPublicPem(other.publicKey) })).status, 409, '置き換えない');

  const st = (await admin.get('/api/admin/status')).json;
  const sign = async (draft, k = keys) => (await core.signManifest({ draft, artifacts: st.artifacts[draft.version], domain: 'sample-app', privateKey: k.privateKey })).manifest;
  const m1 = await sign(core.draftRelease(null, { version: '1.1.0', percent: 10 }));
  assert.equal((await adminPut('/api/admin/manifest', { manifest: await sign(core.draftRelease(null, { version: '1.1.0', percent: 10 }), other) })).json.error, 'signature_mismatch:windows');
  assert.equal((await adminPut('/api/admin/manifest', { manifest: m1 })).status, 200);
  assert.equal((await adminPut('/api/admin/manifest', { manifest: m1 })).json.error, 'seq_not_increasing:1<=1');
  const m2 = await sign(core.draftHalt(m1));
  const wrongSize = structuredClone(m2); wrongSize.signatures.windows.size += 1;
  assert.match((await adminPut('/api/admin/manifest', { manifest: wrongSize })).json.error, /file_mismatch/);
  const extra = { ...m2, note: 'x' };
  assert.match((await adminPut('/api/admin/manifest', { manifest: extra })).json.error, /unknown_field/);
  assert.equal((await adminPut('/api/admin/manifest', { manifest: m2 })).status, 200);
  const served = await raw('GET', '/updates/manifest.json');
  assert.equal(served.json.rollout.percent, 0);
  const file = await raw('GET', served.json.signatures.windows.url);
  assert.equal(file.status, 200);
  assert.ok(fs.existsSync(path.join(work, 'release', 'manifests', 'seq-1.json')), '過去の配信情報を残す');
});
