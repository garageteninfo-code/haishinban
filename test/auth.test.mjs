// 管理画面のログイン・CSRF・試行回数の制限・https・社内の別の PC（LAN）からの開き方の試験。
// 合言葉・証明書・鍵はすべて実行のたびに作り、最後に作業フォルダごと消す。
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { checkConsoleConfig, startServer } from '../server.mjs';
import { ConsoleAuth, passwordProblem } from '../lib/auth.mjs';
import { AdminClient, request } from '../scenario/admin-client.mjs';
import { findOpenssl, makeCert } from '../tools/make-cert.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const work = path.join(ROOT, '一時', `auth-test-${crypto.randomBytes(4).toString('hex')}`);
const servers = [];
const pw = () => `pw-${crypto.randomBytes(12).toString('base64url')}`;
after(async () => { for (const s of servers) await s.close(); fs.rmSync(work, { recursive: true, force: true }); });

async function start(name, extra = {}) {
  const dir = path.join(work, name);
  const s = await startServer({ domain: 'sample-app', host: '127.0.0.1', port: 0, dataDir: path.join(dir, 'data'), releaseDir: path.join(dir, 'release'),
    threshold: {}, guard: {}, limits: { reportsPerHour: 30, heartbeatsPerHour: 60 }, log: () => undefined, ...extra });
  servers.push(s);
  return s;
}
test('合言葉の形：12 文字未満・同じ文字の繰り返し・制御文字は断る', () => {
  assert.equal(passwordProblem('short'), 'too_short');
  assert.equal(passwordProblem('aaaaaaaaaaaaaaaa'), 'too_simple');
  assert.equal(passwordProblem('abcdefghijkl\n'), 'control_chars');
  assert.equal(passwordProblem('とても長い日本語の合言葉です'), null);
});

test('初回の設定 → ログイン → ログアウト。Cookie は HttpOnly・SameSite=Strict。記録には合言葉そのものを置かない', async () => {
  const s = await start('basic');
  const a = new AdminClient(s.url);
  let r = await a.get('/api/admin/session');
  assert.equal(r.json.setupNeeded, true);
  assert.equal(r.json.setupAllowedHere, true);
  assert.equal((await a.get('/api/admin/status')).status, 401, '設定の前は何も見せない');
  assert.equal((await a.post('/api/admin/setup', { password: 'short' })).status, 400);
  const password = pw();
  r = await a.post('/api/admin/setup', { password });
  assert.equal(r.status, 200);
  const sc = String(r.headers['set-cookie']);
  assert.match(sc, /HttpOnly/); assert.match(sc, /SameSite=Strict/); assert.doesNotMatch(sc, /Secure/, 'http のときは Secure を付けない');
  assert.equal((await a.get('/api/admin/status')).status, 200);
  assert.equal((await new AdminClient(s.url).post('/api/admin/setup', { password: pw() })).status, 409, '2 回目の設定はできない（乗っ取り防止）');
  const rec = fs.readFileSync(path.join(work, 'basic', 'data', 'console-auth.json'), 'utf8');
  assert.ok(!rec.includes(password));
  assert.equal(JSON.parse(rec).algo, 'scrypt');
  const old = a.cookie;
  assert.equal((await a.post('/api/admin/logout')).status, 200);
  assert.equal((await request(s.url, 'GET', '/api/admin/status', { headers: { cookie: old } })).status, 401, 'ログアウトした札は使えない');
  const b = new AdminClient(s.url);
  assert.equal((await b.post('/api/admin/login', { password: password + 'x' })).status, 401);
  assert.equal((await b.post('/api/admin/login', { password })).status, 200);
  assert.equal((await b.get('/api/admin/status')).status, 200);
});

test('まちがいが続くと 429（正しい合言葉でも待つ）・書き込みは CSRF の札と同じ Origin が要る・合言葉を変えると古い札は無効', async () => {
  const s = await start('limit', { authLimits: { maxFailures: 3, lockMinutes: 15 } });
  const password = pw();
  const a = new AdminClient(s.url);
  await a.loginOrSetup(password);
  const lockSrv = await start('limit-lock', { authLimits: { maxFailures: 3, lockMinutes: 15 } });
  await new AdminClient(lockSrv.url).loginOrSetup(password);
  const b = new AdminClient(lockSrv.url);
  const codes = [];
  for (let i = 0; i < 4; i++) codes.push((await b.post('/api/admin/login', { password: 'wrong-password-123' })).status);
  assert.deepEqual(codes, [401, 401, 429, 429]);
  const locked = await b.post('/api/admin/login', { password });
  assert.equal(locked.status, 429);
  assert.ok(Number(locked.headers['retry-after']) > 0);
  // CSRF
  assert.equal((await a.call('PUT', '/api/admin/public-key', { pem: 'x' }, { csrf: false })).status, 403);
  assert.equal((await a.call('POST', '/api/admin/logout', {}, { extra: { 'x-csrf-token': 'x'.repeat(43) } })).status, 403);
  assert.equal((await a.call('PUT', '/api/admin/public-key', { pem: 'x' }, { extra: { origin: 'http://evil.example' } })).status, 403);
  assert.equal((await a.call('PUT', '/api/admin/public-key', { pem: 'x' })).status, 409, '札が正しければ中身の確かめまで進む（不正な鍵なので 409）');
  // 合言葉の変更
  const a2 = new AdminClient(s.url); a2.cookie = a.cookie; a2.csrf = a.csrf;
  assert.equal((await a.post('/api/admin/password', { current: 'wrong-password-123', next: pw() })).status, 401);
  const next = pw();
  assert.equal((await a.post('/api/admin/password', { current: password, next })).status, 200);
  assert.equal((await a2.get('/api/admin/status')).status, 401, '変える前の札は無効');
  assert.equal((await a.get('/api/admin/status')).status, 200, '変えた本人には新しい札');
});

test('セッションには期限がある（既定 8 時間）', async () => {
  let t = Date.now();
  const auth = new ConsoleAuth({ file: path.join(work, 'expiry', 'a.json'), now: () => t, sessionHours: 1 });
  await auth.setPassword(pw());
  const { token } = auth.issue();
  assert.ok(auth.session(token));
  t += 3600 * 1000 + 1;
  assert.equal(auth.session(token), null);
});

test('設定の確かめ：LAN を開くには名前の一覧と https が要る', () => {
  assert.throws(() => checkConsoleConfig({ allowLan: true, allowedHosts: [], allowedClients: [], sessionHours: 8 }, { enabled: true }), /allowedHosts/);
  assert.throws(() => checkConsoleConfig({ allowLan: true, allowedHosts: ['haishin.example.local'], allowedClients: [], sessionHours: 8 }, { enabled: false }), /https/);
  assert.throws(() => checkConsoleConfig({ allowLan: true, allowedHosts: ['bad host/'], allowedClients: [], sessionHours: 8 }, { enabled: true }), /形が不正/);
  assert.doesNotThrow(() => checkConsoleConfig({ allowLan: true, allowedHosts: ['haishin.example.local'], allowedClients: [], sessionHours: 8, allowLanWithoutTls: true }, { enabled: false }));
  assert.doesNotThrow(() => checkConsoleConfig({ allowLan: false, allowedHosts: [], allowedClients: [], sessionHours: 8 }, { enabled: false }));
});

const openssl = findOpenssl();
test('https：作った証明書で動く・Cookie に Secure・指紋が証明書と一致・http では話せない', { skip: openssl ? false : 'openssl が無い' }, async () => {
  const c = makeCert({ outDir: path.join(work, 'tls', 'certs'), openssl });
  const ca = fs.readFileSync(c.certFile);
  const s = await start('tls', { tls: { enabled: true, certFile: c.certFile, keyFile: c.keyFile } });
  assert.equal(s.scheme, 'https');
  assert.equal(s.certFingerprint.hex, c.fingerprint.hex);
  assert.equal((await request(s.url, 'GET', '/v1/health', { ca })).status, 200);
  const a = new AdminClient(s.url, { ca });
  const r = await a.loginOrSetup(pw());
  assert.match(String(r.headers['set-cookie']), /Secure/);
  assert.equal((await a.call('PUT', '/api/admin/public-key', { pem: 'x' }, { extra: { origin: `http://127.0.0.1:${s.port}` } })).status, 403, 'https のときは http の Origin を断る');
  await assert.rejects(request(s.url, 'GET', '/v1/health'), 'ca を渡さないと（知らない証明書なので）つながらない');
  await assert.rejects(request(`http://127.0.0.1:${s.port}`, 'GET', '/v1/health'));
});

// 「社内の別の PC」は、この PC の社内側の IP から自分へつなぐことで代わりにする（サーバーはその IP だけで短い間待ち受ける。0.0.0.0 にはしない）。
// サーバーが「この PC」と見なすのは 127.0.0.1 と ::1 だけなので、社内側の IP からの接続は「別の PC」として扱われる。本物の別の PC からは試していない。
function lanIp() {
  for (const list of Object.values(os.networkInterfaces())) for (const a of list || []) if (a.family === 'IPv4' && !a.internal && !a.address.startsWith('169.254.')) return a.address;
  return null;
}
// 社内側の IP を使うので、環境変数 HAISHIN_TEST_LAN=1 のときだけ行う（既定は飛ばす＝127.0.0.1 だけで試す）。
const SRV = process.env.HAISHIN_TEST_LAN === '1' ? lanIp() : null; const PEER = SRV;
test('社内の別の PC（LAN）から：既定は断る・allowLan で名前が合えば開ける・初回の設定はこの PC からだけ', { skip: openssl && SRV ? false : 'HAISHIN_TEST_LAN=1 のときだけ（openssl と社内の IP も要る）' }, async () => {
  const c = makeCert({ outDir: path.join(work, 'lan', 'certs'), ips: [SRV], dns: ['haishin.example.local'], openssl });
  const ca = fs.readFileSync(c.certFile);
  const tls = { enabled: true, certFile: c.certFile, keyFile: c.keyFile };
  // 既定（allowLan: false）
  const s0 = await start('lan0', { host: SRV, tls });
  assert.equal((await request(`https://${SRV}:${s0.port}`, 'GET', '/api/admin/session', { ca, localAddress: PEER })).status, 403);
  assert.equal((await request(`https://${SRV}:${s0.port}`, 'GET', '/v1/health', { ca, localAddress: PEER })).status, 200, '端末向けの口は届く');
  // allowLan: true
  const s = await start('lan1', { host: SRV, tls, console: { allowLan: true, allowedHosts: [SRV], allowedClients: [], sessionHours: 8 } });
  const base = `https://${SRV}:${s.port}`;
  const lan = new AdminClient(base, { ca, localAddress: PEER });
  const sess = await lan.get('/api/admin/session');
  assert.equal(sess.status, 200);
  assert.equal(sess.json.setupAllowedHere, false);
  assert.equal((await lan.post('/api/admin/setup', { password: pw() })).status, 403, '初回の設定は別の PC からはできない');
  const password = pw();
  // 初回の設定は「この PC」から。LAN の IP だけで待ち受けているので、ここでは記録を直接作る（画面の初回設定と同じ関数）。
  await s.auth.setPassword(password);
  assert.equal((await lan.post('/api/admin/login', { password })).status, 200);
  assert.equal((await lan.get('/api/admin/status')).status, 200);
  assert.equal((await lan.call('GET', '/api/admin/status', undefined, { extra: { host: `evil.example:${s.port}` } })).status, 403, '一覧に無い名前（DNS の付け替え）は断る');
  assert.equal((await lan.call('GET', '/api/admin/status', undefined, { extra: { host: `127.0.0.1:${s.port}` } })).status, 403, '別の PC が「127.0.0.1」を名乗っても断る');
  // allowedClients で接続元をしぼる
  const s2 = await start('lan2', { host: SRV, tls, console: { allowLan: true, allowedHosts: [SRV], allowedClients: ['10.255.255.'], sessionHours: 8 } });
  assert.equal((await request(`https://${SRV}:${s2.port}`, 'GET', '/api/admin/session', { ca, localAddress: PEER })).status, 403);
});
