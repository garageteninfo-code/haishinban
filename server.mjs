// 配信番（Windowsアプリ配信の安全セット）：この PC で動く「報告の中継＋更新の置き場＋管理画面」。Node の標準だけ（npm install 不要）。
//
//   node server.mjs [--config config.json]
//
// 端末（Windows アプリ）向け:
//   POST /v1/heartbeat        起動の知らせ { reporterId, appVersion, os }（落ちる割合の分母）
//   POST /v1/reports          不具合の報告。個人情報・鍵が入っていれば 422 で断り、中身は保存しない
//   GET  /v1/health
//   GET  /updates/manifest.json            署名済みの配信情報（UpdateSafetyKit が読む）
//   GET  /updates/files/<版>/<os>.zip      配るファイル
// 管理（既定はこの PC からだけ。config の console.allowLan で社内の別の PC からも。どちらも Host を確かめ、ログインが要る）:
//   GET  /console/            管理画面（日本語）。署名は画面の中（WebCrypto）で行い、秘密鍵はサーバーへ送らない
//   GET  /api/admin/session   ログインしているか・初回の設定が要るか（ログインしていれば CSRF の札）
//   POST /api/admin/setup     初回だけ：合言葉を決める（この PC＝127.0.0.1 からだけ）
//   POST /api/admin/login     合言葉でログイン（15 分に 5 回まちがえると 429）
//   POST /api/admin/logout    ログアウト
//   POST /api/admin/password  合言葉を変える（ほかのセッションは無効になる）
//   GET  /api/admin/status    版ごとの数字・配信情報・知らせ・断った件数
//   PUT  /api/admin/public-key  公開鍵を登録（1 度だけ）
//   PUT  /api/admin/manifest    署名済みの配信情報を置く（サーバーでも署名と通し番号を確かめ直す）
// 書き込み（POST/PUT）は x-haishin-console: 1・Content-Type: application/json・同じ Origin・（ログイン後は）x-csrf-token が要る。
// https（任意）: config の tls.enabled と証明書（tools/make-cert.mjs で作れる）。起動時に証明書の指紋（SHA-256）を表示する。

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { clearCookie, ConsoleAuth, readCookie, sessionCookie } from './lib/auth.mjs';
import { createGuard } from './lib/guard.mjs';
import { ReleaseDir } from './lib/release.mjs';
import { Store } from './lib/store.mjs';
import { CHECKED_REPORT_FIELDS, CHECKED_TOP_FIELDS, LIMITS, readBodyCapped, validateHeartbeat, validateReports } from './lib/validate.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const VERSION = '0.2.0-local';

const CONSOLE_FILES = {
  'index.html': 'text/html; charset=utf-8',
  'console.js': 'text/javascript; charset=utf-8',
  'manifest-core.js': 'text/javascript; charset=utf-8',
  'console.css': 'text/css; charset=utf-8',
};
export const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
const BASE_HEADERS = { 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'cache-control': 'no-store', 'x-frame-options': 'DENY' };
const LOOPBACK_ADDR = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

function send(res, status, body, headers = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  const ct = Buffer.isBuffer(body) || typeof body === 'string' ? {} : { 'content-type': 'application/json; charset=utf-8' };
  res.writeHead(status, { ...BASE_HEADERS, ...ct, ...headers, 'content-length': buf.length });
  res.end(buf);
}

class RateLimiter {
  constructor(limit, windowMs = 3600 * 1000) { this.limit = limit; this.windowMs = windowMs; this.m = new Map(); }
  hit(key, now) {
    const b = Math.floor(now / this.windowMs);
    const cur = this.m.get(key);
    const n = cur && cur.b === b ? cur.n : 0;
    if (n >= this.limit) return false;
    this.m.set(key, { b, n: n + 1 });
    if (this.m.size > 50000) for (const [k, v] of this.m) if (v.b !== b) this.m.delete(k);
    return true;
  }
}

const stripComments = (o) => Object.fromEntries(Object.entries(o || {}).filter(([k]) => !k.startsWith('//')));

export function loadConfig(file) {
  const cfg = file ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
  const base = file ? path.dirname(path.resolve(file)) : HERE;
  const tls = stripComments(cfg.tls);
  return {
    domain: cfg.domain ?? 'sample-app',
    host: cfg.host ?? '127.0.0.1',
    port: cfg.port ?? 38920,
    dataDir: path.resolve(base, cfg.dataDir ?? 'data'),
    releaseDir: path.resolve(base, cfg.releaseDir ?? 'release'),
    threshold: stripComments(cfg.threshold),
    guard: cfg.guard ?? {},
    limits: { reportsPerHour: 30, heartbeatsPerHour: 60, ...(cfg.limits ?? {}) },
    console: { allowLan: false, allowedHosts: [], allowedClients: [], sessionHours: 8, allowLanWithoutTls: false, ...stripComments(cfg.console) },
    tls: {
      enabled: !!tls.enabled,
      certFile: tls.certFile ? path.resolve(base, tls.certFile) : undefined,
      keyFile: tls.keyFile ? path.resolve(base, tls.keyFile) : undefined,
    },
  };
}

/** 証明書の指紋（SHA-256）。colon は「AB:CD:…」、hex は区切りなしの小文字（C# の PinnedCertSha256 に入れる値）。 */
export function certFingerprint(certPem) {
  const fp = new crypto.X509Certificate(certPem).fingerprint256;
  return { colon: fp, hex: fp.replace(/:/g, '').toLowerCase() };
}

/** 管理の口の設定を確かめる（危ない組み合わせでは起動しない）。 */
export function checkConsoleConfig(c, tls) {
  if (!Array.isArray(c.allowedHosts) || !Array.isArray(c.allowedClients)) throw new Error('console.allowedHosts・allowedClients は配列');
  if (!(typeof c.sessionHours === 'number' && c.sessionHours > 0 && c.sessionHours <= 24 * 7)) throw new Error('console.sessionHours は 0 より大きく 168 以下');
  if (!c.allowLan) return;
  if (c.allowedHosts.length === 0) throw new Error('console.allowLan が true のときは console.allowedHosts に、別の PC から開くときの名前（例 "haishin.example.local" や "192.168.10.5"）を書いてください（DNS の付け替え対策）');
  for (const h of c.allowedHosts) if (typeof h !== 'string' || !/^(?:[A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])(?::\d{1,5})?$/.test(h)) throw new Error(`console.allowedHosts の形が不正: ${h}`);
  for (const p of c.allowedClients) if (typeof p !== 'string' || !/^[0-9a-fA-F.:]+$/.test(p)) throw new Error(`console.allowedClients の形が不正: ${p}（例 "192.168.10."）`);
  if (!tls.enabled && !c.allowLanWithoutTls) throw new Error('社内の別の PC から管理画面を開くには https（tls.enabled）が要ります（合言葉が平文で流れるため）。どうしても http で使うときだけ console.allowLanWithoutTls を true に（勧めません）');
}

/**
 * サーバーを起動する（試験・サンプルの台本からも呼ぶ）。
 * @param {ReturnType<typeof loadConfig> & { now?: () => number, log?: (m: string) => void, authLimits?: object }} cfg
 */
export async function startServer(cfg) {
  const now = cfg.now ?? (() => Date.now());
  const log = cfg.log ?? ((m) => console.log(m));
  if (!/^[a-z0-9][a-z0-9.-]{0,39}$/.test(cfg.domain)) throw new Error('domain（製品名）の形が不正');
  const guard = createGuard(cfg.guard);
  const store = new Store({ dataDir: cfg.dataDir, threshold: cfg.threshold, now, log });
  const release = new ReleaseDir({ dir: cfg.releaseDir, domain: cfg.domain });
  const rlReports = new RateLimiter(cfg.limits.reportsPerHour);
  const rlBeats = new RateLimiter(cfg.limits.heartbeatsPerHour);
  const cc = { allowLan: false, allowedHosts: [], allowedClients: [], sessionHours: 8, allowLanWithoutTls: false, ...(cfg.console ?? {}) };
  const tls = cfg.tls ?? { enabled: false };
  checkConsoleConfig(cc, tls);
  const scheme = tls.enabled ? 'https' : 'http';
  let tlsOpts;
  if (tls.enabled) {
    if (!tls.certFile || !tls.keyFile || !fs.existsSync(tls.certFile) || !fs.existsSync(tls.keyFile)) throw new Error('tls.enabled なのに証明書（tls.certFile）か鍵（tls.keyFile）が見つからない（tools/make-cert.mjs で作れます）');
    tlsOpts = { cert: fs.readFileSync(tls.certFile), key: fs.readFileSync(tls.keyFile), minVersion: 'TLSv1.2' };
  }
  const auth = new ConsoleAuth({ file: path.join(cfg.dataDir, 'console-auth.json'), now, sessionHours: cc.sessionHours, ...(cfg.authLimits ?? {}) });
  let port = cfg.port;

  const isLoopback = (req) => LOOPBACK_ADDR.has(req.socket.remoteAddress);
  const clientAddr = (req) => String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
  const withPort = (h) => (/:\d+$/.test(h) && !/^\[[^\]]*\]$/.test(h) ? h : `${h}:${port}`).toLowerCase();
  /** 管理の口を開けてよい相手か（接続元と Host の見出し。Host を確かめるのは DNS の付け替え対策）。 */
  const isAdmin = (req) => {
    const host = String(req.headers.host || '').toLowerCase();
    if (isLoopback(req) && (host === `127.0.0.1:${port}` || host === `localhost:${port}` || host === `[::1]:${port}`)) return true;
    if (!cc.allowLan) return false;
    if (!cc.allowedHosts.some((h) => withPort(h) === host)) return false;
    if (cc.allowedClients.length > 0 && !cc.allowedClients.some((p) => clientAddr(req).startsWith(p))) return false;
    return true;
  };
  /** 書き込みの最低条件（ログインの前でも要る）：印の見出し・同じ Origin・JSON。 */
  const writeShapeOk = (req) => {
    if (req.headers['x-haishin-console'] !== '1') return false;
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== `${scheme}://${req.headers.host}`) return false;
    return String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json');
  };
  const sessionOf = (req) => auth.session(readCookie(req));
  const cookieOpts = { secure: tls.enabled, maxAgeSec: Math.floor(cc.sessionHours * 3600) };

  async function readJson(req, res) {
    if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) { send(res, 415, { error: 'content_type_must_be_json' }); return undefined; }
    const body = await readBodyCapped(req, LIMITS.bodyBytes);
    if (!body.ok) { send(res, body.status, { error: body.error }); return undefined; }
    try { return JSON.parse(body.text); } catch { send(res, 400, { error: 'invalid_json' }); return undefined; }
  }

  function status() {
    const manifest = release.manifest();
    const artifacts = release.artifacts();
    const versions = new Set([...Object.keys(artifacts), ...store.allStats().map((s) => s.version)]);
    const bad = new Set(manifest?.rollback?.badVersions ?? []);
    const rows = [...versions].map((v) => {
      const st = store.stats(v);
      let rollout = null;
      if (bad.has(v)) rollout = 'revoked';
      else if (manifest && manifest.version === v) rollout = manifest.rollout ? manifest.rollout.percent : 100;
      return { ...st, rollout, hasFiles: !!artifacts[v], alerted: store.alerted.has(v) };
    });
    rows.sort((a, b) => b.version.localeCompare(a.version, 'en', { numeric: true }));
    return {
      server: VERSION, domain: cfg.domain, threshold: store.th, manifest, artifacts, versions: rows,
      alerts: store.alerts(), refused: store.refusedCounts, publicKeyPem: release.publicKeyPem(),
    };
  }

  async function handle(req, res) {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;

    // ---- 端末向け ----
    if (p === '/v1/health' && req.method === 'GET') return send(res, 200, { ok: true, version: VERSION });
    if (p === '/v1/heartbeat' || p === '/v1/reports') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' }, { allow: 'POST' });
      const body = await readJson(req, res);
      if (body === undefined) return;
      if (p === '/v1/heartbeat') {
        const v = validateHeartbeat(body);
        if (!v.ok) return send(res, 400, { error: 'invalid_payload', field: v.field, reason: v.reason });
        const leak = guard.checkFields({ os: v.value.os });
        if (leak) { store.refused({ ...leak, appVersion: v.value.appVersion }); return send(res, 422, { error: 'personal_data_refused', field: leak.field, kind: leak.kind }); }
        if (!rlBeats.hit(v.value.reporterId, now())) return send(res, 429, { error: 'rate_limited' });
        const alert = store.heartbeat(v.value);
        return send(res, 200, { ok: true, alert: alert ? true : undefined });
      }
      const v = validateReports(body, now());
      if (!v.ok) return send(res, 400, { error: 'invalid_payload', field: v.field, reason: v.reason });
      const fields = {};
      for (const k of CHECKED_TOP_FIELDS) fields[k] = v.value[k];
      v.value.reports.forEach((r, i) => { for (const k of CHECKED_REPORT_FIELDS) fields[`reports[${i}].${k}`] = r[k]; });
      const leak = guard.checkFields(fields);
      if (leak) {
        // 断った報告は 1 文字も保存しない。記録は「いつ・どの欄・どの種類」だけ。
        store.refused({ ...leak, appVersion: v.value.appVersion });
        return send(res, 422, { error: 'personal_data_refused', field: leak.field, kind: leak.kind, message: '個人情報か鍵らしい物が入っているため受け取りませんでした。端末側で伏せ字にしてから送ってください。' });
      }
      if (!rlReports.hit(v.value.reporterId, now())) return send(res, 429, { error: 'rate_limited' });
      const r = store.saveReports(v.value);
      return send(res, 200, { accepted: v.value.reports.length, alert: r.alert ? true : undefined });
    }
    if (p === '/updates/manifest.json' && req.method === 'GET') {
      const m = release.manifest();
      return m ? send(res, 200, m) : send(res, 404, { error: 'no_manifest' });
    }
    const fm = /^\/updates\/files\/([^/]+)\/([^/]+)$/.exec(p);
    if (fm && req.method === 'GET') {
      let v, f;
      try { v = decodeURIComponent(fm[1]); f = decodeURIComponent(fm[2]); } catch { return send(res, 400, { error: 'bad_path' }); }
      const file = release.filePath(v, f);
      if (!file) return send(res, 404, { error: 'not_found' });
      return send(res, 200, fs.readFileSync(file), { 'content-type': 'application/octet-stream', 'cache-control': 'no-cache' });
    }

    // ---- 管理（既定はこの PC からだけ・ログインが要る） ----
    if (p === '/' || p === '/console' || p.startsWith('/console/') || p.startsWith('/api/admin/')) {
      if (!isAdmin(req)) return send(res, 403, { error: 'admin_not_allowed_from_here' });
    }
    if ((p === '/' || p === '/console') && req.method === 'GET') return send(res, 302, '', { location: '/console/' });
    if (p.startsWith('/console/') && req.method === 'GET') {
      // 画面のファイル（秘密は入っていない）はログインの前でも配る（ログインの画面を出すため）
      const name = p === '/console/' ? 'index.html' : p.slice('/console/'.length);
      if (!Object.hasOwn(CONSOLE_FILES, name)) return send(res, 404, { error: 'not_found' });
      const headers = { 'content-type': CONSOLE_FILES[name] };
      if (name === 'index.html') headers['content-security-policy'] = CSP;
      return send(res, 200, fs.readFileSync(path.join(HERE, 'console', name)), headers);
    }
    if (!p.startsWith('/api/admin/')) return send(res, 404, { error: 'not_found' });

    if (p === '/api/admin/session' && req.method === 'GET') {
      const s = sessionOf(req);
      return send(res, 200, { loggedIn: !!s, setupNeeded: !auth.isSetUp(), setupAllowedHere: !auth.isSetUp() && isLoopback(req), csrf: s ? s.csrf : undefined, https: tls.enabled, lan: cc.allowLan });
    }
    if (p === '/api/admin/setup' || p === '/api/admin/login') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' }, { allow: 'POST' });
      if (!writeShapeOk(req)) return send(res, 403, { error: 'console_header_or_origin' });
      const body = await readJson(req, res);
      if (body === undefined) return;
      if (p === '/api/admin/setup') {
        if (auth.isSetUp()) return send(res, 409, { error: 'already_set_up' });
        if (!isLoopback(req)) return send(res, 403, { error: 'setup_only_from_this_pc' });
        const r = await auth.setPassword(body?.password);
        if (!r.ok) return send(res, 400, r);
        log('[管理] 管理画面の合言葉を設定しました（初回）');
        const t = auth.issue();
        return send(res, 200, { ok: true, csrf: t.csrf }, { 'set-cookie': sessionCookie(t.token, cookieOpts) });
      }
      const r = await auth.login(clientAddr(req), body?.password);
      if (!r.ok) {
        if (r.status === 429) log(`[管理] ログインの失敗が続いたので ${r.retryAfter} 秒止めます（接続元 ${clientAddr(req)}）`);
        return send(res, r.status, { error: r.error, retryAfter: r.retryAfter }, r.retryAfter ? { 'retry-after': String(r.retryAfter) } : {});
      }
      return send(res, 200, { ok: true, csrf: r.csrf }, { 'set-cookie': sessionCookie(r.token, cookieOpts) });
    }

    // ここから先はログインが要る
    const sess = sessionOf(req);
    if (!sess) return send(res, 401, { error: 'login_required' });
    const csrfOk = () => writeShapeOk(req) && ConsoleAuth.csrfOk(sess, req.headers['x-csrf-token']);

    if (p === '/api/admin/logout') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' }, { allow: 'POST' });
      if (!csrfOk()) return send(res, 403, { error: 'csrf' });
      auth.logout(readCookie(req));
      return send(res, 200, { ok: true }, { 'set-cookie': clearCookie(cookieOpts) });
    }
    if (p === '/api/admin/password') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' }, { allow: 'POST' });
      if (!csrfOk()) return send(res, 403, { error: 'csrf' });
      const body = await readJson(req, res);
      if (body === undefined) return;
      const wait = auth.lockedFor(clientAddr(req));
      if (wait > 0) return send(res, 429, { error: 'too_many_attempts', retryAfter: wait }, { 'retry-after': String(wait) });
      if (!(await auth.verify(body?.current))) { auth.fail(clientAddr(req)); return send(res, 401, { error: 'wrong_password' }); }
      const r = await auth.setPassword(body?.next);
      if (!r.ok) return send(res, 400, r);
      log('[管理] 管理画面の合言葉を変えました（ほかのセッションはすべて無効）');
      const t = auth.issue();
      return send(res, 200, { ok: true, csrf: t.csrf }, { 'set-cookie': sessionCookie(t.token, cookieOpts) });
    }
    if (p === '/api/admin/status' && req.method === 'GET') return send(res, 200, status());
    if (p === '/api/admin/public-key' || p === '/api/admin/manifest') {
      if (req.method !== 'PUT') return send(res, 405, { error: 'method_not_allowed' }, { allow: 'PUT' });
      if (!writeShapeOk(req)) return send(res, 403, { error: 'console_header_or_origin' });
      if (!ConsoleAuth.csrfOk(sess, req.headers['x-csrf-token'])) return send(res, 403, { error: 'csrf' });
      const body = await readJson(req, res);
      if (body === undefined) return;
      if (p === '/api/admin/public-key') {
        const r = release.setPublicKey(String(body?.pem ?? ''));
        return send(res, r.ok ? 200 : 409, r);
      }
      const r = release.publish(body?.manifest);
      if (r.ok) log(`[配信] 配信情報を置きました: 版 ${body.manifest.version}・割合 ${body.manifest.rollout ? body.manifest.rollout.percent + '%' : '全員'}・取り下げ ${(body.manifest.rollback?.badVersions ?? []).join(',') || 'なし'}・通し番号 ${r.seq}`);
      return send(res, r.ok ? 200 : 409, r);
    }
    return send(res, 404, { error: 'not_found' });
  }

  const onRequest = (req, res) => {
    handle(req, res).catch((e) => {
      log(`[中継] 想定外の失敗: ${e && e.message ? e.message : String(e)}`);
      if (!res.headersSent) send(res, 500, { error: 'internal_error' });
      else res.end();
    });
  };
  const server = tls.enabled ? https.createServer(tlsOpts, onRequest) : http.createServer(onRequest);
  server.headersTimeout = 20000;
  server.requestTimeout = 30000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(cfg.port, cfg.host, () => { server.off('error', reject); resolve(); });
  });
  port = server.address().port;
  return {
    server, store, release, port, auth, scheme,
    url: `${scheme}://127.0.0.1:${port}`,
    certFingerprint: tls.enabled ? certFingerprint(tlsOpts.cert.toString('utf8')) : null,
    close: () => new Promise((resolve) => { server.close(() => resolve()); server.closeAllConnections(); }),
  };
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const cfgFile = arg('--config') ?? path.join(HERE, 'config.json');
  const cfg = loadConfig(fs.existsSync(cfgFile) ? cfgFile : undefined);
  if (cfg.host !== '127.0.0.1' && cfg.host !== 'localhost') {
    console.log(cfg.console.allowLan
      ? `[注意] ${cfg.host} で待ち受けます。管理画面は ${cfg.console.allowedHosts.join(', ')} の名前でも開けます（ログインが要ります）。`
      : `[注意] ${cfg.host} で待ち受けます。管理画面はこの PC からだけ開けます（端末向けの口だけが外から届きます）。`);
  }
  if (!cfg.tls.enabled) console.log('[注意] http（暗号化なし）で動いています。社内の通信路で報告の中身が読めます。https の設定は 導入手順書.md の「4. https にする」を見てください。');
  const s = await startServer(cfg);
  console.log(`[配信番] ${s.url}/console/ で管理画面を開けます（製品名: ${cfg.domain}）`);
  if (s.certFingerprint) console.log(`  証明書の指紋（SHA-256）: ${s.certFingerprint.colon}\n  アプリ側（C#）の PinnedCertSha256 には: ${s.certFingerprint.hex}`);
  if (!s.auth.isSetUp()) console.log('  まだ管理画面の合言葉がありません。この PC のブラウザで上の URL を開き、合言葉（12 文字以上）を決めてください（初回は 127.0.0.1 からだけ）。');
  console.log(`  報告の置き場: ${cfg.dataDir}`);
  console.log(`  配る物の置き場: ${cfg.releaseDir}`);
  const stop = () => { s.close().then(() => process.exit(0)); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
