// 端末から来る本文の検証（形・型・長さ）。中継の改良版（relay/src/validate.mjs）の考え方を写して、この商品の形に合わせたもの。
//
// ⚠ 知らない欄は断る（strict）。関門を通らない欄から利用者の情報が漏れるのを防ぐため。
// ⚠ reporterId は「端末の installId そのもの」ではなく、端末側で sha256("haishin-report|" + installId) にした 64 桁の 16 進。
//   （UpdateSafetyKit の installId は段階配信の組分けに使うので外へ出さない決まり。）サーバーはさらに自分の塩で混ぜてから保存する。

export const LIMITS = Object.freeze({
  bodyBytes: 65536,
  reports: 50,
  versionMax: 64,
  osMax: 64,
  fingerprintMin: 8,
  fingerprintMax: 128,
  titleMax: 200,
  messageMax: 2000,
  stackMax: 4000,
  stackLines: 30,
  countMax: 1000000,
});

/** 関門で調べる欄（報告ごと）。欄を足すときはここにも足す。 */
export const CHECKED_REPORT_FIELDS = Object.freeze(['title', 'message', 'stack']);
export const CHECKED_TOP_FIELDS = Object.freeze(['os']);

const REPORTER_RE = /^[0-9a-f]{64}$/;
const FP_RE = /^[A-Za-z0-9_-]+$/;
const VERSION_RE = /^[0-9A-Za-z.+-]{1,64}$/;
const KINDS = new Set(['crash', 'error']);
const REPORT_TOP = new Set(['reporterId', 'appVersion', 'os', 'reports']);
const REPORT_KEYS = new Set(['fingerprint', 'kind', 'title', 'message', 'stack', 'count', 'firstSeen', 'lastSeen']);
const HEARTBEAT_TOP = new Set(['reporterId', 'appVersion', 'os']);

const fail = (field, reason) => ({ ok: false, field, reason });
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function str(v, field, { min = 0, max, re } = {}) {
  if (typeof v !== 'string') return fail(field, 'must_be_string');
  if (v.length < min) return fail(field, 'too_short');
  if (max != null && v.length > max) return fail(field, 'too_long');
  if (re && !re.test(v)) return fail(field, 'bad_format');
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v)) return fail(field, 'control_chars');
  return null;
}

function time(v, field, nowMs) {
  let ms;
  if (typeof v === 'number' && Number.isFinite(v)) ms = v;
  else if (typeof v === 'string' && v.length <= 40) ms = Date.parse(v);
  else return { err: fail(field, 'must_be_time') };
  if (!Number.isFinite(ms)) return { err: fail(field, 'must_be_time') };
  if (ms < Date.UTC(2020, 0, 1) || ms > nowMs + 24 * 3600 * 1000) return { err: fail(field, 'time_out_of_range') };
  return { iso: new Date(ms).toISOString() };
}

function top(body, keys) {
  if (!isObj(body)) return fail('$', 'must_be_object');
  for (const k of Object.keys(body)) if (!keys.has(k)) return fail(k, 'unknown_field');
  let e;
  if ((e = str(body.reporterId, 'reporterId', { re: REPORTER_RE }))) return e;
  if ((e = str(body.appVersion, 'appVersion', { re: VERSION_RE }))) return e;
  if ((e = str(body.os, 'os', { min: 1, max: LIMITS.osMax }))) return e;
  if (/[\r\n]/.test(body.os)) return fail('os', 'bad_format');
  return null;
}

/** 起動の知らせ（どの版がいくつ動いているか＝落ちる割合の分母）。 */
export function validateHeartbeat(body) {
  const e = top(body, HEARTBEAT_TOP);
  if (e) return e;
  return { ok: true, value: { reporterId: body.reporterId, appVersion: body.appVersion, os: body.os } };
}

/** 不具合の報告。 */
export function validateReports(body, nowMs = Date.now()) {
  let e = top(body, REPORT_TOP);
  if (e) return e;
  if (!Array.isArray(body.reports)) return fail('reports', 'must_be_array');
  if (body.reports.length < 1) return fail('reports', 'empty');
  if (body.reports.length > LIMITS.reports) return fail('reports', 'too_many');
  const reports = [];
  for (let i = 0; i < body.reports.length; i++) {
    const r = body.reports[i];
    const p = `reports[${i}]`;
    if (!isObj(r)) return fail(p, 'must_be_object');
    for (const k of Object.keys(r)) if (!REPORT_KEYS.has(k)) return fail(`${p}.${k}`, 'unknown_field');
    if ((e = str(r.fingerprint, `${p}.fingerprint`, { min: LIMITS.fingerprintMin, max: LIMITS.fingerprintMax, re: FP_RE }))) return e;
    if (!KINDS.has(r.kind)) return fail(`${p}.kind`, 'bad_enum');
    if ((e = str(r.title, `${p}.title`, { min: 1, max: LIMITS.titleMax }))) return e;
    if (/[\r\n]/.test(r.title)) return fail(`${p}.title`, 'bad_format');
    const message = r.message ?? '';
    const stack = r.stack ?? '';
    if ((e = str(message, `${p}.message`, { max: LIMITS.messageMax }))) return e;
    if ((e = str(stack, `${p}.stack`, { max: LIMITS.stackMax }))) return e;
    if (stack && stack.split('\n').length > LIMITS.stackLines) return fail(`${p}.stack`, 'too_many_lines');
    const count = r.count ?? 1;
    if (!Number.isInteger(count) || count < 1 || count > LIMITS.countMax) return fail(`${p}.count`, 'bad_count');
    const fs = time(r.firstSeen ?? nowMs, `${p}.firstSeen`, nowMs);
    if (fs.err) return fs.err;
    const ls = time(r.lastSeen ?? r.firstSeen ?? nowMs, `${p}.lastSeen`, nowMs);
    if (ls.err) return ls.err;
    if (fs.iso > ls.iso) return fail(`${p}.lastSeen`, 'before_first_seen');
    reports.push({ fingerprint: r.fingerprint.toLowerCase(), kind: r.kind, title: r.title, message, stack, count, firstSeen: fs.iso, lastSeen: ls.iso });
  }
  return { ok: true, value: { reporterId: body.reporterId, appVersion: body.appVersion, os: body.os, reports } };
}

/** 本文を上限つきで読む（Content-Length を信じず、実際のバイト数で止める）。 */
export function readBodyCapped(req, limit = LIMITS.bodyBytes) {
  return new Promise((resolve) => {
    const declared = Number(req.headers['content-length'] || '');
    if (Number.isFinite(declared) && declared > limit) { req.resume(); resolve({ ok: false, status: 413, error: 'body_too_large' }); return; }
    const chunks = [];
    let total = 0;
    let done = false;
    req.on('data', (c) => {
      if (done) return;
      total += c.length;
      if (total > limit) { done = true; req.resume(); resolve({ ok: false, status: 413, error: 'body_too_large' }); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      try {
        resolve({ ok: true, text: new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)) });
      } catch {
        resolve({ ok: false, status: 400, error: 'body_not_utf8' });
      }
    });
    req.on('error', () => { if (!done) { done = true; resolve({ ok: false, status: 400, error: 'body_unreadable' }); } });
  });
}
