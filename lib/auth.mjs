// 管理画面のログイン（合言葉・セッション・CSRF・試行回数の制限）。Node の標準だけ。
//
// 置き場所: <dataDir>/console-auth.json … 合言葉そのものは置かない。scrypt（N=2^15, r=8, p=1）で混ぜた値と塩だけ。
//   合言葉を忘れたら：サーバーを止めてこのファイルを消し、この PC（127.0.0.1）から管理画面を開いて設定し直す。
// セッション: 乱数 32 バイトの札（Cookie: HttpOnly・SameSite=Strict・https のときは Secure）。サーバーは札の sha256 だけを覚える（メモリの中だけ。再起動で全員ログアウト）。
// CSRF: ログインごとに別の乱数を返し、書き込み（POST/PUT）では x-csrf-token の見出しで送らせる。Origin も確かめる（server.mjs）。
// 試行回数: 同じ相手から 15 分に 5 回まちがえたら、その 15 分が終わるまで 429。全体でも 15 分に 50 回で止める（総当たり対策）。

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 256;
const SCRYPT = Object.freeze({ N: 32768, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 });
export const COOKIE_NAME = 'haishin_sid';

function scrypt(password, salt, prm) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password.normalize('NFC'), salt, prm.keylen, { N: prm.N, r: prm.r, p: prm.p, maxmem: SCRYPT.maxmem }, (e, k) => (e ? reject(e) : resolve(k)));
  });
}
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

/** 合言葉の形の確かめ。null なら可。 */
export function passwordProblem(pw) {
  if (typeof pw !== 'string') return 'must_be_string';
  if ([...pw].length < PASSWORD_MIN) return 'too_short';
  if (pw.length > PASSWORD_MAX) return 'too_long';
  if (/[\u0000-\u001f\u007f]/.test(pw)) return 'control_chars';
  if (/^(.)\1+$/u.test(pw)) return 'too_simple';
  return null;
}

export class ConsoleAuth {
  /**
   * @param {{ file: string, now?: () => number, sessionHours?: number, maxFailures?: number, lockMinutes?: number, globalMaxFailures?: number }} o
   */
  constructor({ file, now = () => Date.now(), sessionHours = 8, maxFailures = 5, lockMinutes = 15, globalMaxFailures = 50 }) {
    this.file = file;
    this.now = now;
    this.sessionMs = sessionHours * 3600 * 1000;
    this.maxFailures = maxFailures;
    this.windowMs = lockMinutes * 60 * 1000;
    this.globalMax = globalMaxFailures;
    /** @type {Map<string, { csrf: string, expires: number, created: number }>} 札の sha256 → セッション */
    this.sessions = new Map();
    /** @type {Map<string, { start: number, n: number }>} */
    this.failures = new Map();
    this.globalFail = { start: 0, n: 0 };
    this.record = this.load();
  }

  load() {
    if (!fs.existsSync(this.file)) return null;
    const j = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    if (j.algo !== 'scrypt' || typeof j.salt !== 'string' || typeof j.hash !== 'string') throw new Error(`ログインの記録 ${this.file} の形が不正（消して設定し直してください）`);
    return j;
  }

  isSetUp() { return !!this.record; }

  /** 合言葉を設定する（初回・変更）。それまでのセッションはすべて無効にする。 */
  async setPassword(pw) {
    const why = passwordProblem(pw);
    if (why) return { ok: false, error: `password_${why}` };
    const salt = crypto.randomBytes(16);
    const hash = await scrypt(pw, salt, SCRYPT);
    const rec = { v: 1, algo: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, keylen: SCRYPT.keylen, salt: salt.toString('base64'), hash: hash.toString('base64'), setAt: new Date(this.now()).toISOString() };
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(rec, null, 1) + '\n', { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmp, this.file);
    this.record = rec;
    this.sessions.clear();
    return { ok: true };
  }

  async verify(pw) {
    if (!this.record || typeof pw !== 'string' || pw.length > PASSWORD_MAX) {
      // 記録が無くても同じくらい時間をかける（時間差で分からないように）
      await scrypt(String(pw ?? '').slice(0, PASSWORD_MAX), Buffer.alloc(16), SCRYPT);
      return false;
    }
    const r = this.record;
    const want = Buffer.from(r.hash, 'base64');
    const got = await scrypt(pw, Buffer.from(r.salt, 'base64'), { N: r.N, r: r.r, p: r.p, keylen: want.length });
    return got.length === want.length && crypto.timingSafeEqual(got, want);
  }

  /** いま、この相手は試せるか（待つ秒数を返す。0 なら試せる）。 */
  lockedFor(client) {
    const t = this.now();
    if (this.globalFail.n >= this.globalMax && t - this.globalFail.start < this.windowMs) return Math.ceil((this.globalFail.start + this.windowMs - t) / 1000);
    const f = this.failures.get(client);
    if (f && f.n >= this.maxFailures && t - f.start < this.windowMs) return Math.ceil((f.start + this.windowMs - t) / 1000);
    return 0;
  }

  fail(client) {
    const t = this.now();
    const f = this.failures.get(client);
    if (!f || t - f.start >= this.windowMs) this.failures.set(client, { start: t, n: 1 }); else f.n++;
    if (t - this.globalFail.start >= this.windowMs) this.globalFail = { start: t, n: 1 }; else this.globalFail.n++;
    if (this.failures.size > 10000) for (const [k, v] of this.failures) if (t - v.start >= this.windowMs) this.failures.delete(k);
  }

  /** 新しいセッションを作る（ログイン・初回設定のあと）。 */
  issue() {
    const token = crypto.randomBytes(32).toString('base64url');
    const csrf = crypto.randomBytes(32).toString('base64url');
    const t = this.now();
    this.sessions.set(sha(token), { csrf, expires: t + this.sessionMs, created: t });
    if (this.sessions.size > 200) {
      const oldest = [...this.sessions.entries()].sort((a, b) => a[1].created - b[1].created)[0];
      this.sessions.delete(oldest[0]);
    }
    return { token, csrf };
  }

  /** ログイン。成功なら { ok, token, csrf }、失敗なら { ok:false, status, retryAfter? }。 */
  async login(client, pw) {
    const wait = this.lockedFor(client);
    if (wait > 0) return { ok: false, status: 429, error: 'too_many_attempts', retryAfter: wait };
    if (!this.record) return { ok: false, status: 409, error: 'setup_required' };
    if (!(await this.verify(pw))) {
      this.fail(client);
      const w = this.lockedFor(client);
      return w > 0 ? { ok: false, status: 429, error: 'too_many_attempts', retryAfter: w } : { ok: false, status: 401, error: 'wrong_password' };
    }
    this.failures.delete(client);
    return { ok: true, ...this.issue() };
  }

  /** 札からセッションを引く（期限切れは消す）。 */
  session(token) {
    if (typeof token !== 'string' || token.length < 20 || token.length > 100) return null;
    const k = sha(token);
    const s = this.sessions.get(k);
    if (!s) return null;
    if (s.expires <= this.now()) { this.sessions.delete(k); return null; }
    return s;
  }

  logout(token) { if (typeof token === 'string') this.sessions.delete(sha(token)); }

  /** CSRF の札の比べ（長さが違っても時間差が出ないように）。 */
  static csrfOk(session, header) {
    if (!session || typeof header !== 'string') return false;
    const a = Buffer.from(sha(session.csrf), 'hex');
    const b = Buffer.from(sha(header), 'hex');
    return crypto.timingSafeEqual(a, b);
  }
}

/** Cookie の見出しから 1 つ取り出す。 */
export function readCookie(req, name = COOKIE_NAME) {
  const h = String(req.headers.cookie || '');
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

/** Set-Cookie の値（HttpOnly・SameSite=Strict・Path=/・https なら Secure）。 */
export function sessionCookie(token, { secure, maxAgeSec }) {
  return `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
}
export function clearCookie({ secure }) {
  return `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure ? '; Secure' : ''}`;
}
