// 試験・台本から管理の口を使うための小さな道具（ログインの Cookie と CSRF の札を覚える）。Node の標準だけ。
// https のときは ca（作った証明書）を渡すと、その証明書だけを信じて確かめる（確かめを切ることはしない）。
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';

/** 生の http(s) で送る（Host・Origin・Cookie を自由に変えるため）。 */
export function request(base, method, p, { body, headers = {}, ca, localAddress } = {}) {
  const u = new URL(base);
  const lib = u.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
    const req = lib.request({
      host: u.hostname, port: u.port, method, path: p, ca, localAddress, servername: /^[\d.]+$|^\[/.test(u.hostname) ? undefined : u.hostname,
      // 証明書の名前は、Host の見出しではなく実際につないだ相手（URL）で確かめる（Host を変える試験のため）
      checkServerIdentity: (_h, cert) => tls.checkServerIdentity(u.hostname.replace(/^\[|\]$/g, ''), cert),
      headers: { ...(data !== undefined ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } : {}), ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json; try { json = JSON.parse(text); } catch { json = undefined; }
        resolve({ status: res.statusCode, headers: res.headers, text, json, body: json ?? {} });
      });
    });
    req.on('error', reject);
    if (data !== undefined) req.write(data);
    req.end();
  });
}

export class AdminClient {
  constructor(base, { ca, localAddress } = {}) { this.base = base; this.ca = ca; this.localAddress = localAddress; this.cookie = undefined; this.csrf = undefined; }

  remember(r) {
    const sc = r.headers['set-cookie'];
    if (sc) for (const c of [].concat(sc)) { const v = c.split(';')[0]; this.cookie = v.endsWith('=') ? undefined : v; }
    if (r.json?.csrf) this.csrf = r.json.csrf;
    return r;
  }

  async call(method, p, body, { csrf = true, extra = {} } = {}) {
    const headers = { 'x-haishin-console': '1', ...(this.cookie ? { cookie: this.cookie } : {}), ...(csrf && this.csrf ? { 'x-csrf-token': this.csrf } : {}), ...extra };
    if (body === undefined && method !== 'GET') body = {};
    return this.remember(await request(this.base, method, p, { body, headers, ca: this.ca, localAddress: this.localAddress }));
  }

  /** 初回なら合言葉を設定し、そうでなければログインする。 */
  async loginOrSetup(password) {
    const s = await this.call('GET', '/api/admin/session');
    const r = s.json.setupNeeded ? await this.call('POST', '/api/admin/setup', { password }) : await this.call('POST', '/api/admin/login', { password });
    if (r.status !== 200) throw new Error(`ログインできない: ${r.status} ${r.text}`);
    return r;
  }

  get(p) { return this.call('GET', p); }
  put(p, body) { return this.call('PUT', p, body); }
  post(p, body) { return this.call('POST', p, body); }
}
