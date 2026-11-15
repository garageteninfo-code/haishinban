// 配信情報（manifest）の組み立てと署名。ブラウザ（管理画面）と Node（試験・サンプルの台本・サーバーの確かめ）で同じファイルを使う。
// 依存なし。暗号は WebCrypto（ブラウザの crypto.subtle / Node 20 以降の globalThis.crypto.subtle）。
//
// 署名する文字列は C# の UpdateSafetyKit.ReleaseSignature.BuildPayloadV3 と 1 文字も違わない（tools/sign-manifest.mjs と同じ規則）:
//   <domain>-v3|<os>|<version>|<sha256>|<size>|rollout=<all|percent:salt>|bad=<a,b>|seq=<n>|exp=<unix|none>
// 署名は ECDSA P-256 + SHA-256。WebCrypto は r||s（64 バイト）を返すので、C# が読む DER に直して base64 にする。
//
// ⚠ 秘密鍵はこのファイルの関数の中だけで使い、どこにも送らない。保存は「合言葉で暗号化した鍵ファイル」を利用者が選んだ場所へ。

export const OS_RE = /^[a-z0-9_-]{1,32}$/;
export const VERSION_RE = /^[0-9A-Za-z.+-]{1,64}$/;
export const SHA_RE = /^[0-9a-f]{64}$/;
export const SALT_RE = /^[A-Za-z0-9._-]{0,64}$/;
export const DOMAIN_RE = /^[a-z0-9][a-z0-9.-]{0,39}$/;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

// ---------- 正規化（C# Canon と同じ） ----------
export const trimAscii = (s) => String(s ?? '').replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
export const canonRollout = (r) => (r == null ? 'all' : `${r.percent}:${r.salt ?? ''}`);
export function canonBad(bad) {
  if (!Array.isArray(bad)) return '';
  const list = [...new Set(bad.map(trimAscii).filter((b) => b.length > 0))];
  list.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return list.join(',');
}

/** C# ReleaseJson.ParsePolicy と同じ規則。端末が読めない物には署名しない（投げる）。 */
export function normalizePolicy(m) {
  let rollout = null;
  if (m.rollout != null) {
    const r = m.rollout;
    if (typeof r !== 'object' || Array.isArray(r)) throw new Error('rollout は { percent, salt } の形');
    if (!Number.isInteger(r.percent) || r.percent < 0 || r.percent > 100) throw new Error('rollout.percent は 0〜100 の整数');
    const salt = r.salt == null ? '' : r.salt;
    if (typeof salt !== 'string' || !SALT_RE.test(salt)) throw new Error('rollout.salt は英数字と . _ - の 64 文字まで');
    rollout = { percent: r.percent, salt };
  }
  let badVersions = [];
  if (m.rollback != null) {
    if (typeof m.rollback !== 'object' || Array.isArray(m.rollback)) throw new Error('rollback は { badVersions: [...] } の形');
    const bad = m.rollback.badVersions == null ? [] : m.rollback.badVersions;
    if (!Array.isArray(bad)) throw new Error('rollback.badVersions は配列');
    badVersions = bad.map((b) => {
      if (typeof b !== 'string' || !VERSION_RE.test(trimAscii(b))) throw new Error(`取り下げる版の形が不正: ${JSON.stringify(b)}`);
      return trimAscii(b);
    });
  }
  const seq = m.seq == null ? null : m.seq;
  if (seq != null && (!Number.isSafeInteger(seq) || seq < 1 || seq > MAX_SAFE)) throw new Error('seq は 1 以上の整数');
  const expiresAt = m.expiresAt == null ? null : m.expiresAt;
  if (expiresAt != null && (!Number.isSafeInteger(expiresAt) || expiresAt < 0)) throw new Error('expiresAt は Unix 秒');
  return { rollout, badVersions, seq, expiresAt };
}

/** C# ReleaseSignature.BuildPayloadV3 と同じ文字列。 */
export function buildPayloadV3(domain, os, version, sha256, size, policy) {
  if (!DOMAIN_RE.test(domain)) throw new Error('製品名（domain）は ^[a-z0-9][a-z0-9.-]{0,39}$');
  const o = trimAscii(os).toLowerCase();
  const v = trimAscii(version);
  const s = trimAscii(sha256).toLowerCase();
  if (!OS_RE.test(o)) throw new Error('os の形が不正');
  if (!VERSION_RE.test(v)) throw new Error('版の形が不正（英数字と . + - の 64 文字まで）');
  if (!SHA_RE.test(s)) throw new Error('sha256 は 64 桁の 16 進');
  if (!Number.isSafeInteger(size) || size < 0) throw new Error('大きさは 0 以上の整数');
  if (policy.seq == null) throw new Error('seq（通し番号）が要る');
  if (!Number.isSafeInteger(policy.seq) || policy.seq < 1) throw new Error('seq は 1 以上の整数');
  if (policy.expiresAt != null && (!Number.isSafeInteger(policy.expiresAt) || policy.expiresAt < 0)) throw new Error('expiresAt は Unix 秒');
  const exp = policy.expiresAt == null ? 'none' : String(policy.expiresAt);
  return `${domain}-v3|${o}|${v}|${s}|${size}|rollout=${canonRollout(policy.rollout)}|bad=${canonBad(policy.badVersions)}|seq=${policy.seq}|exp=${exp}`;
}

// ---------- base64・PEM ----------
export function bytesToB64(bytes) {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(s);
}
export function b64ToBytes(b64) {
  const s = atob(String(b64).replace(/\s+/g, ''));
  const u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
  return u;
}
export function toPem(label, der) {
  const b = bytesToB64(der).match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${b}\n-----END ${label}-----\n`;
}
export function fromPem(label, pem) {
  const m = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`).exec(String(pem));
  if (!m) throw new Error(`${label} の PEM ではない`);
  return b64ToBytes(m[1]);
}

// ---------- 署名の形（r||s ⇔ DER） ----------
function derInt(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  let v = bytes.slice(i);
  if (v[0] & 0x80) { const w = new Uint8Array(v.length + 1); w.set(v, 1); v = w; }
  return [0x02, v.length, ...v];
}
/** WebCrypto の r||s（64 バイト）→ DER（C# の Rfc3279DerSequence）。 */
export function p1363ToDer(sig) {
  const u = new Uint8Array(sig);
  if (u.length !== 64) throw new Error('P-256 の署名は 64 バイト');
  const body = [...derInt(u.slice(0, 32)), ...derInt(u.slice(32))];
  return new Uint8Array([0x30, body.length, ...body]);
}
/** DER → r||s（WebCrypto で確かめる用）。形が違えば投げる。 */
export function derToP1363(der) {
  const u = new Uint8Array(der);
  if (u[0] !== 0x30 || u[1] !== u.length - 2) throw new Error('DER の形が不正');
  let p = 2;
  const out = new Uint8Array(64);
  for (let k = 0; k < 2; k++) {
    if (u[p] !== 0x02) throw new Error('DER の形が不正');
    const len = u[p + 1];
    let v = u.slice(p + 2, p + 2 + len);
    p += 2 + len;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) throw new Error('DER の整数が長すぎる');
    out.set(v, k * 32 + (32 - v.length));
  }
  if (p !== u.length) throw new Error('DER の後ろに余分なバイト');
  return out;
}

// ---------- 鍵 ----------
const ALG = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN = { name: 'ECDSA', hash: 'SHA-256' };
const sub = () => {
  const s = globalThis.crypto && globalThis.crypto.subtle;
  if (!s) throw new Error('WebCrypto が使えない（https か localhost で開く）');
  return s;
};

/** 新しい鍵の組（秘密鍵は保存のため書き出せる形）。 */
export async function generateKeyPair() {
  return sub().generateKey(ALG, true, ['sign', 'verify']);
}
export async function exportPublicPem(publicKey) {
  return toPem('PUBLIC KEY', new Uint8Array(await sub().exportKey('spki', publicKey)));
}
export async function importPublicPem(pem) {
  return sub().importKey('spki', fromPem('PUBLIC KEY', pem), ALG, true, ['verify']);
}
/** 秘密鍵（PKCS#8）から鍵の組を作り直す（公開鍵は JWK の x・y から）。tools/sign-manifest.mjs の PEM もそのまま読める。 */
export async function importPrivatePkcs8(pkcs8Bytes) {
  const privateKey = await sub().importKey('pkcs8', pkcs8Bytes, ALG, true, ['sign']);
  const jwk = await sub().exportKey('jwk', privateKey);
  const publicKey = await sub().importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true }, ALG, true, ['verify']);
  return { privateKey, publicKey };
}
export async function importPrivatePem(pem) {
  return importPrivatePkcs8(fromPem('PRIVATE KEY', pem));
}
/** 公開鍵の指紋（SPKI の sha256 の先頭 16 桁）。画面で鍵を見分ける用。 */
export async function keyFingerprint(publicKey) {
  const spki = new Uint8Array(await sub().exportKey('spki', publicKey));
  const h = new Uint8Array(await sub().digest('SHA-256', spki));
  return [...h.slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join(':');
}

export const KEY_FILE_FORMAT = 'haishin-signing-key-v1';
export const KEY_FILE_ITERATIONS = 600000;

async function passKey(passphrase, salt, iterations) {
  const base = await sub().importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return sub().deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** 秘密鍵を合言葉で暗号化した鍵ファイル（JSON の文字列）。合言葉は 10 文字以上。 */
export async function encryptKeyFile(keyPair, passphrase, { iterations = KEY_FILE_ITERATIONS } = {}) {
  if (typeof passphrase !== 'string' || passphrase.length < 10) throw new Error('合言葉は 10 文字以上');
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const pkcs8 = new Uint8Array(await sub().exportKey('pkcs8', keyPair.privateKey));
  const k = await passKey(passphrase, salt, iterations);
  const ct = new Uint8Array(await sub().encrypt({ name: 'AES-GCM', iv }, k, pkcs8));
  pkcs8.fill(0);
  return JSON.stringify({
    format: KEY_FILE_FORMAT,
    note: '配信番の署名用の秘密鍵（合言葉で暗号化）。人に渡さない・サーバーに置かない。',
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: bytesToB64(salt) },
    cipher: { name: 'AES-GCM', iv: bytesToB64(iv) },
    ciphertext: bytesToB64(ct),
    publicKeyPem: await exportPublicPem(keyPair.publicKey),
  }, null, 1);
}

/** 鍵ファイルを開く。合言葉が違えば投げる。 */
export async function decryptKeyFile(text, passphrase) {
  let j;
  try { j = JSON.parse(text); } catch { throw new Error('鍵ファイルの形ではない'); }
  if (!j || j.format !== KEY_FILE_FORMAT) throw new Error('鍵ファイルの形ではない');
  const iterations = j.kdf && j.kdf.iterations;
  if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 10000000) throw new Error('鍵ファイルの設定が不正');
  const k = await passKey(passphrase, b64ToBytes(j.kdf.salt), iterations);
  let pkcs8;
  try {
    pkcs8 = new Uint8Array(await sub().decrypt({ name: 'AES-GCM', iv: b64ToBytes(j.cipher.iv) }, k, b64ToBytes(j.ciphertext)));
  } catch {
    throw new Error('合言葉が違うか、鍵ファイルが壊れている');
  }
  const pair = await importPrivatePkcs8(pkcs8);
  pkcs8.fill(0);
  const pub = await exportPublicPem(pair.publicKey);
  if (j.publicKeyPem && trimAscii(j.publicKeyPem) !== trimAscii(pub)) throw new Error('鍵ファイルの公開鍵が秘密鍵と合わない');
  return pair;
}

// ---------- 署名と確かめ ----------
export async function signPayload(privateKey, payload) {
  const raw = new Uint8Array(await sub().sign(SIGN, privateKey, new TextEncoder().encode(payload)));
  return bytesToB64(p1363ToDer(raw));
}
export async function verifyPayload(publicKey, payload, signatureB64) {
  let p1363;
  try { p1363 = derToP1363(b64ToBytes(signatureB64)); } catch { return false; }
  return sub().verify(SIGN, publicKey, p1363, new TextEncoder().encode(payload));
}

/**
 * 下書きの manifest に署名する。
 * @param {{ draft: { version: string, rollout?: object|null, rollback?: object|null, seq: number, expiresAt?: number|null },
 *           artifacts: Record<string, { sha256: string, size: number, url?: string }>,  // その版の OS ごとのファイル
 *           domain: string, privateKey: CryptoKey }} p
 * @returns {Promise<{ manifest: object, payloads: Record<string, string> }>}
 */
export async function signManifest({ draft, artifacts, domain, privateKey }) {
  const version = trimAscii(draft.version);
  const p = normalizePolicy(draft);
  if (p.seq == null) throw new Error('seq（通し番号）が要る');
  const oses = Object.keys(artifacts || {});
  if (oses.length === 0) throw new Error(`版 ${version} のファイルが無い`);
  const manifest = { version, seq: p.seq };
  if (p.rollout) manifest.rollout = p.rollout;
  if (p.badVersions.length) manifest.rollback = { badVersions: [...new Set(p.badVersions)] };
  if (p.expiresAt != null) manifest.expiresAt = p.expiresAt;
  manifest.signatures = {};
  const payloads = {};
  for (const os of oses.sort()) {
    const a = artifacts[os];
    const payload = buildPayloadV3(domain, os, version, a.sha256, a.size, p);
    const entry = { sha256: trimAscii(a.sha256).toLowerCase(), size: a.size, signatureV3: await signPayload(privateKey, payload) };
    if (a.url) entry.url = a.url;
    manifest.signatures[trimAscii(os).toLowerCase()] = entry;
    payloads[os] = payload;
  }
  return { manifest, payloads };
}

/** manifest のすべての OS の署名を確かめる。null = 正しい、文字列 = 理由。 */
export async function verifyManifest(manifest, domain, publicKey) {
  let p;
  try { p = normalizePolicy(manifest); } catch (e) { return `形が不正: ${e.message}`; }
  if (p.seq == null) return 'seq が無い';
  if (typeof manifest.version !== 'string') return 'version が無い';
  const sigs = manifest.signatures;
  if (!sigs || typeof sigs !== 'object' || Object.keys(sigs).length === 0) return '署名が無い';
  for (const [os, e] of Object.entries(sigs)) {
    if (!e || typeof e !== 'object') return `${os}: 署名の欄が不正`;
    let payload;
    try { payload = buildPayloadV3(domain, os, manifest.version, String(e.sha256 ?? ''), e.size, p); } catch (err) { return `${os}: ${err.message}`; }
    if (typeof e.signatureV3 !== 'string' || !(await verifyPayload(publicKey, payload, e.signatureV3))) return `${os}: 署名が合わない`;
  }
  return null;
}

// ---------- 下書きを作る（画面のボタンと同じ） ----------
/** 乱数の salt（段階配信の組分けの種）。 */
export function newSalt(version) {
  const r = globalThis.crypto.getRandomValues(new Uint8Array(4));
  return `r${String(version).replace(/[^0-9A-Za-z]/g, '')}-${[...r].map((b) => b.toString(16).padStart(2, '0')).join('')}`.slice(0, 64);
}
const nextSeq = (current) => (current && Number.isSafeInteger(current.seq) ? current.seq + 1 : 1);
const keepBad = (current) => (current && current.rollback && Array.isArray(current.rollback.badVersions) ? [...current.rollback.badVersions] : []);
const keepExp = (current, expiresAt) => (expiresAt !== undefined ? expiresAt : current && current.expiresAt != null ? current.expiresAt : null);

/** 新しい版を percent% で配る（同じ版なら salt を引き継ぐ＝割合を上げても前に当たった端末は外れない）。 */
export function draftRelease(current, { version, percent, salt, expiresAt } = {}) {
  const v = trimAscii(version);
  const same = current && trimAscii(current.version) === v && current.rollout;
  const s = salt ?? (same ? current.rollout.salt : newSalt(v));
  const bad = keepBad(current).filter((b) => b !== v);
  return {
    version: v,
    rollout: percent == null || percent >= 100 ? null : { percent, salt: s },
    rollback: bad.length ? { badVersions: bad } : null,
    seq: nextSeq(current),
    expiresAt: keepExp(current, expiresAt),
  };
}

/** 配信を止める（0%）。版も salt もそのまま、割合だけ 0。すでに入れた端末はそのまま（戻すには「取り下げ」）。 */
export function draftHalt(current, { expiresAt } = {}) {
  if (!current || !current.version) throw new Error('今の配信情報が無い');
  return {
    version: current.version,
    rollout: { percent: 0, salt: current.rollout ? current.rollout.salt : newSalt(current.version) },
    rollback: keepBad(current).length ? { badVersions: keepBad(current) } : null,
    seq: nextSeq(current),
    expiresAt: keepExp(current, expiresAt),
  };
}

/**
 * 版を取り下げる。fallbackVersion を渡すと「その版を全員に案内」＝取り下げた版の端末は前の版へ戻される（C# の判定：今の版が不具合版なら古い版でも出す）。
 * 渡さなければ、案内はそのまま・取り下げた版は誰にも出さない（LatestRevoked）。
 */
export function draftRevoke(current, { badVersion, fallbackVersion, expiresAt } = {}) {
  const bad = trimAscii(badVersion);
  if (!VERSION_RE.test(bad)) throw new Error('取り下げる版を選ぶ');
  const list = [...new Set([...keepBad(current), bad])];
  const fb = fallbackVersion ? trimAscii(fallbackVersion) : null;
  if (fb && list.includes(fb)) throw new Error('代わりに配る版が取り下げの一覧に入っている');
  const version = fb || (current && current.version) || bad;
  return {
    version,
    rollout: fb ? null : current && current.rollout ? current.rollout : null,
    rollback: { badVersions: list },
    seq: nextSeq(current),
    expiresAt: keepExp(current, expiresAt),
  };
}
