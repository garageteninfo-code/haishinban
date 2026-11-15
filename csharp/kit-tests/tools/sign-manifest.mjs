// UpdateSafetyKit: sign a release manifest (Node.js, no npm packages).
// 配布する版の manifest に署名する（Node.js 標準だけ・npm のパッケージ不要）。
//
//   node sign-manifest.mjs <dir> <os> <version> --key <private-key.pem> [--domain usk-update]
//        [--percent N --salt S | --no-rollout] [--bad 1.0.3,1.0.4 | --no-bad] [--seq N] [--expires-days D] [--v2]
//
//   <dir>/<os>.<ext> を探して sha256 と大きさを求め、C# の ReleaseSignature.BuildPayloadV3 と 1 文字も違わない文字列に署名して
//   <dir>/manifest.json の signatures[os] に書く。seq（通し番号）は省くと「前の manifest の seq + 1」。
//   seq は下げられない（下げると端末は「古い情報の再送」と見て拒否する）。
//   --expires-days を付けると、その日数が過ぎた manifest は端末に拒否される（古い情報で止め続ける攻撃への対策。定期的に署名し直す運用が前提）。
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OS_RE = /^[a-z0-9_-]{1,32}$/;
const VERSION_RE = /^[0-9A-Za-z.+-]{1,64}$/;
const SHA_RE = /^[0-9a-f]{64}$/;
const SALT_RE = /^[A-Za-z0-9._-]{0,64}$/;
const DOMAIN_RE = /^[a-z0-9][a-z0-9.-]{0,39}$/;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const EXTS = ['zip', 'exe', 'msi', 'msix', 'tar.gz', 'tgz', 'AppImage', 'dmg', 'pkg', 'deb', 'rpm', 'apk', 'aab', 'ipa', 'bin'];

/** Same as C# Canon.TrimAscii: only space, tab, CR, LF. */
export const trimAscii = (s) => String(s ?? '').replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
export const canonRollout = (r) => (r == null ? 'all' : `${r.percent}:${r.salt ?? ''}`);
export function canonBad(bad) {
  if (!Array.isArray(bad)) return '';
  const list = [...new Set(bad.map(trimAscii).filter((b) => b.length > 0))];
  list.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return list.join(',');
}

function checkFields(os, version, sha256, size, policy) {
  const o = trimAscii(os).toLowerCase();
  const v = trimAscii(version);
  const s = trimAscii(sha256).toLowerCase();
  if (!OS_RE.test(o)) throw new Error('os must match ^[a-z0-9_-]{1,32}$');
  if (!VERSION_RE.test(v)) throw new Error('version must match ^[0-9A-Za-z.+-]{1,64}$');
  if (!SHA_RE.test(s)) throw new Error('sha256 must be 64 hex characters');
  if (!Number.isSafeInteger(size) || size < 0) throw new Error('size must be a non-negative integer');
  if (policy.seq != null && (!Number.isSafeInteger(policy.seq) || policy.seq < 1)) throw new Error('seq must be an integer 1..2^53-1');
  if (policy.expiresAt != null && (!Number.isSafeInteger(policy.expiresAt) || policy.expiresAt < 0)) throw new Error('expiresAt must be Unix seconds');
  return { o, v, s };
}

/** Same as C# ReleaseSignature.BuildPayloadV3. */
export function buildPayloadV3(domain, os, version, sha256, size, policy) {
  if (!DOMAIN_RE.test(domain)) throw new Error('domain must match ^[a-z0-9][a-z0-9.-]{0,39}$');
  const { o, v, s } = checkFields(os, version, sha256, size, policy);
  if (policy.seq == null) throw new Error('seq is required for v3');
  const exp = policy.expiresAt == null ? 'none' : String(policy.expiresAt);
  return `${domain}-v3|${o}|${v}|${s}|${size}|rollout=${canonRollout(policy.rollout)}|bad=${canonBad(policy.badVersions)}|seq=${policy.seq}|exp=${exp}`;
}

/** Same as C# ReleaseSignature.BuildPayloadV2 (migration only). */
export function buildPayloadV2(domain, os, version, sha256, size, rollout, badVersions) {
  if (!DOMAIN_RE.test(domain)) throw new Error('domain must match ^[a-z0-9][a-z0-9.-]{0,39}$');
  const { o, v, s } = checkFields(os, version, sha256, size, {});
  return `${domain}-v2|${o}|${v}|${s}|${size}|rollout=${canonRollout(rollout)}|bad=${canonBad(badVersions)}`;
}

/** Same rules as C# ReleaseJson.ParsePolicy. Throws on anything the client would refuse (never sign what clients cannot read). */
export function normalizePolicy(m) {
  let rollout = null;
  if (m.rollout != null) {
    const r = m.rollout;
    if (typeof r !== 'object' || Array.isArray(r)) throw new Error('rollout must be { percent, salt }');
    if (!Number.isInteger(r.percent) || r.percent < 0 || r.percent > 100) throw new Error('rollout.percent must be an integer 0..100');
    const salt = r.salt == null ? '' : r.salt;
    if (typeof salt !== 'string' || !SALT_RE.test(salt)) throw new Error('rollout.salt must be [A-Za-z0-9._-]{0,64}');
    rollout = { percent: r.percent, salt };
  }
  let badVersions = [];
  if (m.rollback != null) {
    if (typeof m.rollback !== 'object' || Array.isArray(m.rollback)) throw new Error('rollback must be { badVersions: [...] }');
    const bad = m.rollback.badVersions == null ? [] : m.rollback.badVersions;
    if (!Array.isArray(bad)) throw new Error('rollback.badVersions must be an array');
    badVersions = bad.map((b) => {
      if (typeof b !== 'string' || !VERSION_RE.test(trimAscii(b))) throw new Error(`bad version value: ${JSON.stringify(b)}`);
      return trimAscii(b);
    });
  }
  const seq = m.seq == null ? null : m.seq;
  if (seq != null && (!Number.isSafeInteger(seq) || seq < 1 || seq > MAX_SAFE)) throw new Error('seq must be an integer 1..2^53-1');
  const expiresAt = m.expiresAt == null ? null : m.expiresAt;
  if (expiresAt != null && (!Number.isSafeInteger(expiresAt) || expiresAt < 0)) throw new Error('expiresAt must be Unix seconds');
  return { rollout, badVersions, seq, expiresAt };
}

export function findArtifact(dir, osKey) {
  for (const ext of EXTS) {
    const p = path.join(dir, `${osKey}.${ext}`);
    if (fs.existsSync(p) && fs.statSync(p).isFile()) return p;
  }
  return null;
}

/**
 * Signs dir/manifest.json. opts.rollout / opts.rollback: undefined = keep / null = remove / value = replace.
 * opts.seq: undefined = previous seq + 1. opts.expiresAt: undefined = keep / null = remove / Unix seconds.
 * The private key is passed in by the caller (tests pass a temporary in-memory key).
 */
export function signManifest({ dir, osKey, version, privateKeyPem, domain = 'usk-update', rollout, rollback, seq, expiresAt, v2 = false }) {
  const key = trimAscii(osKey).toLowerCase();
  const artifact = findArtifact(dir, key);
  if (!artifact) throw new Error(`no artifact for ${key} in ${dir}`);
  const bytes = fs.readFileSync(artifact);
  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  const size = bytes.length;
  const manifestPath = path.join(dir, 'manifest.json');
  const manifest = fs.existsSync(manifestPath) ? JSON.parse(fs.readFileSync(manifestPath, 'utf8')) : {};
  const prevSeq = Number.isSafeInteger(manifest.seq) ? manifest.seq : 0;
  manifest.version = trimAscii(version);
  if (rollout !== undefined) { if (rollout === null) delete manifest.rollout; else manifest.rollout = rollout; }
  if (rollback !== undefined) { if (rollback === null) delete manifest.rollback; else manifest.rollback = rollback; }
  if (expiresAt !== undefined) { if (expiresAt === null) delete manifest.expiresAt; else manifest.expiresAt = expiresAt; }
  manifest.seq = seq === undefined ? prevSeq + 1 : seq;
  if (manifest.seq < prevSeq) throw new Error(`seq must not go down (${manifest.seq} < ${prevSeq}); clients would refuse it as a replay`);
  const p = normalizePolicy(manifest);
  if (p.rollout) manifest.rollout = p.rollout; else delete manifest.rollout;
  if (p.badVersions.length) manifest.rollback = { badVersions: p.badVersions }; else delete manifest.rollback;

  const priv = crypto.createPrivateKey(privateKeyPem);
  if (priv.asymmetricKeyType !== 'ec' || priv.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error('the key must be an EC P-256 private key');
  const sign = (payload) => crypto.sign('sha256', Buffer.from(payload, 'utf8'), priv).toString('base64');
  // seq is shared by the whole manifest, so every OS entry is signed again with the new seq (an entry whose artifact is gone is dropped).
  const old = manifest.signatures && typeof manifest.signatures === 'object' ? manifest.signatures : {};
  const signatures = {};
  const dropped = [];
  let payloadV3; let payloadV2;
  for (const k of new Set([...Object.keys(old), key])) {
    const art = k === key ? artifact : findArtifact(dir, k);
    if (!art) { dropped.push(k); continue; }
    const b = k === key ? bytes : fs.readFileSync(art);
    const h = k === key ? sha256 : crypto.createHash('sha256').update(b).digest('hex');
    const pv3 = buildPayloadV3(domain, k, manifest.version, h, b.length, p);
    const entry = { sha256: h, size: b.length, signatureV3: sign(pv3) };
    if (v2) { const pv2 = buildPayloadV2(domain, k, manifest.version, h, b.length, p.rollout, p.badVersions); entry.signatureV2 = sign(pv2); if (k === key) payloadV2 = pv2; }
    if (k === key) payloadV3 = pv3;
    signatures[k] = entry;
  }
  manifest.signatures = signatures;
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
  return { artifact, manifest, sha256, size, payloadV3, payloadV2, dropped };
}

function main(argv) {
  const pos = []; const o = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--key') o.key = argv[++i];
    else if (a === '--domain') o.domain = argv[++i];
    else if (a === '--percent') o.percent = Number(argv[++i]);
    else if (a === '--salt') o.salt = argv[++i];
    else if (a === '--bad') o.bad = String(argv[++i] ?? '').split(',').map(trimAscii).filter(Boolean);
    else if (a === '--no-rollout') o.noRollout = true;
    else if (a === '--no-bad') o.noBad = true;
    else if (a === '--seq') o.seq = Number(argv[++i]);
    else if (a === '--expires-days') o.expiresDays = Number(argv[++i]);
    else if (a === '--v2') o.v2 = true;
    else pos.push(a);
  }
  const [dir, os, version] = pos;
  if (!dir || !os || !version || !o.key) {
    console.error('usage: node sign-manifest.mjs <dir> <os> <version> --key <private-key.pem> [--domain d] [--percent N --salt S | --no-rollout] [--bad v1,v2 | --no-bad] [--seq N] [--expires-days D] [--v2]');
    process.exit(2);
  }
  try {
    const r = signManifest({
      dir: path.resolve(dir), osKey: os, version, privateKeyPem: fs.readFileSync(o.key, 'utf8'), domain: o.domain ?? 'usk-update',
      rollout: o.noRollout ? null : o.percent !== undefined ? { percent: o.percent, salt: o.salt ?? '' } : undefined,
      rollback: o.noBad ? null : o.bad ? { badVersions: o.bad } : undefined,
      seq: o.seq, expiresAt: o.expiresDays !== undefined ? Math.floor(Date.now() / 1000) + Math.round(o.expiresDays * 86400) : undefined, v2: !!o.v2,
    });
    console.log(`[sign-manifest] signed ${path.basename(r.artifact)} version=${r.manifest.version} seq=${r.manifest.seq} size=${r.size}`);
    console.log(`[sign-manifest] rollout=${canonRollout(r.manifest.rollout)} bad=${canonBad(r.manifest.rollback?.badVersions) || '(none)'} expiresAt=${r.manifest.expiresAt ?? 'none'}`);
  } catch (e) {
    console.error(`[sign-manifest] not signed: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
}

if (process.argv[1] && path.basename(process.argv[1]) === path.basename(fileURLToPath(import.meta.url))) main(process.argv.slice(2));
