// 配る物の置き場（releaseDir）:
//   files/<版>/<os>.<拡張子>   … 配るファイル（例: files/1.1.0/windows.zip）
//   manifest.json              … 今の配信情報（管理画面で署名した物だけ置かれる）
//   manifests/seq-<n>.json     … 過去の配信情報（記録）
//   public-key.pem             … 署名を確かめる公開鍵（秘密鍵はここに置かない）

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { buildPayloadV3, normalizePolicy, OS_RE, trimAscii, VERSION_RE } from '../console/manifest-core.js';

export const EXTS = ['zip', 'exe', 'msi', 'msix', 'bin'];
const FILE_RE = new RegExp(`^([a-z0-9_-]{1,32})\\.(${EXTS.join('|')})$`);

export class ReleaseDir {
  constructor({ dir, domain }) {
    this.dir = dir;
    this.domain = domain;
    this.cache = new Map();
    fs.mkdirSync(path.join(dir, 'files'), { recursive: true });
  }

  get manifestPath() { return path.join(this.dir, 'manifest.json'); }
  get publicKeyPath() { return path.join(this.dir, 'public-key.pem'); }

  /** 版ごとの OS のファイル（sha256・大きさ・取りに行く URL）。 */
  artifacts() {
    const out = {};
    const root = path.join(this.dir, 'files');
    for (const v of fs.readdirSync(root)) {
      if (!VERSION_RE.test(v) || !fs.statSync(path.join(root, v)).isDirectory()) continue;
      for (const f of fs.readdirSync(path.join(root, v))) {
        const m = FILE_RE.exec(f);
        if (!m) continue;
        const p = path.join(root, v, f);
        const st = fs.statSync(p);
        const key = `${p}|${st.size}|${st.mtimeMs}`;
        let sha = this.cache.get(key);
        if (!sha) { sha = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex'); this.cache.set(key, sha); }
        (out[v] ||= {})[m[1]] = { sha256: sha, size: st.size, url: `/updates/files/${encodeURIComponent(v)}/${f}` };
      }
    }
    return out;
  }

  /** files/ の中の 1 つのファイルの場所（無ければ null。パスの外へは出さない）。 */
  filePath(version, file) {
    if (!VERSION_RE.test(version) || !FILE_RE.test(file)) return null;
    const p = path.join(this.dir, 'files', version, file);
    return fs.existsSync(p) && fs.statSync(p).isFile() ? p : null;
  }

  manifest() {
    if (!fs.existsSync(this.manifestPath)) return null;
    return JSON.parse(fs.readFileSync(this.manifestPath, 'utf8'));
  }

  publicKeyPem() {
    return fs.existsSync(this.publicKeyPath) ? fs.readFileSync(this.publicKeyPath, 'utf8') : null;
  }

  /** 公開鍵を置く。すでにあるときは置き換えない（端末に組み込んだ鍵とずれると誰も更新できなくなるため。替えるときは手でファイルを消す）。 */
  setPublicKey(pem) {
    if (this.publicKeyPem()) return { ok: false, error: 'public_key_already_set' };
    let key;
    try { key = crypto.createPublicKey(pem); } catch { return { ok: false, error: 'bad_public_key' }; }
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return { ok: false, error: 'not_p256' };
    fs.writeFileSync(this.publicKeyPath, key.export({ type: 'spki', format: 'pem' }).toString(), 'utf8');
    return { ok: true };
  }

  /**
   * 署名済みの manifest を確かめて置く。管理画面とは別に Node の crypto で確かめ直す（DER の形も厳しく見る）。
   * 確かめること：形（C# と同じ規則）・通し番号が今より大きい・すべての OS の署名・sha256 と大きさが置き場のファイルと一致・URL。
   */
  publish(manifest) {
    const pem = this.publicKeyPem();
    if (!pem) return { ok: false, error: 'no_public_key' };
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) return { ok: false, error: 'bad_manifest' };
    const allowed = new Set(['version', 'rollout', 'rollback', 'seq', 'expiresAt', 'signatures']);
    for (const k of Object.keys(manifest)) if (!allowed.has(k)) return { ok: false, error: `unknown_field:${k}` };
    let p;
    try { p = normalizePolicy(manifest); } catch (e) { return { ok: false, error: `bad_policy:${e.message}` }; }
    if (p.seq == null) return { ok: false, error: 'no_seq' };
    const cur = this.manifest();
    if (cur && Number.isSafeInteger(cur.seq) && p.seq <= cur.seq) return { ok: false, error: `seq_not_increasing:${p.seq}<=${cur.seq}` };
    if (typeof manifest.version !== 'string' || !VERSION_RE.test(trimAscii(manifest.version))) return { ok: false, error: 'bad_version' };
    const version = trimAscii(manifest.version);
    const files = this.artifacts()[version];
    if (!files) return { ok: false, error: `no_files_for_version:${version}` };
    const sigs = manifest.signatures;
    if (!sigs || typeof sigs !== 'object' || Object.keys(sigs).length === 0) return { ok: false, error: 'no_signatures' };
    const pub = crypto.createPublicKey(pem);
    for (const [os, e] of Object.entries(sigs)) {
      if (!OS_RE.test(os) || !e || typeof e !== 'object') return { ok: false, error: `bad_entry:${os}` };
      const f = files[os];
      if (!f) return { ok: false, error: `no_file:${version}/${os}` };
      if (e.sha256 !== f.sha256 || e.size !== f.size) return { ok: false, error: `file_mismatch:${os}` };
      if (e.url !== undefined && e.url !== f.url) return { ok: false, error: `bad_url:${os}` };
      for (const k of Object.keys(e)) if (!['sha256', 'size', 'signatureV3', 'url'].includes(k)) return { ok: false, error: `unknown_field:${os}.${k}` };
      let payload;
      try { payload = buildPayloadV3(this.domain, os, version, e.sha256, e.size, p); } catch (err) { return { ok: false, error: `bad_field:${os}:${err.message}` }; }
      let good = false;
      try { good = typeof e.signatureV3 === 'string' && crypto.verify('sha256', Buffer.from(payload, 'utf8'), { key: pub, dsaEncoding: 'der' }, Buffer.from(e.signatureV3, 'base64')); } catch { good = false; }
      if (!good) return { ok: false, error: `signature_mismatch:${os}` };
    }
    const text = JSON.stringify(manifest, null, 2) + '\n';
    fs.mkdirSync(path.join(this.dir, 'manifests'), { recursive: true });
    fs.writeFileSync(path.join(this.dir, 'manifests', `seq-${p.seq}.json`), text, 'utf8');
    const tmp = `${this.manifestPath}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, text, 'utf8');
    fs.renameSync(tmp, this.manifestPath);
    return { ok: true, seq: p.seq };
  }
}
