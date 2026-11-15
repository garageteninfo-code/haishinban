// 言語をまたいだ確認（改良版）: tools/sign-manifest.mjs で本当に署名した manifest を作り、C# の試験に渡す。
//   node make-vectors.mjs <out.json>
//   秘密鍵はメモリの中だけ（ファイルに書かない）。出力は一時の「公開鍵」と manifest だけ。一時フォルダは最後に消す。
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const { signManifest } = await import(pathToFileURL(path.join(here, '..', '..', 'tools', 'sign-manifest.mjs')).href);
const out = process.argv[2];
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'usk-xlang-'));
const manifests = [];
try {
  const d = path.join(tmp, 'rel'); fs.mkdirSync(d);
  const snap = (name, r) => manifests.push({ name, manifest: JSON.parse(JSON.stringify(r.manifest)) });
  fs.writeFileSync(path.join(d, 'windows.zip'), 'pkg 1.1.0');
  snap('1.1.0 を 10%（seq 1）', signManifest({ dir: d, osKey: 'windows', version: '1.1.0', privateKeyPem: privatePem, domain: 'myapp', rollout: { percent: 10, salt: 'r110' } }));
  snap('1.1.0 を 50%（seq 2）', signManifest({ dir: d, osKey: 'windows', version: '1.1.0', privateKeyPem: privatePem, domain: 'myapp', rollout: { percent: 50, salt: 'r110' } }));
  snap('1.1.0 を止めた 0%（seq 3）', signManifest({ dir: d, osKey: 'windows', version: '1.1.0', privateKeyPem: privatePem, domain: 'myapp', rollout: { percent: 0, salt: 'r110' } }));
  fs.writeFileSync(path.join(d, 'windows.zip'), crypto.randomBytes(512 * 1024));
  snap('1.2.0 で 1.1.0 を不具合版に・期限つき（seq 4）', signManifest({ dir: d, osKey: 'windows', version: '1.2.0', privateKeyPem: privatePem, domain: 'myapp',
    rollout: { percent: 100, salt: 'r120' }, rollback: { badVersions: ['1.1.0'] }, expiresAt: 4102444800 }));
  snap('期限切れ（seq 5・2001 年で期限）', signManifest({ dir: d, osKey: 'windows', version: '1.2.0', privateKeyPem: privatePem, domain: 'myapp', expiresAt: 1000000000 }));
  fs.writeFileSync(out, JSON.stringify({ publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), manifests }, null, 1));
  console.log(`[xlang] ${manifests.length} manifests → ${out}`);
} finally { fs.rmSync(tmp, { recursive: true, force: true }); }
