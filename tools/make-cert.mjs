// 配信番の https 用に、この PC の中で「自己署名の証明書」と鍵を作る（openssl を使う。ダウンロードはしない）。
//
//   node tools/make-cert.mjs [--out certs] [--dns haishin.example.local]... [--ip 192.168.10.5]... [--days 825] [--force]
//
// できる物: <out>/server.crt（証明書・端末に配ってよい）と <out>/server.key（鍵・人に渡さない・サーバーの PC だけ）。
// 最後に証明書の指紋（SHA-256）を表示する → アプリ側（C#）の HaishinConnectionOptions.PinnedCertSha256 に入れる。
// 社内の認証局（CA）がある会社は、そちらで発行した証明書を certFile・keyFile に指定すればよい（そのときは指紋の固定は任意）。
//
// openssl の場所: 環境変数 HAISHIN_OPENSSL → PATH の openssl → Git for Windows の同梱品（C:\Program Files\Git\usr\bin・ucrt64\bin・mingw64\bin）。

import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function findOpenssl() {
  const pf = process.env.ProgramFiles || 'C:\\Program Files';
  const candidates = [
    process.env.HAISHIN_OPENSSL,
    'openssl',
    path.join(pf, 'Git', 'usr', 'bin', 'openssl.exe'),
    path.join(pf, 'Git', 'ucrt64', 'bin', 'openssl.exe'),
    path.join(pf, 'Git', 'mingw64', 'bin', 'openssl.exe'),
  ].filter(Boolean);
  for (const exe of candidates) {
    const r = spawnSync(exe, ['version'], { encoding: 'utf8' });
    if (r.status === 0 && /OpenSSL\s+[3-9]/i.test(r.stdout || '')) return exe;
  }
  return null;
}

const NAME_RE = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

/**
 * 証明書と鍵を作る。
 * @param {{ outDir: string, dns?: string[], ips?: string[], days?: number, force?: boolean, openssl?: string }} o
 * @returns {{ certFile: string, keyFile: string, fingerprint: { colon: string, hex: string } }}
 */
export function makeCert({ outDir, dns = [], ips = [], days = 825, force = false, openssl }) {
  const exe = openssl ?? findOpenssl();
  if (!exe) throw new Error('openssl が見つかりません（Git for Windows に同梱。HAISHIN_OPENSSL で場所を指定できます）。社内の認証局の証明書を使う方法もあります（導入手順書.md）');
  const names = ['localhost', ...dns];
  const addrs = ['127.0.0.1', ...ips];
  for (const n of names) if (!NAME_RE.test(n)) throw new Error(`名前の形が不正: ${n}`);
  for (const a of addrs) if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(a)) throw new Error(`IP の形が不正（IPv4 だけ）: ${a}`);
  if (!Number.isInteger(days) || days < 1 || days > 3650) throw new Error('--days は 1〜3650');
  fs.mkdirSync(outDir, { recursive: true });
  const certFile = path.join(outDir, 'server.crt');
  const keyFile = path.join(outDir, 'server.key');
  if (!force && (fs.existsSync(certFile) || fs.existsSync(keyFile))) throw new Error(`${outDir} にもう証明書か鍵があります（作り直すなら --force。作り直すとアプリ側の指紋も入れ替えが要ります）`);
  const san = [...new Set(names)].map((n) => `DNS:${n}`).concat([...new Set(addrs)].map((a) => `IP:${a}`)).join(',');
  const r = spawnSync(exe, [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', keyFile, '-out', certFile, '-days', String(days), '-sha256',
    '-subj', '/CN=haishin-relay',
    '-addext', `subjectAltName=${san}`,
    '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature',
    '-addext', 'extendedKeyUsage=serverAuth',
  ], { encoding: 'utf8', env: { ...process.env, MSYS2_ARG_CONV_EXCL: '*' } });
  if (r.status !== 0 || !fs.existsSync(certFile)) throw new Error(`openssl が失敗しました: ${(r.stderr || '').split('\n').slice(0, 3).join(' / ')}`);
  const fp = new crypto.X509Certificate(fs.readFileSync(certFile)).fingerprint256;
  return { certFile, keyFile, fingerprint: { colon: fp, hex: fp.replace(/:/g, '').toLowerCase() }, san };
}

function args(name) {
  const out = [];
  process.argv.forEach((a, i) => { if (a === name && process.argv[i + 1]) out.push(process.argv[i + 1]); });
  return out;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  try {
    const r = makeCert({
      outDir: path.resolve(args('--out')[0] ?? path.join(root, 'certs')),
      dns: args('--dns'), ips: args('--ip'), days: Number(args('--days')[0] ?? 825), force: process.argv.includes('--force'),
    });
    console.log(`証明書: ${r.certFile}（端末に配ってよい）`);
    console.log(`鍵:     ${r.keyFile}（人に渡さない・このサーバーの PC だけに置く）`);
    console.log(`名前:   ${r.san}`);
    console.log(`指紋（SHA-256）: ${r.fingerprint.colon}`);
    console.log(`C# の PinnedCertSha256 に入れる値: ${r.fingerprint.hex}`);
    console.log('config.json の tls.enabled を true にして、node server.mjs を起動し直してください。');
  } catch (e) {
    console.error(`[失敗] ${e.message}`);
    process.exit(1);
  }
}
