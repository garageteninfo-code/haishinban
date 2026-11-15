// node --test tools/sign-manifest.test.mjs
// 鍵はすべてこの実行の間だけメモリで作る。一時フォルダには偽の配布物と manifest だけを置き、最後に消す。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildPayloadV3, buildPayloadV2, canonBad, normalizePolicy, signManifest, trimAscii } from './sign-manifest.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const cases = JSON.parse(fs.readFileSync(path.join(here, '..', 'tests', 'vectors', 'payload-v3-cases.json'), 'utf8'));
const key = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { publicKey, privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
};
const verify = (pub, payload, sig) => crypto.verify('sha256', Buffer.from(payload, 'utf8'), pub, Buffer.from(sig, 'base64'));
function withDir(files, fn) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'usk-sign-test-'));
  try { for (const [n, c] of Object.entries(files)) fs.writeFileSync(path.join(d, n), c); return fn(d); }
  finally { fs.rmSync(d, { recursive: true, force: true }); }
}

test('共通の例（valid）: C# と同じ文字列になる', () => {
  for (const c of cases.valid) {
    const p = normalizePolicy(c.manifest);
    assert.equal(buildPayloadV3(c.domain, c.os, c.version, c.sha256, c.size, p), c.payload, c.name);
  }
});

test('共通の例（invalid）: どれも署名しない', () => {
  for (const c of cases.invalid) {
    assert.throws(() => buildPayloadV3(c.domain, c.os, c.version, c.sha256, c.size, normalizePolicy(c.manifest)), undefined, c.name);
  }
});

test('空白は ASCII だけ除く（U+0085 / U+FEFF は残して弾く）', () => {
  assert.equal(trimAscii(' \t1.0\r\n'), '1.0');
  assert.equal(trimAscii('1.0\u0085'), '1.0\u0085');
  assert.equal(canonBad(['1.1', ' 1.0 ', '1.1', '']), '1.0,1.1');
});

test('署名: v3 を書き、rollout・不具合版・seq・期限を束縛する', () => {
  const { publicKey, privatePem } = key();
  withDir({ 'windows.zip': 'pkg-1.1.0', 'manifest.json': JSON.stringify({ notes: 'n' }) }, (dir) => {
    const r = signManifest({ dir, osKey: 'windows', version: '1.1.0', privateKeyPem: privatePem, domain: 'myapp',
      rollout: { percent: 30, salt: 'r110' }, rollback: { badVersions: ['1.0.9'] }, expiresAt: 1800000000 });
    const m = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
    assert.equal(m.notes, 'n');
    assert.equal(m.seq, 1, '最初は 1');
    const s = m.signatures.windows;
    assert.ok(verify(publicKey, r.payloadV3, s.signatureV3));
    assert.equal(s.signatureV2, undefined, 'v2 は頼んだときだけ');
    const p = { rollout: { percent: 30, salt: 'r110' }, badVersions: ['1.0.9'], seq: 1, expiresAt: 1800000000 };
    for (const t of [{ ...p, seq: 2 }, { ...p, expiresAt: null }, { ...p, badVersions: [] }, { ...p, rollout: { percent: 100, salt: 'r110' } }])
      assert.ok(!verify(publicKey, buildPayloadV3('myapp', 'windows', '1.1.0', s.sha256, s.size, t), s.signatureV3), '書き換えると落ちる');
    assert.ok(!verify(publicKey, buildPayloadV3('usk-update', 'windows', '1.1.0', s.sha256, s.size, p), s.signatureV3), '別の製品名では落ちる');
  });
});

test('seq: 省くと +1・下げられない・全 OS を同じ seq で署名し直す', () => {
  const { publicKey, privatePem } = key();
  withDir({ 'windows.zip': 'w', 'linux.tar.gz': 'l' }, (dir) => {
    signManifest({ dir, osKey: 'windows', version: '2.0.0', privateKeyPem: privatePem });
    const r2 = signManifest({ dir, osKey: 'linux', version: '2.0.0', privateKeyPem: privatePem });
    const m = r2.manifest;
    assert.equal(m.seq, 2);
    const p = normalizePolicy(m);
    for (const k of ['windows', 'linux'])
      assert.ok(verify(publicKey, buildPayloadV3('usk-update', k, '2.0.0', m.signatures[k].sha256, m.signatures[k].size, p), m.signatures[k].signatureV3), k);
    assert.throws(() => signManifest({ dir, osKey: 'windows', version: '2.0.1', privateKeyPem: privatePem, seq: 1 }), /must not go down/);
    fs.rmSync(path.join(dir, 'linux.tar.gz'));
    const r3 = signManifest({ dir, osKey: 'windows', version: '2.0.1', privateKeyPem: privatePem });
    assert.deepEqual(r3.dropped, ['linux'], '配布物の無い OS は外して知らせる');
  });
});

test('v2（移行用）も頼めば書ける', () => {
  const { publicKey, privatePem } = key();
  withDir({ 'windows.zip': 'x' }, (dir) => {
    const r = signManifest({ dir, osKey: 'windows', version: '1.0.0', privateKeyPem: privatePem, domain: 'legacy-update', v2: true });
    assert.equal(r.payloadV2, buildPayloadV2('legacy-update', 'windows', '1.0.0', r.sha256, r.size, null, []));
    assert.ok(verify(publicKey, r.payloadV2, r.manifest.signatures.windows.signatureV2));
  });
});

test('P-256 以外の鍵・不正な方針・配布物なしでは署名しない', () => {
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  withDir({ 'windows.zip': 'x' }, (dir) => {
    assert.throws(() => signManifest({ dir, osKey: 'windows', version: '1.0.0', privateKeyPem: rsa }), /P-256/);
    assert.throws(() => signManifest({ dir, osKey: 'windows', version: '1.0.0', privateKeyPem: key().privatePem, rollout: { percent: 150 } }));
    assert.throws(() => signManifest({ dir, osKey: 'mac', version: '1.0.0', privateKeyPem: key().privatePem }), /no artifact/);
  });
});
