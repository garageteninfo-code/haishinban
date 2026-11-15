// 署名の部品（console/manifest-core.js）の試験。Node の WebCrypto（ブラウザと同じ API）で動かす。鍵はメモリの中だけ。
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import * as core from '../console/manifest-core.js';
import * as kitSigner from '../csharp/kit-tests/tools/sign-manifest.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'csharp', 'kit-tests', 'tests', 'vectors', 'payload-v3-cases.json'), 'utf8'));

test('共通の例（C# と同じ文字列）：正しい例は同じ・不正な例は署名しない', () => {
  for (const c of vectors.valid) {
    const p = core.normalizePolicy(c.manifest);
    assert.equal(core.buildPayloadV3(c.domain, c.os, c.version, c.sha256, c.size, p), c.payload, c.name);
  }
  for (const c of vectors.invalid) {
    assert.throws(() => core.buildPayloadV3(c.domain, c.os, c.version, c.sha256, c.size, core.normalizePolicy(c.manifest)), undefined, c.name);
  }
});

test('キットの署名の道具（sign-manifest.mjs）と同じ文字列（乱数の下書き 300 件）', () => {
  for (let i = 0; i < 300; i++) {
    const policy = {
      rollout: i % 3 === 0 ? null : { percent: crypto.randomInt(0, 101), salt: `r${crypto.randomInt(0, 1e6)}` },
      badVersions: Array.from({ length: crypto.randomInt(0, 4) }, () => `1.${crypto.randomInt(0, 20)}.${crypto.randomInt(0, 20)}`),
      seq: crypto.randomInt(1, 1e9),
      expiresAt: i % 2 ? null : crypto.randomInt(0, 2 ** 31),
    };
    const args = ['sample-app', 'windows', `2.${i}.0`, crypto.randomBytes(32).toString('hex'), crypto.randomInt(0, 1e9), policy];
    assert.equal(core.buildPayloadV3(...args), kitSigner.buildPayloadV3(...args));
  }
});

test('WebCrypto の署名（DER に直した物）が Node の crypto でも通る・逆も通る', async () => {
  const kp = await core.generateKeyPair();
  const pem = await core.exportPublicPem(kp.publicKey);
  const pub = crypto.createPublicKey(pem);
  for (let i = 0; i < 50; i++) {
    const payload = `sample-app-v3|windows|1.${i}.0|${'a'.repeat(64)}|${i}|rollout=all|bad=|seq=${i + 1}|exp=none`;
    const sig = await core.signPayload(kp.privateKey, payload);
    assert.ok(crypto.verify('sha256', Buffer.from(payload), { key: pub, dsaEncoding: 'der' }, Buffer.from(sig, 'base64')));
    assert.ok(await core.verifyPayload(kp.publicKey, payload, sig));
    assert.ok(!(await core.verifyPayload(kp.publicKey, payload + 'x', sig)));
  }
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const nodeSig = crypto.sign('sha256', Buffer.from('hello'), { key: privateKey, dsaEncoding: 'der' }).toString('base64');
  const wpub = await core.importPublicPem(publicKey.export({ type: 'spki', format: 'pem' }).toString());
  assert.ok(await core.verifyPayload(wpub, 'hello', nodeSig));
});

test('r||s ⇔ DER：先頭が 0・上の桁が 1 の端の例', () => {
  const mk = (r0, s0) => { const u = new Uint8Array(64); u.fill(0x11); u[0] = r0; u[32] = s0; return u; };
  for (const [r0, s0] of [[0x00, 0x00], [0x80, 0x80], [0x00, 0xff], [0x7f, 0x01]]) {
    const raw = mk(r0, s0);
    if (r0 === 0) raw[1] = 0x00;
    assert.deepEqual(core.derToP1363(core.p1363ToDer(raw)), raw);
  }
  assert.throws(() => core.derToP1363(new Uint8Array([0x30, 0x02, 0x02, 0x00, 0x00])));
});

test('鍵ファイル：合言葉で暗号化して戻せる・合言葉違いは開かない・短い合言葉は断る', async () => {
  const kp = await core.generateKeyPair();
  const pass = crypto.randomBytes(12).toString('base64url');
  const file = await core.encryptKeyFile(kp, pass);
  assert.ok(!file.includes('PRIVATE KEY'), '秘密鍵がそのまま入っていない');
  const back = await core.decryptKeyFile(file, pass);
  assert.equal(await core.exportPublicPem(back.publicKey), await core.exportPublicPem(kp.publicKey));
  const sig = await core.signPayload(back.privateKey, 'x');
  assert.ok(await core.verifyPayload(kp.publicKey, 'x', sig));
  await assert.rejects(core.decryptKeyFile(file, pass + 'x'), /合言葉が違う/);
  await assert.rejects(core.encryptKeyFile(kp, 'short'), /10 文字以上/);
});

test('キットの道具で作った PEM の秘密鍵も読める（公開鍵が一致）', async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pair = await core.importPrivatePem(privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
  assert.equal((await core.exportPublicPem(pair.publicKey)).trim(), publicKey.export({ type: 'spki', format: 'pem' }).toString().trim());
});

test('下書き：割合を上げても salt を引き継ぐ・止めるは 0%・取り下げ', () => {
  const m1 = core.draftRelease(null, { version: '1.1.0', percent: 10 });
  assert.equal(m1.seq, 1);
  const m2 = core.draftRelease(m1, { version: '1.1.0', percent: 50 });
  assert.equal(m2.rollout.salt, m1.rollout.salt);
  assert.equal(m2.seq, 2);
  const h = core.draftHalt(m2);
  assert.deepEqual([h.version, h.rollout.percent, h.rollout.salt, h.seq], ['1.1.0', 0, m1.rollout.salt, 3]);
  const r = core.draftRevoke(h, { badVersion: '1.1.0', fallbackVersion: '1.0.0' });
  assert.deepEqual([r.version, r.rollout, r.rollback.badVersions, r.seq], ['1.0.0', null, ['1.1.0'], 4]);
  const r2 = core.draftRevoke(h, { badVersion: '1.1.0' });
  assert.equal(r2.version, '1.1.0');
  assert.throws(() => core.draftRevoke(h, { badVersion: '1.1.0', fallbackVersion: '1.1.0' }));
  assert.throws(() => core.draftHalt(null));
  const back = core.draftRelease(r, { version: '1.2.0', percent: 100 });
  assert.deepEqual(back.rollback.badVersions, ['1.1.0'], '取り下げた版は次の配信でも残る');
});

test('signManifest → verifyManifest、書き換えると通らない', async () => {
  const kp = await core.generateKeyPair();
  const art = { windows: { sha256: 'ab'.repeat(32), size: 123, url: '/updates/files/1.1.0/windows.zip' } };
  const { manifest } = await core.signManifest({ draft: core.draftRelease(null, { version: '1.1.0', percent: 10 }), artifacts: art, domain: 'sample-app', privateKey: kp.privateKey });
  assert.equal(await core.verifyManifest(manifest, 'sample-app', kp.publicKey), null);
  assert.match(await core.verifyManifest(manifest, 'other-app', kp.publicKey), /合わない/);
  const t = structuredClone(manifest); t.rollout.percent = 100;
  assert.match(await core.verifyManifest(t, 'sample-app', kp.publicKey), /合わない/);
});
