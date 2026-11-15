// 管理画面。通信先はこのサーバー（同じ場所）だけ。署名は WebCrypto でこの画面の中で行い、秘密鍵は送らない。
import {
  decryptKeyFile, draftHalt, draftRelease, draftRevoke, encryptKeyFile, exportPublicPem, generateKeyPair,
  importPrivatePem, keyFingerprint, signManifest, verifyManifest, buildPayloadV3, normalizePolicy, trimAscii,
} from './manifest-core.js';

const $ = (id) => document.getElementById(id);
let status = null;
let keyPair = null;
let keyPub = '';
let draft = null;
let csrf = '';
let timer = null;

function msg(text, kind = '') {
  const m = $('msg');
  m.textContent = text;
  m.className = `msg ${kind}`;
}
function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v; else e.setAttribute(k, v);
  }
  for (const c of children) e.append(c);
  return e;
}
const pct = (x) => (x == null ? '—' : `${(x * 100).toFixed(1)}%`);
const STATUS_TEXT = { over: '基準超え', ok: '問題なし', watch: '要注意（台数が少ない）', too_few: '台数が少ない', no_data: 'データなし' };

const ERR_TEXT = {
  wrong_password: '合言葉が違います。', too_many_attempts: 'まちがいが続いたので、しばらく待ってください。', login_required: 'ログインしてください。',
  password_too_short: '合言葉は 12 文字以上にしてください。', password_too_simple: '同じ文字の繰り返しは使えません。', csrf: '画面を読み込み直してください（札が古い）。',
  setup_only_from_this_pc: '初めの合言葉は、サーバーの PC（127.0.0.1）で開いて決めてください。', already_set_up: 'もう合言葉が決まっています。',
};
async function api(method, path, body) {
  const opt = { method, headers: { 'x-haishin-console': '1' }, cache: 'no-store', credentials: 'same-origin' };
  if (csrf && method !== 'GET') opt.headers['x-csrf-token'] = csrf;
  if (body !== undefined || method !== 'GET') { opt.headers['content-type'] = 'application/json'; opt.body = JSON.stringify(body ?? {}); }
  const r = await fetch(path, opt);
  const j = await r.json().catch(() => ({}));
  if (r.status === 401 && j.error === 'login_required') showLogin();
  if (!r.ok) {
    const e = new Error((ERR_TEXT[j.error] || j.error || `HTTP ${r.status}`) + (j.retryAfter ? `（あと約 ${Math.ceil(j.retryAfter / 60)} 分）` : ''));
    e.code = j.error;
    throw e;
  }
  if (j.csrf) csrf = j.csrf;
  return j;
}

// ---------- ログイン ----------
let sessionInfo = null;
function showLogin() {
  if (timer) { clearInterval(timer); timer = null; }
  $('app').hidden = true;
  $('userbar').hidden = true;
  $('login').hidden = false;
  const s = sessionInfo || {};
  const setup = !!s.setupNeeded;
  $('login-title').textContent = setup ? '初めに：管理画面の合言葉を決める' : 'ログイン';
  $('login-pass2-label').hidden = !setup;
  $('login-pass2').required = setup;
  $('login-pass').autocomplete = setup ? 'new-password' : 'current-password';
  $('login-submit').textContent = setup ? '決めてログイン' : 'ログイン';
  $('login-submit').disabled = setup && !s.setupAllowedHere;
  $('login-hint').textContent = setup
    ? (s.setupAllowedHere ? '12 文字以上。サーバーには混ぜた値（scrypt）だけを置きます。忘れたら data\\console-auth.json を消して決め直します。' : ERR_TEXT.setup_only_from_this_pc)
    : '合言葉は 15 分に 5 回まちがえると、しばらく試せなくなります。';
  $('login-pass').focus();
}
async function showApp() {
  $('login').hidden = true;
  $('app').hidden = false;
  $('userbar').hidden = false;
  await refresh();
  if (!timer) timer = setInterval(refresh, 5000);
}
async function boot() {
  try {
    sessionInfo = await api('GET', '/api/admin/session');
    $('conn').textContent = sessionInfo.https ? ' ／ https で接続中' : ' ／ ⚠ http（暗号化なし）';
    if (sessionInfo.loggedIn) { csrf = sessionInfo.csrf; await showApp(); } else showLogin();
  } catch (e) { msg(`サーバーから読めません：${e.message}`, 'err'); }
}
$('login-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const pw = $('login-pass').value;
  try {
    if (sessionInfo && sessionInfo.setupNeeded) {
      if (pw !== $('login-pass2').value) throw new Error('2 つの合言葉が違います。');
      await api('POST', '/api/admin/setup', { password: pw });
      sessionInfo.setupNeeded = false;
      msg('合言葉を決めました。忘れないよう、社内の決まった場所に控えてください。', 'ok');
    } else {
      await api('POST', '/api/admin/login', { password: pw });
      msg('ログインしました。', 'ok');
    }
    $('login-pass').value = ''; $('login-pass2').value = '';
    await showApp();
  } catch (e) { msg(`ログインできません：${e.message}`, 'err'); }
});
$('logout').addEventListener('click', async () => {
  try { await api('POST', '/api/admin/logout'); } catch { /* 期限切れでも画面は戻す */ }
  csrf = ''; keyPair = null; keyPub = ''; draft = null;
  $('key-state').textContent = '鍵：まだ読み込んでいません';
  $('draft').hidden = true;
  msg('ログアウトしました（読み込んだ鍵も画面から外しました）。', 'ok');
  showLogin();
});
$('pw-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    if ($('pw-next').value !== $('pw-next2').value) throw new Error('新しい合言葉が 2 つで違います。');
    await api('POST', '/api/admin/password', { current: $('pw-current').value, next: $('pw-next').value });
    for (const id of ['pw-current', 'pw-next', 'pw-next2']) $(id).value = '';
    msg('合言葉を変えました。ほかの PC のログインはすべて切れました。', 'ok');
  } catch (e) { msg(`変えられません：${e.message}`, 'err'); }
});

function describeManifest(m) {
  if (!m) return '（まだありません。下で「新しい版を配る」から作ってください）';
  const bad = m.rollback?.badVersions ?? [];
  const parts = [`案内している版 ${m.version}`];
  if (bad.includes(m.version)) parts.push('（取り下げ済みなので誰にも配りません）');
  else parts.push(m.rollout ? `を ${m.rollout.percent}% の端末に配る` : 'を全員に配る');
  if (bad.length) parts.push(`／取り下げた版 ${bad.join(', ')}`);
  parts.push(`／通し番号 ${m.seq}`);
  parts.push(m.expiresAt ? `／期限 ${new Date(m.expiresAt * 1000).toLocaleString('ja-JP')}` : '／期限なし');
  return parts.join('');
}

function render() {
  if (!status) return;
  $('domain').textContent = status.domain;
  const th = status.threshold;
  $('threshold').textContent = `判定の基準：直近 ${th.windowHours} 時間で、動いている端末が ${th.minActiveInstalls} 台以上・落ちた端末が ${th.minCrashInstalls} 台以上で、落ちる割合が ${pct(th.maxCrashRate)} を超えたら「基準超え」。`;

  const tb = $('versions').querySelector('tbody');
  tb.replaceChildren();
  for (const v of status.versions) {
    const roll = v.rollout === 'revoked' ? '取り下げ済み' : v.rollout == null ? '—' : `${v.rollout}%`;
    tb.append(el('tr', {},
      el('td', { text: v.version }), el('td', { text: roll }),
      el('td', { class: 'num', text: String(v.activeInstalls) }), el('td', { class: 'num', text: String(v.crashInstalls) }),
      el('td', { class: 'num', text: String(v.crashReports) }), el('td', { class: 'num', text: pct(v.crashRate) }),
      el('td', { class: `st-${v.status}`, text: STATUS_TEXT[v.status] || v.status })));
  }

  const ref = $('refused');
  ref.replaceChildren();
  const kinds = Object.entries(status.refused || {});
  if (kinds.length === 0) ref.append(el('li', { text: 'なし' }));
  for (const [k, n] of kinds) ref.append(el('li', { text: `${k}：${n} 件` }));

  const cur = $('current');
  cur.replaceChildren(el('p', { text: describeManifest(status.manifest) }));
  cur.append(el('p', { class: 'hint', text: status.publicKeyPem ? 'このサーバーに公開鍵が登録されています。' : 'このサーバーにはまだ公開鍵がありません（「署名の鍵」で登録）。' }));

  // 知らせ：基準を超えていて、まだ止めていない版
  const al = $('alerts');
  al.replaceChildren();
  const m = status.manifest;
  for (const v of status.versions.filter((x) => x.status === 'over')) {
    const halted = m && ((m.version === v.version && m.rollout && m.rollout.percent === 0) || (m.rollback?.badVersions ?? []).includes(v.version));
    if (halted) continue;
    const box = el('div', { class: 'alert', role: 'alert' },
      el('b', { text: `版 ${v.version} の落ちる割合が基準を超えました：${pct(v.crashRate)}（${v.crashInstalls} / ${v.activeInstalls} 台）＞ ${pct(th.maxCrashRate)}` }),
      el('br'), document.createTextNode('配信を止める（0%）か、この版を取り下げることを勧めます。'));
    if (m && m.version === v.version) {
      const b = el('button', { type: 'button', class: 'primary', text: 'この版の配信を止める（0%）の下書きを作る' });
      b.addEventListener('click', () => makeDraft('halt'));
      box.append(el('br'), b);
    }
    al.append(box);
  }

  // 選択肢
  const versions = Object.keys(status.artifacts || {}).sort((a, b) => b.localeCompare(a, 'en', { numeric: true }));
  fillSelect($('rel-version'), versions);
  fillSelect($('rev-version'), [...new Set([...status.versions.map((x) => x.version), ...versions])].sort((a, b) => b.localeCompare(a, 'en', { numeric: true })));
  fillSelect($('rev-fallback'), ['', ...versions], { '': '（代わりに配らない）' });
  updateButtons();
}

function fillSelect(sel, values, labels = {}) {
  const keep = sel.value;
  sel.replaceChildren(...values.map((v) => el('option', { value: v, text: labels[v] ?? v })));
  if (values.includes(keep)) sel.value = keep;
}

async function refresh() {
  try { status = await api('GET', '/api/admin/status'); render(); } catch (e) { msg(`サーバーから読めません：${e.message}`, 'err'); }
}

// ---------- 鍵 ----------
async function setKey(pair, how) {
  keyPair = pair;
  keyPub = await exportPublicPem(pair.publicKey);
  $('key-state').textContent = `鍵：${how}（指紋 ${await keyFingerprint(pair.publicKey)}）`;
  updateButtons();
}
function serverKeyMismatch() {
  return !!(status && status.publicKeyPem && keyPub && trimAscii(status.publicKeyPem) !== trimAscii(keyPub));
}
function updateButtons() {
  const has = !!keyPair;
  $('key-save').disabled = !has;
  $('pub-save').disabled = !has;
  $('pub-register').disabled = !has || !!(status && status.publicKeyPem);
  const canSign = has && !!draft && !serverKeyMismatch();
  $('sign-publish').disabled = !canSign || !(status && status.publicKeyPem);
  $('sign-save').disabled = !canSign;
  if (has && serverKeyMismatch()) msg('読み込んだ鍵は、このサーバーに登録された公開鍵と違います。この鍵では署名できません。', 'err');
}

async function saveFile(name, text, type) {
  if (window.showSaveFilePicker) {
    try {
      const h = await window.showSaveFilePicker({ suggestedName: name });
      const w = await h.createWritable();
      await w.write(new Blob([text], { type }));
      await w.close();
      return true;
    } catch (e) { if (e && e.name === 'AbortError') return false; }
  }
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  return true;
}

$('key-new').addEventListener('click', async () => {
  if (keyPair && !confirm('今の鍵を画面から外して、新しい鍵を作りますか？（保存していない鍵は消えます）')) return;
  await setKey(await generateKeyPair(), '新しく作った鍵・まだ保存していません');
  msg('新しい鍵を作りました。画面を閉じると消えるので、「鍵ファイルとして保存」で控えを作ってください。', 'ok');
});
$('key-file').addEventListener('change', async (ev) => {
  const f = ev.target.files && ev.target.files[0];
  ev.target.value = '';
  if (!f) return;
  try {
    const text = await f.text();
    if (text.includes('-----BEGIN PRIVATE KEY-----')) await setKey(await importPrivatePem(text), `${f.name} から読み込み（暗号化されていない PEM）`);
    else {
      msg('鍵ファイルを開いています…（合言葉の確かめに数秒かかります）');
      await setKey(await decryptKeyFile(text, $('key-pass').value), `${f.name} から読み込み`);
    }
    msg('鍵を読み込みました。', 'ok');
  } catch (e) { msg(`鍵を読めません：${e.message}`, 'err'); }
});
$('key-save').addEventListener('click', async () => {
  try {
    msg('暗号化しています…');
    const text = await encryptKeyFile(keyPair, $('key-pass').value);
    if (await saveFile('haishin-signing-key.json', text, 'application/json')) msg('鍵ファイルを保存しました。人に渡さず、控えを別の場所にも置いてください。', 'ok');
  } catch (e) { msg(`保存できません：${e.message}`, 'err'); }
});
$('pub-save').addEventListener('click', async () => {
  if (await saveFile('public-key.pem', keyPub, 'application/x-pem-file')) msg('公開鍵を書き出しました。アプリ（UpdateSafetyKit）に組み込んでください。', 'ok');
});
$('pub-register').addEventListener('click', async () => {
  try { await api('PUT', '/api/admin/public-key', { pem: keyPub }); msg('公開鍵をこのサーバーに登録しました。', 'ok'); await refresh(); } catch (e) { msg(`登録できません：${e.message}`, 'err'); }
});

// ---------- 下書き ----------
function expiresAt() {
  const d = $('exp-days').value.trim();
  if (!d) return null;
  const n = Number(d);
  if (!Number.isInteger(n) || n < 1) throw new Error('有効期限は 1 以上の整数（日）');
  return Math.floor(Date.now() / 1000) + n * 86400;
}

function makeDraft(kind) {
  try {
    const cur = status && status.manifest;
    const exp = expiresAt();
    let d, summary;
    if (kind === 'release') {
      const version = $('rel-version').value;
      const percent = Number($('rel-percent').value);
      if (!version) throw new Error('配るファイルがありません（release\\files\\<版>\\windows.zip を置く）');
      if (!Number.isInteger(percent) || percent < 0 || percent > 100) throw new Error('割合は 0〜100 の整数');
      d = draftRelease(cur, { version, percent, expiresAt: exp });
      summary = `版 ${version} を ${percent >= 100 ? '全員' : percent + '% の端末'}に配ります。` + (cur && cur.version === version && cur.rollout ? '組分けの種は前と同じなので、前に当たった端末は外れません。' : '');
    } else if (kind === 'halt') {
      d = draftHalt(cur, { expiresAt: exp });
      summary = `版 ${cur.version} の配信を 0% にします。まだ入れていない端末には配りません。すでに ${cur.version} を入れた端末はそのままです（戻すには「この版を取り下げる」）。`;
    } else {
      const bad = $('rev-version').value;
      const fb = $('rev-fallback').value || undefined;
      d = draftRevoke(cur, { badVersion: bad, fallbackVersion: fb, expiresAt: exp });
      summary = fb
        ? `版 ${bad} を取り下げ、${fb} を全員に案内します。${bad} の端末は ${fb} に戻されます（UpdateSafetyKit の判定）。`
        : `版 ${bad} を取り下げます。誰にも配りません。すでに入れた端末はそのままです。`;
    }
    const files = status.artifacts[d.version];
    if (!files) throw new Error(`版 ${d.version} のファイルがこのサーバーにありません`);
    const p = normalizePolicy(d);
    const payloads = Object.keys(files).sort().map((os) => buildPayloadV3(status.domain, os, d.version, files[os].sha256, files[os].size, p));
    draft = { draft: d, files };
    $('draft').hidden = false;
    $('draft-summary').textContent = `${summary}（通し番号 ${d.seq}${d.expiresAt ? '・期限 ' + new Date(d.expiresAt * 1000).toLocaleString('ja-JP') : '・期限なし'}）`;
    $('draft-payloads').textContent = payloads.join('\n');
    $('draft-json').textContent = JSON.stringify(d, null, 2);
    msg(keyPair ? '下書きを作りました。内容を確かめてから署名してください。' : '下書きを作りました。署名するには鍵を読み込んでください。');
    updateButtons();
    $('draft').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (e) { msg(`下書きを作れません：${e.message}`, 'err'); }
}
$('draft-release').addEventListener('click', () => makeDraft('release'));
$('draft-halt').addEventListener('click', () => makeDraft('halt'));
$('draft-revoke').addEventListener('click', () => makeDraft('revoke'));

async function signDraft() {
  const { manifest } = await signManifest({ draft: draft.draft, artifacts: draft.files, domain: status.domain, privateKey: keyPair.privateKey });
  const why = await verifyManifest(manifest, status.domain, keyPair.publicKey);
  if (why) throw new Error(`署名の確かめに失敗：${why}`);
  return manifest;
}
$('sign-publish').addEventListener('click', async () => {
  if (!confirm('この配信情報に署名して、このサーバーに載せます。端末は次の確認のときに読みます。よろしいですか？')) return;
  try {
    const manifest = await signDraft();
    await api('PUT', '/api/admin/manifest', { manifest });
    draft = null;
    $('draft').hidden = true;
    msg(`署名して載せました（通し番号 ${manifest.seq}）。`, 'ok');
    await refresh();
  } catch (e) { msg(`載せられません：${e.message}`, 'err'); }
});
$('sign-save').addEventListener('click', async () => {
  try {
    const manifest = await signDraft();
    if (await saveFile('manifest.json', JSON.stringify(manifest, null, 2) + '\n', 'application/json')) msg(`署名した配信情報をファイルに保存しました（通し番号 ${manifest.seq}）。サーバーには載せていません。`, 'ok');
  } catch (e) { msg(`保存できません：${e.message}`, 'err'); }
});

boot();
