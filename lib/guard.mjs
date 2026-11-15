// 報告の関門：個人情報・鍵が入った報告を「受け取らずに断る」。
//
// 中身は 2 つの部品を合わせたもの（どちらも写し）：
//   1. jpGuard.mjs（試験\改良\ の写し・変更なし）… 日本の電話・メール・カード・マイナンバー・住所・氏名・生年月日・鍵。
//      マイナンバーは検査用数字に加えて「マイナンバー」等の言葉か 4-4-4 の区切りが要るので、ただの 12 桁の業務の番号は断らない。
//   2. 中継（試験\中継と自動修理\改良版\relay\src\redactCheck.mjs）のうち、jpGuard に無い「技術的な漏れ」の規則
//      … 利用者名入りのパス（C:\Users\田中\…）・共有フォルダ（\\サーバー\）・会社の OneDrive・社内の URL ホスト・IPv4・鍵らしい長い塊。
//      中継の電話・カード・マイナンバー・住所・氏名の規則は使わない（12 桁の業務の番号の約 1 割を誤って断っていたため）。
//
// ⚠ 見つけた文字列そのものは返さない・記録しない（種類と欄の名前だけ）。
// ⚠ 規則で見つけるだけなので完全ではない（説明.md の数字を参照）。

import { findAll } from './jpGuard.mjs';

/** 設定で止められない種類（秘密そのもの）。 */
export const LOCKED_KINDS = Object.freeze([
  'private_key', 'api_key', 'github_token', 'slack_token', 'aws_key', 'payment_secret', 'jwt', 'bearer',
  'url_password', 'credential_assign', 'credential_phrase', 'url_credentials',
]);

/** 止められる種類（個人情報と技術的な漏れ）。 */
export const OPTIONAL_KINDS = Object.freeze([
  'email', 'phone', 'address', 'name', 'birth', 'credit_card', 'my_number',
  'user_path', 'unc_path', 'org_name', 'url_host', 'ipv4', 'high_entropy',
]);

export const DEFAULT_GUARD_CONFIG = Object.freeze({
  disabledKinds: [],
  allowHosts: [],
  allowHexHashes: true,
  myNumberWithoutContext: false,
  extraRules: [],
});

const PLACEHOLDER_START = /^[<[*%{]/;
const ROLE_NAME_END = /[者員]$/u;
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '[::1]', '::1']);
const NON_USER_DIRS = new Set(['public', 'default', 'default user', 'all users', 'shared']);
const KEY_CONTEXT = /(?:key|token|secret|auth|passw|pwd|bearer|signature|credential|キー|トークン|鍵|シークレット|パスワード)[^\n]{0,12}$/i;

function normalize(text) {
  return String(text ?? '')
    .normalize('NFKC')
    .replace(/[\u200B-\u200D\u2060\uFEFF\u00AD]/g, '')
    .replace(/(?<=\d)[\u2010-\u2015\u2212\u30FC](?=\d)/g, '-');
}

function isPlaceholderName(name) {
  const n = String(name || '').trim();
  if (!n) return true;
  if (PLACEHOLDER_START.test(n)) return true;
  return NON_USER_DIRS.has(n.toLowerCase());
}

function hostAllowed(host, allowHosts) {
  if (LOOPBACK_HOSTS.has(host) || PLACEHOLDER_START.test(host)) return true;
  for (const a of allowHosts) {
    if (a.startsWith('.') ? host.endsWith(a) || host === a.slice(1) : host === a) return true;
  }
  return false;
}

/** 中継の改良版から写した「技術的な漏れ」の規則（jpGuard に無いもの）。 */
function technicalScan(s, on, cfg, allowHosts) {
  if (on('user_path')) {
    for (const m of s.matchAll(/[A-Za-z]:(?:\\|\/)+Users(?:\\|\/)+([^\\/\s"'<>|]+)/gi)) if (!isPlaceholderName(m[1])) return 'user_path';
    for (const m of s.matchAll(/(?:^|[\s("'=:])\/(?:home|Users)\/([^/\s"'<>|]+)/g)) if (!isPlaceholderName(m[1])) return 'user_path';
  }
  if (on('unc_path')) {
    for (const m of s.matchAll(/(?:^|[\s("'=:])\\\\([^\\\s"'<>|]+)\\/g)) {
      if (!hostAllowed(m[1].toLowerCase(), allowHosts) && m[1] !== '?' && m[1] !== '.') return 'unc_path';
    }
  }
  if (on('org_name') && /OneDrive - (?![<[*%{])[^\\/\r\n]+/.test(s)) return 'org_name';
  for (const m of s.matchAll(/\b[a-z][a-z0-9+.-]*:\/\/([^/\s?#"'<>]+)/gi)) {
    const authority = m[1];
    if (authority.includes('@')) return 'url_credentials';
    const host = authority.replace(/:\d+$/, '').toLowerCase();
    if (hostAllowed(host, allowHosts)) continue;
    if (on('url_host')) return 'url_host';
  }
  if (on('ipv4')) {
    for (const m of s.matchAll(/\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))\b/g)) {
      if (m[1].startsWith('127.') || m[1] === '0.0.0.0') continue;
      return 'ipv4';
    }
  }
  if (on('high_entropy')) {
    for (const m of s.matchAll(/[A-Za-z0-9]{32,}/g)) {
      const t = m[0];
      if (!(/[A-Za-z]/.test(t) && /\d/.test(t))) continue;
      if (cfg.allowHexHashes && /^[0-9a-f]+$/i.test(t) && !KEY_CONTEXT.test(s.slice(Math.max(0, m.index - 30), m.index))) continue;
      return 'high_entropy';
    }
  }
  return null;
}

/** 設定の確かめ。書き間違いは起動時に失敗させる（黙って関門を緩めない）。 */
export function normalizeGuardConfig(config = {}) {
  const cfg = { ...DEFAULT_GUARD_CONFIG, ...(config || {}) };
  const known = new Set([...LOCKED_KINDS, ...OPTIONAL_KINDS]);
  for (const k of cfg.disabledKinds || []) {
    if (LOCKED_KINDS.includes(k)) throw new Error(`関門の設定: ${k} は止められない（秘密そのものの種類）`);
    if (!known.has(k)) throw new Error(`関門の設定: 知らない種類 ${k}（書き間違いで関門を緩めないため起動しない）`);
  }
  if (!Array.isArray(cfg.allowHosts)) throw new Error('関門の設定: allowHosts は配列');
  if (!Array.isArray(cfg.extraRules)) throw new Error('関門の設定: extraRules は配列');
  return cfg;
}

/**
 * 関門を作る。
 * @param {{ disabledKinds?: string[], allowHosts?: string[], allowHexHashes?: boolean, myNumberWithoutContext?: boolean,
 *           extraRules?: { kind: string, pattern: string, flags?: string }[] }} [config]
 */
export function createGuard(config = {}) {
  const cfg = normalizeGuardConfig(config);
  const disabled = new Set(cfg.disabledKinds);
  const on = (k) => !disabled.has(k);
  const allowHosts = cfg.allowHosts.map((h) => String(h).toLowerCase());
  const extra = cfg.extraRules.map((r, i) => {
    if (!r || typeof r.kind !== 'string' || typeof r.pattern !== 'string') throw new Error(`関門の設定: extraRules[${i}] は { kind, pattern } が要る`);
    return { kind: r.kind, re: new RegExp(r.pattern, String(r.flags || '').replace(/g/g, '')) };
  });

  function check(text) {
    const raw = String(text ?? '');
    if (!raw) return null;
    // 1. jpGuard（全角・字間の空白をそろえてから当てる）
    for (const h of findAll(raw, { aggressive: !!cfg.myNumberWithoutContext })) {
      // 「利用者様」「使用者さん」のような役割の言葉は名前ではない（jpGuard の除外の一覧に無かったので、ここで除く。
      // 中継の改良版の「役割の言葉で終わるなら名前ではない」と同じ考え。結合した後の試験で 1 件見つけて足した）
      if (h.kind === 'name' && ROLE_NAME_END.test(raw.slice(h.start, h.end).trim())) continue;
      if (LOCKED_KINDS.includes(h.kind) || h.cat === 'credential' || on(h.kind)) return h.kind;
    }
    // 2. 足した規則
    const norm = normalize(raw);
    for (const r of extra) if (r.re.test(norm) || r.re.test(raw)) return r.kind;
    // 3. 技術的な漏れ（揃えた文字列と元の文字列の両方）
    return technicalScan(norm, on, cfg, allowHosts) || (norm !== raw ? technicalScan(raw, on, cfg, allowHosts) : null);
  }

  /** 欄をまとめて調べる。最初に見つかったものを { field, kind } で返す。無ければ null。 */
  function checkFields(fields) {
    for (const [field, value] of Object.entries(fields)) {
      if (typeof value !== 'string') continue;
      const kind = check(value);
      if (kind) return { field, kind };
    }
    return null;
  }

  return { check, checkFields, config: cfg };
}
