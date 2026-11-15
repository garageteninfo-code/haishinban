// 受け付けた報告・起動の知らせ・断った記録をファイルに置き、版ごとの「落ちる割合」を数える。
//
// 置き場所（dataDir の下）:
//   salt.txt                        … 端末の番号を混ぜる塩（初回に乱数で作る。外へ出さない）
//   reports/<版>/<日付>/<時刻>-<乱数>.json … 受け付けた報告（関門を通った物だけ）
//   heartbeats/<日付>.jsonl          … 起動の知らせ（版・混ぜた端末番号・時刻だけ）
//   refused/<日付>.jsonl             … 断った記録（時刻・欄の名前・種類だけ。中身は書かない）
//   alerts.jsonl                     … 基準を超えた知らせ
//
// 落ちる割合 = その版で「落ちた」と報告した端末の数 ÷ その版で動いている端末の数（どちらも windowHours の中）。

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const VERSION_DIR_RE = /^[0-9A-Za-z.+-]{1,64}$/;
const day = (ms) => new Date(ms).toISOString().slice(0, 10).replace(/-/g, '');

function appendLine(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, JSON.stringify(obj) + '\n', 'utf8');
}
function writeAtomic(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, text, 'utf8');
  fs.renameSync(tmp, file);
}
function readLines(file) {
  if (!fs.existsSync(file)) return [];
  const out = [];
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try { out.push(JSON.parse(line)); } catch { /* 途中で切れた行は飛ばす */ }
  }
  return out;
}

export const DEFAULT_THRESHOLD = Object.freeze({ minActiveInstalls: 10, minCrashInstalls: 3, maxCrashRate: 0.1, windowHours: 72 });

export class Store {
  /** @param {{ dataDir: string, threshold?: object, now?: () => number, log?: (m: string) => void }} o */
  constructor({ dataDir, threshold = {}, now = () => Date.now(), log = () => undefined }) {
    this.dir = dataDir;
    this.th = { ...DEFAULT_THRESHOLD, ...threshold };
    for (const k of Object.keys(DEFAULT_THRESHOLD)) if (!(typeof this.th[k] === 'number' && this.th[k] >= 0)) throw new Error(`基準の設定 ${k} が不正`);
    this.now = now;
    this.log = log;
    fs.mkdirSync(this.dir, { recursive: true });
    const saltFile = path.join(this.dir, 'salt.txt');
    if (!fs.existsSync(saltFile)) fs.writeFileSync(saltFile, crypto.randomBytes(32).toString('hex'), 'utf8');
    this.salt = fs.readFileSync(saltFile, 'utf8').trim();
    /** @type {Map<string, { active: Map<string, number>, crashed: Map<string, number>, crashes: { at: number, n: number }[], errors: { at: number, n: number }[] }>} */
    this.v = new Map();
    this.alerted = new Set();
    this.refusedCounts = {};
    this.load();
  }

  pseudo(reporterId) {
    return crypto.createHash('sha256').update(`${this.salt}|${reporterId}`).digest('hex').slice(0, 32);
  }

  ver(version) {
    let s = this.v.get(version);
    if (!s) { s = { active: new Map(), crashed: new Map(), crashes: [], errors: [] }; this.v.set(version, s); }
    return s;
  }

  seen(version, id, at) {
    const s = this.ver(version);
    if ((s.active.get(id) ?? 0) < at) s.active.set(id, at);
  }

  load() {
    for (const f of this.list(path.join(this.dir, 'heartbeats'))) for (const h of readLines(f)) if (h.v && h.id) this.seen(h.v, h.id, Date.parse(h.at));
    const rdir = path.join(this.dir, 'reports');
    if (fs.existsSync(rdir)) {
      for (const v of fs.readdirSync(rdir)) {
        if (!VERSION_DIR_RE.test(v)) continue;
        for (const d of fs.readdirSync(path.join(rdir, v))) {
          for (const f of this.list(path.join(rdir, v, d))) {
            try { this.count(JSON.parse(fs.readFileSync(f, 'utf8'))); } catch { /* 壊れたファイルは数えない */ }
          }
        }
      }
    }
    for (const f of this.list(path.join(this.dir, 'refused'))) for (const r of readLines(f)) this.refusedCounts[r.kind] = (this.refusedCounts[r.kind] || 0) + 1;
    for (const a of readLines(path.join(this.dir, 'alerts.jsonl'))) this.alerted.add(a.version);
  }

  list(dir) {
    if (!fs.existsSync(dir)) return [];
    return fs.readdirSync(dir).filter((f) => f.endsWith('.json') || f.endsWith('.jsonl')).map((f) => path.join(dir, f));
  }

  count(rec) {
    const at = Date.parse(rec.receivedAt);
    this.seen(rec.appVersion, rec.id, at);
    const s = this.ver(rec.appVersion);
    for (const r of rec.reports) {
      if (r.kind === 'crash') {
        s.crashes.push({ at, n: r.count });
        if ((s.crashed.get(rec.id) ?? 0) < at) s.crashed.set(rec.id, at);
      } else {
        s.errors.push({ at, n: r.count });
      }
    }
  }

  /** 起動の知らせを記録する。 */
  heartbeat({ reporterId, appVersion, os }) {
    const at = this.now();
    const id = this.pseudo(reporterId);
    appendLine(path.join(this.dir, 'heartbeats', `${day(at)}.jsonl`), { at: new Date(at).toISOString(), v: appVersion, os, id });
    this.seen(appVersion, id, at);
    return this.evaluate(appVersion);
  }

  /** 関門を通った報告を保存する。 */
  saveReports({ reporterId, appVersion, os, reports }) {
    const at = this.now();
    const rec = { receivedAt: new Date(at).toISOString(), id: this.pseudo(reporterId), appVersion, os, reports };
    const file = path.join(this.dir, 'reports', appVersion, day(at), `${at}-${crypto.randomBytes(4).toString('hex')}.json`);
    writeAtomic(file, JSON.stringify(rec, null, 1) + '\n');
    this.count(rec);
    return { file, alert: this.evaluate(appVersion) };
  }

  /** 断った記録（中身は書かない）。 */
  refused({ field, kind, appVersion }) {
    const at = this.now();
    appendLine(path.join(this.dir, 'refused', `${day(at)}.jsonl`), { at: new Date(at).toISOString(), v: appVersion ?? null, field, kind });
    this.refusedCounts[kind] = (this.refusedCounts[kind] || 0) + 1;
  }

  /** 1 つの版の数字。 */
  stats(version) {
    const s = this.v.get(version);
    const cutoff = this.now() - this.th.windowHours * 3600 * 1000;
    if (!s) return { version, activeInstalls: 0, crashInstalls: 0, crashReports: 0, errorReports: 0, crashRate: null, status: 'no_data' };
    const activeInstalls = [...s.active.values()].filter((t) => t >= cutoff).length;
    const crashInstalls = [...s.crashed.values()].filter((t) => t >= cutoff).length;
    const crashReports = s.crashes.filter((c) => c.at >= cutoff).reduce((a, c) => a + c.n, 0);
    const errorReports = s.errors.filter((c) => c.at >= cutoff).reduce((a, c) => a + c.n, 0);
    const crashRate = activeInstalls > 0 ? crashInstalls / activeInstalls : null;
    let status = 'ok';
    if (activeInstalls < this.th.minActiveInstalls) status = crashInstalls >= this.th.minCrashInstalls ? 'watch' : 'too_few';
    else if (crashInstalls >= this.th.minCrashInstalls && crashRate > this.th.maxCrashRate) status = 'over';
    return { version, activeInstalls, crashInstalls, crashReports, errorReports, crashRate, status };
  }

  allStats() {
    return [...this.v.keys()].map((v) => this.stats(v));
  }

  /** 基準を超えたら 1 度だけ知らせる（alerts.jsonl と画面とサーバーの表示）。 */
  evaluate(version) {
    const st = this.stats(version);
    if (st.status !== 'over' || this.alerted.has(version)) return null;
    this.alerted.add(version);
    const alert = { at: new Date(this.now()).toISOString(), version, crashRate: st.crashRate, crashInstalls: st.crashInstalls, activeInstalls: st.activeInstalls, threshold: this.th.maxCrashRate };
    appendLine(path.join(this.dir, 'alerts.jsonl'), alert);
    this.log(`[警告] 版 ${version} の落ちる割合が基準を超えました: ${(st.crashRate * 100).toFixed(1)}%（${st.crashInstalls}/${st.activeInstalls} 台）> ${(this.th.maxCrashRate * 100).toFixed(1)}%。管理画面で「配信を止める（0%）」を検討してください。`);
    return alert;
  }

  alerts() {
    return readLines(path.join(this.dir, 'alerts.jsonl'));
  }
}
