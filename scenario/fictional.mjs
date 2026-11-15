// 架空のデータを実行のたびに乱数で作る（実在の番号をファイルに書かないため）。試験とサンプルの台本で使う。
import crypto from 'node:crypto';

const digit = () => crypto.randomInt(0, 10);
export const randDigits = (n) => Array.from({ length: n }, digit).join('');

/** 検査用数字が合う 12 桁（マイナンバーの形。実在するかは関係ない架空の値）。 */
export function fakeMyNumber() {
  const d = randDigits(11);
  let sum = 0;
  for (let n = 1; n <= 11; n++) sum += Number(d[11 - n]) * (n <= 6 ? n + 1 : n - 5);
  const r = sum % 11;
  return d + String(r <= 1 ? 0 : 11 - r);
}

/** Luhn が合う 16 桁（Visa の形の架空の値）。 */
export function fakeCard() {
  const body = '4' + randDigits(14);
  let s = 0;
  for (let i = 0; i < 15; i++) {
    let x = Number(body[14 - i]);
    if (i % 2 === 0) { x *= 2; if (x > 9) x -= 9; }
    s += x;
  }
  return body + String((10 - (s % 10)) % 10);
}

export const fakeMobile = () => `090-${randDigits(4)}-${randDigits(4)}`;
export const fakeInstallId = () => crypto.randomBytes(16).toString('hex');
/** 端末が送る報告者の番号（installId そのものは送らない）。 */
export const reporterIdFor = (installId) => crypto.createHash('sha256').update(`haishin-report|${installId}`).digest('hex');
/** 鍵らしい文字列（形だけ。どこにも使えない乱数）。 */
export const fakeApiKey = () => `sk-ant-${crypto.randomBytes(18).toString('base64url')}`;
