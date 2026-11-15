// 日本の個人情報・鍵の検出と伏せ字（改良版・2026-11-14）
// 元：以前の社内の試作の検出規則（多くはそのまま引き継いだ）。依存なし・AI を使わない。
// 直した所：
//   1. 当てる前に全角→半角などをそろえる（NFKC。1文字ずつそろえて、元の文の位置に戻せるようにする）
//   2. 数字の間の長音「ー」・いろいろなダッシュを「-」とみなす
//   3. マイナンバー：検査数字を確かめる。「マイナンバー・個人番号」の言葉が前にあるか、4-4-4 の区切りの時だけ
//   4. カード：Luhn に加えて、前に「カード」などの言葉があるか、4桁ずつ区切られ発行元の頭の番号に合う時だけ
//   5. 電話：かっこ・空白の区切り、ハイフンなしの固定電話（前に「電話」などの言葉がある時）。桁数（10 / 11桁）を確かめる
//   6. 住所（都道府県・市区町村＋番地）・氏名（欄の名前・様・と申します）・生年月日（欄の名前）を新しく見つける
//   7. 「パスワードは〜」「暗証番号は〜」の形
// 伏せ方：初めは鍵・カード・マイナンバーだけを伏せる。personal: true で電話・メール・住所・氏名・生年月日も伏せる。

// ---------- 1. そろえる（位置の対応つき） ----------
const DASHES = new Set(['-', '‐', '‑', '‒', '–', '—', '―', '−', '－', '﹣']);
export function normalizeWithMap(input) {
  const parts = [];
  let i = 0;
  for (const ch of input) {
    let n = ch.normalize('NFKC');
    if (DASHES.has(ch) || DASHES.has(n)) n = '-';
    parts.push({ t: n, start: i, end: i + ch.length });
    i += ch.length;
  }
  // 数字に挟まれた長音（ー・ｰ）は区切りの「-」
  for (let k = 0; k < parts.length; k++) {
    if (parts[k].t === 'ー' || parts[k].t === 'ｰ') {
      const prev = parts[k - 1]?.t ?? '';
      const next = parts[k + 1]?.t ?? '';
      if (/\d$/.test(prev) && /^\d/.test(next)) parts[k].t = '-';
    }
  }
  // 字の間の空白（手書きの OCR・字間あき）を詰める：漢字かなどうし・漢字かなと数字・数字と「-」の間だけ
  const CJK = /[一-龥々ぁ-んァ-ヶー]/, DIG = /\d/;
  const join = (a, b) => (CJK.test(a) && CJK.test(b)) || (CJK.test(a) && DIG.test(b)) || (DIG.test(a) && CJK.test(b)) || (a === '-' && DIG.test(b)) || (DIG.test(a) && b === '-');
  // 「福 岡 県」のように 1 字ずつ空いている所だけ（ふつうの「山田 太郎」の空白は残す）
  const isSp = (x) => parts[x]?.t === ' ';
  const drop = [];
  for (let k = 1; k < parts.length - 1; k++) {
    if (!isSp(k)) continue;
    const pa = parts[k - 1].t, pb = parts[k + 1].t;
    if (pa.length !== 1 || pb.length !== 1 || !join(pa, pb)) continue;
    if (isSp(k - 2) || isSp(k + 2)) drop.push(k);
  }
  for (const k of drop) parts[k].t = '';
  let text = '';
  const map = []; // 正規化後の 1 文字ごと → 元の [start, end)
  for (const p of parts) {
    for (let j = 0; j < p.t.length; j++) map.push(p);
    text += p.t;
  }
  return { text, map };
}

// ---------- 検査 ----------
function luhn(num) {
  const d = num.replace(/\D/g, '');
  if (d.length < 13 || d.length > 19) return false;
  let s = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) { let x = d.charCodeAt(i) - 48; if (alt) { x *= 2; if (x > 9) x -= 9; } s += x; alt = !alt; }
  return s % 10 === 0;
}
export function myNumberValid(num) {
  const d = num.replace(/\D/g, '');
  if (d.length !== 12) return false;
  let sum = 0;
  for (let n = 1; n <= 11; n++) { const p = d.charCodeAt(11 - n) - 48; sum += p * (n <= 6 ? n + 1 : n - 5); }
  const r = sum % 11;
  return (r <= 1 ? 0 : 11 - r) === d.charCodeAt(11) - 48;
}
function cardIssuerOk(d) {
  const n = d.length;
  if (/^4/.test(d)) return n === 13 || n === 16 || n === 19;           // Visa
  if (/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/.test(d)) return n === 16; // Mastercard
  if (/^3[47]/.test(d)) return n === 15;                               // Amex
  if (/^35(2[89]|[3-8]\d)/.test(d)) return n >= 16 && n <= 19;         // JCB
  if (/^3(0[0-5]|[689])/.test(d)) return n >= 14 && n <= 19;           // Diners
  if (/^6(011|5)/.test(d)) return n >= 16 && n <= 19;                  // Discover
  return false;
}
function phoneDigitsOk(raw) {
  let d = raw.replace(/\D/g, '');
  if (raw.trim().startsWith('+')) { if (!d.startsWith('81')) return d.length >= 8 && d.length <= 15; d = '0' + d.slice(2); }
  if (!d.startsWith('0')) return false;
  if (/^0[5789]0/.test(d)) return d.length === 11;
  if (/^0(120|800)/.test(d)) return d.length === 10 || d.length === 11;
  return d.length === 10;
}

// ---------- 前の言葉（文脈） ----------
const before = (text, idx, n = 24) => text.slice(Math.max(0, idx - n), idx);
const CTX = {
  card: /(カード|クレジット|card|visa|master|amex|jcb|diners|discover|決済|ビザ|マスター|アメックス|アメリカン・?エキスプレス|ダイナース|ジェーシービー|ディスカバー)/i,
  myNumber: /(マイナンバー|個人番号|my[ _]?number|kojin ?bango)/i,
  phone: /(電話|でんわ|tel|携帯|fax|連絡先|番号は)/i,
};

// ---------- 規則 ----------
const PREF = '(?:北海道|東京都|京都府|大阪府|(?:青森|岩手|宮城|秋田|山形|福島|茨城|栃木|群馬|埼玉|千葉|神奈川|新潟|富山|石川|福井|山梨|長野|岐阜|静岡|愛知|三重|滋賀|兵庫|奈良|和歌山|鳥取|島根|岡山|広島|山口|徳島|香川|愛媛|高知|福岡|佐賀|長崎|熊本|大分|宮崎|鹿児島|沖縄)県)';
const PREF_RE = new RegExp(PREF);
const MUNI = '(?:[一-龥ぁ-んァ-ヶー]{1,6}?[市区町村郡]){1,3}';
const STREET = '[一-龥ぁ-んァ-ヶー]{0,10}?';
const KN = '[一二三四五六七八九十〇]';
const NUM = `(?:\\d{1,4}(?:丁目|番地|番|号|-)(?:\\d{1,4}(?:丁目|番地|番|号|-)?){0,3}|${KN}{1,3}丁目(?:(?:${KN}{1,4}|\\d{1,4})(?:番地|番|号)){0,2})`;
const NAME = '[一-龥々]{1,4}(?:[ ]?[一-龥々ぁ-ん]{1,4})?';
const NAME_STOP = new Set(['担当', '担当者', '皆', '各位', 'お客', '客', '管理者', '管理人', '店長', '社長', '大家', '家主', '御中', '貴社', '弊社', '者', '業者', '大工', '職人', '店員', '運転手', '皆様', '奥', '旦那', '息子', '娘', '先方', '相手', '近所', '管理会社', '医者', '患者', '生徒', '社員', '先生', '欄']);
// よくある名字（公開されている名字の順位の上位から。名字を手がかりに、欄の名前が無い所でも氏名を拾う）
const SURNAMES = ('佐藤 鈴木 高橋 田中 伊藤 渡辺 山本 中村 小林 加藤 吉田 山田 佐々木 山口 松本 井上 木村 林 斎藤 清水 山崎 森 池田 橋本 阿部 石川 山下 中島 石井 小川 前田 岡田 長谷川 藤田 後藤 近藤 村上 遠藤 青木 坂本 斉藤 福田 太田 西村 藤井 金子 岡本 藤原 中野 三浦 原田 中川 松田 竹内 小野 田村 中山 和田 石田 森田 上田 原 内田 柴田 酒井 宮崎 横山 高木 安藤 宮本 大野 小島 谷口 今井 工藤 高田 増田 丸山 杉山 村田 大塚 新井 小山 平野 藤本 河野 上野 野口 武田 松井 千葉 岩崎 菅原 木下 久保 佐野 野村 松尾 市川 菊地 杉本 古川 大西 島田 水野 桜井 高野 渡部 吉川 山内 西田 飯田 菊池 西川 小松 北村 安田 五十嵐 川口 平田 関 中田 久保田 服部 東 岩田 土屋 川崎 福島 本田 辻 樋口 秋山 田口 永井 山中 中西 吉村 川上 石原 大橋 馬場 浅野 荒木 大久保 野田 小沢 田辺 川村 星野 黒田 堀 尾崎 望月 永田 熊谷 内藤 松村 西山 大谷 平井 大島 岩本 片山 本間 早川 横田 岡崎 荒井 大石 鎌田 成田 宮田 小田 石橋 篠原 須藤 河合 大川 高井 岡部 川端 高梨 松下 北川 吉岡 小池 山根 宮下 坂井 小西 足立 浜田 上原 西 桑原 堤 宇野 植田 田島 飯塚 竹田 津田 奥村 内山 大森 稲葉 水谷').split(' ').sort((a, b) => b.length - a.length).join('|');
const GIVEN = '[一-龥々ぁ-んァ-ヶ]{1,4}';
const GIVEN_BAD = /[区市町村郡駅店社署局館院課部線通方面側口前様]/;

// kind, category, level（AI に送る前に伏せるか）, 正規表現, 確かめ（任意）, 伏せる部分の名前付きの組（任意）
export const RULES = [
  { kind: 'private_key', cat: 'credential', redact: 'always', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { kind: 'api_key', cat: 'credential', redact: 'always', re: /\bsk-ant-[A-Za-z0-9_-]{10,}\b/g },
  { kind: 'api_key', cat: 'credential', redact: 'always', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b/g },
  { kind: 'api_key', cat: 'credential', redact: 'always', re: /\bAIza[0-9A-Za-z_-]{20,}\b/g },
  { kind: 'api_key', cat: 'credential', redact: 'always', re: /\bgsk_[A-Za-z0-9]{20,}\b/g },
  { kind: 'github_token', cat: 'credential', redact: 'always', re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g },
  { kind: 'slack_token', cat: 'credential', redact: 'always', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { kind: 'aws_key', cat: 'credential', redact: 'always', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { kind: 'payment_secret', cat: 'credential', redact: 'always', re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { kind: 'jwt', cat: 'credential', redact: 'always', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?/g },
  { kind: 'bearer', cat: 'credential', redact: 'always', re: /\bbearer\s+(?<v>[A-Za-z0-9._~+/=-]{16,})/gi },
  { kind: 'url_password', cat: 'credential', redact: 'always', re: /\/\/[^\s/:@]{1,128}:(?<v>[^\s/@]{1,128})@/g },
  { kind: 'credential_assign', cat: 'credential', redact: 'always', re: /(?:password|passwd|pwd|secret|api[_-]?key|パスワード|暗証番号)\s{0,4}[:=]\s{0,4}["']?(?<v>(?=[^\s"']{0,400}\d)[^\s"']{6,400})/gi },
  { kind: 'credential_phrase', cat: 'credential', redact: 'always', re: /(?:パスワード|暗証番号|password|passcode|pin)\s{0,2}(?:は|is)\s{0,3}["']?(?<v>[!-~]{4,64})/gi,
    check: (m) => /\d/.test(m.groups.v) || m.groups.v.length >= 8 },
  // 環境変数の形（大文字の名前に KEY・SECRET・TOKEN・PASSWORD などが入る）
  { kind: 'credential_assign', cat: 'credential', redact: 'always', re: /\b[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD)(?:_[A-Z0-9]+)*\s{0,2}[:=]\s{0,2}["']?(?<v>[^\s"']{8,400})/g },
  // 「PW: 〜」「Pass: 〜」「パス：〜」
  { kind: 'credential_assign', cat: 'credential', redact: 'always', re: /(?:\bPW|\bPass|\bPASS|パス(?!ワード))\s{0,2}[:=]\s{0,2}["']?(?<v>[^\s"']{6,64})/g },
  // URL の問い合わせの部分の pass= など
  { kind: 'url_password', cat: 'credential', redact: 'always', re: /[?&](?:pass|password|passwd|pwd|token|secret|api_?key|key)=(?<v>[^&\s#]{4,})/gi },
  { kind: 'credit_card', cat: 'personal', redact: 'always', re: /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,
    check: (m, text) => {
      const d = m[0].replace(/\D/g, '');
      if (!luhn(d)) return false;
      if (CTX.card.test(before(text, m.index))) return true;
      return /^\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}$/.test(m[0]) && cardIssuerOk(d);
    } },
  { kind: 'my_number', cat: 'personal', redact: 'always', re: /(?<![\d-])\d{4}[ -]{0,2}\d{4}[ -]{0,2}\d{4}(?![\d-])/g,
    check: (m, text, o) => myNumberValid(m[0]) && (o.aggressive || CTX.myNumber.test(before(text, m.index)) || /^\d{4}([ -]{1,2})\d{4}\1\d{4}$/.test(m[0])) },
  { kind: 'email', cat: 'personal', redact: 'personal', re: /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}/g,
    check: (m) => !/(?:^|\.)(?:example\.(?:com|net|org)|example|test|invalid|localhost)$/i.test(m[0].split('@')[1] || '') },
  { kind: 'phone', cat: 'personal', redact: 'personal', re: /(?<![\d.-])0\d{1,4}(?:-|\(| |\.)\d{1,4}(?:-|\)|\) ?| |\.)\d{3,4}(?![\d.-])/g, check: (m) => phoneDigitsOk(m[0]) },
  { kind: 'phone', cat: 'personal', redact: 'personal', re: /\(0\d{1,4}\) ?\d{1,4}-\d{3,4}(?![\d-])/g, check: (m) => phoneDigitsOk(m[0]) },
  { kind: 'phone', cat: 'personal', redact: 'personal', re: /(?<!\d)0[5789]0\d{8}(?!\d)/g },
  { kind: 'phone', cat: 'personal', redact: 'personal', re: /(?<!\d)0\d{9}(?!\d)/g, check: (m, text) => CTX.phone.test(before(text, m.index, 12)) },
  { kind: 'phone', cat: 'personal', redact: 'personal', re: /(?<![\w+])\+\d{1,3}[- ]?\d{1,4}[- ]?\d{2,4}[- ]?\d{3,4}(?!\d)/g, check: (m) => phoneDigitsOk(m[0]) },
  { kind: 'address', cat: 'personal', redact: 'personal', re: new RegExp(`${PREF}?${MUNI}${STREET}${NUM}`, 'g') },
  // 郡・大字・字
  { kind: 'address', cat: 'personal', redact: 'personal', re: new RegExp(`${PREF}?${MUNI}(?:大?字[一-龥ぁ-んァ-ヶー]{1,8}){1,2}\\d{1,5}`, 'g') },
  // 京都の通り名（上ル・下ル・東入・西入）
  { kind: 'address', cat: 'personal', redact: 'personal', re: new RegExp(`${PREF}?${MUNI}[一-龥ぁ-んァ-ヶー]{0,20}?(?:上ル|下ル|上る|下る|東入ル?|西入ル?)[一-龥ぁ-んァ-ヶー]{0,10}\\d{1,4}`, 'g') },
  // 欄の名前のあとの氏名（「欄の名前：」か「欄の名前 」の形。「お名前の欄は」は当てない）
  { kind: 'name', cat: 'personal', redact: 'personal', re: new RegExp(`(?:氏名|お名前|名前|申込者|申込人|契約者|入居者|予約者|依頼者|来店者|宛名|ご依頼主|保護者|患者名|受取人|応募者|生徒名|利用者)(?:様)?(?:\\s{0,2}:\\s{0,2}| {0,2})(?!者|様|殿|各位|欄|は|を|氏名|名前|カナ)(?<v>${NAME})`, 'g'),
    check: (m) => !NAME_STOP.has(m.groups.v.replace(/ /g, '')) },
  { kind: 'name', cat: 'personal', redact: 'personal', re: new RegExp(`担当(?:者)?の?(?!者|様|殿|各位)(?<v>${NAME})(?=と申します|です|より|から|が|、|。|$)`, 'g'),
    check: (m) => !NAME_STOP.has(m.groups.v.replace(/ /g, '')) },
  // ふりがなの欄・ローマ字の欄
  { kind: 'name', cat: 'personal', redact: 'personal', re: /(?:フリガナ|ふりがな|カナ|氏名カナ)\s{0,2}:\s{0,2}(?<v>[ァ-ヶーぁ-ん ]{2,20})/g },
  { kind: 'name', cat: 'personal', redact: 'personal', re: /(?:氏名|お名前|名前|申込者|契約者|予約者|応募者|利用者)\s{0,2}:\s{0,2}(?<v>[ァ-ヶー]{2,}(?:・[ァ-ヶー]{2,}){0,3})/g },
  { kind: 'name', cat: 'personal', redact: 'personal', re: /\b(?:[A-Za-z]+ )?[Nn]ame\s{0,2}:\s{0,2}(?<v>[A-Z][A-Za-z]+ [A-Z][A-Za-z]+)/g },
  // JSON の値
  { kind: 'name', cat: 'personal', redact: 'personal', re: /"(?:name|full_?name|customer_?name|user_?name)"\s{0,2}:\s{0,2}"(?<v>[^"]{2,40})"/gi },
  { kind: 'credential_assign', cat: 'credential', redact: 'always', re: /"(?:password|passwd|pwd|pin|secret|token|api_?key|access_?token)"\s{0,2}:\s{0,2}"(?<v>[^"]{3,400})"/gi },
  // 小文字の設定の名前（aws_access_key_id = 〜 など）
  { kind: 'credential_assign', cat: 'credential', redact: 'always', re: /\b[a-z][a-z0-9_]*(?:_key|_secret|_token|password|passwd)(?:_[a-z0-9]+)*\s{0,2}[:=]\s{0,2}["']?(?<v>[^\s"']{12,400})/g },
  { kind: 'credential_assign', cat: 'credential', redact: 'always', re: /\bPIN(?:コード)?\s{0,2}:?\s{0,2}(?<v>\d{4,8})(?!\d)/g },
  // 担当の〇〇さん（かなの名も）
  { kind: 'name', cat: 'personal', redact: 'personal', re: /(?<=担当の)(?<v>[ぁ-んァ-ヶ一-龥々]{1,6})さん/g, check: (m) => !NAME_STOP.has(m.groups.v) },
  // 区切りの線のあとの署名の行（名字の一覧に無い名前も）
  { kind: 'name', cat: 'personal', redact: 'personal', re: /(?:^|\n)[-―ー=_*]{2,}\n(?:[^\n]*\n){0,2}?(?<v>[一-龥々]{1,4} ?[一-龥々ぁ-ん]{1,4})(?=\n|$)/g,
    check: (m) => !GIVEN_BAD.test(m.groups.v.slice(-1)) && !/(株式|有限|合同|会社|事務所)/.test(m.groups.v) },
  // よくある名字＋名で、です・と申します・様・さん・（ふりがな）・行の終わりが続く
  { kind: 'name', cat: 'personal', redact: 'personal', re: new RegExp(`(?<![一-龥々])(?<v>(?:${SURNAMES}) ?(?:${GIVEN})?)(?=です|と申します|様|さん|殿|[（(]|\\n|$)`, 'gm'),
    check: (m) => { const g = m.groups.v.replace(/^(?:\S+?) ?/, ''); return !GIVEN_BAD.test(m.groups.v.slice(-1)); } },
  // 中黒の外国の名前
  { kind: 'name', cat: 'personal', redact: 'personal', re: /(?<v>[ァ-ヶー]{2,}(?:・[ァ-ヶー]{2,}){1,3})(?=と申します|です|様|さん|[（(])/g },
  { kind: 'name', cat: 'personal', redact: 'personal', re: new RegExp(`(?<![一-龥々])(?<v>${NAME})(?:様|さん|殿)(?=[、。,!！ \\n]|から|に|へ|が|は|と|の|より|も|$)`, 'g'),
    check: (m) => !NAME_STOP.has(m.groups.v.replace(/ /g, '')) && !/^ご/.test(m.groups.v) },
  { kind: 'name', cat: 'personal', redact: 'personal', re: new RegExp(`(?<=^|[、。 :のは])(?<v>${NAME})と申します`, 'g'),
    check: (m) => !NAME_STOP.has(m.groups.v.replace(/ /g, '')) },
  { kind: 'birth', cat: 'personal', redact: 'personal', re: /(?:生年月日|誕生日|生まれ|DOB|Date of birth|Birthday|birth date)(?:は)?\s{0,2}:?\s{0,2}(?<v>(?:\d{4}|(?:明治|大正|昭和|平成|令和|[MTSHR])(?:\d{1,2}|元))(?:年|[/.-])\d{1,2}(?:月|[/.-])\d{1,2}日?)/gi },
  { kind: 'birth', cat: 'personal', redact: 'personal', re: /(?<v>(?:[MTSHR]\d{1,2}|\d{4})[./-]\d{1,2}[./-]\d{1,2})(?=生まれ)/g },
  { kind: 'birth', cat: 'personal', redact: 'personal', re: /(?:DOB|Date of birth|Birthday|birth date)\s{0,2}:?\s{0,2}(?<v>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? \d{1,2},? \d{4})/gi },
  // 日付のあとに「生まれ」
  { kind: 'birth', cat: 'personal', redact: 'personal', re: /(?<v>(?:\d{4}|(?:明治|大正|昭和|平成|令和)(?:\d{1,2}|元))年\d{1,2}月\d{1,2}日)(?=生まれ)/g },
];

// ---------- 見つける ----------
export function findAll(input, o = {}) {
  const { text, map } = normalizeWithMap(String(input ?? ''));
  const hits = [];
  for (const r of RULES) {
    for (const m of text.matchAll(r.re)) {
      if (r.check && !r.check(m, text, o)) continue;
      let a = m.index, b = m.index + m[0].length;
      if (m.groups?.v != null && m.indices === undefined) {
        const off = m[0].lastIndexOf(m.groups.v);
        a = m.index + off; b = a + m.groups.v.length;
      }
      // 住所の頭に付いた「は・の・を…」などは外し、都道府県があればそこから始める
      if (r.kind === 'address') {
        const seg = text.slice(a, b);
        const pref = seg.search(PREF_RE);
        if (pref > 0) a += pref;
        else { const lead = seg.match(/^[はのをにへでがともや]+/); if (lead) a += lead[0].length; }
      }
      if (a >= b) continue;
      hits.push({ kind: r.kind, cat: r.cat, redact: r.redact, start: map[a].start, end: map[b - 1].end });
    }
  }
  return hits;
}

export function classify(input, o = {}) {
  const kinds = {};
  for (const h of findAll(input, o)) kinds[h.kind] = (kinds[h.kind] || 0) + 1;
  return { kinds, found: Object.keys(kinds) };
}

/** AI へ送る前に伏せる。o.personal で個人情報（電話・メール・住所・氏名・生年月日）も伏せる。o.aggressive でマイナンバーを言葉なしでも伏せる。 */
export function redact(input, o = {}) {
  const s = String(input ?? '');
  const hits = findAll(s, o).filter((h) => h.redact === 'always' || (o.personal && h.redact === 'personal'));
  // 重なりは長い方・先の方を残す
  hits.sort((x, y) => x.start - y.start || (y.end - y.start) - (x.end - x.start));
  const keep = [];
  for (const h of hits) { const last = keep[keep.length - 1]; if (last && h.start < last.end) continue; keep.push(h); }
  let out = '', pos = 0;
  for (const h of keep) { out += s.slice(pos, h.start) + `[伏せ字:${h.kind}]`; pos = h.end; }
  out += s.slice(pos);
  return { text: out, count: keep.length, kinds: [...new Set(keep.map((h) => h.kind))] };
}
