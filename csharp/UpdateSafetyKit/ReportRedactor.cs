using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace UpdateSafetyKit;

/// <summary>
/// Local, simple redaction before a report leaves the PC. It is deliberately small and will miss things (for example
/// addresses, and names written without 様/さん/殿). The relay checks again and refuses (422) what it finds; the reporter then
/// replaces the whole field. Replaced text is never logged.
/// <para>報告を PC の外へ出す前の、簡単な伏せ字。わざと小さくしてあり、見落としがある（住所・敬称の無い氏名など）。
/// 中継がもう一度調べて 422 で断るので、そのときは欄ごと伏せる。伏せた文字は記録しない。</para>
/// What it replaces / 伏せる物:
/// <list type="bullet">
/// <item>private keys, bearer tokens, "password=…" style secrets, well-known API key prefixes, credentials in URLs</item>
/// <item>user folders in paths (C:\Users\&lt;name&gt;, /home/&lt;name&gt;), the current Windows user name and PC name, \\server\ shares</item>
/// <item>e-mail addresses, Japanese phone numbers, card numbers (Luhn), My Number (check digit + context or 4-4-4)</item>
/// <item>Japanese names followed by 様・さん・殿・氏, postal codes, IPv4 addresses (except 127.x)</item>
/// </list>
/// </summary>
public static class ReportRedactor
{
    private const RegexOptions O = RegexOptions.CultureInvariant;
    private static readonly TimeSpan T = TimeSpan.FromMilliseconds(200);

    private static readonly Regex PrivateKey = new(@"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", O, T);
    private static readonly Regex Bearer = new(@"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}", O, T);
    private static readonly Regex Assign = new(@"(?i)(password|passwd|pwd|passcode|secret|api[_-]?key|apikey|access[_-]?token|token|パスワード|暗証番号)(\s{0,4}[:=]\s{0,4}|\s{0,2}(?:は|is)\s{0,3})[""']?[^\s""',;]{3,}", O, T);
    private static readonly Regex KeyPrefix = new(@"\b(?:sk-[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|xox[abprs]-[A-Za-z0-9-]{8,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?)", O, T);
    private static readonly Regex UrlCred = new(@"(//)[^\s/:@]{1,128}:[^\s/@]{1,128}@", O, T);
    private static readonly Regex UrlSecretParam = new(@"(?i)([?&](?:pass|password|passwd|pwd|token|secret|api_?key|key)=)[^&\s#]+", O, T);
    private static readonly Regex WinUserPath = new(@"(?i)([A-Za-z]:(?:\\|/)+Users(?:\\|/)+)((?:[^\\/\r\n""'<>|:*?]{1,64}(?=[\\/]))|[^\\/\s""'<>|:*?]+)", O, T);
    private static readonly Regex UnixUserPath = new(@"((?:^|[\s(""'=:])/(?:home|Users)/)([^/\s""'<>|]+)", O, T);
    private static readonly Regex Unc = new(@"((?:^|[\s(""'=:]))\\\\([^\\\s""'<>|?.][^\\\s""'<>|]*)\\", O, T);
    private static readonly Regex OneDriveOrg = new(@"OneDrive - (?![<\[*%{])[^\\/\r\n]+", O, T);
    private static readonly Regex Email = new(@"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}", O, T);
    private static readonly Regex DigitRun = new(@"(?<![\d-])\d(?:[ -]?\d){11,18}(?![\d-])", O, T);
    private static readonly Regex MyNumberContext = new(@"(?i)(マイナンバー|個人番号|my ?number)[^\n]{0,12}$", O, T);
    private static readonly Regex Phone = new(@"(?<![\d.-])(?:0\d{1,4}[-( ]\d{1,4}[-) ]{1,2}\d{3,4}|0[5789]0\d{8}|\+81[- ]?\d{1,4}[- ]?\d{1,4}[- ]?\d{3,4})(?![\d.-])", O, T);
    private static readonly Regex HonorificName = new(@"(?<![一-龥々ぁ-んァ-ヶー])((?:[一-龥々]{1,3}[ 　][一-龥々]{1,3})|[一-龥々]{1,6}|[ァ-ヶー]{2,10}(?:・[ァ-ヶー]{2,10})?)(様|さん|殿|氏)", O, T);
    private static readonly Regex Postal = new(@"〒\s?\d{3}-?\d{4}|(?<![\d-])\d{3}-\d{4}(?![\d-])", O, T);
    private static readonly Regex Ipv4 = new(@"\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))\b", O, T);
    private static readonly Regex StackFile = new(@" in (?:[A-Za-z]:)?[^:\r\n]*[\\/]([^\\/\r\n:]+):line (\d+)", O, T);

    private static readonly HashSet<string> NonUserDirs = new(StringComparer.OrdinalIgnoreCase) { "public", "default", "default user", "all users", "shared", "<user>" };
    /// <summary>Words that end with 様/さん but are not names (kept to keep reports readable). <para>名前ではない言葉。</para></summary>
    private static readonly HashSet<string> NotNames = new(StringComparer.Ordinal) { "利用者", "使用者", "管理者", "担当者", "お客", "皆", "皆々", "各位", "お疲れ", "ご苦労", "同", "奥", "神", "仏", "王", "殿" };

    /// <summary>Redacts <paramref name="text"/>. Full-width digits, letters and "-@.+:/_\" become ASCII first (other Japanese text is kept as is).
    /// <para>伏せ字にする。先に全角の数字・英字・記号の一部を半角にそろえる（ほかの日本語はそのまま）。</para></summary>
    public static string Redact(string? text) => Redact(text, Environment.UserName, Environment.MachineName);

    /// <summary>Redacts with explicit user / PC names (for tests). <para>利用者名・PC 名を渡して伏せる（試験用）。</para></summary>
    public static string Redact(string? text, string? userName, string? machineName)
    {
        if (string.IsNullOrEmpty(text)) return text ?? "";
        var s = Narrow(text);
        s = Regex.Replace(s, "[\u200B-\u200D\u2060\uFEFF\u00AD]", "");
        s = Regex.Replace(s, @"(?<=\d)[\u2010-\u2015\u2212\u30FC](?=\d)", "-");
        try
        {
            s = PrivateKey.Replace(s, "[伏せ字:private_key]");
            s = UrlCred.Replace(s, "$1[伏せ字]@");
            s = UrlSecretParam.Replace(s, "$1[伏せ字]");
            s = Bearer.Replace(s, "$1 [伏せ字]");
            s = Assign.Replace(s, m => m.Groups[1].Value + m.Groups[2].Value + "[伏せ字]");
            s = KeyPrefix.Replace(s, "[伏せ字:key]");
            s = WinUserPath.Replace(s, m => NonUserDirs.Contains(m.Groups[2].Value) ? m.Value : m.Groups[1].Value + "<user>");
            s = UnixUserPath.Replace(s, m => NonUserDirs.Contains(m.Groups[2].Value) ? m.Value : m.Groups[1].Value + "<user>");
            s = Unc.Replace(s, "$1\\\\<server>\\");
            s = OneDriveOrg.Replace(s, "OneDrive - <org>");
            s = Email.Replace(s, "<email>");
            s = ReplaceLiteral(s, userName, "<user>");
            s = ReplaceLiteral(s, machineName, "<pc>");
            s = DigitRun.Replace(s, m => DigitRunReplacement(s, m));
            s = Phone.Replace(s, "<phone>");
            s = Postal.Replace(s, "<postal>");
            s = HonorificName.Replace(s, m => NotNames.Contains(m.Groups[1].Value.Trim()) ? m.Value : "<name>" + m.Groups[2].Value);
            s = Ipv4.Replace(s, m => m.Groups[1].Value.StartsWith("127.", StringComparison.Ordinal) || m.Groups[1].Value == "0.0.0.0" ? m.Value : "<ip>");
        }
        catch (RegexMatchTimeoutException)
        {
            return "[伏せ字:timeout]";   // 調べきれない文は送らない
        }
        return s;
    }

    /// <summary>Stack trace: keep frames, drop the build machine's folders (" in C:\src\App\Form1.cs:line 42" → " in Form1.cs:line 42"), then <see cref="Redact(string?)"/>.
    /// <para>呼び出し履歴：場所は残し、組み立てた PC のフォルダは消す。</para></summary>
    public static string RedactStack(string? stack, string? userName = null, string? machineName = null)
    {
        if (string.IsNullOrEmpty(stack)) return "";
        var s = StackFile.Replace(stack, " in $1:line $2");
        return Redact(s, userName ?? Environment.UserName, machineName ?? Environment.MachineName);
    }

    /// <summary>The text that replaces a whole field after the relay refused it. <para>中継に断られた欄の代わりの文。</para></summary>
    public static string FieldPlaceholder(string? kind)
    {
        var k = Regex.IsMatch(kind ?? "", "^[a-z_]{1,32}$") ? kind : "unknown";
        return $"[伏せ字:{k}]";
    }

    private static string Narrow(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            if ((c >= '０' && c <= '９') || (c >= 'Ａ' && c <= 'Ｚ') || (c >= 'ａ' && c <= 'ｚ') || "－＠．＋：／＿＼".IndexOf(c) >= 0)
                sb.Append((char)(c - 0xFEE0));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    private static string ReplaceLiteral(string s, string? value, string placeholder)
    {
        var v = (value ?? "").Trim();
        if (v.Length < 2 || NonUserDirs.Contains(v)) return s;
        // 英字だけの短い名前（"dev" など）は、ほかの単語の一部と取り違えないよう単語の切れ目で探す
        var pattern = Regex.IsMatch(v, "^[A-Za-z0-9_.-]+$") ? $@"(?<![A-Za-z0-9_]){Regex.Escape(v)}(?![A-Za-z0-9_])" : Regex.Escape(v);
        return Regex.Replace(s, pattern, placeholder, RegexOptions.IgnoreCase | O, T);
    }

    private static string DigitRunReplacement(string all, Match m)
    {
        var digits = new string(m.Value.Where(char.IsAsciiDigit).ToArray());
        if (digits.Length >= 13 && digits.Length <= 19 && Luhn(digits)) return "<card>";
        if (digits.Length == 12 && MyNumberCheck(digits))
        {
            var separated = Regex.IsMatch(m.Value, @"^\d{4}[ -]\d{4}[ -]\d{4}$");
            var context = MyNumberContext.IsMatch(all.Substring(0, m.Index));
            if (separated || context) return "<my_number>";
        }
        return m.Value;
    }

    /// <summary>Luhn check (card numbers). <para>カード番号の検査。</para></summary>
    public static bool Luhn(string digits)
    {
        int sum = 0;
        for (int i = 0; i < digits.Length; i++)
        {
            int d = digits[digits.Length - 1 - i] - '0';
            if (i % 2 == 1) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
        }
        return sum % 10 == 0;
    }

    /// <summary>My Number check digit (12 digits). <para>マイナンバーの検査用数字。</para></summary>
    public static bool MyNumberCheck(string d)
    {
        if (d.Length != 12 || !d.All(char.IsAsciiDigit)) return false;
        int sum = 0;
        for (int n = 1; n <= 11; n++) sum += (d[11 - n] - '0') * (n <= 6 ? n + 1 : n - 5);
        int r = sum % 11;
        return d[11] - '0' == (r <= 1 ? 0 : 11 - r);
    }
}
