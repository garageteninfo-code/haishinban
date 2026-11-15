using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;

namespace UpdateSafetyKit;

/// <summary>
/// Version comparison: dot-separated numbers (any count), optional SemVer pre-release ("-beta.2") and ignored build metadata
/// ("+abc"). 1.0 == 1.0.0, 1.9 &lt; 1.10, 1.0.0-beta &lt; 1.0.0. A version that cannot be parsed is never "newer" (fail-safe).
/// <para>版の比較。ドット区切りの数（桁数自由）＋任意の pre-release（-beta.2）＋無視する build（+abc）。
/// 読めない版は「新しい」と見ない（安全側）。</para>
/// </summary>
public static class VersionCompare
{
    private static readonly Regex Re = new(@"^(\d{1,9}(?:\.\d{1,9})*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$", RegexOptions.CultureInvariant);

    /// <summary>A parsed version. <para>読み取った版。</para></summary>
    public readonly record struct Parsed(int[] Core, string[] Pre);

    /// <summary>Parses after trimming ASCII spaces/tabs. Returns false for anything else (letters in the core, overflow, empty).
    /// <para>前後の ASCII 空白を除いて読む。それ以外（数の部分の文字・桁あふれ・空）は false。</para></summary>
    public static bool TryParse(string? text, out Parsed v)
    {
        v = default;
        var t = Canon.TrimAscii(text);
        var m = Re.Match(t);
        if (!m.Success) return false;
        var parts = m.Groups[1].Value.Split('.');
        var core = new int[parts.Length];
        for (var i = 0; i < parts.Length; i++) core[i] = int.Parse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture);
        var pre = m.Groups[2].Success ? m.Groups[2].Value.Split('.') : Array.Empty<string>();
        v = new Parsed(core, pre);
        return true;
    }

    /// <summary>Compares two parsed versions (-1, 0, 1). <para>比較（-1・0・1）。</para></summary>
    public static int Compare(Parsed a, Parsed b)
    {
        var len = Math.Max(a.Core.Length, b.Core.Length);
        for (var i = 0; i < len; i++)
        {
            var x = i < a.Core.Length ? a.Core[i] : 0;
            var y = i < b.Core.Length ? b.Core[i] : 0;
            if (x != y) return x < y ? -1 : 1;
        }
        // SemVer 11: a version without pre-release is higher than one with it.
        if (a.Pre.Length == 0 || b.Pre.Length == 0) return a.Pre.Length == b.Pre.Length ? 0 : (a.Pre.Length == 0 ? 1 : -1);
        var n = Math.Min(a.Pre.Length, b.Pre.Length);
        for (var i = 0; i < n; i++)
        {
            var c = ComparePre(a.Pre[i], b.Pre[i]);
            if (c != 0) return c;
        }
        return a.Pre.Length.CompareTo(b.Pre.Length);
    }

    private static int ComparePre(string a, string b)
    {
        var an = IsDigits(a); var bn = IsDigits(b);
        if (an && bn)
        {
            var x = a.TrimStart('0'); var y = b.TrimStart('0');
            if (x.Length != y.Length) return x.Length < y.Length ? -1 : 1;
            return Math.Sign(string.CompareOrdinal(x, y));
        }
        if (an != bn) return an ? -1 : 1;
        return Math.Sign(string.CompareOrdinal(a, b));
    }

    private static bool IsDigits(string s) { foreach (var c in s) if (c < '0' || c > '9') return false; return s.Length > 0; }

    /// <summary>
    /// True only when both parse and <paramref name="latest"/> is strictly newer than <paramref name="current"/>.
    /// <para>両方読めて、latest が current より新しいときだけ true。</para>
    /// </summary>
    public static bool IsNewer(string? current, string? latest)
        => TryParse(current, out var c) && TryParse(latest, out var l) && Compare(l, c) > 0;

    /// <summary>Same version ("1.0.3" == "1.0.3.0"). Unparseable versions are the same only when byte-identical after trimming.
    /// <para>同じ版か。読めない版は前後の空白を除いて完全一致のときだけ同じ。</para></summary>
    public static bool Same(string? a, string? b)
    {
        var x = Canon.TrimAscii(a); var y = Canon.TrimAscii(b);
        if (x.Length == 0 || y.Length == 0) return false;
        if (string.Equals(x, y, StringComparison.Ordinal)) return true;
        return TryParse(x, out var p) && TryParse(y, out var q) && Compare(p, q) == 0;
    }

    /// <summary>True when <paramref name="version"/> is listed (using <see cref="Same"/>). <para>一覧に載っているか。</para></summary>
    public static bool IsListed(string? version, IEnumerable<string>? list)
    {
        if (list is null) return false;
        foreach (var b in list) if (Same(version, b)) return true;
        return false;
    }
}
