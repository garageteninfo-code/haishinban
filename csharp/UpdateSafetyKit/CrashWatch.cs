using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UpdateSafetyKit;

/// <summary>
/// Keep the previous version and roll back automatically when the new one keeps crashing (pure logic, no IO).
/// <list type="number">
/// <item>Apply (<see cref="BeginApply"/> → Applying): record the digest of the app folder, then the apply script copies it to
/// "&lt;app folder&gt;&lt;PrevSuffix&gt;" next to it, overwrites the app folder with the new version and starts it.</item>
/// <item>First start of the new version (Applying → Watching).</item>
/// <item>Later starts (Watching): an abnormal exit of the previous run that lasted less than CrashWindow is counted;
/// CrashLimit in a row → rollback. One healthy run (clean exit or longer than CrashWindow) ends watching (Stable).
/// A run whose duration is unknown is neither counted nor treated as healthy.</item>
/// <item>Revoked by the publisher (<see cref="OnBadVersions"/>): roll back while Watching or Stable.</item>
/// <item>Rollback (<see cref="BeginRollback"/>): only when the backup still matches the recorded digest (<see cref="CanRollback"/>).</item>
/// <item>Start after rollback (RollingBack → Idle): notify once; the rolled-back version is not taken again automatically.</item>
/// </list>
/// <para>前の版を残し、新しい版が落ち続けたら自動で戻す（純ロジック・IO なし）。適用 → 1 回目の起動で見張り開始 →
/// CrashWindow 未満の異常終了が CrashLimit 回続いたら戻す。健全な 1 回で見張り終了。長さが分からない回は数えず健全とも見ない。
/// 配布元の不具合版の指定でも戻す。戻す前に控えの中身が記録と一致するか確かめる。</para>
/// </summary>
public static class CrashWatch
{
    /// <summary>Phases of the update state. <para>状態。</para></summary>
    public enum Phase { Idle, Applying, Watching, Stable, RollingBack }

    /// <summary>Why a rollback happened.</summary>
    public enum Why { None, Crashes, BadVersion }

    /// <summary>One-time notices for the next start.</summary>
    public enum Notice { None, RolledBack, RollbackFailed, ApplyFailed }

    /// <summary>What the caller must do now.</summary>
    public enum Action { None, Rollback }

    /// <summary>Persisted update state (one key per line; see <see cref="Serialize"/>). <para>保存する状態。</para></summary>
    public sealed class State
    {
        /// <summary>Current phase.</summary>
        public Phase Phase = Phase.Idle;
        /// <summary>Version before the update (= the version in the backup).</summary>
        public string From = "";
        /// <summary>Version after the update.</summary>
        public string To = "";
        /// <summary>Digest of the backup contents. Empty = no usable backup.</summary>
        public string PrevDigest = "";
        /// <summary>Early crashes counted so far.</summary>
        public int Crashes;
        /// <summary>Why the last rollback happened.</summary>
        public Why Reason = Why.None;
        /// <summary>Versions this device rolled back (never taken again automatically).</summary>
        public List<string> RolledBack = new();
        /// <summary>Notice to show once on the next start.</summary>
        public Notice Pending = Notice.None;
        /// <summary>Versions for the notice text.</summary>
        public string NoticeFrom = "", NoticeTo = "";
        /// <summary>The app folder that created this record (records of other folders are left alone).</summary>
        public string AppDir = "";
        /// <summary>Highest release sequence number accepted on this device (replay protection, see <see cref="Freshness"/>).</summary>
        public long LastSeq;
    }

    /// <summary>Result of a transition.</summary>
    public sealed record Result(State Next, Action Action);

    /// <summary>What is known about the previous run. RanFor null = unknown (e.g. the clock jumped).
    /// <para>前回の実行について分かっていること。RanFor が null なら長さ不明。</para></summary>
    public readonly record struct LastRun(bool Abnormal, TimeSpan? RanFor)
    {
        /// <summary>The previous run ended normally (or there was none).</summary>
        public static LastRun Clean => new(false, null);
    }

    /// <summary>Backup folder next to the app folder: "...\Programs\MyApp" → "...\Programs\MyApp.prev". The separator of the input is kept.
    /// <para>控えの置き場（実行フォルダの隣）。区切りは渡された物をそのまま使う。</para></summary>
    public static string PrevDirFor(UpdateSafetyOptions o, string appDir)
    {
        var a = (appDir ?? "").TrimEnd('\\', '/');
        if (a.Length == 0) throw new ArgumentException("appDir is required");
        var i = Math.Max(a.LastIndexOf('\\'), a.LastIndexOf('/'));
        var parent = i > 0 ? a.Substring(0, i) : "";
        var name = i >= 0 ? a.Substring(i + 1) : "";
        if (parent.Length == 0 || name.Length == 0)
            throw new ArgumentException("appDir must not be a drive root");
        return parent + a[i] + name + o.PrevSuffix;
    }

    private static string NormRel(string rel) => (rel ?? "").Replace('/', '\\').Trim('\\');

    /// <summary>True when a path relative to the app folder is (inside) one of <see cref="UpdateSafetyOptions.MutableDirs"/>.
    /// <para>利用者データのフォルダ（の中）か。</para></summary>
    public static bool IsExcluded(UpdateSafetyOptions o, string relPath)
    {
        var r = NormRel(relPath);
        foreach (var raw in o.MutableDirs)
        {
            var d = NormRel(raw);
            if (r.Equals(d, StringComparison.OrdinalIgnoreCase) || r.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>
    /// Digest of a folder: sha256 over sorted (relative path, file sha256) rows, paths case-insensitive, user-data folders excluded.
    /// <para>フォルダの中身の要約。1 ファイルでも名前・中身・増減が違えば変わる。利用者データは数えない。</para>
    /// </summary>
    public static string TreeDigest(UpdateSafetyOptions o, IEnumerable<(string Rel, string Sha256)> files)
    {
        var rows = files
            .Select(f => (Rel: NormRel(f.Rel).ToLowerInvariant(), Sha: Canon.TrimAscii(f.Sha256).ToLowerInvariant()))
            .Where(f => f.Rel.Length > 0 && !IsExcluded(o, f.Rel))
            .OrderBy(f => f.Rel, StringComparer.Ordinal)
            .ToList();
        var sb = new StringBuilder(o.TreeDomain).Append('\n');
        foreach (var f in rows) sb.Append(f.Rel).Append('\t').Append(f.Sha).Append('\n');
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()))).ToLowerInvariant();
    }

    /// <summary>Enough free space for the backup? The existing backup (deleted first) counts as free. null = enough; otherwise "needMB|freeMB".
    /// <para>控えを写す空きがあるか。null = 足りる。</para></summary>
    public static string? CheckSpace(UpdateSafetyOptions o, long freeBytes, long appBytes, long existingPrevBytes)
    {
        if (appBytes < 0 || freeBytes < 0) return "unknown";
        var need = Math.Max(0, appBytes - Math.Max(0, existingPrevBytes)) + o.SpaceMarginBytes;
        return freeBytes >= need ? null : string.Create(CultureInfo.InvariantCulture, $"{Mb(need)}|{Mb(freeBytes)}");
    }

    private static long Mb(long bytes) => (bytes + 1024 * 1024 - 1) / (1024 * 1024);

    /// <summary>True when the record belongs to this app folder (an empty Idle record belongs to anyone).
    /// <para>この実行フォルダの記録か。</para></summary>
    public static bool BelongsTo(State s, string appDir)
        => (s.Phase == Phase.Idle && s.AppDir.Length == 0)
           || string.Equals(s.AppDir.TrimEnd('\\', '/'), (appDir ?? "").TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase);

    /// <summary>Serializes the state (one "key=value" per line). <para>状態を文字にする。</para></summary>
    public static string Serialize(State s) => string.Join("\n", new[]
    {
        "phase=" + s.Phase,
        "from=" + Clean(s.From),
        "to=" + Clean(s.To),
        "prevDigest=" + Clean(s.PrevDigest),
        "crashes=" + s.Crashes.ToString(CultureInfo.InvariantCulture),
        "reason=" + s.Reason,
        "rolledBack=" + string.Join(",", s.RolledBack.Select(Clean)),
        "notice=" + s.Pending,
        "noticeFrom=" + Clean(s.NoticeFrom),
        "noticeTo=" + Clean(s.NoticeTo),
        "appDir=" + Clean(s.AppDir),
        "lastSeq=" + s.LastSeq.ToString(CultureInfo.InvariantCulture),
    }) + "\n";

    /// <summary>Parses the state. Unknown or broken lines are skipped; a missing/broken file means Idle (do nothing).
    /// <para>読めない行は飛ばす。無い・壊れている → Idle（何もしない側）。</para></summary>
    public static State Parse(string? text)
    {
        var s = new State();
        if (string.IsNullOrWhiteSpace(text)) return s;
        foreach (var raw in text.Replace("\r", "").Split('\n'))
        {
            var i = raw.IndexOf('=');
            if (i <= 0) continue;
            var k = raw.Substring(0, i);
            var v = raw.Substring(i + 1).Trim();
            switch (k)
            {
                case "phase": if (Enum.TryParse<Phase>(v, out var p) && Enum.IsDefined(p)) s.Phase = p; break;
                case "from": s.From = v; break;
                case "to": s.To = v; break;
                case "prevDigest": s.PrevDigest = v; break;
                case "crashes": if (int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var c)) s.Crashes = c; break;
                case "reason": if (Enum.TryParse<Why>(v, out var w) && Enum.IsDefined(w)) s.Reason = w; break;
                case "rolledBack": s.RolledBack = v.Split(',').Select(x => x.Trim()).Where(x => x.Length > 0).Distinct(StringComparer.Ordinal).ToList(); break;
                case "notice": if (Enum.TryParse<Notice>(v, out var n) && Enum.IsDefined(n)) s.Pending = n; break;
                case "noticeFrom": s.NoticeFrom = v; break;
                case "noticeTo": s.NoticeTo = v; break;
                case "appDir": s.AppDir = v; break;
                case "lastSeq": if (long.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var q)) s.LastSeq = q; break;
            }
        }
        return s;
    }

    private static string Clean(string? v) => (v ?? "").Replace("\n", " ").Replace("\r", " ").Replace(",", " ").Trim();

    private static State Copy(State s) => Parse(Serialize(s));

    /// <summary>Record just before the apply script runs. <para>適用の手順を走らせる直前に記録する。</para></summary>
    public static State BeginApply(State s, string from, string to, string prevDigest, string appDir)
    {
        var n = Copy(s);
        n.Phase = Phase.Applying; n.From = from; n.To = to; n.PrevDigest = prevDigest; n.Crashes = 0; n.Reason = Why.None; n.AppDir = appDir ?? "";
        return n;
    }

    /// <summary>Remember the sequence number of release info whose signature and freshness were verified.
    /// <para>署名と鮮度を確かめた配信情報の通し番号を覚える（下がることはない）。</para></summary>
    public static State AcceptSeq(State s, long seq)
    {
        var n = Copy(s);
        if (seq > n.LastSeq) n.LastSeq = seq;
        return n;
    }

    /// <summary>
    /// Decision right after start-up. For Watching, the "previous run" is always the new version (the switch Applying → Watching
    /// happens on the new version's first start).
    /// <para>起動直後の判定。</para>
    /// </summary>
    public static Result OnStartup(UpdateSafetyOptions o, State s, string current, LastRun last)
    {
        var n = Copy(s);
        switch (s.Phase)
        {
            case Phase.Applying:
                if (VersionCompare.Same(current, s.To)) { n.Phase = Phase.Watching; n.Crashes = 0; return new(n, Action.None); }
                n.Phase = Phase.Idle; n.PrevDigest = ""; n.Crashes = 0;
                if (VersionCompare.Same(current, s.From)) { n.Pending = Notice.ApplyFailed; n.NoticeFrom = s.From; n.NoticeTo = s.To; }
                return new(n, Action.None);

            case Phase.Watching:
                if (!VersionCompare.Same(current, s.To)) { n.Phase = Phase.Idle; n.Crashes = 0; return new(n, Action.None); }
                if (last.Abnormal && last.RanFor is null) return new(n, Action.None);   // unknown length: neither a crash nor healthy
                if (last.Abnormal && last.RanFor < o.CrashWindow)
                {
                    n.Crashes = s.Crashes + 1;
                    if (n.Crashes >= o.CrashLimit) { n.Reason = Why.Crashes; return new(n, Action.Rollback); }
                    return new(n, Action.None);
                }
                n.Phase = Phase.Stable; n.Crashes = 0;
                return new(n, Action.None);

            case Phase.RollingBack:
                n.Phase = Phase.Idle; n.Crashes = 0; n.PrevDigest = "";
                if (VersionCompare.Same(current, s.From))
                {
                    if (!n.RolledBack.Any(v => VersionCompare.Same(v, s.To))) n.RolledBack.Add(s.To);
                    if (n.RolledBack.Count > o.MaxRolledBackHistory) n.RolledBack.RemoveRange(0, n.RolledBack.Count - o.MaxRolledBackHistory);
                    n.Pending = Notice.RolledBack;
                }
                else n.Pending = Notice.RollbackFailed;   // stop trying (no rollback loop)
                n.NoticeFrom = s.From; n.NoticeTo = s.To;
                return new(n, Action.None);

            default:
                return new(n, Action.None);
        }
    }

    /// <summary>
    /// The publisher revoked versions (pass only a list whose signature and freshness were verified). Rolls back when the current
    /// version is listed, a backup exists, the backup's version is not listed, and this update is Watching or Stable.
    /// <para>配布元が不具合版を指定したとき（確かめた一覧だけを渡す）。</para>
    /// </summary>
    public static Result OnBadVersions(State s, string current, IReadOnlyList<string> badVersions)
    {
        var n = Copy(s);
        if (!VersionCompare.IsListed(current, badVersions)) return new(n, Action.None);
        if (s.Phase is not (Phase.Watching or Phase.Stable)) return new(n, Action.None);
        if (!VersionCompare.Same(current, s.To) || s.PrevDigest.Length == 0 || s.From.Length == 0) return new(n, Action.None);
        if (VersionCompare.IsListed(s.From, badVersions)) return new(n, Action.None);
        n.Reason = Why.BadVersion;
        return new(n, Action.Rollback);
    }

    /// <summary>Check just before rolling back. null = OK; otherwise "no-record" / "no-prev" / "digest-mismatch".
    /// <para>戻す直前の確かめ。</para></summary>
    public static string? CanRollback(State s, string? actualPrevDigest)
    {
        if (s.PrevDigest.Length != 64) return "no-record";
        if (string.IsNullOrEmpty(actualPrevDigest)) return "no-prev";
        if (!string.Equals(actualPrevDigest, s.PrevDigest, StringComparison.OrdinalIgnoreCase)) return "digest-mismatch";
        return null;
    }

    /// <summary>Record just before the rollback script runs.</summary>
    public static State BeginRollback(State s) { var n = Copy(s); n.Phase = Phase.RollingBack; return n; }

    /// <summary>Rollback is impossible (no backup / mismatch): drop the backup record and notify.</summary>
    public static State GiveUpRollback(State s)
    {
        var n = Copy(s);
        n.Phase = Phase.Stable; n.PrevDigest = ""; n.Crashes = 0;
        n.Pending = Notice.RollbackFailed; n.NoticeFrom = s.From; n.NoticeTo = s.To;
        return n;
    }

    /// <summary>Clear the one-time notice.</summary>
    public static State ClearNotice(State s) { var n = Copy(s); n.Pending = Notice.None; n.NoticeFrom = ""; n.NoticeTo = ""; return n; }
}
