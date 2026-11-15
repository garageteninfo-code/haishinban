using System;
using System.Globalization;

namespace UpdateSafetyKit;

/// <summary>
/// "Did the previous run end normally?" A marker is written at start-up, refreshed by a heartbeat and deleted on a clean exit.
/// A marker left behind means the previous run did not exit cleanly (native crash, kill, power loss). The run length is taken from a
/// monotonic clock (<see cref="Environment.TickCount64"/>), so changing the wall clock does not make a long run look short or vice versa.
/// <para>「前回はちゃんと終わったか」。起動時に印を置き、心拍で書き足し、正常終了で消す。印が残っていれば正常に終わっていない。
/// 動いた長さは単調な時計（TickCount64）で測るので、時計を変えても長さを取り違えない。</para>
/// </summary>
public sealed class RunMarker
{
    /// <summary>Process id of the run.</summary>
    public int Pid;
    /// <summary>Wall-clock start (UTC) – for display and for the PID-reuse check.</summary>
    public DateTime StartedAtUtc;
    /// <summary>Wall-clock time of the last heartbeat (UTC).</summary>
    public DateTime HeartbeatUtc;
    /// <summary>Monotonic milliseconds from start to the last heartbeat. Null in markers written by older code.</summary>
    public long? ElapsedMs;
    /// <summary>App version of the run.</summary>
    public string Version = "";
}

/// <summary>Verdict about the previous run. RanFor null = length unknown. <para>前回の終わり方の判定。</para></summary>
public sealed record ExitVerdict(bool Abnormal, TimeSpan? RanFor)
{
    /// <summary>As the input of <see cref="CrashWatch.OnStartup"/>.</summary>
    public CrashWatch.LastRun ToLastRun() => new(Abnormal, RanFor);
}

/// <summary>Serialization and judgement of <see cref="RunMarker"/> (pure logic). <para>印の読み書きと判定（純ロジック）。</para></summary>
public static class RunMarkerLogic
{
    private const string Fmt = "yyyy-MM-ddTHH:mm:ss.fffZ";

    /// <summary>One "key=value" per line.</summary>
    public static string Serialize(RunMarker m) => string.Join("\n", new[]
    {
        "pid=" + m.Pid.ToString(CultureInfo.InvariantCulture),
        "started=" + m.StartedAtUtc.ToUniversalTime().ToString(Fmt, CultureInfo.InvariantCulture),
        "heartbeat=" + m.HeartbeatUtc.ToUniversalTime().ToString(Fmt, CultureInfo.InvariantCulture),
        "elapsedMs=" + (m.ElapsedMs?.ToString(CultureInfo.InvariantCulture) ?? ""),
        "version=" + (m.Version ?? "").Replace("\n", " ").Replace("\r", " ").Trim(),
    }) + "\n";

    /// <summary>Null when unreadable (treated as "no marker" = normal; never assume a crash from garbage).</summary>
    public static RunMarker? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var m = new RunMarker();
        bool sawPid = false, sawStart = false;
        foreach (var raw in text.Replace("\r", "").Split('\n'))
        {
            var i = raw.IndexOf('=');
            if (i <= 0) continue;
            var k = raw.Substring(0, i); var v = raw.Substring(i + 1);
            switch (k)
            {
                case "pid": if (int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p)) { m.Pid = p; sawPid = true; } break;
                case "started": if (TryTime(v, out var s)) { m.StartedAtUtc = s; sawStart = true; } break;
                case "heartbeat": if (TryTime(v, out var h)) m.HeartbeatUtc = h; break;
                case "elapsedMs": if (long.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var e)) m.ElapsedMs = e; break;
                case "version": m.Version = v; break;
            }
        }
        if (!sawPid || !sawStart) return null;
        if (m.HeartbeatUtc == default) m.HeartbeatUtc = m.StartedAtUtc;
        return m;
    }

    private static bool TryTime(string v, out DateTime t) =>
        DateTime.TryParseExact(v, Fmt, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t);

    /// <summary>
    /// Judges the previous run. No marker → normal. The same process still alive → normal (another instance). Otherwise abnormal,
    /// with RanFor from the monotonic ElapsedMs; for old markers without it, the wall-clock difference is used only when it is not
    /// negative (a negative value means the clock moved, so the length is unknown).
    /// <para>印なし → 正常。同じプロセスが生きている → 正常。それ以外 → 異常。長さは ElapsedMs（単調な時計）。古い印で壁時計の差が負なら「不明」。</para>
    /// </summary>
    /// <param name="prev">Marker left by the previous run, or null.</param>
    /// <param name="samePrevProcessAlive">True only if a process with that PID is alive AND it is the same process (started no later
    /// than the marker; see <c>UpdateGuardIO.IsSameProcessAlive</c>). A reused PID must be passed as false.</param>
    public static ExitVerdict Judge(RunMarker? prev, bool samePrevProcessAlive)
    {
        if (prev is null || samePrevProcessAlive) return new ExitVerdict(false, null);
        TimeSpan? ranFor = null;
        if (prev.ElapsedMs is { } ms && ms >= 0) ranFor = TimeSpan.FromMilliseconds(ms);
        else
        {
            var wall = prev.HeartbeatUtc - prev.StartedAtUtc;
            if (wall >= TimeSpan.Zero) ranFor = wall;
        }
        return new ExitVerdict(true, ranFor);
    }
}
