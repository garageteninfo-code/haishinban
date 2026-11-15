using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace UpdateSafetyKit;

/// <summary>
/// File-system side of the kit (the decisions live in the pure classes). Every method is best-effort and never throws:
/// failures return null / false so the app keeps running and the caller can fail closed.
/// <para>ファイル操作の側（判定は純ロジックの側）。例外は投げず、失敗は null / false を返す。</para>
/// </summary>
public static class UpdateGuardIO
{
    private static readonly UTF8Encoding Utf8NoBom = new(false);

    /// <summary>Loads the update state; a missing or unreadable file gives a fresh Idle state.</summary>
    public static CrashWatch.State LoadState(string statePath)
    {
        try { return File.Exists(statePath) ? CrashWatch.Parse(File.ReadAllText(statePath)) : new CrashWatch.State(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new CrashWatch.State(); }
    }

    /// <summary>Saves atomically (write temp file, then replace). Returns false when it could not be saved.</summary>
    public static bool SaveState(string statePath, CrashWatch.State s) => WriteAtomic(statePath, CrashWatch.Serialize(s));

    /// <summary>Returns the device's install id, creating it on first use. Empty when it cannot be stored (the device then only
    /// receives 100% rollouts).</summary>
    public static string InstallId(string installIdPath)
    {
        try
        {
            if (File.Exists(installIdPath))
            {
                var cur = File.ReadAllText(installIdPath).Trim();
                if (Rollout.IsValidInstallId(cur)) return cur;
            }
            var id = Rollout.NewInstallId();
            return WriteAtomic(installIdPath, id + "\n") ? id : "";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return ""; }
    }

    /// <summary>Digest and size of a folder (user-data folders and reparse points skipped). Null when any file cannot be read.</summary>
    public static (string Digest, long Bytes)? DigestTree(UpdateSafetyOptions o, string root)
    {
        try
        {
            if (!Directory.Exists(root)) return null;
            var rows = new List<(string, string)>();
            long bytes = 0;
            var opts = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = false };
            foreach (var f in Directory.EnumerateFiles(root, "*", opts))
            {
                var rel = Path.GetRelativePath(root, f);
                if (CrashWatch.IsExcluded(o, rel)) continue;
                using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                rows.Add((rel, Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant()));
                bytes += fs.Length;
            }
            return (CrashWatch.TreeDigest(o, rows), bytes);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { return null; }
    }

    /// <summary>Free bytes on the drive of <paramref name="path"/>, or -1.</summary>
    public static long FreeBytes(string path)
    {
        try { return new DriveInfo(Path.GetPathRoot(Path.GetFullPath(path))!).AvailableFreeSpace; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return -1; }
    }

    /// <summary>
    /// True when a process with <paramref name="pid"/> is alive AND started no later than the marker said (plus 2 s). A process that
    /// started later is a different program that reused the PID.
    /// <para>その PID のプロセスが生きていて、しかも印の起動時刻より後に始まったものではないときだけ true（番号の使い回しを見分ける）。</para>
    /// </summary>
    public static bool IsSameProcessAlive(int pid, DateTime markerStartedUtc)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            if (p.HasExited) return false;
            return p.StartTime.ToUniversalTime() <= markerStartedUtc.AddSeconds(2);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { return false; }
    }

    /// <summary>
    /// Writes the script (ASCII) into <paramref name="workDir"/> and starts it hidden with its environment variables.
    /// Returns false when it could not be started. The caller exits the app afterwards.
    /// <para>手順を書いて、環境変数つきで見えない窓で起動する。起動できなければ false。アプリの終了は呼び出し側。</para>
    /// </summary>
    public static bool LaunchScript(ScriptPlan plan, string workDir, string fileName)
    {
        using var p = StartScript(plan, workDir, fileName);
        return p is not null;
    }

    /// <summary>
    /// Runs the script and waits (for drills and tests; the real apply/rollback must use <see cref="LaunchScript"/> because the
    /// script waits for the app to exit). Returns the exit code, or null when it could not start or timed out.
    /// <para>手順を走らせて終わるまで待つ（演習・試験用）。</para>
    /// </summary>
    public static int? RunScript(ScriptPlan plan, string workDir, string fileName, TimeSpan timeout)
    {
        using var p = StartScript(plan, workDir, fileName);
        if (p is null) return null;
        if (!p.WaitForExit((int)Math.Min(int.MaxValue, timeout.TotalMilliseconds))) { try { p.Kill(true); } catch (InvalidOperationException) { } return null; }
        return p.ExitCode;
    }

    private static Process? StartScript(ScriptPlan plan, string workDir, string fileName)
    {
        try
        {
            if (fileName.IndexOfAny(new[] { '\\', '/', '"' }) >= 0) return null;
            Directory.CreateDirectory(workDir);
            var path = Path.Combine(workDir, fileName);
            if (path.Contains('"')) return null;
            File.WriteAllText(path, plan.Script, Encoding.ASCII);
            var psi = new ProcessStartInfo { FileName = "cmd.exe", CreateNoWindow = true, UseShellExecute = false, WorkingDirectory = workDir };
            // /s + doubled quotes: cmd strips only the outer pair, so a path with spaces, '&' or '^' stays quoted.
            psi.Arguments = "/d /s /c \"\"" + path + "\"\"";
            foreach (var kv in plan.Environment) psi.Environment[kv.Key] = kv.Value;
            return Process.Start(psi);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or InvalidOperationException) { return null; }
    }

    internal static bool WriteAtomic(string path, string text)
    {
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, text, Utf8NoBom);
            File.Move(tmp, path, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }
}

/// <summary>
/// Run marker on disk with a heartbeat (call <see cref="Begin"/> as early as possible in Main, <see cref="End"/> on a clean exit).
/// <para>印のファイルと心拍。Main のできるだけ早い所で Begin、正常終了で End。</para>
/// </summary>
public sealed class SessionMarkerFile : IDisposable
{
    private readonly string _path;
    private readonly RunMarker _marker;
    private readonly long _startTick;
    private Timer? _timer;

    /// <summary>The verdict about the previous run (read by <see cref="Begin"/>).</summary>
    public ExitVerdict Previous { get; }

    private SessionMarkerFile(string path, ExitVerdict previous, string version)
    {
        _path = path; Previous = previous;
        _startTick = Environment.TickCount64;
        _marker = new RunMarker { Pid = Environment.ProcessId, StartedAtUtc = DateTime.UtcNow, HeartbeatUtc = DateTime.UtcNow, ElapsedMs = 0, Version = version };
    }

    /// <summary>Reads the previous marker, judges it, writes this run's marker and starts the heartbeat.</summary>
    public static SessionMarkerFile Begin(string markerPath, string version, TimeSpan? heartbeat = null)
    {
        RunMarker? prev = null;
        try { if (File.Exists(markerPath)) prev = RunMarkerLogic.Parse(File.ReadAllText(markerPath)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { prev = null; }
        var alive = prev is not null && UpdateGuardIO.IsSameProcessAlive(prev.Pid, prev.StartedAtUtc);
        var s = new SessionMarkerFile(markerPath, RunMarkerLogic.Judge(prev, alive), version);
        s.Beat();
        var every = heartbeat ?? TimeSpan.FromSeconds(30);
        s._timer = new Timer(_ => s.Beat(), null, every, every);
        return s;
    }

    private void Beat()
    {
        _marker.HeartbeatUtc = DateTime.UtcNow;
        _marker.ElapsedMs = Environment.TickCount64 - _startTick;
        UpdateGuardIO.WriteAtomic(_path, RunMarkerLogic.Serialize(_marker));
    }

    /// <summary>Clean exit: stop the heartbeat and delete the marker.</summary>
    public void End()
    {
        _timer?.Dispose(); _timer = null;
        try { File.Delete(_path); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* next start will see a marker: counted as abnormal */ }
    }

    /// <summary>Stops the heartbeat without deleting the marker.</summary>
    public void Dispose() { _timer?.Dispose(); _timer = null; }
}
