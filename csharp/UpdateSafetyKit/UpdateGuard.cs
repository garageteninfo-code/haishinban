using System;
using System.IO;

namespace UpdateSafetyKit;

/// <summary>
/// Convenience wrapper that ties the pieces together for one installed app. All product-specific names are constructor inputs.
/// Typical use:
/// <code>
/// var marker = SessionMarkerFile.Begin(guard.MarkerPath, version);          // first lines of Main
/// var start  = guard.StartupCheck(version, marker.Previous);                 // may start a rollback
/// if (start.RollbackStarted) Environment.Exit(0);
/// var check  = guard.CheckRelease(release, PublicKeyPem, version, serverSaysAvailable, DateTimeOffset.UtcNow);
/// if (check.Offer.Kind == Rollout.OfferKind.Offer) { /* download, verify sha256/size, extract, then guard.StartApply(...) */ }
/// </code>
/// <para>1 つのアプリ向けに部品をつなぐ入口。製品固有の名前はすべてコンストラクタで渡す。</para>
/// </summary>
public sealed class UpdateGuard
{
    private readonly UpdateSafetyOptions _o;

    /// <summary>The app folder (the folder that is overwritten by updates).</summary>
    public string AppDir { get; }
    /// <summary>File name of the app's executable (e.g. "MyApp.exe").</summary>
    public string ExeName { get; }
    /// <summary>Folder for state files (should be outside the app folder, e.g. %LOCALAPPDATA%\MyApp).</summary>
    public string DataDir { get; }
    /// <summary>Folder for generated scripts and staging (default: %TEMP%\&lt;Domain&gt;).</summary>
    public string WorkRoot { get; }

    /// <summary>update-state.txt in DataDir.</summary>
    public string StatePath => Path.Combine(DataDir, "update-state.txt");
    /// <summary>install-id.txt in DataDir.</summary>
    public string InstallIdPath => Path.Combine(DataDir, "install-id.txt");
    /// <summary>app.running in DataDir.</summary>
    public string MarkerPath => Path.Combine(DataDir, "app.running");
    /// <summary>The backup folder next to AppDir.</summary>
    public string PrevDir => CrashWatch.PrevDirFor(_o, AppDir);

    /// <summary>Creates the guard. <para>入口を作る。</para></summary>
    public UpdateGuard(UpdateSafetyOptions options, string dataDir, string appDir, string exeName, string? workRoot = null)
    {
        _o = (options ?? throw new ArgumentNullException(nameof(options))).Validate();
        DataDir = dataDir ?? throw new ArgumentNullException(nameof(dataDir));
        AppDir = (appDir ?? throw new ArgumentNullException(nameof(appDir))).TrimEnd('\\', '/');
        ExeName = exeName ?? throw new ArgumentNullException(nameof(exeName));
        WorkRoot = workRoot ?? Path.Combine(Path.GetTempPath(), _o.Domain);
    }

    /// <summary>Result of <see cref="StartupCheck"/>.</summary>
    public sealed record StartupResult(CrashWatch.State State, bool RollbackStarted, string? RollbackRefused);

    /// <summary>
    /// Call once right after <see cref="SessionMarkerFile.Begin"/>. When the new version crashed early CrashLimit times in a row,
    /// starts the rollback script; the caller must then exit immediately.
    /// <para>起動直後に 1 回。続けて落ちていたら戻しの手順を起動する（呼び出し側はすぐ終了する）。</para>
    /// </summary>
    public StartupResult StartupCheck(string currentVersion, ExitVerdict previous)
    {
        var s = UpdateGuardIO.LoadState(StatePath);
        if (s.Phase == CrashWatch.Phase.Idle || !CrashWatch.BelongsTo(s, AppDir)) return new(s, false, null);
        var r = CrashWatch.OnStartup(_o, s, currentVersion, previous.ToLastRun());
        UpdateGuardIO.SaveState(StatePath, r.Next);
        if (r.Action != CrashWatch.Action.Rollback) return new(r.Next, false, null);
        var (started, why) = TryStartRollback(r.Next);
        return new(UpdateGuardIO.LoadState(StatePath), started, why);
    }

    /// <summary>Result of <see cref="CheckRelease"/>.</summary>
    public sealed record ReleaseCheck(Rollout.OfferDecision Offer, UpdateError? Error);

    /// <summary>
    /// Verifies the v3 signature and freshness, remembers the accepted sequence number, and decides whether to offer.
    /// <para>v3 の署名と鮮度を確かめ、通し番号を覚え、出すかを決める。</para>
    /// </summary>
    public ReleaseCheck CheckRelease(ReleaseInfo? release, string? publicKeyPem, string currentVersion, bool serverAvailable, DateTimeOffset nowUtc, long minimumSeq = 0)
    {
        var s = UpdateGuardIO.LoadState(StatePath);
        if (release is null) return new(Rollout.DecideOffer(serverAvailable, null, currentVersion, null, new UpdateError(UpdateErrorCode.PolicyInvalid), null, s.RolledBack), null);
        var err = ReleaseSignature.VerifyV3(_o, release, publicKeyPem) ?? Freshness.Check(release.Policy, s.LastSeq, nowUtc, minimumSeq);
        if (err is null && release.Policy.Seq is { } seq && seq > s.LastSeq) UpdateGuardIO.SaveState(StatePath, CrashWatch.AcceptSeq(s, seq));
        var offer = Rollout.DecideOffer(serverAvailable, release.Version, currentVersion, err is null ? release.Policy : null, err,
            UpdateGuardIO.InstallId(InstallIdPath), s.RolledBack);
        return new(offer, err);
    }

    /// <summary>
    /// Records the update and starts the apply script (the caller exits right after a true result). Checks free space first.
    /// <para>記録してから適用の手順を起動する（true なら呼び出し側はすぐ終了）。先に空き容量を確かめる。</para>
    /// </summary>
    public (bool Started, string? Why) StartApply(int pid, string stagingDir, string fromVersion, string toVersion)
    {
        var tree = UpdateGuardIO.DigestTree(_o, AppDir);
        if (tree is null) return (false, "cannot-read-app-folder");
        var prevBytes = UpdateGuardIO.DigestTree(_o, PrevDir)?.Bytes ?? 0;
        var space = CrashWatch.CheckSpace(_o, UpdateGuardIO.FreeBytes(AppDir), tree.Value.Bytes, prevBytes);
        if (space is not null) return (false, "space:" + space);
        ScriptPlan plan;
        try { plan = UpdateScripts.BuildApply(_o, pid, stagingDir, AppDir, ExeName); }
        catch (ArgumentException ex) { return (false, "script:" + ex.Message); }
        if (!UpdateGuardIO.SaveState(StatePath, CrashWatch.BeginApply(UpdateGuardIO.LoadState(StatePath), fromVersion, toVersion, tree.Value.Digest, AppDir)))
            return (false, "state-not-saved");
        var work = Path.Combine(WorkRoot, "apply-" + DateTime.UtcNow.ToString("yyyyMMddHHmmssfff", System.Globalization.CultureInfo.InvariantCulture));
        return UpdateGuardIO.LaunchScript(plan, work, "update-apply.cmd") ? (true, null) : (false, "launch-failed");
    }

    /// <summary>
    /// Starts the rollback script when the backup still matches the record. Otherwise records "rollback failed" and returns the reason.
    /// <para>控えが記録と一致するときだけ戻しの手順を起動する。だめなら「戻せなかった」を記録して理由を返す。</para>
    /// </summary>
    public (bool Started, string? Why) TryStartRollback(CrashWatch.State s)
    {
        var why = CrashWatch.CanRollback(s, Directory.Exists(PrevDir) ? UpdateGuardIO.DigestTree(_o, PrevDir)?.Digest : null);
        if (why is null)
        {
            ScriptPlan? plan = null;
            try { plan = UpdateScripts.BuildRollback(_o, Environment.ProcessId, AppDir, ExeName); }
            catch (ArgumentException ex) { why = "script:" + ex.Message; }
            if (plan is not null)
            {
                if (!UpdateGuardIO.SaveState(StatePath, CrashWatch.BeginRollback(s))) why = "state-not-saved";
                else
                {
                    var work = Path.Combine(WorkRoot, "rollback-" + DateTime.UtcNow.ToString("yyyyMMddHHmmssfff", System.Globalization.CultureInfo.InvariantCulture));
                    if (UpdateGuardIO.LaunchScript(plan, work, "update-rollback.cmd")) return (true, null);
                    why = "launch-failed";
                }
            }
        }
        UpdateGuardIO.SaveState(StatePath, CrashWatch.GiveUpRollback(s));
        return (false, why);
    }
}
