using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace UpdateSafetyKit;

/// <summary>Result of one POST to the relay. Status 0 = network error. <para>1 回の送信の結果（0 は通信の失敗）。</para></summary>
public readonly record struct TransportResult(int Status, string? Body, bool CertificateRejected = false);

/// <summary>How the reporter talks to the relay (replaceable for tests). <para>中継への送り方（試験で差し替えられる）。</para></summary>
public interface IReportTransport
{
    /// <summary>POST a JSON body to a path relative to the relay (e.g. "v1/reports").</summary>
    Task<TransportResult> PostJsonAsync(string path, string json, CancellationToken ct);
}

/// <summary>The real transport over <see cref="HttpClient"/> (make it with <see cref="HaishinHttp.CreateClient"/>).</summary>
public sealed class HttpReportTransport : IReportTransport
{
    private readonly HttpClient _http;
    /// <summary>Uses (does not own) the client.</summary>
    public HttpReportTransport(HttpClient http) => _http = http ?? throw new ArgumentNullException(nameof(http));

    /// <inheritdoc />
    public async Task<TransportResult> PostJsonAsync(string path, string json, CancellationToken ct)
    {
        try
        {
            using var content = new StringContent(json, new UTF8Encoding(false), "application/json");
            using var res = await _http.PostAsync(path, content, ct).ConfigureAwait(false);
            var body = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return new((int)res.StatusCode, body.Length > 4096 ? body.Substring(0, 4096) : body);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (HttpRequestException ex) when (HaishinHttp.IsCertificateRejected(ex)) { return new(0, null, true); }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException) { return new(0, null); }
    }
}

/// <summary>Settings of <see cref="CrashReporter"/>. <para>報告の送り手の設定。</para></summary>
public sealed class CrashReporterOptions
{
    private static readonly Regex VersionRe = new("^[0-9A-Za-z.+-]{1,64}$", RegexOptions.CultureInvariant);

    /// <summary>Version of the running app (same text as in the manifest). <para>動いている版。</para></summary>
    public string AppVersion { get; init; } = "";
    /// <summary>Folder for the send queue (e.g. %LOCALAPPDATA%\MyApp\haishin-queue). Reports survive a crash and an offline PC here.
    /// <para>送る前の報告を置くフォルダ。落ちても・つながらなくても、ここに残って次に送る。</para></summary>
    public string QueueDir { get; init; } = "";
    /// <summary>install-id.txt shared with <see cref="UpdateGuard"/> (<see cref="UpdateGuard.InstallIdPath"/>). The id itself is never sent;
    /// only sha256("haishin-report|" + id). <para>UpdateGuard と同じ install-id.txt。番号そのものは送らない。</para></summary>
    public string InstallIdPath { get; init; } = "";
    /// <summary>OS text sent with reports. Default: "Windows 10.0.26100" style (no user or PC names).</summary>
    public string Os { get; init; } = DefaultOs();
    /// <summary>Attempts per item for temporary failures (network, 429, 5xx) before dropping it. <para>一時的な失敗のときに試す回数。</para></summary>
    public int MaxAttempts { get; init; } = 8;
    /// <summary>First retry delay (doubles each time, with random jitter). <para>最初の待ち時間（毎回 2 倍・ゆらぎつき）。</para></summary>
    public TimeSpan BaseDelay { get; init; } = TimeSpan.FromSeconds(2);
    /// <summary>Longest wait between retries. <para>待ち時間の上限。</para></summary>
    public TimeSpan MaxDelay { get; init; } = TimeSpan.FromMinutes(5);
    /// <summary>At most this many items wait in the queue (oldest start-up pings are dropped first). <para>置いておく数の上限。</para></summary>
    public int MaxQueued { get; init; } = 50;
    /// <summary>Reports older than this are dropped unsent. <para>この古さを超えた報告は送らずに捨てる。</para></summary>
    public TimeSpan MaxReportAge { get; init; } = TimeSpan.FromDays(7);
    /// <summary>Start-up pings older than this are dropped (stale pings would distort the crash rate). <para>起動の知らせはこの古さで捨てる。</para></summary>
    public TimeSpan MaxPingAge { get; init; } = TimeSpan.FromHours(12);
    /// <summary>Optional log of what happened (never contains report text). <para>何が起きたかの記録（報告の中身は入れない）。</para></summary>
    public Action<string>? Log { get; init; }

    /// <summary>"Windows 10.0.26100" (from <see cref="Environment.OSVersion"/>).</summary>
    public static string DefaultOs()
    {
        var v = Environment.OSVersion.Version;
        var name = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.OSDescription.Split(' ').FirstOrDefault() ?? "OS";
        return string.Create(CultureInfo.InvariantCulture, $"{name} {v.Major}.{v.Minor}.{v.Build}");
    }

    /// <summary>Throws <see cref="ArgumentException"/> for settings that cannot work. <para>使えない設定なら例外。</para></summary>
    public CrashReporterOptions Validate()
    {
        if (!VersionRe.IsMatch(AppVersion ?? "")) throw new ArgumentException("AppVersion must match ^[0-9A-Za-z.+-]{1,64}$");
        if (string.IsNullOrWhiteSpace(QueueDir)) throw new ArgumentException("QueueDir is required");
        if (string.IsNullOrWhiteSpace(InstallIdPath)) throw new ArgumentException("InstallIdPath is required");
        if (string.IsNullOrWhiteSpace(Os) || Os.Length > 64 || Os.Contains('\n') || Os.Contains('\r')) throw new ArgumentException("Os must be 1..64 characters without line breaks");
        if (MaxAttempts < 1 || MaxQueued < 1) throw new ArgumentException("MaxAttempts and MaxQueued must be >= 1");
        if (BaseDelay < TimeSpan.Zero || MaxDelay < BaseDelay) throw new ArgumentException("0 <= BaseDelay <= MaxDelay");
        return this;
    }
}

/// <summary>Counters for the app's diagnostics screen (no report text). <para>数だけ（中身は無い）。</para></summary>
public sealed record ReporterStats(int Sent, int Retried, int Refused, int Redacted, int Dropped, int Queued, bool LastCertificateRejected);

/// <summary>
/// Sends crash reports and start-up pings to the Haishin relay without blocking the app.
/// <list type="bullet">
/// <item>Each item is first written to a small file in <see cref="CrashReporterOptions.QueueDir"/>, then a single background task sends it.
/// Nothing waits for the network on the calling thread (except <see cref="ReportCrashAndFlush"/>, which is for a dying process
/// and waits at most the time you pass).</item>
/// <item>Text is redacted locally first (<see cref="ReportRedactor"/>). If the relay still refuses (422, with the field and kind),
/// that whole field is replaced with "[伏せ字:kind]" and sent again; after several refusals the item is dropped.</item>
/// <item>Network errors, 429 and 5xx are retried with exponential backoff and jitter; 400/413/415 are dropped (they will never pass).</item>
/// <item>The device is identified only by reporterId = sha256("haishin-report|" + installId), never by the install id itself.</item>
/// </list>
/// <para>落ちた報告と起動の知らせを、アプリを止めずに中継へ送る。まずファイルに置き、裏の 1 本の処理が送る。
/// 先に PC の中で伏せ字にし、それでも 422 で断られたら、その欄を丸ごと伏せて送り直す（何度も断られたら捨てる）。
/// 通信の失敗・429・5xx は待ち時間を延ばしながら送り直す。端末は reporterId（installId を混ぜた値）だけで表す。</para>
/// </summary>
public sealed class CrashReporter : IDisposable
{
    private const int MaxRedactions = 6;
    private static readonly JsonSerializerOptions JsonOut = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private static readonly Regex FieldRe = new(@"^reports\[(\d{1,2})\]\.(title|message|stack)$", RegexOptions.CultureInvariant);

    private readonly CrashReporterOptions _o;
    private readonly IReportTransport _transport;
    private readonly Func<DateTimeOffset> _now;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly Random _rng;
    private readonly object _io = new();
    private readonly SemaphoreSlim _wake = new(0, int.MaxValue);
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly CancellationTokenSource _stop = new();
    private Task? _loop;
    private int _sent, _retried, _refused, _redacted, _dropped;
    private volatile bool _certRejected;

    /// <summary>The id sent instead of the install id. <para>installId の代わりに送る番号。</para></summary>
    public string ReporterId { get; }

    /// <summary>Creates the reporter. Call <see cref="Start"/> once (it also sends what an earlier run left in the queue).
    /// <paramref name="now"/>, <paramref name="delay"/> and <paramref name="random"/> are for tests.</summary>
    public CrashReporter(CrashReporterOptions options, IReportTransport transport,
        Func<DateTimeOffset>? now = null, Func<TimeSpan, CancellationToken, Task>? delay = null, Random? random = null)
    {
        _o = (options ?? throw new ArgumentNullException(nameof(options))).Validate();
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _delay = delay ?? ((t, ct) => Task.Delay(t, ct));
        _rng = random ?? new Random();
        var id = UpdateGuardIO.InstallId(_o.InstallIdPath);
        // installId を保存できない端末でも報告は送る（その実行の間だけの乱数）
        ReporterId = ReporterIdFor(Rollout.IsValidInstallId(id) ? id : Rollout.NewInstallId());
        try { Directory.CreateDirectory(_o.QueueDir); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Log("queue folder cannot be created"); }
    }

    /// <summary>sha256("haishin-report|" + installId) as 64 lowercase hex (the format the relay accepts).</summary>
    public static string ReporterIdFor(string installId)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("haishin-report|" + installId))).ToLowerInvariant();

    /// <summary>Delay before retry number <paramref name="attempt"/> (1 = first retry): min(max, base·2^(attempt-1)) scaled by 0.5..1.0.
    /// <para>attempt 回目の送り直しまでの待ち時間。</para></summary>
    public static TimeSpan Backoff(int attempt, TimeSpan baseDelay, TimeSpan maxDelay, double random01)
    {
        var exp = Math.Min(30, Math.Max(0, attempt - 1));
        var ms = Math.Min(maxDelay.TotalMilliseconds, baseDelay.TotalMilliseconds * Math.Pow(2, exp));
        return TimeSpan.FromMilliseconds(ms * (0.5 + 0.5 * Math.Clamp(random01, 0, 1)));
    }

    /// <summary>Current counters. <para>今の数。</para></summary>
    public ReporterStats Stats => new(_sent, _retried, _refused, _redacted, _dropped, QueueFiles().Count, _certRejected);

    /// <summary>Starts the background sender (idempotent). <para>裏の送り手を始める。</para></summary>
    public void Start()
    {
        lock (_io) { _loop ??= Task.Run(() => LoopAsync(_stop.Token)); }
        _wake.Release();
    }

    /// <summary>Queues a start-up ping (counts this install as running this version). Returns at once.
    /// <para>起動の知らせを置く（すぐ戻る）。</para></summary>
    public void SendStartupPing()
    {
        var body = new JsonObject { ["reporterId"] = ReporterId, ["appVersion"] = _o.AppVersion, ["os"] = _o.Os };
        Enqueue("heartbeat", body);
        _wake.Release();
    }

    /// <summary>Queues an error/crash report built from <paramref name="ex"/> on a background thread. Returns at once.
    /// <para>例外から報告を作って置く（裏で行い、すぐ戻る）。</para></summary>
    public void ReportException(Exception ex, bool crash = false, string? context = null)
    {
        if (ex is null) return;
        var at = _now();
        _ = Task.Run(() =>
        {
            try { EnqueueReport(BuildReport(ex, crash ? "crash" : "error", at, context)); _wake.Release(); }
            catch (Exception e) { Log("could not queue report: " + e.GetType().Name); }
        });
    }

    /// <summary>
    /// For unhandled-exception handlers: writes the report to the queue synchronously (so it survives the process), then tries
    /// to send the queue for at most <paramref name="maxWait"/>. Returns true when the queue is empty afterwards. What is left
    /// is sent on the next start. <para>落ちる直前用：まず同期でファイルに置き、最長 maxWait だけ送ってみる。残りは次の起動で送る。</para>
    /// </summary>
    public bool ReportCrashAndFlush(Exception ex, TimeSpan maxWait, string? context = null)
    {
        try { EnqueueReport(BuildReport(ex, "crash", _now(), context)); }
        catch (Exception e) { Log("could not queue crash: " + e.GetType().Name); return false; }
        try { return Task.Run(() => FlushAsync(maxWait)).GetAwaiter().GetResult() == 0; }
        catch (Exception) { return false; }
    }

    /// <summary>Tries to send everything that is due now, for at most <paramref name="maxWait"/>. Returns the number of items still queued.
    /// <para>いま送れる物を最長 maxWait だけ送る。残った数を返す。</para></summary>
    public async Task<int> FlushAsync(TimeSpan maxWait)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
        cts.CancelAfter(maxWait);
        try { await SendDueAsync(cts.Token, ignoreNotBefore: true).ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        return QueueFiles().Count;
    }

    /// <summary>Hooks AppDomain.UnhandledException (crash, flush up to 2 s) and TaskScheduler.UnobservedTaskException (error).
    /// WinForms / WPF apps should also hook their UI-thread exception event (see the sample app).
    /// <para>処理されなかった例外を報告につなぐ。WinForms・WPF は画面の側の例外の口もつなぐ（サンプル参照）。</para></summary>
    public void AttachToAppDomain()
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) => { if (e.ExceptionObject is Exception ex) ReportCrashAndFlush(ex, TimeSpan.FromSeconds(2)); };
        TaskScheduler.UnobservedTaskException += (_, e) => ReportException(e.Exception, crash: false);
    }

    // ---------------- 報告を作る ----------------

    /// <summary>Builds the redacted report object (one entry of "reports"). Public for tests and for apps that send their own.
    /// <para>伏せ字にした報告を作る。</para></summary>
    public static JsonObject BuildReport(Exception ex, string kind, DateTimeOffset at, string? context = null, string? userName = null, string? machineName = null)
    {
        var root = ex;
        var type = ex.GetType().FullName ?? ex.GetType().Name;
        var firstLine = (ex.Message ?? "").Replace("\r", "").Split('\n')[0];
        var title = Clip(OneLine(ReportRedactor.Redact($"{ShortType(type)}: {firstLine}", userName ?? Environment.UserName, machineName ?? Environment.MachineName)), 200);
        var msg = new StringBuilder();
        if (!string.IsNullOrWhiteSpace(context)) msg.Append(context.Trim()).Append('\n');
        msg.Append(ex.Message);
        for (var inner = ex.InnerException; inner is not null && msg.Length < 1800; inner = inner.InnerException)
            msg.Append("\n--- ").Append(ShortType(inner.GetType().FullName ?? "")).Append(": ").Append(inner.Message);
        var message = Clip(ReportRedactor.Redact(msg.ToString(), userName ?? Environment.UserName, machineName ?? Environment.MachineName), 2000);
        var stack = ReportRedactor.RedactStack(ex.StackTrace ?? "", userName ?? Environment.UserName, machineName ?? Environment.MachineName);
        var lines = stack.Replace("\r", "").Split('\n').Where(l => l.Trim().Length > 0).Take(30).ToList();
        stack = Clip(string.Join("\n", lines), 4000);
        var stamp = at.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        return new JsonObject
        {
            ["fingerprint"] = Fingerprint(ex, kind),
            ["kind"] = kind == "crash" ? "crash" : "error",
            ["title"] = title.Length == 0 ? ShortType(type) : title,
            ["message"] = message,
            ["stack"] = stack,
            ["count"] = 1,
            ["firstSeen"] = stamp,
            ["lastSeen"] = stamp,
        };
    }

    /// <summary>Same exception type thrown from the same methods → same fingerprint (line numbers, paths and message text are not used).
    /// <para>同じ型・同じ場所の例外は同じ指紋（行番号・パス・文は使わない）。</para></summary>
    public static string Fingerprint(Exception ex, string kind)
    {
        var frames = new StackTrace(ex, false).GetFrames()
            .Select(f => f.GetMethod())
            .Where(m => m is not null)
            .Take(6)
            .Select(m => $"{m!.DeclaringType?.FullName}.{m.Name}");
        var basis = $"{kind}|{ex.GetType().FullName}|{string.Join("|", frames)}";
        return "ex-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(basis))).ToLowerInvariant().Substring(0, 24);
    }

    private static string ShortType(string fullName) => fullName.StartsWith("System.", StringComparison.Ordinal) ? fullName.Substring(fullName.LastIndexOf('.') + 1) : fullName;
    private static string OneLine(string s) => s.Replace('\r', ' ').Replace('\n', ' ').Trim();
    private static string Clip(string s, int max) => s.Length <= max ? s : s.Substring(0, max - 1) + "…";

    // ---------------- 置き場（ファイル） ----------------

    private void EnqueueReport(JsonObject report)
    {
        lock (_io)
        {
            // 同じ指紋の報告がまだ送られずに残っていれば、回数を足すだけにする（同じ落ち方で置き場があふれないように）
            foreach (var f in QueueFiles())
            {
                var item = Read(f);
                if (item?["type"]?.GetValue<string>() != "report") continue;
                var r = item["body"]?["reports"]?[0];
                if (r is null || r["fingerprint"]?.GetValue<string>() != report["fingerprint"]!.GetValue<string>()) continue;
                r["count"] = Math.Min(1000000, (r["count"]?.GetValue<int>() ?? 1) + 1);
                r["lastSeen"] = report["lastSeen"]!.GetValue<string>();
                Write(f, item);
                return;
            }
            var body = new JsonObject { ["reporterId"] = ReporterId, ["appVersion"] = _o.AppVersion, ["os"] = _o.Os, ["reports"] = new JsonArray(report) };
            Enqueue("report", body, locked: true);
        }
    }

    private void Enqueue(string type, JsonObject body, bool locked = false)
    {
        if (!locked) Monitor.Enter(_io);
        try
        {
            var now = _now();
            var item = new JsonObject { ["type"] = type, ["created"] = now.ToUnixTimeMilliseconds(), ["notBefore"] = 0L, ["attempts"] = 0, ["redactions"] = 0, ["body"] = body };
            var name = $"{now.ToUnixTimeMilliseconds():D13}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant()}-{type}.json";
            Write(Path.Combine(_o.QueueDir, name), item);
            Trim();
        }
        finally { if (!locked) Monitor.Exit(_io); }
    }

    private void Trim()
    {
        var files = QueueFiles();
        if (files.Count <= _o.MaxQueued) return;
        var ordered = files.OrderBy(f => f.Contains("-heartbeat", StringComparison.Ordinal) ? 0 : 1).ThenBy(f => f, StringComparer.Ordinal).ToList();
        foreach (var f in ordered.Take(files.Count - _o.MaxQueued)) { Delete(f); _dropped++; Log("queue full: dropped oldest item"); }
    }

    private List<string> QueueFiles()
    {
        try { return Directory.Exists(_o.QueueDir) ? Directory.GetFiles(_o.QueueDir, "*.json").OrderBy(f => f, StringComparer.Ordinal).ToList() : new List<string>(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new List<string>(); }
    }

    private static JsonObject? Read(string f)
    {
        try { return JsonNode.Parse(File.ReadAllText(f)) as JsonObject; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }

    private void Write(string f, JsonObject item)
    {
        try
        {
            var tmp = f + "." + Environment.ProcessId.ToString(CultureInfo.InvariantCulture) + ".tmp";
            File.WriteAllText(tmp, item.ToJsonString(JsonOut), new UTF8Encoding(false));
            File.Move(tmp, f, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Log("queue write failed"); }
    }

    private static void Delete(string f) { try { File.Delete(f); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { } }

    private void Log(string m) { try { _o.Log?.Invoke("[haishin-reporter] " + m); } catch (Exception) { } }

    // ---------------- 送る ----------------

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TimeSpan? next;
            try { next = await SendDueAsync(ct, ignoreNotBefore: false).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            catch (Exception e) { Log("sender error: " + e.GetType().Name); next = _o.MaxDelay; }
            try
            {
                if (next is { } wait) await Task.WhenAny(_wake.WaitAsync(ct), _delay(wait, ct)).ConfigureAwait(false);
                else await _wake.WaitAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
        }
    }

    /// <summary>Sends due items. Returns the wait until the next retry, or null when nothing waits.</summary>
    private async Task<TimeSpan?> SendDueAsync(CancellationToken ct, bool ignoreNotBefore)
    {
        await _sendLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            long? earliest = null;
            foreach (var f in QueueFiles())
            {
                ct.ThrowIfCancellationRequested();
                JsonObject? item;
                lock (_io) item = Read(f);
                if (item is null) { Delete(f); continue; }
                var type = item["type"]?.GetValue<string>() ?? "";
                var now = _now().ToUnixTimeMilliseconds();
                var created = item["created"]?.GetValue<long>() ?? 0;
                var maxAge = type == "heartbeat" ? _o.MaxPingAge : _o.MaxReportAge;
                if (now - created > maxAge.TotalMilliseconds) { Delete(f); _dropped++; Log($"dropped old {type}"); continue; }
                var notBefore = item["notBefore"]?.GetValue<long>() ?? 0;
                if (!ignoreNotBefore && notBefore > now) { earliest = Math.Min(earliest ?? long.MaxValue, notBefore); continue; }

                var path = type == "heartbeat" ? "v1/heartbeat" : "v1/reports";
            resend:
                var res = await _transport.PostJsonAsync(path, item["body"]!.ToJsonString(JsonOut), ct).ConfigureAwait(false);
                _certRejected = res.CertificateRejected;
                if (res.Status is >= 200 and < 300) { Delete(f); _sent++; continue; }
                if (res.Status == 422)
                {
                    _refused++;
                    var redactions = (item["redactions"]?.GetValue<int>() ?? 0) + 1;
                    if (redactions > MaxRedactions || !RedactRefusedField(item, res.Body)) { Delete(f); _dropped++; Log($"relay refused {type} (personal data); dropped"); continue; }
                    item["redactions"] = redactions;
                    _redacted++;
                    lock (_io) Write(f, item);
                    Log($"relay refused {type} (personal data); field replaced, sending again");
                    goto resend;   // 伏せた形ですぐ送り直す（回数は MaxRedactions まで）
                }
                if (res.Status is 400 or 404 or 405 or 413 or 415)
                {
                    // 形が合わない物は何度送っても通らない（404 は中継の場所の設定違い：数回だけ試す）
                    if (res.Status != 404 || (item["attempts"]?.GetValue<int>() ?? 0) >= 2) { Delete(f); _dropped++; Log($"relay rejected {type} ({res.Status}); dropped"); continue; }
                }
                var attempts = (item["attempts"]?.GetValue<int>() ?? 0) + 1;
                if (attempts >= _o.MaxAttempts) { Delete(f); _dropped++; Log($"{type} not delivered after {attempts} attempts; dropped"); continue; }
                var wait = Backoff(attempts, _o.BaseDelay, _o.MaxDelay, _rng.NextDouble());
                item["attempts"] = attempts;
                item["notBefore"] = now + (long)wait.TotalMilliseconds;
                lock (_io) Write(f, item);
                _retried++;
                earliest = Math.Min(earliest ?? long.MaxValue, now + (long)wait.TotalMilliseconds);
                if (res.Status == 0) break;   // つながらないときは後ろの物も今は送らない
            }
            if (earliest is null) return null;
            var ms = Math.Max(0, earliest.Value - _now().ToUnixTimeMilliseconds());
            return TimeSpan.FromMilliseconds(ms);
        }
        finally { _sendLock.Release(); }
    }

    /// <summary>Replaces the field named in the 422 answer ({ field, kind }) with "[伏せ字:kind]". False when it cannot.</summary>
    private static bool RedactRefusedField(JsonObject item, string? responseBody)
    {
        string? field = null, kind = null;
        try
        {
            if (!string.IsNullOrEmpty(responseBody) && JsonNode.Parse(responseBody) is JsonObject r)
            {
                field = r["field"]?.GetValue<string>();
                kind = r["kind"]?.GetValue<string>();
            }
        }
        catch (JsonException) { }
        var body = item["body"] as JsonObject;
        if (body is null || field is null) return false;
        var placeholder = ReportRedactor.FieldPlaceholder(kind);
        if (field == "os") { body["os"] = "Windows"; return true; }
        var m = FieldRe.Match(field);
        if (!m.Success) return false;
        var i = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
        if (body["reports"] is not JsonArray arr || i >= arr.Count || arr[i] is not JsonObject rep) return false;
        var name = m.Groups[2].Value;
        if (rep[name]?.GetValue<string>() == placeholder) return false;   // もう伏せてあるのに断られた
        rep[name] = placeholder;
        return true;
    }

    /// <summary>Stops the background sender (queued items stay on disk for the next start).</summary>
    public void Dispose()
    {
        _stop.Cancel();
        try { _loop?.Wait(TimeSpan.FromSeconds(1)); } catch (AggregateException) { }
        _stop.Dispose();
        _wake.Dispose();
        _sendLock.Dispose();
    }
}
