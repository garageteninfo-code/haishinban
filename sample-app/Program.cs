// 配信番のサンプルアプリ（架空の「在庫管理」）。組み込み方の見本：
//   1. 起動の最初に SessionMarkerFile.Begin → UpdateGuard.StartupCheck（続けて落ちていたら前の版へ戻す手順を起動して終わる）
//   2. CrashReporter を作って Start・起動の知らせ（SendStartupPing）・処理されなかった例外を報告につなぐ
//   3. 画面を出したあと、裏で配信情報を取り（ManifestClient）、UpdateGuard.CheckRelease で「出すか」を決めて表示する
//   4. 普通に閉じたら marker.End()（「正常に終わった」印）
//
// 引数（試験・台本用。本物のアプリには要らない）:
//   --config <file>        設定（既定：exe の隣の sampleapp.json）
//   --data-dir <dir>       状態・報告の置き場（既定：%LOCALAPPDATA%\HaishinSampleApp）
//   --app-version <版>     動いている版のふり（既定：アセンブリの版 1.0.0）
//   --auto check|crash     画面を出して自動で「確認」して閉じる／「落ちたことにする」を押す
//   --result <file>        自動のときの結果（JSON）の書き出し先
//   --crash-message <文>   「落ちたことにする」の例外の文（架空の個人情報を入れて伏せ字を試す）
using System.Reflection;
using System.Text.Json;
using UpdateSafetyKit;

namespace HaishinSample;

internal static class Program
{
    internal static AppContextData Ctx = null!;

    [STAThread]
    private static int Main(string[] args)
    {
        string Arg(string n) { var i = Array.IndexOf(args, n); return i >= 0 && i + 1 < args.Length ? args[i + 1] : ""; }
        var cfgFile = Arg("--config");
        if (cfgFile.Length == 0) cfgFile = Path.Combine(AppContext.BaseDirectory, "sampleapp.json");
        SampleConfig cfg;
        try { cfg = SampleConfig.Load(cfgFile); }
        catch (Exception ex) when (ex is IOException or JsonException or ArgumentException or UnauthorizedAccessException)
        {
            MessageBox.Show($"設定を読めません：{cfgFile}\n{ex.Message}\n（sampleapp.example.json を見本にしてください）", "配信番サンプル", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 2;
        }
        var version = Arg("--app-version");
        if (version.Length == 0) version = Assembly.GetExecutingAssembly().GetName().Version is { } v ? $"{v.Major}.{v.Minor}.{v.Build}" : "1.0.0";
        var dataDir = Arg("--data-dir");
        if (dataDir.Length == 0) dataDir = cfg.DataDir.Length > 0 ? cfg.DataDir : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HaishinSampleApp");
        Directory.CreateDirectory(dataDir);

        // 1. 起動直後：前回の終わり方を見て、必要なら前の版へ戻す
        var options = new UpdateSafetyOptions { Domain = cfg.Domain, Language = UpdateLanguage.Japanese }.Validate();
        var guard = new UpdateGuard(options, dataDir, AppContext.BaseDirectory, "SampleApp.exe");
        using var marker = SessionMarkerFile.Begin(guard.MarkerPath, version);
        var start = guard.StartupCheck(version, marker.Previous);
        if (start.RollbackStarted) return 0;   // 戻しの手順が動き出した。すぐ終わる

        // 2. 報告の送り手（画面を止めない。送れない間は dataDir\haishin-queue に残る）
        using var http = HaishinHttp.CreateClient(new HaishinConnectionOptions { BaseUrl = new Uri(cfg.RelayUrl), PinnedCertSha256 = cfg.PinnedCertSha256 });
        using var reporter = new CrashReporter(new CrashReporterOptions
        {
            AppVersion = version, QueueDir = Path.Combine(dataDir, "haishin-queue"), InstallIdPath = guard.InstallIdPath,
            BaseDelay = TimeSpan.FromSeconds(2), MaxDelay = TimeSpan.FromMinutes(5),
        }, new HttpReportTransport(http));
        reporter.Start();
        reporter.SendStartupPing();
        reporter.AttachToAppDomain();

        Ctx = new AppContextData(cfg, version, dataDir, options, guard, http, reporter, start, Arg("--auto"), Arg("--result"), Arg("--crash-message"));

        // 画面の側の例外：報告をファイルに置いてから（最長 3 秒送ってみて）終わる。印は消さない＝次の起動で「異常終了」と分かる
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) =>
        {
            var delivered = reporter.ReportCrashAndFlush(e.Exception, TimeSpan.FromSeconds(3));
            Ctx.WriteResult(new { mode = "crash", version, delivered, stats = reporter.Stats });
            if (Ctx.Auto.Length == 0)
                MessageBox.Show(delivered ? "問題が起きたので終了します。報告を送りました（個人情報は伏せ字にしています）。" : "問題が起きたので終了します。報告は次の起動で送ります。",
                    "在庫管理（サンプル）", MessageBoxButtons.OK, MessageBoxIcon.Error);
            Environment.Exit(3);
        };

        Application.EnableVisualStyles();
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());

        // 4. 普通に閉じた
        marker.End();
        reporter.FlushAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
        return 0;
    }
}

internal sealed record AppContextData(SampleConfig Cfg, string Version, string DataDir, UpdateSafetyOptions Options, UpdateGuard Guard,
    HttpClient Http, CrashReporter Reporter, UpdateGuard.StartupResult Start, string Auto, string ResultFile, string CrashMessage)
{
    private static readonly JsonSerializerOptions J = new() { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    public void WriteResult(object o)
    {
        if (ResultFile.Length == 0) return;
        try { File.WriteAllText(ResultFile, JsonSerializer.Serialize(o, J)); } catch (IOException) { }
    }
}

internal sealed class SampleConfig
{
    public string Domain { get; init; } = "sample-app";
    public string RelayUrl { get; init; } = "";
    public string[] PinnedCertSha256 { get; init; } = Array.Empty<string>();
    public string PublicKeyFile { get; init; } = "public-key.pem";
    public string DataDir { get; init; } = "";
    /// <summary>The publisher public key (PEM). A real app embeds it in the program instead of reading a file.</summary>
    public string PublicKeyPem { get; private set; } = "";

    public static SampleConfig Load(string file)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(file));
        var r = doc.RootElement;
        string S(string n, string d) => r.TryGetProperty(n, out var x) && x.ValueKind == JsonValueKind.String ? x.GetString() ?? d : d;
        var pins = r.TryGetProperty("pinnedCertSha256", out var p) && p.ValueKind == JsonValueKind.Array ? p.EnumerateArray().Select(e => e.GetString() ?? "").ToArray() : Array.Empty<string>();
        var c = new SampleConfig { Domain = S("domain", "sample-app"), RelayUrl = S("relayUrl", ""), PinnedCertSha256 = pins, PublicKeyFile = S("publicKeyFile", "public-key.pem"), DataDir = S("dataDir", "") };
        if (c.RelayUrl.Length == 0) throw new ArgumentException("relayUrl がありません");
        var pk = Path.IsPathRooted(c.PublicKeyFile) ? c.PublicKeyFile : Path.Combine(Path.GetDirectoryName(Path.GetFullPath(file)) ?? ".", c.PublicKeyFile);
        c.PublicKeyPem = File.Exists(pk) ? File.ReadAllText(pk) : "";
        return c;
    }
}
