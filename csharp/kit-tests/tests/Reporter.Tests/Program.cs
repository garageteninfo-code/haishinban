// 報告の送り手（CrashReporter）・伏せ字（ReportRedactor）・証明書の固定（HaishinHttp）の試験。依存ゼロの小さな仕組み。
//
//   dotnet run                       … 単体の試験（通信は偽物の送り先。ネットに出ない）
//   dotnet run -- --relay <https URL> --pin <指紋> --work <フォルダ>
//                                    … 本物の中継（この PC の中で起動した物）へ送る試験。Node の試験（test/csharp-reporter.test.mjs）から呼ぶ
// データはすべて架空。失敗が 1 件でもあれば終了コード 1。
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using UpdateSafetyKit;

int passed = 0, failed = 0;
void Check(string name, bool ok, string? detail = null)
{
    if (ok) { passed++; Console.WriteLine($"  PASS  {name}"); }
    else { failed++; Console.WriteLine($"  FAIL  {name}{(detail != null ? " — " + detail : "")}"); }
}
Console.OutputEncoding = System.Text.Encoding.UTF8;
string Arg(string n) { var i = Array.IndexOf(args, n); return i >= 0 && i + 1 < args.Length ? args[i + 1] : ""; }

if (args.Contains("--relay")) return await LiveRelay(Arg("--relay"), Arg("--pin"), Arg("--work"));

var root = Path.Combine(Path.GetTempPath(), "haishin-reporter-test-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)));
Directory.CreateDirectory(root);
try
{
    Console.WriteLine("== 1. reporterId（Node と同じ形） ==");
    Check("1.1 sha256(\"haishin-report|\" + installId) が Node の値と一致", CrashReporter.ReporterIdFor("00112233445566778899aabbccddeeff") == "58c74adf765193ee6decc8076100e9c6decd621ad231efca834ec82482506ea3");

    Console.WriteLine("== 2. 伏せ字 ==");
    string R(string s) => ReportRedactor.Redact(s, "yamada", "PC-SOUMU-01");
    Check("2.1 日本語の利用者名のパス", R(@"C:\Users\山田 花子\AppData\Local\App\a.json を読めない") == @"C:\Users\<user>\AppData\Local\App\a.json を読めない", R(@"C:\Users\山田 花子\AppData\Local\App\a.json を読めない"));
    Check("2.2 Public・既に伏せたパスはそのまま", R(@"C:\Users\Public\x C:\Users\<user>\y") == @"C:\Users\Public\x C:\Users\<user>\y");
    Check("2.3 /home/<名前>", R("open /home/taro/app.log failed") == "open /home/<user>/app.log failed");
    Check("2.4 今の Windows の利用者名・PC 名そのもの", R("user yamada on PC-SOUMU-01") == "user <user> on <pc>" && R("yamadas") == "yamadas", R("user yamada on PC-SOUMU-01"));
    Check("2.5 共有フォルダ", R(@"保存先 \\fileserv01\share\a.xlsx") == @"保存先 \\<server>\share\a.xlsx", R(@"保存先 \\fileserv01\share\a.xlsx"));
    Check("2.6 メール", R("送信先 taro.yamada@example.co.jp で失敗") == "送信先 <email> で失敗");
    Check("2.7 電話（ハイフン・全角・続き数字・+81）", R("TEL 06-1234-5678") == "TEL <phone>" && R("携帯 ０９０－１２３４－５６７８") == "携帯 <phone>" && R("09012345678") == "<phone>" && R("+81 90 1234 5678") == "<phone>", $"{R("携帯 ０９０－１２３４－５６７８")} / {R("+81 90 1234 5678")}");
    Check("2.8 カード（Luhn が合う物だけ）", R("カード 4111 1111 1111 1111") == "カード <card>" && R("番号 4111 1111 1111 1112") == "番号 4111 1111 1111 1112");
    var myNo = MakeMyNumber();
    Check("2.9 マイナンバー：言葉つき・4-4-4 は伏せる", R($"マイナンバー {myNo} の行") == "マイナンバー <my_number> の行" && R($"{myNo[..4]}-{myNo[4..8]}-{myNo[8..]}") == "<my_number>");
    Check("2.10 マイナンバー：言葉なしの 12 桁（伝票番号）は残す", R($"伝票番号 {myNo} の保存中") == $"伝票番号 {myNo} の保存中");
    Check("2.11 敬称つきの名前", R("顧客 山田太郎様の伝票") == "顧客 <name>様の伝票" && R("担当 タナカさん") == "担当 <name>さん" && R("利用者様の画面") == "利用者様の画面", R("顧客 山田太郎様の伝票"));
    Check("2.12 鍵・合言葉・Bearer・URL の中の合言葉", R("password=Hunter2pass!") == "password=[伏せ字]" && R("Authorization: Bearer abcdefghijklmnop1234") == "Authorization: Bearer [伏せ字]"
        && R("key sk-ant-abcdefghijklmnop") == "key [伏せ字:key]" && R("https://u:secret1@db.example/") == "https://[伏せ字]@db.example/", R("password=Hunter2pass!"));
    Check("2.13 秘密鍵の塊", R("-----BEGIN PRIVATE KEY-----\nMIGH\n-----END PRIVATE KEY-----") == "[伏せ字:private_key]");
    Check("2.14 IPv4（127.x は残す）・郵便番号", R("接続先 192.168.10.5 と 127.0.0.1") == "接続先 <ip> と 127.0.0.1" && R("〒530-0001 へ") == "<postal> へ");
    Check("2.15 住所は伏せない（中継が断る → 欄ごと伏せる、の役割分担）", R("大阪府大阪市北区梅田1丁目2-3") == "大阪府大阪市北区梅田1丁目2-3");
    Check("2.16 呼び出し履歴：組み立てた PC のフォルダを消し、ファイル名と行は残す",
        ReportRedactor.RedactStack(@"   at App.Form1.Save() in C:\Users\dev\src\App\Form1.cs:line 42", "x", "y") == "   at App.Form1.Save() in Form1.cs:line 42");
    Check("2.17 業務の文はそのまま", R("在庫の保存に失敗しました（伝票 123456789012・数量 30）") == "在庫の保存に失敗しました（伝票 123456789012・数量 30）");

    Console.WriteLine("== 3. 報告の形 ==");
    Exception Thrown(string msg) { try { throw new InvalidOperationException(msg); } catch (Exception e) { return e; } }
    var e1 = Thrown("顧客 山田太郎様の保存に失敗\n2 行目");
    var e2 = Thrown("別の文");
    var rep = CrashReporter.BuildReport(e1, "crash", DateTimeOffset.UtcNow, null, "yamada", "PC1");
    Check("3.1 題名は 1 行・伏せ字・200 文字以内", rep["title"]!.GetValue<string>() == "InvalidOperationException: 顧客 <name>様の保存に失敗");
    Check("3.2 同じ型・同じ場所なら同じ指紋（文が違っても）", rep["fingerprint"]!.GetValue<string>() == CrashReporter.BuildReport(e2, "crash", DateTimeOffset.UtcNow)["fingerprint"]!.GetValue<string>());
    Check("3.3 指紋の形（中継の規則 [A-Za-z0-9_-] 8〜128）", System.Text.RegularExpressions.Regex.IsMatch(rep["fingerprint"]!.GetValue<string>(), "^[A-Za-z0-9_-]{8,128}$"));
    var big = CrashReporter.BuildReport(Thrown(new string('あ', 5000)), "error", DateTimeOffset.UtcNow);
    Check("3.4 長さの上限（message 2000・title 200）", big["message"]!.GetValue<string>().Length <= 2000 && big["title"]!.GetValue<string>().Length <= 200 && big["kind"]!.GetValue<string>() == "error");

    Console.WriteLine("== 4. 待ち時間（指数・ゆらぎ・上限） ==");
    var b = TimeSpan.FromSeconds(2); var mx = TimeSpan.FromMinutes(5);
    Check("4.1 1 回目は 1〜2 秒", CrashReporter.Backoff(1, b, mx, 0) == TimeSpan.FromSeconds(1) && CrashReporter.Backoff(1, b, mx, 1) == TimeSpan.FromSeconds(2));
    Check("4.2 倍々に延びる", CrashReporter.Backoff(4, b, mx, 1) == TimeSpan.FromSeconds(16));
    Check("4.3 上限 5 分を超えない", CrashReporter.Backoff(40, b, mx, 1) == mx);

    Console.WriteLine("== 5. 送り手（偽物の送り先） ==");
    var n = 0;
    CrashReporterOptions Opt(string name, int maxAttempts = 5) => new()
    {
        AppVersion = "1.1.0", QueueDir = Path.Combine(root, name, "queue"), InstallIdPath = Path.Combine(root, name, "install-id.txt"),
        Os = "Windows 10.0.26100", MaxAttempts = maxAttempts, BaseDelay = TimeSpan.FromMilliseconds(1), MaxDelay = TimeSpan.FromMilliseconds(5),
    };
    async Task<(FakeTransport t, CrashReporter r)> Run(string name, Func<string, string, TransportResult> answer, Action<CrashReporter> act, int maxAttempts = 5)
    {
        var t = new FakeTransport(answer);
        var r = new CrashReporter(Opt(name, maxAttempts), t, delay: (_, _) => Task.CompletedTask);
        act(r);
        await WaitDone(r, t, TimeSpan.FromSeconds(5));
        return (t, r);
    }
    {
        var (t, r) = await Run("ok", (_, _) => new(200, "{}"), r => { r.SendStartupPing(); r.Start(); });
        Check("5.1 起動の知らせが届く・置き場は空", t.Calls.Count == 1 && t.Calls[0].Path == "v1/heartbeat" && r.Stats.Queued == 0);
        var body = JsonNode.Parse(t.Calls[0].Json)!;
        Check("5.2 installId そのものは送らない（reporterId だけ）", body["reporterId"]!.GetValue<string>() == CrashReporter.ReporterIdFor(File.ReadAllText(Path.Combine(root, "ok", "install-id.txt")).Trim())
            && !t.Calls[0].Json.Contains(File.ReadAllText(Path.Combine(root, "ok", "install-id.txt")).Trim()));
        r.Dispose();
    }
    {
        n = 0;
        var (t, r) = await Run("retry", (_, _) => ++n <= 2 ? new(n == 1 ? 503 : 0, null) : new(200, "{}"), r => { r.ReportException(Thrown("x"), crash: true); r.Start(); });
        Check("5.3 503・通信の失敗は待ってから送り直し、3 回目で届く", t.Calls.Count == 3 && r.Stats.Sent == 1 && r.Stats.Retried == 2, $"calls {t.Calls.Count} {r.Stats}");
        r.Dispose();
    }
    {
        var (t, r) = await Run("giveup", (_, _) => new(429, null), r => { r.ReportException(Thrown("x")); r.Start(); }, maxAttempts: 3);
        Check("5.4 届かないまま上限の回数に達したら捨てる", t.Calls.Count == 3 && r.Stats.Dropped == 1 && r.Stats.Queued == 0, $"calls {t.Calls.Count} {r.Stats}");
        r.Dispose();
    }
    {
        // 中継が住所を見つけて 422（端末の伏せ字は住所を伏せない）→ その欄を丸ごと伏せて送り直す
        var (t, r) = await Run("refuse", (p, j) => RefuseAddress(j),
            r => { r.ReportException(Thrown("配送先 大阪府大阪市北区梅田1丁目2-3 で失敗")); r.Start(); });
        var last = JsonNode.Parse(t.Calls[^1].Json)!["reports"]![0]!;
        Check("5.5 422 → 断られた欄（題名・本文）を「[伏せ字:address]」にして送り直し、受け取られる", t.Calls.Count == 3 && last["message"]!.GetValue<string>() == "[伏せ字:address]" && last["title"]!.GetValue<string>() == "[伏せ字:address]" && r.Stats.Sent == 1 && r.Stats.Redacted == 2, $"calls {t.Calls.Count} {r.Stats}");
        Check("5.6 送り直しでも指紋・呼び出し履歴は残る", last["fingerprint"]!.GetValue<string>().StartsWith("ex-", StringComparison.Ordinal) && last["stack"]!.GetValue<string>().Contains("at ", StringComparison.Ordinal));
        Check("5.7 断られた中身は置き場のファイルにも残らない", !Directory.GetFiles(Path.Combine(root, "refuse", "queue")).Any(f => File.ReadAllText(f).Contains("梅田")));
        r.Dispose();
    }
    {
        var (t, r) = await Run("refuse-always", (_, _) => new(422, "{\"field\":\"reports[0].title\",\"kind\":\"name\"}"), r => { r.ReportException(Thrown("x")); r.Start(); });
        Check("5.8 伏せても断られ続けたら捨てる（無限に送らない）", r.Stats.Dropped == 1 && r.Stats.Queued == 0 && t.Calls.Count <= 3, $"calls {t.Calls.Count} {r.Stats}");
        r.Dispose();
    }
    {
        var (t, r) = await Run("bad", (_, _) => new(400, "{\"error\":\"invalid_payload\"}"), r => { r.ReportException(Thrown("x")); r.Start(); });
        Check("5.9 400（形が合わない）は送り直さずに捨てる", t.Calls.Count == 1 && r.Stats.Dropped == 1);
        r.Dispose();
    }
    {
        // つながらない間は置き場に残り、次の起動（別の CrashReporter）で送られる
        var offline = new FakeTransport((_, _) => new(0, null));
        var r1 = new CrashReporter(Opt("persist", maxAttempts: 50), offline, delay: (_, _) => Task.Delay(50));
        r1.ReportCrashAndFlush(Thrown("落ちた"), TimeSpan.FromMilliseconds(200));
        r1.Dispose();
        var left = Directory.GetFiles(Path.Combine(root, "persist", "queue"), "*.json").Length;
        var online = new FakeTransport((_, _) => new(200, "{}"));
        var r2 = new CrashReporter(Opt("persist"), online, delay: (_, _) => Task.CompletedTask);
        r2.Start();
        await WaitQueued(r2, 0, TimeSpan.FromSeconds(5));
        Check("5.10 落ちる直前の報告はファイルに残り、次の起動で届く", left == 1 && online.Calls.Count == 1 && online.Calls[0].Json.Contains("\"kind\":\"crash\""), $"left {left} calls {online.Calls.Count}");
        r2.Dispose();
    }
    {
        var hold = new FakeTransport((_, _) => new(0, null));
        var r = new CrashReporter(Opt("dedup"), hold, delay: (_, _) => Task.Delay(10000));
        for (int i = 0; i < 5; i++) r.ReportCrashAndFlush(Thrown("同じ"), TimeSpan.Zero);
        var files = Directory.GetFiles(Path.Combine(root, "dedup", "queue"), "*.json");
        Check("5.11 同じ落ち方は 1 件にまとめて回数を足す", files.Length == 1 && JsonNode.Parse(File.ReadAllText(files[0]))!["body"]!["reports"]![0]!["count"]!.GetValue<int>() == 5);
        r.Dispose();
    }
    {
        var hold = new FakeTransport((_, _) => new(0, null));
        var o = Opt("cap"); o = new CrashReporterOptions { AppVersion = o.AppVersion, QueueDir = o.QueueDir, InstallIdPath = o.InstallIdPath, MaxQueued = 5 };
        var r = new CrashReporter(o, hold);
        for (int i = 0; i < 9; i++) r.SendStartupPing();
        Check("5.12 置き場の数に上限（古い物から捨てる）", Directory.GetFiles(o.QueueDir, "*.json").Length == 5);
        r.Dispose();
    }
    {
        // 画面を止めない：送り先が 3 秒かかっても、呼んだ側はすぐ戻る
        var slow = new FakeTransport((_, _) => { Thread.Sleep(3000); return new(200, "{}"); });
        var r = new CrashReporter(Opt("noblock"), slow);
        r.Start();
        var sw = Stopwatch.StartNew();
        r.SendStartupPing();
        r.ReportException(Thrown("x"));
        sw.Stop();
        Check("5.13 送り先が遅くても呼び出しはすぐ戻る（画面を止めない）", sw.ElapsedMilliseconds < 200, $"{sw.ElapsedMilliseconds} ms");
        r.Dispose();
    }

    Console.WriteLine("== 6. 接続の設定・証明書の固定 ==");
    Check("6.1 http（暗号化なし）は既定で断る・127.0.0.1 は可", Throws(() => new HaishinConnectionOptions { BaseUrl = new Uri("http://haishin.example.local:38920/") }.Validate())
        && !Throws(() => new HaishinConnectionOptions { BaseUrl = new Uri("http://127.0.0.1:38920/") }.Validate()));
    Check("6.2 固定の指紋は https だけ・形が違えば断る", Throws(() => new HaishinConnectionOptions { BaseUrl = new Uri("http://127.0.0.1:1/"), PinnedCertSha256 = new[] { new string('a', 64) } }.Validate())
        && Throws(() => new HaishinConnectionOptions { PinnedCertSha256 = new[] { "abc" } }.Validate()));
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    using var cert = new CertificateRequest("CN=haishin-test", key, HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    var fp = Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();
    var colon = string.Join(":", Enumerable.Range(0, 32).Select(i => fp.Substring(i * 2, 2).ToUpperInvariant()));
    Check("6.3 「AB:CD:…」の形の指紋も読める", HaishinConnectionOptions.NormalizePin(colon) == fp);
    Check("6.4 指紋が合う証明書だけ受け入れる（自己署名でも）", HaishinHttp.ValidateServerCertificate(cert, System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors, new[] { fp })
        && !HaishinHttp.ValidateServerCertificate(cert, System.Net.Security.SslPolicyErrors.None, new[] { new string('0', 64) }));
    Check("6.5 指紋を入れないときは Windows の普通の確かめ（自己署名は断る）", !HaishinHttp.ValidateServerCertificate(cert, System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors, Array.Empty<string>()));
}
finally { try { Directory.Delete(root, true); } catch (IOException) { } }

Console.WriteLine($"== 合計: {passed} 合格 / {failed} 不合格 ==");
return failed == 0 ? 0 : 1;

static bool Throws(Action a) { try { a(); return false; } catch (ArgumentException) { return true; } }

static async Task WaitQueued(CrashReporter r, int target, TimeSpan max)
{
    var sw = Stopwatch.StartNew();
    while (sw.Elapsed < max && r.Stats.Queued != target) await Task.Delay(20);
    await Task.Delay(50);
}

// 送り先が 1 回以上呼ばれ、置き場が空になり、少し落ち着くまで待つ
static async Task WaitDone(CrashReporter r, FakeTransport t, TimeSpan max)
{
    var sw = Stopwatch.StartNew();
    int stable = 0;
    while (sw.Elapsed < max && stable < 5)
    {
        await Task.Delay(20);
        int calls; lock (t.Calls) calls = t.Calls.Count;
        stable = calls > 0 && r.Stats.Queued == 0 ? stable + 1 : 0;
    }
}

// 偽物の中継：住所（梅田）が入っている最初の欄を 422 で断る
static TransportResult RefuseAddress(string json)
{
    var rep = JsonNode.Parse(json)!["reports"]![0]!;
    foreach (var f in new[] { "title", "message", "stack" })
        if (rep[f]!.GetValue<string>().Contains("梅田", StringComparison.Ordinal))
            return new(422, "{\"error\":\"personal_data_refused\",\"field\":\"reports[0]." + f + "\",\"kind\":\"address\"}");
    return new(200, "{}");
}

static string MakeMyNumber()
{
    var d = string.Concat(Enumerable.Range(0, 11).Select(_ => RandomNumberGenerator.GetInt32(10).ToString(System.Globalization.CultureInfo.InvariantCulture)));
    int sum = 0;
    for (int n = 1; n <= 11; n++) sum += (d[11 - n] - '0') * (n <= 6 ? n + 1 : n - 5);
    int r = sum % 11;
    return d + (r <= 1 ? 0 : 11 - r).ToString(System.Globalization.CultureInfo.InvariantCulture);
}

// 本物の中継へ（Node の試験から呼ぶ）。正しい指紋で届く・違う指紋では送らない・422 で欄を伏せて送り直す。
async Task<int> LiveRelay(string relay, string pin, string work)
{
    Directory.CreateDirectory(work);
    var conn = new HaishinConnectionOptions { BaseUrl = new Uri(relay), PinnedCertSha256 = new[] { pin } };
    using var http = HaishinHttp.CreateClient(conn);
    var o = new CrashReporterOptions { AppVersion = "1.1.0", QueueDir = Path.Combine(work, "q"), InstallIdPath = Path.Combine(work, "install-id.txt"), BaseDelay = TimeSpan.FromMilliseconds(50), MaxDelay = TimeSpan.FromMilliseconds(200) };
    using (var r = new CrashReporter(o, new HttpReportTransport(http)))
    {
        r.Start();
        r.SendStartupPing();
        Exception ex; try { throw new IOException(@"C:\Users\山田 花子\Documents\在庫.xlsx を開けません。配送先 大阪府大阪市北区梅田1丁目2-3"); } catch (Exception e) { ex = e; }
        r.ReportException(ex, crash: true);
        await Task.Delay(300);
        await r.FlushAsync(TimeSpan.FromSeconds(10));
        var st = r.Stats;
        Check("L.1 正しい指紋：起動の知らせと報告が届く", st.Sent == 2 && st.Queued == 0, st.ToString());
        Check("L.2 住所入りは中継に 422 で断られ、欄を伏せて送り直して届いた", st.Refused >= 1 && st.Redacted >= 1, st.ToString());
    }
    var bad = new HaishinConnectionOptions { BaseUrl = new Uri(relay), PinnedCertSha256 = new[] { new string('0', 64) } };
    using var http2 = HaishinHttp.CreateClient(bad);
    var o2 = new CrashReporterOptions { AppVersion = "1.1.0", QueueDir = Path.Combine(work, "q2"), InstallIdPath = Path.Combine(work, "install-id.txt"), MaxAttempts = 2, BaseDelay = TimeSpan.Zero, MaxDelay = TimeSpan.Zero };
    using (var r2 = new CrashReporter(o2, new HttpReportTransport(http2)))
    {
        r2.SendStartupPing();
        await r2.FlushAsync(TimeSpan.FromSeconds(5));
        Check("L.3 違う指紋：送らない（証明書を断ったと分かる）", r2.Stats.Sent == 0 && r2.Stats.LastCertificateRejected, r2.Stats.ToString());
    }
    var m = await ManifestClient.FetchAsync(http2);
    Check("L.4 違う指紋：配信情報も取らない（CertificateRejected）", m.Problem == FetchProblem.CertificateRejected, m.Problem.ToString());
    Console.WriteLine($"== 合計: {passed} 合格 / {failed} 不合格 ==");
    return failed == 0 ? 0 : 1;
}

sealed class FakeTransport : IReportTransport
{
    private readonly Func<string, string, TransportResult> _answer;
    public List<(string Path, string Json)> Calls { get; } = new();
    public FakeTransport(Func<string, string, TransportResult> answer) => _answer = answer;
    public Task<TransportResult> PostJsonAsync(string path, string json, CancellationToken ct)
    {
        lock (Calls) Calls.Add((path, json));
        return Task.FromResult(_answer(path, json));
    }
}
