// 管理画面（ブラウザの WebCrypto）で署名した配信情報を、C# の UpdateSafetyKit で確かめる。
//
//   dotnet run -- <request.json>
//
// request.json:
//   { "domain": "...", "publicKeyPem": "...",
//     "manifests": [ { "name": "...", "manifest": { ... } }, ... ],      … 順番に端末へ届いたものとして判定する
//     "fleet": [ { "installId": "<32 桁の 16 進>", "currentVersion": "1.0.0" }, ... ],
//     "guardDevice": { "dataDir": "...", "appDir": "...", "installId": "...", "currentVersion": "1.0.0" } }   … 任意
//
// 出力（標準出力に JSON）: manifest ごとに、署名の結果・端末ごとの判定の数・入口（UpdateGuard.CheckRelease）の判定。
// fleet の各端末は「受け入れた最大の通し番号」をメモリで覚える（再送の拒否も確かめるため）。guardDevice は本物の状態ファイルに覚える。
using System.Text.Json;
using UpdateSafetyKit;

if (args.Length < 1 || !File.Exists(args[0])) { Console.Error.WriteLine("usage: HaishinVerify <request.json>"); return 2; }
using var doc = JsonDocument.Parse(File.ReadAllText(args[0]));
var root = doc.RootElement;
var options = new UpdateSafetyOptions { Domain = root.GetProperty("domain").GetString()!, Language = UpdateLanguage.Japanese }.Validate();
var pem = root.GetProperty("publicKeyPem").GetString();
var now = DateTimeOffset.UtcNow;

var fleet = new List<(string Id, string Current)>();
if (root.TryGetProperty("fleet", out var fl))
    foreach (var d in fl.EnumerateArray()) fleet.Add((d.GetProperty("installId").GetString()!, d.GetProperty("currentVersion").GetString()!));
var lastSeq = new long[fleet.Count];

UpdateGuard? guard = null;
string? guardCurrent = null;
if (root.TryGetProperty("guardDevice", out var gd))
{
    var dataDir = gd.GetProperty("dataDir").GetString()!;
    Directory.CreateDirectory(dataDir);
    File.WriteAllText(Path.Combine(dataDir, "install-id.txt"), gd.GetProperty("installId").GetString() + "\n");
    guard = new UpdateGuard(options, dataDir, gd.GetProperty("appDir").GetString()!, "SampleApp.exe");
    guardCurrent = gd.GetProperty("currentVersion").GetString();
}

var results = new List<object>();
foreach (var item in root.GetProperty("manifests").EnumerateArray())
{
    var name = item.GetProperty("name").GetString();
    var (release, perr) = ReleaseJson.FromManifest(item.GetProperty("manifest"), "windows");
    var sigErr = release is null ? perr : ReleaseSignature.VerifyV3(options, release, pem);

    var counts = new Dictionary<string, int>();
    var perDevice = new List<string>();
    for (int i = 0; i < fleet.Count; i++)
    {
        UpdateError? err = sigErr;
        if (err is null && release is not null) err = Freshness.Check(release.Policy, lastSeq[i], now);
        if (err is null && release?.Policy.Seq is { } s && s > lastSeq[i]) lastSeq[i] = s;
        var decision = Rollout.DecideOffer(true, release?.Version, fleet[i].Current, err is null ? release?.Policy : null, err, fleet[i].Id, null);
        var key = decision.Kind.ToString();
        counts[key] = counts.TryGetValue(key, out var n) ? n + 1 : 1;
        perDevice.Add(key);
    }

    object? guardResult = null;
    if (guard is not null)
    {
        var check = guard.CheckRelease(release, pem, guardCurrent!, true, now);
        guardResult = new { offer = check.Offer.Kind.ToString(), percent = check.Offer.Percent, error = check.Error?.Code.ToString(), message = check.Error?.Message(UpdateLanguage.Japanese) };
    }
    results.Add(new
    {
        name,
        version = release?.Version,
        seq = release?.Policy.Seq,
        signature = sigErr is null ? "ok" : sigErr.Code.ToString(),
        signatureMessage = sigErr?.Message(UpdateLanguage.Japanese),
        fleet = counts,
        decisions = perDevice,
        guard = guardResult,
    });
}
Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine(JsonSerializer.Serialize(new { runtime = Environment.Version.ToString(), results }, new JsonSerializerOptions { WriteIndented = false, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
return 0;
