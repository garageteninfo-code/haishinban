// UpdateSafetyKit の試験（依存ゼロの小さな試験の仕組み）。失敗が 1 件でもあれば終了コード 1。
//   引数: [1] tools の xlang JSON（任意） [2] 原本の v2 の共通の例（任意・互換の確認）
//   環境変数 USK_LIVE_DIR があれば、そのフォルダの中で実際に cmd / robocopy を走らせる（Windows のみ）。
//   鍵はすべてこの実行の間だけメモリで作る。
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UpdateSafetyKit;

int passed = 0, failed = 0;
var failures = new List<string>();
void Check(string name, bool ok, string? detail = null)
{
    if (ok) { passed++; Console.WriteLine($"  PASS  {name}"); }
    else { failed++; failures.Add(name); Console.WriteLine($"  FAIL  {name}{(detail != null ? " — " + detail : "")}"); }
}
bool Throws<T>(Action a) where T : Exception { try { a(); return false; } catch (T) { return true; } }

var O = new UpdateSafetyOptions { Domain = "myapp", MutableDirs = new[] { "data", @"backend\data" } }.Validate();
using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var pub = new string(PemEncoding.Write("PUBLIC KEY", key.ExportSubjectPublicKeyInfo()));
using var wrong = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var wrongPub = new string(PemEncoding.Write("PUBLIC KEY", wrong.ExportSubjectPublicKeyInfo()));
string Sign(string payload) => Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
var sha = new string('a', 64);
ReleaseInfo Rel(string version, ReleasePolicy p, Func<string, string>? signer = null, long size = 100)
{
    var r = new ReleaseInfo("windows", version, sha, size, p, null);
    return r with { SignatureV3 = (signer ?? Sign)(ReleaseSignature.BuildPayloadV3(O, r.Os, r.Version, r.Sha256, r.Size, r.Policy)) };
}

string? FindUp(string rel)
{
    var d = new DirectoryInfo(AppContext.BaseDirectory);
    while (d != null && !File.Exists(Path.Combine(d.FullName, rel))) d = d.Parent;
    return d == null ? null : Path.Combine(d.FullName, rel);
}

Console.WriteLine("== 1. v3 の共通の例（Node と同じ文字列） ==");
{
    var f = FindUp(Path.Combine("tests", "vectors", "payload-v3-cases.json"));
    Check("1.0 共通の例が見つかる", f != null);
    if (f != null)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(f));
        foreach (var c in doc.RootElement.GetProperty("valid").EnumerateArray())
        {
            var o = new UpdateSafetyOptions { Domain = c.GetProperty("domain").GetString()! };
            var (p, e) = ReleaseJson.ParsePolicy(c.GetProperty("manifest"));
            var got = p is null ? "(error " + e + ")" : ReleaseSignature.BuildPayloadV3(o, c.GetProperty("os").GetString(), c.GetProperty("version").GetString(), c.GetProperty("sha256").GetString(), c.GetProperty("size").GetInt64(), p);
            Check("1.v " + c.GetProperty("name").GetString(), got == c.GetProperty("payload").GetString(), got);
        }
        foreach (var c in doc.RootElement.GetProperty("invalid").EnumerateArray())
        {
            var refused = false;
            try
            {
                var o = new UpdateSafetyOptions { Domain = c.GetProperty("domain").GetString()! }.Validate();
                var (p, e) = ReleaseJson.ParsePolicy(c.GetProperty("manifest"));
                if (p is null) refused = true;
                else ReleaseSignature.BuildPayloadV3(o, c.GetProperty("os").GetString(), c.GetProperty("version").GetString(), c.GetProperty("sha256").GetString(), c.GetProperty("size").GetInt64(), p);
            }
            catch (ArgumentException) { refused = true; }
            Check("1.i 署名しない: " + c.GetProperty("name").GetString(), refused);
        }
    }
}

Console.WriteLine("== 2. 元の形（v2）との互換 ==");
{
    var f = args.Length > 1 ? args[1] : null;
    if (f != null && File.Exists(f))
    {
        var compat = new UpdateSafetyOptions { Domain = "legacy-update" };
        using var doc = JsonDocument.Parse(File.ReadAllText(f));
        int n = 0, ok = 0;
        foreach (var c in doc.RootElement.GetProperty("valid").EnumerateArray())
        {
            n++;
            var (p, _) = ReleaseJson.ParsePolicy(c.GetProperty("manifest"));
            if (p != null && ReleaseSignature.BuildPayloadV2(compat, c.GetProperty("os").GetString(), c.GetProperty("version").GetString(), c.GetProperty("sha256").GetString(), c.GetProperty("size").GetInt64(), p.Rollout, p.BadVersions) == c.GetProperty("payload").GetString()) ok++;
        }
        Check($"2.1 元の v2 の例と同じ文字列（{ok}/{n}）", n > 0 && ok == n);
        int m = 0, rej = 0;
        foreach (var c in doc.RootElement.GetProperty("invalid").EnumerateArray()) { m++; if (ReleaseJson.ParsePolicy(c.GetProperty("manifest")).Policy is null) rej++; }
        Check($"2.2 元の不正な例はすべて拒否（{rej}/{m}）", m > 0 && rej == m);
    }
    else Console.WriteLine("  （元の例の場所が渡されていないので飛ばしました）");
    var h = SHA256.HashData(Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef" + "s"));
    Check("2.3 組の計算は元と同じ（sha256(installId+salt) 先頭 2 バイト mod 100）", Rollout.Bucket("0123456789abcdef0123456789abcdef", "s") == ((h[0] << 8) | h[1]) % 100);
}

Console.WriteLine("== 3. 署名 v3（改ざん・鍵違い・形） ==");
{
    var pol = new ReleasePolicy(new RolloutSpec(10, "s1"), new[] { "1.0.9" }, 5, 4102444800);
    var r = Rel("1.1.0", pol);
    Check("3.1 正しい署名は通る", ReleaseSignature.VerifyV3(O, r, pub) == null);
    Check("3.2 sha256 の改ざんは落ちる", ReleaseSignature.VerifyV3(O, r with { Sha256 = new string('b', 64) }, pub)?.Code == UpdateErrorCode.SignatureMismatch);
    Check("3.3 割合の改ざん（10→100）は落ちる", ReleaseSignature.VerifyV3(O, r with { Policy = pol with { Rollout = new RolloutSpec(100, "s1") } }, pub) != null);
    Check("3.4 不具合版の削除は落ちる", ReleaseSignature.VerifyV3(O, r with { Policy = pol with { BadVersions = Array.Empty<string>() } }, pub) != null);
    Check("3.5 通し番号の改ざんは落ちる", ReleaseSignature.VerifyV3(O, r with { Policy = pol with { Seq = 6 } }, pub) != null);
    Check("3.6 期限の改ざん・削除は落ちる", ReleaseSignature.VerifyV3(O, r with { Policy = pol with { ExpiresAt = 4102444801 } }, pub) != null && ReleaseSignature.VerifyV3(O, r with { Policy = pol with { ExpiresAt = null } }, pub) != null);
    Check("3.7 版・大きさ・OS の改ざんは落ちる", ReleaseSignature.VerifyV3(O, r with { Version = "1.1.1" }, pub) != null && ReleaseSignature.VerifyV3(O, r with { Size = 101 }, pub) != null && ReleaseSignature.VerifyV3(O, r with { Os = "linux" }, pub) != null);
    Check("3.8 別の鍵では落ちる", ReleaseSignature.VerifyV3(O, r, wrongPub)?.Code == UpdateErrorCode.SignatureMismatch);
    Check("3.9 別の製品名（Domain）の署名は使い回せない", ReleaseSignature.VerifyV3(new UpdateSafetyOptions { Domain = "other" }, r, pub) != null);
    var v2sig = Sign(ReleaseSignature.BuildPayloadV2(O, "windows", "1.1.0", sha, 100, pol.Rollout, pol.BadVersions));
    Check("3.10 v2 の署名を v3 として使い回せない", ReleaseSignature.VerifyV3(O, r with { SignatureV3 = v2sig }, pub) != null);
    Check("3.11 署名なし・鍵なし・壊れた署名は拒否（fail-closed）",
        ReleaseSignature.VerifyV3(O, r with { SignatureV3 = null }, pub)?.Code == UpdateErrorCode.NoSignature
        && ReleaseSignature.VerifyV3(O, r, null)?.Code == UpdateErrorCode.NoPublicKey
        && ReleaseSignature.VerifyV3(O, r with { SignatureV3 = "not base64!!" }, pub)?.Code == UpdateErrorCode.BadSignatureEncoding
        && ReleaseSignature.VerifyV3(O, r, "-----BEGIN PUBLIC KEY-----\nzzzz\n-----END PUBLIC KEY-----")?.Code == UpdateErrorCode.VerifyFailed);
    var p1363 = Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(ReleaseSignature.BuildPayloadV3(O, "windows", "1.1.0", sha, 100, pol)), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    Check("3.12 形式違い（P1363）の署名は落ちる", ReleaseSignature.VerifyV3(O, r with { SignatureV3 = p1363 }, pub) != null);
    using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    Check("3.13 P-256 以外の公開鍵は使わない", ReleaseSignature.VerifyV3(O, r, new string(PemEncoding.Write("PUBLIC KEY", p384.ExportSubjectPublicKeyInfo())))?.Code == UpdateErrorCode.VerifyFailed);
    Check("3.14 版に | や非 ASCII を入れた情報は検証の前に拒否（InvalidField）",
        ReleaseSignature.VerifyV3(O, r with { Version = "1.1.0|x" }, pub)?.Code == UpdateErrorCode.InvalidField
        && ReleaseSignature.VerifyV3(O, r with { Version = "1.1.0\u0085" }, pub)?.Code == UpdateErrorCode.InvalidField);
    Check("3.15 v3 で seq が無ければ拒否", ReleaseSignature.VerifyV3(O, r with { Policy = pol with { Seq = null } }, pub)?.Code == UpdateErrorCode.InvalidField);
    Check("3.16 知らせの文は日英どちらも出る", new UpdateError(UpdateErrorCode.Replay).Message(UpdateLanguage.Japanese).Contains("古い") && new UpdateError(UpdateErrorCode.Replay).Message().Contains("older"));
}

Console.WriteLine("== 4. 鮮度（古い署名の再送・期限） ==");
{
    var now = DateTimeOffset.FromUnixTimeSeconds(1_900_000_000);
    var p50 = new ReleasePolicy(new RolloutSpec(50, "r"), Array.Empty<string>(), 2);
    Check("4.1 前より新しい・同じ通し番号は受ける", Freshness.Check(p50, 1, now) == null && Freshness.Check(p50, 2, now) == null);
    Check("4.2 0% に止めた（seq 3）後に 50%（seq 2）を再送 → 拒否", Freshness.Check(p50, 3, now)?.Code == UpdateErrorCode.Replay);
    var oldNoBad = new ReleasePolicy(null, Array.Empty<string>(), 4);
    Check("4.3 不具合版の指定（seq 5）の後に古い manifest（seq 4）を再送 → 拒否", Freshness.Check(oldNoBad, 5, now)?.Code == UpdateErrorCode.Replay);
    Check("4.4 期限切れは拒否・期限内は受ける", Freshness.Check(p50 with { ExpiresAt = 1_899_999_999 }, 0, now)?.Code == UpdateErrorCode.Expired && Freshness.Check(p50 with { ExpiresAt = 1_900_000_000 }, 0, now) == null);
    Check("4.5 入れたばかりの端末でも、ビルドに焼き込んだ最小の通し番号より古いものは拒否", Freshness.Check(p50, 0, now, minimumSeq: 3)?.Code == UpdateErrorCode.Replay);
    var st = CrashWatch.AcceptSeq(CrashWatch.AcceptSeq(new CrashWatch.State(), 7), 3);
    Check("4.6 覚える通し番号は下がらない・保存しても残る", st.LastSeq == 7 && CrashWatch.Parse(CrashWatch.Serialize(st)).LastSeq == 7);
}

Console.WriteLine("== 5. 出すかの判定（ダウングレード・不具合版・段階配信） ==");
{
    var id = Enumerable.Range(0, 500).Select(_ => Rollout.NewInstallId()).ToList();
    var r30 = new RolloutSpec(30, "s");
    var inId = id.First(x => Rollout.InCohort(x, r30)); var outId = id.First(x => !Rollout.InCohort(x, r30));
    var all = ReleasePolicy.Everyone;
    Rollout.OfferKind K(string latest, string cur, ReleasePolicy? p, UpdateError? e = null, string? who = null, IEnumerable<string>? rb = null)
        => Rollout.DecideOffer(true, latest, cur, p, e, who ?? inId, rb).Kind;
    Check("5.1 古い版（正しく署名済み）は出さない", K("1.0.0", "1.2.0", all) == Rollout.OfferKind.NotNewer);
    Check("5.2 current は省けない（null は例外）", Throws<ArgumentNullException>(() => Rollout.DecideOffer(true, "1.0.0", null!, all, null, inId, null)));
    Check("5.3 今の版が署名つきの不具合版なら古い版へ移す", K("1.1.0", "1.2.0", new ReleasePolicy(null, new[] { "1.2.0" })) == Rollout.OfferKind.Offer);
    Check("5.4 案内された版そのものが不具合版なら出さない（まだ古い版の端末にも）", K("1.1.0", "1.0.0", new ReleasePolicy(r30, new[] { "1.1.0" })) == Rollout.OfferKind.LatestRevoked);
    Check("5.5 検証の誤りがあれば出さない", K("1.1.0", "1.0.0", all, new UpdateError(UpdateErrorCode.Replay)) == Rollout.OfferKind.Unverified);
    Check("5.6 組の中は出す・外は出さない", K("1.1.0", "1.0.0", new ReleasePolicy(r30, Array.Empty<string>())) == Rollout.OfferKind.Offer && K("1.1.0", "1.0.0", new ReleasePolicy(r30, Array.Empty<string>()), null, outId) == Rollout.OfferKind.NotInCohort);
    Check("5.7 この端末で戻した版は出さない・次の版は出す", K("1.1.0", "1.0.0", all, null, null, new[] { "1.1.0.0" }) == Rollout.OfferKind.RolledBackBefore && K("1.1.1", "1.0.0", all, null, null, new[] { "1.1.0" }) == Rollout.OfferKind.Offer);
    Check("5.8 サーバーが案内しなければ出さない", Rollout.DecideOffer(false, "9.9.9", "1.0.0", all, null, inId, null).Kind == Rollout.OfferKind.None);
    var in10 = id.Where(x => Rollout.InCohort(x, new RolloutSpec(10, "s"))).ToHashSet();
    var in30 = id.Where(x => Rollout.InCohort(x, r30)).ToHashSet();
    Check("5.9 同じ salt で割合を上げても外れない（10% ⊂ 30%）・30% はおよそ 3 割", in10.IsSubsetOf(in30) && in30.Count is > 100 and < 200, in30.Count.ToString());
    Check("5.10 installId が壊れていれば 100% のときだけ", !Rollout.InCohort("XYZ", new RolloutSpec(99, "s")) && Rollout.InCohort(null, new RolloutSpec(100, "s")));
}

Console.WriteLine("== 6. 版の比較 ==");
{
    Check("6.1 1.9 < 1.10・1.0 = 1.0.0", VersionCompare.IsNewer("1.9", "1.10") && VersionCompare.Same("1.0", "1.0.0.0"));
    Check("6.2 1.0.1-hotfix は 1.0.0 より新しい", VersionCompare.IsNewer("1.0.0", "1.0.1-hotfix"));
    Check("6.3 1.0.0-beta → 1.0.0 へ上げられる・逆は無い", VersionCompare.IsNewer("1.0.0-beta", "1.0.0") && !VersionCompare.IsNewer("1.0.0", "1.0.0-beta"));
    Check("6.4 SemVer の並び（alpha < alpha.1 < beta < beta.2 < beta.11 < rc.1）",
        VersionCompare.IsNewer("1.0.0-alpha", "1.0.0-alpha.1") && VersionCompare.IsNewer("1.0.0-alpha.1", "1.0.0-beta") && VersionCompare.IsNewer("1.0.0-beta", "1.0.0-beta.2")
        && VersionCompare.IsNewer("1.0.0-beta.2", "1.0.0-beta.11") && VersionCompare.IsNewer("1.0.0-beta.11", "1.0.0-rc.1"));
    Check("6.5 桁あふれ・文字・空の版は『新しい』と見ない（安全側）", !VersionCompare.IsNewer("1.0.5", "1.0.99999999999") && !VersionCompare.IsNewer("1.0.0", "abc") && !VersionCompare.IsNewer("1.0.0", "") && !VersionCompare.IsNewer("x", "2.0"));
    Check("6.6 build の印（+abc）は比べない", VersionCompare.Same("1.2.3+a", "1.2.3+b") && !VersionCompare.IsNewer("1.2.3+a", "1.2.3+b"));
    Check("6.7 1.0.3 と 1.0.30 は違う", !VersionCompare.Same("1.0.3", "1.0.30"));
}

Console.WriteLine("== 7. 自動の戻し（起動の見張り） ==");
{
    var dg = new string('d', 64);
    var s0 = CrashWatch.BeginApply(new CrashWatch.State { RolledBack = new() { "0.9.0" } }, "1.0.0", "1.1.0", dg, @"C:\App");
    CrashWatch.Result Run(CrashWatch.State s, bool abn, TimeSpan? t, string cur = "1.1.0") => CrashWatch.OnStartup(O, s, cur, new CrashWatch.LastRun(abn, t));
    var w = Run(s0, false, null).Next;
    Check("7.1 新しい版の 1 回目の起動で見張りを始める", w.Phase == CrashWatch.Phase.Watching && w.Crashes == 0);
    var c1 = Run(w, true, TimeSpan.FromMinutes(2)); var c2 = Run(c1.Next, true, TimeSpan.FromMinutes(3));
    Check("7.2 10 分以内に 2 回 → 戻す・1 回 → 戻さない", c2.Action == CrashWatch.Action.Rollback && c2.Next.Reason == CrashWatch.Why.Crashes && c1.Action == CrashWatch.Action.None && c1.Next.Crashes == 1);
    Check("7.3 10 分以降の異常終了は数えない（境目 9:59 は数え 10:00 は数えない）",
        Run(c1.Next, true, TimeSpan.FromMinutes(11)).Action == CrashWatch.Action.None && Run(c1.Next, true, TimeSpan.FromSeconds(599)).Action == CrashWatch.Action.Rollback && Run(c1.Next, true, TimeSpan.FromMinutes(10)).Action == CrashWatch.Action.None);
    Check("7.4 落ち→正常→落ち では戻さない", Run(Run(c1.Next, false, null).Next, true, TimeSpan.FromMinutes(1)).Action == CrashWatch.Action.None);
    var u = Run(c1.Next, true, null);
    Check("7.5 長さ不明の異常終了は数えず、見張りも続ける", u.Action == CrashWatch.Action.None && u.Next.Phase == CrashWatch.Phase.Watching && u.Next.Crashes == 1);
    var lim3 = new UpdateSafetyOptions { CrashLimit = 3, CrashWindow = TimeSpan.FromMinutes(5) }.Validate();
    var x1 = CrashWatch.OnStartup(lim3, w, "1.1.0", new(true, TimeSpan.FromMinutes(4)));
    var x2 = CrashWatch.OnStartup(lim3, x1.Next, "1.1.0", new(true, TimeSpan.FromMinutes(4)));
    var x3 = CrashWatch.OnStartup(lim3, x2.Next, "1.1.0", new(true, TimeSpan.FromMinutes(4)));
    Check("7.6 回数・時間は設定できる（3 回・5 分）", x2.Action == CrashWatch.Action.None && x3.Action == CrashWatch.Action.Rollback);
    var back = CrashWatch.OnStartup(O, CrashWatch.BeginRollback(c2.Next), "1.0.0", CrashWatch.LastRun.Clean);
    Check("7.7 戻した後: 知らせる・取り直さない一覧に入れる", back.Next.Pending == CrashWatch.Notice.RolledBack && back.Next.RolledBack.SequenceEqual(new[] { "0.9.0", "1.1.0" }) && back.Next.PrevDigest == "");
    var stuck = CrashWatch.OnStartup(O, CrashWatch.BeginRollback(c2.Next), "1.1.0", CrashWatch.LastRun.Clean);
    Check("7.8 戻せなかった → 知らせて止める（輪にしない）", stuck.Next.Pending == CrashWatch.Notice.RollbackFailed && stuck.Next.PrevDigest == "");
    var stable = Run(w, false, null).Next;
    Check("7.9 不具合版の指定: 載っていれば戻す・前の版も載っていれば戻さない・控えが無ければ戻さない",
        CrashWatch.OnBadVersions(stable, "1.1.0", new[] { "1.1.0" }).Action == CrashWatch.Action.Rollback
        && CrashWatch.OnBadVersions(stable, "1.1.0", new[] { "1.1.0", "1.0.0" }).Action == CrashWatch.Action.None
        && CrashWatch.OnBadVersions(new CrashWatch.State(), "1.1.0", new[] { "1.1.0" }).Action == CrashWatch.Action.None);
    Check("7.10 戻す前の照合（一致・不一致・控えなし・記録なし）", CrashWatch.CanRollback(c2.Next, dg.ToUpperInvariant()) == null && CrashWatch.CanRollback(c2.Next, new string('e', 64)) == "digest-mismatch"
        && CrashWatch.CanRollback(c2.Next, null) == "no-prev" && CrashWatch.CanRollback(new CrashWatch.State(), dg) == "no-record");
    var ser = CrashWatch.Serialize(c1.Next);
    Check("7.11 保存と読み直しで同じ・壊れた記録は Idle", CrashWatch.Serialize(CrashWatch.Parse(ser)) == ser && CrashWatch.Parse("phase=Explode\ncrashes=-3").Phase == CrashWatch.Phase.Idle && CrashWatch.Parse("crashes=-3").Crashes == 0);
    Check("7.12 記録は作った実行フォルダだけのもの", CrashWatch.BelongsTo(s0, @"c:\app\") && !CrashWatch.BelongsTo(s0, @"C:\Other"));
    Check("7.13 控えの置き場（隣の <名前>.prev・区切りはそのまま・ドライブ直下は不可）",
        CrashWatch.PrevDirFor(O, @"C:\Users\田中\Programs\MyApp\") == @"C:\Users\田中\Programs\MyApp.prev" && CrashWatch.PrevDirFor(O, "/opt/x/MyApp") == "/opt/x/MyApp.prev" && Throws<ArgumentException>(() => CrashWatch.PrevDirFor(O, @"C:\")));
    Check("7.14 利用者データのフォルダは設定どおり除く（似た名前は除かない）", CrashWatch.IsExcluded(O, @"backend\data\x.db") && CrashWatch.IsExcluded(O, "DATA/y") && !CrashWatch.IsExcluded(O, @"backend\dataset\a") && !CrashWatch.IsExcluded(O, "database.js"));
    var t1 = new List<(string, string)> { ("MyApp.exe", "aa"), (@"lib\a.dll", "bb"), (@"data\db", "cc") };
    Check("7.15 要約: 並び・大小・区切りに依らず、データは数えず、1 ファイルの違いで変わる",
        CrashWatch.TreeDigest(O, t1) == CrashWatch.TreeDigest(O, new List<(string, string)> { ("lib/A.DLL", "BB"), ("myapp.exe", "aa") })
        && CrashWatch.TreeDigest(O, t1) != CrashWatch.TreeDigest(O, new List<(string, string)> { ("MyApp.exe", "ab"), (@"lib\a.dll", "bb") })
        && CrashWatch.TreeDigest(O, t1) != CrashWatch.TreeDigest(new UpdateSafetyOptions { TreeDomain = "other-tree", MutableDirs = O.MutableDirs }, t1));
    const long MB = 1024 * 1024;
    Check("7.16 空き容量", CrashWatch.CheckSpace(O, 2000 * MB, 400 * MB, 0) == null && CrashWatch.CheckSpace(O, 500 * MB, 400 * MB, 0) == "656|500" && CrashWatch.CheckSpace(O, -1, 1, 0) != null);
}

Console.WriteLine("== 8. 前回の終わり方（時計の変更・pid の使い回し） ==");
{
    var t0 = new DateTime(2026, 11, 14, 10, 0, 0, DateTimeKind.Utc);
    var back = RunMarkerLogic.Judge(new RunMarker { Pid = 1, StartedAtUtc = t0, HeartbeatUtc = t0.AddHours(-2).AddMinutes(31), ElapsedMs = 31 * 60_000 }, false);
    Check("8.1 時計が戻っても、31 分動いた回は 31 分と測る（数えない）", back.Abnormal && back.RanFor == TimeSpan.FromMinutes(31));
    var fwd = RunMarkerLogic.Judge(new RunMarker { Pid = 1, StartedAtUtc = t0, HeartbeatUtc = t0.AddHours(1).AddMinutes(2), ElapsedMs = 2 * 60_000 }, false);
    Check("8.2 時計が進んでも、2 分で落ちた回は 2 分と測る（数える）", fwd.RanFor == TimeSpan.FromMinutes(2));
    var w = CrashWatch.OnStartup(O, CrashWatch.BeginApply(new CrashWatch.State(), "1.0.0", "1.1.0", new string('d', 64), @"C:\App"), "1.1.0", CrashWatch.LastRun.Clean).Next;
    Check("8.3 時計が戻った 31 分の回が 2 回あっても戻さない", CrashWatch.OnStartup(O, CrashWatch.OnStartup(O, w, "1.1.0", back.ToLastRun()).Next, "1.1.0", back.ToLastRun()).Action == CrashWatch.Action.None);
    var legacy = RunMarkerLogic.Judge(new RunMarker { Pid = 1, StartedAtUtc = t0, HeartbeatUtc = t0.AddHours(-1) }, false);
    Check("8.4 古い形の印で壁時計の差が負 → 長さ不明（0 と見なさない）", legacy.Abnormal && legacy.RanFor is null);
    Check("8.5 同じプロセスが生きていれば正常・印が無ければ正常", !RunMarkerLogic.Judge(new RunMarker { Pid = 1, StartedAtUtc = t0 }, true).Abnormal && !RunMarkerLogic.Judge(null, false).Abnormal);
    var m = new RunMarker { Pid = 77, StartedAtUtc = t0, HeartbeatUtc = t0.AddSeconds(30), ElapsedMs = 30_000, Version = "1.1.0" };
    var rt = RunMarkerLogic.Parse(RunMarkerLogic.Serialize(m));
    Check("8.6 印の保存と読み直し", rt != null && rt.Pid == 77 && rt.ElapsedMs == 30_000 && rt.StartedAtUtc == t0 && RunMarkerLogic.Parse("garbage") == null);
    Check("8.7 自分のプロセスは『同じプロセスが生きている』・起動より前の印の時刻なら別のプロセス",
        UpdateGuardIO.IsSameProcessAlive(Environment.ProcessId, DateTime.UtcNow) && !UpdateGuardIO.IsSameProcessAlive(Environment.ProcessId, Process.GetCurrentProcess().StartTime.ToUniversalTime().AddMinutes(-5)));
}

Console.WriteLine("== 9. 適用・戻しの手順 ==");
{
    var app = @"C:\Users\田中\AppData\Local\Programs\My App";
    var stg = @"C:\Users\田中\AppData\Local\Temp\myapp\1\staging";
    var a = UpdateScripts.BuildApply(O, 4321, stg, app, "MyApp.exe");
    var lines = a.Script.Split("\r\n");
    int L(string s) => Array.FindIndex(lines, l => l.Contains(s, StringComparison.Ordinal));
    Check("9.1 日本語の利用者名でも作れる・手順は ASCII だけ・パスは環境変数", a.Script.All(c => c <= 127) && a.Environment["USK_APP"] == app && a.Environment["USK_PREV"] == app + ".prev" && a.Environment["USK_STAGING"] == stg);
    Check("9.2 順番: 終了待ち → 前の控えを消す → 今の版を写す → 上書き", L("Wait-Process -Id 4321") is var i0 && i0 >= 0 && L("rd /s /q") > i0 && L("robocopy \"%USK_APP%\" \"%USK_PREV%\" /E") > L("rd /s /q") && L("robocopy \"%USK_STAGING%\" \"%USK_APP%\" /E") > L("robocopy \"%USK_APP%\" \"%USK_PREV%\""));
    Check("9.3 写せなければ上書きしない・上書きに失敗したら控えから戻す", lines[L("robocopy \"%USK_APP%\" \"%USK_PREV%\"") + 1] == "if errorlevel 8 goto prevfail" && L(":applyfail") > 0 && lines[L(":applyfail") + 1].StartsWith("robocopy \"%USK_PREV%\" \"%USK_APP%\" /E", StringComparison.Ordinal));
    Check("9.4 消すのは控えだけ・削除系のスイッチなし", a.Script.Split("rd ").Length == 2 && new[] { "/MIR", "/PURGE", "/MOVE", "del ", "Remove-Item" }.All(sw => !a.Script.Contains(sw, StringComparison.OrdinalIgnoreCase)));
    Check("9.5 利用者データは /XD で除く", lines[L("robocopy \"%USK_APP%\" \"%USK_PREV%\"")].Contains("/XD \"%USK_APP%\\data\" \"%USK_APP%\\backend\\data\""));
    var rb = UpdateScripts.BuildRollback(O, 4321, app, "MyApp.exe");
    Check("9.6 戻し: ASCII・止めるのは実行フォルダの中だけ（$env で受け取る）・控えから写す", rb.Script.All(c => c <= 127) && rb.Script.Contains("StartsWith($env:USK_APP + '\\'") && rb.Script.Contains("robocopy \"%USK_PREV%\" \"%USK_APP%\" /E"));
    Check("9.7 \" ・改行・相対パス・実行フォルダの中の staging・パス付きの exe 名は拒否",
        Throws<ArgumentException>(() => UpdateScripts.BuildApply(O, 1, "C:\\s\" & calc & \"", app, "a.exe"))
        && Throws<ArgumentException>(() => UpdateScripts.BuildApply(O, 1, stg, app, "a.exe\r\ndel x"))
        && Throws<ArgumentException>(() => UpdateScripts.BuildApply(O, 1, @"tmp\staging", app, "a.exe"))
        && Throws<ArgumentException>(() => UpdateScripts.BuildApply(O, 1, app + @"\staging", app, "a.exe"))
        && Throws<ArgumentException>(() => UpdateScripts.BuildRollback(O, 1, app, @"..\a.exe"))
        && Throws<ArgumentException>(() => UpdateScripts.BuildRollback(O, 0, app, "a.exe")));
    Check("9.8 % ! & ' を含むパスは使える（値は再展開されない）", UpdateScripts.BuildApply(O, 1, @"C:\T\%PATH%!x&y'z\s", @"C:\P\a&b'c%d%\App", "a.exe").Environment["USK_APP"] == @"C:\P\a&b'c%d%\App");
    Check("9.9 起動しない設定なら start が入らない", !UpdateScripts.BuildApply(new UpdateSafetyOptions { LaunchAfterScript = false }, 1, stg, app, "a.exe").Script.Contains("start "));
}

Console.WriteLine("== 10. 設定・ダウンロード先 ==");
{
    Check("10.1 使えない設定は例外", Throws<ArgumentException>(() => new UpdateSafetyOptions { Domain = "Bad Name" }.Validate()) && Throws<ArgumentException>(() => new UpdateSafetyOptions { MutableDirs = new[] { @"..\up" } }.Validate())
        && Throws<ArgumentException>(() => new UpdateSafetyOptions { MutableDirs = new[] { "データ" } }.Validate()) && Throws<ArgumentException>(() => new UpdateSafetyOptions { CrashLimit = 0 }.Validate())
        && Throws<ArgumentException>(() => new UpdateSafetyOptions { PrevSuffix = @"\x" }.Validate()));
    var po = new UpdateSafetyOptions { AllowedDownloadPrefix = "/api/app/" };
    Check("10.2 ダウンロード先: 同じサーバーの相対パスだけ・接頭辞・sha256 の形",
        ReleaseSignature.ValidateSource(po, "/api/app/pkg?os=windows", sha) == null && ReleaseSignature.ValidateSource(po, "http://evil/x", sha) != null
        && ReleaseSignature.ValidateSource(po, "//evil/x", sha) != null && ReleaseSignature.ValidateSource(po, "/api/appX/p", sha) != null
        && ReleaseSignature.ValidateSource(po, "/api/app/p", "zz") != null && ReleaseSignature.ValidateSource(new UpdateSafetyOptions(), "/dl/p", sha) == null);
}

Console.WriteLine("== 11. 言語をまたいだ確認（tools/sign-manifest.mjs で署名 → C# で検証） ==");
if (args.Length > 0 && File.Exists(args[0]))
{
    using var doc = JsonDocument.Parse(File.ReadAllText(args[0]));
    var xpub = doc.RootElement.GetProperty("publicKeyPem").GetString();
    var rels = new List<(string Name, ReleaseInfo? R, UpdateError? E)>();
    foreach (var m in doc.RootElement.GetProperty("manifests").EnumerateArray())
    {
        var (r, e) = ReleaseJson.FromManifest(m.GetProperty("manifest"), "windows");
        rels.Add((m.GetProperty("name").GetString()!, r, e));
    }
    foreach (var (name, r, e) in rels)
        Check("11.1 Node の署名が C# で通る: " + name, r != null && e == null && ReleaseSignature.VerifyV3(O, r, xpub) == null, e?.ToString() ?? (r == null ? "null" : ReleaseSignature.VerifyV3(O, r, xpub)?.ToString()));
    Check("11.2 別の製品名の設定では通らない", rels.All(x => x.R == null || ReleaseSignature.VerifyV3(new UpdateSafetyOptions(), x.R, xpub) != null));
    var now = DateTimeOffset.FromUnixTimeSeconds(1_900_000_000);
    long last = 0; var seen = new List<string>();
    foreach (var (name, r, _) in rels.Take(4)) { var f = Freshness.Check(r!.Policy, last, now); seen.Add(f?.Code.ToString() ?? "ok"); if (f == null) last = r.Policy.Seq!.Value; }
    Check("11.3 seq 1→2→3→4 を順に受ける", seen.All(x => x == "ok") && last == 4, string.Join(",", seen));
    Check("11.4 seq 4 を受けた後に 50%（seq 2）を再送 → 拒否", Freshness.Check(rels[1].R!.Policy, last, now)?.Code == UpdateErrorCode.Replay);
    Check("11.5 期限切れの manifest は拒否", Freshness.Check(rels[4].R!.Policy, last, now)?.Code == UpdateErrorCode.Expired);
    var ids = Enumerable.Range(0, 300).Select(_ => Rollout.NewInstallId()).ToList();
    Check("11.6 止めた 0% は誰にも出さない", ids.All(x => Rollout.DecideOffer(true, rels[2].R!.Version, "1.0.0", rels[2].R!.Policy, null, x, null).Kind == Rollout.OfferKind.NotInCohort));
    Check("11.7 1.2.0 の manifest の不具合版（1.1.0）で、1.1.0 の端末は戻す判定になる",
        CrashWatch.OnBadVersions(CrashWatch.OnStartup(O, CrashWatch.BeginApply(new CrashWatch.State(), "1.0.0", "1.1.0", new string('d', 64), @"C:\A"), "1.1.0", CrashWatch.LastRun.Clean).Next, "1.1.0", rels[3].R!.Policy.BadVersions).Action == CrashWatch.Action.Rollback);
}
else Console.WriteLine("  （xlang の材料が無いので飛ばしました）");

Console.WriteLine("== 12. 実際に cmd と robocopy を走らせる（日本語・空白・& ' % を含むフォルダ） ==");
var live = Environment.GetEnvironmentVariable("USK_LIVE_DIR");
if (OperatingSystem.IsWindows() && !string.IsNullOrEmpty(live))
{
    var root = Path.Combine(live, "実地 田中&'%x%" + Guid.NewGuid().ToString("N")[..6]);
    try
    {
        var app = Path.Combine(root, "Programs", "My App");
        var stg = Path.Combine(root, "一時", "staging");
        Directory.CreateDirectory(Path.Combine(app, "data")); Directory.CreateDirectory(Path.Combine(app, "lib")); Directory.CreateDirectory(stg);
        File.WriteAllText(Path.Combine(app, "MyApp.exe"), "v1 exe"); File.WriteAllText(Path.Combine(app, "lib", "a.dll"), "v1 dll");
        File.WriteAllText(Path.Combine(app, "data", "customer.db"), "customer data v1");
        File.WriteAllText(Path.Combine(stg, "MyApp.exe"), "v2 exe"); File.WriteAllText(Path.Combine(stg, "new-only.dll"), "v2 new");
        Directory.CreateDirectory(Path.Combine(stg, "data")); File.WriteAllText(Path.Combine(stg, "data", "customer.db"), "SHOULD NOT OVERWRITE");
        var lo = new UpdateSafetyOptions { Domain = "myapp", MutableDirs = new[] { "data" }, LaunchAfterScript = false }.Validate();
        var deadPid = 999_999; // Windows の PID は 4 の倍数なので存在しない番号（Wait-Process はすぐ戻る）
        var digestBefore = UpdateGuardIO.DigestTree(lo, app)!.Value.Digest;
        var codeA = UpdateGuardIO.RunScript(UpdateScripts.BuildApply(lo, deadPid, stg, app, "MyApp.exe"), Path.Combine(root, "work a"), "update-apply.cmd", TimeSpan.FromMinutes(2));
        var prev = CrashWatch.PrevDirFor(lo, app);
        Check("12.1 適用の手順が終わる（終了コード 0）", codeA == 0, $"code={codeA}");
        Check("12.2 新しい版で上書きされた", File.ReadAllText(Path.Combine(app, "MyApp.exe")) == "v2 exe" && File.Exists(Path.Combine(app, "new-only.dll")));
        Check("12.3 利用者データは上書きされない", File.ReadAllText(Path.Combine(app, "data", "customer.db")) == "customer data v1");
        Check("12.4 控えに前の版が写り、利用者データは写っていない", File.ReadAllText(Path.Combine(prev, "MyApp.exe")) == "v1 exe" && !Directory.Exists(Path.Combine(prev, "data")));
        Check("12.5 控えの要約が適用前の記録と一致する（戻してよい）", CrashWatch.CanRollback(new CrashWatch.State { PrevDigest = digestBefore }, UpdateGuardIO.DigestTree(lo, prev)?.Digest) == null);
        File.WriteAllText(Path.Combine(app, "data", "customer.db"), "customer data changed by v2");
        var codeR = UpdateGuardIO.RunScript(UpdateScripts.BuildRollback(lo, deadPid, app, "MyApp.exe"), Path.Combine(root, "work r"), "update-rollback.cmd", TimeSpan.FromMinutes(2));
        Check("12.6 戻しの手順が終わる（終了コード 0）", codeR == 0, $"code={codeR}");
        Check("12.7 前の版に戻った・利用者データは今のまま", File.ReadAllText(Path.Combine(app, "MyApp.exe")) == "v1 exe" && File.ReadAllText(Path.Combine(app, "lib", "a.dll")) == "v1 dll" && File.ReadAllText(Path.Combine(app, "data", "customer.db")) == "customer data changed by v2");
        Console.WriteLine($"  （記録）戻した後も新しい版にだけあったファイルが残る: new-only.dll = {File.Exists(Path.Combine(app, "new-only.dll"))}");
        // 2 回目の適用: 前の控えを消して作り直す（1 世代だけ）
        File.WriteAllText(Path.Combine(app, "MyApp.exe"), "v1b exe");
        var codeA2 = UpdateGuardIO.RunScript(UpdateScripts.BuildApply(lo, deadPid, stg, app, "MyApp.exe"), Path.Combine(root, "work a2"), "update-apply.cmd", TimeSpan.FromMinutes(2));
        Check("12.8 2 回目の適用で控えは作り直される（1 世代）", codeA2 == 0 && File.ReadAllText(Path.Combine(prev, "MyApp.exe")) == "v1b exe");
        // 控えを書き換えられたら戻さない（UpdateGuard 経由・手順は起動しない）
        File.WriteAllText(Path.Combine(prev, "MyApp.exe"), "tampered");
        var g = new UpdateGuard(lo, Path.Combine(root, "state"), app, "MyApp.exe", Path.Combine(root, "work g"));
        var st = CrashWatch.BeginApply(new CrashWatch.State(), "1.0.0", "1.1.0", digestBefore, app);
        UpdateGuardIO.SaveState(g.StatePath, st);
        var (started, why) = g.TryStartRollback(st);
        Check("12.9 控えの中身が記録と違えば戻しを起動せず『戻せなかった』を記録", !started && why == "digest-mismatch" && UpdateGuardIO.LoadState(g.StatePath).Pending == CrashWatch.Notice.RollbackFailed);
        // 入れ口: 鮮度つきの判定と通し番号の保存
        var rel = Rel("1.1.0", new ReleasePolicy(null, Array.Empty<string>(), 10));
        var go = new UpdateGuard(O, Path.Combine(root, "state2"), app, "MyApp.exe", Path.Combine(root, "work g2"));
        var ok1 = go.CheckRelease(rel, pub, "1.0.0", true, DateTimeOffset.UtcNow);
        var replay = go.CheckRelease(Rel("1.1.0", new ReleasePolicy(null, Array.Empty<string>(), 9)), pub, "1.0.0", true, DateTimeOffset.UtcNow);
        Check("12.10 入口: 正しい版は出す・通し番号を保存・より古い番号は再送として拒否",
            ok1.Offer.Kind == Rollout.OfferKind.Offer && UpdateGuardIO.LoadState(go.StatePath).LastSeq == 10 && replay.Error?.Code == UpdateErrorCode.Replay && replay.Offer.Kind == Rollout.OfferKind.Unverified);
        var mk = SessionMarkerFile.Begin(go.MarkerPath, "1.1.0", TimeSpan.FromMilliseconds(200));
        Thread.Sleep(700); mk.Dispose();   // 異常終了の代わり（印を消さない）
        File.WriteAllText(go.MarkerPath, System.Text.RegularExpressions.Regex.Replace(File.ReadAllText(go.MarkerPath), @"pid=\d+", "pid=999999"));   // 別のプロセスだったことにする
        var next = SessionMarkerFile.Begin(go.MarkerPath, "1.1.0");
        Check("12.11 印を消さずに終わった回は次の起動で『異常・長さあり』と分かる", next.Previous.Abnormal && next.Previous.RanFor is { } rf && rf > TimeSpan.Zero && rf < TimeSpan.FromMinutes(1), next.Previous.ToString());
        next.End();
        var third = SessionMarkerFile.Begin(go.MarkerPath, "1.1.0"); third.End();
        Check("12.12 正常に終えた回は次の起動で『正常』", !third.Previous.Abnormal);
    }
    finally { try { Directory.Delete(root, true); } catch (IOException) { } }
}
else Console.WriteLine("  （USK_LIVE_DIR が無い・Windows でないので飛ばしました）");

Console.WriteLine($"== 合計: {passed} 合格 / {failed} 不合格 ==");
foreach (var f in failures) Console.WriteLine("  不合格: " + f);
return failed == 0 ? 0 : 1;
