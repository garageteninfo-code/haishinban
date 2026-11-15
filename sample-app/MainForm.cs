using UpdateSafetyKit;

namespace HaishinSample;

/// <summary>架空の「在庫管理」の画面。更新の様子を表示し、試験用に「落ちたことにする」ボタンがある。</summary>
internal sealed class MainForm : Form
{
    private readonly Label _version = new() { AutoSize = true };
    private readonly Label _status = new() { AutoSize = false, Height = 64, Dock = DockStyle.Top, Text = "更新を確かめています…" };
    private readonly Label _report = new() { AutoSize = true, ForeColor = SystemColors.GrayText };
    private readonly Button _check = new() { Text = "更新を確認", AutoSize = true };
    private readonly Button _crash = new() { Text = "落ちたことにする（試験）", AutoSize = true };
    private readonly Button _error = new() { Text = "エラーを報告（試験）", AutoSize = true };
    private bool _busy;

    public MainForm()
    {
        var c = Program.Ctx;
        Text = "在庫管理（配信番のサンプル）";
        Font = new Font("Yu Gothic UI", 10f);
        ClientSize = new Size(560, 260);
        MinimumSize = new Size(420, 240);
        StartPosition = FormStartPosition.CenterScreen;
        if (c.Auto.Length > 0) { WindowState = FormWindowState.Minimized; ShowInTaskbar = false; }

        _version.Text = $"この PC の版：{c.Version}　／　配信のサーバー：{c.Cfg.RelayUrl}";
        var notice = c.Start.State.Pending switch
        {
            CrashWatch.Notice.RolledBack => $"前回、版 {c.Start.State.NoticeTo} で問題が続いたので {c.Start.State.NoticeFrom} に戻しました。",
            CrashWatch.Notice.RollbackFailed => $"版 {c.Start.State.NoticeTo} を前の版に戻せませんでした。管理者に連絡してください。",
            CrashWatch.Notice.ApplyFailed => $"版 {c.Start.State.NoticeTo} への更新が終わりませんでした（{c.Start.State.NoticeFrom} のまま）。",
            _ => "",
        };
        var panel = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(8), FlowDirection = FlowDirection.LeftToRight, WrapContents = true };
        panel.Controls.AddRange(new Control[] { _check, _error, _crash });
        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(8), FlowDirection = FlowDirection.TopDown, WrapContents = false };
        top.Controls.Add(_version);
        if (notice.Length > 0) top.Controls.Add(new Label { AutoSize = true, Text = notice, ForeColor = Color.DarkRed });
        top.Controls.Add(_report);
        _status.Padding = new Padding(8);
        Controls.Add(_status);
        Controls.Add(top);
        Controls.Add(panel);

        _check.Click += async (_, _) => await CheckAsync();
        _error.Click += (_, _) =>
        {
            try { InventoryService.LoadSlip(""); }
            catch (Exception ex) { c.Reporter.ReportException(ex, crash: false); _report.Text = "エラーの報告を置きました（裏で送ります）。"; }
        };
        // 押すと画面の処理の中で例外が起きる → Program の ThreadException が報告して終わる
        _crash.Click += (_, _) => InventoryService.SaveSlip(c.CrashMessage.Length > 0 ? c.CrashMessage : "在庫の保存で例外（試験）");
        Shown += async (_, _) => await OnShownAsync();
    }

    private async Task OnShownAsync()
    {
        var c = Program.Ctx;
        var result = await CheckAsync();
        if (c.Auto == "check")
        {
            await c.Reporter.FlushAsync(TimeSpan.FromSeconds(5));
            c.WriteResult(new { mode = "check", version = c.Version, result.Kind, result.Latest, result.Percent, result.Text, result.Error, result.Fetch, result.RollbackTo, stats = c.Reporter.Stats });
            Close();
        }
        else if (c.Auto == "crash")
        {
            await c.Reporter.FlushAsync(TimeSpan.FromSeconds(5));   // 起動の知らせを先に届ける（分母）
            _crash.PerformClick();
        }
    }

    internal sealed record CheckResult(string Kind, string? Latest, int Percent, string Text, string? Error, string Fetch, string? RollbackTo);

    private async Task<CheckResult> CheckAsync()
    {
        var c = Program.Ctx;
        if (_busy) return new("Busy", null, 0, "", null, "", null);
        _busy = true;
        _check.Enabled = false;
        _status.Text = "更新を確かめています…";
        try
        {
            var fetch = await ManifestClient.FetchAsync(c.Http, "windows");   // 画面の外（裏）で通信する
            var check = c.Guard.CheckRelease(fetch.Release, c.Cfg.PublicKeyPem, c.Version, fetch.Problem == FetchProblem.None, DateTimeOffset.UtcNow);
            var r = Describe(c, fetch, check);
            _status.Text = r.Text;
            _status.ForeColor = r.Kind is "Offer" ? Color.DarkGreen : r.Error is not null || fetch.Problem == FetchProblem.CertificateRejected ? Color.DarkRed : SystemColors.ControlText;
            var st = c.Reporter.Stats;
            _report.Text = $"報告：送った {st.Sent} 件・送る前 {st.Queued} 件・伏せて送り直し {st.Redacted} 件";
            return r;
        }
        finally { _busy = false; _check.Enabled = true; }
    }

    /// <summary>判定を日本語の文にする（本物のアプリでは、ここで「更新する」ボタンを出したり、戻しを始めたりする）。</summary>
    internal static CheckResult Describe(AppContextData c, ManifestFetchResult fetch, UpdateGuard.ReleaseCheck check)
    {
        var latest = fetch.Release?.Version;
        var pct = check.Offer.Percent;
        var fp = fetch.Problem.ToString();
        if (fetch.Problem != FetchProblem.None) return new("None", null, 0, fetch.Message(UpdateLanguage.Japanese), null, fp, null);
        if (check.Error is not null) return new("Unverified", latest, 0, check.Error.Message(UpdateLanguage.Japanese), check.Error.Code.ToString(), fp, null);
        var bad = fetch.Release!.Policy.BadVersions;
        return check.Offer.Kind switch
        {
            Rollout.OfferKind.Offer when VersionCompare.IsListed(c.Version, bad) =>
                new("Offer", latest, pct, $"この版 {c.Version} は配布元が取り下げました。版 {latest} に戻します（戻しの判定）。", null, fp, latest),
            Rollout.OfferKind.Offer => new("Offer", latest, pct, $"新しい版 {latest} があります（{(pct >= 100 ? "全員" : pct + "% の端末")}に配信中・この端末は対象）。", null, fp, null),
            Rollout.OfferKind.NotInCohort when pct <= 0 => new("NotInCohort", latest, pct, $"版 {latest} の配信は止められています。今の版 {c.Version} のまま使えます。", null, fp, null),
            Rollout.OfferKind.NotInCohort => new("NotInCohort", latest, pct, $"版 {latest} は一部の端末（{pct}%）にだけ配っています。この端末はまだ対象外です。", null, fp, null),
            Rollout.OfferKind.NotNewer => new("NotNewer", latest, pct, $"最新です（版 {c.Version}）。", null, fp, null),
            Rollout.OfferKind.LatestRevoked => new("LatestRevoked", latest, pct, $"版 {latest} は取り下げられています。今の版 {c.Version} のまま使えます。", null, fp, null),
            Rollout.OfferKind.RolledBackBefore => new("RolledBackBefore", latest, pct, $"版 {latest} は、この PC で前に問題が続いて戻した版なので、自動では入れません。", null, fp, null),
            _ => new(check.Offer.Kind.ToString(), latest, pct, "配信の情報がありません。", null, fp, null),
        };
    }
}

/// <summary>架空の業務の処理（呼び出し履歴を本物らしくするため）。</summary>
internal static class InventoryService
{
    public static void SaveSlip(string message) => throw new InvalidOperationException(message);
    public static void LoadSlip(string slipNo)
    {
        if (slipNo.Length == 0) throw new ArgumentException("伝票番号が空です", nameof(slipNo));
    }
}
