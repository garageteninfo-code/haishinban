using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace UpdateSafetyKit;

/// <summary>
/// Settings shared by every part of the kit. Nothing here is product-specific: the app passes its own names and folders.
/// <para>キット全体の設定。製品固有の名前・フォルダは持たず、アプリ側が渡す。</para>
/// </summary>
public sealed class UpdateSafetyOptions
{
    private static readonly Regex DomainRe = new("^[a-z0-9][a-z0-9.-]{0,39}$", RegexOptions.CultureInvariant);

    /// <summary>
    /// Domain-separation prefix for signed payloads ("&lt;Domain&gt;-v3|..."). Use a name unique to your product so a signature
    /// made for another product (or another payload version) can never be reused.
    /// <para>署名する文字列の先頭に付ける名前。製品ごとに変えると、他の製品・他の版の署名を使い回せない。</para>
    /// </summary>
    public string Domain { get; init; } = "usk-update";

    /// <summary>Prefix line of the folder digest. <para>フォルダの要約の先頭行。</para></summary>
    public string TreeDomain { get; init; } = "usk-tree-v1";

    /// <summary>
    /// Folders inside the app folder that hold user data (relative, "\" or "/"). They are never copied to the backup and never
    /// overwritten by a rollback, and are excluded from the folder digest.
    /// <para>実行フォルダの中で利用者のデータが入るフォルダ（相対）。控えに写さず、戻しで上書きせず、要約にも入れない。</para>
    /// </summary>
    public IReadOnlyList<string> MutableDirs { get; init; } = Array.Empty<string>();

    /// <summary>Suffix of the backup folder created next to the app folder. <para>実行フォルダの隣に作る控えの名前の末尾。</para></summary>
    public string PrevSuffix { get; init; } = ".prev";

    /// <summary>An abnormal exit counts as a "crash right after the update" only if the run was shorter than this.
    /// <para>この長さより短い実行の異常終了だけを「更新直後の異常終了」と数える。</para></summary>
    public TimeSpan CrashWindow { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>Consecutive early crashes that trigger an automatic rollback. <para>何回続けて落ちたら戻すか。</para></summary>
    public int CrashLimit { get; init; } = 2;

    /// <summary>Extra free space required on top of the backup size. <para>控えの大きさに上乗せして空けておく量。</para></summary>
    public long SpaceMarginBytes { get; init; } = 256L * 1024 * 1024;

    /// <summary>How many rolled-back versions to remember (oldest dropped). <para>戻した版を何件まで覚えるか。</para></summary>
    public int MaxRolledBackHistory { get; init; } = 20;

    /// <summary>
    /// If set, a download URL must be a relative path starting with this prefix (e.g. "/api/app/"). If null, any relative path
    /// starting with "/" (same server) is allowed. Absolute URLs are always rejected.
    /// <para>設定すると、ダウンロード先はこの接頭辞で始まる相対パスだけ。null なら「/」で始まる相対パス（同じサーバー）なら可。絶対 URL は常に拒否。</para>
    /// </summary>
    public string? AllowedDownloadPrefix { get; init; }

    /// <summary>Prefix of the environment variables that carry paths into the generated scripts.
    /// <para>生成する手順（cmd）へパスを渡す環境変数の接頭辞。</para></summary>
    public string ScriptEnvPrefix { get; init; } = "USK_";

    /// <summary>Whether the generated scripts start the app again at the end. <para>手順の最後にアプリを起動し直すか。</para></summary>
    public bool LaunchAfterScript { get; init; } = true;

    /// <summary>Language of the messages returned by <see cref="UpdateError.Message"/>. <para>知らせの言語。</para></summary>
    public UpdateLanguage Language { get; init; } = UpdateLanguage.English;

    /// <summary>Throws <see cref="ArgumentException"/> when a setting cannot work. <para>設定が使えない形なら例外。</para></summary>
    public UpdateSafetyOptions Validate()
    {
        if (!DomainRe.IsMatch(Domain ?? "")) throw new ArgumentException("Domain must match ^[a-z0-9][a-z0-9.-]{0,39}$");
        if (!DomainRe.IsMatch(TreeDomain ?? "")) throw new ArgumentException("TreeDomain must match ^[a-z0-9][a-z0-9.-]{0,39}$");
        if (string.IsNullOrEmpty(PrevSuffix) || PrevSuffix.IndexOfAny(new[] { '\\', '/', '"', ':', '*', '?', '<', '>', '|' }) >= 0)
            throw new ArgumentException("PrevSuffix must be a plain file-name suffix such as \".prev\"");
        if (CrashLimit < 1) throw new ArgumentException("CrashLimit must be >= 1");
        if (CrashWindow <= TimeSpan.Zero) throw new ArgumentException("CrashWindow must be positive");
        if (SpaceMarginBytes < 0) throw new ArgumentException("SpaceMarginBytes must be >= 0");
        if (MaxRolledBackHistory < 1) throw new ArgumentException("MaxRolledBackHistory must be >= 1");
        if (!Regex.IsMatch(ScriptEnvPrefix ?? "", "^[A-Z][A-Z0-9_]{0,15}$")) throw new ArgumentException("ScriptEnvPrefix must match ^[A-Z][A-Z0-9_]{0,15}$");
        foreach (var d in MutableDirs ?? Array.Empty<string>())
        {
            var n = (d ?? "").Replace('/', '\\').Trim('\\');
            if (n.Length == 0 || !Regex.IsMatch(n, @"^[A-Za-z0-9._ \-\\]+$") || n.Split('\\').Any(p => p == ".." || p == "." || p.Length == 0))
                throw new ArgumentException($"MutableDirs entry must be a relative folder inside the app folder: {d}");
        }
        return this;
    }
}

/// <summary>Language of user-facing messages. <para>知らせの言語。</para></summary>
public enum UpdateLanguage { English, Japanese }
