using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace UpdateSafetyKit;

/// <summary>
/// Where the Haishin relay is and how to trust it. With <see cref="PinnedCertSha256"/> set, only a server certificate whose
/// SHA-256 fingerprint is in the list is accepted (for a self-signed certificate made by tools/make-cert.mjs); chain and name
/// errors are then ignored because the exact certificate is pinned. Without pins, normal Windows validation is used
/// (for a certificate issued by the company's internal CA that is installed in the Windows certificate store).
/// <para>中継の場所と信じ方。PinnedCertSha256 を入れると、その指紋の証明書だけを受け入れる（自己署名の証明書向け）。
/// 入れなければ Windows の普通の確かめ（社内の認証局の証明書を Windows に入れてある場合）。</para>
/// </summary>
public sealed class HaishinConnectionOptions
{
    private static readonly Regex PinRe = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);

    /// <summary>Base URL of the relay, e.g. https://haishin.example.local:38920/ . <para>中継の URL。</para></summary>
    public Uri BaseUrl { get; init; } = new("https://127.0.0.1:38920/");

    /// <summary>SHA-256 fingerprints (hex; ":" and spaces allowed) of accepted server certificates. Two entries allow a
    /// certificate change without breaking installed apps. <para>受け入れる証明書の指紋（2 つ入れておくと証明書の入れ替えができる）。</para></summary>
    public IReadOnlyList<string> PinnedCertSha256 { get; init; } = Array.Empty<string>();

    /// <summary>Timeout of one request. <para>1 回の通信の待ち時間。</para></summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Allow plain http (not encrypted). Off by default; http to 127.0.0.1/localhost is always allowed.
    /// <para>暗号化なしの http を許すか（既定は許さない。127.0.0.1 だけは可）。</para></summary>
    public bool AllowInsecureHttp { get; init; }

    /// <summary>"AB:CD:..." / "ab cd ..." / "abcd..." → 64 lowercase hex, or null when it is not a SHA-256 fingerprint.</summary>
    public static string? NormalizePin(string? pin)
    {
        var p = new string((pin ?? "").Where(c => c != ':' && c != ' ' && c != '-').ToArray()).ToLowerInvariant();
        return PinRe.IsMatch(p) ? p : null;
    }

    /// <summary>The pins in normalized form.</summary>
    public IReadOnlyList<string> NormalizedPins => PinnedCertSha256.Select(NormalizePin).Where(p => p is not null).Select(p => p!).ToList();

    /// <summary>Throws <see cref="ArgumentException"/> for settings that cannot work safely. <para>危ない・使えない設定なら例外。</para></summary>
    public HaishinConnectionOptions Validate()
    {
        if (BaseUrl is null || !BaseUrl.IsAbsoluteUri) throw new ArgumentException("BaseUrl must be an absolute URL");
        var https = BaseUrl.Scheme == Uri.UriSchemeHttps;
        if (!https && BaseUrl.Scheme != Uri.UriSchemeHttp) throw new ArgumentException("BaseUrl must be http or https");
        if (!https && !AllowInsecureHttp && !BaseUrl.IsLoopback) throw new ArgumentException("BaseUrl is http (not encrypted). Use https, or set AllowInsecureHttp = true");
        foreach (var p in PinnedCertSha256 ?? Array.Empty<string>())
            if (NormalizePin(p) is null) throw new ArgumentException("PinnedCertSha256 entries must be SHA-256 fingerprints (64 hex characters)");
        if ((PinnedCertSha256?.Count ?? 0) > 0 && !https) throw new ArgumentException("PinnedCertSha256 needs an https BaseUrl");
        if (Timeout <= TimeSpan.Zero || Timeout > TimeSpan.FromMinutes(5)) throw new ArgumentException("Timeout must be between 0 and 5 minutes");
        return this;
    }
}

/// <summary>Creates the HttpClient used for the relay (with certificate pinning). BCL only.
/// <para>中継との通信に使う HttpClient を作る（証明書の固定つき）。</para></summary>
public static class HaishinHttp
{
    /// <summary>SHA-256 fingerprint of a certificate (64 lowercase hex). <para>証明書の指紋。</para></summary>
    public static string Fingerprint(X509Certificate cert)
        => Convert.ToHexString(SHA256.HashData(cert.GetRawCertData())).ToLowerInvariant();

    /// <summary>True when the certificate's fingerprint is one of the pins.</summary>
    public static bool MatchesPin(X509Certificate? cert, IReadOnlyList<string> normalizedPins)
    {
        if (cert is null || normalizedPins.Count == 0) return false;
        var fp = Fingerprint(cert);
        return normalizedPins.Any(p => CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(p), System.Text.Encoding.ASCII.GetBytes(fp)));
    }

    /// <summary>The certificate check used by <see cref="CreateClient"/>: pins if any, otherwise normal validation.</summary>
    public static bool ValidateServerCertificate(X509Certificate? cert, SslPolicyErrors errors, IReadOnlyList<string> normalizedPins)
        => normalizedPins.Count > 0 ? MatchesPin(cert, normalizedPins) : errors == SslPolicyErrors.None;

    /// <summary>Creates an HttpClient whose BaseAddress is the relay. Proxies are not used (closed networks, and a proxy would
    /// see the traffic). The caller owns and disposes it. <para>中継向けの HttpClient（プロキシは使わない）。</para></summary>
    public static HttpClient CreateClient(HaishinConnectionOptions options)
    {
        var o = (options ?? throw new ArgumentNullException(nameof(options))).Validate();
        var pins = o.NormalizedPins;
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = o.Timeout,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (_, cert, _, errors) => ValidateServerCertificate(cert, errors, pins),
            },
        };
        var baseUrl = o.BaseUrl.AbsoluteUri.EndsWith('/') ? o.BaseUrl : new Uri(o.BaseUrl.AbsoluteUri + "/");
        var http = new HttpClient(handler, disposeHandler: true) { BaseAddress = baseUrl, Timeout = o.Timeout };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Haishin-SafeRollout/0.2");
        return http;
    }

    /// <summary>True when the exception means "the server certificate was rejected" (wrong pin / untrusted).</summary>
    public static bool IsCertificateRejected(Exception? ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
            if (e is AuthenticationException) return true;
        return false;
    }
}

/// <summary>Why fetching the manifest failed. <para>配信情報を取れなかった理由。</para></summary>
public enum FetchProblem
{
    /// <summary>Fetched.</summary>
    None,
    /// <summary>The server has no manifest yet (404).</summary>
    NoManifest,
    /// <summary>Could not reach the server (offline, timeout, refused).</summary>
    Network,
    /// <summary>The server certificate was rejected (wrong pin, or not trusted). Possible impersonation.</summary>
    CertificateRejected,
    /// <summary>The server answered with something that is not a manifest.</summary>
    BadResponse,
}

/// <summary>Result of <see cref="ManifestClient.FetchAsync"/>. When <see cref="Release"/> is null, pass it to
/// <see cref="UpdateGuard.CheckRelease"/> anyway (it fails closed). <para>取得の結果。</para></summary>
public sealed record ManifestFetchResult(ReleaseInfo? Release, UpdateError? ParseError, FetchProblem Problem, string? Detail)
{
    /// <summary>Japanese / English text for the app's status line. <para>状態の表示に使う文。</para></summary>
    public string Message(UpdateLanguage lang)
    {
        var ja = lang == UpdateLanguage.Japanese;
        return Problem switch
        {
            FetchProblem.None => ParseError is null ? (ja ? "配信情報を受け取りました。" : "Release info received.") : ParseError.Message(lang),
            FetchProblem.NoManifest => ja ? "サーバーにまだ配信情報がありません。" : "The server has no release info yet.",
            FetchProblem.Network => ja ? "配信のサーバーにつながりません（あとで自動で確かめ直します）。" : "Cannot reach the update server (will retry later).",
            FetchProblem.CertificateRejected => ja ? "サーバーの証明書が、アプリに登録した物と違います（なりすましの可能性）。更新は確かめません。" : "The server certificate does not match the pinned one (possible impersonation). Updates are not checked.",
            _ => ja ? "サーバーの答えが配信情報の形ではありません。" : "The server response is not release info.",
        };
    }
}

/// <summary>Fetches /updates/manifest.json from the relay. Never throws (except for cancellation).
/// <para>中継から配信情報を取る。例外は投げない（取り消しを除く）。</para></summary>
public static class ManifestClient
{
    /// <summary>Upper bound of the manifest size. <para>配信情報の大きさの上限。</para></summary>
    public const int MaxBytes = 256 * 1024;

    /// <summary>GET updates/manifest.json and read the entry for <paramref name="os"/>.</summary>
    public static async Task<ManifestFetchResult> FetchAsync(HttpClient http, string os = "windows", CancellationToken ct = default)
    {
        try
        {
            using var res = await http.GetAsync("updates/manifest.json", HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (res.StatusCode == HttpStatusCode.NotFound) return new(null, null, FetchProblem.NoManifest, null);
            if (!res.IsSuccessStatusCode) return new(null, null, FetchProblem.BadResponse, ((int)res.StatusCode).ToString(System.Globalization.CultureInfo.InvariantCulture));
            if (res.Content.Headers.ContentLength is > MaxBytes) return new(null, null, FetchProblem.BadResponse, "too-large");
            await using var s = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var ms = new MemoryStream();
            var buf = new byte[16384];
            int n;
            while ((n = await s.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
            {
                ms.Write(buf, 0, n);
                if (ms.Length > MaxBytes) return new(null, null, FetchProblem.BadResponse, "too-large");
            }
            using var doc = JsonDocument.Parse(ms.ToArray());
            var (release, err) = ReleaseJson.FromManifest(doc.RootElement, os);
            return new(release, err, FetchProblem.None, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (HttpRequestException ex) when (HaishinHttp.IsCertificateRejected(ex)) { return new(null, null, FetchProblem.CertificateRejected, null); }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException) { return new(null, null, FetchProblem.Network, ex.GetType().Name); }
        catch (JsonException) { return new(null, null, FetchProblem.BadResponse, "json"); }
    }
}
