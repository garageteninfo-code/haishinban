using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace UpdateSafetyKit;

/// <summary>Staged rollout: Percent 0..100 and a per-release Salt ([A-Za-z0-9._-]{0,64}).
/// <para>段階配信の指定。Percent は 0..100、Salt は配信ごとに変える組分けの種。</para></summary>
public sealed record RolloutSpec(int Percent, string Salt);

/// <summary>
/// The signed release policy: rollout, revoked ("bad") versions, a monotonically increasing sequence number and an optional
/// expiry (Unix seconds). Seq and ExpiresAt exist to stop replay of old, correctly signed release info.
/// <para>署名される配信方針: 段階配信・不具合版の一覧・増え続ける通し番号・任意の有効期限（Unix 秒）。
/// 通し番号と期限は「正しく署名された古い情報の再送」を止めるためのもの。</para>
/// </summary>
public sealed record ReleasePolicy(RolloutSpec? Rollout, IReadOnlyList<string> BadVersions, long? Seq = null, long? ExpiresAt = null)
{
    /// <summary>No rollout limit and no revoked versions. <para>全員・不具合版なし。</para></summary>
    public static readonly ReleasePolicy Everyone = new(null, Array.Empty<string>());
}

/// <summary>Everything the client needs about one release for one OS. <para>1 つの OS 向けの 1 つの版の情報。</para></summary>
public sealed record ReleaseInfo(string Os, string Version, string Sha256, long Size, ReleasePolicy Policy, string? SignatureV3, string? SignatureV2 = null);

/// <summary>Canonical forms shared byte-for-byte with tools/sign-manifest.mjs. ASCII only. <para>署名側（Node）と 1 文字も違わない正規化。ASCII のみ。</para></summary>
public static class Canon
{
    /// <summary>Max integer that JavaScript can represent exactly (seq / expiresAt must stay below it).</summary>
    public const long MaxSafeInteger = 9007199254740991L;

    internal static readonly Regex OsRe = new("^[a-z0-9_-]{1,32}$", RegexOptions.CultureInvariant);
    internal static readonly Regex VersionRe = new("^[0-9A-Za-z.+-]{1,64}$", RegexOptions.CultureInvariant);
    internal static readonly Regex ShaRe = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);
    internal static readonly Regex SaltRe = new("^[A-Za-z0-9._-]{0,64}$", RegexOptions.CultureInvariant);

    /// <summary>
    /// Trims only ASCII space, tab, CR and LF. (JavaScript's trim() and .NET's Trim() disagree on characters such as U+0085 and
    /// U+FEFF; using ASCII on both sides keeps the signer and the client identical.)
    /// <para>前後の ASCII の空白（スペース・タブ・改行）だけを除く。JS と .NET で空白の範囲が違う文字（U+0085・U+FEFF）でずれないように。</para>
    /// </summary>
    public static string TrimAscii(string? s) => (s ?? string.Empty).Trim(' ', '\t', '\r', '\n');

    /// <summary>"all" when there is no rollout, otherwise "&lt;percent&gt;:&lt;salt&gt;".</summary>
    public static string Rollout(RolloutSpec? r) => r is null ? "all" : string.Create(CultureInfo.InvariantCulture, $"{r.Percent}:{r.Salt}");

    /// <summary>Revoked versions: trimmed, empty removed, de-duplicated, ordinal-sorted, joined by ",".</summary>
    public static string Bad(IEnumerable<string>? bad)
    {
        if (bad is null) return string.Empty;
        var list = bad.Select(TrimAscii).Where(b => b.Length > 0).Distinct(StringComparer.Ordinal).ToList();
        list.Sort(StringComparer.Ordinal);
        return string.Join(",", list);
    }
}

/// <summary>
/// Publisher signature over a release (ECDSA P-256 + SHA-256, DER signature, SPKI PEM public key; BCL only).
/// v3 binds os, version, sha256, size, rollout, revoked versions, sequence number and expiry. v2 (no seq/expiry) is kept only for
/// migrating from the original format.
/// <para>配布元の署名（ECDSA P-256・SHA-256・DER・SPKI PEM。標準ライブラリだけ）。v3 は OS・版・sha256・大きさ・段階配信・
/// 不具合版・通し番号・期限をまとめて束縛する。v2（通し番号なし）は元の形からの移行用。</para>
/// </summary>
public static class ReleaseSignature
{
    /// <summary>Builds the v3 string that is signed. Throws <see cref="ArgumentException"/> for values that cannot be signed safely.
    /// <para>署名する v3 の文字列。安全に署名できない値は例外。</para></summary>
    public static string BuildPayloadV3(UpdateSafetyOptions options, string? os, string? version, string? sha256, long size, ReleasePolicy policy)
    {
        var (o, v, s) = CheckFields(os, version, sha256, size, policy);
        if (policy.Seq is null) throw new ArgumentException("seq is required for v3");
        var exp = policy.ExpiresAt is null ? "none" : policy.ExpiresAt.Value.ToString(CultureInfo.InvariantCulture);
        return string.Create(CultureInfo.InvariantCulture,
            $"{options.Domain}-v3|{o}|{v}|{s}|{size}|rollout={Canon.Rollout(policy.Rollout)}|bad={Canon.Bad(policy.BadVersions)}|seq={policy.Seq.Value}|exp={exp}");
    }

    /// <summary>Builds the v2 string (migration only; same layout as the original kit when Domain is set to its prefix).
    /// <para>v2 の文字列（移行用）。</para></summary>
    public static string BuildPayloadV2(UpdateSafetyOptions options, string? os, string? version, string? sha256, long size, RolloutSpec? rollout, IEnumerable<string>? badVersions)
    {
        var (o, v, s) = CheckFields(os, version, sha256, size, new ReleasePolicy(rollout, (badVersions ?? Array.Empty<string>()).ToList()));
        return string.Create(CultureInfo.InvariantCulture, $"{options.Domain}-v2|{o}|{v}|{s}|{size}|rollout={Canon.Rollout(rollout)}|bad={Canon.Bad(badVersions)}");
    }

    private static (string Os, string Version, string Sha) CheckFields(string? os, string? version, string? sha256, long size, ReleasePolicy policy)
    {
        var o = Canon.TrimAscii(os).ToLowerInvariant();
        var v = Canon.TrimAscii(version);
        var s = Canon.TrimAscii(sha256).ToLowerInvariant();
        if (!Canon.OsRe.IsMatch(o)) throw new ArgumentException("os must match ^[a-z0-9_-]{1,32}$");
        if (!Canon.VersionRe.IsMatch(v)) throw new ArgumentException("version must match ^[0-9A-Za-z.+-]{1,64}$");
        if (!Canon.ShaRe.IsMatch(s)) throw new ArgumentException("sha256 must be 64 hex characters");
        if (size < 0) throw new ArgumentException("size must be >= 0");
        if (policy.Rollout is { } r && (r.Percent < 0 || r.Percent > 100 || !Canon.SaltRe.IsMatch(r.Salt ?? "")))
            throw new ArgumentException("rollout must be percent 0..100 and salt [A-Za-z0-9._-]{0,64}");
        foreach (var b in policy.BadVersions ?? Array.Empty<string>())
            if (!Canon.VersionRe.IsMatch(Canon.TrimAscii(b))) throw new ArgumentException("badVersions entries must match ^[0-9A-Za-z.+-]{1,64}$");
        if (policy.Seq is { } q && (q < 1 || q > Canon.MaxSafeInteger)) throw new ArgumentException("seq must be 1..2^53-1");
        if (policy.ExpiresAt is { } e && (e < 0 || e > Canon.MaxSafeInteger)) throw new ArgumentException("expiresAt must be 0..2^53-1");
        return (o, v, s);
    }

    /// <summary>
    /// Verifies a v3 signature. Returns null when valid, otherwise the reason. Fail-closed: a missing key, missing signature,
    /// malformed value or wrong key is always a refusal. Freshness (seq / expiry) is checked separately by <see cref="Freshness"/>.
    /// <para>v3 の署名を確かめる。null = 正しい。鍵なし・署名なし・形の不正・鍵違いは必ず拒否。鮮度は <see cref="Freshness"/> で別に確かめる。</para>
    /// </summary>
    public static UpdateError? VerifyV3(UpdateSafetyOptions options, ReleaseInfo release, string? publicKeyPem)
    {
        string payload;
        try { payload = BuildPayloadV3(options, release.Os, release.Version, release.Sha256, release.Size, release.Policy); }
        catch (ArgumentException ex) { return new UpdateError(UpdateErrorCode.InvalidField, ex.Message); }
        return VerifyPayload(payload, release.SignatureV3, publicKeyPem);
    }

    /// <summary>Verifies a v2 signature (migration only: v2 cannot detect replay). <para>v2 の確かめ（移行用。再送は見抜けない）。</para></summary>
    public static UpdateError? VerifyV2(UpdateSafetyOptions options, ReleaseInfo release, string? publicKeyPem)
    {
        string payload;
        try { payload = BuildPayloadV2(options, release.Os, release.Version, release.Sha256, release.Size, release.Policy.Rollout, release.Policy.BadVersions); }
        catch (ArgumentException ex) { return new UpdateError(UpdateErrorCode.InvalidField, ex.Message); }
        return VerifyPayload(payload, release.SignatureV2, publicKeyPem);
    }

    /// <summary>Verifies a DER ECDSA P-256/SHA-256 signature over an exact UTF-8 string. <para>文字列そのものへの署名を確かめる。</para></summary>
    public static UpdateError? VerifyPayload(string payload, string? signatureBase64, string? publicKeyPem)
    {
        if (string.IsNullOrWhiteSpace(publicKeyPem)) return new UpdateError(UpdateErrorCode.NoPublicKey);
        if (string.IsNullOrWhiteSpace(signatureBase64)) return new UpdateError(UpdateErrorCode.NoSignature);
        byte[] sig;
        try { sig = Convert.FromBase64String(signatureBase64.Trim()); }
        catch (FormatException) { return new UpdateError(UpdateErrorCode.BadSignatureEncoding, "base64"); }
        if (sig.Length == 0) return new UpdateError(UpdateErrorCode.BadSignatureEncoding, "empty");
        try
        {
            using var ec = ECDsa.Create();
            ec.ImportFromPem(publicKeyPem);
            if (ec.KeySize != 256) return new UpdateError(UpdateErrorCode.VerifyFailed, "key is not P-256");
            return ec.VerifyData(Encoding.UTF8.GetBytes(payload), sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)
                ? null
                : new UpdateError(UpdateErrorCode.SignatureMismatch);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            return new UpdateError(UpdateErrorCode.VerifyFailed, ex.GetType().Name);
        }
    }

    /// <summary>
    /// Download location and hash check: the URL must be a relative path on the same server (and start with
    /// <see cref="UpdateSafetyOptions.AllowedDownloadPrefix"/> when set); sha256 must be 64 hex characters.
    /// <para>ダウンロード先（同じサーバーの相対パス。接頭辞の指定があればそれで始まる）と sha256（64 桁の 16 進）の確かめ。</para>
    /// </summary>
    public static UpdateError? ValidateSource(UpdateSafetyOptions options, string? downloadUrl, string? sha256)
    {
        var url = Canon.TrimAscii(downloadUrl);
        if (url.Length == 0 || url[0] != '/' || url.StartsWith("//", StringComparison.Ordinal) || url.Contains('\\') || url.Contains("://", StringComparison.Ordinal))
            return new UpdateError(UpdateErrorCode.BadSource, "url must be a same-server relative path");
        if (options.AllowedDownloadPrefix is { } p && !url.StartsWith(p, StringComparison.Ordinal))
            return new UpdateError(UpdateErrorCode.BadSource, "url prefix");
        var s = Canon.TrimAscii(sha256).ToLowerInvariant();
        if (!Canon.ShaRe.IsMatch(s)) return new UpdateError(UpdateErrorCode.BadSource, "sha256");
        return null;
    }
}

/// <summary>
/// Freshness of signed release info. The client stores the highest sequence number it has accepted; older info is refused
/// (replay), and info past its signed expiry is refused (freeze). The very first info a fresh install sees is trusted as long as
/// its seq is at least <c>minimumSeq</c> (embed the seq of the build's own release to close that gap).
/// <para>署名された配信情報の鮮度。端末は受け入れた最大の通し番号を覚え、それより古い情報（再送）と、期限切れの情報（凍結）を拒む。
/// 入れたばかりの端末は minimumSeq 以上なら受け入れる（ビルド時の通し番号を焼き込むと穴を狭められる）。</para>
/// </summary>
public static class Freshness
{
    /// <summary>Returns null when fresh, otherwise <see cref="UpdateErrorCode.Replay"/> / <see cref="UpdateErrorCode.Expired"/>.</summary>
    public static UpdateError? Check(ReleasePolicy policy, long lastAcceptedSeq, DateTimeOffset nowUtc, long minimumSeq = 0)
    {
        if (policy.Seq is not { } seq) return new UpdateError(UpdateErrorCode.InvalidField, "seq missing");
        if (seq < lastAcceptedSeq || seq < minimumSeq)
            return new UpdateError(UpdateErrorCode.Replay, string.Create(CultureInfo.InvariantCulture, $"seq {seq} < {Math.Max(lastAcceptedSeq, minimumSeq)}"));
        if (policy.ExpiresAt is { } exp && nowUtc.ToUnixTimeSeconds() > exp)
            return new UpdateError(UpdateErrorCode.Expired, DateTimeOffset.FromUnixTimeSeconds(exp).ToString("u", CultureInfo.InvariantCulture));
        return null;
    }
}

/// <summary>Reads release info from JSON (the manifest written by tools/sign-manifest.mjs, or an equivalent server response).
/// <para>JSON（sign-manifest.mjs が書く manifest か同じ形のサーバー応答）から版の情報を読む。</para></summary>
public static class ReleaseJson
{
    /// <summary>
    /// Reads the policy fields (rollout, rollback.badVersions, seq, expiresAt). Missing / null sections mean "everyone" and
    /// "no revoked versions". A malformed section returns an error (caller must not offer or roll back).
    /// <para>方針の欄を読む。欄が無い・null は「全員・不具合版なし」。形が不正なら誤り（出さない・戻さない）。</para>
    /// </summary>
    public static (ReleasePolicy? Policy, UpdateError? Error) ParsePolicy(JsonElement root)
    {
        static (ReleasePolicy?, UpdateError?) Bad(string why) => (null, new UpdateError(UpdateErrorCode.PolicyInvalid, why));
        if (root.ValueKind != JsonValueKind.Object) return Bad("root");
        RolloutSpec? rollout = null;
        if (root.TryGetProperty("rollout", out var ro) && ro.ValueKind != JsonValueKind.Null)
        {
            if (ro.ValueKind != JsonValueKind.Object) return Bad("rollout");
            if (!ro.TryGetProperty("percent", out var p) || p.ValueKind != JsonValueKind.Number || !p.TryGetInt32(out var pct) || pct < 0 || pct > 100)
                return Bad("rollout.percent must be an integer 0..100");
            var salt = "";
            if (ro.TryGetProperty("salt", out var s) && s.ValueKind != JsonValueKind.Null)
            {
                if (s.ValueKind != JsonValueKind.String) return Bad("rollout.salt");
                salt = s.GetString() ?? "";
            }
            if (!Canon.SaltRe.IsMatch(salt)) return Bad("rollout.salt characters");
            rollout = new RolloutSpec(pct, salt);
        }
        var bad = new List<string>();
        if (root.TryGetProperty("rollback", out var rb) && rb.ValueKind != JsonValueKind.Null)
        {
            if (rb.ValueKind != JsonValueKind.Object) return Bad("rollback");
            if (rb.TryGetProperty("badVersions", out var bv) && bv.ValueKind != JsonValueKind.Null)
            {
                if (bv.ValueKind != JsonValueKind.Array) return Bad("rollback.badVersions");
                foreach (var e in bv.EnumerateArray())
                {
                    if (e.ValueKind != JsonValueKind.String) return Bad("rollback.badVersions element");
                    var v = Canon.TrimAscii(e.GetString());
                    if (!Canon.VersionRe.IsMatch(v)) return Bad("rollback.badVersions value");
                    bad.Add(v);
                }
            }
        }
        long? seq = null, exp = null;
        if (root.TryGetProperty("seq", out var sq) && sq.ValueKind != JsonValueKind.Null)
        {
            if (sq.ValueKind != JsonValueKind.Number || !sq.TryGetInt64(out var q) || q < 1 || q > Canon.MaxSafeInteger) return Bad("seq must be an integer 1..2^53-1");
            seq = q;
        }
        if (root.TryGetProperty("expiresAt", out var ex) && ex.ValueKind != JsonValueKind.Null)
        {
            if (ex.ValueKind != JsonValueKind.Number || !ex.TryGetInt64(out var t) || t < 0 || t > Canon.MaxSafeInteger) return Bad("expiresAt must be Unix seconds");
            exp = t;
        }
        return (new ReleasePolicy(rollout, bad, seq, exp), null);
    }

    /// <summary>
    /// Reads one OS entry of a manifest: { version, rollout, rollback, seq, expiresAt, signatures: { "&lt;os&gt;": { sha256, size, signatureV3 } } }.
    /// <para>manifest の 1 つの OS の分を読む。</para>
    /// </summary>
    public static (ReleaseInfo? Release, UpdateError? Error) FromManifest(JsonElement manifest, string os)
    {
        var (policy, err) = ParsePolicy(manifest);
        if (policy is null) return (null, err);
        if (!manifest.TryGetProperty("version", out var v) || v.ValueKind != JsonValueKind.String) return (null, new UpdateError(UpdateErrorCode.InvalidField, "version"));
        var key = Canon.TrimAscii(os).ToLowerInvariant();
        if (!manifest.TryGetProperty("signatures", out var sigs) || sigs.ValueKind != JsonValueKind.Object || !sigs.TryGetProperty(key, out var e) || e.ValueKind != JsonValueKind.Object)
            return (null, new UpdateError(UpdateErrorCode.NoSignature, "signatures." + key));
        string? Str(string n) => e.TryGetProperty(n, out var x) && x.ValueKind == JsonValueKind.String ? x.GetString() : null;
        if (!e.TryGetProperty("size", out var sz) || !sz.TryGetInt64(out var size)) return (null, new UpdateError(UpdateErrorCode.InvalidField, "size"));
        return (new ReleaseInfo(key, v.GetString() ?? "", Str("sha256") ?? "", size, policy, Str("signatureV3"), Str("signatureV2")), null);
    }
}
