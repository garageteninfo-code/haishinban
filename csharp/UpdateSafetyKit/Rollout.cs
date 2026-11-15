using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace UpdateSafetyKit;

/// <summary>
/// Staged rollout and the "should this device get the update?" decision. A device's bucket is
/// sha256(installId + salt)[0..2] mod 100; it is in the rollout when bucket &lt; percent. Raising the percent with the same salt
/// never removes a device that was already in; changing the salt reshuffles devices.
/// <para>段階配信と「この端末に新しい版を出すか」の判定。組＝sha256(installId + salt) の先頭 2 バイト mod 100。
/// 同じ salt で割合を上げても、前に当たった端末は外れない。salt を変えると引き直し。</para>
/// </summary>
public static class Rollout
{
    private static readonly Regex InstallIdRe = new("^[0-9a-f]{32}$", RegexOptions.CultureInvariant);

    /// <summary>This device's bucket (0..99). <para>この端末の組の番号。</para></summary>
    public static int Bucket(string installId, string salt)
    {
        var h = SHA256.HashData(Encoding.UTF8.GetBytes((installId ?? "") + (salt ?? "")));
        return ((h[0] << 8) | h[1]) % 100;
    }

    /// <summary>
    /// In the rollout? No rollout = everyone, 0% = nobody, 100% = everyone. A device without a valid install id is only included at 100%.
    /// <para>対象か。installId が無い・壊れている端末は 100% のときだけ対象。</para>
    /// </summary>
    public static bool InCohort(string? installId, RolloutSpec? rollout)
    {
        if (rollout is null || rollout.Percent >= 100) return true;
        if (rollout.Percent <= 0 || !IsValidInstallId(installId)) return false;
        return Bucket(installId!, rollout.Salt ?? "") < rollout.Percent;
    }

    /// <summary>New random install id (32 lowercase hex). Keep it on the device; it is never sent anywhere.
    /// <para>新しい端末の乱数（外へ送らない）。</para></summary>
    public static string NewInstallId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    /// <summary>True for 32 lowercase hex characters.</summary>
    public static bool IsValidInstallId(string? s) => s is not null && InstallIdRe.IsMatch(s);

    /// <summary>Result kinds of <see cref="DecideOffer"/>. <para>判定の種類。</para></summary>
    public enum OfferKind
    {
        /// <summary>The server announces nothing.</summary>
        None,
        /// <summary>Offer the update.</summary>
        Offer,
        /// <summary>Signature, policy or freshness could not be verified (fail-closed).</summary>
        Unverified,
        /// <summary>Not in this staged rollout yet.</summary>
        NotInCohort,
        /// <summary>This device rolled this version back before; it is not taken again automatically.</summary>
        RolledBackBefore,
        /// <summary>Not newer than the current version, and the current version is not signed as revoked (downgrade protection).</summary>
        NotNewer,
        /// <summary>The announced version itself is in the signed revoked list (never offer a revoked version).</summary>
        LatestRevoked,
    }

    /// <summary>The decision and the rollout percent (for messages). <para>判定と割合（知らせの文に使う）。</para></summary>
    public sealed record OfferDecision(OfferKind Kind, int Percent);

    /// <summary>
    /// Decides whether to offer <paramref name="latest"/>. Order: nothing announced → verification → announced version revoked → downgrade protection →
    /// rolled back before → rollout. <paramref name="verificationError"/> is the combined result of signature + policy +
    /// freshness (null = all fine). <paramref name="current"/> is required: an older (correctly signed) release is offered only
    /// when the current version is in the signed revoked list.
    /// <para>出すかの判定。current は必須（古い版へ移すのは、今の版が署名つきの不具合版のときだけ）。verificationError は署名・方針・鮮度の結果をまとめたもの。</para>
    /// </summary>
    public static OfferDecision DecideOffer(bool serverAvailable, string? latest, string current, ReleasePolicy? policy,
        UpdateError? verificationError, string? installId, IEnumerable<string>? rolledBackVersions)
    {
        if (current is null) throw new ArgumentNullException(nameof(current));
        if (!serverAvailable) return new(OfferKind.None, 100);
        if (policy is null || verificationError is not null) return new(OfferKind.Unverified, 0);
        if (VersionCompare.IsListed(latest, policy.BadVersions)) return new(OfferKind.LatestRevoked, 0);
        if (!VersionCompare.IsNewer(current, latest) && !VersionCompare.IsListed(current, policy.BadVersions)) return new(OfferKind.NotNewer, 100);
        var pct = policy.Rollout?.Percent ?? 100;
        if (rolledBackVersions is not null && rolledBackVersions.Any(v => VersionCompare.Same(v, latest))) return new(OfferKind.RolledBackBefore, pct);
        if (!InCohort(installId, policy.Rollout)) return new(OfferKind.NotInCohort, pct);
        return new(OfferKind.Offer, pct);
    }
}
