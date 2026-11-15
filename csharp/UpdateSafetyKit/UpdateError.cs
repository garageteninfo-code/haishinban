namespace UpdateSafetyKit;

/// <summary>Why an update step was refused. Every refusal is fail-closed (the update is not applied).
/// <para>更新を止めた理由。どれも「止める側」（適用しない）。</para></summary>
public enum UpdateErrorCode
{
    /// <summary>No public key is embedded in the app.</summary>
    NoPublicKey,
    /// <summary>The release carries no signature.</summary>
    NoSignature,
    /// <summary>The signature is not valid base64 or is empty.</summary>
    BadSignatureEncoding,
    /// <summary>The signature does not match the publisher key (tampering or impersonation).</summary>
    SignatureMismatch,
    /// <summary>The key or signature could not be processed.</summary>
    VerifyFailed,
    /// <summary>A signed field (os, version, sha256, size, seq, expiry) has a form that cannot be signed safely.</summary>
    InvalidField,
    /// <summary>The rollout / revocation section of the release info is malformed.</summary>
    PolicyInvalid,
    /// <summary>The release info is older than one already accepted on this device (replay of an old signed manifest).</summary>
    Replay,
    /// <summary>The signed release info has expired (a server may be freezing clients on old info).</summary>
    Expired,
    /// <summary>The download location or hash is not acceptable.</summary>
    BadSource,
}

/// <summary>A refusal with a code and a short bilingual message. <para>止めた理由（符号と日英の短い文）。</para></summary>
public sealed record UpdateError(UpdateErrorCode Code, string Detail = "")
{
    /// <summary>User-facing message in the requested language. <para>指定の言語の知らせの文。</para></summary>
    public string Message(UpdateLanguage lang = UpdateLanguage.English)
    {
        var ja = lang == UpdateLanguage.Japanese;
        var text = Code switch
        {
            UpdateErrorCode.NoPublicKey => ja ? "更新の署名を確かめる公開鍵がアプリに組み込まれていません。適用を中止しました。" : "No update-signing public key is embedded in the app. The update was not applied.",
            UpdateErrorCode.NoSignature => ja ? "更新に配布元の署名がありません（未署名の更新は適用できません）。" : "The update has no publisher signature (unsigned updates are never applied).",
            UpdateErrorCode.BadSignatureEncoding => ja ? "更新の署名の形が不正です。" : "The update signature is malformed.",
            UpdateErrorCode.SignatureMismatch => ja ? "更新の署名が配布元の鍵と一致しません（改ざん・なりすましの可能性）。適用を中止しました。" : "The update signature does not match the publisher key (possible tampering). The update was not applied.",
            UpdateErrorCode.VerifyFailed => ja ? "更新の署名を確かめられませんでした。適用を中止しました。" : "The update signature could not be verified. The update was not applied.",
            UpdateErrorCode.InvalidField => ja ? "更新の情報に署名できない形の値があります。" : "The update info contains a value that cannot be signed safely.",
            UpdateErrorCode.PolicyInvalid => ja ? "配信の指定（段階配信・不具合版）の形が不正です。" : "The rollout / revocation section is malformed.",
            UpdateErrorCode.Replay => ja ? "この端末が前に受け取ったものより古い配信情報です（古い情報の再送の可能性）。" : "This release info is older than one this device already accepted (possible replay).",
            UpdateErrorCode.Expired => ja ? "配信情報の有効期限が切れています（古い情報で止められている可能性）。" : "The signed release info has expired (the server may be serving stale info).",
            UpdateErrorCode.BadSource => ja ? "ダウンロード先またはハッシュが不正です。適用を中止しました。" : "The download location or hash is not acceptable. The update was not applied.",
            _ => Code.ToString(),
        };
        return Detail.Length == 0 ? text : $"{text} ({Detail})";
    }

    /// <inheritdoc />
    public override string ToString() => $"{Code}{(Detail.Length > 0 ? ": " + Detail : "")}";
}
