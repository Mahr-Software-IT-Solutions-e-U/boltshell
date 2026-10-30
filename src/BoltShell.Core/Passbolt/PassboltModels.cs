using static BoltShell.Core.Localization.Texts;

namespace BoltShell.Core.Passbolt;

/// <summary>Everything needed to log in, except the passphrase. Safe to persist (the key is passphrase-protected).</summary>
public sealed record PassboltAccount(
    string ServerUrl,
    string UserId,
    string ArmoredPrivateKey,
    string? Username = null,
    string? ServerFingerprint = null)
{
    public string BaseUrl => ServerUrl.TrimEnd('/');

    /// <summary>
    /// Passbolt must be reached over HTTPS: bearer and refresh tokens and TOTP codes travel outside the PGP layer.
    /// Plain HTTP is only allowed for loopback addresses (local development).
    /// </summary>
    /// <exception cref="ArgumentException">The URL is not absolute, or uses HTTP for a non-loopback host.</exception>
    public static Uri ValidateServerUrl(string? url)
    {
        if (!Uri.TryCreate(url?.Trim(), UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || string.IsNullOrEmpty(uri.Host))
            throw new ArgumentException(Tr("'{0}' is not a valid Passbolt address (https://…).", url));
        if (uri.Scheme == Uri.UriSchemeHttp && !uri.IsLoopback)
            throw new ArgumentException(Tr("Passbolt must be reachable via HTTPS; '{0}' was given with http://.", uri.Host));
        return uri;
    }
}

/// <summary>A decrypted, display-ready Passbolt resource (no secret data).</summary>
public sealed record PassboltResource(
    string Id,
    string Name,
    string? Username,
    IReadOnlyList<string> Uris,
    string? Description,
    string? ResourceTypeId,
    string? FolderParentId,
    DateTimeOffset? Modified,
    IReadOnlyList<CustomFieldDefinition> CustomFields)
{
    public string? PrimaryUri => Uris.Count > 0 ? Uris[0] : null;
}

/// <summary>Custom field metadata (Passbolt v5). The value lives in the secret.</summary>
public sealed record CustomFieldDefinition(string Id, string Key, string? MetadataValue);

/// <summary>Decrypted secret of a resource.</summary>
public sealed record PassboltSecret(
    string? Password,
    string? Description,
    IReadOnlyDictionary<string, string> CustomFieldValues,
    Crypto.TotpSettings? Totp = null);

/// <summary>A resource to create. Custom fields need Passbolt v5.</summary>
public sealed record NewResource(
    string Name,
    string Username,
    IReadOnlyList<string> Uris,
    string? Password,
    string? FolderId,
    IReadOnlyList<NewCustomField> CustomFields,
    string? Description = null);

/// <param name="Type">Passbolt custom field type: <c>text</c> or <c>password</c>.</param>
public sealed record NewCustomField(string Key, string Value, string Type = "text");

public sealed record PassboltFolder(string Id, string Name, string? FolderParentId);

public sealed record LoginResult(IReadOnlyList<string> MfaProviders)
{
    public bool MfaRequired => MfaProviders.Count > 0;
}

public sealed class PassboltApiException(string message, int? statusCode = null, Exception? inner = null)
    : Exception(message, inner)
{
    public int? StatusCode { get; } = statusCode;
}
