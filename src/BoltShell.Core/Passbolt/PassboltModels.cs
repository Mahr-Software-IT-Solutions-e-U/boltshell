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
    IReadOnlyDictionary<string, string> CustomFieldValues);

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
