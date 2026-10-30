using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Bcpg.OpenPgp;
using BoltShell.Core.Crypto;

namespace BoltShell.Core.Passbolt;

/// <summary>
/// Minimal Passbolt API client using JWT authentication.
/// All decryption happens locally; the server only ever sees encrypted data.
/// </summary>
public sealed class PassboltClient : IDisposable
{
    private static readonly HashSet<string> PlainPasswordTypes = ["password-string", "v5-password-string"];

    private readonly PassboltAccount _account;
    private readonly HttpClient _http;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private readonly Dictionary<string, string> _resourceTypeSlugs = new();
    private readonly Dictionary<string, ResourceType> _resourceTypes = new();

    private PgpKeyChain? _keys;
    private PgpPublicKeys? _serverKey;
    private string? _accessToken;
    private string? _refreshToken;
    private bool _metadataKeysLoaded;
    private (string Id, PgpPublicKeys Key)? _sharedMetadataKey;
    private readonly Dictionary<string, PgpPublicKeys> _metadataPublicKeys = new();

    public PassboltClient(PassboltAccount account, HttpMessageHandler? handler = null, ILogger<PassboltClient>? logger = null)
    {
        PassboltAccount.ValidateServerUrl(account.BaseUrl); // also covers accounts stored before this check existed
        _account = account;
        _logger = logger ?? NullLogger<PassboltClient>.Instance;
        _http = new HttpClient(handler ?? new HttpClientHandler { CookieContainer = new CookieContainer() })
        {
            BaseAddress = new Uri(account.BaseUrl + "/"),
            Timeout = TimeSpan.FromSeconds(30),
        };
        _http.DefaultRequestHeaders.Accept.ParseAdd("application/json");
    }

    public PassboltAccount Account => _account;
    public bool IsAuthenticated => _accessToken is not null;
    public string? ServerFingerprint => _serverKey?.Fingerprint;

    /// <summary>Unlocks the user key and performs the JWT challenge/response login.</summary>
    /// <exception cref="PgpException">Wrong passphrase.</exception>
    /// <exception cref="PassboltApiException">Server rejected the login or its key does not match.</exception>
    public async Task<LoginResult> LoginAsync(string passphrase, CancellationToken ct = default)
    {
        _keys = PgpKeyChain.Unlock(_account.ArmoredPrivateKey, passphrase);

        var verify = await SendAsync(HttpMethod.Get, "auth/verify.json", null, authenticated: false, ct);
        _serverKey = PgpPublicKeys.Parse(verify["keydata"]?.GetValue<string>()
                                         ?? throw new PassboltApiException("Server did not return its public key."));
        if (_account.ServerFingerprint is { } expected
            && !string.Equals(expected, _serverKey.Fingerprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new PassboltApiException(
                $"Server key fingerprint {_serverKey.Fingerprint} does not match the expected {expected}. " +
                "The server may have been replaced or compromised.");
        }

        var verifyToken = Guid.NewGuid().ToString();
        var challenge = new JsonObject
        {
            ["version"] = "1.0.0",
            ["domain"] = _account.BaseUrl,
            ["verify_token"] = verifyToken,
            ["verify_token_expiry"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
        };
        var encrypted = PgpMessage.EncryptAndSign(challenge.ToJsonString(), _serverKey, _keys);

        var login = await SendAsync(HttpMethod.Post, "auth/jwt/login.json",
            new JsonObject { ["user_id"] = _account.UserId, ["challenge"] = encrypted }, authenticated: false, ct);

        var response = JsonNode.Parse(PgpMessage.Decrypt(
            login["challenge"]?.GetValue<string>() ?? throw new PassboltApiException("Login response has no challenge."),
            _keys, verifyWith: _serverKey))!;

        if (response["verify_token"]?.GetValue<string>() != verifyToken)
            throw new PassboltApiException("Server returned an invalid verify token.");

        _accessToken = response["access_token"]?.GetValue<string>();
        _refreshToken = response["refresh_token"]?.GetValue<string>();
        if (_accessToken is null)
            throw new PassboltApiException("Server did not return an access token.");

        var mfa = login["mfa_providers"]?.AsArray().Select(n => n!.GetValue<string>()).ToList() ?? [];
        _logger.LogInformation("Logged in to {Server} (MFA providers: {Mfa})", _account.BaseUrl, string.Join(",", mfa));

        if (mfa.Count == 0)
            await LoadResourceTypesAsync(ct);
        return new LoginResult(mfa);
    }

    /// <summary>Completes a login that requires TOTP based multi-factor authentication.</summary>
    public async Task VerifyTotpAsync(string code, CancellationToken ct = default)
    {
        await SendAsync(HttpMethod.Post, "mfa/verify/totp.json",
            new JsonObject { ["totp"] = code, ["remember"] = false }, authenticated: true, ct);
        await LoadResourceTypesAsync(ct);
    }

    public async Task LogoutAsync(CancellationToken ct = default)
    {
        if (_accessToken is not null && _refreshToken is not null)
        {
            try
            {
                await SendAsync(HttpMethod.Post, "auth/jwt/logout.json",
                    new JsonObject { ["refresh_token"] = _refreshToken }, authenticated: true, ct);
            }
            catch (Exception ex) when (ex is PassboltApiException or HttpRequestException)
            {
                _logger.LogDebug(ex, "Logout failed; discarding tokens anyway.");
            }
        }
        _accessToken = _refreshToken = null;
        _keys = null;
    }

    public async Task<IReadOnlyList<PassboltFolder>> GetFoldersAsync(CancellationToken ct = default)
    {
        var body = await SendAsync(HttpMethod.Get, "folders.json", null, authenticated: true, ct);
        return body.AsArray()
            .Select(f => new PassboltFolder(
                f!["id"]!.GetValue<string>(),
                f["name"]?.GetValue<string>() ?? "(unnamed)",
                f["folder_parent_id"]?.GetValue<string>()))
            .ToList();
    }

    public async Task<IReadOnlyList<PassboltResource>> GetResourcesAsync(CancellationToken ct = default)
    {
        var keys = RequireKeys();
        var body = await SendAsync(HttpMethod.Get, "resources.json", null, authenticated: true, ct);
        var items = body.AsArray();

        if (!_metadataKeysLoaded && items.Any(r => r?["metadata_key_type"]?.GetValue<string>() == "shared_key"))
            await LoadMetadataKeysAsync(ct);

        var result = new List<PassboltResource>(items.Count);
        foreach (var item in items)
        {
            try
            {
                result.Add(ParseResource(item!, keys));
            }
            catch (Exception ex) when (ex is PgpException or JsonException or InvalidOperationException)
            {
                _logger.LogWarning(ex, "Skipping resource {Id} that could not be decrypted", item?["id"]);
            }
        }
        return result;
    }

    /// <summary>Fetches and decrypts the secret of a resource. Call this only right before it is needed.</summary>
    public async Task<PassboltSecret> GetSecretAsync(PassboltResource resource, CancellationToken ct = default)
    {
        var keys = RequireKeys();
        var body = await SendAsync(HttpMethod.Get, $"secrets/resource/{Uri.EscapeDataString(resource.Id)}.json", null, authenticated: true, ct);
        var plaintext = PgpMessage.Decrypt(body["data"]?.GetValue<string>()
                                           ?? throw new PassboltApiException("Secret has no data."), keys);
        var slug = resource.ResourceTypeId is { } typeId ? _resourceTypeSlugs.GetValueOrDefault(typeId) : null;
        return ParseSecret(plaintext, slug);
    }

    /// <summary>
    /// Creates a resource. Uses a Passbolt v5 type with encrypted metadata and custom fields when the server offers one,
    /// otherwise a v4 "password and description" resource (custom fields are then not available).
    /// If <paramref name="resource"/> has a folder, the folder's permissions are applied, so everyone who can see the folder can use the resource.
    /// </summary>
    /// <returns>The new resource id, and a warning if sharing with the folder's users failed.</returns>
    public async Task<(string Id, string? Warning)> CreateResourceAsync(NewResource resource, CancellationToken ct = default)
    {
        var keys = RequireKeys();
        if (!_metadataKeysLoaded)
            await LoadMetadataKeysAsync(ct);

        var v5Type = _resourceTypes.Values.FirstOrDefault(t => t.Slug == "v5-default");
        var v4Type = _resourceTypes.Values.FirstOrDefault(t => t.Slug == "password-and-description");
        var ownPublicKey = keys.PublicKeys;

        JsonObject body;
        string secretPlaintext;
        if (v5Type is not null)
        {
            var fields = resource.CustomFields.Select(f => (Field: f, Id: Guid.NewGuid().ToString())).ToList();
            var metadata = new JsonObject
            {
                ["object_type"] = "PASSBOLT_RESOURCE_METADATA",
                ["resource_type_id"] = v5Type.Id,
                ["name"] = resource.Name,
                ["username"] = resource.Username,
                ["uris"] = new JsonArray(resource.Uris.Select(u => (JsonNode)JsonValue.Create(u)!).ToArray()),
                ["description"] = resource.Description ?? "",
                ["custom_fields"] = new JsonArray(fields.Select(f => (JsonNode)new JsonObject
                {
                    ["id"] = f.Id, ["type"] = f.Field.Type, ["metadata_key"] = f.Field.Key,
                }).ToArray()),
            };
            secretPlaintext = new JsonObject
            {
                ["object_type"] = "PASSBOLT_SECRET_DATA",
                ["resource_type_id"] = v5Type.Id,
                ["password"] = resource.Password ?? "",
                ["description"] = "",
                ["custom_fields"] = new JsonArray(fields.Select(f => (JsonNode)new JsonObject
                {
                    ["id"] = f.Id, ["type"] = f.Field.Type, ["secret_value"] = f.Field.Value,
                }).ToArray()),
            }.ToJsonString();

            // Prefer the organisation's shared metadata key so the resource can be shared; else the user's own key.
            var (metadataKeyId, metadataKeyType, metadataRecipient) = _sharedMetadataKey is { } shared
                ? (shared.Id, "shared_key", shared.Key)
                : (await GetOwnGpgKeyIdAsync(ct), "user_key", ownPublicKey);
            body = new JsonObject
            {
                ["resource_type_id"] = v5Type.Id,
                ["folder_parent_id"] = resource.FolderId,
                ["metadata"] = PgpMessage.EncryptAndSign(metadata.ToJsonString(), metadataRecipient, keys),
                ["metadata_key_id"] = metadataKeyId,
                ["metadata_key_type"] = metadataKeyType,
            };
        }
        else if (v4Type is not null)
        {
            var privateKey = resource.CustomFields.FirstOrDefault(f => f.Key == Ssh.SshConnectionMapper.PrivateKeyField)?.Value;
            secretPlaintext = new JsonObject
            {
                ["password"] = resource.Password ?? "",
                ["description"] = privateKey ?? "",
            }.ToJsonString();
            body = new JsonObject
            {
                ["name"] = resource.Name,
                ["username"] = resource.Username,
                ["uri"] = resource.Uris.FirstOrDefault() ?? "",
                ["description"] = resource.Description ?? "",
                ["resource_type_id"] = v4Type.Id,
                ["folder_parent_id"] = resource.FolderId,
            };
        }
        else
        {
            throw new PassboltApiException("The server offers no supported resource type (v5-default or password-and-description).");
        }

        body["secrets"] = new JsonArray(new JsonObject { ["data"] = PgpMessage.EncryptAndSign(secretPlaintext, ownPublicKey, keys) });
        var created = await SendAsync(HttpMethod.Post, "resources.json", body, authenticated: true, ct);
        var id = created["id"]?.GetValue<string>() ?? throw new PassboltApiException("Server did not return the new resource id.");

        string? warning = null;
        if (resource.FolderId is { } folderId)
        {
            try
            {
                await ShareLikeFolderAsync(id, folderId, secretPlaintext, ct);
            }
            catch (Exception ex) when (ex is PassboltApiException or PgpException or HttpRequestException or InvalidOperationException)
            {
                _logger.LogWarning(ex, "Sharing resource {Id} like folder {Folder} failed", id, folderId);
                warning = "Die Ressource wurde angelegt, aber die Freigaben des Ordners konnten nicht übernommen werden: " + ex.Message;
            }
        }
        return (id, warning);
    }

    /// <summary>
    /// Sets a text custom field (e.g. <c>ssh_host_key</c>) of an existing Passbolt v5 resource: adds it if missing,
    /// otherwise replaces its value. The value is stored in the secret like the Passbolt extension does, so the secret is
    /// re-encrypted for every user with access; the metadata keeps its key (shared or personal).
    /// </summary>
    public async Task SetCustomFieldAsync(string resourceId, string key, string value, CancellationToken ct = default)
    {
        var keys = RequireKeys();
        if (!_metadataKeysLoaded)
            await LoadMetadataKeysAsync(ct);
        var escapedId = Uri.EscapeDataString(resourceId);
        var item = await SendAsync(HttpMethod.Get, $"resources/{escapedId}.json", null, authenticated: true, ct);
        if (item["metadata"]?.GetValue<string>() is not { } armoredMetadata)
            throw new PassboltApiException("This is a Passbolt v4 resource; custom fields need a v5 resource. Migrate it in Passbolt or add the field there.");
        var metadataKeyId = item["metadata_key_id"]?.GetValue<string>();
        var metadataKeyType = item["metadata_key_type"]?.GetValue<string>() ?? "user_key";
        var typeId = item["resource_type_id"]?.GetValue<string>();

        var metadata = JsonNode.Parse(PgpMessage.Decrypt(armoredMetadata, keys))!.AsObject();
        var secretBody = await SendAsync(HttpMethod.Get, $"secrets/resource/{escapedId}.json", null, authenticated: true, ct);
        var secretPlaintext = PgpMessage.Decrypt(secretBody["data"]?.GetValue<string>() ?? throw new PassboltApiException("Secret has no data."), keys);
        if (JsonNode.Parse(secretPlaintext) is not JsonObject secret)
            throw new PassboltApiException("The resource's secret is not a v5 secret object.");

        ApplyCustomField(metadata, secret, key, value);

        PgpPublicKeys metadataRecipient;
        if (metadataKeyType == "shared_key")
            metadataRecipient = metadataKeyId is not null && _metadataPublicKeys.TryGetValue(metadataKeyId, out var shared) ? shared
                : throw new PassboltApiException("The shared metadata key of this resource is not available.");
        else
            metadataRecipient = keys.PublicKeys;

        // Everyone with access needs the new secret, encrypted to their own key.
        var users = await SendAsync(HttpMethod.Get, $"users.json?filter[has-access]={escapedId}&contain[gpgkey]=1", null, authenticated: true, ct);
        var secrets = new JsonArray();
        var newSecret = secret.ToJsonString();
        foreach (var user in users.AsArray())
        {
            var userId = user?["id"]?.GetValue<string>();
            var armored = user?["gpgkey"]?["armored_key"]?.GetValue<string>();
            if (userId is null || armored is null)
                throw new PassboltApiException($"User {userId} has no public key.");
            var recipient = userId == _account.UserId ? keys.PublicKeys : PgpPublicKeys.Parse(armored);
            secrets.Add(new JsonObject { ["user_id"] = userId, ["data"] = PgpMessage.EncryptAndSign(newSecret, recipient, keys) });
        }
        if (secrets.Count == 0)
            throw new PassboltApiException("Could not determine who has access to the resource.");

        var body = new JsonObject
        {
            ["resource_type_id"] = typeId,
            ["metadata"] = PgpMessage.EncryptAndSign(metadata.ToJsonString(), metadataRecipient, keys),
            ["metadata_key_id"] = metadataKeyId,
            ["metadata_key_type"] = metadataKeyType,
            ["secrets"] = secrets,
        };
        await SendAsync(HttpMethod.Put, $"resources/{escapedId}.json", body, authenticated: true, ct);
    }

    /// <summary>Adds or replaces custom field <paramref name="key"/> in decrypted v5 metadata and secret objects.</summary>
    internal static void ApplyCustomField(JsonObject metadata, JsonObject secret, string key, string value)
    {
        if (metadata["custom_fields"] is not JsonArray metaFields)
            metadata["custom_fields"] = metaFields = new JsonArray();
        if (secret["custom_fields"] is not JsonArray secretFields)
            secret["custom_fields"] = secretFields = new JsonArray();

        var existing = metaFields.OfType<JsonObject>()
            .FirstOrDefault(f => string.Equals(f["metadata_key"]?.GetValue<string>()?.Trim(), key, StringComparison.OrdinalIgnoreCase));
        string id;
        if (existing is null)
        {
            id = Guid.NewGuid().ToString();
            metaFields.Add(new JsonObject { ["id"] = id, ["type"] = "text", ["metadata_key"] = key });
        }
        else
        {
            id = existing["id"]!.GetValue<string>();
            existing.Remove("metadata_value"); // the secret value is authoritative
        }

        var secretField = secretFields.OfType<JsonObject>().FirstOrDefault(f => f["id"]?.GetValue<string>() == id);
        if (secretField is null)
            secretFields.Add(new JsonObject { ["id"] = id, ["type"] = existing?["type"]?.GetValue<string>() ?? "text", ["secret_value"] = value });
        else
            secretField["secret_value"] = value;
    }

    /// <summary>Applies the folder's user/group permissions to a resource and encrypts its secret for every added user.</summary>
    private async Task ShareLikeFolderAsync(string resourceId, string folderId, string secretPlaintext, CancellationToken ct)
    {
        var keys = RequireKeys();
        var folder = await SendAsync(HttpMethod.Get, $"folders/{Uri.EscapeDataString(folderId)}.json?contain[permissions]=1", null, authenticated: true, ct);
        var permissions = new JsonArray();
        foreach (var permission in folder["permissions"]?.AsArray() ?? [])
        {
            var aro = permission?["aro"]?.GetValue<string>();
            var aroId = permission?["aro_foreign_key"]?.GetValue<string>();
            if (aro is null || aroId is null || aro == "User" && aroId == _account.UserId)
                continue; // the creator already owns the resource
            permissions.Add(new JsonObject { ["is_new"] = true, ["aro"] = aro, ["aro_foreign_key"] = aroId, ["type"] = permission!["type"]!.GetValue<int>() });
        }
        if (permissions.Count == 0)
            return;

        var simulation = await SendAsync(HttpMethod.Post, $"share/simulate/resource/{Uri.EscapeDataString(resourceId)}.json",
            new JsonObject { ["permissions"] = permissions.DeepClone() }, authenticated: true, ct);
        var userIds = (simulation["changes"]?["added"]?.AsArray() ?? [])
            .Select(a => a?["User"]?["id"]?.GetValue<string>())
            .OfType<string>()
            .Where(u => u != _account.UserId)
            .Distinct()
            .ToList();

        var secrets = new JsonArray();
        foreach (var userId in userIds)
        {
            var user = await SendAsync(HttpMethod.Get, $"users/{Uri.EscapeDataString(userId)}.json?contain[gpgkey]=1", null, authenticated: true, ct);
            var armored = user["gpgkey"]?["armored_key"]?.GetValue<string>()
                          ?? throw new PassboltApiException($"User {userId} has no public key.");
            secrets.Add(new JsonObject { ["user_id"] = userId, ["data"] = PgpMessage.EncryptAndSign(secretPlaintext, PgpPublicKeys.Parse(armored), keys) });
        }

        await SendAsync(HttpMethod.Put, $"share/resource/{Uri.EscapeDataString(resourceId)}.json",
            new JsonObject { ["permissions"] = permissions, ["secrets"] = secrets }, authenticated: true, ct);
    }

    private async Task<string> GetOwnGpgKeyIdAsync(CancellationToken ct)
    {
        var me = await SendAsync(HttpMethod.Get, "users/me.json?contain[gpgkey]=1", null, authenticated: true, ct);
        return me["gpgkey"]?["id"]?.GetValue<string>() ?? throw new PassboltApiException("Could not determine the user's key id.");
    }

    internal static PassboltSecret ParseSecret(string plaintext, string? resourceTypeSlug)
    {
        var noFields = new Dictionary<string, string>();
        if (resourceTypeSlug is not null && PlainPasswordTypes.Contains(resourceTypeSlug))
            return new PassboltSecret(plaintext, null, noFields);
        if (!plaintext.TrimStart().StartsWith('{'))
            return new PassboltSecret(plaintext, null, noFields);

        JsonNode? json;
        try
        {
            json = JsonNode.Parse(plaintext);
        }
        catch (JsonException)
        {
            return new PassboltSecret(plaintext, null, noFields);
        }

        var fields = new Dictionary<string, string>();
        if (json?["custom_fields"] is JsonArray customFields)
        {
            foreach (var field in customFields)
            {
                if (field?["id"]?.GetValue<string>() is { } id && field["secret_value"] is JsonValue value)
                    fields[id] = value.ToString();
            }
        }
        return new PassboltSecret(
            json?["password"]?.GetValue<string>(),
            json?["description"]?.GetValue<string>(),
            fields);
    }

    internal static PassboltResource ParseResource(JsonNode item, PgpKeyChain keys)
    {
        var id = item["id"]!.GetValue<string>();
        var folderId = item["folder_parent_id"]?.GetValue<string>();
        var typeId = item["resource_type_id"]?.GetValue<string>();
        DateTimeOffset? modified = DateTimeOffset.TryParse(item["modified"]?.GetValue<string>(), out var m) ? m : null;

        // Passbolt v5: name/username/uris live in an encrypted metadata object.
        var source = item;
        if (item["metadata"] is JsonValue metadataValue && metadataValue.TryGetValue<string>(out var armoredMetadata))
            source = JsonNode.Parse(PgpMessage.Decrypt(armoredMetadata, keys))!;

        var uris = new List<string>();
        if (source["uris"] is JsonArray uriArray)
            uris.AddRange(uriArray.Select(u => u?.GetValue<string>()).OfType<string>().Where(u => u.Length > 0));
        else if (source["uri"]?.GetValue<string>() is { Length: > 0 } uri)
            uris.Add(uri);

        var customFields = new List<CustomFieldDefinition>();
        if (source["custom_fields"] is JsonArray fieldArray)
        {
            foreach (var field in fieldArray)
            {
                if (field?["id"]?.GetValue<string>() is { } fieldId)
                    customFields.Add(new CustomFieldDefinition(fieldId,
                        field["metadata_key"]?.GetValue<string>() ?? "",
                        (field["metadata_value"] as JsonValue)?.ToString()));
            }
        }

        return new PassboltResource(
            id,
            source["name"]?.GetValue<string>() ?? "(unnamed)",
            source["username"]?.GetValue<string>(),
            uris,
            source["description"]?.GetValue<string>(),
            typeId ?? source["resource_type_id"]?.GetValue<string>(),
            folderId,
            modified,
            customFields);
    }

    private async Task LoadResourceTypesAsync(CancellationToken ct)
    {
        var body = await SendAsync(HttpMethod.Get, "resource-types.json", null, authenticated: true, ct);
        _resourceTypeSlugs.Clear();
        _resourceTypes.Clear();
        foreach (var type in body.AsArray())
        {
            if (type?["id"]?.GetValue<string>() is { } id && type["slug"]?.GetValue<string>() is { } slug)
            {
                _resourceTypeSlugs[id] = slug;
                _resourceTypes[id] = new ResourceType(id, slug);
            }
        }
    }

    private async Task LoadMetadataKeysAsync(CancellationToken ct)
    {
        var keys = RequireKeys();
        var body = await SendAsync(HttpMethod.Get, "metadata/keys.json?contain[metadata_private_keys]=1", null, authenticated: true, ct);
        foreach (var metadataKey in body.AsArray())
        {
            // The active shared key (not expired/deleted) is used to encrypt metadata of new resources.
            if (metadataKey?["armored_key"]?.GetValue<string>() is { } armoredPublic && metadataKey["id"]?.GetValue<string>() is { } keyId
                && metadataKey["expired"] is null && metadataKey["deleted"] is null)
            {
                try
                {
                    _sharedMetadataKey = (keyId, PgpPublicKeys.Parse(armoredPublic));
                    _metadataPublicKeys[keyId] = _sharedMetadataKey.Value.Key;
                }
                catch (PgpException ex)
                {
                    _logger.LogWarning(ex, "Unreadable metadata public key {Id}", keyId);
                }
            }
            if (metadataKey?["metadata_private_keys"] is not JsonArray privateKeys)
                continue;
            foreach (var privateKey in privateKeys)
            {
                if (privateKey?["data"]?.GetValue<string>() is not { } data)
                    continue;
                try
                {
                    var payload = JsonNode.Parse(PgpMessage.Decrypt(data, keys))!;
                    keys.AddDecryptionKey(payload["armored_key"]!.GetValue<string>(), payload["passphrase"]?.GetValue<string>() ?? "");
                }
                catch (Exception ex) when (ex is PgpException or JsonException or NullReferenceException)
                {
                    _logger.LogWarning(ex, "Could not unlock metadata key {Id}", metadataKey["id"]);
                }
            }
        }
        _metadataKeysLoaded = true;
    }

    private PgpKeyChain RequireKeys() =>
        _keys is not null && _accessToken is not null ? _keys : throw new InvalidOperationException("Not logged in.");

    private async Task<JsonNode> SendAsync(HttpMethod method, string path, JsonNode? payload, bool authenticated, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(method, AppendApiVersion(path));
            if (payload is not null)
                request.Content = JsonContent.Create(payload);
            if (authenticated && _accessToken is not null)
                request.Headers.Authorization = new("Bearer", _accessToken);

            using var response = await _http.SendAsync(request, ct);
            if (response.StatusCode == HttpStatusCode.Unauthorized && authenticated && attempt == 0 && await TryRefreshAsync(ct))
                continue;

            JsonNode? envelope = null;
            try
            {
                envelope = await response.Content.ReadFromJsonAsync<JsonNode>(ct);
            }
            catch (JsonException)
            {
                // fall through to status handling
            }

            if (!response.IsSuccessStatusCode)
            {
                var message = envelope?["header"]?["message"]?.GetValue<string>() ?? response.ReasonPhrase ?? "Request failed";
                throw new PassboltApiException($"{method} {path}: {message}", (int)response.StatusCode);
            }
            return envelope?["body"] ?? throw new PassboltApiException($"{method} {path}: empty response");
        }
    }

    private async Task<bool> TryRefreshAsync(CancellationToken ct)
    {
        if (_refreshToken is null)
            return false;
        await _refreshLock.WaitAsync(ct);
        try
        {
            var body = await SendAsync(HttpMethod.Post, "auth/jwt/refresh.json",
                new JsonObject { ["user_id"] = _account.UserId, ["refresh_token"] = _refreshToken }, authenticated: false, ct);
            _accessToken = body["access_token"]?.GetValue<string>() ?? _accessToken;
            _refreshToken = body["refresh_token"]?.GetValue<string>() ?? _refreshToken;
            return true;
        }
        catch (PassboltApiException ex)
        {
            _logger.LogWarning(ex, "Token refresh failed");
            _accessToken = null;
            return false;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private static string AppendApiVersion(string path) =>
        path + (path.Contains('?') ? "&" : "?") + "api-version=v2";

    private sealed record ResourceType(string Id, string Slug);

    public void Dispose()
    {
        _http.Dispose();
        _refreshLock.Dispose();
    }
}
