using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using BoltShell.Core.Crypto;
using BoltShell.Core.Passbolt;

namespace BoltShell.Core.Tests;

public class PassboltClientTests
{
    private const string Domain = "https://passbolt.test";
    private const string UserId = "11111111-1111-1111-1111-111111111111";

    [Fact]
    public async Task Login_ListResources_AndDecryptSecrets_V4AndV5()
    {
        var server = new FakePassboltServer();
        using var client = new PassboltClient(Account(), server);

        var login = await client.LoginAsync(TestKeys.UserPassphrase);
        Assert.False(login.MfaRequired);
        Assert.True(client.IsAuthenticated);

        var resources = await client.GetResourcesAsync();
        Assert.Equal(["legacy", "modern"], resources.Select(r => r.Name).Order());

        var legacy = resources.Single(r => r.Name == "legacy");
        Assert.Equal(["ssh://root@legacy.example.com"], legacy.Uris);
        Assert.Equal("legacy-pw", (await client.GetSecretAsync(legacy)).Password);

        var modern = resources.Single(r => r.Name == "modern");
        Assert.Equal("deploy", modern.Username);
        Assert.Equal("passphrase", modern.CustomFields.Single().Key);
        var secret = await client.GetSecretAsync(modern);
        Assert.Equal("modern-pw", secret.Password);
        Assert.Equal("kp", secret.CustomFieldValues["cf1"]);

        Assert.Equal(1, server.RefreshCalls);
    }

    [Fact]
    public async Task CreateResource_V5_WithSharedMetadataKey_AndFolderSharing()
    {
        var server = new FakePassboltServer();
        using var client = new PassboltClient(Account(), server);
        await client.LoginAsync(TestKeys.UserPassphrase);

        var (id, warning) = await client.CreateResourceAsync(new NewResource(
            "web-01", "root", ["ssh://root@web-01:22"], "", FakePassboltServer.ShareFolderId,
            [new("ssh_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----", "password"), new("ssh_host_key", "SHA256:abc")]));

        Assert.Null(warning);
        var created = Assert.Single(server.Created);
        Assert.Equal(id, created["id"]!.GetValue<string>());
        Assert.Equal("shared_key", created["metadata_key_type"]!.GetValue<string>());
        Assert.Equal(FakePassboltServer.ShareFolderId, created["folder_parent_id"]!.GetValue<string>());
        Assert.Null(created["name"]); // v5: name only inside the encrypted metadata

        // Metadata is readable with the organisation's metadata key, and lists the custom fields (keys only).
        var metadataKeys = PgpKeyChain.Unlock(TestKeys.Metadata.Private, "");
        var metadata = JsonNode.Parse(PgpMessage.Decrypt(created["metadata"]!.GetValue<string>(), metadataKeys))!;
        Assert.Equal("web-01", metadata["name"]!.GetValue<string>());
        Assert.Equal(["ssh_private_key", "ssh_host_key"], metadata["custom_fields"]!.AsArray().Select(f => f!["metadata_key"]!.GetValue<string>()));
        Assert.DoesNotContain("PRIVATE KEY", metadata.ToJsonString());

        // The folder's other user got an encrypted copy of the secret.
        var share = server.LastShare!;
        Assert.Equal(FakePassboltServer.BobId, share["permissions"]![0]!["aro_foreign_key"]!.GetValue<string>());
        var bobsSecret = share["secrets"]!.AsArray().Single()!;
        var bobKeys = PgpKeyChain.Unlock(TestKeys.Server.Private, "");
        Assert.Contains("PRIVATE KEY", PgpMessage.Decrypt(bobsSecret["data"]!.GetValue<string>(), bobKeys));

        // The new resource round-trips through listing and the SSH mapping.
        var resource = (await client.GetResourcesAsync()).Single(r => r.Id == id);
        var spec = Ssh.SshConnectionMapper.Map(resource, await client.GetSecretAsync(resource));
        Assert.Equal("root", spec.Username);
        Assert.True(spec.Credentials.HasPrivateKey);
        Assert.Equal("abc", Assert.Single(spec.HostKeys!).FingerprintSha256);
    }

    [Fact]
    public async Task Login_FailsWhenServerKeyDoesNotMatchPinnedFingerprint()
    {
        using var client = new PassboltClient(Account() with { ServerFingerprint = "DEADBEEF" }, new FakePassboltServer());
        var ex = await Assert.ThrowsAsync<PassboltApiException>(() => client.LoginAsync(TestKeys.UserPassphrase));
        Assert.Contains("does not match", ex.Message);
    }

    [Fact]
    public async Task Login_RejectsTamperedVerifyToken()
    {
        using var client = new PassboltClient(Account(), new FakePassboltServer { TamperVerifyToken = true });
        await Assert.ThrowsAsync<PassboltApiException>(() => client.LoginAsync(TestKeys.UserPassphrase));
    }

    [Fact]
    public void ParseSecret_HandlesPlainAndJsonTypes()
    {
        Assert.Equal("{not json", PassboltClient.ParseSecret("{not json", null).Password);
        Assert.Equal("{\"password\":\"x\"}", PassboltClient.ParseSecret("{\"password\":\"x\"}", "password-string").Password);
        var parsed = PassboltClient.ParseSecret("{\"password\":\"x\",\"description\":\"d\"}", "password-and-description");
        Assert.Equal(("x", "d"), (parsed.Password, parsed.Description));
    }

    [Fact]
    public void AccountKit_ParsesBase64Json()
    {
        var json = new JsonObject
        {
            ["domain"] = Domain,
            ["user_id"] = UserId,
            ["username"] = "ada@example.com",
            ["user_private_armored_key"] = TestKeys.User.Private,
            ["server_public_armored_key"] = TestKeys.Server.Public,
        }.ToJsonString();

        var account = AccountKit.Parse(Convert.ToBase64String(Encoding.UTF8.GetBytes(json)));

        Assert.Equal(Domain, account.ServerUrl);
        Assert.Equal(UserId, account.UserId);
        Assert.Equal(PgpPublicKeys.Parse(TestKeys.Server.Public).Fingerprint, account.ServerFingerprint);
    }

    internal static PassboltAccount Account() => new(Domain + "/", UserId, TestKeys.User.Private);

    /// <summary>Implements just enough of the Passbolt API to exercise the client, including real PGP crypto.</summary>
    [Fact]
    public async Task SetCustomField_AddsHostKey_ToMetadataAndEverySecret()
    {
        var server = new FakePassboltServer();
        using var client = new PassboltClient(Account(), server);
        await client.LoginAsync(TestKeys.UserPassphrase);
        var (id, _) = await client.CreateResourceAsync(new NewResource("web-01", "root", ["ssh://root@web-01:22"], "pw", null, []));

        const string hostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        await client.SetCustomFieldAsync(id, "ssh_host_key", hostKey);

        var update = Assert.Single(server.Updates);
        Assert.Equal("shared_key", update["metadata_key_type"]!.GetValue<string>());
        Assert.Equal(2, update["secrets"]!.AsArray().Count); // the user and bob, each with an own copy
        var bobsSecret = update["secrets"]!.AsArray().Single(x => x!["user_id"]!.GetValue<string>() == FakePassboltServer.BobId)!;
        Assert.Contains(hostKey, PgpMessage.Decrypt(bobsSecret["data"]!.GetValue<string>(), PgpKeyChain.Unlock(TestKeys.Server.Private, "")));

        var resource = (await client.GetResourcesAsync()).Single(r => r.Id == id);
        var spec = Ssh.SshConnectionMapper.Map(resource, await client.GetSecretAsync(resource));
        Assert.True(spec.HasPinnedHostKeys);
        Assert.Equal("pw", spec.Credentials.Password); // the rest of the secret is unchanged
    }

    [Fact]
    public async Task SetCustomField_ReplacesExistingValue()
    {
        var server = new FakePassboltServer();
        using var client = new PassboltClient(Account(), server);
        await client.LoginAsync(TestKeys.UserPassphrase);
        var (id, _) = await client.CreateResourceAsync(new NewResource("win-01", "admin", ["rdp://win-01"], "pw", null, [new("rdp_cert_sha256", "old")]));

        await client.SetCustomFieldAsync(id, "RDP_CERT_SHA256", "new");

        var resource = (await client.GetResourcesAsync()).Single(r => r.Id == id);
        Assert.Single(resource.CustomFields); // replaced, not added twice
        var spec = Rdp.RdpConnectionMapper.Map(resource, await client.GetSecretAsync(resource));
        Assert.Equal(["new"], spec.CertificateFingerprints);
    }

    [Fact]
    public async Task UpdateCustomField_SeesTheCurrentValue_SoOtherHostsEntriesStay()
    {
        var server = new FakePassboltServer();
        using var client = new PassboltClient(Account(), server);
        await client.LoginAsync(TestKeys.UserPassphrase);
        var (id, _) = await client.CreateResourceAsync(new NewResource("cluster", "root", ["ssh://a.example.com", "ssh://b.example.com"], "pw", null,
            [new("ssh_host_key", "a.example.com SHA256:aaa")]));

        string? seen = null;
        await client.UpdateCustomFieldAsync(id, "ssh_host_key", current => { seen = current; return current + "\nb.example.com SHA256:bbb"; });

        Assert.Equal("a.example.com SHA256:aaa", seen);
        var resource = (await client.GetResourcesAsync()).Single(r => r.Id == id);
        var secret = await client.GetSecretAsync(resource);
        Assert.Equal("bbb", Assert.Single(Ssh.SshConnectionMapper.Map(resource, secret, "ssh://b.example.com").HostKeys!).FingerprintSha256);
        Assert.Equal("aaa", Assert.Single(Ssh.SshConnectionMapper.Map(resource, secret, "ssh://a.example.com").HostKeys!).FingerprintSha256);
    }

    [Fact]
    public async Task SetCustomField_OnV4Resource_ExplainsWhy()
    {
        using var client = new PassboltClient(Account(), new FakePassboltServer());
        await client.LoginAsync(TestKeys.UserPassphrase);
        var ex = await Assert.ThrowsAsync<PassboltApiException>(() => client.SetCustomFieldAsync("r1", "ssh_host_key", "SHA256:x"));
        Assert.Contains("v4", ex.Message);
    }

    internal sealed class FakePassboltServer : HttpMessageHandler
    {
        private const string PasswordStringType = "a28a04cd-6f53-518a-967c-9963bf9cec51";
        private const string V5DefaultType = "b28a04cd-6f53-518a-967c-9963bf9cec52";
        private const string MetadataKeyId = "c28a04cd-6f53-518a-967c-9963bf9cec53";

        private readonly PgpKeyChain _serverKeys = PgpKeyChain.Unlock(TestKeys.Server.Private, "");
        private readonly PgpPublicKeys _userPublic = PgpPublicKeys.Parse(TestKeys.User.Public);
        private readonly PgpPublicKeys _metadataPublic = PgpPublicKeys.Parse(TestKeys.Metadata.Public);
        private string _accessToken = "access-1";
        private bool _expiredOnce;

        public bool TamperVerifyToken { get; init; }
        public int RefreshCalls { get; private set; }

        // Resource creation and sharing ("bob" uses the server test key so tests can decrypt his copy).
        public const string BobId = "22222222-2222-2222-2222-222222222222";
        public const string ShareFolderId = "f9";
        public List<JsonObject> Created { get; } = [];
        public JsonNode? LastShare { get; private set; }
        public List<JsonObject> Updates { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Assert.Contains("api-version=v2", request.RequestUri!.Query);
            var path = request.RequestUri.AbsolutePath;
            var payload = request.Content is null ? null : JsonNode.Parse(await request.Content.ReadAsStringAsync(ct));

            switch (path)
            {
                case "/auth/verify.json":
                    return Ok(new JsonObject { ["fingerprint"] = _serverKeys.Fingerprint, ["keydata"] = TestKeys.Server.Public });
                case "/auth/jwt/login.json":
                    return Login(payload!);
                case "/auth/jwt/refresh.json":
                    RefreshCalls++;
                    Assert.Equal("refresh-1", payload!["refresh_token"]!.GetValue<string>());
                    _accessToken = "access-2";
                    return Ok(new JsonObject { ["access_token"] = _accessToken, ["refresh_token"] = "refresh-2" });
            }

            if (request.Headers.Authorization?.Parameter != _accessToken)
                return Error(HttpStatusCode.Unauthorized);

            // Simulate the access token expiring once, to exercise the refresh flow.
            if (path == "/resources.json" && !_expiredOnce)
            {
                _expiredOnce = true;
                _accessToken = "expired";
                return Error(HttpStatusCode.Unauthorized);
            }

            if (request.Method == HttpMethod.Post && path == "/resources.json")
            {
                var created = payload!.AsObject();
                created["id"] = $"new-{Created.Count + 1}";
                Created.Add(created);
                return Ok(new JsonObject { ["id"] = created["id"]!.GetValue<string>() });
            }
            if (request.Method == HttpMethod.Get && path.StartsWith("/resources/", StringComparison.Ordinal))
            {
                var id = path["/resources/".Length..^".json".Length];
                if (id == "r1")
                    return Ok(new JsonObject { ["id"] = "r1", ["name"] = "legacy", ["resource_type_id"] = PasswordStringType });
                var resource = Created.Single(c => c["id"]!.GetValue<string>() == id).DeepClone().AsObject();
                resource.Remove("secrets");
                return Ok(resource);
            }
            if (request.Method == HttpMethod.Put && path.StartsWith("/resources/", StringComparison.Ordinal))
            {
                var id = path["/resources/".Length..^".json".Length];
                Updates.Add(payload!.AsObject());
                var stored = Created.Single(c => c["id"]!.GetValue<string>() == id);
                stored["metadata"] = payload!["metadata"]!.DeepClone();
                stored["secrets"] = new JsonArray(payload["secrets"]!.AsArray().Single(x => x!["user_id"]!.GetValue<string>() == UserId)!.DeepClone());
                return Ok(stored.DeepClone());
            }
            if (path == "/users.json")
            {
                Assert.Contains("filter[has-access]=", Uri.UnescapeDataString(request.RequestUri.Query));
                return Ok(new JsonArray(
                    new JsonObject { ["id"] = UserId, ["gpgkey"] = new JsonObject { ["armored_key"] = TestKeys.User.Public } },
                    new JsonObject { ["id"] = BobId, ["gpgkey"] = new JsonObject { ["armored_key"] = TestKeys.Server.Public } }));
            }
            if (path == $"/folders/{ShareFolderId}.json")
            {
                Assert.Contains("contain[permissions]=1", Uri.UnescapeDataString(request.RequestUri.Query));
                return Ok(new JsonObject
                {
                    ["id"] = ShareFolderId,
                    ["permissions"] = new JsonArray(
                        new JsonObject { ["aro"] = "User", ["aro_foreign_key"] = UserId, ["type"] = 15 },
                        new JsonObject { ["aro"] = "User", ["aro_foreign_key"] = BobId, ["type"] = 7 }),
                });
            }
            if (path.StartsWith("/share/simulate/resource/", StringComparison.Ordinal))
            {
                Assert.Single(payload!["permissions"]!.AsArray()); // the creator's own permission is not sent
                return Ok(new JsonObject { ["changes"] = new JsonObject { ["added"] = new JsonArray(new JsonObject { ["User"] = new JsonObject { ["id"] = BobId } }) } });
            }
            if (path == $"/users/{BobId}.json")
                return Ok(new JsonObject { ["id"] = BobId, ["gpgkey"] = new JsonObject { ["armored_key"] = TestKeys.Server.Public } });
            if (request.Method == HttpMethod.Put && path.StartsWith("/share/resource/", StringComparison.Ordinal))
            {
                LastShare = payload;
                return Ok(new JsonObject());
            }
            if (path.StartsWith("/secrets/resource/new-", StringComparison.Ordinal))
            {
                var id = path["/secrets/resource/".Length..^".json".Length];
                return Ok(new JsonObject { ["data"] = Created.Single(c => c["id"]!.GetValue<string>() == id)["secrets"]![0]!["data"]!.GetValue<string>() });
            }

            return path switch
            {
                "/resource-types.json" => Ok(new JsonArray(
                    new JsonObject { ["id"] = PasswordStringType, ["slug"] = "password-string" },
                    new JsonObject { ["id"] = V5DefaultType, ["slug"] = "v5-default" })),
                "/folders.json" => Ok(new JsonArray()),
                "/resources.json" => Ok(new JsonArray([.. Created.Select(c => c.DeepClone()),
                    new JsonObject
                    {
                        ["id"] = "r1", ["name"] = "legacy", ["username"] = "root", ["uri"] = "ssh://root@legacy.example.com",
                        ["resource_type_id"] = PasswordStringType, ["modified"] = "2026-01-01T00:00:00+00:00",
                    },
                    new JsonObject
                    {
                        ["id"] = "r2", ["resource_type_id"] = V5DefaultType, ["metadata_key_id"] = MetadataKeyId,
                        ["metadata_key_type"] = "shared_key",
                        ["metadata"] = EncryptFor(_metadataPublic, new JsonObject
                        {
                            ["object_type"] = "PASSBOLT_RESOURCE_METADATA", ["resource_type_id"] = V5DefaultType,
                            ["name"] = "modern", ["username"] = "deploy", ["uris"] = new JsonArray("modern.example.com:2222"),
                            ["custom_fields"] = new JsonArray(new JsonObject { ["id"] = "cf1", ["type"] = "password", ["metadata_key"] = "passphrase" }),
                        }.ToJsonString()),
                    }])),
                "/metadata/keys.json" => Ok(new JsonArray(new JsonObject
                {
                    ["id"] = MetadataKeyId,
                    ["armored_key"] = TestKeys.Metadata.Public,
                    ["expired"] = null,
                    ["deleted"] = null,
                    ["metadata_private_keys"] = new JsonArray(new JsonObject
                    {
                        ["data"] = EncryptFor(_userPublic, new JsonObject
                        {
                            ["object_type"] = "PASSBOLT_METADATA_PRIVATE_KEY", ["armored_key"] = TestKeys.Metadata.Private, ["passphrase"] = "",
                        }.ToJsonString()),
                    }),
                })),
                "/secrets/resource/r1.json" => Ok(new JsonObject { ["data"] = EncryptFor(_userPublic, "legacy-pw") }),
                "/secrets/resource/r2.json" => Ok(new JsonObject
                {
                    ["data"] = EncryptFor(_userPublic, new JsonObject
                    {
                        ["object_type"] = "PASSBOLT_SECRET_DATA", ["password"] = "modern-pw",
                        ["custom_fields"] = new JsonArray(new JsonObject { ["id"] = "cf1", ["type"] = "password", ["secret_value"] = "kp" }),
                    }.ToJsonString()),
                }),
                _ => Error(HttpStatusCode.NotFound),
            };
        }

        private HttpResponseMessage Login(JsonNode payload)
        {
            Assert.Equal(UserId, payload["user_id"]!.GetValue<string>());
            var challenge = JsonNode.Parse(PgpMessage.Decrypt(payload["challenge"]!.GetValue<string>(), _serverKeys, verifyWith: _userPublic))!;
            Assert.Equal("1.0.0", challenge["version"]!.GetValue<string>());
            Assert.Equal(Domain, challenge["domain"]!.GetValue<string>());
            Assert.True(challenge["verify_token_expiry"]!.GetValue<long>() > DateTimeOffset.UtcNow.ToUnixTimeSeconds());

            var response = new JsonObject
            {
                ["version"] = "1.0.0",
                ["domain"] = Domain,
                ["verify_token"] = TamperVerifyToken ? Guid.NewGuid().ToString() : challenge["verify_token"]!.GetValue<string>(),
                ["access_token"] = _accessToken,
                ["refresh_token"] = "refresh-1",
            };
            return Ok(new JsonObject { ["challenge"] = EncryptFor(_userPublic, response.ToJsonString()) });
        }

        private string EncryptFor(PgpPublicKeys recipient, string plaintext) => PgpMessage.EncryptAndSign(plaintext, recipient, _serverKeys);

        private static HttpResponseMessage Ok(JsonNode body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(new JsonObject { ["header"] = new JsonObject { ["status"] = "success" }, ["body"] = body }.ToJsonString(),
                Encoding.UTF8, "application/json"),
        };

        private static HttpResponseMessage Error(HttpStatusCode code) => new(code)
        {
            Content = new StringContent(new JsonObject { ["header"] = new JsonObject { ["status"] = "error", ["message"] = code.ToString() }, ["body"] = null }.ToJsonString(),
                Encoding.UTF8, "application/json"),
        };
    }
}

/// <summary>Audit finding SEC-03: Passbolt only over HTTPS (loopback excepted), on every path.</summary>
public class ServerUrlTests
{
    [Theory]
    [InlineData("http://passbolt.example")]
    [InlineData("http://10.0.0.5")]
    [InlineData("http://localhost.evil.example")]
    [InlineData("ftp://passbolt.example")]
    [InlineData("passbolt.example")]
    [InlineData("")]
    public void InsecureOrInvalid_IsRejected(string url)
    {
        Assert.Throws<ArgumentException>(() => Passbolt.PassboltAccount.ValidateServerUrl(url));
        Assert.ThrowsAny<Exception>(() => new Passbolt.PassboltClient(new Passbolt.PassboltAccount(url, "u", "k")));
    }

    [Theory]
    [InlineData("https://passbolt.example")]
    [InlineData("http://localhost:8080")]
    [InlineData("http://127.0.0.1:5077/pb")]
    [InlineData("http://[::1]:8080")]
    public void HttpsOrLoopback_IsAccepted(string url)
    {
        Passbolt.PassboltAccount.ValidateServerUrl(url);
        using var client = new Passbolt.PassboltClient(new Passbolt.PassboltAccount(url, "u", "k"));
    }

    [Fact]
    public void AccountKit_WithRemoteHttp_IsRejected()
    {
        var json = new System.Text.Json.Nodes.JsonObject
        {
            ["domain"] = "http://passbolt.example",
            ["user_id"] = "11111111-1111-1111-1111-111111111111",
            ["user_private_armored_key"] = TestKeys.User.Private,
        }.ToJsonString();
        var ex = Assert.Throws<FormatException>(() => Passbolt.AccountKit.Parse(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json))));
        Assert.Contains("HTTPS", ex.Message);
    }
}
