using BoltShell.Core.Passbolt;
using BoltShell.Core.Ssh;

namespace BoltShell.Core.Tests;

public class SshMappingTests
{
    private const string Key = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----";

    // ssh-keygen -l on this key prints SHA256:DvVf1SbWe/v9F14T5gki+t0oBv/d1rQxJJsyBtwuBC8
    private const string HostPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDvDH1ptg3N3Xu8YBPv83N5mSH0ihPSABzcMcyfkgEhY";

    [Theory]
    [InlineData("ssh://server.example.com", "server.example.com", 22, null)]
    [InlineData("ssh://server.example.com:2222", "server.example.com", 2222, null)]
    [InlineData("ssh://root@10.0.0.1", "10.0.0.1", 22, "root")]
    [InlineData("SSH://deploy@host:2200/", "host", 2200, "deploy")]
    [InlineData("ssh://user:secret@host", "host", 22, "user")]
    [InlineData("ssh://[2001:db8::1]:2022", "2001:db8::1", 2022, null)]
    [InlineData("  ssh://host  ", "host", 22, null)]
    public void SshTarget_Parses(string input, string host, int port, string? user)
    {
        Assert.True(SshTarget.TryParse(input, out var target));
        Assert.Equal(new SshTarget(host, port, user), target);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("server.example.com")]
    [InlineData("root@server")]
    [InlineData("server:22")]
    [InlineData("sftp://host")]
    [InlineData("https://gitlab.example.com")]
    [InlineData("ssh://host:99999")]
    [InlineData("ssh://host:abc")]
    [InlineData("ssh://[::1")]
    [InlineData("ssh://two words")]
    [InlineData("ssh://")]
    public void SshTarget_RejectsInvalid(string? input) => Assert.False(SshTarget.TryParse(input, out _));

    [Theory]
    [InlineData("deploy@10.0.10.21:2222", "10.0.10.21", 2222, "deploy")]
    [InlineData("backup.intern", "backup.intern", 22, null)]
    [InlineData("ssh://root@host", "host", 22, "root")]
    public void SshTarget_ParsesQuickConnect(string input, string host, int port, string? user)
    {
        Assert.True(SshTarget.TryParseQuick(input, out var target));
        Assert.Equal(new SshTarget(host, port, user), target);
    }

    [Theory]
    [InlineData("https://host")]
    [InlineData("odoo prod")]
    [InlineData("")]
    public void SshTarget_RejectsInvalidQuickConnect(string input) => Assert.False(SshTarget.TryParseQuick(input, out _));

    [Fact]
    public void Map_PasswordOnly()
    {
        var spec = SshConnectionMapper.Map(Resource("ssh://web01:2222", "admin"), Secret("pw"));
        Assert.Equal(new SshTarget("web01", 2222), spec.Target);
        Assert.Equal("admin", spec.Username);
        Assert.Equal(new SshCredentials("pw", null, null), spec.Credentials);
        Assert.False(spec.HasPinnedHostKeys);
    }

    [Fact]
    public void Map_UriUserWinsOverUsernameField()
    {
        Assert.Equal("root", SshConnectionMapper.Map(Resource("ssh://root@web01", "admin"), Secret("pw")).Username);
    }

    [Fact]
    public void Map_KeyField_PasswordIsPassphrase()
    {
        var spec = SshConnectionMapper.Map(Resource("ssh://web01", "admin", Field("f1", "ssh_private_key")),
            Secret("kp", fields: new() { ["f1"] = Key }));

        // The passphrase must not be offered to the server as a login password.
        Assert.Equal(new SshCredentials(null, Key + "\n", "kp"), spec.Credentials);
    }

    [Fact]
    public void Map_KeyAndPassphraseFields_PasswordIsLoginPassword()
    {
        var spec = SshConnectionMapper.Map(
            Resource("ssh://web01", "admin", Field("f1", "SSH_Private_Key"), Field("f2", "ssh_passphrase")),
            Secret("login-pw", fields: new() { ["f1"] = Key, ["f2"] = "kp" }));

        Assert.Equal(new SshCredentials("login-pw", Key + "\n", "kp"), spec.Credentials);
    }

    [Fact]
    public void Map_KeyWithoutPassphrase_EmptyPassword()
    {
        var spec = SshConnectionMapper.Map(Resource("ssh://web01", "admin", Field("f1", "ssh_private_key")),
            Secret("", fields: new() { ["f1"] = Key }));
        Assert.Equal(new SshCredentials(null, Key + "\n", null), spec.Credentials);
    }

    [Fact]
    public void Map_V4Fallback_KeyInNote()
    {
        var spec = SshConnectionMapper.Map(Resource("ssh://web01", "admin"), Secret("kp", note: "my key:\r\n" + Key.Replace("\n", "\r\n")));
        Assert.Equal(new SshCredentials(null, Key + "\n", "kp"), spec.Credentials);
    }

    [Fact]
    public void Map_KeyPastedIntoPassword_IsNeverSentAsPassword()
    {
        var spec = SshConnectionMapper.Map(Resource("ssh://web01", "admin"), Secret(Key));
        Assert.Equal(new SshCredentials(null, Key + "\n", null), spec.Credentials);
    }

    [Fact]
    public void Map_PublicKeyAndHostIdentity()
    {
        var spec = SshConnectionMapper.Map(
            Resource("ssh://web01", "admin", Field("f1", "ssh_public_key"), Field("f2", "ssh_host_key")),
            Secret("pw", fields: new() { ["f1"] = " ssh-ed25519 AAAAPUB user@laptop \n", ["f2"] = "web01 " + HostPublicKey }));

        Assert.Equal("ssh-ed25519 AAAAPUB user@laptop", spec.PublicKey);
        Assert.True(spec.HasPinnedHostKeys);
        Assert.Equal(new ExpectedHostKey("ssh-ed25519", "DvVf1SbWe/v9F14T5gki+t0oBv/d1rQxJJsyBtwuBC8"), Assert.Single(spec.HostKeys!));
    }

    [Fact]
    public void Map_CustomFieldValueFromMetadata_WhenSecretHasNone()
    {
        var resource = Resource("ssh://web01", "admin") with { CustomFields = [new("f2", "ssh_host_key", "SHA256:abc")] };
        var spec = SshConnectionMapper.Map(resource, Secret("pw"));
        Assert.Equal("abc", Assert.Single(spec.HostKeys!).FingerprintSha256);
    }

    [Fact]
    public void ParseHostKeys_AcceptsAllFormats()
    {
        var keys = SshConnectionMapper.ParseHostKeys($"""
            # comment
            SHA256:DvVf1SbWe/v9F14T5gki+t0oBv/d1rQxJJsyBtwuBC8
            256 SHA256:abcdef= root@host (ED25519)
            {HostPublicKey} root@host
            [web01]:2222,10.0.0.5 {HostPublicKey}
            """);

        Assert.Equal(
            [
                new ExpectedHostKey(null, "DvVf1SbWe/v9F14T5gki+t0oBv/d1rQxJJsyBtwuBC8"),
                new ExpectedHostKey(null, "abcdef"),
                new ExpectedHostKey("ssh-ed25519", "DvVf1SbWe/v9F14T5gki+t0oBv/d1rQxJJsyBtwuBC8"),
                new ExpectedHostKey("ssh-ed25519", "DvVf1SbWe/v9F14T5gki+t0oBv/d1rQxJJsyBtwuBC8"),
            ],
            keys);
    }

    [Theory]
    [InlineData("not a key")]
    [InlineData("ssh-ed25519 !!notbase64!!")]
    public void ParseHostKeys_RejectsGarbage(string text) =>
        Assert.Throws<FormatException>(() => SshConnectionMapper.ParseHostKeys(text));

    [Fact]
    public void Map_WithoutUsername_Throws() =>
        Assert.Throws<InvalidOperationException>(() => SshConnectionMapper.Map(Resource("ssh://web01", null), Secret("pw")));

    [Fact]
    public void Map_WithoutSshUri_Throws() =>
        Assert.Throws<InvalidOperationException>(() => SshConnectionMapper.Map(Resource("web01", "u"), Secret("pw")));

    private static CustomFieldDefinition Field(string id, string key) => new(id, key, null);

    private static PassboltResource Resource(string uri, string? username, params CustomFieldDefinition[] fields) =>
        new("id", "Server", username, uri.Length > 0 ? [uri] : [], null, null, null, null, fields);

    private static PassboltSecret Secret(string password, string? note = null, Dictionary<string, string>? fields = null) =>
        new(password, note, fields ?? new Dictionary<string, string>());
}
