using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using BoltShell.Core.Provisioning;
using BoltShell.Core.Ssh;

namespace BoltShell.Core.Tests;

public sealed class ProvisioningTests : IClassFixture<LocalSshServer>, IDisposable
{
    private readonly LocalSshServer _server;
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), "pbssh-prov-" + Guid.NewGuid().ToString("N")[..8]);
    private readonly SshConnector _connector;

    public ProvisioningTests(LocalSshServer server)
    {
        _server = server;
        Directory.CreateDirectory(_workDir);
        _connector = new SshConnector(new KnownHostsStore(Path.Combine(_workDir, "kh.json")), NullLogger<SshConnector>.Instance)
        {
            HostKeyPrompt = _ => Task.FromResult(true),
        };
    }

    [Fact]
    public void GeneratedKey_IsValidOpenSsh_AndMatchesSshKeygen()
    {
        var key = SshKeyGenerator.GenerateEd25519("test@example");

        Assert.False(SshConnectionMapper.IsEncrypted(key.PrivateKey)); // SSH.NET can load it
        Assert.StartsWith("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", key.PublicKey);
        Assert.EndsWith(" test@example", key.PublicKey);

        if (OperatingSystem.IsWindows() || !File.Exists("/usr/bin/ssh-keygen"))
            return;
        var file = Path.Combine(_workDir, "id_test");
        File.WriteAllText(file, key.PrivateKey);
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Assert.Equal(key.PublicKey, Run("ssh-keygen", $"-y -f {file}").Trim());
        Assert.Contains("SHA256:" + key.FingerprintSha256, Run("ssh-keygen", $"-l -f {file}"));
    }

    [Fact]
    public void HostKeyLine_UsesKeyTypeFromBlob()
    {
        var key = SshKeyGenerator.GenerateEd25519("");
        var blob = Convert.FromBase64String(key.PublicKey.Split(' ')[1]);
        Assert.Equal(key.PublicKey, SshKeyGenerator.HostKeyLine(blob));
    }

    [Fact]
    public void Mapper_UnencryptedKey_PasswordIsLoginPassword()
    {
        var key = SshKeyGenerator.GenerateEd25519("x");
        var resource = new Passbolt.PassboltResource("id", "web", "root", ["ssh://root@web"], null, null, null, null,
            [new("f1", SshConnectionMapper.PrivateKeyField, null)]);
        var spec = SshConnectionMapper.Map(resource, new Passbolt.PassboltSecret("login-pw", null, new Dictionary<string, string> { ["f1"] = key.PrivateKey }));
        Assert.Equal(new SshCredentials("login-pw", key.PrivateKey, null), spec.Credentials);
    }

    [Fact]
    public async Task Provision_InstallsKey_Saves_AndDisablesPasswordLogin()
    {
        if (!_server.Available) return;
        var conf = Path.Combine(_server.Directory, "sshd_config.d", HostProvisioner.ConfigFileName);
        File.Delete(conf);
        ProvisionedHost? saved = null;
        var provisioner = CreateProvisioner(disablePassword: true);

        var (spec, warning) = await provisioner.RunAsync((host, _) =>
        {
            saved = host;
            return Task.FromResult<string?>(null);
        });

        Assert.Null(warning);
        Assert.All(provisioner.Steps.Where(s => s.Kind != ProvisionStepKind.AllowRootKeyLogin),
            s => Assert.True(s.Status == StepStatus.Done, $"{s.Kind}: {s.Status} – {s.Detail}"));
        Assert.Equal(StepStatus.Skipped, provisioner.Steps.Single(s => s.Kind == ProvisionStepKind.AllowRootKeyLogin).Status);

        // The key is installed, the host key captured, the Passbolt payload follows the convention.
        Assert.NotNull(saved);
        Assert.Contains(saved.Key.PublicKey, File.ReadAllLines(Path.Combine(_server.Directory, "authorized_keys2")));
        Assert.Equal(_server.HostPublicKey.Split(' ')[1], saved.HostKeyLine.Split(' ')[1]);
        var resource = saved.ToResource("folder-1");
        Assert.Equal([$"ssh://{_server.User}@127.0.0.1:{_server.Port}"], resource.Uris);
        Assert.Equal("pw123", resource.Password);
        Assert.Equal(["ssh_private_key", "ssh_public_key", "ssh_host_key"], resource.CustomFields.Select(f => f.Key));

        // sshd drop-in written, validated and effective.
        Assert.Contains("PasswordAuthentication no", File.ReadAllText(conf));
        Assert.Contains("passwordauthentication no", Run("/usr/sbin/sshd", $"-T -C user=x,host=localhost,addr=127.0.0.1 -f {_server.Directory}/sshd_config"));

        // The returned spec connects with the new key and the pinned host key, no prompt needed.
        Assert.True(spec.HasPinnedHostKeys);
        await using var manager = new SessionManager(new SshConnector(new KnownHostsStore(Path.Combine(_workDir, "kh2.json")), NullLogger<SshConnector>.Instance));
        await manager.CreateTerminal(spec).ConnectAsync(80, 24);

        // Idempotent: the key line is not duplicated by a second install.
        Assert.Single(File.ReadAllLines(Path.Combine(_server.Directory, "authorized_keys2")), l => l == saved.Key.PublicKey);
    }

    [Fact]
    public async Task Provision_RollsBackKey_WhenSavingFails()
    {
        if (!_server.Available) return;
        var provisioner = CreateProvisioner(disablePassword: false);
        string? installed = null;

        await Assert.ThrowsAsync<InvalidOperationException>(() => provisioner.RunAsync((host, _) =>
        {
            installed = host.Key.PublicKey;
            Assert.Contains(installed, File.ReadAllText(Path.Combine(_server.Directory, "authorized_keys2")));
            throw new InvalidOperationException("Passbolt down");
        }));

        Assert.NotNull(installed);
        Assert.DoesNotContain(installed, File.ReadAllText(Path.Combine(_server.Directory, "authorized_keys2")));
        Assert.Equal(StepStatus.Failed, provisioner.Steps.Single(s => s.Kind == ProvisionStepKind.SaveToPassbolt).Status);
    }

    [Fact]
    public async Task Provision_FailsEarly_WhenSudoPasswordIsWrong()
    {
        if (!_server.Available) return;
        var provisioner = CreateProvisioner(disablePassword: true, password: "wrong");

        var ex = await Assert.ThrowsAsync<ProvisioningException>(() => provisioner.RunAsync((_, _) => Task.FromResult<string?>(null)));

        Assert.Contains("sudo", ex.Message);
        Assert.Equal(StepStatus.Failed, provisioner.Steps.Single(s => s.Kind == ProvisionStepKind.CheckPrivileges).Status);
        Assert.Equal(StepStatus.Pending, provisioner.Steps.Single(s => s.Kind == ProvisionStepKind.InstallKey).Status);
    }

    [Fact]
    public void ScriptQuoting_SurvivesSingleQuotes()
    {
        Assert.Equal("'it'\\''s'", HostProvisioner.Quote("it's"));
        Assert.Equal("'a b'", HostProvisioner.Quote("a b"));
    }

    [Fact]
    public void EffectiveConfig_IsParsed()
    {
        var parsed = HostProvisioner.ParseEffectiveConfig("port 22\npermitrootlogin without-password\nPasswordAuthentication No\n");
        Assert.Equal("without-password", parsed["permitrootlogin"]);
        Assert.Equal("no", parsed["passwordauthentication"]);
    }

    // Logs in with the fixture's key (the test sshd has no password auth); "pw123" is used for the fake sudo.
    private HostProvisioner CreateProvisioner(bool disablePassword, string password = "pw123") =>
        new(_connector, NullLogger<HostProvisioner>.Instance,
            new ProvisionRequest("local", new SshTarget("127.0.0.1", _server.Port), _server.User,
                new SshCredentials(password, _server.ClientKey, null), KeyForRoot: false, DisablePasswordLogin: disablePassword))
        {
            SudoCommand = Path.Combine(_server.Directory, "fake-sudo"),
            SshdConfigPath = Path.Combine(_server.Directory, "sshd_config"),
            SshdConfigDir = Path.Combine(_server.Directory, "sshd_config.d"),
            SshdCommand = _server.SshdCommand,
            ReloadCommand = _server.ReloadCommand,
            AuthorizedKeysPathOverride = Path.Combine(_server.Directory, "authorized_keys2"),
        };

    private static string Run(string file, string args)
    {
        using var p = Process.Start(new ProcessStartInfo(file, args) { RedirectStandardOutput = true, RedirectStandardError = true })!;
        var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        return output;
    }

    public void Dispose() => Directory.Delete(_workDir, recursive: true);
}
