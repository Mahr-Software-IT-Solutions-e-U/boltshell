using Microsoft.Extensions.Logging.Abstractions;
using BoltShell.App.Services;
using BoltShell.Core.Rdp;
using BoltShell.Core.Ssh;

namespace BoltShell.App.Tests;

/// <summary>Audit finding SEC-04: locking an account must stop new connections from already open tabs.</summary>
public sealed class AccountLockTests : IAsyncDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "boltshell-lock-" + Guid.NewGuid().ToString("N")[..8]);
    private readonly SessionManager _sessions;
    private readonly RdpProxy _proxy;
    private readonly WorkspaceState _state = new();

    public AccountLockTests()
    {
        Directory.CreateDirectory(_dir);
        var connector = new SshConnector(new KnownHostsStore(Path.Combine(_dir, "kh.json")), NullLogger<SshConnector>.Instance);
        _sessions = new SessionManager(connector);
        _proxy = new RdpProxy(new KnownHostsStore(Path.Combine(_dir, "kh2.json")), NullLogger<RdpProxy>.Instance);
    }

    [Fact]
    public async Task LockingAccount_DropsSshCredentials_AndBlocksNewConnections()
    {
        var spec = new SshConnectionSpec("web", new SshTarget("127.0.0.1", 1), "root", new SshCredentials("secret", null, null));
        var tab = _state.Open(_sessions, spec, "acc-1", "res-1");
        var manual = _state.Open(_sessions, spec with { DisplayName = "manual" }, null, null);

        _state.ClearCredentials("acc-1", _proxy);

        Assert.True(tab.CredentialsCleared);
        Assert.False(tab.Spec!.Credentials.HasPassword);
        Assert.False(tab.Terminal!.Spec.Credentials.HasPassword);
        // A reconnect with the cleared tab cannot authenticate anymore.
        await Assert.ThrowsAsync<InvalidOperationException>(() => tab.Terminal.ConnectAsync(80, 24));
        // Quick connections without a Passbolt account are not affected.
        Assert.False(manual.CredentialsCleared);
        Assert.True(manual.Spec!.Credentials.HasPassword);

        _state.RestoreCredentials(tab, spec, null, _proxy);
        Assert.False(tab.CredentialsCleared);
        Assert.Equal("secret", tab.Terminal.Spec.Credentials.Password);
    }

    [Fact]
    public void LockingAccount_DropsRdpPassword_AlsoInTheProxy()
    {
        var spec = new RdpConnectionSpec("win", new RdpTarget("10.0.0.5"), "admin", null, "secret", []);
        var tab = _state.OpenRdp(_proxy, spec, "acc-1", "res-1");

        _state.ClearCredentials("acc-1", _proxy);

        Assert.Null(tab.Rdp!.Spec.Password);
        Assert.True(tab.CredentialsCleared);
        Assert.Equal(tab.Rdp.Id, _proxy.Update(tab.Rdp, tab.Rdp.Spec).Id);
    }

    public async ValueTask DisposeAsync()
    {
        await _sessions.DisposeAsync();
        await _proxy.DisposeAsync();
        Directory.Delete(_dir, recursive: true);
    }
}
