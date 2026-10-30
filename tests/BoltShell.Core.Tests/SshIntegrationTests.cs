using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using BoltShell.Core.Ssh;
using BoltShell.Core.Transfer;

namespace BoltShell.Core.Tests;

/// <summary>End-to-end tests against a real local sshd. They return early (pass) if sshd is unavailable.</summary>
public sealed class SshIntegrationTests : IClassFixture<LocalSshServer>, IDisposable
{
    private readonly LocalSshServer _server;
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), "pbssh-work-" + Guid.NewGuid().ToString("N")[..8]);
    private readonly KnownHostsStore _knownHosts;
    private readonly SshConnector _connector;
    private readonly ConcurrentQueue<HostKeyInfo> _prompts = new();

    public SshIntegrationTests(LocalSshServer server)
    {
        _server = server;
        Directory.CreateDirectory(_workDir);
        _knownHosts = new KnownHostsStore(Path.Combine(_workDir, "known_hosts.json"));
        _connector = new SshConnector(_knownHosts, NullLogger<SshConnector>.Instance)
        {
            HostKeyPrompt = key =>
            {
                _prompts.Enqueue(key);
                return Task.FromResult(key.Status == HostKeyStatus.Unknown);
            },
        };
    }

    [Fact]
    public async Task Terminal_RunsCommand_AndPinsHostKey()
    {
        if (!_server.Available) return;
        await using var manager = new SessionManager(_connector);

        var output = await RunEchoAsync(manager.CreateTerminal(Spec(_server.ClientKey)), "first");
        Assert.Contains("pb-first-42", output);
        Assert.Single(_prompts);
        Assert.Equal(HostKeyStatus.Unknown, _prompts.Single().Status);
        Assert.Single(_knownHosts.List());

        // Second connection: key is pinned, no prompt.
        await RunEchoAsync(manager.CreateTerminal(Spec(_server.ClientKey)), "second");
        Assert.Single(_prompts);
    }

    [Fact]
    public async Task Terminal_RejectsChangedHostKey()
    {
        if (!_server.Available) return;
        var target = new SshTarget("127.0.0.1", _server.Port);
        _knownHosts.Trust(new HostKeyInfo(target.HostKeyId, "ssh-ed25519", "AAAAwrongfingerprint", HostKeyStatus.Unknown, null));
        await using var manager = new SessionManager(_connector);
        var session = manager.CreateTerminal(Spec(_server.ClientKey));

        await Assert.ThrowsAsync<HostKeyRejectedException>(() => session.ConnectAsync(80, 24));
        Assert.Equal(HostKeyStatus.Changed, Assert.Single(_prompts).Status);
        Assert.Equal(SessionState.Failed, session.State);
    }

    [Fact]
    public async Task PassboltHostIdentity_Matching_ConnectsWithoutPrompt()
    {
        if (!_server.Available) return;
        await using var manager = new SessionManager(_connector);
        var spec = Spec(_server.ClientKey) with { HostKeys = SshConnectionMapper.ParseHostKeys("[127.0.0.1]:22 " + _server.HostPublicKey) };

        Assert.Contains("pb-pinned-42", await RunEchoAsync(manager.CreateTerminal(spec), "pinned"));
        Assert.Empty(_prompts);
        Assert.Empty(_knownHosts.List()); // Passbolt is the source of truth; nothing stored locally
    }

    [Fact]
    public async Task PassboltHostIdentity_Mismatch_IsRejectedWithoutPrompt()
    {
        if (!_server.Available) return;
        await using var manager = new SessionManager(_connector);
        // Even a locally trusted key must not override the identity stored in Passbolt.
        _knownHosts.Trust(await FetchHostKeyAsync());
        var spec = Spec(_server.ClientKey) with { HostKeys = [new ExpectedHostKey("ssh-ed25519", "AAAAwrongfingerprint")] };

        var terminal = manager.CreateTerminal(spec);
        var ex = await Assert.ThrowsAsync<HostKeyRejectedException>(() => terminal.ConnectAsync(80, 24));
        Assert.Contains("does not match the host identity stored in Passbolt", ex.Message);
        Assert.Equal(SessionState.Failed, terminal.State);

        var sftp = manager.CreateSftp(spec);
        await Assert.ThrowsAsync<HostKeyRejectedException>(() => sftp.ConnectAsync());
        Assert.Empty(_prompts);
    }

    [Fact]
    public async Task EncryptedKey_RequiresPassphrase()
    {
        if (!_server.Available) return;
        await using var manager = new SessionManager(_connector);
        var session = manager.CreateTerminal(Spec(_server.EncryptedClientKey));

        var ex = await Assert.ThrowsAsync<KeyPassphraseRequiredException>(() => session.ConnectAsync(80, 24));
        Assert.False(ex.WrongPassphrase);

        session.UpdateCredentials(session.Spec.Credentials with { KeyPassphrase = "wrong" });
        Assert.True((await Assert.ThrowsAsync<KeyPassphraseRequiredException>(() => session.ConnectAsync(80, 24))).WrongPassphrase);

        session.UpdateCredentials(session.Spec.Credentials with { KeyPassphrase = "secret" });
        Assert.Contains("pb-enc-42", await RunEchoAsync(session, "enc"));
    }

    [Fact]
    public async Task ConcurrentKeystrokes_ArriveInOrder()
    {
        if (!_server.Available) return;
        await using var manager = new SessionManager(_connector);
        _knownHosts.Trust(await FetchHostKeyAsync());
        var session = manager.CreateTerminal(Spec(_server.ClientKey));
        var output = new StringBuilder();
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.DataReceived += data =>
        {
            lock (output)
            {
                output.Append(Encoding.UTF8.GetString(data));
                if (output.ToString().Contains("pb-order-42"))
                    done.TrySetResult();
            }
        };
        await session.ConnectAsync(120, 40);

        // Like a UI: one write per keystroke, fired without awaiting the previous one.
        await Task.WhenAll("echo pb-order-$((40+2))\n".Select(c => session.WriteAsync(c.ToString())));

        await done.Task.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task WorkingDirectory_FollowsCd_WithoutWindowTitle_AndInNestedShell()
    {
        if (!_server.Available) return;
        await using var manager = new SessionManager(_connector);
        _knownHosts.Trust(await FetchHostKeyAsync());
        var session = manager.CreateTerminal(Spec(_server.ClientKey));
        await session.ConnectAsync(120, 40);
        var nested = Directory.CreateDirectory(Path.Combine(_workDir, "nested dir")).FullName;

        // A plain prompt that sets no window title, like root's default .bashrc on Debian.
        await session.WriteAsync("PS1='$ '; PROMPT_COMMAND=; cd /tmp\n");
        Assert.Equal("/tmp", await WaitForDirectoryAsync(session, "/tmp"));

        // A nested shell is the terminal's foreground process; its cwd counts.
        await session.WriteAsync($"sh\n");
        await session.WriteAsync($"cd '{nested}'\n");
        Assert.Equal(nested, await WaitForDirectoryAsync(session, nested));

        await session.WriteAsync("exit\n");
        Assert.Equal("/tmp", await WaitForDirectoryAsync(session, "/tmp"));
    }

    [Fact]
    public async Task Sftp_SymlinkToDirectory_CanBeOpened_ButIsNotFollowedRecursively()
    {
        if (!_server.Available) return;
        await using var manager = new SessionManager(_connector);
        var sftp = manager.CreateSftp(Spec(_server.ClientKey));
        await sftp.ConnectAsync();

        var root = Directory.CreateDirectory(Path.Combine(_server.Directory, "links")).FullName;
        var target = Directory.CreateDirectory(Path.Combine(_server.Directory, "link-target")).FullName;
        File.WriteAllText(Path.Combine(target, "inside.txt"), "x");
        File.CreateSymbolicLink(Path.Combine(root, "to-dir"), target);
        File.CreateSymbolicLink(Path.Combine(root, "dangling"), Path.Combine(_server.Directory, "missing"));
        File.WriteAllText(Path.Combine(root, "plain.txt"), "y");

        var listing = await sftp.ListAsync(root);
        var link = listing.Single(e => e.Name == "to-dir");
        Assert.True(link.IsSymlink);
        Assert.True(link.IsDirectory);
        Assert.False(listing.Single(e => e.Name == "dangling").IsDirectory);
        Assert.Equal(["to-dir", "dangling", "plain.txt"], listing.Select(e => e.Name));

        // Opening the link lists the target's content.
        Assert.Equal(["inside.txt"], (await sftp.ListAsync(link.FullPath)).Select(e => e.Name));

        // Downloading the parent folder copies real files but does not follow links inside it.
        var download = Directory.CreateDirectory(Path.Combine(_workDir, "dl")).FullName;
        await sftp.DownloadAsync(new Transfer.RemoteEntry("links", root, true, false, 0, default, ""), download);
        Assert.Equal(["plain.txt"], Directory.GetFileSystemEntries(Path.Combine(download, "links")).Select(Path.GetFileName));
    }

    private static async Task<string?> WaitForDirectoryAsync(SshTerminalSession session, string expected)
    {
        string? current = null;
        for (var i = 0; i < 30 && current != expected; i++)
        {
            await Task.Delay(100);
            current = await session.GetWorkingDirectoryAsync();
        }
        return current;
    }

    [Fact]
    public async Task ParallelSessions_AreIndependent()
    {
        if (!_server.Available) return;
        await using var manager = new SessionManager(_connector);
        _knownHosts.Trust(await FetchHostKeyAsync());

        var outputs = await Task.WhenAll(Enumerable.Range(1, 5)
            .Select(i => RunEchoAsync(manager.CreateTerminal(Spec(_server.ClientKey)), $"p{i}")));

        for (var i = 1; i <= 5; i++)
        {
            Assert.Contains($"pb-p{i}-42", outputs[i - 1]);
            Assert.DoesNotContain($"pb-p{(i % 5) + 1}-42", outputs[i - 1]);
        }
        Assert.Equal(5, manager.Count);
    }

    [Fact]
    public async Task Sftp_UploadListDownloadDelete()
    {
        if (!_server.Available) return;
        await using var manager = new SessionManager(_connector);
        var sftp = manager.CreateSftp(Spec(_server.ClientKey));
        await sftp.ConnectAsync();
        Assert.False(sftp.IsScpFallback);

        var local = Directory.CreateDirectory(Path.Combine(_workDir, "upload-src"));
        File.WriteAllText(Path.Combine(local.FullName, "a.txt"), "alpha");
        Directory.CreateDirectory(Path.Combine(local.FullName, "sub"));
        var big = new byte[3 * 1024 * 1024];
        Random.Shared.NextBytes(big);
        File.WriteAllBytes(Path.Combine(local.FullName, "sub", "big.bin"), big);

        var remoteRoot = Path.Combine(_server.Directory, "remote");
        Directory.CreateDirectory(remoteRoot);
        await sftp.UploadAsync(local.FullName, remoteRoot);

        var upload = Assert.Single(sftp.Transfers);
        Assert.Equal(TransferState.Completed, upload.State);
        Assert.Equal(big.Length + 5, upload.TransferredBytes);
        Assert.Equal(100, upload.Percent);

        var listing = await sftp.ListAsync(remoteRoot + "/upload-src");
        Assert.Equal(["sub", "a.txt"], listing.Select(e => e.Name));
        Assert.True(listing[0].IsDirectory);

        var downloadDir = Directory.CreateDirectory(Path.Combine(_workDir, "download")).FullName;
        await sftp.DownloadAsync((await sftp.ListAsync(remoteRoot)).Single(e => e.Name == "upload-src"), downloadDir);
        Assert.Equal("alpha", File.ReadAllText(Path.Combine(downloadDir, "upload-src", "a.txt")));
        Assert.Equal(big, File.ReadAllBytes(Path.Combine(downloadDir, "upload-src", "sub", "big.bin")));
        Assert.Empty(Directory.GetFiles(downloadDir, "*.part", SearchOption.AllDirectories));

        await sftp.DeleteAsync(listing[0]);
        Assert.Equal(["a.txt"], (await sftp.ListAsync(remoteRoot + "/upload-src")).Select(e => e.Name));
    }

    private SshConnectionSpec Spec(string privateKey) =>
        new("local", new SshTarget("127.0.0.1", _server.Port), _server.User, new SshCredentials(null, privateKey, null));

    private async Task<HostKeyInfo> FetchHostKeyAsync()
    {
        HostKeyInfo? captured = null;
        var probe = new SshConnector(new KnownHostsStore(Path.Combine(_workDir, "probe.json")), NullLogger<SshConnector>.Instance)
        {
            HostKeyPrompt = k => { captured = k; return Task.FromResult(true); },
        };
        using var client = probe.CreateSshClient(Spec(_server.ClientKey));
        await client.ConnectAsync(CancellationToken.None);
        return captured!;
    }

    private static async Task<string> RunEchoAsync(SshTerminalSession session, string tag)
    {
        var output = new StringBuilder();
        var expected = $"pb-{tag}-42";
        // Must not continue on SSH.NET's receive thread: Disconnect() there would deadlock.
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.DataReceived += data =>
        {
            lock (output)
            {
                output.Append(Encoding.UTF8.GetString(data));
                if (output.ToString().Contains(expected))
                    done.TrySetResult();
            }
        };
        await session.ConnectAsync(120, 40);
        Assert.Equal(SessionState.Connected, session.State);
        session.Resize(100, 30);
        // Arithmetic expansion ensures we match the command's output, not the echoed input.
        await session.WriteAsync($"echo pb-{tag}-$((40+2))\n");
        await done.Task.WaitAsync(TimeSpan.FromSeconds(15));
        await session.DisconnectAsync();
        lock (output)
            return output.ToString();
    }

    public void Dispose() => Directory.Delete(_workDir, recursive: true);
}
