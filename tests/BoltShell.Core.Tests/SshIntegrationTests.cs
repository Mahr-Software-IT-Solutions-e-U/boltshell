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
        _server.WaitUntilListening(); // a previous test may have reloaded sshd
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

    [SkippableFact]
    public async Task Terminal_RunsCommand_AndPinsHostKey()
    {
        Skip.IfNot(_server.Available, "OpenSSH server (sshd) not installed");
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

    [SkippableFact]
    public async Task Terminal_RejectsChangedHostKey()
    {
        Skip.IfNot(_server.Available, "OpenSSH server (sshd) not installed");
        var target = new SshTarget("127.0.0.1", _server.Port);
        _knownHosts.Trust(new HostKeyInfo(target.HostKeyId, "ssh-ed25519", "AAAAwrongfingerprint", HostKeyStatus.Unknown, null));
        await using var manager = new SessionManager(_connector);
        var session = manager.CreateTerminal(Spec(_server.ClientKey));

        await Assert.ThrowsAsync<HostKeyRejectedException>(() => session.ConnectAsync(80, 24));
        Assert.Equal(HostKeyStatus.Changed, Assert.Single(_prompts).Status);
        Assert.Equal(SessionState.Failed, session.State);
    }

    [SkippableFact]
    public async Task PassboltHostIdentity_Matching_ConnectsWithoutPrompt()
    {
        Skip.IfNot(_server.Available, "OpenSSH server (sshd) not installed");
        await using var manager = new SessionManager(_connector);
        var spec = Spec(_server.ClientKey) with { HostKeys = SshConnectionMapper.ParseHostKeys("[127.0.0.1]:22 " + _server.HostPublicKey) };

        Assert.Contains("pb-pinned-42", await RunEchoAsync(manager.CreateTerminal(spec), "pinned"));
        Assert.Empty(_prompts);
        Assert.Empty(_knownHosts.List()); // Passbolt is the source of truth; nothing stored locally
    }

    [SkippableFact]
    public async Task PassboltHostIdentity_Mismatch_IsRejectedWithoutPrompt()
    {
        Skip.IfNot(_server.Available, "OpenSSH server (sshd) not installed");
        await using var manager = new SessionManager(_connector);
        // Even a locally trusted key must not override the identity stored in Passbolt.
        _knownHosts.Trust(await FetchHostKeyAsync());
        var spec = Spec(_server.ClientKey) with { HostKeys = [new ExpectedHostKey("ssh-ed25519", "AAAAwrongfingerprint")] };

        var terminal = manager.CreateTerminal(spec);
        var ex = await Assert.ThrowsAsync<HostKeyRejectedException>(() => terminal.ConnectAsync(80, 24));
        Assert.Contains("does not match the host identity stored in Passbolt", ex.Message);
        Assert.Equal(SessionState.Failed, terminal.State);

        // The tab can show what the server presented and offer it for Passbolt.
        Assert.True(ex.PinnedInPassbolt);
        Assert.Equal(["AAAAwrongfingerprint"], ex.ExpectedFingerprints);
        Assert.Same(ex, terminal.HostKeyMismatch);
        var presented = Assert.Single(SshConnectionMapper.ParseHostKeys(terminal.ObservedHostKey));
        Assert.Equal(Assert.Single(SshConnectionMapper.ParseHostKeys("[127.0.0.1]:22 " + _server.HostPublicKey)).FingerprintSha256, presented.FingerprintSha256);

        // After the identity is updated, the next connect succeeds and the mismatch is cleared.
        terminal.UpdateHostKeys(SshConnectionMapper.ParseHostKeys(terminal.ObservedHostKey));
        Assert.Contains("pb-updated-42", await RunEchoAsync(terminal, "updated"));
        Assert.Null(terminal.HostKeyMismatch);

        var sftp = manager.CreateSftp(spec);
        await Assert.ThrowsAsync<HostKeyRejectedException>(() => sftp.ConnectAsync());
        Assert.Empty(_prompts);
    }

    [SkippableFact]
    public async Task EncryptedKey_RequiresPassphrase()
    {
        Skip.IfNot(_server.Available, "OpenSSH server (sshd) not installed");
        await using var manager = new SessionManager(_connector);
        var session = manager.CreateTerminal(Spec(_server.EncryptedClientKey));

        var ex = await Assert.ThrowsAsync<KeyPassphraseRequiredException>(() => session.ConnectAsync(80, 24));
        Assert.False(ex.WrongPassphrase);

        session.UpdateCredentials(session.Spec.Credentials with { KeyPassphrase = "wrong" });
        Assert.True((await Assert.ThrowsAsync<KeyPassphraseRequiredException>(() => session.ConnectAsync(80, 24))).WrongPassphrase);

        session.UpdateCredentials(session.Spec.Credentials with { KeyPassphrase = "secret" });
        Assert.Contains("pb-enc-42", await RunEchoAsync(session, "enc"));
    }

    [SkippableFact]
    public async Task ConcurrentKeystrokes_ArriveInOrder()
    {
        Skip.IfNot(_server.Available, "OpenSSH server (sshd) not installed");
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

    [SkippableFact]
    public async Task WorkingDirectory_FollowsCd_WithoutWindowTitle_AndInNestedShell()
    {
        Skip.IfNot(_server.Available, "OpenSSH server (sshd) not installed");
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

    [SkippableFact]
    public async Task Sftp_SymlinkToDirectory_CanBeOpened_ButIsNotFollowedRecursively()
    {
        Skip.IfNot(_server.Available, "OpenSSH server (sshd) not installed");
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

    [SkippableFact]
    public async Task Sftp_RecursiveDownload_SkipsTraversalNames_AndLinksAtTarget()
    {
        Skip.IfNot(_server.Available, "OpenSSH server (sshd) not installed");
        await using var manager = new SessionManager(_connector);
        var sftp = manager.CreateSftp(Spec(_server.ClientKey));
        await sftp.ConnectAsync();

        // A hostile server folder: on Linux "..\\outside.txt" is an ordinary file name, on Windows a path.
        var remote = Directory.CreateDirectory(Path.Combine(_server.Directory, "hostile")).FullName;
        File.WriteAllText(Path.Combine(remote, "..\\outside.txt"), "evil");
        File.WriteAllText(Path.Combine(remote, "ok.txt"), "fine");
        File.WriteAllText(Path.Combine(remote, "linked.txt"), "overwrite?");

        var download = Directory.CreateDirectory(Path.Combine(_workDir, "safe-dl")).FullName;
        var victim = Path.Combine(_workDir, "victim.txt");
        File.WriteAllText(victim, "keep");
        Directory.CreateDirectory(Path.Combine(download, "hostile"));
        File.CreateSymbolicLink(Path.Combine(download, "hostile", "linked.txt"), victim);

        await sftp.DownloadAsync((await sftp.ListAsync(_server.Directory)).Single(e => e.Name == "hostile"), download);

        var transfer = sftp.Transfers.Last();
        Assert.Equal("fine", File.ReadAllText(Path.Combine(download, "hostile", "ok.txt")));
        Assert.Equal("keep", File.ReadAllText(victim)); // not written through the link
        Assert.False(File.Exists(Path.Combine(download, "outside.txt")));
        Assert.Empty(Directory.GetFiles(_workDir, "*outside*", SearchOption.AllDirectories));
        Assert.Equal(TransferState.Completed, transfer.State);
        Assert.Contains(transfer.Warnings, w => w.Contains("outside.txt"));  // skipped and reported
        Assert.Contains(transfer.Warnings, w => w.Contains("symlink"));  // link at the target skipped and reported
        Assert.Equal(2, transfer.Warnings.Count);
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

    [SkippableFact]
    public async Task ParallelSessions_AreIndependent()
    {
        Skip.IfNot(_server.Available, "OpenSSH server (sshd) not installed");
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

    [SkippableFact]
    public async Task Sftp_UploadListDownloadDelete()
    {
        Skip.IfNot(_server.Available, "OpenSSH server (sshd) not installed");
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

    [SkippableFact]
    public async Task Vim_AcceptsTypedText_AndSaves()
    {
        Skip.IfNot(_server.Available, "OpenSSH server (sshd) not installed");
        Skip.If(!File.Exists("/usr/bin/vim"), "vim not installed");
        var file = Path.Combine(_workDir, "vim-test.txt");
        await using var manager = new SessionManager(_connector);
        var session = manager.CreateTerminal(Spec(_server.ClientKey));
        var output = new StringBuilder();
        session.DataReceived += data => { lock (output) output.Append(Encoding.UTF8.GetString(data)); };
        await session.ConnectAsync(100, 30);

        await session.WriteAsync($"vim -u NONE -N {file}\r");
        await Task.Delay(1500); // vim starts and switches to the alternate screen
        foreach (var key in new[] { "i", "hello from vim", "\u001b", ":wq\r" })
        {
            await session.WriteAsync(key);
            await Task.Delay(300);
        }
        for (var i = 0; i < 50 && !File.Exists(file); i++)
            await Task.Delay(100);
        await session.DisconnectAsync();

        string log;
        lock (output)
            log = output.ToString();
        Assert.True(File.Exists(file), "vim did not write the file. Output:\n" + log);
        Assert.Equal("hello from vim", File.ReadAllText(file).TrimEnd('\n'));
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
