using Renci.SshNet;
using Renci.SshNet.Common;
using BoltShell.Core.Ssh;

namespace BoltShell.Core.Transfer;

public sealed record RemoteEntry(string Name, string FullPath, bool IsDirectory, bool IsSymlink, long Size, DateTime LastWriteTime, string Permissions);

public enum TransferDirection { Upload, Download }
public enum TransferState { Queued, Running, Completed, Failed, Cancelled }

/// <summary>Progress and control for one file transfer.</summary>
public sealed class TransferItem
{
    internal readonly CancellationTokenSource Cts = new();

    public required string Name { get; init; }
    public required string Source { get; init; }
    public required string Destination { get; init; }
    public required TransferDirection Direction { get; init; }
    public long TotalBytes { get; internal set; }
    public long TransferredBytes { get; internal set; }
    public TransferState State { get; internal set; } = TransferState.Queued;
    public string? Error { get; internal set; }

    /// <summary>Entries skipped during a folder download because their names were unsafe locally.</summary>
    public IReadOnlyList<string> Warnings => _warnings;
    private readonly List<string> _warnings = [];
    internal void Warn(string message)
    {
        lock (_warnings)
            _warnings.Add(message);
    }

    public double Percent => TotalBytes > 0 ? Math.Min(100, TransferredBytes * 100.0 / TotalBytes) : State == TransferState.Completed ? 100 : 0;
    public void Cancel() => Cts.Cancel();
}

/// <summary>
/// File transfer session. Uses SFTP; if the server has no SFTP subsystem it falls back to
/// legacy SCP, which can transfer files but cannot list directories.
/// </summary>
public sealed class SftpSession : IAsyncDisposable
{
    private readonly SshConnector _connector;
    private readonly List<TransferItem> _transfers = [];
    private SftpClient? _sftp;
    private ScpClient? _scp;

    internal SftpSession(SshConnector connector, SshConnectionSpec spec)
    {
        _connector = connector;
        Spec = spec;
    }

    public Guid Id { get; } = Guid.NewGuid();
    public SshConnectionSpec Spec { get; private set; }
    public bool IsScpFallback => _scp is not null;
    public bool IsConnected => _sftp?.IsConnected == true || _scp?.IsConnected == true;
    public string HomeDirectory { get; private set; } = "/";

    public IReadOnlyList<TransferItem> Transfers
    {
        get { lock (_transfers) return _transfers.ToList(); }
    }

    /// <summary>Raised (on a background thread) whenever a transfer's progress or state changes.</summary>
    public event Action? TransfersChanged;

    public void UpdateCredentials(SshCredentials credentials) => Spec = Spec with { Credentials = credentials };

    /// <summary>Replaces the expected host identity (used from the next connect on).</summary>
    public void UpdateHostKeys(IReadOnlyList<ExpectedHostKey>? hostKeys) => Spec = Spec with { HostKeys = hostKeys };

    public async Task ConnectAsync(CancellationToken ct = default)
    {
        await DisposeClientsAsync();
        _sftp = _connector.CreateSftpClient(Spec);
        try
        {
            await _connector.ConnectAsync(_sftp, ct);
            HomeDirectory = _sftp.WorkingDirectory;
        }
        catch (SshException ex) when (ex.Message.Contains("subsystem", StringComparison.OrdinalIgnoreCase))
        {
            _sftp.Dispose();
            _sftp = null;
            _scp = _connector.CreateScpClient(Spec);
            await _connector.ConnectAsync(_scp, ct);
            HomeDirectory = ".";
        }
    }

    public async Task<IReadOnlyList<RemoteEntry>> ListAsync(string path, CancellationToken ct = default)
    {
        var sftp = RequireSftp();
        var entries = new List<RemoteEntry>();
        await foreach (var file in sftp.ListDirectoryAsync(path, ct))
        {
            if (file.Name is "." or "..")
                continue;
            // The listing describes the link itself; resolve it so links to directories can be opened.
            var isDirectory = file.IsDirectory || file.IsSymbolicLink && await IsDirectoryTargetAsync(sftp, file.FullName, ct);
            entries.Add(new RemoteEntry(file.Name, file.FullName, isDirectory, file.IsSymbolicLink, file.Length,
                file.LastWriteTime, PermissionString(file)));
        }
        return entries.OrderByDescending(e => e.IsDirectory).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static async Task<bool> IsDirectoryTargetAsync(SftpClient sftp, string linkPath, CancellationToken ct)
    {
        try
        {
            // GetAttributes canonicalises the path (realpath) first, so it reports the link target.
            return (await sftp.GetAttributesAsync(linkPath, ct)).IsDirectory;
        }
        catch (SshException)
        {
            return false; // dangling link or no permission: treat like a file
        }
    }

    public Task CreateDirectoryAsync(string path, CancellationToken ct = default) => RequireSftp().CreateDirectoryAsync(path, ct);

    public Task RenameAsync(string from, string to, CancellationToken ct = default) => RequireSftp().RenameFileAsync(from, to, ct);

    public async Task DeleteAsync(RemoteEntry entry, CancellationToken ct = default)
    {
        var sftp = RequireSftp();
        if (entry.IsDirectory && !entry.IsSymlink)
        {
            foreach (var child in await ListAsync(entry.FullPath, ct))
                await DeleteAsync(child, ct);
            await sftp.DeleteDirectoryAsync(entry.FullPath, ct);
        }
        else
        {
            await sftp.DeleteFileAsync(entry.FullPath, ct);
        }
    }

    /// <summary>Uploads a local file or directory (recursively) into <paramref name="remoteDirectory"/>.</summary>
    public Task UploadAsync(string localPath, string remoteDirectory)
    {
        var name = Path.GetFileName(localPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var item = AddTransfer(name, localPath, CombineRemote(remoteDirectory, name), TransferDirection.Upload);
        return RunAsync(item, async ct =>
        {
            if (Directory.Exists(localPath))
            {
                var files = Directory.EnumerateFiles(localPath, "*", SearchOption.AllDirectories).ToList();
                item.TotalBytes = files.Sum(f => new FileInfo(f).Length);
                await UploadDirectoryAsync(localPath, item.Destination, item, ct);
            }
            else
            {
                item.TotalBytes = new FileInfo(localPath).Length;
                await UploadFileAsync(localPath, item.Destination, item, ct);
            }
        });
    }

    /// <summary>Uploads data from a stream (e.g. a browser file input) to a remote file.</summary>
    public Task UploadStreamAsync(Stream content, string name, long size, string remoteDirectory)
    {
        var item = AddTransfer(name, name, CombineRemote(remoteDirectory, name), TransferDirection.Upload);
        item.TotalBytes = size;
        return RunAsync(item, async ct =>
        {
            var start = item.TransferredBytes;
            if (_sftp is not null)
                await _sftp.UploadFileAsync(content, item.Destination, new SyncProgress<UploadFileProgressReport>(r => Report(item, start + (long)r.TotalBytesUploaded)), ct);
            else
                await Task.Run(() => RequireScp().Upload(content, item.Destination), ct);
        });
    }

    /// <summary>
    /// Downloads a remote file or directory (recursively) into <paramref name="localDirectory"/>. Remote names are
    /// checked with <see cref="LocalPaths"/>: the download never writes outside the chosen folder.
    /// </summary>
    public Task DownloadAsync(RemoteEntry entry, string localDirectory)
    {
        var item = AddTransfer(entry.Name, entry.FullPath, Path.Join(localDirectory, entry.Name), TransferDirection.Download);
        return RunAsync(item, async ct =>
        {
            var destination = LocalPaths.Child(localDirectory, entry.Name);
            if (entry.IsDirectory)
            {
                item.TotalBytes = await MeasureAsync(entry.FullPath, ct);
                await DownloadDirectoryAsync(entry.FullPath, destination, entry.Name, item, ct);
            }
            else
            {
                item.TotalBytes = entry.Size;
                await DownloadFileAsync(entry.FullPath, destination, entry.Name, item, ct);
            }
        });
    }

    /// <summary>SCP fallback: download a file by path (no directory listing available).</summary>
    public Task DownloadPathAsync(string remotePath, string localDirectory)
    {
        var name = remotePath.TrimEnd('/').Split('/').Last();
        return DownloadAsync(new RemoteEntry(name, remotePath, false, false, 0, default, ""), localDirectory);
    }

    public void ClearFinishedTransfers()
    {
        lock (_transfers)
            _transfers.RemoveAll(t => t.State is TransferState.Completed or TransferState.Cancelled or TransferState.Failed);
        TransfersChanged?.Invoke();
    }

    private async Task UploadDirectoryAsync(string localDir, string remoteDir, TransferItem item, CancellationToken ct)
    {
        if (_scp is not null)
        {
            await Task.Run(() => _scp.Upload(new DirectoryInfo(localDir), remoteDir), ct);
            return;
        }
        var sftp = RequireSftp();
        if (!await sftp.ExistsAsync(remoteDir, ct))
            await sftp.CreateDirectoryAsync(remoteDir, ct);

        foreach (var dir in Directory.EnumerateDirectories(localDir))
            await UploadDirectoryAsync(dir, CombineRemote(remoteDir, Path.GetFileName(dir)), item, ct);
        foreach (var file in Directory.EnumerateFiles(localDir))
            await UploadFileAsync(file, CombineRemote(remoteDir, Path.GetFileName(file)), item, ct);
    }

    private async Task UploadFileAsync(string localFile, string remoteFile, TransferItem item, CancellationToken ct)
    {
        await using var input = File.OpenRead(localFile);
        var start = item.TransferredBytes;
        if (_sftp is not null)
        {
            await _sftp.UploadFileAsync(input, remoteFile, new SyncProgress<UploadFileProgressReport>(r => Report(item, start + (long)r.TotalBytesUploaded)), ct);
        }
        else
        {
            await Task.Run(() => RequireScp().Upload(input, remoteFile), ct);
            Report(item, start + input.Length);
        }
    }

    private async Task DownloadDirectoryAsync(string remoteDir, string localDir, string name, TransferItem item, CancellationToken ct)
    {
        // SSH.NET's SCP client builds local paths from server-sent names without our checks.
        if (_scp is not null)
            throw new NotSupportedException("Ordner können über SCP aus Sicherheitsgründen nicht heruntergeladen werden; bitte einzelne Dateien wählen.");

        LocalPaths.EnsureNotLink(localDir, name);
        Directory.CreateDirectory(localDir);
        foreach (var child in await ListAsync(remoteDir, ct))
        {
            // Links inside a downloaded tree are skipped: following them could loop or pull in unrelated data.
            if (child.IsSymlink)
                continue;
            // Unsafe names and links at the target are skipped and reported; the rest of the folder is still downloaded.
            try
            {
                var target = LocalPaths.Child(localDir, child.Name);
                if (child.IsDirectory)
                    await DownloadDirectoryAsync(child.FullPath, target, child.Name, item, ct);
                else
                    await DownloadFileAsync(child.FullPath, target, child.Name, item, ct);
            }
            catch (UnsafeRemoteNameException ex)
            {
                item.Warn(ex.Message);
            }
        }
    }

    private async Task DownloadFileAsync(string remoteFile, string localFile, string name, TransferItem item, CancellationToken ct)
    {
        var start = item.TransferredBytes;
        var partial = localFile + ".part";
        // Never write through an existing link: File.Create would follow it out of the download folder.
        LocalPaths.EnsureNotLink(localFile, name);
        LocalPaths.EnsureNotLink(partial, name);
        await using (var output = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            if (_sftp is not null)
                await _sftp.DownloadFileAsync(remoteFile, output, new SyncProgress<DownloadFileProgressReport>(r => Report(item, start + (long)r.TotalBytesDownloaded)), ct);
            else
                await Task.Run(() => RequireScp().Download(remoteFile, output), ct);
            Report(item, start + output.Length);
        }
        File.Move(partial, localFile, overwrite: true);
    }

    private async Task<long> MeasureAsync(string remoteDir, CancellationToken ct)
    {
        if (_sftp is null)
            return 0;
        long total = 0;
        foreach (var child in await ListAsync(remoteDir, ct))
            total += child.IsSymlink ? 0 : child.IsDirectory ? await MeasureAsync(child.FullPath, ct) : child.Size;
        return total;
    }

    private TransferItem AddTransfer(string name, string source, string destination, TransferDirection direction)
    {
        var item = new TransferItem { Name = name, Source = source, Destination = destination, Direction = direction };
        lock (_transfers)
            _transfers.Add(item);
        TransfersChanged?.Invoke();
        return item;
    }

    private async Task RunAsync(TransferItem item, Func<CancellationToken, Task> work)
    {
        item.State = TransferState.Running;
        TransfersChanged?.Invoke();
        try
        {
            await work(item.Cts.Token);
            item.State = TransferState.Completed;
        }
        catch (OperationCanceledException)
        {
            item.State = TransferState.Cancelled;
        }
        catch (Exception ex)
        {
            item.State = TransferState.Failed;
            item.Error = ex.Message;
        }
        TransfersChanged?.Invoke();
    }

    private void Report(TransferItem item, long transferred)
    {
        item.TransferredBytes = transferred;
        TransfersChanged?.Invoke();
    }

    private SftpClient RequireSftp() =>
        _sftp ?? throw new InvalidOperationException(_scp is not null
            ? "The server does not support SFTP; only SCP transfers by path are available."
            : "Not connected.");

    private ScpClient RequireScp() => _scp ?? throw new InvalidOperationException("Not connected.");

    public static string CombineRemote(string directory, string name) =>
        directory.EndsWith('/') ? directory + name : directory + "/" + name;

    private static string PermissionString(Renci.SshNet.Sftp.ISftpFile f) => string.Concat(
        f.IsDirectory ? 'd' : f.IsSymbolicLink ? 'l' : '-',
        f.OwnerCanRead ? 'r' : '-', f.OwnerCanWrite ? 'w' : '-', f.OwnerCanExecute ? 'x' : '-',
        f.GroupCanRead ? 'r' : '-', f.GroupCanWrite ? 'w' : '-', f.GroupCanExecute ? 'x' : '-',
        f.OthersCanRead ? 'r' : '-', f.OthersCanWrite ? 'w' : '-', f.OthersCanExecute ? 'x' : '-');

    private Task DisposeClientsAsync()
    {
        foreach (var client in new BaseClient?[] { _sftp, _scp })
        {
            if (client is null)
                continue;
            if (client.IsConnected)
                client.Disconnect();
            client.Dispose();
        }
        _sftp = null;
        _scp = null;
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var transfer in Transfers)
            transfer.Cancel();
        TransfersChanged = null;
        await DisposeClientsAsync();
    }

    /// <summary>Reports synchronously; <see cref="Progress{T}"/> would post to the UI context and arrive out of order.</summary>
    private sealed class SyncProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }
}
