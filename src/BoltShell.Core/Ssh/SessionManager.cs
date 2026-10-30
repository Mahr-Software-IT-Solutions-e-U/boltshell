using System.Collections.Concurrent;
using BoltShell.Core.Transfer;

namespace BoltShell.Core.Ssh;

/// <summary>Owns all open terminal and file-transfer sessions. Each session has its own SSH connection.</summary>
public sealed class SessionManager(SshConnector connector) : IAsyncDisposable
{
    private readonly ConcurrentDictionary<Guid, IAsyncDisposable> _sessions = new();

    public SshTerminalSession CreateTerminal(SshConnectionSpec spec)
    {
        var session = new SshTerminalSession(connector, spec);
        _sessions[session.Id] = session;
        return session;
    }

    public SftpSession CreateSftp(SshConnectionSpec spec)
    {
        var session = new SftpSession(connector, spec);
        _sessions[session.Id] = session;
        return session;
    }

    public async Task CloseAsync(Guid id)
    {
        if (_sessions.TryRemove(id, out var session))
            await session.DisposeAsync();
    }

    public int Count => _sessions.Count;

    public async ValueTask DisposeAsync()
    {
        foreach (var id in _sessions.Keys.ToList())
            await CloseAsync(id);
    }
}
