using System.Text;
using Renci.SshNet;

namespace BoltShell.Core.Ssh;

public enum SessionState { Created, Connecting, Connected, Closed, Failed }

/// <summary>An interactive shell (PTY) on a remote host.</summary>
public sealed class SshTerminalSession : IAsyncDisposable
{
    private readonly SshConnector _connector;
    private SshClient? _client;
    private ShellStream? _shell;
    private (int Columns, int Rows) _size = (80, 24);

    // ShellStream is not safe for concurrent writes; UI input events can overlap while a write is in flight.
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    internal SshTerminalSession(SshConnector connector, SshConnectionSpec spec)
    {
        _connector = connector;
        Spec = spec;
    }

    public Guid Id { get; } = Guid.NewGuid();

    /// <summary>Current terminal size in columns and rows.</summary>
    public (int Columns, int Rows) Size => _size;
    public SshConnectionSpec Spec { get; private set; }
    public SessionState State { get; private set; } = SessionState.Created;
    public string? Error { get; private set; }

    /// <summary>The host key the server presented on the last connect (known_hosts line), if any.</summary>
    public string? ObservedHostKey { get; private set; }

    /// <summary>Set when the last connect was refused because the server's key contradicts Passbolt.</summary>
    public HostKeyRejectedException? HostKeyMismatch { get; private set; }

    /// <summary>Raised after input containing Enter was sent (e.g. to refresh the working directory).</summary>
    public event Action? InputSubmitted;

    /// <summary>Raw terminal output. Raised on an SSH.NET thread.</summary>
    public event Action<byte[]>? DataReceived;

    public event Action<SessionState>? StateChanged;

    /// <summary>Replaces the credentials, e.g. after the user entered a key passphrase.</summary>
    public void UpdateCredentials(SshCredentials credentials) => Spec = Spec with { Credentials = credentials };

    /// <summary>Replaces the expected host identity (used from the next connect on).</summary>
    public void UpdateHostKeys(IReadOnlyList<ExpectedHostKey>? hostKeys) => Spec = Spec with { HostKeys = hostKeys };

    public async Task ConnectAsync(int columns, int rows, CancellationToken ct = default)
    {
        if (State is SessionState.Connecting or SessionState.Connected)
            return;
        SetState(SessionState.Connecting);
        try
        {
            await CloseClientAsync();
            _size = (columns, rows);
            HostKeyMismatch = null;
            _client = _connector.CreateSshClient(Spec);
            try
            {
                await _connector.ConnectAsync(_client, ct);
            }
            catch (HostKeyRejectedException ex) when (ex.PinnedInPassbolt)
            {
                HostKeyMismatch = ex;
                throw;
            }
            finally
            {
                ObservedHostKey = _connector.ObservedHostKey(_client);
            }
            // Use the latest size: the terminal may have been resized while connecting.
            _shell = _client.CreateShellStream("xterm-256color", (uint)_size.Columns, (uint)_size.Rows, 0, 0, 64 * 1024);
            _shell.DataReceived += (_, e) => DataReceived?.Invoke(e.Data);
            _shell.Closed += (_, _) => SetState(SessionState.Closed);
            _shell.ErrorOccurred += (_, e) => Fail(e.Exception);
            _client.ErrorOccurred += (_, e) => Fail(e.Exception);
            Error = null;
            SetState(SessionState.Connected);
        }
        catch (Exception ex)
        {
            Fail(ex);
            throw;
        }
    }

    public async Task WriteAsync(string input)
    {
        if (_shell is null || State != SessionState.Connected)
            return;
        var bytes = Encoding.UTF8.GetBytes(input);
        await _writeLock.WaitAsync();
        try
        {
            if (_shell is not { } shell)
                return;
            await shell.WriteAsync(bytes);
            await shell.FlushAsync();
        }
        finally
        {
            _writeLock.Release();
        }
        if (input.Contains('\r') || input.Contains('\n'))
            InputSubmitted?.Invoke();
    }

    public void Resize(int columns, int rows)
    {
        if (columns <= 0 || rows <= 0 || _size == (columns, rows))
            return;
        _size = (columns, rows);
        if (_shell is not null && State == SessionState.Connected)
            _shell.ChangeWindowSize((uint)columns, (uint)rows, 0, 0);
    }

    // Runs over a separate exec channel of the same connection: find this connection's sshd process, its child that owns
    // a TTY (our shell), then the TTY's foreground process (e.g. a nested shell after `su -`) and read its cwd from /proc.
    // Independent of prompt or window-title configuration; Linux only (other systems return null).
    internal const string WorkingDirectoryScript = """
        p=$$
        while [ "${p:-1}" -gt 1 ]; do
          case "$(ps -o comm= -p "$p" 2>/dev/null)" in sshd*) break ;; esac
          p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
        done
        [ "${p:-1}" -gt 1 ] || exit 1
        s=$(ps -e -o pid=,ppid=,tty= | awk -v p="$p" '$2 == p && $3 != "?" { print $1; exit }')
        [ -n "$s" ] || exit 1
        f=$(ps -o tpgid= -p "$s" | tr -d ' ')
        readlink "/proc/$f/cwd" 2>/dev/null || readlink "/proc/$s/cwd"
        """;

    /// <summary>The current working directory of the shell's foreground process, or null if it cannot be determined.</summary>
    public async Task<string?> GetWorkingDirectoryAsync(CancellationToken ct = default)
    {
        if (_client is not { IsConnected: true } client || State != SessionState.Connected)
            return null;
        try
        {
            using var command = client.CreateCommand("sh -c '" + WorkingDirectoryScript.Replace("'", "'\\''") + "'");
            command.CommandTimeout = TimeSpan.FromSeconds(5);
            await command.ExecuteAsync(ct);
            var path = command.Result.Trim();
            return command.ExitStatus == 0 && path.StartsWith('/') ? path : null;
        }
        catch (Exception ex) when (ex is Renci.SshNet.Common.SshException or TimeoutException or InvalidOperationException)
        {
            return null;
        }
    }

    public async Task DisconnectAsync()
    {
        await CloseClientAsync();
        SetState(SessionState.Closed);
    }

    private void Fail(Exception ex)
    {
        Error = ex.Message;
        SetState(SessionState.Failed);
    }

    private void SetState(SessionState state)
    {
        if (State == state)
            return;
        State = state;
        StateChanged?.Invoke(state);
    }

    private Task CloseClientAsync()
    {
        _shell?.Dispose();
        _shell = null;
        if (_client is not null)
        {
            if (_client.IsConnected)
                _client.Disconnect();
            _client.Dispose();
            _client = null;
        }
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        DataReceived = null;
        StateChanged = null;
        InputSubmitted = null;
        await CloseClientAsync();
    }
}
