using Microsoft.Extensions.Logging;
using BoltShell.Core.Config;
using BoltShell.Core.Passbolt;
using BoltShell.Core.Rdp;
using BoltShell.Core.Ssh;

namespace BoltShell.Core.Accounts;

/// <summary>
/// Runtime state of one Passbolt account: locked/unlocked, and the resource list.
/// The resource metadata (names, hosts) stays visible after locking; secrets need an unlock.
/// </summary>
public sealed class AccountSession : IDisposable
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly Func<HttpMessageHandler>? _handlerFactory;
    private PassboltClient? _client;

    internal AccountSession(AccountConfig config, ILoggerFactory loggerFactory, Func<HttpMessageHandler>? handlerFactory)
    {
        Config = config;
        _loggerFactory = loggerFactory;
        _handlerFactory = handlerFactory;
    }

    public AccountConfig Config { get; internal set; }
    public string Id => Config.Id;
    public bool IsUnlocked => _client?.IsAuthenticated == true && !MfaPending;
    public bool MfaPending { get; private set; }
    public DateTimeOffset LastActivity { get; private set; }

    public IReadOnlyList<PassboltResource> Resources { get; private set; } = [];
    public IReadOnlyDictionary<string, PassboltFolder> Folders { get; private set; } = new Dictionary<string, PassboltFolder>();

    /// <summary>Resources that are hosts: an <c>ssh://</c> or <c>rdp://</c> URI.</summary>
    public IEnumerable<PassboltResource> Hosts =>
        Resources.Where(r => SshConnectionMapper.HasSshTarget(r) || RdpConnectionMapper.HasRdpTarget(r));

    public event Action? Changed;

    /// <summary>Raised when the server key was pinned on first login, so the config must be saved.</summary>
    internal event Action<AccountSession>? ConfigChanged;

    public async Task<LoginResult> UnlockAsync(string passphrase, CancellationToken ct = default)
    {
        _client?.Dispose();
        _client = new PassboltClient(Config.Account, _handlerFactory?.Invoke(), _loggerFactory.CreateLogger<PassboltClient>());
        LoginResult result;
        try
        {
            result = await _client.LoginAsync(passphrase, ct);
        }
        catch
        {
            _client.Dispose();
            _client = null;
            throw;
        }

        if (Config.Account.ServerFingerprint is null && _client.ServerFingerprint is { } fingerprint)
        {
            Config = Config with { Account = Config.Account with { ServerFingerprint = fingerprint } };
            ConfigChanged?.Invoke(this);
        }

        MfaPending = result.MfaRequired;
        Touch();
        if (!MfaPending)
            await RefreshAsync(ct);
        Changed?.Invoke();
        return result;
    }

    public async Task VerifyTotpAsync(string code, CancellationToken ct = default)
    {
        await RequireClient().VerifyTotpAsync(code, ct);
        MfaPending = false;
        await RefreshAsync(ct);
        Changed?.Invoke();
    }

    /// <summary>Reloads folders and resources from the server.</summary>
    public async Task RefreshAsync(CancellationToken ct = default)
    {
        var client = RequireUnlockedClient();
        var folders = await client.GetFoldersAsync(ct);
        var resources = await client.GetResourcesAsync(ct);
        Folders = folders.ToDictionary(f => f.Id);
        Resources = resources.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList();
        Touch();
        Changed?.Invoke();
    }

    /// <summary>Decrypts the resource's secret and turns it into SSH connection parameters.</summary>
    public async Task<SshConnectionSpec> GetConnectionSpecAsync(PassboltResource resource, CancellationToken ct = default)
    {
        var secret = await RequireUnlockedClient().GetSecretAsync(resource, ct);
        Touch();
        return SshConnectionMapper.Map(resource, secret);
    }

    /// <summary>Creates a resource (in a folder, shared like the folder) and reloads the resource list.</summary>
    /// <returns>The new resource id and a warning if sharing failed.</returns>
    public async Task<(string Id, string? Warning)> CreateResourceAsync(NewResource resource, CancellationToken ct = default)
    {
        var result = await RequireUnlockedClient().CreateResourceAsync(resource, ct);
        Touch();
        await RefreshAsync(ct);
        return result;
    }

    /// <summary>Adds or replaces a text custom field of a resource (e.g. the host identity) and reloads the resource list.</summary>
    public async Task SetCustomFieldAsync(PassboltResource resource, string key, string value, CancellationToken ct = default)
    {
        await RequireUnlockedClient().SetCustomFieldAsync(resource.Id, key, value, ct);
        Touch();
        await RefreshAsync(ct);
    }

    /// <summary>Decrypts the resource's secret and turns it into RDP connection parameters.</summary>
    public async Task<RdpConnectionSpec> GetRdpSpecAsync(PassboltResource resource, CancellationToken ct = default)
    {
        var secret = await RequireUnlockedClient().GetSecretAsync(resource, ct);
        Touch();
        return RdpConnectionMapper.Map(resource, secret);
    }

    /// <summary>Folder path like "Server / Odoo", or empty for the root.</summary>
    public string FolderPath(string? folderId)
    {
        var parts = new List<string>();
        var seen = new HashSet<string>();
        while (folderId is not null && seen.Add(folderId) && Folders.TryGetValue(folderId, out var folder))
        {
            parts.Insert(0, folder.Name);
            folderId = folder.FolderParentId;
        }
        return string.Join(" / ", parts);
    }

    /// <summary>Forgets the unlocked key and tokens. Open SSH sessions are not affected.</summary>
    public void Lock()
    {
        if (_client is { } client)
        {
            _ = client.LogoutAsync().ContinueWith(_ => client.Dispose(), TaskScheduler.Default);
            _client = null;
        }
        MfaPending = false;
        Changed?.Invoke();
    }

    internal void Touch() => LastActivity = DateTimeOffset.UtcNow;

    internal bool ShouldAutoLock(DateTimeOffset now) =>
        _client is not null && Config.AutoLockMinutes > 0 && now - LastActivity >= TimeSpan.FromMinutes(Config.AutoLockMinutes);

    internal void SetLastActivityForTest(DateTimeOffset value) => LastActivity = value;

    private PassboltClient RequireClient() => _client ?? throw new InvalidOperationException($"Account '{Config.DisplayName}' is locked.");

    private PassboltClient RequireUnlockedClient() =>
        IsUnlocked ? _client! : throw new InvalidOperationException($"Account '{Config.DisplayName}' is locked.");

    public void Dispose() => _client?.Dispose();
}
