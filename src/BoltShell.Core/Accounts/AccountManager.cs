using Microsoft.Extensions.Logging;
using BoltShell.Core.Config;
using static BoltShell.Core.Localization.Texts;

namespace BoltShell.Core.Accounts;

/// <summary>All configured Passbolt accounts, persisted in <see cref="SettingsStore"/>, with inactivity auto-lock.</summary>
public sealed class AccountManager : IDisposable
{
    private readonly SettingsStore _settings;
    private readonly ILoggerFactory _loggerFactory;
    private readonly Func<HttpMessageHandler>? _handlerFactory;
    private readonly List<AccountSession> _accounts = [];
    private readonly Timer _autoLockTimer;

    public AccountManager(SettingsStore settings, ILoggerFactory loggerFactory)
        : this(settings, loggerFactory, null)
    {
    }

    internal AccountManager(SettingsStore settings, ILoggerFactory loggerFactory, Func<HttpMessageHandler>? handlerFactory)
    {
        _settings = settings;
        _loggerFactory = loggerFactory;
        _handlerFactory = handlerFactory;
        foreach (var config in settings.Current.Accounts)
            _accounts.Add(CreateSession(config));
        _autoLockTimer = new Timer(_ => AutoLock(DateTimeOffset.UtcNow), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    public IReadOnlyList<AccountSession> Accounts
    {
        get { lock (_accounts) return _accounts.ToList(); }
    }

    public int LockedCount => Accounts.Count(a => !a.IsUnlocked);

    /// <summary>Raised when accounts are added, removed, locked, unlocked or refreshed.</summary>
    public event Action? Changed;

    public AccountSession? Find(string id) => Accounts.FirstOrDefault(a => a.Id == id);

    public AccountSession Add(string displayName, Passbolt.PassboltAccount account, int autoLockMinutes = 15)
    {
        Passbolt.PassboltAccount.ValidateServerUrl(account.BaseUrl);
        if (Accounts.Any(a => a.Config.Account.BaseUrl.Equals(account.BaseUrl, StringComparison.OrdinalIgnoreCase)
                              && a.Config.Account.UserId == account.UserId))
            throw new InvalidOperationException(Tr("This Passbolt account is already configured."));

        var config = new AccountConfig
        {
            Id = Guid.NewGuid().ToString("N"),
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? new Uri(account.BaseUrl).Host : displayName.Trim(),
            Account = account,
            AutoLockMinutes = autoLockMinutes,
        };
        var session = CreateSession(config);
        lock (_accounts)
            _accounts.Add(session);
        Save();
        Changed?.Invoke();
        return session;
    }

    public void Update(string id, Func<AccountConfig, AccountConfig> change)
    {
        var session = Find(id) ?? throw new KeyNotFoundException(id);
        session.Config = change(session.Config) with { Id = id };
        Save();
        Changed?.Invoke();
    }

    public void Remove(string id)
    {
        AccountSession? session;
        lock (_accounts)
        {
            session = _accounts.FirstOrDefault(a => a.Id == id);
            if (session is null)
                return;
            _accounts.Remove(session);
        }
        session.Lock();
        session.Dispose();
        Save();
        Changed?.Invoke();
    }

    public void LockAll()
    {
        foreach (var account in Accounts)
            account.Lock();
    }

    internal void AutoLock(DateTimeOffset now)
    {
        foreach (var account in Accounts.Where(a => a.ShouldAutoLock(now)))
            account.Lock();
    }

    private AccountSession CreateSession(AccountConfig config)
    {
        var session = new AccountSession(config, _loggerFactory, _handlerFactory);
        session.Changed += () => Changed?.Invoke();
        session.ConfigChanged += _ => Save();
        return session;
    }

    private void Save()
    {
        var configs = Accounts.Select(a => a.Config).ToList();
        _settings.Update(s => s with { Accounts = configs });
    }

    public void Dispose()
    {
        _autoLockTimer.Dispose();
        foreach (var account in Accounts)
            account.Dispose();
    }
}
