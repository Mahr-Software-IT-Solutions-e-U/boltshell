using Microsoft.Extensions.Logging.Abstractions;
using BoltShell.Core.Accounts;
using BoltShell.Core.Config;
using BoltShell.Core.Crypto;

namespace BoltShell.Core.Tests;

public sealed class AccountManagerTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "pbssh-acc-" + Guid.NewGuid().ToString("N")[..8]);

    [Fact]
    public void Accounts_ArePersistedAndReloaded()
    {
        using (var manager = Create())
        {
            manager.Add("Intern", PassboltClientTests.Account(), autoLockMinutes: 5);
            Assert.Throws<InvalidOperationException>(() => manager.Add("Again", PassboltClientTests.Account()));
        }

        using var reloaded = Create();
        var account = Assert.Single(reloaded.Accounts);
        Assert.Equal("Intern", account.Config.DisplayName);
        Assert.Equal(5, account.Config.AutoLockMinutes);
        Assert.False(account.IsUnlocked);

        reloaded.Remove(account.Id);
        Assert.Empty(Create().Accounts);
    }

    [Fact]
    public async Task Unlock_LoadsHosts_PinsServerKey_AndAutoLocks()
    {
        using var manager = Create();
        var account = manager.Add("Intern", PassboltClientTests.Account(), autoLockMinutes: 15);
        var changes = 0;
        manager.Changed += () => changes++;

        await account.UnlockAsync(TestKeys.UserPassphrase);

        Assert.True(account.IsUnlocked);
        Assert.Equal(["legacy", "modern"], account.Resources.Select(r => r.Name));
        Assert.Equal(["legacy"], account.Hosts.Select(h => h.Resource.Name)); // only ssh:// URIs
        Assert.True(changes > 0);

        // The server key fingerprint is pinned and persisted on first unlock.
        var expected = PgpPublicKeys.Parse(TestKeys.Server.Public).Fingerprint;
        Assert.Equal(expected, account.Config.Account.ServerFingerprint);
        Assert.Equal(expected, new SettingsStore(_dir).Current.Accounts.Single().Account.ServerFingerprint);

        manager.AutoLock(DateTimeOffset.UtcNow.AddMinutes(14));
        Assert.True(account.IsUnlocked);
        manager.AutoLock(DateTimeOffset.UtcNow.AddMinutes(16));
        Assert.False(account.IsUnlocked);

        // Metadata stays visible while locked; secrets need an unlock.
        Assert.Single(account.Hosts);
        await Assert.ThrowsAsync<InvalidOperationException>(() => account.GetConnectionSpecAsync(account.Hosts.Single().Resource));
    }

    [Fact]
    public async Task AutoLockZero_NeverLocks()
    {
        using var manager = Create();
        var account = manager.Add("Intern", PassboltClientTests.Account(), autoLockMinutes: 0);
        await account.UnlockAsync(TestKeys.UserPassphrase);
        manager.AutoLock(DateTimeOffset.UtcNow.AddDays(1));
        Assert.True(account.IsUnlocked);
    }

    [Fact]
    public async Task WrongPassphrase_StaysLocked()
    {
        using var manager = Create();
        var account = manager.Add("Intern", PassboltClientTests.Account());
        await Assert.ThrowsAnyAsync<Exception>(() => account.UnlockAsync("wrong"));
        Assert.False(account.IsUnlocked);
    }

    private AccountManager Create() =>
        new(new SettingsStore(_dir), NullLoggerFactory.Instance, () => new PassboltClientTests.FakePassboltServer());

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }
}

public sealed class SettingsMigrationTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "boltshell-mig-" + Guid.NewGuid().ToString("N")[..8]);

    [Fact]
    public void LegacyFolder_IsMovedOnce()
    {
        var legacy = Path.Combine(_root, LegacyName);
        var current = Path.Combine(_root, "BoltShell");
        Directory.CreateDirectory(legacy);
        File.WriteAllText(Path.Combine(legacy, "settings.json"), "{}");

        BoltShell.Core.Config.SettingsStore.MigrateLegacyDirectory(legacy, current);
        Assert.True(File.Exists(Path.Combine(current, "settings.json")));
        Assert.False(Directory.Exists(legacy));

        // A later legacy folder (old version started again) never overwrites the current data.
        Directory.CreateDirectory(legacy);
        BoltShell.Core.Config.SettingsStore.MigrateLegacyDirectory(legacy, current);
        Assert.True(Directory.Exists(legacy));
    }

    private const string LegacyName = BoltShell.Core.Config.SettingsStore.LegacyDirectoryName;

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }
}
