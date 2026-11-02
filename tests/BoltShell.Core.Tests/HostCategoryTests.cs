using BoltShell.Core.Accounts;
using BoltShell.Core.Config;
using Microsoft.Extensions.Logging.Abstractions;
using BoltShell.Core.Passbolt;

namespace BoltShell.Core.Tests;

/// <summary>Host list categories: Passbolt folder tree and personal groups.</summary>
public sealed class HostCategoryTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "boltshell-groups-" + Guid.NewGuid().ToString("N")[..8]);

    private static PassboltResource Res(string id, string name, string? folder, params string[] uris) =>
        new(id, name, "root", uris, null, null, folder, null, []);

    private static readonly Dictionary<string, PassboltFolder> Folders = new()
    {
        ["srv"] = new("srv", "Server", null),
        ["odoo"] = new("odoo", "Odoo", "srv"),
        ["empty"] = new("empty", "Empty", "srv"),
        ["web"] = new("web", "Web", null),
    };

    [Fact]
    public void Tree_FollowsPassboltFolders_SortedAndPruned()
    {
        var hosts = new[]
        {
            Res("1", "zeta", null, "ssh://zeta"),
            Res("2", "odoo-02", "odoo", "ssh://odoo-02"),
            Res("3", "odoo-01", "odoo", "ssh://odoo-01"),
            Res("4", "backup", "srv", "ssh://backup"),
            Res("5", "alpha", "hidden-folder", "rdp://alpha"), // folder not visible to the user: root
        }.SelectMany(HostEntry.For);

        var root = HostTree.Build(Folders, hosts);

        Assert.Equal(["alpha", "zeta"], root.Hosts.Select(h => h.Resource.Name));
        var server = Assert.Single(root.Folders); // "Web" and "Empty" hold no hosts
        Assert.Equal(("Server", 3), (server.Name, server.Count));
        Assert.Equal(["backup"], server.Hosts.Select(h => h.Resource.Name));
        var odoo = Assert.Single(server.Folders);
        Assert.Equal(["odoo-01", "odoo-02"], odoo.Hosts.Select(h => h.Resource.Name));
        Assert.Equal(5, root.Count);
    }

    [Fact]
    public void Tree_SurvivesFolderCycles()
    {
        var folders = new Dictionary<string, PassboltFolder> { ["a"] = new("a", "A", "b"), ["b"] = new("b", "B", "a") };
        var root = HostTree.Build(folders, HostEntry.For(Res("1", "h", "a", "ssh://h")));
        Assert.Equal(0, root.Count); // no visible path to the root: nothing shown, but no endless loop
    }

    private HostGroupStore Store(string dir, AccountManager? accounts = null) =>
        new(new SettingsStore(dir), accounts ?? new AccountManager(new SettingsStore(dir), NullLoggerFactory.Instance),
            NullLogger<HostGroupStore>.Instance) { SaveDelay = TimeSpan.FromMinutes(10) };

    [Fact]
    public void Groups_ArePerAccount_MergedByName_AndPersisted()
    {
        var hosts = HostEntry.For(Res("r1", "cluster", null, "ssh://a", "ssh://b"));
        using var store = Store(_dir);

        store.Create(" Produktion ", "acc-1", hosts[0].Key);
        store.Create("produktion", "acc-2", hosts[1].Key); // same name in another account: one group
        store.ToggleMember("Produktion", "acc-1", hosts[1].Key);

        var group = Assert.Single(store.Groups);
        Assert.Equal("Produktion", group.Name);
        Assert.Equivalent(new[] { ("acc-1", hosts[0].Key), ("acc-2", hosts[1].Key), ("acc-1", hosts[1].Key) }, group.Members, strict: true);
        Assert.True(store.IsGrouped("acc-1", hosts[1].Key));
        Assert.False(store.IsGrouped("acc-2", hosts[0].Key));

        store.ToggleMember("Produktion", "acc-1", hosts[1].Key);
        Assert.False(store.IsMember("Produktion", "acc-1", hosts[1].Key));

        store.SetView(HostListView.Groups);
        store.ToggleCollapsed(HostGroupStore.GroupNode("Produktion"));
        using (var reloaded = Store(_dir))
        {
            Assert.Equal(HostListView.Groups, reloaded.View);
            Assert.Equal(2, Assert.Single(reloaded.Groups).Members.Count);
            Assert.True(reloaded.IsCollapsed(HostGroupStore.GroupNode("PRODUKTION")));

            reloaded.Rename("produktion", "Prod");
            Assert.Equal("Prod", Assert.Single(reloaded.Groups).Name);
            reloaded.Delete("prod");
            Assert.Empty(reloaded.Groups);
        }
    }

    [Fact]
    public void LegacyLocalGroups_AreMovedToTheirAccounts()
    {
        new SettingsStore(_dir).Update(s => s with
        {
            HostGroups = [new LegacyHostGroup("g1", "Web", ["acc-1\nr1\nssh://a", "acc-2\nr9\nssh://z"])],
        });
        using var store = Store(_dir);

        var group = Assert.Single(store.Groups);
        Assert.Equal([("acc-1", "r1\nssh://a"), ("acc-2", "r9\nssh://z")], group.Members);
        Assert.Empty(new SettingsStore(_dir).Current.HostGroups);
    }

    [Fact]
    public async Task Groups_SyncThroughAPrivatePassboltResource_BetweenDevices()
    {
        var server = new PassboltClientTests.FakePassboltServer();
        AccountManager Device(string dir, out AccountSession account)
        {
            var manager = new AccountManager(new SettingsStore(dir), NullLoggerFactory.Instance, () => server);
            account = manager.Add("Intern", PassboltClientTests.Account());
            return manager;
        }
        var dirB = _dir + "-b";
        try
        {
            using var managerA = Device(_dir, out var accountA);
            using var managerB = Device(dirB, out var accountB);
            using var storeA = Store(_dir, managerA);
            using var storeB = Store(dirB, managerB);

            // Device A: group while unlocked -> stored in a new private resource (not a host, not shared).
            await accountA.UnlockAsync(TestKeys.UserPassphrase);
            var host = Assert.Single(accountA.Hosts);
            storeA.Create("Produktion", accountA.Id, host.Key);
            await storeA.SyncAsync(accountA);
            var created = Assert.Single(server.Created);
            Assert.Null(created["folder_parent_id"]?.GetValue<string>());
            Assert.Null(server.LastShare);
            Assert.NotNull(accountA.PrivateSettings);
            Assert.DoesNotContain(accountA.Hosts, h => h.Resource.Id == accountA.PrivateSettings!.Id);

            // Device B: unlocking brings the groups over.
            await accountB.UnlockAsync(TestKeys.UserPassphrase);
            await storeB.SyncAsync(accountB);
            Assert.True(storeB.IsMember("Produktion", accountB.Id, host.Key));

            // B renames; A sees it after its next refresh (the newer copy wins).
            storeB.Rename("Produktion", "Prod");
            await storeB.SyncAsync(accountB);
            Assert.Single(server.Updates);
            await accountA.RefreshAsync();
            await storeA.SyncAsync(accountA);
            Assert.Equal("Prod", Assert.Single(storeA.Groups).Name);
            Assert.Empty(storeA.SyncErrors);
        }
        finally
        {
            if (Directory.Exists(dirB))
                Directory.Delete(dirB, recursive: true);
        }
    }

    [Fact]
    public void RemoteDocument_RoundTrips_AndIgnoresGarbage()
    {
        var doc = new HostGroupDocument { Updated = DateTimeOffset.UtcNow, Groups = [new HostGroupEntry("Web", ["r1\nssh://a"])] };
        var parsed = HostGroupStore.Parse(HostGroupStore.Serialize(doc))!;
        Assert.Equal(doc.Updated, parsed.Updated);
        Assert.Equal(["r1\nssh://a"], Assert.Single(parsed.Groups).Members);
        Assert.Null(HostGroupStore.Parse("not json"));
        Assert.Null(HostGroupStore.Parse(""));
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }
}
