using BoltShell.Core.Accounts;
using BoltShell.Core.Config;
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

    [Fact]
    public void Groups_ArePersonalAndPersisted()
    {
        var host = HostEntry.For(Res("r1", "cluster", null, "ssh://a", "ssh://b"))[1];
        var key = HostGroupStore.MemberKey("acc-1", host);
        var store = new HostGroupStore(new SettingsStore(_dir));
        var changes = 0;
        store.Changed += () => changes++;

        var group = store.Create("  Produktion ", key);
        store.ToggleCollapsed(HostGroupStore.GroupNode(group.Id));
        store.ToggleCollapsed(HostGroupStore.FolderNode("acc-1", "srv"));

        // A new store reads the same settings file.
        var reloaded = new HostGroupStore(new SettingsStore(_dir));
        var saved = Assert.Single(reloaded.Groups);
        Assert.Equal(("Produktion", key), (saved.Name, Assert.Single(saved.Members)));
        Assert.True(reloaded.IsCollapsed(HostGroupStore.GroupNode(group.Id)));
        Assert.True(reloaded.IsCollapsed(HostGroupStore.FolderNode("acc-1", "srv")));

        reloaded.ToggleMember(group.Id, key);
        Assert.Empty(reloaded.Groups[0].Members);
        reloaded.ToggleMember(group.Id, key);
        reloaded.Rename(group.Id, "Prod");
        Assert.Equal(("Prod", 1), (reloaded.Groups[0].Name, reloaded.Groups[0].Members.Count));

        reloaded.Delete(group.Id);
        Assert.Empty(reloaded.Groups);
        Assert.False(reloaded.IsCollapsed(HostGroupStore.GroupNode(group.Id)));
        Assert.Equal(3, changes);
    }

    [Fact]
    public void MemberKey_DistinguishesAccountsAndUris()
    {
        var hosts = HostEntry.For(Res("r1", "cluster", null, "ssh://a", "ssh://b"));
        Assert.Equal(4, new[] { "acc-1", "acc-2" }.SelectMany(a => hosts.Select(h => HostGroupStore.MemberKey(a, h))).Distinct().Count());
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }
}
