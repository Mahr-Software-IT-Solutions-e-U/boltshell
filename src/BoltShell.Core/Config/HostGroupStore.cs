using BoltShell.Core.Accounts;

namespace BoltShell.Core.Config;

/// <summary>
/// Personal host groups and the collapsed state of the host list, kept in the local settings
/// (never in Passbolt, so nothing changes for the team).
/// </summary>
public sealed class HostGroupStore(SettingsStore settings)
{
    public IReadOnlyList<HostGroup> Groups => settings.Current.HostGroups;

    public event Action? Changed;

    /// <summary>Identifies a host across accounts: account, resource and URI.</summary>
    public static string MemberKey(string accountId, HostEntry host) => accountId + "\n" + host.Key;

    public bool IsCollapsed(string node) => settings.Current.CollapsedSidebarNodes.Contains(node);

    public void ToggleCollapsed(string node) => Save(s =>
    {
        var collapsed = new HashSet<string>(s.CollapsedSidebarNodes);
        if (!collapsed.Remove(node))
            collapsed.Add(node);
        return s with { CollapsedSidebarNodes = collapsed };
    });

    public HostGroup Create(string name, string? firstMember = null)
    {
        var group = new HostGroup(Guid.NewGuid().ToString("N"), name.Trim(), firstMember is null ? [] : [firstMember]);
        Save(s => s with { HostGroups = [.. s.HostGroups, group] });
        return group;
    }

    public void Rename(string groupId, string name) =>
        Save(s => s with { HostGroups = s.HostGroups.Select(g => g.Id == groupId ? g with { Name = name.Trim() } : g).ToList() });

    public void Delete(string groupId) => Save(s => s with
    {
        HostGroups = s.HostGroups.Where(g => g.Id != groupId).ToList(),
        CollapsedSidebarNodes = s.CollapsedSidebarNodes.Where(n => n != GroupNode(groupId)).ToHashSet(),
    });

    /// <summary>Adds the host to the group, or removes it if it is already a member.</summary>
    public void ToggleMember(string groupId, string memberKey) => Save(s => s with
    {
        HostGroups = s.HostGroups.Select(g => g.Id != groupId ? g
            : g with { Members = g.Members.Contains(memberKey) ? g.Members.Where(m => m != memberKey).ToList() : [.. g.Members, memberKey] }).ToList(),
    });

    public static string GroupNode(string groupId) => "group:" + groupId;

    public static string FolderNode(string accountId, string folderId) => $"folder:{accountId}:{folderId}";

    private void Save(Func<AppSettings, AppSettings> change)
    {
        settings.Update(change);
        Changed?.Invoke();
    }
}
