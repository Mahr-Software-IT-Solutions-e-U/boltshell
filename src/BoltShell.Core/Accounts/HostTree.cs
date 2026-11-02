using BoltShell.Core.Passbolt;

namespace BoltShell.Core.Accounts;

/// <summary>A Passbolt folder with the hosts in it; the root node has no id.</summary>
public sealed record HostFolderNode(string? Id, string Name, IReadOnlyList<HostFolderNode> Folders, IReadOnlyList<HostEntry> Hosts)
{
    /// <summary>Hosts in this folder and all subfolders.</summary>
    public int Count => Hosts.Count + Folders.Sum(f => f.Count);
}

/// <summary>Arranges hosts in their Passbolt folder structure.</summary>
public static class HostTree
{
    /// <summary>
    /// Builds the folder tree. Only folders that (directly or below) contain hosts are kept; folders and hosts
    /// whose parent is not visible to the user are placed at the root. Sorted by name.
    /// </summary>
    public static HostFolderNode Build(IReadOnlyDictionary<string, PassboltFolder> folders, IEnumerable<HostEntry> hosts)
    {
        string? Parent(string? folderId) => folderId is not null && folders.ContainsKey(folderId) ? folderId : null;

        var hostsByFolder = hosts.ToLookup(h => Parent(h.Resource.FolderParentId));
        var foldersByParent = folders.Values.ToLookup(f => Parent(f.FolderParentId));
        var visited = new HashSet<string>();

        HostFolderNode Node(string? id, string name)
        {
            var children = foldersByParent[id]
                .Where(f => visited.Add(f.Id)) // guards against cycles in broken data
                .Select(f => Node(f.Id, f.Name))
                .Where(n => n.Count > 0)
                .OrderBy(n => n.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var own = hostsByFolder[id].OrderBy(h => h.DisplayName, StringComparer.OrdinalIgnoreCase).ThenBy(h => h.Uri).ToList();
            return new HostFolderNode(id, name, children, own);
        }

        return Node(null, "");
    }
}
