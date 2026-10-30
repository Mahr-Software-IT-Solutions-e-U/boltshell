using BoltShell.Core.Passbolt;
using BoltShell.Core.Rdp;
using BoltShell.Core.Ssh;

namespace BoltShell.Core.Accounts;

/// <summary>
/// One connectable host of a Passbolt resource. Every <c>ssh://</c> and <c>rdp://</c> URI of a resource is its own host
/// with the resource's credentials (e.g. a cluster sharing a key, or a Windows server reachable via RDP and SSH).
/// </summary>
/// <param name="SharedResource">True if the resource has more than one host URI.</param>
public sealed record HostEntry(PassboltResource Resource, string Uri, bool IsRdp, string Host, int Port, bool SharedResource)
{
    /// <summary>Unique within an account.</summary>
    public string Key => KeyFor(Resource.Id, Uri);

    /// <summary>The resource name, plus the host if the resource has several.</summary>
    public string DisplayName => SharedResource ? $"{Resource.Name} ({Host})" : Resource.Name;

    public static string KeyFor(string resourceId, string uri) => resourceId + "\n" + uri;

    /// <summary>The hosts of a resource, in URI order.</summary>
    public static IReadOnlyList<HostEntry> For(PassboltResource resource)
    {
        var entries = new List<(string Uri, bool IsRdp, string Host, int Port)>();
        foreach (var uri in resource.Uris)
        {
            if (SshTarget.TryParse(uri, out var ssh))
                entries.Add((uri, false, ssh.Host, ssh.Port));
            else if (RdpTarget.TryParse(uri, out var rdp))
                entries.Add((uri, true, rdp.Host, rdp.Port));
        }
        return entries.Select(e => new HostEntry(resource, e.Uri, e.IsRdp, e.Host, e.Port, entries.Count > 1)).ToList();
    }
}
