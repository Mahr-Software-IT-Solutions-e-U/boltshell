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

    /// <summary>Own name of this host from the URI fragment (<c>ssh://10.0.0.11#node-1</c>), if any.</summary>
    public string? Label => LabelOf(Uri);

    /// <summary>See <see cref="Name"/>.</summary>
    public string DisplayName => Name(Resource.Name, Uri, Host, SharedResource);

    public static string KeyFor(string resourceId, string uri) => resourceId + "\n" + uri;

    /// <summary>
    /// "resource · label" if the URI has a fragment, otherwise "resource (host)" for a resource with several hosts,
    /// otherwise just the resource name.
    /// </summary>
    public static string Name(string resourceName, string? uri, string host, bool sharedResource) =>
        LabelOf(uri) is { } label ? $"{resourceName} · {label}"
        : sharedResource ? $"{resourceName} ({host})"
        : resourceName;

    /// <summary>The URI fragment as a label (unescaped, trimmed), or null.</summary>
    public static string? LabelOf(string? uri)
    {
        var hash = uri?.IndexOf('#') ?? -1;
        if (hash < 0)
            return null;
        var label = System.Uri.UnescapeDataString(uri![(hash + 1)..]).Trim();
        return label.Length > 0 ? label : null;
    }

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
