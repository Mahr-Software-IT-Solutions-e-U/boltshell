using System.Text.RegularExpressions;
using BoltShell.Core.Rdp;
using BoltShell.Core.Ssh;
using BoltShell.Core.Transfer;
using static BoltShell.Core.Localization.Texts;

namespace BoltShell.App.Services;

/// <summary>
/// One open session tab: either an SSH terminal (plus an SFTP panel opened on demand over its own connection)
/// or an RDP desktop.
/// </summary>
public sealed partial class SessionTab
{
    public required string Title { get; init; }

    /// <summary>Passbolt account the credentials came from; null for a manual quick connection.</summary>
    public string? AccountId { get; init; }
    public string? ResourceId { get; init; }

    /// <summary>The URI of the resource this tab connects to (a resource can hold several hosts); null for its first one.</summary>
    public string? HostUri { get; init; }

    /// <summary>True if this tab belongs to the given host of a resource.</summary>
    public bool Is(string accountId, string resourceId, string? hostUri) =>
        AccountId == accountId && ResourceId == resourceId && (HostUri is null || hostUri is null || HostUri == hostUri);

    // SSH
    public SshConnectionSpec? Spec { get; internal set; }
    public SshTerminalSession? Terminal { get; init; }

    // RDP
    public RdpProxySession? Rdp { get; internal set; }

    /// <summary>
    /// True after the Passbolt account was locked: the tab's credentials were dropped. Open connections keep running,
    /// but every new connection (duplicate, reconnect, SFTP) first needs an unlock and freshly decrypted credentials.
    /// </summary>
    public bool CredentialsCleared { get; internal set; }
    public SessionState RdpState { get; set; } = SessionState.Created;

    /// <summary>The user hid the "host identity not in Passbolt" notice for this tab.</summary>
    public bool HostIdentityDismissed { get; set; }
    public (int Width, int Height)? RdpDesktopSize { get; set; }

    public bool IsRdp => Rdp is not null;
    public Guid Id { get; } = Guid.NewGuid();
    public SessionState State => Terminal?.State ?? RdpState;
    public string HostAndPort => Rdp?.Spec.Target.HostAndPort ?? Spec!.Target.HostAndPort;
    public string Username => Rdp is { } r ? (r.Spec.Domain is { } d ? $"{d}\\{r.Spec.Username}" : r.Spec.Username) : Spec!.Username;
    public object TargetKey => (object?)Rdp?.Spec.Target ?? Spec!.Target;
    public SftpSession? Sftp { get; set; }
    public bool SftpVisible { get; set; }
    public bool FollowTerminal { get; set; } = true;

    /// <summary>Working directory reported by the shell via the window title ("user@host: /path"), if any.</summary>
    public string? TerminalDirectory { get; private set; }

    public string AuthLabel =>
        IsRdp ? Tr("NLA, password from Passbolt")
              : Spec!.Credentials.HasPrivateKey
                  ? (AccountId is null ? Tr("Public key (manual)") : Tr("Public key from Passbolt"))
                  : (AccountId is null ? Tr("Password (manual)") : Tr("Password from Passbolt"));

    [GeneratedRegex(@"^[^@\s]+@[^:\s]+:\s*(?<dir>\S.*)$")]
    private static partial Regex ShellTitle();

    /// <summary>Updates <see cref="TerminalDirectory"/> from a terminal title; returns true if it changed.</summary>
    public bool UpdateFromTitle(string title)
    {
        var match = ShellTitle().Match(title.Trim());
        if (!match.Success)
            return false;
        var directory = match.Groups["dir"].Value.Trim();
        if (directory == TerminalDirectory)
            return false;
        TerminalDirectory = directory;
        return true;
    }
}

/// <summary>Open tabs. A singleton so sessions survive navigating to other pages.</summary>
public sealed class WorkspaceState
{
    private readonly List<SessionTab> _tabs = [];

    public IReadOnlyList<SessionTab> Tabs => _tabs;
    public SessionTab? Active { get; private set; }

    public event Action? Changed;

    /// <summary>Opens a new RDP tab and makes it active. The tab connects when it is rendered.</summary>
    public SessionTab OpenRdp(RdpProxy proxy, RdpConnectionSpec spec, string? accountId, string? resourceId, string? hostUri = null)
    {
        var count = _tabs.Count(t => Equals(t.TargetKey, spec.Target));
        var tab = new SessionTab
        {
            Title = spec.DisplayName + (count > 0 ? $" ({count + 1})" : ""),
            Rdp = proxy.Register(spec),
            AccountId = accountId,
            ResourceId = resourceId,
            HostUri = hostUri,
        };
        _tabs.Add(tab);
        Active = tab;
        Notify();
        return tab;
    }

    /// <summary>Opens a new terminal tab for <paramref name="spec"/> and makes it active.</summary>
    public SessionTab Open(SessionManager sessions, SshConnectionSpec spec, string? accountId, string? resourceId, string? hostUri = null)
    {
        var count = _tabs.Count(t => Equals(t.TargetKey, spec.Target));
        var tab = new SessionTab
        {
            Title = spec.DisplayName + (count > 0 ? $" ({count + 1})" : ""),
            Spec = spec,
            Terminal = sessions.CreateTerminal(spec),
            AccountId = accountId,
            ResourceId = resourceId,
            HostUri = hostUri,
        };
        tab.Terminal.StateChanged += _ => Notify();
        _tabs.Add(tab);
        Active = tab;
        Notify();
        return tab;
    }

    public void Activate(SessionTab tab)
    {
        Active = tab;
        Notify();
    }

    /// <summary>Drops cached credentials of all tabs that belong to <paramref name="accountId"/> (account was locked).</summary>
    public void ClearCredentials(string accountId, RdpProxy proxy)
    {
        var empty = new SshCredentials(null, null, null);
        foreach (var tab in _tabs.Where(t => t.AccountId == accountId && !t.CredentialsCleared))
        {
            if (tab.Spec is { } spec)
            {
                tab.Spec = spec with { Credentials = empty };
                tab.Terminal?.UpdateCredentials(empty);
                tab.Sftp?.UpdateCredentials(empty);
            }
            if (tab.Rdp is { } rdp)
                tab.Rdp = proxy.Update(rdp, rdp.Spec with { Password = null });
            tab.CredentialsCleared = true;
        }
    }

    /// <summary>Puts freshly decrypted credentials back into a tab after the account was unlocked again.</summary>
    public void RestoreCredentials(SessionTab tab, SshConnectionSpec? spec, RdpConnectionSpec? rdpSpec, RdpProxy proxy)
    {
        if (spec is not null && tab.Spec is not null)
        {
            tab.Spec = tab.Spec with { Credentials = spec.Credentials, HostKeys = spec.HostKeys };
            tab.Terminal?.UpdateCredentials(spec.Credentials);
            tab.Sftp?.UpdateCredentials(spec.Credentials);
        }
        if (rdpSpec is not null && tab.Rdp is { } rdp)
            tab.Rdp = proxy.Update(rdp, rdpSpec);
        tab.CredentialsCleared = false;
    }

    /// <summary>
    /// Applies a host identity just stored in Passbolt to all tabs of that host (used from their next connect on).
    /// </summary>
    public void UpdateHostIdentity(string accountId, string resourceId, string? hostUri, IReadOnlyList<ExpectedHostKey>? hostKeys,
        IReadOnlyList<string>? certificateFingerprints, RdpProxy proxy)
    {
        foreach (var tab in _tabs.Where(t => t.Is(accountId, resourceId, hostUri)))
        {
            if (hostKeys is not null && tab.Spec is { } spec)
            {
                tab.Spec = spec with { HostKeys = hostKeys };
                tab.Terminal?.UpdateHostKeys(hostKeys);
                tab.Sftp?.UpdateHostKeys(hostKeys);
            }
            if (certificateFingerprints is not null && tab.Rdp is { } rdp)
                tab.Rdp = proxy.Update(rdp, rdp.Spec with { CertificateFingerprints = certificateFingerprints });
            tab.HostIdentityDismissed = false;
        }
        Notify();
    }

    public void Remove(SessionTab tab)
    {
        var index = _tabs.IndexOf(tab);
        if (index < 0)
            return;
        _tabs.RemoveAt(index);
        if (Active == tab)
            Active = _tabs.Count == 0 ? null : _tabs[Math.Min(index, _tabs.Count - 1)];
        Notify();
    }

    public void Notify() => Changed?.Invoke();
}
