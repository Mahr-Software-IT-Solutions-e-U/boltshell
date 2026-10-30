using System.Text.RegularExpressions;
using BoltShell.Core.Rdp;
using BoltShell.Core.Ssh;
using BoltShell.Core.Transfer;

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

    // SSH
    public SshConnectionSpec? Spec { get; init; }
    public SshTerminalSession? Terminal { get; init; }

    // RDP
    public RdpProxySession? Rdp { get; init; }
    public SessionState RdpState { get; set; } = SessionState.Created;
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
        IsRdp ? "NLA, Passwort aus Passbolt"
              : (Spec!.Credentials.HasPrivateKey ? "Public Key" : "Passwort") + (AccountId is null ? " (manuell)" : " aus Passbolt");

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
    public SessionTab OpenRdp(RdpProxy proxy, RdpConnectionSpec spec, string? accountId, string? resourceId)
    {
        var count = _tabs.Count(t => Equals(t.TargetKey, spec.Target));
        var tab = new SessionTab
        {
            Title = spec.DisplayName + (count > 0 ? $" ({count + 1})" : ""),
            Rdp = proxy.Register(spec),
            AccountId = accountId,
            ResourceId = resourceId,
        };
        _tabs.Add(tab);
        Active = tab;
        Notify();
        return tab;
    }

    /// <summary>Opens a new terminal tab for <paramref name="spec"/> and makes it active.</summary>
    public SessionTab Open(SessionManager sessions, SshConnectionSpec spec, string? accountId, string? resourceId)
    {
        var count = _tabs.Count(t => Equals(t.TargetKey, spec.Target));
        var tab = new SessionTab
        {
            Title = spec.DisplayName + (count > 0 ? $" ({count + 1})" : ""),
            Spec = spec,
            Terminal = sessions.CreateTerminal(spec),
            AccountId = accountId,
            ResourceId = resourceId,
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
