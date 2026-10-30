namespace BoltShell.Core.Ssh;

/// <summary>Host, port and optional user parsed from a Passbolt URI field.</summary>
public sealed record SshTarget(string Host, int Port = 22, string? Username = null)
{
    public override string ToString() => (Username is null ? "" : Username + "@") + HostAndPort;

    public string HostAndPort => (Host.Contains(':') ? $"[{Host}]" : Host) + (Port == 22 ? "" : $":{Port}");

    /// <summary>Key used for host key pinning ("host:port").</summary>
    public string HostKeyId => $"{Host.ToLowerInvariant()}:{Port}";

    private const string Scheme = "ssh://";

    /// <summary>
    /// Accepts only <c>ssh://</c> URIs: <c>ssh://host</c>, <c>ssh://user@host:port</c>, <c>ssh://[::1]:22</c>.
    /// The explicit scheme is the convention that marks a Passbolt resource as an SSH host,
    /// so web logins (<c>https://…</c> or bare hostnames) never show up.
    /// </summary>
    public static bool TryParse(string? value, out SshTarget target)
    {
        target = null!;
        var input = value?.Trim();
        if (input is null || !input.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
            return false;
        input = input[Scheme.Length..];

        // Strip path / query.
        var pathStart = input.IndexOfAny(['/', '?', '#']);
        if (pathStart >= 0)
            input = input[..pathStart];

        string? user = null;
        var at = input.LastIndexOf('@');
        if (at >= 0)
        {
            user = Uri.UnescapeDataString(input[..at]);
            var colon = user.IndexOf(':'); // ssh://user:password@host – drop the password part
            if (colon >= 0)
                user = user[..colon];
            if (user.Length == 0)
                user = null;
            input = input[(at + 1)..];
        }

        string host;
        var port = 22;
        if (input.StartsWith('['))
        {
            var close = input.IndexOf(']');
            if (close < 0)
                return false;
            host = input[1..close];
            var rest = input[(close + 1)..];
            if (rest.StartsWith(':') && !TryParsePort(rest[1..], out port))
                return false;
        }
        else if (input.Count(c => c == ':') == 1)
        {
            var colon = input.IndexOf(':');
            host = input[..colon];
            if (!TryParsePort(input[(colon + 1)..], out port))
                return false;
        }
        else
        {
            host = input; // plain host or bare IPv6 address
        }

        if (host.Length == 0 || host.Any(char.IsWhiteSpace))
            return false;

        target = new SshTarget(host, port, user);
        return true;
    }

    /// <summary>
    /// Parses user input for a quick connection: <c>user@host:port</c>, <c>host</c> or a full <c>ssh://</c> URI.
    /// Unlike Passbolt URIs, the scheme is optional here because the user explicitly asks for SSH.
    /// </summary>
    public static bool TryParseQuick(string? value, out SshTarget target)
    {
        target = null!;
        var input = value?.Trim();
        if (string.IsNullOrEmpty(input) || input.Contains("://") && !input.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
            return false;
        return TryParse(input.Contains("://") ? input : Scheme + input, out target);
    }

    private static bool TryParsePort(string text, out int port) =>
        int.TryParse(text, out port) && port is > 0 and <= 65535;
}
