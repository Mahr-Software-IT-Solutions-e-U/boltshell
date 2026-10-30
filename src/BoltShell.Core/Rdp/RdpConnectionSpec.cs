using BoltShell.Core.Passbolt;
using BoltShell.Core.Ssh;
using static BoltShell.Core.Localization.Texts;

namespace BoltShell.Core.Rdp;

/// <summary>Host, port and optional user/domain from an <c>rdp://</c> URI.</summary>
public sealed record RdpTarget(string Host, int Port = 3389, string? Username = null, string? Domain = null)
{
    private const string Scheme = "rdp://";

    public string HostAndPort => (Host.Contains(':') ? $"[{Host}]" : Host) + (Port == 3389 ? "" : $":{Port}");

    /// <summary>"host:port" as sent to the proxy (always with port).</summary>
    public string Destination => (Host.Contains(':') ? $"[{Host}]" : Host) + ":" + Port;

    /// <summary>Key for certificate pinning.</summary>
    public string CertificateId => $"rdp:{Host.ToLowerInvariant()}:{Port}";

    /// <summary>
    /// Accepts <c>rdp://host</c>, <c>rdp://user@host:3390</c>, <c>rdp://DOMAIN\user@host</c> (also <c>%5C</c>) and IPv6 in brackets.
    /// </summary>
    public static bool TryParse(string? value, out RdpTarget target)
    {
        target = null!;
        var input = value?.Trim();
        if (input is null || !input.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
            return false;
        // Reuse the SSH URI parser for host/port/user, then apply RDP defaults.
        if (!SshTarget.TryParse("ssh://" + input[Scheme.Length..], out var parsed))
            return false;
        var port = parsed.Port == 22 && !HasExplicitPort(input) ? 3389 : parsed.Port;
        var (user, domain) = SplitUser(parsed.Username);
        target = new RdpTarget(parsed.Host, port, user, domain);
        return true;
    }

    /// <summary>Splits "DOMAIN\user" (or "user@domain" is left as is: Windows accepts UPNs as user names).</summary>
    public static (string? User, string? Domain) SplitUser(string? username)
    {
        if (string.IsNullOrEmpty(username))
            return (null, null);
        var backslash = username.IndexOf('\\');
        return backslash > 0 ? (username[(backslash + 1)..], username[..backslash]) : (username, null);
    }

    private static bool HasExplicitPort(string uri)
    {
        var authority = uri[Scheme.Length..].Split('/', '?', '#')[0];
        var at = authority.LastIndexOf('@');
        var hostPart = at >= 0 ? authority[(at + 1)..] : authority;
        return hostPart.StartsWith('[') ? hostPart.Contains("]:") : hostPart.Contains(':');
    }
}

/// <summary>Everything needed to open an RDP session.</summary>
/// <param name="CertificateFingerprints">Pinned server certificate SHA256 fingerprints from Passbolt (base64, no padding).</param>
public sealed record RdpConnectionSpec(
    string DisplayName,
    RdpTarget Target,
    string Username,
    string? Domain,
    string? Password,
    IReadOnlyList<string> CertificateFingerprints);

/// <summary>
/// Passbolt convention for RDP hosts: URI <c>rdp://[DOMAIN\]user@host[:port]</c>, password field = Windows password,
/// optional custom fields <c>rdp_domain</c> and <c>rdp_cert_sha256</c> (server certificate fingerprint, pins the identity).
/// </summary>
public static class RdpConnectionMapper
{
    public const string DomainField = "rdp_domain";
    public const string CertificateField = "rdp_cert_sha256";

    public static bool HasRdpTarget(PassboltResource resource) =>
        resource.Uris.Any(u => RdpTarget.TryParse(u, out _));

    /// <param name="uri">The <c>rdp://</c> URI to connect to (see <see cref="Accounts.HostEntry"/>); null for the first one.</param>
    public static RdpConnectionSpec Map(PassboltResource resource, PassboltSecret secret, string? uri = null)
    {
        uri ??= resource.Uris.FirstOrDefault(u => RdpTarget.TryParse(u, out _));
        var target = (uri is not null && resource.Uris.Contains(uri) && RdpTarget.TryParse(uri, out var chosen) ? chosen : null)
                     ?? throw new InvalidOperationException(Tr("Resource '{0}' has no rdp:// URI.", resource.Name));
        var shared = Accounts.HostEntry.For(resource).Count > 1;

        string? FieldValue(string name) =>
            resource.CustomFields
                .Where(f => string.Equals(f.Key.Trim(), name, StringComparison.OrdinalIgnoreCase))
                .Select(f => secret.CustomFieldValues.GetValueOrDefault(f.Id) is { Length: > 0 } v ? v : f.MetadataValue)
                .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

        var (fieldUser, fieldDomain) = RdpTarget.SplitUser(resource.Username);
        var username = target.Username ?? fieldUser
                       ?? throw new InvalidOperationException(Tr("Resource '{0}' has no username.", resource.Name));
        var domain = target.Domain ?? FieldValue(DomainField)?.Trim() ?? fieldDomain;

        var fingerprints = ParseFingerprints(FieldValue(CertificateField), shared ? target : null);

        return new RdpConnectionSpec(Accounts.HostEntry.Name(resource.Name, uri, target.Host, shared), target, username, domain, secret.Password, fingerprints);
    }

    /// <summary>
    /// Parses <c>rdp_cert_sha256</c>: fingerprints separated by lines, commas or spaces, or lines <c>host fingerprint</c>
    /// for resources with several hosts. Selection by <paramref name="target"/> works like
    /// <see cref="SshConnectionMapper.ParseHostKeys"/>: matching hosts, else unqualified entries, else all.
    /// </summary>
    public static IReadOnlyList<string> ParseFingerprints(string? text, RdpTarget? target = null)
    {
        var entries = new List<(string? Patterns, string Fingerprint)>();
        foreach (var line in (text ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var tokens = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length == 2 && !tokens[0].Split(',', StringSplitOptions.RemoveEmptyEntries).Any(IsFingerprint))
                entries.Add((tokens[0], NormalizeFingerprint(tokens[1])));
            else
                entries.AddRange(line.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(f => ((string?)null, NormalizeFingerprint(f))));
        }

        if (target is null)
            return entries.Select(e => e.Fingerprint).ToList();
        var forTarget = entries.Where(e => e.Patterns is not null && HostPatterns.Matches(e.Patterns, target.Host, target.Port, 3389)).ToList();
        if (forTarget.Count == 0)
            forTarget = entries.Where(e => e.Patterns is null).ToList();
        return (forTarget.Count > 0 ? forTarget : entries).Select(e => e.Fingerprint).ToList();
    }

    /// <summary>
    /// <c>rdp_cert_sha256</c> after storing <paramref name="fingerprint"/> for <paramref name="target"/>: just the fingerprint
    /// for a resource with one host, otherwise a <c>host fingerprint</c> line next to the other hosts' entries.
    /// </summary>
    public static string WithCertificate(string? existing, RdpTarget target, string fingerprint, bool sharedResource)
    {
        if (!sharedResource)
            return fingerprint;
        var kept = (existing ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries) is not [var patterns, _]
                           || patterns.Split(',', StringSplitOptions.RemoveEmptyEntries).Any(IsFingerprint)
                           || !HostPatterns.Matches(patterns, target.Host, target.Port, 3389));
        return string.Join("\n", kept.Append($"{HostPatterns.For(target.Host, target.Port, 3389)} {fingerprint}"));
    }

    private static bool IsFingerprint(string token)
    {
        var base64 = NormalizeFingerprint(token);
        var buffer = new byte[48];
        return Convert.TryFromBase64String(base64.PadRight((base64.Length + 3) / 4 * 4, '='), buffer, out var length) && length == 32;
    }

    /// <summary>
    /// Accepts <c>SHA256:base64</c>, base64 or hex (with or without colons, as printed by
    /// <c>openssl x509 -fingerprint -sha256</c>) and returns unpadded base64.
    /// </summary>
    public static string NormalizeFingerprint(string value)
    {
        var text = value.Trim();
        if (text.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase) || text.StartsWith("SHA256=", StringComparison.OrdinalIgnoreCase))
            text = text[7..];
        var hex = text.Replace(":", "");
        if (hex.Length == 64 && hex.All(Uri.IsHexDigit))
            return Convert.ToBase64String(Convert.FromHexString(hex)).TrimEnd('=');
        return text.TrimEnd('=');
    }
}
