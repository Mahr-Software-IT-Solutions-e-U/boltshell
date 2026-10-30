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

    public static RdpConnectionSpec Map(PassboltResource resource, PassboltSecret secret)
    {
        var target = resource.Uris.Select(u => RdpTarget.TryParse(u, out var t) ? t : null).FirstOrDefault(t => t is not null)
                     ?? throw new InvalidOperationException(Tr("Resource '{0}' has no rdp:// URI.", resource.Name));

        string? FieldValue(string name) =>
            resource.CustomFields
                .Where(f => string.Equals(f.Key.Trim(), name, StringComparison.OrdinalIgnoreCase))
                .Select(f => secret.CustomFieldValues.GetValueOrDefault(f.Id) is { Length: > 0 } v ? v : f.MetadataValue)
                .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

        var (fieldUser, fieldDomain) = RdpTarget.SplitUser(resource.Username);
        var username = target.Username ?? fieldUser
                       ?? throw new InvalidOperationException(Tr("Resource '{0}' has no username.", resource.Name));
        var domain = target.Domain ?? FieldValue(DomainField)?.Trim() ?? fieldDomain;

        var fingerprints = (FieldValue(CertificateField) ?? "")
            .Split(['\n', ',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(NormalizeFingerprint)
            .ToList();

        return new RdpConnectionSpec(resource.Name, target, username, domain, secret.Password, fingerprints);
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
