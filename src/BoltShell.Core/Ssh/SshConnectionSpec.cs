using System.Security.Cryptography;
using System.Text.RegularExpressions;
using BoltShell.Core.Passbolt;
using static BoltShell.Core.Localization.Texts;

namespace BoltShell.Core.Ssh;

/// <summary>Credentials for one connection. Kept in memory only for as long as the connection needs them.</summary>
/// <param name="Totp">One-time password settings from Passbolt, answered automatically when the server asks for a code.</param>
public sealed record SshCredentials(string? Password, string? PrivateKey, string? KeyPassphrase, Crypto.TotpSettings? Totp = null)
{
    public bool HasPrivateKey => !string.IsNullOrEmpty(PrivateKey);
    public bool HasPassword => !string.IsNullOrEmpty(Password);
}

/// <summary>A host key the server must present, as published in Passbolt.</summary>
/// <param name="Algorithm">e.g. <c>ssh-ed25519</c>; null if only a fingerprint was given.</param>
/// <param name="FingerprintSha256">Base64 SHA256 fingerprint without padding, as printed by <c>ssh-keygen -l</c>.</param>
public sealed record ExpectedHostKey(string? Algorithm, string FingerprintSha256);

/// <summary>Everything needed to open an SSH connection.</summary>
public sealed record SshConnectionSpec(
    string DisplayName,
    SshTarget Target,
    string Username,
    SshCredentials Credentials,
    IReadOnlyList<ExpectedHostKey>? HostKeys = null,
    string? PublicKey = null)
{
    /// <summary>True if Passbolt defines the host identity; then only those keys are accepted.</summary>
    public bool HasPinnedHostKeys => HostKeys is { Count: > 0 };
}

/// <summary>
/// Maps a Passbolt resource and its decrypted secret to an SSH connection. Convention:
/// <list type="table">
/// <item><term>URI</term><description><c>ssh://[user@]host[:port]</c> – marks the resource as SSH host</description></item>
/// <item><term>Username</term><description>login user, unless the URI contains one</description></item>
/// <item><term>Password</term><description>login password; or the passphrase of an <b>encrypted</b> key if there is no <c>ssh_passphrase</c> field</description></item>
/// <item><term><c>ssh_private_key</c></term><description>private key (OpenSSH/PEM)</description></item>
/// <item><term><c>ssh_passphrase</c></term><description>key passphrase (then Password is the login password)</description></item>
/// <item><term><c>ssh_public_key</c></term><description>public key of the private key (informational)</description></item>
/// <item><term><c>ssh_host_key</c></term><description>host identity: known_hosts lines, public keys or SHA256 fingerprints</description></item>
/// </list>
/// For Passbolt v4 (no custom fields) the private key may be put in the encrypted note.
/// </summary>
public static partial class SshConnectionMapper
{
    public const string PrivateKeyField = "ssh_private_key";
    public const string PublicKeyField = "ssh_public_key";
    public const string PassphraseField = "ssh_passphrase";
    public const string HostKeyField = "ssh_host_key";

    [GeneratedRegex(@"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", RegexOptions.Singleline)]
    private static partial Regex PrivateKeyBlock();

    /// <summary>True if the resource has an <c>ssh://</c> URI.</summary>
    public static bool HasSshTarget(PassboltResource resource) =>
        resource.Uris.Any(u => SshTarget.TryParse(u, out _));

    /// <summary>Builds the connection spec. A key passphrase is never offered to the server as a login password.</summary>
    /// <param name="uri">The <c>ssh://</c> URI to connect to (see <see cref="Accounts.HostEntry"/>); null for the first one.</param>
    public static SshConnectionSpec Map(PassboltResource resource, PassboltSecret secret, string? uri = null)
    {
        var target = (uri is null
                         ? resource.Uris.Select(u => SshTarget.TryParse(u, out var t) ? t : null).FirstOrDefault(t => t is not null)
                         : resource.Uris.Contains(uri) && SshTarget.TryParse(uri, out var chosen) ? chosen : null)
                     ?? throw new InvalidOperationException(Tr("Resource '{0}' has no ssh:// URI.", resource.Name));
        var shared = Accounts.HostEntry.For(resource).Count > 1;

        var username = target.Username ?? resource.Username
                       ?? throw new InvalidOperationException(Tr("Resource '{0}' has no username.", resource.Name));

        // v5 custom field values live in the secret; fall back to the (encrypted) metadata value.
        string? FieldValue(string name) =>
            resource.CustomFields
                .Where(f => string.Equals(f.Key.Trim(), name, StringComparison.OrdinalIgnoreCase))
                .Select(f => NullIfEmpty(secret.CustomFieldValues.GetValueOrDefault(f.Id)) ?? NullIfEmpty(f.MetadataValue))
                .FirstOrDefault(v => v is not null);

        var hostKeys = ParseHostKeys(FieldValue(HostKeyField), shared ? target : null);
        var publicKey = FieldValue(PublicKeyField)?.Trim();
        var password = NullIfEmpty(secret.Password);
        var passphraseField = FieldValue(PassphraseField);
        var privateKey = ExtractKey(FieldValue(PrivateKeyField)) ?? ExtractKey(secret.Description);

        SshCredentials credentials;
        if (privateKey is null && ExtractKey(password) is { } keyInPassword)
            credentials = new SshCredentials(null, keyInPassword, passphraseField); // tolerated, never sent as password
        else if (privateKey is null)
            credentials = new SshCredentials(password, null, null);
        else if (passphraseField is not null)
            credentials = new SshCredentials(password, privateKey, passphraseField);
        else if (!IsEncrypted(privateKey))
            credentials = new SshCredentials(password, privateKey, null); // nothing to unlock: the password is the login password
        else
            credentials = new SshCredentials(null, privateKey, password);

        return new SshConnectionSpec(shared ? $"{resource.Name} ({target.Host})" : resource.Name, target, username,
            credentials with { Totp = secret.Totp }, hostKeys, publicKey);
    }

    /// <summary>
    /// Parses the host identity field. One entry per line; accepted forms:
    /// <c>SHA256:base64</c>, <c>ssh-ed25519 AAAA… [comment]</c> and known_hosts lines <c>host ssh-ed25519 AAAA…</c>
    /// (also <c>host SHA256:…</c>).
    /// </summary>
    /// <param name="target">
    /// For resources with several hosts: only entries whose host pattern matches the target count, else the entries
    /// without host pattern. If neither exists, all entries count, so a pin never silently disappears.
    /// </param>
    public static IReadOnlyList<ExpectedHostKey> ParseHostKeys(string? text, SshTarget? target = null)
    {
        var entries = new List<(string? Patterns, ExpectedHostKey Key)>();
        if (string.IsNullOrWhiteSpace(text))
            return [];

        foreach (var raw in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (raw.StartsWith('#'))
                continue;
            var parts = raw.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            var patterns = LinePatterns(parts);

            // A fingerprint, optionally preceded by the algorithm ("ssh-ed25519 SHA256:…").
            var fingerprint = parts.FirstOrDefault(p => p.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase));
            if (fingerprint is not null)
            {
                entries.Add((patterns, new ExpectedHostKey(parts.FirstOrDefault(IsKeyAlgorithm), fingerprint[7..].TrimEnd('='))));
                continue;
            }

            // A public key, optionally preceded by known_hosts host patterns / markers.
            var index = Array.FindIndex(parts, IsKeyAlgorithm);
            if (index < 0 || index + 1 >= parts.Length)
                throw new FormatException(Tr("Unrecognised entry in {0}: '{1}'.", HostKeyField, raw));
            byte[] blob;
            try
            {
                blob = Convert.FromBase64String(parts[index + 1]);
            }
            catch (FormatException)
            {
                throw new FormatException(Tr("Invalid base64 in {0}: '{1}'.", HostKeyField, raw));
            }
            entries.Add((patterns, new ExpectedHostKey(parts[index], Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('='))));
        }

        if (target is null)
            return entries.Select(e => e.Key).ToList();
        var forTarget = entries.Where(e => e.Patterns is not null && HostPatterns.Matches(e.Patterns, target.Host, target.Port, 22)).ToList();
        if (forTarget.Count == 0)
            forTarget = entries.Where(e => e.Patterns is null).ToList();
        return (forTarget.Count > 0 ? forTarget : entries).Select(e => e.Key).ToList();
    }

    /// <summary>
    /// The host identity field after storing <paramref name="keyLine"/> (<c>ssh-ed25519 AAAA…</c>) for <paramref name="target"/>.
    /// A resource with one host gets just the key; with several hosts, the entry for this host is added or replaced
    /// as a known_hosts line and the other hosts' entries stay.
    /// </summary>
    public static string WithHostKey(string? existing, SshTarget target, string keyLine, bool sharedResource)
    {
        if (!sharedResource)
            return keyLine;
        var kept = (existing ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => LinePatterns(line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)) is not { } patterns
                           || !HostPatterns.Matches(patterns, target.Host, target.Port, 22));
        return string.Join("\n", kept.Append($"{HostPatterns.For(target.Host, target.Port, 22)} {keyLine}"));
    }

    // Host patterns of a known_hosts line (after an optional @marker), or null if the line starts with the key.
    private static string? LinePatterns(string[] parts)
    {
        var first = parts.Length > 0 && parts[0].StartsWith('@') ? 1 : 0;
        if (parts.Length <= first + 1 || IsKeyAlgorithm(parts[first]) || parts[first].StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase))
            return null;
        return parts[first];
    }

    /// <summary>True if the private key needs a passphrase. Unparsable keys count as encrypted (the safe choice).</summary>
    public static bool IsEncrypted(string privateKey)
    {
        try
        {
            using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(privateKey));
            using var _ = new Renci.SshNet.PrivateKeyFile(stream);
            return false;
        }
        catch (Exception)
        {
            return true;
        }
    }

    private static bool IsKeyAlgorithm(string token) =>
        token.StartsWith("ssh-", StringComparison.Ordinal)
        || token.StartsWith("ecdsa-sha2-", StringComparison.Ordinal)
        || token.StartsWith("sk-", StringComparison.Ordinal)
        || token.StartsWith("rsa-sha2-", StringComparison.Ordinal);

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    internal static string? ExtractKey(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        var match = PrivateKeyBlock().Match(text.Replace("\r\n", "\n"));
        return match.Success ? match.Value + "\n" : null;
    }
}
