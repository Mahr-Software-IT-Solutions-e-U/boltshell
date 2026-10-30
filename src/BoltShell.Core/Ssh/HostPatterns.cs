using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace BoltShell.Core.Ssh;

/// <summary>
/// known_hosts style host patterns, used when one Passbolt resource holds the identities of several hosts:
/// <c>host</c>, <c>[host]:port</c>, comma-separated lists, <c>*</c>/<c>?</c> wildcards, <c>!negation</c>
/// and hashed entries (<c>|1|salt|hash</c>).
/// </summary>
public static class HostPatterns
{
    /// <summary>The pattern written for a host: <c>host</c> on the default port, otherwise <c>[host]:port</c>.</summary>
    public static string For(string host, int port, int defaultPort) =>
        port == defaultPort && !host.Contains(':') ? host.ToLowerInvariant() : $"[{host.ToLowerInvariant()}]:{port}";

    /// <summary>True if <paramref name="patterns"/> matches the host (and no negated pattern excludes it).</summary>
    public static bool Matches(string patterns, string host, int port, int defaultPort)
    {
        var name = For(host, port, defaultPort);
        var matched = false;
        foreach (var raw in patterns.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var negated = raw.StartsWith('!');
            var pattern = negated ? raw[1..] : raw;
            var hit = pattern.StartsWith("|1|", StringComparison.Ordinal) ? HashedMatches(pattern, name) : GlobMatches(pattern, name);
            if (hit && negated)
                return false;
            matched |= hit;
        }
        return matched;
    }

    private static bool GlobMatches(string pattern, string name)
    {
        var regex = "^" + Regex.Escape(pattern.ToLowerInvariant()).Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
        return Regex.IsMatch(name, regex, RegexOptions.CultureInvariant);
    }

    private static bool HashedMatches(string pattern, string name)
    {
        var parts = pattern.Split('|'); // "", "1", salt, hash
        if (parts.Length != 4)
            return false;
        try
        {
            var hash = HMACSHA1.HashData(Convert.FromBase64String(parts[2]), Encoding.ASCII.GetBytes(name));
            return CryptographicOperations.FixedTimeEquals(hash, Convert.FromBase64String(parts[3]));
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
