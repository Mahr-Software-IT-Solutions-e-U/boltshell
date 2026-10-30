using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Bcpg.OpenPgp;
using static BoltShell.Core.Localization.Texts;

namespace BoltShell.Core.Passbolt;

/// <summary>
/// Parses a Passbolt account kit (<c>account-kit.passbolt</c>, exported from the browser extension).
/// The file is base64; its content is either plain JSON or an OpenPGP signed message wrapping the JSON.
/// </summary>
public static class AccountKit
{
    public static PassboltAccount Parse(string fileContent)
    {
        var json = Unwrap(fileContent.Trim());
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        string Required(string name) =>
            root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s
                ? s
                : throw new FormatException(Tr("Account kit is missing '{0}'.", name));

        string? serverFingerprint = null;
        if (root.TryGetProperty("server_public_armored_key", out var serverKey) && serverKey.GetString() is { } armored)
            serverFingerprint = Crypto.PgpPublicKeys.Parse(armored).Fingerprint;

        var domain = Required("domain");
        try
        {
            PassboltAccount.ValidateServerUrl(domain);
        }
        catch (ArgumentException ex)
        {
            throw new FormatException(ex.Message, ex);
        }

        return new PassboltAccount(
            ServerUrl: domain,
            UserId: Required("user_id"),
            ArmoredPrivateKey: Required("user_private_armored_key"),
            Username: root.TryGetProperty("username", out var u) ? u.GetString() : null,
            ServerFingerprint: serverFingerprint);
    }

    private static string Unwrap(string content)
    {
        string decoded;
        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(content));
        }
        catch (FormatException)
        {
            decoded = content; // already plain text
        }

        decoded = decoded.Trim();
        if (decoded.StartsWith('{'))
            return decoded;
        if (decoded.StartsWith("-----BEGIN PGP SIGNED MESSAGE-----", StringComparison.Ordinal))
            return ExtractCleartext(decoded);
        if (decoded.StartsWith("-----BEGIN PGP", StringComparison.Ordinal))
            return ExtractLiteralData(decoded);
        throw new FormatException(Tr("Unrecognised account kit format."));
    }

    private static string ExtractCleartext(string signed)
    {
        var lines = signed.Replace("\r\n", "\n").Split('\n');
        var start = Array.IndexOf(lines, "") + 1; // body starts after the armor headers
        var end = Array.FindIndex(lines, l => l.StartsWith("-----BEGIN PGP SIGNATURE-----", StringComparison.Ordinal));
        if (start <= 0 || end < start)
            throw new FormatException(Tr("Malformed cleartext-signed account kit."));
        return string.Join('\n', lines[start..end].Select(l => l.StartsWith("- ", StringComparison.Ordinal) ? l[2..] : l));
    }

    // The signature is not verified here: the kit is imported by the user from their own export,
    // and the server key it contains is checked against the server during login.
    private static string ExtractLiteralData(string armored)
    {
        using var input = PgpUtilities.GetDecoderStream(new MemoryStream(Encoding.ASCII.GetBytes(armored)));
        var factory = new PgpObjectFactory(input);
        for (var obj = factory.NextPgpObject(); obj is not null; obj = factory.NextPgpObject())
        {
            if (obj is PgpCompressedData compressed)
            {
                factory = new PgpObjectFactory(compressed.GetDataStream());
                continue;
            }
            if (obj is PgpLiteralData literal)
            {
                using var reader = new StreamReader(literal.GetInputStream(), Encoding.UTF8);
                return reader.ReadToEnd();
            }
        }
        throw new FormatException(Tr("Account kit signed message contains no data."));
    }
}
