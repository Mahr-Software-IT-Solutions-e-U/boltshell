using System.Buffers.Binary;
using System.Security.Cryptography;

namespace BoltShell.Core.Crypto;

/// <summary>
/// Time-based one-time password (RFC 6238) as stored in Passbolt v5 secrets
/// (<c>"totp": {"secret_key", "algorithm", "digits", "period"}</c>).
/// </summary>
/// <param name="SecretKey">Base32 encoded shared secret.</param>
public sealed record TotpSettings(string SecretKey, string Algorithm = "SHA1", int Digits = 6, int Period = 30)
{
    /// <summary>The code valid at <paramref name="time"/>.</summary>
    public string Code(DateTimeOffset time)
    {
        var key = Base32Decode(SecretKey);
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, time.ToUnixTimeSeconds() / Period);
        var hash = Algorithm.ToUpperInvariant() switch
        {
            "SHA256" => HMACSHA256.HashData(key, counter),
            "SHA512" => HMACSHA512.HashData(key, counter),
            _ => HMACSHA1.HashData(key, counter),
        };
        var offset = hash[^1] & 0x0F;
        var binary = BinaryPrimitives.ReadInt32BigEndian(hash.AsSpan(offset)) & 0x7FFFFFFF;
        return (binary % (int)Math.Pow(10, Digits)).ToString(new string('0', Digits));
    }

    /// <summary>Time until the next code becomes valid.</summary>
    public TimeSpan UntilNextPeriod(DateTimeOffset time) =>
        TimeSpan.FromSeconds(Period - time.ToUnixTimeSeconds() % Period);

    internal static byte[] Base32Decode(string text)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var clean = text.Replace(" ", "").Replace("-", "").TrimEnd('=').ToUpperInvariant();
        var output = new List<byte>(clean.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (var c in clean)
        {
            var value = alphabet.IndexOf(c);
            if (value < 0)
                throw new FormatException(Localization.Texts.Tr("The TOTP secret is not valid base32."));
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                output.Add((byte)(buffer >> bits));
                buffer &= (1 << bits) - 1;
            }
        }
        return output.ToArray();
    }
}
