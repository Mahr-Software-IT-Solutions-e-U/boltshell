using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace BoltShell.Core.Tests;

/// <summary>Generates OpenPGP key pairs shaped like Passbolt's (RSA master for signing, RSA subkey for encryption).</summary>
public static class TestKeys
{
    private static readonly Lazy<(string Private, string Public)> UserKey = new(() => Generate("Ada User <ada@example.com>", "user-pass"));
    private static readonly Lazy<(string Private, string Public)> ServerKey = new(() => Generate("Passbolt Server <server@example.com>", ""));
    private static readonly Lazy<(string Private, string Public)> MetadataKey = new(() => Generate("Passbolt Metadata Key <no-reply@example.com>", ""));

    public const string UserPassphrase = "user-pass";
    public static (string Private, string Public) User => UserKey.Value;
    public static (string Private, string Public) Server => ServerKey.Value;
    public static (string Private, string Public) Metadata => MetadataKey.Value;

    public static (string Private, string Public) Generate(string userId, string passphrase)
    {
        var random = new SecureRandom();
        var generator = new RsaKeyPairGenerator();
        generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), random, 2048, 12));
        var now = DateTime.UtcNow.AddMinutes(-1);
        var master = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, generator.GenerateKeyPair(), now);
        var sub = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, generator.GenerateKeyPair(), now);

        var masterFlags = new PgpSignatureSubpacketGenerator();
        masterFlags.SetKeyFlags(false, PgpKeyFlags.CanSign | PgpKeyFlags.CanCertify);
        var subFlags = new PgpSignatureSubpacketGenerator();
        subFlags.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);

        var ringGen = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, master, userId,
            SymmetricKeyAlgorithmTag.Aes256, passphrase.ToCharArray(), true, masterFlags.Generate(), null, random);
        ringGen.AddSubKey(sub, subFlags.Generate(), null);

        return (Armor(ringGen.GenerateSecretKeyRing().Encode), Armor(ringGen.GeneratePublicKeyRing().Encode));
    }

    private static string Armor(Action<Stream> encode)
    {
        using var ms = new MemoryStream();
        using (var armor = new ArmoredOutputStream(ms))
            encode(armor);
        return Encoding.ASCII.GetString(ms.ToArray());
    }
}
