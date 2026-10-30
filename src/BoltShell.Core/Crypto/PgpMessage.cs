using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using static BoltShell.Core.Localization.Texts;

namespace BoltShell.Core.Crypto;

public static class PgpMessage
{
    private static readonly SecureRandom Random = new();

    /// <summary>Encrypts <paramref name="plaintext"/> for <paramref name="recipient"/> and signs it with the chain's signing key.</summary>
    public static string EncryptAndSign(string plaintext, PgpPublicKeys recipient, PgpKeyChain signer)
    {
        var data = Encoding.UTF8.GetBytes(plaintext);
        using var output = new MemoryStream();
        using (var armor = new ArmoredOutputStream(output))
        {
            var encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, withIntegrityPacket: true, Random);
            encGen.AddMethod(recipient.EncryptionKey);
            using var encOut = encGen.Open(armor, new byte[1 << 16]);

            var compGen = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            using var compOut = compGen.Open(encOut);

            var sigGen = new PgpSignatureGenerator(signer.SigningPublicKey.Algorithm, HashAlgorithmTag.Sha256);
            sigGen.InitSign(PgpSignature.BinaryDocument, signer.SigningKey, Random);
            var subpackets = new PgpSignatureSubpacketGenerator();
            subpackets.SetIssuerFingerprint(false, signer.SigningPublicKey);
            subpackets.SetSignatureCreationTime(false, DateTime.UtcNow);
            sigGen.SetHashedSubpackets(subpackets.Generate());
            sigGen.GenerateOnePassVersion(false).Encode(compOut);

            var litGen = new PgpLiteralDataGenerator();
            using (var litOut = litGen.Open(compOut, PgpLiteralData.Binary, PgpLiteralData.Console, data.Length, DateTime.UtcNow))
            {
                litOut.Write(data, 0, data.Length);
            }
            sigGen.Update(data);
            sigGen.Generate().Encode(compOut);
        }
        return Encoding.ASCII.GetString(output.ToArray());
    }

    /// <summary>
    /// Decrypts an armored message with any key in <paramref name="keys"/>.
    /// If <paramref name="verifyWith"/> is given, the message must carry a valid signature from it.
    /// </summary>
    public static string Decrypt(string armoredMessage, PgpKeyChain keys, PgpPublicKeys? verifyWith = null)
    {
        using var input = PgpUtilities.GetDecoderStream(new MemoryStream(Encoding.ASCII.GetBytes(armoredMessage)));
        var factory = new PgpObjectFactory(input);
        var obj = factory.NextPgpObject();
        var encList = obj as PgpEncryptedDataList ?? factory.NextPgpObject() as PgpEncryptedDataList
                      ?? throw new PgpException(Tr("Not an encrypted OpenPGP message."));

        PgpPublicKeyEncryptedData? encrypted = null;
        PgpPrivateKey? privateKey = null;
        foreach (var candidate in encList.GetEncryptedDataObjects().OfType<PgpPublicKeyEncryptedData>())
        {
            if (keys.TryGetPrivateKey(candidate.KeyId, out var key))
            {
                encrypted = candidate;
                privateKey = key;
                break;
            }
        }
        if (encrypted is null || privateKey is null)
            throw new PgpException(Tr("Message is not encrypted for any available key."));

        using var clear = encrypted.GetDataStream(privateKey);
        var plainFactory = new PgpObjectFactory(clear);
        var message = plainFactory.NextPgpObject();

        if (message is PgpCompressedData compressed)
        {
            plainFactory = new PgpObjectFactory(compressed.GetDataStream());
            message = plainFactory.NextPgpObject();
        }

        PgpOnePassSignature? onePass = null;
        if (message is PgpOnePassSignatureList opsList)
        {
            onePass = opsList[0];
            message = plainFactory.NextPgpObject();
        }

        if (message is not PgpLiteralData literal)
            throw new PgpException(Tr("Unexpected OpenPGP packet {0}.", message?.GetType().Name));

        byte[] data;
        using (var ms = new MemoryStream())
        {
            literal.GetInputStream().CopyTo(ms);
            data = ms.ToArray();
        }

        if (verifyWith is not null)
        {
            if (onePass is null)
                throw new PgpException(Tr("Message is not signed."));
            var signerKey = verifyWith.FindKey(onePass.KeyId)
                            ?? throw new PgpException(Tr("Message was signed by an unexpected key."));
            onePass.InitVerify(signerKey);
            onePass.Update(data);
            if (plainFactory.NextPgpObject() is not PgpSignatureList sigs || !onePass.Verify(sigs[0]))
                throw new PgpException(Tr("Invalid message signature."));
        }

        // The MDC can only be checked once the whole decrypted stream has been consumed.
        clear.CopyTo(Stream.Null);
        if (encrypted.IsIntegrityProtected() && !encrypted.Verify())
            throw new PgpException(Tr("Message integrity check failed."));

        return Encoding.UTF8.GetString(data);
    }
}
