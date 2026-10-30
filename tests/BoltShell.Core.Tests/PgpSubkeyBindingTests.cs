using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using BoltShell.Core.Crypto;

namespace BoltShell.Core.Tests;

/// <summary>
/// Audit finding SEC-01: a pinned primary-key fingerprint must also pin every key that is used.
/// An attacker who can replace server responses appends his own subkey to the genuine server certificate.
/// </summary>
public class PgpSubkeyBindingTests
{
    private static readonly SecureRandom Random = new();

    [Fact]
    public void UnboundSubkey_IsIgnored_ForEncryptionAndSignatures()
    {
        var attacker = AttackerKey(signingSubkey: true, backSignature: true);
        var stripped = StripSignatures(attacker.SubkeyPublic);
        var tampered = Inject(TestKeys.Server.Public, stripped);

        Assert.Equal(PgpPublicKeys.Parse(TestKeys.Server.Public).Fingerprint, tampered.Fingerprint); // pin still matches
        Assert.NotEqual(stripped.KeyId, tampered.EncryptionKey.KeyId);
        Assert.Null(tampered.FindKey(stripped.KeyId));
    }

    [Fact]
    public void SubkeyBoundByAnotherPrimaryKey_IsIgnored()
    {
        var attacker = AttackerKey(signingSubkey: true, backSignature: true);
        var tampered = Inject(TestKeys.Server.Public, attacker.SubkeyPublic); // binding signature exists, but from the attacker's primary

        Assert.NotEqual(attacker.SubkeyPublic.KeyId, tampered.EncryptionKey.KeyId);
        Assert.Null(tampered.FindKey(attacker.SubkeyPublic.KeyId));
    }

    [Fact]
    public void ForgedResponse_SignedWithInjectedSubkey_IsRejected()
    {
        var attacker = AttackerKey(signingSubkey: true, backSignature: true);
        var tampered = Inject(TestKeys.Server.Public, StripSignatures(attacker.SubkeyPublic));
        var user = PgpKeyChain.Unlock(TestKeys.User.Private, TestKeys.UserPassphrase);

        // The attacker encrypts a forged login response for the user and signs it with the injected subkey.
        var forged = EncryptAndSignWith("{\"verify_token\":\"x\"}", PgpPublicKeys.Parse(TestKeys.User.Public).EncryptionKey, attacker.SubkeyPrivate, attacker.SubkeyPublic);

        Assert.Throws<PgpException>(() => PgpMessage.Decrypt(forged, user, verifyWith: tampered));
    }

    [Fact]
    public void SigningSubkey_RequiresBackSignature()
    {
        var withoutBack = AttackerKey(signingSubkey: true, backSignature: false);
        var ring = PgpPublicKeys.Parse(withoutBack.Armored);
        Assert.Null(ring.FindKey(withoutBack.SubkeyPublic.KeyId));

        var withBack = AttackerKey(signingSubkey: true, backSignature: true);
        var good = PgpPublicKeys.Parse(withBack.Armored);
        Assert.NotNull(good.FindKey(withBack.SubkeyPublic.KeyId)); // properly bound signing subkey is accepted
        Assert.Equal(withBack.SubkeyPublic.KeyId, good.EncryptionKey.KeyId);
    }

    [Fact]
    public void RevokedSubkey_IsIgnored()
    {
        var key = AttackerKey(signingSubkey: false, backSignature: false);
        var ring = PgpPublicKeys.Parse(key.Armored);
        Assert.Equal(key.SubkeyPublic.KeyId, ring.EncryptionKey.KeyId);

        var revocation = new PgpSignatureGenerator(key.PrimaryPublic.Algorithm, HashAlgorithmTag.Sha256);
        revocation.InitSign(PgpSignature.SubkeyRevocation, key.PrimaryPrivate, Random);
        var revoked = PgpPublicKey.AddCertification(key.SubkeyPublic, revocation.GenerateCertification(key.PrimaryPublic, key.SubkeyPublic));
        var revokedRing = PgpPublicKeyRing.InsertPublicKey(ring.Ring, revoked);

        // The primary key may only sign/certify, so with its only encryption subkey revoked nothing is left to encrypt to.
        Assert.Throws<PgpException>(() => PgpPublicKeys.Parse(Armor(revokedRing.Encode)).EncryptionKey);
    }

    [Fact]
    public async Task FullLogin_WithInjectedSubkey_FailsDespiteMatchingPin()
    {
        var attacker = AttackerKey(signingSubkey: true, backSignature: true);
        var injected = StripSignatures(attacker.SubkeyPublic);
        var tamperedArmored = Armor(PgpPublicKeyRing.InsertPublicKey(PgpPublicKeys.Parse(TestKeys.Server.Public).Ring, injected).Encode);
        var pinned = PgpPublicKeys.Parse(TestKeys.Server.Public).Fingerprint;
        var handler = new ForgingServer(tamperedArmored, attacker.SubkeyPrivate, injected);
        using var client = new Passbolt.PassboltClient(PassboltClientTests.Account() with { ServerFingerprint = pinned }, handler);

        await Assert.ThrowsAnyAsync<Exception>(() => client.LoginAsync(TestKeys.UserPassphrase));
        Assert.False(client.IsAuthenticated);
        Assert.False(handler.CouldReadChallenge); // the challenge went to the genuine server subkey
    }

    /// <summary>Man in the middle: genuine server primary key + own subkey; answers the login with a forged, self-signed response.</summary>
    private sealed class ForgingServer(string tamperedKey, PgpPrivateKey attackerPrivate, PgpPublicKey attackerPublic) : HttpMessageHandler
    {
        public bool CouldReadChallenge { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            System.Text.Json.Nodes.JsonNode body;
            if (request.RequestUri!.AbsolutePath == "/auth/verify.json")
            {
                body = new System.Text.Json.Nodes.JsonObject { ["keydata"] = tamperedKey };
            }
            else
            {
                var payload = System.Text.Json.Nodes.JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!;
                CouldReadChallenge = TryDecrypt(payload["challenge"]!.GetValue<string>());
                var forged = new System.Text.Json.Nodes.JsonObject { ["verify_token"] = "guessed", ["access_token"] = "t", ["refresh_token"] = "r" };
                body = new System.Text.Json.Nodes.JsonObject
                {
                    ["challenge"] = EncryptAndSignWith(forged.ToJsonString(), PgpPublicKeys.Parse(TestKeys.User.Public).EncryptionKey, attackerPrivate, attackerPublic),
                };
            }
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(new System.Text.Json.Nodes.JsonObject { ["header"] = new System.Text.Json.Nodes.JsonObject(), ["body"] = body }.ToJsonString()),
            };
        }

        private bool TryDecrypt(string armored)
        {
            try
            {
                using var input = PgpUtilities.GetDecoderStream(new MemoryStream(Encoding.ASCII.GetBytes(armored)));
                var factory = new PgpObjectFactory(input);
                var list = factory.NextPgpObject() as PgpEncryptedDataList ?? (PgpEncryptedDataList)factory.NextPgpObject();
                return list.GetEncryptedDataObjects().OfType<PgpPublicKeyEncryptedData>().Any(d => d.KeyId == attackerPublic.KeyId);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    private sealed record GeneratedKey(string Armored, PgpPublicKey PrimaryPublic, PgpPrivateKey PrimaryPrivate, PgpPublicKey SubkeyPublic, PgpPrivateKey SubkeyPrivate);

    /// <summary>RSA primary (certify/sign) + RSA subkey for encryption, optionally also for signing with or without back-signature.</summary>
    private static GeneratedKey AttackerKey(bool signingSubkey, bool backSignature)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Random, 2048, 12));
        var now = DateTime.UtcNow.AddMinutes(-1);
        var primary = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, generator.GenerateKeyPair(), now);
        var sub = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, generator.GenerateKeyPair(), now);

        var primaryFlags = new PgpSignatureSubpacketGenerator();
        primaryFlags.SetKeyFlags(false, PgpKeyFlags.CanSign | PgpKeyFlags.CanCertify);
        var subPackets = new PgpSignatureSubpacketGenerator();
        subPackets.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage | (signingSubkey ? PgpKeyFlags.CanSign : 0));
        if (signingSubkey && backSignature)
        {
            var back = new PgpSignatureGenerator(sub.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            back.InitSign(PgpSignature.PrimaryKeyBinding, sub.PrivateKey, Random);
            subPackets.AddEmbeddedSignature(false, back.GenerateCertification(primary.PublicKey, sub.PublicKey));
        }

        var ringGen = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, primary, "Attacker <a@example.com>",
            SymmetricKeyAlgorithmTag.Aes256, Array.Empty<char>(), true, primaryFlags.Generate(), null, Random);
        ringGen.AddSubKey(sub, subPackets.Generate(), null);
        var publicRing = ringGen.GeneratePublicKeyRing();
        return new GeneratedKey(Armor(publicRing.Encode), primary.PublicKey, primary.PrivateKey,
            publicRing.GetPublicKey(sub.KeyId), sub.PrivateKey);
    }

    private static PgpPublicKey StripSignatures(PgpPublicKey subkey)
    {
        foreach (var signature in subkey.GetSignatures().ToList())
            subkey = PgpPublicKey.RemoveCertification(subkey, signature);
        return subkey;
    }

    private static PgpPublicKeys Inject(string armoredRing, PgpPublicKey foreignSubkey)
    {
        var ring = PgpPublicKeyRing.InsertPublicKey(PgpPublicKeys.Parse(armoredRing).Ring, foreignSubkey);
        return PgpPublicKeys.Parse(Armor(ring.Encode));
    }

    internal static string EncryptAndSignWith(string text, PgpPublicKey recipient, PgpPrivateKey signer, PgpPublicKey signerPublic)
    {
        var data = Encoding.UTF8.GetBytes(text);
        using var output = new MemoryStream();
        using (var armor = new ArmoredOutputStream(output))
        {
            var enc = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
            enc.AddMethod(recipient);
            using var encOut = enc.Open(armor, new byte[1 << 16]);
            var sig = new PgpSignatureGenerator(signerPublic.Algorithm, HashAlgorithmTag.Sha256);
            sig.InitSign(PgpSignature.BinaryDocument, signer, Random);
            sig.GenerateOnePassVersion(false).Encode(encOut);
            using (var lit = new PgpLiteralDataGenerator().Open(encOut, PgpLiteralData.Binary, "", data.Length, DateTime.UtcNow))
                lit.Write(data, 0, data.Length);
            sig.Update(data);
            sig.Generate().Encode(encOut);
        }
        return Encoding.ASCII.GetString(output.ToArray());
    }

    private static string Armor(Action<Stream> encode)
    {
        using var ms = new MemoryStream();
        using (var armor = new ArmoredOutputStream(ms))
            encode(armor);
        return Encoding.ASCII.GetString(ms.ToArray());
    }
}
