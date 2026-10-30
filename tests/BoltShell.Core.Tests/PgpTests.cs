using Org.BouncyCastle.Bcpg.OpenPgp;
using BoltShell.Core.Crypto;

namespace BoltShell.Core.Tests;

public class PgpTests
{
    [Fact]
    public void EncryptAndSign_RoundTrips_AndVerifiesSignature()
    {
        var user = PgpKeyChain.Unlock(TestKeys.User.Private, TestKeys.UserPassphrase);
        var server = PgpKeyChain.Unlock(TestKeys.Server.Private, "");

        var message = PgpMessage.EncryptAndSign("hällo wörld", PgpPublicKeys.Parse(TestKeys.Server.Public), user);

        Assert.StartsWith("-----BEGIN PGP MESSAGE-----", message);
        Assert.Equal("hällo wörld", PgpMessage.Decrypt(message, server, verifyWith: PgpPublicKeys.Parse(TestKeys.User.Public)));
    }

    [Fact]
    public void Decrypt_RejectsSignatureFromWrongKey()
    {
        var user = PgpKeyChain.Unlock(TestKeys.User.Private, TestKeys.UserPassphrase);
        var server = PgpKeyChain.Unlock(TestKeys.Server.Private, "");
        var message = PgpMessage.EncryptAndSign("x", PgpPublicKeys.Parse(TestKeys.Server.Public), user);

        Assert.Throws<PgpException>(() => PgpMessage.Decrypt(message, server, verifyWith: PgpPublicKeys.Parse(TestKeys.Metadata.Public)));
    }

    [Fact]
    public void Unlock_WithWrongPassphrase_Throws()
    {
        Assert.Throws<PgpException>(() => PgpKeyChain.Unlock(TestKeys.User.Private, "wrong"));
    }

    [Fact]
    public void Decrypt_UsesAdditionalDecryptionKeys()
    {
        var user = PgpKeyChain.Unlock(TestKeys.User.Private, TestKeys.UserPassphrase);
        var server = PgpKeyChain.Unlock(TestKeys.Server.Private, "");
        var forMetadataKey = PgpMessage.EncryptAndSign("{\"name\":\"db\"}", PgpPublicKeys.Parse(TestKeys.Metadata.Public), server);

        Assert.Throws<PgpException>(() => PgpMessage.Decrypt(forMetadataKey, user));
        user.AddDecryptionKey(TestKeys.Metadata.Private, "");
        Assert.Equal("{\"name\":\"db\"}", PgpMessage.Decrypt(forMetadataKey, user));
    }

    [Fact]
    public void Fingerprint_MatchesBetweenPublicAndPrivate()
    {
        var chain = PgpKeyChain.Unlock(TestKeys.User.Private, TestKeys.UserPassphrase);
        Assert.Equal(PgpPublicKeys.Parse(TestKeys.User.Public).Fingerprint, chain.Fingerprint);
        Assert.Equal(40, chain.Fingerprint.Length);
    }
}
