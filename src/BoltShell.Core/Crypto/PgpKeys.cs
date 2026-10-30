using Org.BouncyCastle.Bcpg.OpenPgp;

namespace BoltShell.Core.Crypto;

/// <summary>An OpenPGP public key ring, e.g. the Passbolt server key.</summary>
public sealed class PgpPublicKeys
{
    private PgpPublicKeys(PgpPublicKeyRing ring) => Ring = ring;

    public PgpPublicKeyRing Ring { get; }

    public string Fingerprint => Convert.ToHexString(Ring.GetPublicKey().GetFingerprint());

    /// <summary>Key used to encrypt messages for this recipient (prefers subkeys).</summary>
    public PgpPublicKey EncryptionKey =>
        Ring.GetPublicKeys().Where(k => k.IsEncryptionKey && !k.HasRevocation())
            .OrderBy(k => k.IsMasterKey) // subkeys first
            .FirstOrDefault()
        ?? throw new PgpException("Public key has no usable encryption key.");

    public PgpPublicKey? FindKey(long keyId) => Ring.GetPublicKey(keyId);

    public static PgpPublicKeys Parse(string armored)
    {
        using var input = PgpUtilities.GetDecoderStream(new MemoryStream(System.Text.Encoding.ASCII.GetBytes(armored)));
        var factory = new PgpObjectFactory(input);
        return factory.NextPgpObject() switch
        {
            PgpPublicKeyRing ring => new PgpPublicKeys(ring),
            PgpSecretKeyRing secret => new PgpPublicKeys(ToPublicRing(secret)),
            var other => throw new PgpException($"Expected a public key, got {other?.GetType().Name ?? "nothing"}."),
        };
    }

    private static PgpPublicKeyRing ToPublicRing(PgpSecretKeyRing secret)
    {
        using var ms = new MemoryStream();
        foreach (var key in secret.GetPublicKeys())
            key.Encode(ms);
        return new PgpPublicKeyRing(ms.ToArray());
    }
}

/// <summary>
/// One or more unlocked OpenPGP private keys. Passbolt v5 needs the user key plus shared
/// metadata keys, so decryption looks up the matching key by key id across all rings.
/// </summary>
public sealed class PgpKeyChain
{
    private readonly Dictionary<long, PgpPrivateKey> _privateKeys = new();

    private PgpKeyChain(PgpSecretKeyRing primary, PgpPrivateKey signingKey, PgpPublicKey signingPublicKey)
    {
        Primary = primary;
        SigningKey = signingKey;
        SigningPublicKey = signingPublicKey;
    }

    public PgpSecretKeyRing Primary { get; }
    public PgpPrivateKey SigningKey { get; }
    public PgpPublicKey SigningPublicKey { get; }

    public string Fingerprint => Convert.ToHexString(Primary.GetPublicKey().GetFingerprint());

    public PgpPublicKeys PublicKeys => PgpPublicKeys.Parse(ExportPublicArmored());

    internal bool TryGetPrivateKey(long keyId, out PgpPrivateKey key) => _privateKeys.TryGetValue(keyId, out key!);

    /// <summary>Unlocks an armored secret key with the given passphrase.</summary>
    /// <exception cref="PgpException">The passphrase is wrong or the key is invalid.</exception>
    public static PgpKeyChain Unlock(string armoredPrivateKey, string passphrase)
    {
        var ring = ReadSecretRing(armoredPrivateKey);
        var unlocked = UnlockRing(ring, passphrase);

        var signing = ring.GetSecretKeys().FirstOrDefault(k => k.IsSigningKey && k.IsMasterKey)
                      ?? ring.GetSecretKeys().FirstOrDefault(k => k.IsSigningKey)
                      ?? throw new PgpException("Private key has no signing key.");

        var chain = new PgpKeyChain(ring, unlocked[signing.KeyId], signing.PublicKey);
        foreach (var (id, key) in unlocked)
            chain._privateKeys[id] = key;
        return chain;
    }

    /// <summary>Adds another private key (e.g. a Passbolt shared metadata key) used only for decryption.</summary>
    public void AddDecryptionKey(string armoredPrivateKey, string passphrase)
    {
        foreach (var (id, key) in UnlockRing(ReadSecretRing(armoredPrivateKey), passphrase))
            _privateKeys.TryAdd(id, key);
    }

    public string ExportPublicArmored()
    {
        using var ms = new MemoryStream();
        using (var armor = new Org.BouncyCastle.Bcpg.ArmoredOutputStream(ms))
        {
            foreach (var key in Primary.GetPublicKeys())
                key.Encode(armor);
        }
        return System.Text.Encoding.ASCII.GetString(ms.ToArray());
    }

    private static PgpSecretKeyRing ReadSecretRing(string armored)
    {
        using var input = PgpUtilities.GetDecoderStream(new MemoryStream(System.Text.Encoding.ASCII.GetBytes(armored)));
        return new PgpObjectFactory(input).NextPgpObject() as PgpSecretKeyRing
               ?? throw new PgpException("Expected an OpenPGP private key block.");
    }

    private static Dictionary<long, PgpPrivateKey> UnlockRing(PgpSecretKeyRing ring, string passphrase)
    {
        var result = new Dictionary<long, PgpPrivateKey>();
        var chars = passphrase.ToCharArray();
        try
        {
            foreach (PgpSecretKey sk in ring.GetSecretKeys())
            {
                if (sk.IsPrivateKeyEmpty)
                    continue; // gnu-dummy stub (offline master key)
                result[sk.KeyId] = sk.ExtractPrivateKeyUtf8(chars);
            }
        }
        finally
        {
            Array.Clear(chars);
        }
        return result.Count > 0 ? result : throw new PgpException("Private key contains no usable secret keys.");
    }
}
