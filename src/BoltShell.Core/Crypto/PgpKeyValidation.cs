using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace BoltShell.Core.Crypto;

public enum PgpKeyUsage { Sign, Encrypt }

/// <summary>
/// Decides which keys of a certificate may be used, based only on cryptographically verified signatures
/// (RFC 9580 §10.1.3): a subkey counts only with a valid binding signature from the primary key, a signing subkey
/// additionally needs a valid embedded primary-key binding (back-signature). Revocation, expiry and key flags are
/// taken from verified signatures. This keeps fingerprint pinning meaningful: pinning the primary key also pins
/// every key that is actually used.
/// </summary>
internal static class PgpKeyValidation
{
    private const int KeyFlagSign = 0x02;
    private const int KeyFlagEncrypt = 0x04 | 0x08;

    /// <summary>Usable keys of <paramref name="ring"/> for <paramref name="usage"/>, subkeys first (newest first), primary last.</summary>
    public static IReadOnlyList<PgpPublicKey> UsableKeys(PgpPublicKeyRing ring, PgpKeyUsage usage, DateTime? now = null)
    {
        var at = now ?? DateTime.UtcNow;
        var primary = ring.GetPublicKey();
        if (IsRevoked(primary, primary, PgpSignature.KeyRevocation))
            return [];

        var result = new List<PgpPublicKey>();
        foreach (var key in ring.GetPublicKeys().Where(k => !k.IsMasterKey).OrderByDescending(k => k.CreationTime))
        {
            if (IsUsableSubkey(primary, key, usage, at))
                result.Add(key);
        }
        if (IsUsablePrimary(primary, usage, at))
            result.Add(primary);
        return result;
    }

    private static bool IsUsablePrimary(PgpPublicKey primary, PgpKeyUsage usage, DateTime at)
    {
        if (!AlgorithmSupports(primary, usage))
            return false;

        // Newest valid self-certification of a user ID (or a direct-key signature) carries flags and expiry.
        var selfSignature = SelfCertifications(primary).OrderByDescending(s => s.CreationTime).FirstOrDefault();
        if (selfSignature is null)
            return false;
        var hashed = selfSignature.GetHashedSubPackets();
        if (IsExpired(primary, hashed, at))
            return false;
        return !hashed.HasSubpacket(SignatureSubpacketTag.KeyFlags) || (hashed.GetKeyFlags() & Flags(usage)) != 0;
    }

    private static bool IsUsableSubkey(PgpPublicKey primary, PgpPublicKey subkey, PgpKeyUsage usage, DateTime at)
    {
        if (!AlgorithmSupports(subkey, usage) || IsRevoked(primary, subkey, PgpSignature.SubkeyRevocation))
            return false;

        var binding = subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding)
            .Where(s => s.KeyId == primary.KeyId && Verify(s, primary, () => s.VerifyCertification(primary, subkey)))
            .OrderByDescending(s => s.CreationTime)
            .FirstOrDefault();
        if (binding is null)
            return false; // unbound or bound by another primary key: never use it

        var hashed = binding.GetHashedSubPackets();
        if (IsExpired(subkey, hashed, at))
            return false;
        if (hashed.HasSubpacket(SignatureSubpacketTag.KeyFlags) && (hashed.GetKeyFlags() & Flags(usage)) == 0)
            return false;
        if (!hashed.HasSubpacket(SignatureSubpacketTag.KeyFlags) && usage == PgpKeyUsage.Sign)
            return false; // signing subkeys must say so explicitly

        if (usage == PgpKeyUsage.Sign)
        {
            // The subkey must also certify that it belongs to the primary key (primary key binding signature).
            var backSignatures = Items(binding.GetHashedSubPackets().GetEmbeddedSignatures())
                .Concat(Items(binding.GetUnhashedSubPackets()?.GetEmbeddedSignatures()));
            if (!backSignatures.Any(b => b.SignatureType == PgpSignature.PrimaryKeyBinding
                                         && b.KeyId == subkey.KeyId
                                         && Verify(b, subkey, () => b.VerifyCertification(primary, subkey))))
                return false;
        }
        return true;
    }

    private static IEnumerable<PgpSignature> SelfCertifications(PgpPublicKey primary)
    {
        foreach (var id in primary.GetUserIds())
        {
            foreach (PgpSignature signature in primary.GetSignaturesForId(id) ?? [])
            {
                if (signature.KeyId == primary.KeyId && signature.SignatureType is >= 0x10 and <= 0x13
                    && Verify(signature, primary, () => signature.VerifyCertification(id, primary)))
                    yield return signature;
            }
        }
        foreach (var signature in primary.GetSignaturesOfType(PgpSignature.DirectKey))
        {
            if (signature.KeyId == primary.KeyId && Verify(signature, primary, () => signature.VerifyCertification(primary)))
                yield return signature;
        }
    }

    private static bool IsRevoked(PgpPublicKey primary, PgpPublicKey key, int revocationType) =>
        key.GetSignaturesOfType(revocationType).Any(s => s.KeyId == primary.KeyId && Verify(s, primary,
            () => revocationType == PgpSignature.KeyRevocation ? s.VerifyCertification(key) : s.VerifyCertification(primary, key)));

    private static bool IsExpired(PgpPublicKey key, PgpSignatureSubpacketVector hashed, DateTime at)
    {
        var seconds = hashed.GetKeyExpirationTime();
        return seconds > 0 && key.CreationTime.ToUniversalTime().AddSeconds(seconds) <= at;
    }

    private static bool Verify(PgpSignature signature, PgpPublicKey signer, Func<bool> verify)
    {
        try
        {
            signature.InitVerify(signer);
            return verify();
        }
        catch (PgpException)
        {
            return false;
        }
    }

    private static IEnumerable<PgpSignature> Items(PgpSignatureList? list) =>
        list is null ? [] : Enumerable.Range(0, list.Count).Select(i => list[i]);

    private static int Flags(PgpKeyUsage usage) => usage == PgpKeyUsage.Sign ? KeyFlagSign : KeyFlagEncrypt;

    private static bool AlgorithmSupports(PgpPublicKey key, PgpKeyUsage usage) => usage switch
    {
        PgpKeyUsage.Encrypt => key.IsEncryptionKey,
        _ => key.Algorithm is PublicKeyAlgorithmTag.RsaGeneral or PublicKeyAlgorithmTag.RsaSign or PublicKeyAlgorithmTag.Dsa
            or PublicKeyAlgorithmTag.ECDsa or PublicKeyAlgorithmTag.EdDsa_Legacy or PublicKeyAlgorithmTag.Ed25519 or PublicKeyAlgorithmTag.Ed448,
    };
}
