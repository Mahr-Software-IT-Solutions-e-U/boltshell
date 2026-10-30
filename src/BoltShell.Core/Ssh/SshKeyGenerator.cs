using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BoltShell.Core.Ssh;

/// <summary>A generated SSH key pair in OpenSSH formats.</summary>
/// <param name="PrivateKey">Unencrypted <c>-----BEGIN OPENSSH PRIVATE KEY-----</c> block.</param>
/// <param name="PublicKey">authorized_keys line: <c>ssh-ed25519 AAAA… comment</c>.</param>
/// <param name="FingerprintSha256">As printed by <c>ssh-keygen -l</c>, without the <c>SHA256:</c> prefix.</param>
public sealed record SshKeyPair(string PrivateKey, string PublicKey, string FingerprintSha256);

/// <summary>Generates Ed25519 keys in the <c>openssh-key-v1</c> format understood by OpenSSH and SSH.NET.</summary>
public static class SshKeyGenerator
{
    private const string KeyType = "ssh-ed25519";

    public static SshKeyPair GenerateEd25519(string comment)
    {
        if (comment.Any(c => char.IsControl(c)))
            throw new ArgumentException("Comment must not contain control characters.", nameof(comment));

        var privateParams = new Ed25519PrivateKeyParameters(new SecureRandom());
        var seed = privateParams.GetEncoded();          // 32 bytes
        var publicKey = privateParams.GeneratePublicKey().GetEncoded(); // 32 bytes

        var publicBlob = new SshWriter().String(KeyType).Bytes(publicKey).ToArray();

        // Private section: two equal check ints, the key, the comment, then padding 1,2,3… to the cipher block size (8 for "none").
        var check = RandomNumberGenerator.GetInt32(int.MaxValue);
        var section = new SshWriter()
            .UInt32((uint)check).UInt32((uint)check)
            .String(KeyType)
            .Bytes(publicKey)
            .Bytes([.. seed, .. publicKey])               // OpenSSH stores seed || public key
            .String(comment);
        for (byte pad = 1; section.Length % 8 != 0; pad++)
            section.Raw([pad]);

        var blob = new SshWriter()
            .Raw(Encoding.ASCII.GetBytes("openssh-key-v1\0"))
            .String("none")      // cipher
            .String("none")      // kdf
            .Bytes([])           // kdf options
            .UInt32(1)           // number of keys
            .Bytes(publicBlob)
            .Bytes(section.ToArray())
            .ToArray();

        CryptographicOperations.ZeroMemory(seed);

        var base64 = Convert.ToBase64String(blob);
        var pem = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for (var i = 0; i < base64.Length; i += 70)
            pem.Append(base64, i, Math.Min(70, base64.Length - i)).Append('\n');
        pem.Append("-----END OPENSSH PRIVATE KEY-----\n");

        var publicLine = $"{KeyType} {Convert.ToBase64String(publicBlob)}" + (comment.Length > 0 ? " " + comment : "");
        var fingerprint = Convert.ToBase64String(SHA256.HashData(publicBlob)).TrimEnd('=');
        return new SshKeyPair(pem.ToString(), publicLine, fingerprint);
    }

    /// <summary>Builds a known_hosts-style public key line from a raw SSH host key blob.</summary>
    public static string HostKeyLine(byte[] hostKeyBlob)
    {
        // The blob starts with the key type as an SSH string (e.g. "ssh-rsa", even if the negotiated algorithm was rsa-sha2-512).
        var length = (int)BinaryPrimitives.ReadUInt32BigEndian(hostKeyBlob);
        var type = Encoding.ASCII.GetString(hostKeyBlob, 4, length);
        return $"{type} {Convert.ToBase64String(hostKeyBlob)}";
    }

    private sealed class SshWriter
    {
        private readonly MemoryStream _stream = new();

        public long Length => _stream.Length;

        public SshWriter UInt32(uint value)
        {
            Span<byte> buffer = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
            _stream.Write(buffer);
            return this;
        }

        public SshWriter Bytes(byte[] value) => UInt32((uint)value.Length).Raw(value);

        public SshWriter String(string value) => Bytes(Encoding.UTF8.GetBytes(value));

        public SshWriter Raw(byte[] value)
        {
            _stream.Write(value);
            return this;
        }

        public byte[] ToArray() => _stream.ToArray();
    }
}
