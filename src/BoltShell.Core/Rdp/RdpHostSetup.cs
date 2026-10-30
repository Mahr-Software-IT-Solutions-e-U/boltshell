using System.Buffers.Binary;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BoltShell.Core.Passbolt;
using static BoltShell.Core.Localization.Texts;

namespace BoltShell.Core.Rdp;

/// <summary>The TLS certificate an RDP server presents (fetched without logging in).</summary>
/// <param name="FingerprintSha256">Unpadded base64, the format stored in <c>rdp_cert_sha256</c>.</param>
public sealed record RdpServerCertificate(string Subject, string FingerprintSha256, string FingerprintHex, DateTime NotAfter);

/// <summary>Data for a new RDP host in Passbolt.</summary>
public sealed record NewRdpHost(string Name, RdpTarget Target, string Username, string? Domain, string Password, RdpServerCertificate? Certificate)
{
    /// <summary>
    /// The Passbolt resource following the convention: <c>rdp://[DOMAIN%5C]user@host[:port]</c> (the domain lives in the
    /// URI so it also works without custom fields), password field, and <c>rdp_cert_sha256</c> when a certificate was fetched.
    /// </summary>
    public NewResource ToResource(string? folderId)
    {
        var user = Uri.EscapeDataString(Domain is { Length: > 0 } d ? $"{d}\\{Username}" : Username);
        var host = Target.Host.Contains(':') ? $"[{Target.Host}]" : Target.Host;
        var uri = $"rdp://{user}@{host}" + (Target.Port == 3389 ? "" : $":{Target.Port}");
        var fields = Certificate is null
            ? new List<NewCustomField>()
            : [new(RdpConnectionMapper.CertificateField, Certificate.FingerprintSha256)];
        return new NewResource(Name, Domain is { Length: > 0 } dom ? $"{dom}\\{Username}" : Username, [uri], Password, folderId, fields,
            $"Angelegt mit BoltShell am {DateTime.Now:dd.MM.yyyy}.");
    }
}

public static class RdpProbe
{
    // TPKT + X.224 Connection Request + RDP_NEG_REQ asking for TLS | CredSSP (no cookie).
    private static readonly byte[] ConnectionRequest =
        [3, 0, 0, 19, 14, 0xE0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0];

    /// <summary>
    /// Connects, negotiates TLS and returns the server certificate, without authenticating.
    /// Throws if the server is unreachable or does not offer TLS-based security.
    /// </summary>
    public static async Task<RdpServerCertificate> GetCertificateAsync(RdpTarget target, CancellationToken ct = default)
    {
        using var tcp = new TcpClient();
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            await tcp.ConnectAsync(target.Host, target.Port, timeout.Token);
        }
        var stream = tcp.GetStream();
        await stream.WriteAsync(ConnectionRequest, ct);

        var header = new byte[4];
        await stream.ReadExactlyAsync(header, ct);
        if (header[0] != 3)
            throw new InvalidDataException(Tr("The server does not respond like an RDP server."));
        var confirm = new byte[BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2)) - 4];
        await stream.ReadExactlyAsync(confirm, ct);
        if (RdpProxy.X224NegotiationFailure([.. header, .. confirm]) is { } failure)
            throw new InvalidOperationException(Tr("The server does not offer TLS/NLA (RDP_NEG_FAILURE {0}).", failure));

        X509Certificate2? certificate = null;
        await using var tls = new SslStream(stream, leaveInnerStreamOpen: false);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = target.Host,
            AllowTlsResume = false,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = (_, cert, _, _) =>
            {
                certificate = cert is null ? null : new X509Certificate2(cert);
                return cert is not null;
            },
        }, ct);

        if (certificate is null)
            throw new InvalidOperationException(Tr("The server did not send a certificate."));
        var hash = SHA256.HashData(certificate.RawData);
        return new RdpServerCertificate(
            certificate.Subject,
            Convert.ToBase64String(hash).TrimEnd('='),
            string.Join(':', hash.Select(b => b.ToString("X2"))),
            certificate.NotAfter);
    }
}
