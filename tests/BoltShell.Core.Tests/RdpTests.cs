using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using BoltShell.Core.Passbolt;
using BoltShell.Core.Rdp;
using BoltShell.Core.Ssh;

namespace BoltShell.Core.Tests;

public sealed class RdpTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "pbssh-rdp-" + Guid.NewGuid().ToString("N")[..8]);

    public RdpTests() => Directory.CreateDirectory(_dir);

    [Theory]
    [InlineData("rdp://win01", "win01", 3389, null, null)]
    [InlineData("rdp://admin@win01:3390", "win01", 3390, "admin", null)]
    [InlineData("rdp://CORP\\admin@10.0.0.5", "10.0.0.5", 3389, "admin", "CORP")]
    [InlineData("rdp://CORP%5Cadmin@win01", "win01", 3389, "admin", "CORP")]
    [InlineData("rdp://[2001:db8::5]:3391", "2001:db8::5", 3391, null, null)]
    [InlineData("RDP://win01:22", "win01", 22, null, null)]
    public void RdpTarget_Parses(string uri, string host, int port, string? user, string? domain)
    {
        Assert.True(RdpTarget.TryParse(uri, out var target));
        Assert.Equal(new RdpTarget(host, port, user, domain), target);
    }

    [Theory]
    [InlineData("ssh://win01")]
    [InlineData("win01:3389")]
    [InlineData("rdp://")]
    public void RdpTarget_Rejects(string uri) => Assert.False(RdpTarget.TryParse(uri, out _));

    [Fact]
    public void Mapper_UsesUriUserFieldsAndPins()
    {
        var resource = new PassboltResource("r", "win01", "CORP\\fallback", ["rdp://win01"], null, null, null, null,
            [new("f1", RdpConnectionMapper.CertificateField, null), new("f2", RdpConnectionMapper.DomainField, null)]);
        var hex = "AB:CD" + string.Concat(Enumerable.Repeat(":00", 30));
        var spec = RdpConnectionMapper.Map(resource, new PassboltSecret("pw", null, new Dictionary<string, string> { ["f1"] = hex, ["f2"] = "OTHER" }));

        Assert.Equal("fallback", spec.Username);
        Assert.Equal("OTHER", spec.Domain); // the custom field beats the username prefix
        Assert.Equal("pw", spec.Password);
        Assert.Equal(Convert.ToBase64String(Convert.FromHexString(hex.Replace(":", ""))).TrimEnd('='), Assert.Single(spec.CertificateFingerprints));
    }

    [Fact]
    public void RdCleanPath_RoundTrips()
    {
        var pdu = new RdCleanPathPdu
        {
            Destination = "win01:3389", ProxyAuth = "token", X224ConnectionPdu = [3, 0, 0, 5, 1],
            ServerCertChain = [[1, 2], [3]], ServerAddr = "10.0.0.5:3389",
            Error = new RdCleanPathError(1, HttpStatusCode: 403),
        };
        var encoded = pdu.Encode();

        Assert.Equal(encoded.Length, RdCleanPathPdu.CompleteLength(encoded));
        Assert.Null(RdCleanPathPdu.CompleteLength(encoded.AsSpan(0, encoded.Length - 1)));
        var decoded = RdCleanPathPdu.Decode(encoded);
        Assert.Equal(3390, decoded.Version);
        Assert.Equal("win01:3389", decoded.Destination);
        Assert.Equal("token", decoded.ProxyAuth);
        Assert.Equal([3, 0, 0, 5, 1], decoded.X224ConnectionPdu);
        Assert.Equal(2, decoded.ServerCertChain!.Count);
        Assert.Equal(new RdCleanPathError(1, 403), decoded.Error);
    }

    [Fact]
    public async Task Proxy_NegotiatesX224_Tls_AndRelays()
    {
        using var cert = CreateCertificate();
        await using var server = new FakeRdpServer(cert);
        var prompts = 0;
        await using var proxy = new RdpProxy(new KnownHostsStore(Path.Combine(_dir, "kh.json")), NullLogger<RdpProxy>.Instance)
        {
            CertificatePrompt = _ => { prompts++; return Task.FromResult(true); },
        };
        var session = proxy.Register(Spec(server.Port));

        using var ws = await ConnectAsync(session);
        await SendAsync(ws, new RdCleanPathPdu { Destination = session.Spec.Target.Destination, ProxyAuth = session.Token, X224ConnectionPdu = FakeRdpServer.X224Request });
        var response = RdCleanPathPdu.Decode(await ReceiveAsync(ws));

        Assert.Null(response.Error);
        Assert.Equal(FakeRdpServer.X224Response, response.X224ConnectionPdu);
        Assert.Equal(cert.RawData, response.ServerCertChain![0]);
        Assert.Equal($"127.0.0.1:{server.Port}", response.ServerAddr);
        Assert.Equal(1, prompts);

        // After the handshake the proxy relays the (TLS-protected) stream in both directions.
        await ws.SendAsync("ping"u8.ToArray(), WebSocketMessageType.Binary, true, CancellationToken.None);
        Assert.Equal("pong:ping"u8.ToArray(), await ReceiveAsync(ws));
    }

    [Fact]
    public async Task Proxy_RepeatedConnectionsToSameServer_EachRelay()
    {
        // Reconnects reuse the session id and target; each one must get a working TLS stream (no resumption issues).
        using var cert = CreateCertificate();
        await using var server = new FakeRdpServer(cert);
        await using var proxy = new RdpProxy(new KnownHostsStore(Path.Combine(_dir, "kh.json")), NullLogger<RdpProxy>.Instance)
        {
            CertificatePrompt = _ => Task.FromResult(true),
        };
        var session = proxy.Register(Spec(server.Port));
        for (var i = 0; i < 3; i++)
        {
            using var ws = await ConnectAsync(session);
            await SendAsync(ws, new RdCleanPathPdu { Destination = session.Spec.Target.Destination, ProxyAuth = session.Token, X224ConnectionPdu = FakeRdpServer.X224Request });
            Assert.Null(RdCleanPathPdu.Decode(await ReceiveAsync(ws)).Error);
            await ws.SendAsync(System.Text.Encoding.ASCII.GetBytes($"n{i}"), WebSocketMessageType.Binary, true, CancellationToken.None);
            Assert.Equal(System.Text.Encoding.ASCII.GetBytes($"pong:n{i}"), await ReceiveAsync(ws));
        }
    }

    [Fact]
    public void Describe_ShowsInnerErrors()
    {
        var ex = new IOException("The decryption operation failed, see inner exception.", new System.ComponentModel.Win32Exception(unchecked((int)0x80090330)));
        Assert.Contains(" → ", RdpProxy.Describe(ex));
        Assert.Contains("0x80090330", RdpProxy.Describe(ex));
    }

    [Fact]
    public async Task Proxy_RejectsWrongToken_WrongDestination_AndUnpinnedCertificate()
    {
        using var cert = CreateCertificate();
        await using var server = new FakeRdpServer(cert);
        await using var proxy = new RdpProxy(new KnownHostsStore(Path.Combine(_dir, "kh.json")), NullLogger<RdpProxy>.Instance)
        {
            CertificatePrompt = _ => Task.FromResult(true),
        };

        var session = proxy.Register(Spec(server.Port));
        Assert.Equal(403, (await HandshakeAsync(session, token: "wrong")).Error?.HttpStatusCode);
        Assert.Equal(403, (await HandshakeAsync(session, destination: "evil.example:3389")).Error?.HttpStatusCode);

        // A Passbolt pin that does not match is refused without asking.
        var pinned = proxy.Register(Spec(server.Port) with { CertificateFingerprints = ["AAAAnotthecert"] });
        Assert.Equal(495, (await HandshakeAsync(pinned)).Error?.HttpStatusCode);
        var fingerprint = Convert.ToBase64String(SHA256.HashData(cert.RawData)).TrimEnd('=');
        var observed = proxy.Observed(pinned.Id)!;
        Assert.True(observed.Mismatch);
        Assert.Equal(fingerprint, observed.FingerprintSha256);
        Assert.Equal(["AAAAnotthecert"], observed.Expected);

        // The matching pin is accepted.
        var good = proxy.Register(Spec(server.Port) with { CertificateFingerprints = [fingerprint] });
        Assert.Null((await HandshakeAsync(good)).Error);
    }

    [Fact]
    public async Task Proxy_ReportsUnreachableTarget()
    {
        await using var proxy = new RdpProxy(new KnownHostsStore(Path.Combine(_dir, "kh.json")), NullLogger<RdpProxy>.Instance);
        var free = new TcpListener(IPAddress.Loopback, 0);
        free.Start();
        var port = ((IPEndPoint)free.LocalEndpoint).Port;
        free.Stop();

        var response = await HandshakeAsync(proxy.Register(Spec(port)));
        Assert.NotNull(response.Error?.WsaLastError);
    }

    [Fact]
    public async Task Probe_ReturnsServerCertificate()
    {
        using var cert = CreateCertificate();
        await using var server = new FakeRdpServer(cert);

        var result = await RdpProbe.GetCertificateAsync(new RdpTarget("127.0.0.1", server.Port));

        Assert.Equal("CN=fake-rdp", result.Subject);
        Assert.Equal(Convert.ToBase64String(SHA256.HashData(cert.RawData)).TrimEnd('='), result.FingerprintSha256);
        Assert.Equal(RdpConnectionMapper.NormalizeFingerprint(result.FingerprintHex), result.FingerprintSha256);
    }

    [Fact]
    public void NewRdpHost_FollowsConvention_AndRoundTripsThroughMapper()
    {
        var host = new NewRdpHost("dc01", new RdpTarget("dc01.lab.local", 3390), "admin", "LAB", "pw",
            new RdpServerCertificate("CN=dc01", "Zm9vYmFy", "66:6F", DateTime.UtcNow));
        var resource = host.ToResource("folder");

        Assert.Equal(["rdp://LAB%5Cadmin@dc01.lab.local:3390"], resource.Uris);
        Assert.Equal("pw", resource.Password);
        Assert.Equal("folder", resource.FolderId);

        // What Passbolt stores maps back to the same connection.
        var stored = new PassboltResource("id", resource.Name, resource.Username, resource.Uris, null, null, null, null,
            [new("f", RdpConnectionMapper.CertificateField, null)]);
        var spec = RdpConnectionMapper.Map(stored, new PassboltSecret("pw", null, new Dictionary<string, string> { ["f"] = "Zm9vYmFy" }));
        Assert.Equal(("admin", "LAB", 3390, "Zm9vYmFy"), (spec.Username, spec.Domain, spec.Target.Port, spec.CertificateFingerprints.Single()));
    }

    private static RdpConnectionSpec Spec(int port) => new("test", new RdpTarget("127.0.0.1", port), "user", null, "pw", []);

    private static async Task<RdCleanPathPdu> HandshakeAsync(RdpProxySession session, string? token = null, string? destination = null)
    {
        using var ws = await ConnectAsync(session);
        await SendAsync(ws, new RdCleanPathPdu
        {
            Destination = destination ?? session.Spec.Target.Destination,
            ProxyAuth = token ?? session.Token,
            X224ConnectionPdu = FakeRdpServer.X224Request,
        });
        return RdCleanPathPdu.Decode(await ReceiveAsync(ws));
    }

    private static async Task<ClientWebSocket> ConnectAsync(RdpProxySession session)
    {
        var ws = new ClientWebSocket();
        ws.Options.AddSubProtocol("binary");
        await ws.ConnectAsync(new Uri(session.ProxyAddress), CancellationToken.None);
        return ws;
    }

    private static Task SendAsync(WebSocket ws, RdCleanPathPdu pdu) =>
        ws.SendAsync(pdu.Encode(), WebSocketMessageType.Binary, true, CancellationToken.None);

    private static async Task<byte[]> ReceiveAsync(WebSocket ws)
    {
        var buffer = new byte[64 * 1024];
        using var ms = new MemoryStream();
        WebSocketReceiveResult result;
        do
        {
            result = await ws.ReceiveAsync(buffer, new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token);
            ms.Write(buffer, 0, result.Count);
        } while (!result.EndOfMessage);
        return ms.ToArray();
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=fake-rdp", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
    }

    /// <summary>Speaks just enough RDP: answers the X.224 request in clear text, then TLS, then echoes "pong:" + data.</summary>
    private sealed class FakeRdpServer : IAsyncDisposable
    {
        public static readonly byte[] X224Request = [3, 0, 0, 11, 6, 0xE0, 0, 0, 0, 0, 0];
        public static readonly byte[] X224Response = [3, 0, 0, 11, 6, 0xD0, 0, 0, 0x12, 0x34, 0];

        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly X509Certificate2 _cert;
        private readonly CancellationTokenSource _cts = new();

        public FakeRdpServer(X509Certificate2 cert)
        {
            _cert = cert;
            _listener.Start();
            _ = AcceptAsync();
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        private async Task AcceptAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_cts.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                _ = Task.Run(async () =>
                {
                    using var _ = client;
                    var stream = client.GetStream();
                    var header = new byte[4];
                    await stream.ReadExactlyAsync(header);
                    Assert.Equal(3, header[0]);
                    await stream.ReadExactlyAsync(new byte[System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2)) - 4]);
                    await stream.WriteAsync(X224Response);
                    await using var tls = new SslStream(stream);
                    await tls.AuthenticateAsServerAsync(_cert);
                    var buffer = new byte[1024];
                    int read;
                    while ((read = await tls.ReadAsync(buffer)) > 0)
                    {
                        await tls.WriteAsync("pong:"u8.ToArray().Concat(buffer[..read]).ToArray());
                        await tls.FlushAsync();
                    }
                });
            }
        }

        public ValueTask DisposeAsync()
        {
            _cts.Cancel();
            _listener.Stop();
            return ValueTask.CompletedTask;
        }
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);
}
