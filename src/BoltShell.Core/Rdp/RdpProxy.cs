using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using BoltShell.Core.Ssh;

namespace BoltShell.Core.Rdp;

/// <summary>A registered RDP session: where the web client connects and how it authenticates to the proxy.</summary>
public sealed record RdpProxySession(string Id, string Token, string ProxyAddress, RdpConnectionSpec Spec);

/// <summary>The certificate an RDP server presented, and whether it contradicted the Passbolt pin.</summary>
/// <param name="FingerprintSha256">Unpadded base64, the format of <c>rdp_cert_sha256</c>.</param>
/// <param name="Expected">Fingerprints pinned in Passbolt (empty if none).</param>
public sealed record RdpCertificateObservation(string FingerprintSha256, string? Subject, IReadOnlyList<string> Expected)
{
    public bool Pinned => Expected.Count > 0;
    public bool Mismatch => Pinned && !Expected.Contains(FingerprintSha256);
}

/// <summary>
/// Local RDCleanPath proxy for the IronRDP web client running in the app's WebView.
/// Listens on 127.0.0.1 only; each session gets a random token and is bound to one destination.
/// The proxy forwards the client's X.224 request, performs the TLS handshake with the RDP server (verifying the
/// certificate against Passbolt pins or the local trust store), returns the certificate chain to the client for
/// CredSSP and then relays the RDP stream. Credentials never pass through here – the web client handles NLA.
/// </summary>
public sealed class RdpProxy(KnownHostsStore trustStore, ILogger<RdpProxy> logger) : IAsyncDisposable
{
    /// <summary>Algorithm name of RDP certificates in the local trust store (persisted, therefore not translated).</summary>
    public const string CertificateAlgorithm = "TLS-Zertifikat";

    private const string WebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private readonly ConcurrentDictionary<string, RdpProxySession> _sessions = new();
    private readonly ConcurrentDictionary<string, RdpCertificateObservation> _observed = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Lock _startLock = new();
    private TcpListener? _listener;

    /// <summary>Asked for unknown or changed server certificates (when Passbolt has no pin). Without it they are rejected.</summary>
    public Func<HostKeyInfo, Task<bool>>? CertificatePrompt { get; set; }

    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);

    public RdpProxySession Register(RdpConnectionSpec spec)
    {
        var port = EnsureStarted();
        var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var session = new RdpProxySession(id, token, $"ws://127.0.0.1:{port}/rdp/{id}", spec);
        _sessions[id] = session;
        return session;
    }

    public void Unregister(string sessionId)
    {
        _sessions.TryRemove(sessionId, out _);
        _observed.TryRemove(sessionId, out _);
    }

    /// <summary>The certificate seen on the last connect of a session, if it got that far.</summary>
    public RdpCertificateObservation? Observed(string sessionId) => _observed.GetValueOrDefault(sessionId);

    /// <summary>Replaces the connection data of a registered session (e.g. to drop or refresh credentials).</summary>
    public RdpProxySession Update(RdpProxySession session, RdpConnectionSpec spec)
    {
        var updated = session with { Spec = spec };
        if (_sessions.ContainsKey(session.Id))
            _sessions[session.Id] = updated;
        return updated;
    }

    private int EnsureStarted()
    {
        lock (_startLock)
        {
            if (_listener is null)
            {
                _listener = new TcpListener(IPAddress.Loopback, 0);
                _listener.Start();
                _ = AcceptLoopAsync(_listener);
            }
            return ((IPEndPoint)_listener.LocalEndpoint).Port;
        }
    }

    private async Task AcceptLoopAsync(TcpListener listener)
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(_cts.Token);
            }
            catch (Exception) when (_cts.IsCancellationRequested)
            {
                return;
            }
            _ = Task.Run(() => HandleClientAsync(client));
        }
    }

    private async Task HandleClientAsync(TcpClient client)
    {
        using var _ = client;
        var ct = _cts.Token;
        WebSocket? ws = null;
        try
        {
            var stream = client.GetStream();
            var (path, key, protocols) = await ReadUpgradeRequestAsync(stream, ct);
            var sessionId = path.StartsWith("/rdp/", StringComparison.Ordinal) ? path[5..] : "";
            if (key is null || !_sessions.TryGetValue(sessionId, out var session))
            {
                await stream.WriteAsync("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(), ct);
                return;
            }

            var subProtocol = protocols.Contains("binary") ? "binary" : null;
            var accept = Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(key + WebSocketGuid)));
            var response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                           $"Sec-WebSocket-Accept: {accept}\r\n" + (subProtocol is null ? "" : $"Sec-WebSocket-Protocol: {subProtocol}\r\n") + "\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(response), ct);
            ws = WebSocket.CreateFromStream(stream, new WebSocketCreationOptions
            {
                IsServer = true,
                SubProtocol = subProtocol,
                KeepAliveInterval = TimeSpan.FromSeconds(30),
            });

            await HandleSessionAsync(ws, session, ct);
        }
        catch (Exception ex) when (ex is IOException or WebSocketException or OperationCanceledException or SocketException)
        {
            logger.LogInformation(ex, "RDP proxy connection ended: {Message}", ex.Message);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "RDP proxy connection failed");
        }
        finally
        {
            // Always send a close frame; a missing one shows up in the web client as "WebSocket Closed: code 1006".
            if (ws is { State: WebSocketState.Open or WebSocketState.CloseReceived })
            {
                try
                {
                    await ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "closed", CancellationToken.None);
                }
                catch (Exception)
                {
                }
            }
            ws?.Dispose();
        }
    }

    private async Task HandleSessionAsync(WebSocket ws, RdpProxySession session, CancellationToken ct)
    {
        var request = RdCleanPathPdu.Decode(await ReceivePduAsync(ws, ct));
        var target = session.Spec.Target;
        logger.LogInformation("RDP {Session}: request for {Destination}, X.224 {Length} bytes", session.Id, request.Destination, request.X224ConnectionPdu?.Length);
        if (request.Version != RdCleanPathPdu.Version1 || request.X224ConnectionPdu is null)
        {
            logger.LogWarning("RDP {Session}: unsupported RDCleanPath version {Version}", session.Id, request.Version);
            await SendErrorAsync(ws, new RdCleanPathError(RdCleanPathPdu.GeneralError, HttpStatusCode: 400), ct);
            return;
        }
        // Only the web client of this app session knows the token; the destination cannot be changed by it.
        if (!FixedTimeEquals(request.ProxyAuth, session.Token) ||
            !string.Equals(request.Destination, target.Destination, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning("RDP {Session}: rejected (token or destination mismatch: {Destination})", session.Id, request.Destination);
            await SendErrorAsync(ws, new RdCleanPathError(RdCleanPathPdu.GeneralError, HttpStatusCode: 403), ct);
            return;
        }

        using var tcp = new TcpClient();
        SslStream? tls = null;
        var step = "connect";
        try
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(ConnectTimeout);
                await tcp.ConnectAsync(target.Host, target.Port, timeout.Token);
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                var wsa = ex is SocketException se ? se.ErrorCode : (int)SocketError.TimedOut;
                logger.LogWarning("RDP {Session}: {Destination} unreachable: {Error}", session.Id, target.Destination, ex.Message);
                await SendErrorAsync(ws, new RdCleanPathError(103, WsaLastError: (ushort)wsa), ct); // TARGET_UNREACHABLE
                return;
            }
            tcp.NoDelay = true;
            var network = tcp.GetStream();
            logger.LogInformation("RDP {Session}: TCP connected to {Remote}", session.Id, tcp.Client.RemoteEndPoint);

            // X.224 negotiation happens in clear text before TLS.
            step = "X.224";
            await network.WriteAsync(request.X224ConnectionPdu, ct);
            var x224Response = await ReadTpktAsync(network, ct);
            logger.LogInformation("RDP {Session}: X.224 response {Length} bytes: {Hex}", session.Id, x224Response.Length, Convert.ToHexString(x224Response));
            if (X224NegotiationFailure(x224Response) is { } failure)
            {
                logger.LogWarning("RDP {Session}: server refused the requested security protocol (RDP_NEG_FAILURE {Code})", session.Id, failure);
                await SendPduAsync(ws, new RdCleanPathPdu
                {
                    Error = new RdCleanPathError(RdCleanPathPdu.NegotiationError),
                    X224ConnectionPdu = x224Response,
                }, ct);
                await ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "negotiation failed", ct);
                return;
            }

            step = "TLS";
            X509Certificate2? leaf = null;
            var chain = new List<byte[]>();
            tls = new SslStream(network, leaveInnerStreamOpen: false);
            try
            {
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = target.Host,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    // Every connection needs a full handshake: with Windows (SChannel) session resumption, follow-up
                    // connections to the same RDP server failed with "decryption operation failed" right after the
                    // first CredSSP message. A full handshake also guarantees a fresh server certificate for CredSSP.
                    AllowTlsResume = false,
                    // RDP servers usually use self-signed certificates; identity is checked below by fingerprint.
                    RemoteCertificateValidationCallback = (_, certificate, x509Chain, _) =>
                    {
                        if (certificate is null)
                            return false;
                        leaf = new X509Certificate2(certificate);
                        chain.Add(leaf.RawData);
                        foreach (var element in x509Chain?.ChainElements.Skip(1) ?? [])
                            chain.Add(element.Certificate.RawData);
                        return true;
                    },
                }, ct);
            }
            catch (Exception ex) when (ex is AuthenticationException or IOException)
            {
                logger.LogWarning(ex, "RDP {Session}: TLS handshake with {Destination} failed", session.Id, target.Destination);
                await SendErrorAsync(ws, new RdCleanPathError(105), ct); // TLS_HANDSHAKE_FAILED
                return;
            }
            logger.LogInformation("RDP {Session}: TLS {Protocol} {Cipher}, certificate {Subject}", session.Id, tls.SslProtocol, tls.NegotiatedCipherSuite, leaf?.Subject);

            step = "certificate";
            if (leaf is null || !await VerifyCertificateAsync(session, leaf))
            {
                logger.LogWarning("RDP {Session}: server certificate not accepted", session.Id);
                await SendErrorAsync(ws, new RdCleanPathError(RdCleanPathPdu.GeneralError, HttpStatusCode: 495), ct);
                return;
            }

            step = "response";
            var remote = (IPEndPoint)tcp.Client.RemoteEndPoint!;
            await SendPduAsync(ws, new RdCleanPathPdu
            {
                X224ConnectionPdu = x224Response,
                ServerCertChain = chain,
                ServerAddr = remote.Address.IsIPv4MappedToIPv6 ? $"{remote.Address.MapToIPv4()}:{remote.Port}" : remote.ToString(),
            }, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Anything unexpected before the relay: tell the client why instead of dropping the socket.
            logger.LogWarning(ex, "RDP {Session}: failed during {Step}", session.Id, step);
            try
            {
                await SendErrorAsync(ws, new RdCleanPathError(RdCleanPathPdu.GeneralError, HttpStatusCode: 502), ct);
            }
            catch (Exception)
            {
            }
            if (tls is not null)
                await tls.DisposeAsync();
            return;
        }

        logger.LogInformation("RDP {Session}: relaying", session.Id);
        await using (tls)
        {
            var (up, down, reason) = await RelayAsync(ws, tls!, ct);
            logger.LogInformation("RDP {Session}: relay ended ({Reason}); client→server {Up} bytes, server→client {Down} bytes",
                session.Id, reason, up, down);
        }
    }

    /// <summary>Returns the failure code if the X.224 Connection Confirm carries an RDP_NEG_FAILURE (type 3).</summary>
    internal static int? X224NegotiationFailure(byte[] tpkt)
    {
        // TPKT(4) + X.224 CC header (LI byte + 6) = 11 bytes, then optional RDP_NEG_RSP/FAILURE (type, flags, length(2), code(4)).
        const int negotiationOffset = 11;
        if (tpkt.Length < negotiationOffset + 8 || tpkt[negotiationOffset] != 3)
            return null;
        return BinaryPrimitives.ReadInt32LittleEndian(tpkt.AsSpan(negotiationOffset + 4));
    }

    /// <summary>Passbolt pin (<c>rdp_cert_sha256</c>) is authoritative; otherwise trust on first use with a prompt.</summary>
    private async Task<bool> VerifyCertificateAsync(RdpProxySession session, X509Certificate2 certificate)
    {
        var spec = session.Spec;
        var fingerprint = Convert.ToBase64String(SHA256.HashData(certificate.RawData)).TrimEnd('=');
        var observation = new RdpCertificateObservation(fingerprint, certificate.Subject, spec.CertificateFingerprints);
        _observed[session.Id] = observation;
        if (observation.Pinned)
        {
            var ok = !observation.Mismatch;
            if (!ok)
                logger.LogWarning("RDP certificate of {Target} (SHA256:{Fingerprint}) does not match Passbolt", spec.Target.Destination, fingerprint);
            return ok;
        }

        var info = trustStore.Check(spec.Target.CertificateId, CertificateAlgorithm, fingerprint);
        if (info.Status == HostKeyStatus.Trusted)
            return true;
        var accepted = CertificatePrompt is { } prompt && await prompt(info);
        if (accepted)
            trustStore.Trust(info);
        return accepted;
    }

    private static async Task<(long Up, long Down, string Reason)> RelayAsync(WebSocket ws, Stream server, CancellationToken ct)
    {
        long up = 0, down = 0;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var toServer = Task.Run(async () =>
        {
            var buffer = new byte[64 * 1024];
            while (ws.State == WebSocketState.Open)
            {
                var result = await ws.ReceiveAsync(buffer, linked.Token);
                if (result.MessageType == WebSocketMessageType.Close)
                    return "client closed";
                await server.WriteAsync(buffer.AsMemory(0, result.Count), linked.Token);
                await server.FlushAsync(linked.Token);
                up += result.Count;
            }
            return "client gone";
        }, linked.Token);
        var toClient = Task.Run(async () =>
        {
            var buffer = new byte[64 * 1024];
            int read;
            while ((read = await server.ReadAsync(buffer, linked.Token)) > 0)
            {
                await ws.SendAsync(buffer.AsMemory(0, read), WebSocketMessageType.Binary, true, linked.Token);
                down += read;
            }
            return "server closed";
        }, linked.Token);

        var finished = await Task.WhenAny(toServer, toClient);
        var reason = finished.IsFaulted ? Describe(finished.Exception!.InnerException ?? finished.Exception) : finished.Result;
        await linked.CancelAsync();
        if (ws.State == WebSocketState.Open)
        {
            try
            {
                await ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "closed", CancellationToken.None);
            }
            catch (WebSocketException)
            {
            }
        }
        return (up, down, reason);
    }

    /// <summary>"outer → inner → innermost" messages, so logs show e.g. the SChannel error behind an IOException.</summary>
    internal static string Describe(Exception exception)
    {
        var messages = new List<string>();
        for (var e = exception; e is not null; e = e.InnerException)
            messages.Add(e is System.ComponentModel.Win32Exception win32 ? $"{win32.Message} (0x{win32.NativeErrorCode:X8})" : e.Message);
        return string.Join(" → ", messages.Distinct());
    }

    private static async Task<byte[]> ReceivePduAsync(WebSocket ws, CancellationToken ct)
    {
        var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        while (true)
        {
            var result = await ws.ReceiveAsync(chunk, ct);
            if (result.MessageType == WebSocketMessageType.Close)
                throw new WebSocketException("Client closed before sending the RDCleanPath request.");
            buffer.Write(chunk, 0, result.Count);
            if (buffer.Length > 64 * 1024)
                throw new InvalidDataException("RDCleanPath request too large.");
            if (RdCleanPathPdu.CompleteLength(buffer.GetBuffer().AsSpan(0, (int)buffer.Length)) is { } length)
                return buffer.GetBuffer()[..length];
        }
    }

    private static Task SendPduAsync(WebSocket ws, RdCleanPathPdu pdu, CancellationToken ct) =>
        ws.SendAsync(pdu.Encode(), WebSocketMessageType.Binary, true, ct);

    private static async Task SendErrorAsync(WebSocket ws, RdCleanPathError error, CancellationToken ct)
    {
        await SendPduAsync(ws, new RdCleanPathPdu { Error = error }, ct);
        if (ws.State == WebSocketState.Open)
            await ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "error", ct);
    }

    /// <summary>Reads one TPKT-framed packet (version 3, 16-bit big-endian total length).</summary>
    private static async Task<byte[]> ReadTpktAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, ct);
        if (header[0] != 3)
            throw new InvalidDataException($"RDP server sent no TPKT X.224 response (first bytes {Convert.ToHexString(header)}).");
        var length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
        var packet = new byte[length];
        header.CopyTo(packet, 0);
        await stream.ReadExactlyAsync(packet.AsMemory(4, length - 4), ct);
        return packet;
    }

    private static async Task<(string Path, string? Key, string[] Protocols)> ReadUpgradeRequestAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new List<byte>();
        var one = new byte[1];
        while (buffer.Count < 16 * 1024)
        {
            if (await stream.ReadAsync(one, ct) == 0)
                throw new IOException("Connection closed during WebSocket handshake.");
            buffer.Add(one[0]);
            if (buffer.Count >= 4 && buffer[^1] == '\n' && buffer[^2] == '\r' && buffer[^3] == '\n' && buffer[^4] == '\r')
                break;
        }
        var lines = Encoding.ASCII.GetString(buffer.ToArray()).Split("\r\n");
        var requestLine = lines[0].Split(' ');
        var path = requestLine.Length > 1 ? requestLine[1].Split('?')[0] : "";
        string? key = null;
        var protocols = Array.Empty<string>();
        var isUpgrade = false;
        foreach (var line in lines.Skip(1))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0)
                continue;
            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (name.Equals("Sec-WebSocket-Key", StringComparison.OrdinalIgnoreCase))
                key = value;
            else if (name.Equals("Sec-WebSocket-Protocol", StringComparison.OrdinalIgnoreCase))
                protocols = value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            else if (name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase))
                isUpgrade = value.Equals("websocket", StringComparison.OrdinalIgnoreCase);
        }
        return (path, isUpgrade ? key : null, protocols);
    }

    private static bool FixedTimeEquals(string? a, string b) =>
        a is not null && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _listener?.Stop();
        _cts.Dispose();
    }
}
