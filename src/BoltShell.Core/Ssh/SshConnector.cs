using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Extensions.Logging;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace BoltShell.Core.Ssh;

/// <summary>The private key is encrypted and no (or a wrong) passphrase was supplied.</summary>
public sealed class KeyPassphraseRequiredException(bool wrongPassphrase, Exception? inner = null)
    : Exception(wrongPassphrase ? "The passphrase for the SSH private key is wrong." : "The SSH private key needs a passphrase.", inner)
{
    public bool WrongPassphrase { get; } = wrongPassphrase;
}

public sealed class HostKeyRejectedException(HostKeyInfo key, string message) : Exception(message)
{
    public HostKeyInfo Key { get; } = key;
}

/// <summary>
/// Creates SSH.NET clients for a <see cref="SshConnectionSpec"/> and enforces host key verification.
/// </summary>
public sealed class SshConnector(KnownHostsStore knownHosts, ILogger<SshConnector> logger)
{
    /// <summary>
    /// Asked for unknown or changed host keys; returns true to trust (and remember) the key.
    /// Without a handler, untrusted keys are rejected.
    /// </summary>
    public Func<HostKeyInfo, Task<bool>>? HostKeyPrompt { get; set; }

    public TimeSpan KeepAliveInterval { get; set; } = TimeSpan.FromSeconds(30);

    // Why the host key of a client was rejected; SSH.NET itself only reports a generic key exchange failure.
    private readonly ConditionalWeakTable<BaseClient, HostKeyRejectedException> _rejections = new();

    /// <summary>Connects a client created by this connector, reporting host key rejections as <see cref="HostKeyRejectedException"/>.</summary>
    public async Task ConnectAsync(BaseClient client, CancellationToken ct = default)
    {
        try
        {
            await client.ConnectAsync(ct);
        }
        catch (Exception) when (_rejections.TryGetValue(client, out var rejection))
        {
            throw rejection;
        }
    }

    public SshClient CreateSshClient(SshConnectionSpec spec) => Configure(new SshClient(BuildConnectionInfo(spec)), spec);

    public SftpClient CreateSftpClient(SshConnectionSpec spec) => Configure(new SftpClient(BuildConnectionInfo(spec)), spec);

    public ScpClient CreateScpClient(SshConnectionSpec spec) => Configure(new ScpClient(BuildConnectionInfo(spec), RemotePathTransformation.ShellQuote), spec);

    private T Configure<T>(T client, SshConnectionSpec spec) where T : BaseClient
    {
        client.KeepAliveInterval = KeepAliveInterval;
        client.HostKeyReceived += (_, e) =>
        {
            _rejections.Remove(client);
            e.CanTrust = VerifyHostKey(client, spec, e);
        };
        return client;
    }

    // SSH.NET raises this synchronously on its connect thread, so blocking on the UI prompt is fine here.
    private bool VerifyHostKey(BaseClient client, SshConnectionSpec spec, HostKeyEventArgs e)
    {
        var fingerprint = e.FingerPrintSHA256.TrimEnd('=');

        // Host identity published in Passbolt is authoritative: no prompt, no local override.
        if (spec.HasPinnedHostKeys)
        {
            if (spec.HostKeys!.Any(k => k.FingerprintSha256 == fingerprint))
                return true;
            var presented = new HostKeyInfo(spec.Target.HostKeyId, e.HostKeyName, fingerprint, HostKeyStatus.Changed,
                string.Join(", ", spec.HostKeys!.Select(k => k.FingerprintSha256)));
            logger.LogWarning("Host key for {Host} does not match Passbolt: {Algorithm} SHA256:{Fingerprint}",
                presented.HostKeyId, presented.Algorithm, fingerprint);
            _rejections.AddOrUpdate(client, new HostKeyRejectedException(presented,
                $"The host key of {spec.Target.HostAndPort} (SHA256:{fingerprint}) does not match the host identity " +
                $"stored in Passbolt ({SshConnectionMapper.HostKeyField}). Connection refused to protect against " +
                "man-in-the-middle attacks. If the server was reinstalled, update the resource in Passbolt."));
            return false;
        }

        var info = knownHosts.Check(spec.Target.HostKeyId, e.HostKeyName, fingerprint);
        if (info.Status == HostKeyStatus.Trusted)
            return true;

        logger.LogInformation("Host key for {Host} is {Status}: {Algorithm} SHA256:{Fingerprint}",
            info.HostKeyId, info.Status, info.Algorithm, info.FingerprintSha256);

        var accepted = HostKeyPrompt is { } prompt && prompt(info).GetAwaiter().GetResult();
        if (accepted)
            knownHosts.Trust(info);
        else
            _rejections.AddOrUpdate(client, new HostKeyRejectedException(info, $"The host key of {spec.Target.HostAndPort} was not accepted."));
        return accepted;
    }

    internal static ConnectionInfo BuildConnectionInfo(SshConnectionSpec spec)
    {
        var user = spec.Username;
        var creds = spec.Credentials;
        var methods = new List<AuthenticationMethod>();

        if (creds.HasPrivateKey)
            methods.Add(new PrivateKeyAuthenticationMethod(user, LoadPrivateKey(creds.PrivateKey!, creds.KeyPassphrase)));

        if (creds.HasPassword)
        {
            var password = creds.Password!;
            methods.Add(new PasswordAuthenticationMethod(user, password));
            var keyboard = new KeyboardInteractiveAuthenticationMethod(user);
            keyboard.AuthenticationPrompt += (_, e) =>
            {
                foreach (var prompt in e.Prompts)
                {
                    if (prompt.Request.Contains("password", StringComparison.OrdinalIgnoreCase))
                        prompt.Response = password;
                }
            };
            methods.Add(keyboard);
        }

        if (methods.Count == 0)
            throw new InvalidOperationException($"No password or private key available for '{spec.DisplayName}'.");

        return new ConnectionInfo(spec.Target.Host, spec.Target.Port, user, methods.ToArray())
        {
            Timeout = TimeSpan.FromSeconds(15),
        };
    }

    private static PrivateKeyFile LoadPrivateKey(string key, string? passphrase)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(key));
        try
        {
            return new PrivateKeyFile(stream, string.IsNullOrEmpty(passphrase) ? null : passphrase);
        }
        catch (SshPassPhraseNullOrEmptyException ex)
        {
            throw new KeyPassphraseRequiredException(wrongPassphrase: false, ex);
        }
        catch (SshException ex) when (!string.IsNullOrEmpty(passphrase))
        {
            throw new KeyPassphraseRequiredException(wrongPassphrase: true, ex);
        }
    }
}
