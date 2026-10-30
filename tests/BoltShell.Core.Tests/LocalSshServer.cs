using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace BoltShell.Core.Tests;

/// <summary>
/// Runs an unprivileged OpenSSH server on a random localhost port with key-only auth for the current user.
/// Tests using it are skipped when sshd/ssh-keygen are not installed.
/// </summary>
public sealed class LocalSshServer : IDisposable
{
    private readonly Process? _process;

    public LocalSshServer()
    {
        var sshd = new[] { "/usr/sbin/sshd", "/usr/bin/sshd" }.FirstOrDefault(File.Exists);
        if (sshd is null || OperatingSystem.IsWindows())
            return;

        Directory = Path.Combine(Path.GetTempPath(), "pbssh-test-" + Guid.NewGuid().ToString("N")[..8]);
        System.IO.Directory.CreateDirectory(Directory);
        Run("ssh-keygen", $"-q -t ed25519 -N \"\" -f {Directory}/host_key");
        Run("ssh-keygen", $"-q -t ed25519 -N \"\" -f {Directory}/client_key");
        Run("ssh-keygen", $"-q -t ed25519 -N secret -f {Directory}/client_key_enc");
        File.WriteAllText(Path.Combine(Directory, "authorized_keys"),
            File.ReadAllText($"{Directory}/client_key.pub") + File.ReadAllText($"{Directory}/client_key_enc.pub"));

        Port = FreePort();
        System.IO.Directory.CreateDirectory(Path.Combine(Directory, "sshd_config.d"));
        File.WriteAllText(Path.Combine(Directory, "authorized_keys2"), "");
        // Fake sudo for provisioning tests: accepts the password "pw123" on stdin, pretends to be root for the
        // privilege check ("id -u"), then runs the command as the current user.
        File.WriteAllText(Path.Combine(Directory, "fake-sudo"), "#!/bin/sh\nread -r pw\n[ \"$pw\" = pw123 ] || { echo 'Sorry, try again.' >&2; exit 1; }\n[ \"$3\" = 'id -u' ] && { echo 0; exit 0; }\nexec \"$@\"\n");
        File.SetUnixFileMode(Path.Combine(Directory, "fake-sudo"), UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        File.WriteAllText(Path.Combine(Directory, "sshd_config"), $"""
            Include {Directory}/sshd_config.d/*.conf
            Port {Port}
            ListenAddress 127.0.0.1
            HostKey {Directory}/host_key
            PidFile {Directory}/sshd.pid
            AuthorizedKeysFile {Directory}/authorized_keys {Directory}/authorized_keys2
            StrictModes no
            UsePAM no
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            PubkeyAuthentication yes
            Subsystem sftp internal-sftp
            """);

        _process = Process.Start(new ProcessStartInfo(sshd, $"-D -e -f {Directory}/sshd_config")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        });
        WaitForPort();
    }

    public bool Available => _process is { HasExited: false };
    public string Directory { get; } = "";
    public int Port { get; }
    public string User => Environment.UserName;
    public string SshdCommand => $"/usr/sbin/sshd -f {Directory}/sshd_config";
    public string ReloadCommand => $"kill -HUP $(cat {Directory}/sshd.pid)";
    public string HostPublicKey => File.ReadAllText(Path.Combine(Directory, "host_key.pub"));
    public string ClientKey => File.ReadAllText(Path.Combine(Directory, "client_key"));
    public string EncryptedClientKey => File.ReadAllText(Path.Combine(Directory, "client_key_enc"));

    /// <summary>Blocks until sshd accepts connections again (it re-executes itself on reload).</summary>
    public void WaitUntilListening()
    {
        if (Available)
            WaitForPort();
    }

    private void WaitForPort()
    {
        for (var i = 0; i < 50 && _process is { HasExited: false }; i++)
        {
            try
            {
                using var tcp = new TcpClient();
                tcp.Connect(IPAddress.Loopback, Port);
                return;
            }
            catch (SocketException)
            {
                Thread.Sleep(100);
            }
        }
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static void Run(string file, string args)
    {
        using var p = Process.Start(new ProcessStartInfo(file, args) { RedirectStandardOutput = true, RedirectStandardError = true })!;
        p.WaitForExit();
        if (p.ExitCode != 0)
            throw new InvalidOperationException($"{file} {args} failed: {p.StandardError.ReadToEnd()}");
    }

    public void Dispose()
    {
        if (_process is { HasExited: false })
            _process.Kill();
        _process?.Dispose();
        if (Directory.Length > 0)
            System.IO.Directory.Delete(Directory, recursive: true);
    }
}
