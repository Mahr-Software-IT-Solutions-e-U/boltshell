using System.Text;
using Microsoft.Extensions.Logging;
using Renci.SshNet;
using Renci.SshNet.Common;
using BoltShell.Core.Ssh;

namespace BoltShell.Core.Provisioning;

public enum ProvisionStepKind
{
    Connect,
    CheckPrivileges,
    GenerateKey,
    InstallKey,
    AllowRootKeyLogin,
    VerifyKeyLogin,
    SaveToPassbolt,
    DisablePasswordLogin,
    VerifyPasswordLogin,
}

public enum StepStatus { Pending, Running, Done, Skipped, Failed }

public sealed class ProvisionStep(ProvisionStepKind kind, string title)
{
    public ProvisionStepKind Kind { get; } = kind;
    public string Title { get; } = title;
    public StepStatus Status { get; internal set; } = StepStatus.Pending;
    public string? Detail { get; internal set; }
}

/// <param name="Name">Name of the Passbolt resource.</param>
/// <param name="Target">Host and port (user is ignored).</param>
/// <param name="LoginUser">Existing account used for provisioning.</param>
/// <param name="LoginCredentials">Usually just the password; it is also used for sudo.</param>
/// <param name="KeyForRoot">Install the key for root and allow root login by key only (<c>PermitRootLogin prohibit-password</c>).</param>
/// <param name="DisablePasswordLogin">Disable SSH password authentication after the key works.</param>
public sealed record ProvisionRequest(
    string Name,
    SshTarget Target,
    string LoginUser,
    SshCredentials LoginCredentials,
    bool KeyForRoot,
    bool DisablePasswordLogin)
{
    public string KeyUser => KeyForRoot ? "root" : LoginUser;
}

/// <summary>What gets stored in Passbolt after the key works.</summary>
/// <param name="LoginPassword">Password of <see cref="KeyUser"/>, if known (only when the key is for the login user).</param>
public sealed record ProvisionedHost(string Name, SshTarget Target, string KeyUser, SshKeyPair Key, string HostKeyLine, string? LoginPassword)
{
    /// <summary>The Passbolt resource following the app's convention (ssh:// URI, ssh_* custom fields).</summary>
    public Passbolt.NewResource ToResource(string? folderId) => new(
        Name,
        KeyUser,
        [$"ssh://{KeyUser}@{Target.HostAndPort}"],
        LoginPassword,
        folderId,
        [
            new(SshConnectionMapper.PrivateKeyField, Key.PrivateKey, "password"),
            new(SshConnectionMapper.PublicKeyField, Key.PublicKey),
            new(SshConnectionMapper.HostKeyField, HostKeyLine),
        ],
        $"Provisioniert mit BoltShell am {DateTime.Now:dd.MM.yyyy}.");
}

public sealed class ProvisioningException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Turns a password-only host into a key-based Passbolt host:
/// connect with password → generate Ed25519 key → install it → (allow root key login) → verify key login →
/// save to Passbolt → (disable password login) → verify. The first connection stays open throughout,
/// so a broken sshd configuration can still be rolled back. Changes are rolled back if a step before saving fails.
/// </summary>
public sealed class HostProvisioner
{
    /// <summary>sshd drop-in written by the app (sorted first, so its settings win).</summary>
    public const string ConfigFileName = "00-boltshell.conf";

    private readonly SshConnector _connector;
    private readonly ILogger _logger;
    private readonly ProvisionRequest _request;
    private readonly List<ProvisionStep> _steps;

    public HostProvisioner(SshConnector connector, ILogger<HostProvisioner> logger, ProvisionRequest request)
    {
        _connector = connector;
        _logger = logger;
        _request = request;
        _steps =
        [
            new(ProvisionStepKind.Connect, $"Mit {request.LoginUser}@{request.Target.HostAndPort} per Passwort verbinden"),
            new(ProvisionStepKind.CheckPrivileges, request.LoginUser == "root" ? "Root-Rechte prüfen" : "sudo-Rechte prüfen"),
            new(ProvisionStepKind.GenerateKey, "Ed25519-Schlüssel erzeugen"),
            new(ProvisionStepKind.InstallKey, $"Public Key für {request.KeyUser} installieren"),
            new(ProvisionStepKind.AllowRootKeyLogin, "Root-Login per Schlüssel erlauben"),
            new(ProvisionStepKind.VerifyKeyLogin, $"Login als {request.KeyUser} per Schlüssel testen"),
            new(ProvisionStepKind.SaveToPassbolt, "In Passbolt speichern"),
            new(ProvisionStepKind.DisablePasswordLogin, "Passwort-Login deaktivieren"),
            new(ProvisionStepKind.VerifyPasswordLogin, "Prüfen: Passwort-Login abgelehnt, Schlüssel funktioniert"),
        ];
        if (!request.KeyForRoot)
            Skip(ProvisionStepKind.AllowRootKeyLogin, "nicht gewählt");
        if (!NeedsPrivileges)
            Skip(ProvisionStepKind.CheckPrivileges, "nicht nötig");
        if (!request.DisablePasswordLogin)
        {
            Skip(ProvisionStepKind.DisablePasswordLogin, "nicht gewählt");
            Skip(ProvisionStepKind.VerifyPasswordLogin, "nicht gewählt");
        }
    }

    public IReadOnlyList<ProvisionStep> Steps => _steps;

    /// <summary>Raised on every step change (on a background thread).</summary>
    public event Action? Changed;

    // Overridable for tests, which run against an unprivileged sshd in a temp directory.
    internal string SudoCommand { get; init; } = "sudo -S -p ''";
    internal string SshdConfigPath { get; init; } = "/etc/ssh/sshd_config";
    internal string SshdConfigDir { get; init; } = "/etc/ssh/sshd_config.d";
    internal string SshdCommand { get; init; } = "\"$(command -v sshd || echo /usr/sbin/sshd)\"";
    internal string ReloadCommand { get; init; } =
        "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null " +
        "|| service ssh reload 2>/dev/null || service sshd reload";
    internal string? AuthorizedKeysPathOverride { get; init; }

    private bool NeedsPrivileges => _request.KeyForRoot || _request.DisablePasswordLogin;
    private bool RunsAsRoot => _request.LoginUser == "root";
    private string ConfigFile => $"{SshdConfigDir}/{ConfigFileName}";

    /// <summary>Runs all steps. Returns the connection spec for the new key and an optional warning.</summary>
    /// <param name="saveToPassbolt">Stores the host; returns a warning (e.g. sharing failed) or null.</param>
    public async Task<(SshConnectionSpec Spec, string? Warning)> RunAsync(
        Func<ProvisionedHost, CancellationToken, Task<string?>> saveToPassbolt, CancellationToken ct = default)
    {
        var warnings = new List<string>();
        var loginSpec = new SshConnectionSpec(_request.Name, _request.Target with { Username = null }, _request.LoginUser, _request.LoginCredentials);

        // 1. Connect with the password; capture the host key for ssh_host_key.
        byte[]? hostKeyBlob = null;
        using var admin = _connector.CreateSshClient(loginSpec);
        admin.HostKeyReceived += (_, e) => hostKeyBlob = e.HostKey;
        await StepAsync(ProvisionStepKind.Connect, async () =>
        {
            try
            {
                await _connector.ConnectAsync(admin, ct);
            }
            catch (SshAuthenticationException ex)
            {
                throw new ProvisioningException("Anmeldung fehlgeschlagen: Benutzer oder Passwort falsch, oder der Server erlaubt keinen Passwort-Login.", ex);
            }
            return null;
        });
        var hostKeyLine = SshKeyGenerator.HostKeyLine(hostKeyBlob ?? throw new ProvisioningException("Der Server hat keinen Host-Key gesendet."));
        var hostKeys = SshConnectionMapper.ParseHostKeys(hostKeyLine);

        // 2. Root or working sudo is needed for root's authorized_keys and sshd configuration.
        if (NeedsPrivileges)
        {
            await StepAsync(ProvisionStepKind.CheckPrivileges, async () =>
            {
                var result = await RunAsync(admin, "id -u", privileged: true, ct);
                if (result.ExitCode != 0 || result.Output.Trim() != "0")
                    throw new ProvisioningException(RunsAsRoot
                        ? "Keine Root-Rechte."
                        : $"{_request.LoginUser} kann sudo nicht nutzen (falsches Passwort, keine Berechtigung oder 'requiretty'). {result.Error.Trim()}");
                return RunsAsRoot ? "angemeldet als root" : "sudo funktioniert";
            });
        }

        // 3. Key pair, kept in memory only.
        SshKeyPair key = null!;
        await StepAsync(ProvisionStepKind.GenerateKey, () =>
        {
            var comment = $"boltshell {_request.KeyUser}@{SafeComment(_request.Target.Host)} {DateTime.UtcNow:yyyy-MM-dd}";
            key = SshKeyGenerator.GenerateEd25519(comment);
            return Task.FromResult<string?>("SHA256:" + key.FingerprintSha256);
        });

        var keyInstalled = false;
        var configWritten = false;
        try
        {
            // 4. authorized_keys (idempotent).
            await StepAsync(ProvisionStepKind.InstallKey, async () =>
            {
                await RunCheckedAsync(admin, InstallKeyScript(key.PublicKey), privileged: _request.KeyForRoot && !RunsAsRoot, ct);
                keyInstalled = true;
                return null;
            });

            // 5. PermitRootLogin must allow keys before we can verify root's key login.
            if (_request.KeyForRoot)
            {
                await StepAsync(ProvisionStepKind.AllowRootKeyLogin, async () =>
                {
                    var effective = await EffectiveConfigAsync(admin, "root", ct);
                    if (effective.GetValueOrDefault("permitrootlogin") is "yes" or "prohibit-password" or "without-password")
                        return $"bereits erlaubt (PermitRootLogin {effective["permitrootlogin"]})";
                    await WriteSshdConfigAsync(admin, ["PermitRootLogin prohibit-password"], ct);
                    configWritten = true;
                    return "PermitRootLogin prohibit-password";
                });
            }

            // 6. A fresh connection with only the new key.
            var keySpec = new SshConnectionSpec(_request.Name, _request.Target with { Username = null }, _request.KeyUser,
                new SshCredentials(null, key.PrivateKey, null), hostKeys, key.PublicKey);
            await StepAsync(ProvisionStepKind.VerifyKeyLogin, async () => await VerifyKeyLoginAsync(keySpec, ct));

            // 7. Passbolt. If this fails, the server is restored (key removed) – nothing half-done remains.
            var loginPassword = _request.KeyForRoot && !RunsAsRoot ? null : _request.LoginCredentials.Password;
            await StepAsync(ProvisionStepKind.SaveToPassbolt, async () =>
            {
                var warning = await saveToPassbolt(
                    new ProvisionedHost(_request.Name, _request.Target with { Username = null }, _request.KeyUser, key, hostKeyLine, loginPassword), ct);
                if (warning is not null)
                    warnings.Add(warning);
                return warning;
            });

            var finalSpec = keySpec with { Credentials = new SshCredentials(loginPassword, key.PrivateKey, null) };

            // 8./9. Optional: disable password login. The admin connection stays open to undo a broken config.
            if (_request.DisablePasswordLogin)
            {
                await StepAsync(ProvisionStepKind.DisablePasswordLogin, async () =>
                {
                    var lines = new List<string>();
                    if (_request.KeyForRoot)
                        lines.Add("PermitRootLogin prohibit-password");
                    lines.Add("PasswordAuthentication no");
                    lines.Add("KbdInteractiveAuthentication no");
                    await WriteSshdConfigAsync(admin, lines, ct);
                    return $"{ConfigFile}";
                });

                await StepAsync(ProvisionStepKind.VerifyPasswordLogin, async () =>
                {
                    try
                    {
                        await VerifyKeyLoginAsync(keySpec, ct);
                    }
                    catch (Exception ex)
                    {
                        // Key login broke after the change: restore immediately via the still-open admin session.
                        await RemoveSshdConfigAsync(admin, ct);
                        throw new ProvisioningException("Nach dem Deaktivieren funktionierte der Schlüssel-Login nicht mehr – Änderung zurückgenommen. " + ex.Message, ex);
                    }

                    var effective = await EffectiveConfigAsync(admin, _request.LoginUser, ct);
                    if (effective.GetValueOrDefault("passwordauthentication") != "no")
                    {
                        var message = $"sshd meldet weiterhin PasswordAuthentication {effective.GetValueOrDefault("passwordauthentication", "?")} – " +
                                      "eventuell überschreibt eine frühere Einstellung oder ein Match-Block die Datei.";
                        warnings.Add(message);
                        throw new ProvisioningException(message);
                    }
                    if (await PasswordLoginWorksAsync(loginSpec, ct))
                    {
                        const string message = "Ein Login mit Passwort ist weiterhin möglich – bitte die sshd-Konfiguration prüfen.";
                        warnings.Add(message);
                        throw new ProvisioningException(message);
                    }
                    return "Passwort abgelehnt, Schlüssel funktioniert";
                }, failSoft: true);
            }

            return (finalSpec, warnings.Count > 0 ? string.Join(" ", warnings) : null);
        }
        catch when (Status(ProvisionStepKind.SaveToPassbolt) != StepStatus.Done)
        {
            await RollbackAsync(admin, key, keyInstalled, configWritten);
            throw;
        }
    }

    private async Task RollbackAsync(SshClient admin, SshKeyPair? key, bool keyInstalled, bool configWritten)
    {
        if (!admin.IsConnected)
            return;
        try
        {
            if (keyInstalled && key is not null)
                await RunCheckedAsync(admin, RemoveKeyScript(key.PublicKey), privileged: _request.KeyForRoot && !RunsAsRoot, CancellationToken.None);
            if (configWritten)
                await RemoveSshdConfigAsync(admin, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Rollback on {Host} failed", _request.Target);
        }
    }

    private async Task<string?> VerifyKeyLoginAsync(SshConnectionSpec keySpec, CancellationToken ct)
    {
        using var client = _connector.CreateSshClient(keySpec);
        await ConnectAfterReloadAsync(client, ct);
        var result = await RunAsync(client, "id -un", privileged: false, ct);
        if (result.Output.Trim() != keySpec.Username)
            throw new ProvisioningException($"Unerwarteter Benutzer nach Schlüssel-Login: '{result.Output.Trim()}'.");
        return $"angemeldet als {keySpec.Username}";
    }

    private async Task<bool> PasswordLoginWorksAsync(SshConnectionSpec loginSpec, CancellationToken ct)
    {
        if (!loginSpec.Credentials.HasPassword)
            return false;
        var passwordOnly = loginSpec with
        {
            Credentials = new SshCredentials(loginSpec.Credentials.Password, null, null),
            HostKeys = null,
        };
        using var client = _connector.CreateSshClient(passwordOnly);
        try
        {
            await ConnectAfterReloadAsync(client, ct);
            return true;
        }
        catch (SshAuthenticationException)
        {
            return false;
        }
    }

    /// <summary>
    /// After a reload sshd re-executes itself and briefly refuses connections; retry those (not auth failures) for a few seconds.
    /// </summary>
    private async Task ConnectAfterReloadAsync(BaseClient client, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await _connector.ConnectAsync(client, ct);
                return;
            }
            catch (Exception ex) when (attempt < 20 && ex is System.Net.Sockets.SocketException or SshConnectionException
                                           && ex is not SshAuthenticationException)
            {
                await Task.Delay(500, ct);
            }
        }
    }

    private async Task WriteSshdConfigAsync(SshClient admin, IReadOnlyList<string> lines, CancellationToken ct)
    {
        var content = string.Join(" ", new[] { "# Managed by BoltShell" }.Concat(lines).Select(Quote));
        // $$-raw string: shell braces stay literal, {{…}} interpolates.
        var script = $$"""
            set -e
            CONF={{Quote(ConfigFile)}}
            grep -Eqi '^[[:space:]]*Include[[:space:]].*sshd_config\.d' {{Quote(SshdConfigPath)}} || { echo PBSSH_NO_INCLUDE; exit 3; }
            mkdir -p {{Quote(SshdConfigDir)}}
            if [ -f "$CONF" ]; then cp -p "$CONF" "$CONF.pbssh-bak"; fi
            printf '%s\n' {{content}} > "$CONF"
            chmod 644 "$CONF"
            if ! ERR=$({{SshdCommand}} -t 2>&1); then
              if [ -f "$CONF.pbssh-bak" ]; then mv "$CONF.pbssh-bak" "$CONF"; else rm -f "$CONF"; fi
              echo "PBSSH_SSHD_TEST_FAILED $ERR"; exit 4
            fi
            rm -f "$CONF.pbssh-bak"
            {{ReloadCommand}}
            """;
        var result = await RunAsync(admin, script, privileged: true, ct);
        if (result.Output.Contains("PBSSH_NO_INCLUDE"))
            throw new ProvisioningException($"{SshdConfigPath} bindet {SshdConfigDir}/*.conf nicht ein (Include fehlt). Keine Änderung vorgenommen.");
        if (result.Output.Contains("PBSSH_SSHD_TEST_FAILED"))
            throw new ProvisioningException("sshd -t hat die neue Konfiguration abgelehnt, sie wurde zurückgenommen: " + result.Output.Replace("PBSSH_SSHD_TEST_FAILED", "").Trim());
        if (result.ExitCode != 0)
            throw new ProvisioningException($"sshd-Konfiguration fehlgeschlagen (Exit {result.ExitCode}): {result.Error.Trim()}");
    }

    private async Task RemoveSshdConfigAsync(SshClient admin, CancellationToken ct) =>
        await RunAsync(admin, $"rm -f {Quote(ConfigFile)} && ({ReloadCommand})", privileged: true, ct);

    /// <summary>Effective sshd settings for a connection by <paramref name="user"/> (<c>sshd -T</c>, respects Match blocks).</summary>
    private async Task<Dictionary<string, string>> EffectiveConfigAsync(SshClient admin, string user, CancellationToken ct)
    {
        var result = await RunAsync(admin, $"{SshdCommand} -T -C {Quote($"user={user},host=localhost,addr=127.0.0.1")}", privileged: true, ct);
        if (result.ExitCode != 0)
            throw new ProvisioningException("sshd -T fehlgeschlagen: " + result.Error.Trim());
        return ParseEffectiveConfig(result.Output);
    }

    internal static Dictionary<string, string> ParseEffectiveConfig(string output) =>
        output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => l.Split(' ', 2))
            .Where(p => p.Length == 2)
            .GroupBy(p => p[0].ToLowerInvariant())
            .ToDictionary(g => g.Key, g => g.First()[1].Trim().ToLowerInvariant());

    internal string InstallKeyScript(string publicKey) => $"""
        set -e
        umask 077
        AK={AuthorizedKeysExpression()}
        mkdir -p "$(dirname "$AK")"
        touch "$AK"
        grep -qxF {Quote(publicKey)} "$AK" || printf '%s\n' {Quote(publicKey)} >> "$AK"
        chmod 700 "$(dirname "$AK")"
        chmod 600 "$AK"
        command -v restorecon >/dev/null 2>&1 && restorecon -R "$(dirname "$AK")" || true
        """;

    internal string RemoveKeyScript(string publicKey) => $"""
        AK={AuthorizedKeysExpression()}
        [ -f "$AK" ] || exit 0
        grep -vxF {Quote(publicKey)} "$AK" > "$AK.pbssh-tmp" || true
        cat "$AK.pbssh-tmp" > "$AK"
        rm -f "$AK.pbssh-tmp"
        """;

    private string AuthorizedKeysExpression() =>
        AuthorizedKeysPathOverride is { } path
            ? Quote(path)
            : $"\"$(getent passwd {Quote(_request.KeyUser)} | cut -d: -f6)/.ssh/authorized_keys\"";

    private async Task RunCheckedAsync(SshClient client, string script, bool privileged, CancellationToken ct)
    {
        var result = await RunAsync(client, script, privileged, ct);
        if (result.ExitCode != 0)
            throw new ProvisioningException($"Befehl fehlgeschlagen (Exit {result.ExitCode}): {result.Error.Trim()}");
    }

    private sealed record CommandResult(int ExitCode, string Output, string Error);

    // The script is passed as one single-quoted argument to sh; the sudo password goes to stdin, never into the command line.
    private async Task<CommandResult> RunAsync(SshClient client, string script, bool privileged, CancellationToken ct)
    {
        var useSudo = privileged && !RunsAsRoot;
        var text = (useSudo ? SudoCommand + " " : "") + "sh -c " + Quote(script.Replace("\r\n", "\n"));
        using var command = client.CreateCommand(text);
        command.CommandTimeout = TimeSpan.FromMinutes(2);
        var execution = command.ExecuteAsync(ct);
        if (useSudo)
        {
            using var input = command.CreateInputStream();
            var bytes = Encoding.UTF8.GetBytes((_request.LoginCredentials.Password ?? "") + "\n");
            await input.WriteAsync(bytes, ct);
        }
        await execution;
        return new CommandResult(command.ExitStatus ?? -1, command.Result, command.Error);
    }

    internal static string Quote(string value) => "'" + value.Replace("'", "'\\''") + "'";

    private static string SafeComment(string value) => new(value.Where(c => char.IsLetterOrDigit(c) || c is '.' or '-' or ':' or '_').ToArray());

    private async Task StepAsync(ProvisionStepKind kind, Func<Task<string?>> work, bool failSoft = false)
    {
        var step = _steps.Single(s => s.Kind == kind);
        step.Status = StepStatus.Running;
        step.Detail = null;
        Changed?.Invoke();
        try
        {
            step.Detail = await work();
            step.Status = StepStatus.Done;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Provisioning step {Step} failed on {Host}", kind, _request.Target);
            step.Status = StepStatus.Failed;
            step.Detail = ex.Message;
            Changed?.Invoke();
            if (!failSoft)
                throw;
            return;
        }
        Changed?.Invoke();
    }

    private void Skip(ProvisionStepKind kind, string reason)
    {
        var step = _steps.Single(s => s.Kind == kind);
        step.Status = StepStatus.Skipped;
        step.Detail = reason;
    }

    private StepStatus Status(ProvisionStepKind kind) => _steps.Single(s => s.Kind == kind).Status;
}
