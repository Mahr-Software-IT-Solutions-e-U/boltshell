using System.Text.Json;
using BoltShell.Core.Passbolt;

namespace BoltShell.Core.Config;

/// <summary>A configured Passbolt account. The private key is stored passphrase-protected, as exported by Passbolt.</summary>
public sealed record AccountConfig
{
    public required string Id { get; init; }
    public required string DisplayName { get; init; }
    public required PassboltAccount Account { get; init; }

    /// <summary>Lock the account after this many minutes without use; 0 = never.</summary>
    public int AutoLockMinutes { get; init; } = 15;
}

public sealed record AppSettings
{
    public List<AccountConfig> Accounts { get; init; } = [];

    public int TerminalFontSize { get; init; } = 13;
    public string TerminalFontFamily { get; init; } = "'JetBrains Mono', Consolas, Menlo, monospace";

    /// <summary>Use the operating system's title bar instead of the app's own (frameless window).</summary>
    public bool NativeTitleBar { get; init; }

    /// <summary>Last local directory used for downloads.</summary>
    public string? DownloadDirectory { get; init; }

    public HashSet<string> FavoriteResourceIds { get; init; } = [];
}

/// <summary>Stores <see cref="AppSettings"/> as JSON in the per-user config directory.</summary>
public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };
    private readonly string _path;

    public SettingsStore(string? directory = null)
    {
        Directory = directory ?? DefaultDirectory();
        _path = Path.Combine(Directory, "settings.json");
        Current = Load();
    }

    public string Directory { get; }
    public string KnownHostsPath => Path.Combine(Directory, "known_hosts.json");
    public AppSettings Current { get; private set; }

    public event Action<AppSettings>? Changed;

    public void Update(Func<AppSettings, AppSettings> change)
    {
        Current = change(Current);
        System.IO.Directory.CreateDirectory(Directory);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(Current, Options));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(tmp, _path, overwrite: true);
        Changed?.Invoke(Current);
    }

    private AppSettings Load()
    {
        if (!File.Exists(_path))
            return new AppSettings();
        try
        {
            return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(_path), Options) ?? new AppSettings();
        }
        catch (JsonException)
        {
            File.Copy(_path, _path + ".broken", overwrite: true);
            return new AppSettings();
        }
    }

    /// <summary>%APPDATA%\BoltShell, ~/Library/Application Support/BoltShell or ~/.config/BoltShell.</summary>
    public static string DefaultDirectory()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.Create);
        var directory = Path.Combine(appData, "BoltShell");
        MigrateLegacyDirectory(Path.Combine(appData, LegacyDirectoryName), directory);
        return directory;
    }

    /// <summary>Folder name used before the app was renamed to BoltShell.</summary>
    internal const string LegacyDirectoryName = "PassboltSshManager";

    /// <summary>Moves settings, accounts and trusted host keys from the pre-rename folder, once.</summary>
    internal static void MigrateLegacyDirectory(string legacy, string current)
    {
        if (!System.IO.Directory.Exists(legacy) || System.IO.Directory.Exists(current))
            return;
        try
        {
            System.IO.Directory.Move(legacy, current);
        }
        catch (IOException)
        {
            // e.g. the old version is still running and holds a log file: keep using the old data next time
        }
    }
}
