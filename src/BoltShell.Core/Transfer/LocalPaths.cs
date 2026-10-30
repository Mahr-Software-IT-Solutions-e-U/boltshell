using static BoltShell.Core.Localization.Texts;

namespace BoltShell.Core.Transfer;

/// <summary>A remote file name that must not be used as a local file name (e.g. <c>..\outside.txt</c>).</summary>
public sealed class UnsafeRemoteNameException(string name, string reason)
    : IOException(Tr("'{0}' was not transferred: {1}", name, reason))
{
    public string RemoteName { get; } = name;
}

/// <summary>
/// Turns names chosen by a remote server into local paths that cannot leave the download folder.
/// The rules are the same on every OS: a name that is harmless on Linux (<c>a\b</c>) is a path on Windows.
/// </summary>
public static class LocalPaths
{
    private static readonly char[] Forbidden = ['/', '\\', ':', '<', '>', '"', '|', '?', '*'];

    private static readonly HashSet<string> ReservedWindowsNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
    };

    /// <summary>Why <paramref name="name"/> is not a safe single file name, or null if it is.</summary>
    public static string? Problem(string? name)
    {
        if (string.IsNullOrEmpty(name))
            return Tr("empty name");
        if (name is "." or "..")
            return Tr("refers to another folder");
        if (name.IndexOfAny(Forbidden) >= 0)
            return Tr("contains path separators or characters not allowed on Windows");
        if (name.Any(c => c < 0x20))
            return Tr("contains control characters");
        if (name.EndsWith('.') || name.EndsWith(' '))
            return Tr("ends with a dot or space (ambiguous on Windows)");
        var stem = name.Split('.')[0].TrimEnd(' ');
        if (ReservedWindowsNames.Contains(stem))
            return Tr("is a reserved device name on Windows");
        return null;
    }

    /// <summary>
    /// <paramref name="directory"/>/<paramref name="name"/> after checking the name and that the result stays inside
    /// <paramref name="directory"/>, which itself must not be a symbolic link or reparse point.
    /// </summary>
    /// <exception cref="UnsafeRemoteNameException">The name or resulting path is not safe.</exception>
    public static string Child(string directory, string name)
    {
        if (Problem(name) is { } reason)
            throw new UnsafeRemoteNameException(name, reason);

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        var full = Path.GetFullPath(Path.Combine(root, name));
        var comparison = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!full.StartsWith(root + Path.DirectorySeparatorChar, comparison) || Path.GetDirectoryName(full) is not { } parent
            || !string.Equals(Path.TrimEndingDirectorySeparator(parent), root, comparison))
            throw new UnsafeRemoteNameException(name, Tr("would end up outside the target folder"));
        return full;
    }

    /// <summary>Throws if <paramref name="path"/> exists as a symbolic link / reparse point (writing would follow it).</summary>
    public static void EnsureNotLink(string path, string name)
    {
        FileSystemInfo info = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);
        if (info.Exists && (info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint)))
            throw new UnsafeRemoteNameException(name, Tr("the target is a link (symlink/reparse point), which is not written through"));
    }
}
