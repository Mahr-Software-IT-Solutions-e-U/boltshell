using BoltShell.Core.Transfer;

namespace BoltShell.Core.Tests;

/// <summary>Audit finding SEC-02: remote names must never leave the chosen download folder.</summary>
public sealed class LocalPathsTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "boltshell-paths-" + Guid.NewGuid().ToString("N")[..8]);

    public LocalPathsTests() => Directory.CreateDirectory(_root);

    [Theory]
    [InlineData("..\\outside.txt")]
    [InlineData("../outside.txt")]
    [InlineData("sub\\..\\..\\x")]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("C:\\Windows\\win.ini")]
    [InlineData("C:evil")]
    [InlineData("\\\\server\\share\\x")]
    [InlineData("/etc/passwd")]
    [InlineData("file.txt:stream")]
    [InlineData("CON")]
    [InlineData("nul.txt")]
    [InlineData("COM1.log")]
    [InlineData("trailing.")]
    [InlineData("trailing ")]
    [InlineData("a\u0001b")]
    [InlineData("")]
    public void UnsafeNames_AreRejected(string name)
    {
        Assert.NotNull(LocalPaths.Problem(name));
        Assert.Throws<UnsafeRemoteNameException>(() => LocalPaths.Child(_root, name));
    }

    [Theory]
    [InlineData("report.pdf")]
    [InlineData(".bashrc")]
    [InlineData("..hidden")]
    [InlineData("name with spaces.txt")]
    [InlineData("Übersicht 2026.xlsx")]
    [InlineData("console.log")]
    public void NormalNames_StayInsideTheFolder(string name)
    {
        var path = LocalPaths.Child(_root, name);
        Assert.Equal(Path.Combine(Path.GetFullPath(_root), name), path);
    }

    [SkippableFact]
    public void ExistingSymlinkAtTarget_IsNotWrittenThrough()
    {
        // Creating symlinks needs extra rights on Windows; the check itself is platform independent.
        Skip.If(OperatingSystem.IsWindows(), "symlink creation needs developer mode on Windows");
        var outside = Path.Combine(_root, "outside.txt");
        var folder = Directory.CreateDirectory(Path.Combine(_root, "download")).FullName;
        File.CreateSymbolicLink(Path.Combine(folder, "innocent.txt"), outside);

        Assert.Throws<UnsafeRemoteNameException>(() => LocalPaths.EnsureNotLink(Path.Combine(folder, "innocent.txt"), "innocent.txt"));
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);
}
