using BoltShell.App.Services;

namespace BoltShell.App.Tests;

/// <summary>
/// Velopack reports every macOS .app and Linux AppImage as "portable" (they update in place),
/// so only a Windows portable zip may be excluded from auto-updates.
/// </summary>
public sealed class UpdateSupportTests
{
    [Theory]
    // installed, portable, windows -> supported
    [InlineData(true, false, true, true)]    // Windows Setup.exe install
    [InlineData(true, true, true, false)]    // Windows portable zip
    [InlineData(true, true, false, true)]    // macOS .app / Linux AppImage (always "portable")
    [InlineData(false, false, true, false)]  // development run
    [InlineData(false, true, false, false)]  // development run on macOS/Linux
    public void Updates_are_supported_for_installed_builds_except_windows_portable(
        bool installed, bool portable, bool windows, bool expected)
    {
        Assert.Equal(expected, UpdateService.IsUpdatable(installed, portable, windows));
    }
}
