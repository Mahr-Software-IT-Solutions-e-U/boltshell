using Photino.NET;

namespace BoltShell.App.Services;

/// <summary>Native open/save dialogs via the Photino window (the WebView cannot expose local paths).</summary>
public sealed class FileDialogService
{
    public PhotinoWindow? Window { get; set; }

    public async Task<string[]> PickFilesAsync(string title, string? startDirectory = null)
    {
        var window = Window ?? throw new InvalidOperationException("Window not ready.");
        return await window.ShowOpenFileAsync(title, startDirectory ?? Home, multiSelect: true) ?? [];
    }

    public async Task<string?> PickFolderAsync(string title, string? startDirectory = null)
    {
        var window = Window ?? throw new InvalidOperationException("Window not ready.");
        var result = await window.ShowOpenFolderAsync(title, startDirectory ?? Home, multiSelect: false);
        return result?.FirstOrDefault();
    }

    private static string Home => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
}
