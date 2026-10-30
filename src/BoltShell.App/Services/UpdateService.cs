using System.Reflection;
using Microsoft.Extensions.Logging;
using Velopack;
using Velopack.Sources;

namespace BoltShell.App.Services;

/// <summary>
/// Checks GitHub Releases for a newer version (only for installed builds, not portable or development runs)
/// and installs it on request. Failures (e.g. offline) are only logged.
/// </summary>
public sealed class UpdateService(ILogger<UpdateService> logger)
{
    private UpdateManager? _manager;
    private UpdateInfo? _update;

    public string? AvailableVersion => _update?.TargetFullRelease.Version.ToString();
    public bool IsDownloading { get; private set; }
    public int Progress { get; private set; }

    public event Action? Changed;

    public static string? RepositoryUrl =>
        typeof(UpdateService).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == "RepositoryUrl")?.Value;

    public async Task CheckAsync()
    {
        try
        {
            if (RepositoryUrl is not { Length: > 0 } repo)
                return;
            _manager ??= new UpdateManager(new GithubSource(repo, null, false));
            if (!_manager.IsInstalled || _manager.IsPortable)
                return;
            _update = await _manager.CheckForUpdatesAsync();
            if (_update is not null)
            {
                logger.LogInformation("Update available: {Current} -> {Version}", _manager.CurrentVersion, AvailableVersion);
                Changed?.Invoke();
            }
        }
        catch (Exception ex)
        {
            logger.LogInformation(ex, "Update check failed");
        }
    }

    /// <summary>Downloads the update and restarts into the new version.</summary>
    public async Task InstallAsync()
    {
        if (_manager is null || _update is null || IsDownloading)
            return;
        IsDownloading = true;
        Changed?.Invoke();
        try
        {
            await _manager.DownloadUpdatesAsync(_update, p =>
            {
                Progress = p;
                Changed?.Invoke();
            });
            _manager.ApplyUpdatesAndRestart(_update.TargetFullRelease);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Update installation failed");
            IsDownloading = false;
            Changed?.Invoke();
            throw;
        }
    }
}
