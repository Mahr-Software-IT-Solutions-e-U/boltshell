using System.Reflection;
using Microsoft.Extensions.Logging;
using Velopack;
using Velopack.Sources;

namespace BoltShell.App.Services;

public enum UpdateCheckResult { UpdateAvailable, UpToDate, NotSupported, Failed }

/// <summary>
/// Checks GitHub Releases for a newer version (only for installed builds, not portable or development runs):
/// at start, then every few hours in the background, and on request. Installs on request.
/// </summary>
public sealed class UpdateService(ILogger<UpdateService> logger)
{
    public static readonly TimeSpan CheckInterval = TimeSpan.FromHours(6);

    private readonly SemaphoreSlim _checkLock = new(1, 1);
    private UpdateManager? _manager;
    private UpdateInfo? _update;
    private int _started;

    public string? AvailableVersion => _update?.TargetFullRelease.Version.ToString();
    public bool IsDownloading { get; private set; }
    public bool IsChecking { get; private set; }
    public int Progress { get; private set; }
    public DateTimeOffset? LastChecked { get; private set; }
    public string? LastError { get; private set; }

    /// <summary>The running version (from the installation, otherwise from the assembly).</summary>
    public string CurrentVersion =>
        Manager?.CurrentVersion?.ToString()
        ?? typeof(UpdateService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? "?";

    /// <summary>False for development runs and portable builds; those are updated by downloading a new version.</summary>
    public bool IsSupported => Manager is { IsInstalled: true, IsPortable: false };

    public event Action? Changed;

    public static string? RepositoryUrl =>
        typeof(UpdateService).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == "RepositoryUrl")?.Value;

    private UpdateManager? Manager
    {
        get
        {
            if (_manager is null && RepositoryUrl is { Length: > 0 } repo)
            {
                try
                {
                    _manager = new UpdateManager(new GithubSource(repo, null, false));
                }
                catch (Exception ex)
                {
                    logger.LogInformation(ex, "Update manager not available");
                }
            }
            return _manager;
        }
    }

    /// <summary>Checks now and then every <see cref="CheckInterval"/> in the background. Only the first call has an effect.</summary>
    public void Start()
    {
        if (Interlocked.Exchange(ref _started, 1) == 1 || !IsSupported)
            return;
        _ = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(CheckInterval);
            do
            {
                if (!IsDownloading)
                    await CheckAsync();
            }
            while (await timer.WaitForNextTickAsync());
        });
    }

    /// <summary>Looks for a newer release. Failures (e.g. offline) are logged and reported, never thrown.</summary>
    public async Task<UpdateCheckResult> CheckAsync()
    {
        if (!IsSupported)
            return UpdateCheckResult.NotSupported;
        await _checkLock.WaitAsync();
        IsChecking = true;
        Changed?.Invoke();
        try
        {
            _update = await _manager!.CheckForUpdatesAsync();
            LastError = null;
            if (_update is not null)
                logger.LogInformation("Update available: {Current} -> {Version}", _manager.CurrentVersion, AvailableVersion);
            return _update is null ? UpdateCheckResult.UpToDate : UpdateCheckResult.UpdateAvailable;
        }
        catch (Exception ex)
        {
            logger.LogInformation(ex, "Update check failed");
            LastError = ex.Message;
            return UpdateCheckResult.Failed;
        }
        finally
        {
            LastChecked = DateTimeOffset.Now;
            IsChecking = false;
            _checkLock.Release();
            Changed?.Invoke();
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
