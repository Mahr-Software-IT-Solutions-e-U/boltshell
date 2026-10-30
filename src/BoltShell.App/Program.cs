using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MudBlazor.Services;
using BoltShell.App;
using BoltShell.App.Services;
using BoltShell.Core;
using BoltShell.Core.Ssh;
using Photino.Blazor;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        // Handles install/update/uninstall hooks when started by the Velopack installer; returns immediately otherwise.
        Velopack.VelopackApp.Build().Run();

        var builder = PhotinoBlazorAppBuilder.CreateDefault(args);
        var logDirectory = Path.Combine(BoltShell.Core.Config.SettingsStore.DefaultDirectory(), "logs");
        builder.Services.AddLogging(logging => logging
            .AddProvider(new FileLoggerProvider(logDirectory))
            .SetMinimumLevel(LogLevel.Information)
            .AddFilter("BoltShell.Core.Rdp", LogLevel.Debug)
            .AddFilter("Microsoft", LogLevel.Warning));
        builder.Services.AddMudServices();
        builder.Services.AddBoltShellCore();
        builder.Services.AddSingleton<FileDialogService>();
        builder.Services.AddSingleton<WorkspaceState>();
        builder.Services.AddSingleton<WindowService>();
        builder.Services.AddSingleton<UpdateService>();
        builder.RootComponents.Add<App>("app");

        var app = builder.Build();
        app.Services.GetRequiredService<FileDialogService>().Window = app.MainWindow;

        var settings = app.Services.GetRequiredService<BoltShell.Core.Config.SettingsStore>().Current;
        BoltShell.Core.Localization.Texts.Register(typeof(App).Assembly);
        BoltShell.Core.Localization.Texts.SetLanguage(settings.Language);

        // Frameless window with the app's own title bar (see WindowControls); can be turned off in settings.json.
        var frameless = !settings.NativeTitleBar;
        app.MainWindow.SetChromeless(frameless);
        app.Services.GetRequiredService<WindowService>().Attach(app.MainWindow, frameless);

        app.MainWindow
            .SetTitle("BoltShell")
            .SetIconFile(Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "app.ico" : "icon-256.png"))
            .SetSize(1440, 900)
            .SetMinSize(960, 600)
            .SetUseOsDefaultLocation(false)
            .Center();
#if !DEBUG
        app.MainWindow.SetDevToolsEnabled(false);
#endif

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            app.MainWindow.ShowMessage("Unerwarteter Fehler", e.ExceptionObject.ToString() ?? "Unknown error");

        app.Run();

        // Close all SSH connections cleanly when the window is closed.
        app.Services.GetRequiredService<SessionManager>().DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
