using Microsoft.Extensions.DependencyInjection;
using BoltShell.Core.Accounts;
using BoltShell.Core.Config;
using BoltShell.Core.Rdp;
using BoltShell.Core.Ssh;

namespace BoltShell.Core;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddBoltShellCore(this IServiceCollection services, string? configDirectory = null)
    {
        services.AddSingleton(_ => new SettingsStore(configDirectory));
        services.AddSingleton(sp => new KnownHostsStore(sp.GetRequiredService<SettingsStore>().KnownHostsPath));
        services.AddSingleton<SshConnector>();
        services.AddSingleton<SessionManager>();
        services.AddSingleton<AccountManager>();
        services.AddSingleton<RdpProxy>();
        return services;
    }
}
