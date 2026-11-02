using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using BoltShell.Core.Accounts;

namespace BoltShell.Core.Config;

/// <summary>A group as shown: all accounts' groups with the same name, merged.</summary>
public sealed record MergedHostGroup(string Name, IReadOnlyList<(string AccountId, string HostKey)> Members);

/// <summary>
/// Personal host groups and the host list view. Each account keeps the groups of its own hosts in a private
/// (not shared) Passbolt resource, so they follow the user to other devices without data of one organisation ending
/// up in another one's Passbolt. Groups with the same name are merged for display. A local copy is kept in the
/// settings, so the list works while an account is locked; the newer copy wins when syncing.
/// </summary>
public sealed class HostGroupStore : IDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly SettingsStore _settings;
    private readonly AccountManager _accounts;
    private readonly ILogger<HostGroupStore> _logger;
    private readonly Lock _gate = new();
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _syncLocks = new();
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _pendingSaves = new();
    private readonly ConcurrentDictionary<string, IReadOnlyList<Passbolt.PassboltResource>> _syncedResources = new();
    private readonly ConcurrentDictionary<string, string> _syncErrors = new();

    public HostGroupStore(SettingsStore settings, AccountManager accounts, ILogger<HostGroupStore> logger)
    {
        _settings = settings;
        _accounts = accounts;
        _logger = logger;
        MigrateLegacyGroups();
        _accounts.Changed += OnAccountsChanged;
    }

    /// <summary>Delay before a change is written to Passbolt (several quick changes become one write).</summary>
    public TimeSpan SaveDelay { get; set; } = TimeSpan.FromSeconds(1);

    public event Action? Changed;

    public HostListView View => _settings.Current.HostListView;

    public void SetView(HostListView view) => Save(s => s with { HostListView = view });

    /// <summary>Accounts whose last sync with Passbolt failed, with the reason.</summary>
    public IReadOnlyDictionary<string, string> SyncErrors => _syncErrors;

    /// <summary>Groups of all accounts, merged by name (case-insensitive), sorted.</summary>
    public IReadOnlyList<MergedHostGroup> Groups =>
        _settings.Current.AccountHostGroups
            .SelectMany(a => a.Value.Groups.Select(g => (AccountId: a.Key, Group: g)))
            .GroupBy(x => x.Group.Name, StringComparer.OrdinalIgnoreCase)
            .Select(g => new MergedHostGroup(g.First().Group.Name,
                g.SelectMany(x => x.Group.Members.Select(m => (x.AccountId, m))).Distinct().ToList()))
            .OrderBy(g => g.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

    public bool IsMember(string groupName, string accountId, string hostKey) =>
        Document(accountId)?.Groups.Any(g => Same(g.Name, groupName) && g.Members.Contains(hostKey)) == true;

    /// <summary>True if the host is in at least one group.</summary>
    public bool IsGrouped(string accountId, string hostKey) =>
        Document(accountId)?.Groups.Any(g => g.Members.Contains(hostKey)) == true;

    /// <summary>Creates a group (in the host's account) with the host as first member.</summary>
    public void Create(string name, string accountId, string hostKey)
    {
        name = name.Trim();
        Modify([accountId], doc => doc.Groups.Any(g => Same(g.Name, name))
            ? Toggle(doc, name, hostKey, add: true)
            : doc with { Groups = [.. doc.Groups, new HostGroupEntry(name, [hostKey])] });
    }

    /// <summary>Adds the host to the group, or removes it if it is already a member.</summary>
    public void ToggleMember(string groupName, string accountId, string hostKey) =>
        Modify([accountId], doc => doc.Groups.Any(g => Same(g.Name, groupName))
            ? Toggle(doc, groupName, hostKey, add: null)
            : doc with { Groups = [.. doc.Groups, new HostGroupEntry(groupName, [hostKey])] });

    /// <summary>Renames the group in every account that has it.</summary>
    public void Rename(string oldName, string newName)
    {
        newName = newName.Trim();
        Modify(AccountsWith(oldName), doc => doc with
        {
            Groups = doc.Groups.Select(g => Same(g.Name, oldName) ? g with { Name = newName } : g).ToList(),
        });
    }

    /// <summary>Deletes the group in every account (the hosts stay in Passbolt).</summary>
    public void Delete(string name)
    {
        Modify(AccountsWith(name), doc => doc with { Groups = doc.Groups.Where(g => !Same(g.Name, name)).ToList() });
        Save(s => s with { CollapsedSidebarNodes = s.CollapsedSidebarNodes.Where(n => n != GroupNode(name)).ToHashSet() });
    }

    public bool IsCollapsed(string node) => _settings.Current.CollapsedSidebarNodes.Contains(node);

    public void ToggleCollapsed(string node) => Save(s =>
    {
        var collapsed = new HashSet<string>(s.CollapsedSidebarNodes);
        if (!collapsed.Remove(node))
            collapsed.Add(node);
        return s with { CollapsedSidebarNodes = collapsed };
    });

    public static string GroupNode(string groupName) => "group:" + groupName.ToLowerInvariant();

    public static string FolderNode(string accountId, string folderId) => $"folder:{accountId}:{folderId}";

    /// <summary>
    /// Compares the local copy with the account's private Passbolt resource: the newer one wins
    /// (remote → local copy, local → written to Passbolt). Errors are kept in <see cref="SyncErrors"/>.
    /// </summary>
    public async Task SyncAsync(AccountSession account, CancellationToken ct = default)
    {
        var gate = _syncLocks.GetOrAdd(account.Id, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            if (!account.IsUnlocked)
                return;
            var remoteText = await account.ReadPrivateSettingsAsync(ct);
            var remote = Parse(remoteText);
            if (remoteText is not null && remote is null)
                _logger.LogWarning("Private BoltShell settings of account {Account} are not readable; they will be replaced", account.Id);
            var local = Document(account.Id);

            if (remote is not null && (local is null || remote.Updated > local.Updated))
            {
                Save(s => s with { AccountHostGroups = new(s.AccountHostGroups) { [account.Id] = remote } });
            }
            else if (local is not null && (remote is null || local.Updated > remote.Updated))
            {
                await account.WritePrivateSettingsAsync(Serialize(local), ct);
            }
            if (_syncErrors.TryRemove(account.Id, out _))
                Changed?.Invoke();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Syncing host groups of account {Account} failed", account.Id);
            _syncErrors[account.Id] = ex.Message;
            Changed?.Invoke();
        }
        finally
        {
            gate.Release();
        }
    }

    internal static string Serialize(HostGroupDocument document) => JsonSerializer.Serialize(new RemoteDocument(1, document.Updated,
        document.Groups.Select(g => new RemoteGroup(g.Name, g.Members)).ToList()), Json);

    internal static HostGroupDocument? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        try
        {
            var remote = JsonSerializer.Deserialize<RemoteDocument>(text, Json);
            return remote is null ? null : new HostGroupDocument
            {
                Updated = remote.Updated,
                Groups = (remote.Groups ?? []).Where(g => !string.IsNullOrWhiteSpace(g.Name))
                    .Select(g => new HostGroupEntry(g.Name, (g.Members ?? []).Distinct().ToList())).ToList(),
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    // What is stored in Passbolt (the encrypted note of the private resource).
    private sealed record RemoteDocument(int Version, DateTimeOffset Updated, List<RemoteGroup>? Groups);

    private sealed record RemoteGroup(string Name, List<string>? Members);

    private HostGroupDocument? Document(string accountId) => _settings.Current.AccountHostGroups.GetValueOrDefault(accountId);

    private IEnumerable<string> AccountsWith(string groupName) =>
        _settings.Current.AccountHostGroups.Where(a => a.Value.Groups.Any(g => Same(g.Name, groupName))).Select(a => a.Key).ToList();

    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static HostGroupDocument Toggle(HostGroupDocument doc, string groupName, string hostKey, bool? add) => doc with
    {
        Groups = doc.Groups.Select(g => !Same(g.Name, groupName) ? g
            : g.Members.Contains(hostKey) && add != true ? g with { Members = g.Members.Where(m => m != hostKey).ToList() }
            : g.Members.Contains(hostKey) ? g
            : g with { Members = [.. g.Members, hostKey] }).ToList(),
    };

    // Changes the given accounts' groups, stamps them as newer than Passbolt's copy and schedules the upload.
    private void Modify(IEnumerable<string> accountIds, Func<HostGroupDocument, HostGroupDocument> change)
    {
        var ids = accountIds.ToList();
        Save(s =>
        {
            var all = new Dictionary<string, HostGroupDocument>(s.AccountHostGroups);
            foreach (var id in ids)
                all[id] = change(all.GetValueOrDefault(id) ?? new HostGroupDocument()) with { Updated = DateTimeOffset.UtcNow };
            return s with { AccountHostGroups = all };
        });
        foreach (var id in ids)
            ScheduleSync(id);
    }

    private void ScheduleSync(string accountId)
    {
        if (_accounts.Find(accountId) is not { IsUnlocked: true } account)
            return; // synced on the next unlock
        var cts = new CancellationTokenSource();
        if (_pendingSaves.TryGetValue(accountId, out var previous))
            previous.Cancel();
        _pendingSaves[accountId] = cts;
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(SaveDelay, cts.Token);
                await SyncAsync(account, cts.Token);
            }
            catch (OperationCanceledException)
            {
            }
        });
    }

    // Every unlock or refresh of an account (new resource list) compares its groups with Passbolt.
    private void OnAccountsChanged()
    {
        foreach (var account in _accounts.Accounts.Where(a => a.IsUnlocked))
        {
            if (_syncedResources.TryGetValue(account.Id, out var seen) && ReferenceEquals(seen, account.Resources))
                continue;
            _syncedResources[account.Id] = account.Resources;
            _ = SyncAsync(account);
        }
    }

    private void Save(Func<AppSettings, AppSettings> change)
    {
        lock (_gate)
            _settings.Update(change);
        Changed?.Invoke();
    }

    private void MigrateLegacyGroups()
    {
        if (_settings.Current.HostGroups.Count == 0)
            return;
        Save(s =>
        {
            var all = new Dictionary<string, HostGroupDocument>(s.AccountHostGroups);
            foreach (var group in s.HostGroups)
            {
                foreach (var byAccount in group.Members.Select(m => m.Split('\n', 2)).Where(p => p.Length == 2).GroupBy(p => p[0]))
                {
                    var doc = all.GetValueOrDefault(byAccount.Key) ?? new HostGroupDocument();
                    all[byAccount.Key] = doc with
                    {
                        Updated = DateTimeOffset.UtcNow,
                        Groups = [.. doc.Groups, new HostGroupEntry(group.Name, byAccount.Select(p => p[1]).ToList())],
                    };
                }
            }
            return s with { AccountHostGroups = all, HostGroups = [] };
        });
    }

    public void Dispose()
    {
        _accounts.Changed -= OnAccountsChanged;
        foreach (var cts in _pendingSaves.Values)
            cts.Cancel();
    }
}
