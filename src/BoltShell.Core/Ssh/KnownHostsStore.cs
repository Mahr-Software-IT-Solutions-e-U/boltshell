using System.Text.Json;

namespace BoltShell.Core.Ssh;

public enum HostKeyStatus { Trusted, Unknown, Changed }

/// <summary>A host key presented by a server during connect.</summary>
public sealed record HostKeyInfo(string HostKeyId, string Algorithm, string FingerprintSha256, HostKeyStatus Status, string? PreviousFingerprint);

/// <summary>
/// Trust-on-first-use store for SSH host keys ("host:port" → algorithm → SHA256 fingerprint).
/// Kept separate from ~/.ssh/known_hosts so the app never modifies the user's OpenSSH files.
/// </summary>
public sealed class KnownHostsStore
{
    private readonly string _path;
    private readonly Lock _lock = new();
    private Dictionary<string, Dictionary<string, string>> _entries;

    public KnownHostsStore(string path)
    {
        _path = path;
        _entries = Load(path);
    }

    public HostKeyInfo Check(string hostKeyId, string algorithm, string fingerprintSha256)
    {
        lock (_lock)
        {
            if (!_entries.TryGetValue(hostKeyId, out var keys) || keys.Count == 0)
                return new HostKeyInfo(hostKeyId, algorithm, fingerprintSha256, HostKeyStatus.Unknown, null);
            if (keys.TryGetValue(algorithm, out var known))
            {
                return known == fingerprintSha256
                    ? new HostKeyInfo(hostKeyId, algorithm, fingerprintSha256, HostKeyStatus.Trusted, null)
                    : new HostKeyInfo(hostKeyId, algorithm, fingerprintSha256, HostKeyStatus.Changed, known);
            }
            // Host is known but presents a key type we have not seen: treat like a change.
            return new HostKeyInfo(hostKeyId, algorithm, fingerprintSha256, HostKeyStatus.Changed, keys.Values.First());
        }
    }

    /// <summary>Trusts the key, replacing any previously stored keys for that host.</summary>
    public void Trust(HostKeyInfo key)
    {
        lock (_lock)
        {
            _entries[key.HostKeyId] = new Dictionary<string, string> { [key.Algorithm] = key.FingerprintSha256 };
            Save();
        }
    }

    public void Remove(string hostKeyId)
    {
        lock (_lock)
        {
            if (_entries.Remove(hostKeyId))
                Save();
        }
    }

    public IReadOnlyList<(string HostKeyId, string Algorithm, string Fingerprint)> List()
    {
        lock (_lock)
            return _entries.SelectMany(e => e.Value.Select(k => (e.Key, k.Key, k.Value))).OrderBy(e => e.Item1).ToList();
    }

    private void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_entries, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(tmp, _path, overwrite: true);
    }

    private static Dictionary<string, Dictionary<string, string>> Load(string path)
    {
        if (!File.Exists(path))
            return new();
        return JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string>>>(File.ReadAllText(path)) ?? new();
    }
}
