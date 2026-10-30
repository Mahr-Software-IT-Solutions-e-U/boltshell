using System.Security.Cryptography;
using System.Text;
using BoltShell.Core.Accounts;
using BoltShell.Core.Passbolt;
using BoltShell.Core.Rdp;
using BoltShell.Core.Ssh;

namespace BoltShell.Core.Tests;

/// <summary>Passbolt resources with additional URIs: every ssh:// and rdp:// URI is its own host.</summary>
public class MultiHostTests
{
    private const string KeyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    private const string KeyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGQoZu6VQ9W3vQx5mFZ2v4nLDYcbP4wqKCpRB1oJ0FUj";

    private static string Fp(string keyLine) =>
        Convert.ToBase64String(SHA256.HashData(Convert.FromBase64String(keyLine.Split(' ')[1]))).TrimEnd('=');

    private static PassboltResource Resource(params string[] uris) =>
        new("r1", "cluster", "root", uris, null, null, null, null, [new CustomFieldDefinition("hk", SshConnectionMapper.HostKeyField, null)]);

    private static PassboltSecret Secret(string? hostKeys = null) =>
        new("pw", null, hostKeys is null ? new Dictionary<string, string>() : new Dictionary<string, string> { ["hk"] = hostKeys });

    [Fact]
    public void EveryHostUri_IsOwnEntry_OtherUrisAreIgnored()
    {
        var hosts = HostEntry.For(Resource("ssh://a.example.com", "https://web.example.com", "rdp://win.example.com", "ssh://b.example.com:2222"));

        Assert.Equal(["ssh://a.example.com", "rdp://win.example.com", "ssh://b.example.com:2222"], hosts.Select(h => h.Uri));
        Assert.Equal([false, true, false], hosts.Select(h => h.IsRdp));
        Assert.All(hosts, h => Assert.True(h.SharedResource));
        Assert.Equal("cluster (b.example.com)", hosts[2].DisplayName);
        Assert.Equal(3, hosts.Select(h => h.Key).Distinct().Count());

        var single = Assert.Single(HostEntry.For(Resource("ssh://a.example.com")));
        Assert.Equal("cluster", single.DisplayName);
    }

    [Fact]
    public void UriFragment_NamesTheHost_AndIsIgnoredForTheConnection()
    {
        var resource = Resource("ssh://10.0.0.11#node-1", "ssh://10.0.0.12:2222#Node%202", "rdp://10.0.0.20#", "ssh://10.0.0.13");
        var hosts = HostEntry.For(resource);

        Assert.Equal(["cluster · node-1", "cluster · Node 2", "cluster (10.0.0.20)", "cluster (10.0.0.13)"], hosts.Select(h => h.DisplayName));
        Assert.Equal("node-1", hosts[0].Label);
        Assert.Null(hosts[2].Label); // empty fragment

        var spec = SshConnectionMapper.Map(resource, Secret(), "ssh://10.0.0.12:2222#Node%202");
        Assert.Equal(("10.0.0.12", 2222, "cluster · Node 2"), (spec.Target.Host, spec.Target.Port, spec.DisplayName));
        Assert.Equal("cluster · node-1", SshConnectionMapper.Map(resource, Secret()).DisplayName); // default: first URI, with its label
        Assert.Equal("cluster (10.0.0.20)", RdpConnectionMapper.Map(resource, Secret(), "rdp://10.0.0.20#").DisplayName);

        // A single-host resource with a label also shows it.
        Assert.Equal("cluster · prod", Assert.Single(HostEntry.For(Resource("ssh://web.example.com#prod"))).DisplayName);
    }

    [Fact]
    public void Map_UsesTheChosenUri_AndNamesTheHost()
    {
        var resource = Resource("ssh://a.example.com", "ssh://deploy@b.example.com:2222");
        var spec = SshConnectionMapper.Map(resource, Secret(), "ssh://deploy@b.example.com:2222");

        Assert.Equal(("b.example.com", 2222, "deploy"), (spec.Target.Host, spec.Target.Port, spec.Username));
        Assert.Equal("cluster (b.example.com)", spec.DisplayName);
        Assert.Equal("a.example.com", SshConnectionMapper.Map(resource, Secret()).Target.Host); // default: first
        Assert.Throws<InvalidOperationException>(() => SshConnectionMapper.Map(resource, Secret(), "ssh://not-in-the-resource"));
    }

    [Fact]
    public void HostKeys_ArePickedPerHost_WithFallbacks()
    {
        var field = $"a.example.com {KeyA}\n[b.example.com]:2222 {KeyB}";
        var resource = Resource("ssh://a.example.com", "ssh://b.example.com:2222", "ssh://c.example.com");

        Assert.Equal([Fp(KeyA)], SshConnectionMapper.Map(resource, Secret(field), "ssh://a.example.com").HostKeys!.Select(k => k.FingerprintSha256));
        Assert.Equal([Fp(KeyB)], SshConnectionMapper.Map(resource, Secret(field), "ssh://b.example.com:2222").HostKeys!.Select(k => k.FingerprintSha256));
        // No entry for c and no unqualified entry: all entries count, so the pin is never silently dropped.
        Assert.Equal(2, SshConnectionMapper.Map(resource, Secret(field), "ssh://c.example.com").HostKeys!.Count);
        // An unqualified entry applies to hosts without their own entry.
        var withDefault = field + "\n" + KeyB;
        Assert.Equal([Fp(KeyB)], SshConnectionMapper.Map(resource, Secret(withDefault), "ssh://c.example.com").HostKeys!.Select(k => k.FingerprintSha256));
    }

    [Fact]
    public void SingleHostResource_KeepsUsingEveryEntry()
    {
        // Pasted known_hosts line for another name (e.g. the IP): still pinned, as before.
        var spec = SshConnectionMapper.Map(Resource("ssh://a.example.com"), Secret($"10.0.0.5 {KeyA}"));
        Assert.Equal([Fp(KeyA)], spec.HostKeys!.Select(k => k.FingerprintSha256));
    }

    [Theory]
    [InlineData("a.example.com", "a.example.com", 22, true)]
    [InlineData("A.EXAMPLE.COM", "a.example.com", 22, true)]
    [InlineData("[a.example.com]:2222", "a.example.com", 2222, true)]
    [InlineData("a.example.com", "a.example.com", 2222, false)]
    [InlineData("*.example.com", "b.example.com", 22, true)]
    [InlineData("*.example.com,!b.example.com", "b.example.com", 22, false)]
    [InlineData("web-?.example.com", "web-1.example.com", 22, true)]
    public void HostPatterns_FollowKnownHosts(string patterns, string host, int port, bool expected) =>
        Assert.Equal(expected, HostPatterns.Matches(patterns, host, port, 22));

    [Fact]
    public void HostPatterns_SupportHashedEntries()
    {
        var salt = RandomNumberGenerator.GetBytes(20);
        var hash = HMACSHA1.HashData(salt, Encoding.ASCII.GetBytes("[b.example.com]:2222"));
        var pattern = $"|1|{Convert.ToBase64String(salt)}|{Convert.ToBase64String(hash)}";
        Assert.True(HostPatterns.Matches(pattern, "b.example.com", 2222, 22));
        Assert.False(HostPatterns.Matches(pattern, "b.example.com", 22, 22));
    }

    [Fact]
    public void WithHostKey_ReplacesOnlyThisHostsEntry()
    {
        var existing = $"# cluster\na.example.com {KeyA}\n[b.example.com]:2222 {KeyA}";
        var updated = SshConnectionMapper.WithHostKey(existing, new SshTarget("b.example.com", 2222), KeyB, sharedResource: true);

        Assert.Equal($"# cluster\na.example.com {KeyA}\n[b.example.com]:2222 {KeyB}", updated);
        Assert.Equal(KeyB, SshConnectionMapper.WithHostKey(existing, new SshTarget("b.example.com", 2222), KeyB, sharedResource: false));
        Assert.Equal($"c.example.com {KeyB}", SshConnectionMapper.WithHostKey(null, new SshTarget("c.example.com"), KeyB, sharedResource: true));
    }

    [Fact]
    public void RdpCertificates_PerHost_AndMerged()
    {
        var fpA = Convert.ToBase64String(SHA256.HashData("a"u8)).TrimEnd('=');
        var fpB = Convert.ToBase64String(SHA256.HashData("b"u8)).TrimEnd('=');
        var field = RdpConnectionMapper.WithCertificate($"win-a.example.com {fpA}", new RdpTarget("win-b.example.com", 3390), fpB, sharedResource: true);

        Assert.Equal($"win-a.example.com {fpA}\n[win-b.example.com]:3390 {fpB}", field);
        Assert.Equal([fpA], RdpConnectionMapper.ParseFingerprints(field, new RdpTarget("win-a.example.com")));
        Assert.Equal([fpB], RdpConnectionMapper.ParseFingerprints(field, new RdpTarget("win-b.example.com", 3390)));
        // Old formats (several fingerprints separated by commas/spaces) still work.
        Assert.Equal([fpA, fpB], RdpConnectionMapper.ParseFingerprints($"{fpA}, {fpB}"));
        Assert.Equal([fpA, fpB], RdpConnectionMapper.ParseFingerprints($"{fpA} {fpB}"));
    }
}
