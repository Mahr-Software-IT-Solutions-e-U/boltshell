using BoltShell.Core.Crypto;
using BoltShell.Core.Passbolt;
using BoltShell.Core.Ssh;

namespace BoltShell.Core.Tests;

/// <summary>Servers that ask for more than a password (e.g. password + one-time code via PAM).</summary>
public class KeyboardInteractiveTests
{
    private static readonly SshCredentials PasswordOnly = new("pw", null, null);

    private static KeyboardQuestion Q(string text, bool echo = false) => new("root@h:22", null, text, echo);

    [Theory] // RFC 6238 appendix B (8 digits)
    [InlineData("SHA1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59, "94287082")]
    [InlineData("SHA1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1111111109, "07081804")]
    [InlineData("SHA256", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA", 1234567890, "91819424")]
    [InlineData("SHA512", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA", 2000000000, "38618901")]
    public void Totp_MatchesRfc6238(string algorithm, string secret, long time, string expected) =>
        Assert.Equal(expected, new TotpSettings(secret, algorithm, 8).Code(DateTimeOffset.FromUnixTimeSeconds(time)));

    [Fact]
    public void Totp_DefaultsToSixDigits_AndKnowsTheNextPeriod()
    {
        var totp = new TotpSettings("gezd gnbv gy3t qojq gezd gnbv gy3t qojq"); // spaces and lower case as shown by authenticator apps
        Assert.Equal("287082", totp.Code(DateTimeOffset.FromUnixTimeSeconds(59)));
        Assert.Equal(TimeSpan.FromSeconds(1), totp.UntilNextPeriod(DateTimeOffset.FromUnixTimeSeconds(59)));
    }

    [Theory]
    [InlineData("Password: ")]
    [InlineData("Passwort: ")]
    [InlineData("root@host's password:")]
    public void PasswordQuestion_GetsThePasswordOnce(string text)
    {
        var state = new KeyboardState();
        var asked = new List<string>();
        Assert.Equal("pw", SshConnector.Answer(Q(text), PasswordOnly, state, (q, _) => { asked.Add(q.Question); return "typed"; }));
        Assert.Empty(asked);
        // A second password question means the password was rejected: ask instead of looping.
        Assert.Equal("typed", SshConnector.Answer(Q(text), PasswordOnly, state, (q, _) => "typed"));
    }

    [Theory]
    [InlineData("Verification code: ")]
    [InlineData("One-time password (OATH) for `root': ")]
    [InlineData("Passcode or option (1-3): ", true)]
    [InlineData("Bestätigungscode: ")]
    public void CodeQuestion_WithoutTotp_AsksTheUser_AndNeverSendsThePassword(string text, bool echo = false)
    {
        KeyboardAnswer? kind = null;
        var answer = SshConnector.Answer(Q(text, echo), PasswordOnly, new KeyboardState(), (_, k) => { kind = k; return "123456"; });
        Assert.Equal("123456", answer);
        Assert.Equal(KeyboardAnswer.User, kind);
    }

    [Fact]
    public void CodeQuestion_WithTotpFromPassbolt_IsAnsweredAutomatically()
    {
        var creds = PasswordOnly with { Totp = new TotpSettings("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") };
        var state = new KeyboardState();
        var kinds = new List<KeyboardAnswer>();
        string? Responder(KeyboardQuestion q, KeyboardAnswer k) { kinds.Add(k); return k == KeyboardAnswer.Totp ? "000111" : "typed"; }

        Assert.Equal("pw", SshConnector.Answer(Q("Password: "), creds, state, Responder));
        Assert.Equal("000111", SshConnector.Answer(Q("Verification code: "), creds, state, Responder));
        Assert.Equal("typed", SshConnector.Answer(Q("Verification code: "), creds, state, Responder)); // rejected: ask the user
        Assert.Equal([KeyboardAnswer.Totp, KeyboardAnswer.User], kinds);
    }

    [Fact]
    public void UnknownQuestion_WithoutPrompt_GetsNoAnswer() =>
        Assert.Null(SshConnector.Answer(Q("Favourite colour?", echo: true), PasswordOnly, new KeyboardState(), null));

    [Fact]
    public void PassboltSecret_WithTotp_IsMappedIntoTheCredentials()
    {
        var secret = PassboltClient.ParseSecret(
            """{"password":"pw","totp":{"secret_key":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algorithm":"SHA256","digits":8,"period":60}}""",
            "v5-default-with-totp");
        Assert.Equal(new TotpSettings("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA256", 8, 60), secret.Totp);

        var resource = new PassboltResource("r", "otp-host", "root", ["ssh://otp.example.com"], null, null, null, null, []);
        Assert.Equal(secret.Totp, SshConnectionMapper.Map(resource, secret).Credentials.Totp);
    }
}
