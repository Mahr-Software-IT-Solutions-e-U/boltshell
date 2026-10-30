using System.Text.RegularExpressions;
using BoltShell.Core.Localization;

namespace BoltShell.App.Tests;

/// <summary>
/// Keeps the translation catalogs in sync with the code: every text passed to <c>Tr("…")</c> has a translation in
/// every language, no catalog entry is stale, and placeholders match.
/// </summary>
public partial class LocalizationTests
{
    [GeneratedRegex("""\bTr\(\s*"((?:[^"\\]|\\.)*)"(?<rest>\s*[,)])""")]
    private static partial Regex Literal();

    [GeneratedRegex(@"\bTr\(\s*[\$@]")]
    private static partial Regex NonLiteral();

    [GeneratedRegex(@"\{(\d+)(?:[,:][^}]*)?\}")]
    private static partial Regex Placeholder();

    private static readonly string Root = FindRoot();

    private static IEnumerable<string> SourceFiles() =>
        Directory.EnumerateFiles(Path.Combine(Root, "src"), "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
            .Where(f => !f.Split(Path.DirectorySeparatorChar).Any(d => d is "obj" or "bin"));

    private static HashSet<string> UsedKeys()
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var file in SourceFiles())
        {
            foreach (Match match in Literal().Matches(File.ReadAllText(file)))
                keys.Add(Regex.Unescape(match.Groups[1].Value));
        }
        return keys;
    }

    private static List<(string Language, string File, IReadOnlyDictionary<string, string> Entries)> CatalogFiles() =>
        [.. Texts.CatalogFiles(typeof(Texts).Assembly), .. Texts.CatalogFiles(typeof(App).Assembly)];

    [Fact]
    public void Tr_IsOnlyCalledWithPlainStringLiterals()
    {
        var offenders = SourceFiles()
            .SelectMany(f => NonLiteral().Matches(File.ReadAllText(f)).Select(m => $"{Path.GetFileName(f)}: {m.Value}"))
            .ToList();
        Assert.True(offenders.Count == 0, "Use Tr(\"… {0} …\", value) instead of interpolated/verbatim strings:\n" + string.Join("\n", offenders));
    }

    [Fact]
    public void EveryText_IsTranslated_AndNoEntryIsStale()
    {
        var used = UsedKeys();
        Assert.NotEmpty(used);
        foreach (var language in Texts.Languages.Select(l => l.Code).Where(c => c != "en"))
        {
            var entries = CatalogFiles().Where(c => c.Language == language).SelectMany(c => c.Entries.Keys).ToHashSet(StringComparer.Ordinal);
            var missing = used.Where(k => !entries.Contains(k)).Order().ToList();
            var stale = entries.Where(k => !used.Contains(k)).Order().ToList();
            Assert.True(missing.Count == 0, $"Missing '{language}' translations:\n" + string.Join("\n", missing));
            Assert.True(stale.Count == 0, $"Unused '{language}' catalog entries:\n" + string.Join("\n", stale));
        }
    }

    [Fact]
    public void Translations_KeepPlaceholders_AndDoNotConflict()
    {
        var problems = new List<string>();
        foreach (var group in CatalogFiles().SelectMany(c => c.Entries.Select(e => (c.Language, c.File, e.Key, e.Value)))
                     .GroupBy(e => (e.Language, e.Key)))
        {
            if (group.Select(e => e.Value).Distinct().Count() > 1)
                problems.Add($"{group.Key.Language}: '{group.Key.Key}' translated differently in {string.Join(", ", group.Select(e => e.File))}");
            var entry = group.First();
            if (!Placeholders(entry.Key).SetEquals(Placeholders(entry.Value)))
                problems.Add($"{entry.Language}/{entry.File}: placeholders differ in '{entry.Key}'");
            if (string.IsNullOrWhiteSpace(entry.Value))
                problems.Add($"{entry.Language}/{entry.File}: empty translation for '{entry.Key}'");
        }
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public void SwitchingLanguage_ChangesTexts_AndFallsBackToEnglish()
    {
        Texts.Register(typeof(App).Assembly);
        var before = Texts.Language;
        try
        {
            Texts.SetLanguage("de");
            Assert.Equal("Unbekannter Host", Texts.Tr("Unknown host"));
            Assert.Equal("not in any catalog", Texts.Tr("not in any catalog"));
            Texts.SetLanguage("en");
            Assert.Equal("Unknown host", Texts.Tr("Unknown host"));
            Texts.SetLanguage("xx");
            Assert.Equal("en", Texts.Language);
        }
        finally
        {
            Texts.SetLanguage(before);
        }
    }

    private static HashSet<string> Placeholders(string text) =>
        Placeholder().Matches(text).Select(m => m.Groups[1].Value).ToHashSet();

    private static string FindRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "BoltShell.slnx")))
                return dir.FullName;
        }
        throw new InvalidOperationException("Repository root not found.");
    }
}
