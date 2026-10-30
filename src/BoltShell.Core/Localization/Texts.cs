using System.Globalization;
using System.Reflection;
using System.Text.Json;

namespace BoltShell.Core.Localization;

/// <summary>
/// Translates user-facing texts, gettext style: the English text in the code is the key, translations live in
/// embedded JSON catalogs <c>i18n/&lt;language&gt;/&lt;name&gt;.json</c> (flat objects "English" → "translation").
/// A missing translation falls back to English. Placeholders use <see cref="string.Format(string, object?[])"/> syntax.
/// </summary>
public static class Texts
{
    /// <summary>Selectable languages (code, native name). English is the source language.</summary>
    public static readonly IReadOnlyList<(string Code, string Name)> Languages = [("en", "English"), ("de", "Deutsch")];

    private static readonly Lock Gate = new();
    private static readonly HashSet<Assembly> Registered = [];
    private static Dictionary<string, Dictionary<string, string>> _catalogs = new();
    private static Dictionary<string, string>? _current;

    static Texts()
    {
        Register(typeof(Texts).Assembly);
        SetLanguage(null);
    }

    /// <summary>The active language code, e.g. <c>de</c>.</summary>
    public static string Language { get; private set; } = "en";

    /// <summary>Raised after <see cref="SetLanguage"/> changed the language.</summary>
    public static event Action? Changed;

    /// <summary>Loads the catalogs embedded in <paramref name="assembly"/>.</summary>
    public static void Register(Assembly assembly)
    {
        lock (Gate)
        {
            if (!Registered.Add(assembly))
                return;
            var catalogs = _catalogs.ToDictionary(c => c.Key, c => new Dictionary<string, string>(c.Value));
            foreach (var (language, entries) in ReadCatalogs(assembly))
            {
                var catalog = catalogs.TryGetValue(language, out var existing) ? existing : catalogs[language] = new Dictionary<string, string>();
                foreach (var (key, value) in entries)
                    catalog[key] = value;
            }
            _catalogs = catalogs;
            _current = _catalogs.GetValueOrDefault(Language);
        }
    }

    /// <summary>Sets the language; null, empty or <c>auto</c> follows the operating system.</summary>
    public static void SetLanguage(string? code)
    {
        var language = string.IsNullOrEmpty(code) || code == "auto" ? SystemLanguage() : code;
        if (!Languages.Any(l => l.Code == language))
            language = "en";
        var changed = language != Language;
        lock (Gate)
        {
            Language = language;
            _current = _catalogs.GetValueOrDefault(language);
        }
        if (changed)
            Changed?.Invoke();
    }

    /// <summary>The operating system's UI language if it is supported, otherwise English.</summary>
    public static string SystemLanguage()
    {
        var name = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
        return Languages.Any(l => l.Code == name) ? name : "en";
    }

    /// <summary>Translates <paramref name="text"/> (English) into the active language.</summary>
    public static string Tr(string text) => _current?.GetValueOrDefault(text) ?? text;

    /// <summary>Translates <paramref name="text"/> and fills in its <c>{0}</c>… placeholders.</summary>
    public static string Tr(string text, params object?[] args) => string.Format(CultureInfo.CurrentCulture, Tr(text), args);

    /// <summary>All catalog entries of a language (for tests and tooling).</summary>
    public static IReadOnlyDictionary<string, string> Catalog(string language)
    {
        lock (Gate)
            return _catalogs.GetValueOrDefault(language) ?? new Dictionary<string, string>();
    }

    /// <summary>Catalog files of an assembly: (language, file name, entries).</summary>
    public static IEnumerable<(string Language, string File, IReadOnlyDictionary<string, string> Entries)> CatalogFiles(Assembly assembly)
    {
        foreach (var name in assembly.GetManifestResourceNames())
        {
            var parts = name.Replace('\\', '/').Split('/');
            if (parts is not ["i18n", var language, var file] || !file.EndsWith(".json", StringComparison.Ordinal))
                continue;
            using var stream = assembly.GetManifestResourceStream(name)!;
            var entries = JsonSerializer.Deserialize<Dictionary<string, string>>(stream) ?? [];
            yield return (language, file, entries);
        }
    }

    private static IEnumerable<(string Language, IReadOnlyDictionary<string, string> Entries)> ReadCatalogs(Assembly assembly) =>
        CatalogFiles(assembly).Select(f => (f.Language, f.Entries));
}
