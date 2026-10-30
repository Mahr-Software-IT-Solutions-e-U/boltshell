using System.Runtime.CompilerServices;

namespace BoltShell.Core.Tests;

internal static class TestLanguage
{
    /// <summary>Tests assert the English source texts, independent of the developer's OS language.</summary>
    [ModuleInitializer]
    internal static void UseEnglish() => Localization.Texts.SetLanguage("en");
}
