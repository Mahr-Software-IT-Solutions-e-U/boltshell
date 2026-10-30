using Microsoft.AspNetCore.Components;

namespace BoltShell.App.Components;

/// <summary>
/// Base of all components (see _Imports.razor): the cascading language makes every component re-render when the
/// UI language is switched, so open sessions keep running while all texts change.
/// </summary>
public abstract class LocalizedComponent : ComponentBase
{
    [CascadingParameter(Name = "Language")] public string? Language { get; set; }
}
