# Third-party notices

BoltShell is licensed under GPL-3.0-or-later ([LICENSE](LICENSE)). Every build and installer contains this file, the
GPL text and the full license texts of all bundled components in the folder [`licenses/`](licenses/).

| Component | Version | Use | License | Full text |
|---|---|---|---|---|
| .NET runtime, Microsoft.Extensions.* (self-contained builds) | 10.0 | Runtime | MIT | `licenses/dotnet-runtime-LICENSE.txt`, `licenses/dotnet-runtime-THIRD-PARTY-NOTICES.txt` |
| ASP.NET Core components (Microsoft.AspNetCore.Components*, Microsoft.JSInterop) | 10.0 | UI framework | MIT | `licenses/aspnetcore-LICENSE.txt`, `licenses/aspnetcore-THIRD-PARTY-NOTICES.txt` |
| Microsoft.AspNetCore.Components.WebView (dotnet/maui) | 10.0.1 | Blazor in a WebView | MIT | `licenses/maui-LICENSE.txt`, `licenses/Microsoft.AspNetCore.Components.WebView-THIRD-PARTY-NOTICES.txt` |
| WebView2Loader.dll (Microsoft Edge WebView2 SDK, via Photino) | – | Windows WebView | BSD-style (Microsoft) | `licenses/WebView2Loader.txt` |
| [Photino.NET](https://github.com/tryphotino/photino.NET), [Photino.Blazor](https://github.com/tryphotino/photino.Blazor), [Photino.Native](https://github.com/tryphotino/photino.Native) | 4.0.x | Desktop window | Apache-2.0 | `licenses/Photino.*.txt` |
| [MudBlazor](https://github.com/MudBlazor/MudBlazor) | 9.12.0 | Dialogs, snackbars | MIT | `licenses/MudBlazor.txt` |
| [XtermBlazor](https://github.com/BattlefieldDuck/XtermBlazor) | 2.4.0 | Terminal component | MIT | `licenses/XtermBlazor.txt` |
| [xterm.js](https://github.com/xtermjs/xterm.js) (bundled in XtermBlazor) | 6.x | Terminal | MIT | `licenses/xterm.js.txt` |
| xterm.js addon-fit, addon-web-links | 0.11 / 0.12 | Terminal | MIT | `licenses/xterm-addons.txt` |
| [Macross.Json.Extensions](https://github.com/Macross-Software/core) (dependency of XtermBlazor) | 3.0.0 | JSON | MIT | `licenses/Macross.Json.Extensions.txt` |
| [SSH.NET](https://github.com/sshnet/SSH.NET) | 2026.0.0 | SSH, SFTP, SCP | MIT | `licenses/SSH.NET.txt` |
| [BouncyCastle.Cryptography](https://github.com/bcgit/bc-csharp) | 2.7.0 | OpenPGP, Ed25519 | MIT | `licenses/BouncyCastle.txt` |
| [IronRDP web client](https://github.com/Devolutions/IronRDP) (`@devolutions/iron-remote-desktop` 0.11.0, `-rdp` 0.7.0) | – | RDP (JavaScript + WebAssembly) | MIT OR Apache-2.0 (used under MIT) | `licenses/IronRDP-MIT.txt`, `licenses/IronRDP-Apache-2.0.txt` |
| [Velopack](https://github.com/velopack/velopack) | 1.2.161 | Installer, updates | MIT | `licenses/Velopack.txt` |
| [Inter](https://github.com/rsms/inter) | 4.x | Font | SIL OFL 1.1 | `licenses/Inter-OFL.txt` |
| [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) | 2.x | Font | SIL OFL 1.1 | `licenses/JetBrainsMono-OFL.txt` |

The IronRDP WebAssembly module is compiled from IronRDP and its Rust dependencies, which are published under permissive
licenses (predominantly MIT and/or Apache-2.0); see the IronRDP repository for the dependency list of the bundled version.

Test-only (not distributed): xUnit (Apache-2.0), Microsoft.NET.Test.Sdk (MIT), coverlet (MIT), GitHubActionsTestLogger (MIT),
Xunit.SkippableFact (MS-PL).

## Source code

BoltShell is distributed under the GPL together with its complete source code: every release is built by GitHub Actions
from the tagged commit (`vX.Y.Z`), and the GitHub release page links the corresponding source archives. Build scripts are
part of the repository (`.github/workflows/build.yml`, `scripts/`).
