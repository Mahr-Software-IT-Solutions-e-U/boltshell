#!/usr/bin/env bash
# Builds the Windows app and installer into a fixed directory:
#   dist/win-x64/    ready-to-run app (self-contained)
#   dist/releases/   BoltShell-win-Setup.exe, BoltShell-win-Portable.zip, update packages
# dist/releases is kept between runs so Velopack can create delta updates.
# Usage: scripts/publish.sh [version]   (default: <Version> from the app's .csproj)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="$ROOT/src/BoltShell.App/BoltShell.App.csproj"
DIST="$ROOT/dist"
VERSION="${1:-$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$PROJECT" | head -1)}"

command -v vpk >/dev/null || dotnet tool install -g vpk --version 1.2.161

echo "Publishing BoltShell $VERSION to $DIST"
rm -rf "$DIST/win-x64"
dotnet publish "$PROJECT" -c Release -r win-x64 --self-contained -o "$DIST/win-x64" -p:Version="$VERSION"
cp "$ROOT/README.md" "$ROOT/LICENSE" "$DIST/win-x64/"

# "[win]" lets vpk build the Windows installer on Linux/macOS as well.
vpk "[win]" pack --packId BoltShell --packVersion "$VERSION" --packDir "$DIST/win-x64" \
  --mainExe BoltShell.exe --packTitle "BoltShell" --packAuthors "BoltShell contributors" \
  --icon "$ROOT/src/BoltShell.App/Assets/icon/app.ico" --outputDir "$DIST/releases" --yes

echo
echo "Installer: $DIST/releases/BoltShell-win-Setup.exe"
echo "Portable:  $DIST/releases/BoltShell-win-Portable.zip"
