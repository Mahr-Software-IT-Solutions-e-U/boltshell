# Builds the Windows app and installer into a fixed directory:
#   dist\win-x64\    ready-to-run app (self-contained)
#   dist\releases\   BoltShell-win-Setup.exe, BoltShell-win-Portable.zip, update packages
# dist\releases is kept between runs so Velopack can create delta updates.
# Usage: .\scripts\publish.ps1 [-Version 1.2.3]   (default: <Version> from the app's .csproj)
param([string]$Version)
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Project = Join-Path $Root "src\BoltShell.App\BoltShell.App.csproj"
$Dist = Join-Path $Root "dist"
if (-not $Version) { $Version = ([xml](Get-Content $Project)).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1 }

if (-not (Get-Command vpk -ErrorAction SilentlyContinue)) { dotnet tool install -g vpk --version 1.2.161 }

Write-Host "Publishing BoltShell $Version to $Dist"
Remove-Item -Recurse -Force (Join-Path $Dist "win-x64") -ErrorAction SilentlyContinue
dotnet publish $Project -c Release -r win-x64 --self-contained -o (Join-Path $Dist "win-x64") -p:Version=$Version
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item (Join-Path $Root "README.md") (Join-Path $Dist "win-x64")  # LICENSE, notices and licenses\ come from the build

vpk pack --packId BoltShell --packVersion $Version --packDir (Join-Path $Dist "win-x64") `
  --mainExe BoltShell.exe --packTitle "BoltShell" --packAuthors "BoltShell contributors" `
  --icon (Join-Path $Root "src\BoltShell.App\Assets\icon\app.ico") --outputDir (Join-Path $Dist "releases")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Installer: $Dist\releases\BoltShell-win-Setup.exe"
Write-Host "Portable:  $Dist\releases\BoltShell-win-Portable.zip"
