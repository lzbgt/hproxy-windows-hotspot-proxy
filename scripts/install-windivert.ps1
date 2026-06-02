param(
    [string]$Version = "2.2.2",
    [string]$Destination = "third_party/windivert/win-x64"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$destinationPath = Join-Path $repoRoot $Destination
$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) "hproxy-windivert-$Version"
$packagePath = Join-Path $tmpRoot "Native.WinDivert.$Version.nupkg"
$archivePath = Join-Path $tmpRoot "Native.WinDivert.$Version.zip"
$extractPath = Join-Path $tmpRoot "extract"
$packageUrl = "https://www.nuget.org/api/v2/package/Native.WinDivert/$Version"

Remove-Item -Recurse -Force $tmpRoot -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $tmpRoot, $extractPath, $destinationPath | Out-Null

Invoke-WebRequest -Uri $packageUrl -OutFile $packagePath
Copy-Item $packagePath $archivePath -Force
Expand-Archive -Path $archivePath -DestinationPath $extractPath -Force

Copy-Item (Join-Path $extractPath "runtimes/win-x64/native/WinDivert.dll") $destinationPath -Force
Copy-Item (Join-Path $extractPath "runtimes/win-x64/native/WinDivert64.sys") $destinationPath -Force
Copy-Item (Join-Path $extractPath "LICENSE") $destinationPath -Force
Copy-Item (Join-Path $extractPath "ReadMe.md") $destinationPath -Force

Write-Output "Installed Native.WinDivert $Version to $destinationPath"
