param(
    [string]$Version = "0.8.0"
)

$ErrorActionPreference = "Stop"
if ($Version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$') {
    throw "Version must be a semantic version."
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$packageRoot = Join-Path $projectRoot "artifacts\stage\NetMind-AI-$Version-win-x64"
$manifestPath = Join-Path $packageRoot "release-manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath)) { throw "Release manifest was not found: $manifestPath" }

$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding utf8 | ConvertFrom-Json
if ($manifest.product -ne "NetMind AI" -or $manifest.version -ne $Version -or
    $manifest.target -ne "win-x64" -or -not $manifest.selfContained) {
    throw "Release manifest identity does not match the requested self-contained win-x64 package."
}

$required = @(
    "NetMind.Workbench.exe",
    "CoreHost/NetMind.CoreHost.exe",
    "SandboxHost/NetMind.SandboxHost.exe",
    "docs/installation.md",
    "docs/development.md"
)
$manifestByPath = @{}
foreach ($entry in $manifest.files) { $manifestByPath[$entry.path] = $entry }
foreach ($path in $required) {
    if (-not $manifestByPath.ContainsKey($path)) { throw "Required release file is missing from manifest: $path" }
}

foreach ($entry in $manifest.files) {
    $filePath = Join-Path $packageRoot ($entry.path.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { throw "Manifest file is missing: $($entry.path)" }
    $file = Get-Item -LiteralPath $filePath
    if ($file.Length -ne [long]$entry.sizeBytes) { throw "Size mismatch: $($entry.path)" }
    $hash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $entry.sha256) { throw "SHA-256 mismatch: $($entry.path)" }
}

$actualPaths = Get-ChildItem -LiteralPath $packageRoot -File -Recurse |
    ForEach-Object { $_.FullName.Substring($packageRoot.Length).TrimStart([char]92, [char]47).Replace('\', '/') } |
    Where-Object { $_ -ne "release-manifest.json" }
$untracked = @($actualPaths | Where-Object { -not $manifestByPath.ContainsKey($_) })
if ($untracked.Count -gt 0) { throw "Files missing from release manifest: $($untracked -join ', ')" }

$debugArtifacts = @(Get-ChildItem -LiteralPath $packageRoot -File -Recurse |
    Where-Object { $_.Extension -in @('.pdb', '.dbg') })
if ($debugArtifacts.Count -gt 0) { throw "Release package contains debug artifacts: $($debugArtifacts.Name -join ', ')" }
if (Test-Path -LiteralPath (Join-Path $packageRoot "NetMind.CoreHost.exe")) {
    throw "CoreHost must only exist in the CoreHost subdirectory."
}
if (Test-Path -LiteralPath (Join-Path $packageRoot "NetMind.SandboxHost.exe")) {
    throw "SandboxHost must only exist in the SandboxHost subdirectory."
}

Write-Output "Release verified: $packageRoot"
Write-Output "Manifest files: $($manifest.files.Count)"
