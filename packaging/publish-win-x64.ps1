param(
    [string]$Version = "0.8.0",
    [switch]$SkipArchive
)

$ErrorActionPreference = "Stop"
if ($Version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$') {
    throw "Version must be a semantic version such as 0.8.0 or 0.8.0-preview.1."
}
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$artifactsRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot "artifacts"))
$stageRoot = [System.IO.Path]::GetFullPath((Join-Path $artifactsRoot "stage"))
$packageName = "NetMind-AI-$Version-win-x64"
$packageRoot = [System.IO.Path]::GetFullPath((Join-Path $stageRoot $packageName))

if (-not $packageRoot.StartsWith($stageRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Package output must stay under artifacts/stage."
}
if (Test-Path -LiteralPath $packageRoot) {
    Remove-Item -LiteralPath $packageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null

$common = @(
    "--configuration", "Release",
    "--runtime", "win-x64",
    "--self-contained", "true",
    "-p:Version=$Version",
    "-p:PublishSingleFile=true",
    "-p:IncludeNativeLibrariesForSelfExtract=true",
    "-p:DebugType=None",
    "-p:DebugSymbols=false"
)

& dotnet publish (Join-Path $projectRoot "src\NetMind.Workbench\NetMind.Workbench.csproj") @common --output $packageRoot
if ($LASTEXITCODE -ne 0) { throw "Workbench publish failed." }

$coreHostOutput = Join-Path $packageRoot "CoreHost"
$sandboxHostOutput = Join-Path $packageRoot "SandboxHost"
if (Test-Path -LiteralPath $coreHostOutput) { Remove-Item -LiteralPath $coreHostOutput -Recurse -Force }
if (Test-Path -LiteralPath $sandboxHostOutput) { Remove-Item -LiteralPath $sandboxHostOutput -Recurse -Force }
New-Item -ItemType Directory -Path $coreHostOutput -Force | Out-Null
New-Item -ItemType Directory -Path $sandboxHostOutput -Force | Out-Null
& dotnet publish (Join-Path $projectRoot "src\NetMind.CoreHost\NetMind.CoreHost.csproj") @common --output $coreHostOutput
if ($LASTEXITCODE -ne 0) { throw "CoreHost publish failed." }

# Bundle the WinDivert native files when available. Missing files only produce a warning.
$winDivertSource = Join-Path $projectRoot "packaging\windivert"
foreach ($winDivertFile in @("WinDivert.dll", "WinDivert64.sys")) {
    $winDivertPath = Join-Path $winDivertSource $winDivertFile
    if (Test-Path -LiteralPath $winDivertPath) {
        Copy-Item -LiteralPath $winDivertPath -Destination $coreHostOutput -Force
    } else {
        Write-Warning "Missing $winDivertFile; low-level transparent capture will be unavailable in this package."
    }
}
& dotnet publish (Join-Path $projectRoot "src\NetMind.SandboxHost\NetMind.SandboxHost.csproj") @common --output $sandboxHostOutput
if ($LASTEXITCODE -ne 0) { throw "SandboxHost publish failed." }

foreach ($orphanPattern in @("NetMind.CoreHost.*", "NetMind.SandboxHost.*")) {
    Get-ChildItem -LiteralPath $packageRoot -Filter $orphanPattern -File | Remove-Item -Force
}

$portableGuide = Get-ChildItem -LiteralPath (Join-Path $projectRoot "packaging") -Filter "*.txt" -File | Select-Object -First 1
if ($null -eq $portableGuide) { throw "Portable package guide was not found." }
Copy-Item -LiteralPath $portableGuide.FullName -Destination (Join-Path $packageRoot $portableGuide.Name)
$docsOutput = Join-Path $packageRoot "docs"
New-Item -ItemType Directory -Path $docsOutput -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot "docs\installation.md") -Destination $docsOutput
Copy-Item -LiteralPath (Join-Path $projectRoot "docs\development.md") -Destination $docsOutput

$files = Get-ChildItem -LiteralPath $packageRoot -File -Recurse | Sort-Object FullName | ForEach-Object {
    $relativePath = $_.FullName.Substring($packageRoot.Length).TrimStart([char]92, [char]47).Replace('\', '/')
    [ordered]@{
        path = $relativePath
        sizeBytes = $_.Length
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$manifest = [ordered]@{
    product = "NetMind AI"
    version = $Version
    target = "win-x64"
    selfContained = $true
    builtAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
    minimumOperatingSystem = "Windows 10 1903 x64"
    entryPoint = "NetMind.Workbench.exe"
    files = @($files)
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $packageRoot "release-manifest.json") -Encoding utf8

if (-not $SkipArchive) {
    $archivePath = Join-Path $artifactsRoot ($packageName + ".zip")
    if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
    Compress-Archive -LiteralPath $packageRoot -DestinationPath $archivePath -CompressionLevel Optimal
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$archiveHash  $([System.IO.Path]::GetFileName($archivePath))" | Set-Content -LiteralPath ($archivePath + ".sha256") -Encoding ascii
    Write-Output "Package: $archivePath"
    Write-Output "SHA-256: $archiveHash"
}
Write-Output "Package directory: $packageRoot"
