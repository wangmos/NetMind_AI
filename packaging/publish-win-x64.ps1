param(
    [string]$Version = "0.8.0",
    [switch]$SkipArchive,
    # 默认自包含（目标机无需安装 .NET）。传 -SelfContained:$false 产出框架依赖包：
    # 体积小得多，但要求目标机已安装 .NET 10 桌面运行时。
    [bool]$SelfContained = $true
)

$ErrorActionPreference = "Stop"
if ($Version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$') {
    throw "Version must be a semantic version such as 0.8.0 or 0.8.0-preview.1."
}
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$artifactsRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot "artifacts"))
$stageRoot = [System.IO.Path]::GetFullPath((Join-Path $artifactsRoot "stage"))
$packageName = if ($SelfContained) { "NetMind-AI-$Version-win-x64" } else { "NetMind-AI-$Version-win-x64-framework-dependent" }
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
    "--self-contained", $(if ($SelfContained) { "true" } else { "false" }),
    "-p:Version=$Version",
    "-p:DebugType=None",
    "-p:DebugSymbols=false"
)
# 单文件只用于自包含包：框架依赖发布时，PublishSingleFile 会让 SDK 把仅用于
# 构建排序的 CoreHost / SandboxHost 项目引用判定为自包含可执行文件（NETSDK1151），
# 框架依赖包因此保持多文件布局——反正它本来就依赖已安装的运行时。
if ($SelfContained) {
    $common += @("-p:PublishSingleFile=true", "-p:IncludeNativeLibrariesForSelfExtract=true")
}

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
# 说明文件里的版本号与运行时要求必须跟着本次发布走，否则框架依赖包会写着「已包含运行时」误导用户。
$guideText = Get-Content -LiteralPath $portableGuide.FullName -Raw -Encoding UTF8
$guideText = [System.Text.RegularExpressions.Regex]::Replace($guideText, '\d+\.\d+\.\d+', $Version)
$bundledLine = "- 本包包含 .NET 10 运行时，不需要另外安装 .NET。"
$frameworkLine = "- 本包不含运行时，需要先安装 .NET 10 桌面运行时（Windows Desktop Runtime x64）：" +
    "https://dotnet.microsoft.com/download/dotnet/10.0"
if (-not $guideText.Contains($bundledLine)) { throw "Portable guide is missing the runtime requirement line." }
$guideText = $guideText.Replace($bundledLine, $(if ($SelfContained) { $bundledLine } else { $frameworkLine }))
Set-Content -LiteralPath (Join-Path $packageRoot $portableGuide.Name) -Value $guideText -Encoding utf8
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
    selfContained = $SelfContained
    builtAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
    minimumOperatingSystem = "Windows 10 1903 x64"
    runtimeRequirement = $(if ($SelfContained) { "无需安装 .NET" } else { ".NET 10 桌面运行时（Windows Desktop Runtime x64）" })
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
