# Convert the generated PNG icon into a multi-size ICO (PNG-compressed entries, Windows 7+).
param(
    [string]$Source = "$env:USERPROFILE\.qoder-cn\vibe_images\netmind-app-icon_1786241487.png",
    [string]$Target = "$PSScriptRoot\..\src\NetMind.Workbench\Assets\app.ico"
)

Add-Type -AssemblyName System.Drawing

$sizes = @(256, 64, 48, 32, 16)
$pngBytesList = New-Object System.Collections.Generic.List[byte[]]

foreach ($size in $sizes) {
    $original = [System.Drawing.Image]::FromFile($Source)
    $resized = New-Object System.Drawing.Bitmap($original, $size, $size)
    $stream = New-Object System.IO.MemoryStream
    $resized.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngBytesList.Add($stream.ToArray())
    $stream.Dispose()
    $resized.Dispose()
    $original.Dispose()
}

$targetDir = Split-Path $Target -Parent
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

$fs = [System.IO.File]::Create($Target)
$writer = New-Object System.IO.BinaryWriter($fs)
# ICONDIR: reserved, type (1 = icon), entry count
$writer.Write([uint16]0)
$writer.Write([uint16]1)
$writer.Write([uint16]$sizes.Count)

$headerSize = 6 + 16 * $sizes.Count
$offset = $headerSize
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $size = $sizes[$i]
    $bytes = $pngBytesList[$i]
    $dim = if ($size -ge 256) { 0 } else { $size }
    $writer.Write([byte]$dim)
    $writer.Write([byte]$dim)
    $writer.Write([byte]0)
    $writer.Write([byte]0)
    $writer.Write([uint16]1)
    $writer.Write([uint16]32)
    $writer.Write([uint32]$bytes.Length)
    $writer.Write([uint32]$offset)
    $offset += $bytes.Length
}
foreach ($bytes in $pngBytesList) { $writer.Write($bytes) }
$writer.Dispose()
$fs.Dispose()
Write-Host "Generated $Target with sizes: $($sizes -join ', ')"
