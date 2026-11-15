param(
    [string]$AppExe = "artifacts/publish/win-x64/StartupGuard.App.exe",
    [string]$AssetsDir = "assets"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Path $AssetsDir -Force | Out-Null

if (-not (Test-Path $AppExe)) {
    throw "StartupGuard.App.exe not found at: $AppExe"
}

$resolvedExe = (Resolve-Path $AppExe).Path
$resolvedOut = (Resolve-Path $AssetsDir).Path

Write-Host "Capturing automated dual-mode UI screenshots into $resolvedOut ..."
$proc = Start-Process -FilePath $resolvedExe -ArgumentList "--screenshot", $resolvedOut -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    throw "Screenshot process exited with code $($proc.ExitCode)."
}

$expected = @("preview_startup.jpg", "preview_contextmenu.jpg", "preview_review_logs.jpg")
foreach ($name in $expected) {
    $file = Join-Path $resolvedOut $name
    if (-not (Test-Path $file) -or (Get-Item $file).Length -lt 10240) {
        throw "Screenshot missing or unexpectedly small: $file"
    }
    Write-Host "  ✓ $name ($([math]::Round((Get-Item $file).Length / 1KB, 1)) KB)"
}
