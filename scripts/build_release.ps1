param(
    [string]$Version = "1.0.3",
    [string]$DotnetCli = "dotnet",
    [string[]]$Archs = @("x64", "arm64"),
    [string[]]$DeployModes = @("self-contained", "framework-dependent"),
    [switch]$SkipSetup
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$distDir = Join-Path $repoRoot "dist"
$installerDir = Join-Path $repoRoot "installer"

New-Item -ItemType Directory -Path $distDir -Force | Out-Null

# Clean stale release packages in dist/ so SHA256SUMS.txt only reflects this build
Get-ChildItem $distDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "StartupGuard-*" -or $_.Name -eq "SHA256SUMS.txt" } |
    Remove-Item -Force -ErrorAction SilentlyContinue

# Normalize semver (strip leading v, ignore pre-release suffix for AssemblyVersion/FileVersion)
$cleanVer = $Version.TrimStart('v')
$numericCore = ($cleanVer -split '-')[0]
$parts = $numericCore.Split('.')
while ($parts.Count -lt 3) { $parts += "0" }
$threePartVer = "$($parts[0]).$($parts[1]).$($parts[2])"
$fourPartVer = "$threePartVer.0"

$projects = @(
    "src\StartupGuard.Service\StartupGuard.Service.csproj",
    "src\StartupGuard.TrayHost\StartupGuard.TrayHost.csproj",
    "src\StartupGuard.ProbeHost\StartupGuard.ProbeHost.csproj",
    "src\StartupGuard.App\StartupGuard.App.csproj"
)

$iscc = $null
if (-not $SkipSetup) {
    $innoCandidates = @(
        (Join-Path $repoRoot "..\.tools\inno6\ISCC.exe"),
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe"
    )
    $iscc = $innoCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) {
        $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
        if ($cmd) { $iscc = $cmd.Source }
    }
    if (-not $iscc) {
        throw "Inno Setup 6.4+ (ISCC.exe) not found."
    }
}

$issScript = Join-Path $installerDir "StartupGuard.iss"

foreach ($rawArch in $Archs) {
    $arch = $rawArch.Trim().ToLowerInvariant()
    if ($arch -notin @("x64", "arm64")) {
        throw "Unsupported target architecture '$arch'. StartupGuard supports 64-bit x64 and arm64 only."
    }
    $rid = "win-$arch"
    $msbuildPlatform = if ($arch -eq "arm64") { "ARM64" } else { "x64" }

    foreach ($rawMode in $DeployModes) {
        $deployMode = $rawMode.Trim().ToLowerInvariant()
        if ($deployMode -notin @("self-contained", "framework-dependent")) {
            throw "Unsupported deploy mode '$deployMode'. Expected 'self-contained' or 'framework-dependent'."
        }
        $selfContainedFlag = if ($deployMode -eq "self-contained") { "true" } else { "false" }

        $publishDir = Join-Path $repoRoot "artifacts\publish\$rid-$deployMode"
        if (Test-Path $publishDir) {
            Remove-Item $publishDir -Recurse -Force
        }
        New-Item -ItemType Directory -Path $publishDir -Force | Out-Null

        Write-Host "=== Publishing StartupGuard v$cleanVer ($arch / $deployMode) ==="
        foreach ($proj in $projects) {
            $projPath = Join-Path $repoRoot $proj
            Write-Host "  -> $proj ($rid, self-contained=$selfContainedFlag)"
            & $DotnetCli publish $projPath `
                -c Release `
                -r $rid `
                --self-contained $selfContainedFlag `
                -p:Platform=$msbuildPlatform `
                -p:Version="$cleanVer" `
                -p:AssemblyVersion="$fourPartVer" `
                -p:FileVersion="$fourPartVer" `
                -p:PublishSingleFile=false `
                -p:DebugType=none `
                -p:DebugSymbols=false `
                -o $publishDir `
                --nologo
            if ($LASTEXITCODE -ne 0) {
                throw "dotnet publish failed for $proj ($rid / $deployMode)"
            }
        }

        # 1. Build Portable ZIP (StartupGuard-<ver>-<arch>-<mode>-portable.zip)
        $portableZip = Join-Path $distDir "StartupGuard-$cleanVer-$arch-$deployMode-portable.zip"
        if (Test-Path $portableZip) { Remove-Item $portableZip -Force }

        $portableStage = Join-Path ([System.IO.Path]::GetTempPath()) ("StartupGuard-Portable-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $portableStage -Force | Out-Null
        try {
            Copy-Item (Join-Path $publishDir "*") $portableStage -Recurse -Force
            Get-ChildItem $portableStage -Filter "*.pdb" -Recurse -File | Remove-Item -Force -ErrorAction SilentlyContinue
            foreach ($doc in @("README.md", "LICENSE", "THIRD-PARTY-NOTICES.md")) {
                $docPath = Join-Path $repoRoot $doc
                if (Test-Path $docPath) { Copy-Item $docPath $portableStage -Force }
            }
            Compress-Archive -Path (Join-Path $portableStage "*") -DestinationPath $portableZip -Force
            Write-Host "Built Portable ZIP: $portableZip"
        }
        finally {
            if (Test-Path $portableStage) { Remove-Item $portableStage -Recurse -Force -ErrorAction SilentlyContinue }
        }

        # 2. Build Inno Setup 6.4+ Installer (StartupGuard-<ver>-<arch>-<mode>-Setup.exe)
        if (-not $SkipSetup) {
            $setupBase = "StartupGuard-$cleanVer-$arch-$deployMode-Setup"
            $setupOut = Join-Path $distDir "$setupBase.exe"
            if (Test-Path $setupOut) { Remove-Item $setupOut -Force }

            Write-Host "Building Inno Setup: $setupOut"
            & $iscc `
                "/Q" `
                "/DProductVersion=$threePartVer" `
                "/DTargetArch=$arch" `
                "/DDeployMode=$deployMode" `
                "/DPublishDir=$publishDir" `
                "/DOutputDir=$distDir" `
                "/DOutputBaseFilename=$setupBase" `
                $issScript
            if ($LASTEXITCODE -ne 0) {
                throw "ISCC.exe failed ($arch / $deployMode) with code $LASTEXITCODE"
            }
        }
    }
}

# 3. Write SHA256 checksums for release notes
$checksumFile = Join-Path $distDir "SHA256SUMS.txt"
$artifacts = Get-ChildItem $distDir -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | Sort-Object Name
$lines = foreach ($f in $artifacts) {
    $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $($f.Name)"
}
[System.IO.File]::WriteAllLines($checksumFile, $lines, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "=== Release artifacts ready in $distDir ==="
Get-ChildItem $distDir -File | Sort-Object Name | Select-Object Name, Length
