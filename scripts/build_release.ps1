param(
    [string]$Version = "1.0.0",
    [string]$DotnetCli = "dotnet",
    [switch]$SkipNsis,
    [switch]$SkipMsix
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$publishDir = Join-Path $repoRoot "artifacts\publish\win-x64"
$distDir = Join-Path $repoRoot "dist"
$installerDir = Join-Path $repoRoot "installer"

New-Item -ItemType Directory -Path $publishDir -Force | Out-Null
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

# Normalize semver (strip leading v, ignore pre-release suffix for AssemblyVersion/AppxVersion)
$cleanVer = $Version.TrimStart('v')
$numericCore = ($cleanVer -split '-')[0]
$parts = $numericCore.Split('.')
while ($parts.Count -lt 3) { $parts += "0" }
$threePartVer = "$($parts[0]).$($parts[1]).$($parts[2])"
$fourPartVer = "$threePartVer.0"

Write-Host "=== Publishing StartupGuard v$cleanVer (win-x64 self-contained) ==="
$projects = @(
    "src\StartupGuard.Service\StartupGuard.Service.csproj",
    "src\StartupGuard.TrayHost\StartupGuard.TrayHost.csproj",
    "src\StartupGuard.ProbeHost\StartupGuard.ProbeHost.csproj",
    "src\StartupGuard.App\StartupGuard.App.csproj"
)

foreach ($proj in $projects) {
    $projPath = Join-Path $repoRoot $proj
    Write-Host "Publishing $proj ..."
    & $DotnetCli publish $projPath `
        -c Release `
        -r win-x64 `
        --self-contained true `
        -p:Platform=x64 `
        -p:Version="$cleanVer" `
        -p:AssemblyVersion="$fourPartVer" `
        -p:FileVersion="$fourPartVer" `
        -p:PublishSingleFile=false `
        -p:DebugType=none `
        -p:DebugSymbols=false `
        -o $publishDir `
        --nologo
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed for $proj"
    }
}

# 1. Build Portable ZIP
$portableZip = Join-Path $distDir "StartupGuard-v$cleanVer-win-x64.zip"
if (Test-Path $portableZip) { Remove-Item $portableZip -Force }

$portableStage = Join-Path ([System.IO.Path]::GetTempPath()) ("StartupGuard-Portable-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $portableStage -Force | Out-Null
try {
    Copy-Item (Join-Path $publishDir "*") $portableStage -Recurse -Force
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

# 2. Build NSIS Installer
if (-not $SkipNsis) {
    $nsisCandidates = @(
        (Join-Path $repoRoot "..\.tools\nsis\nsis-3.11\makensis.exe"),
        "C:\Program Files (x86)\NSIS\makensis.exe",
        "C:\Program Files\NSIS\makensis.exe"
    )
    $makensis = $nsisCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $makensis) {
        $cmd = Get-Command makensis.exe -ErrorAction SilentlyContinue
        if ($cmd) { $makensis = $cmd.Source }
    }
    if (-not $makensis) {
        throw "NSIS (makensis.exe) not found."
    }

    $nsiScript = Join-Path $installerDir "StartupGuard.nsi"
    Write-Host "Building NSIS installer with $makensis (PRODUCT_VERSION=$cleanVer)..."
    & $makensis "/DPRODUCT_VERSION=$cleanVer" $nsiScript
    if ($LASTEXITCODE -ne 0) {
        throw "makensis failed with code $LASTEXITCODE"
    }
}

# 3. Build MSIX Package + Anonymous Self-Signed Test Certificate (zero PII)
if (-not $SkipMsix) {
    $sdkRoots = @(
        (Join-Path $repoRoot "..\.tools\winsdk\bin"),
        "C:\Program Files (x86)\Windows Kits\10\bin"
    )
    $makeAppx = $null
    $signTool = $null
    foreach ($sdkRoot in $sdkRoots) {
        if (-not (Test-Path $sdkRoot)) { continue }
        $latestBin = Get-ChildItem $sdkRoot -Directory |
            Where-Object { $_.Name -match '^\d+\.' } |
            Sort-Object { [version]$_.Name } -Descending |
            ForEach-Object { Join-Path $_.FullName "x64" } |
            Where-Object { (Test-Path (Join-Path $_ "makeappx.exe")) -and (Test-Path (Join-Path $_ "signtool.exe")) } |
            Select-Object -First 1
        if ($latestBin) {
            $makeAppx = Join-Path $latestBin "makeappx.exe"
            $signTool = Join-Path $latestBin "signtool.exe"
            break
        }
    }
    if (-not $makeAppx) { $makeAppx = (Get-Command makeappx.exe -ErrorAction SilentlyContinue)?.Source }
    if (-not $signTool) { $signTool = (Get-Command signtool.exe -ErrorAction SilentlyContinue)?.Source }

    if (-not $makeAppx -or -not $signTool) {
        throw "Windows SDK makeappx.exe / signtool.exe not found."
    }

    $msixStage = Join-Path ([System.IO.Path]::GetTempPath()) ("StartupGuard-Msix-" + [Guid]::NewGuid().ToString("N"))
    $pfxPath = Join-Path ([System.IO.Path]::GetTempPath()) ("StartupGuard-Ephem-" + [Guid]::NewGuid().ToString("N") + ".pfx")
    $certThumbprint = $null

    New-Item -ItemType Directory -Path (Join-Path $msixStage "Assets") -Force | Out-Null

    try {
        Copy-Item (Join-Path $publishDir "*") $msixStage -Recurse -Force
        $manifestXml = Get-Content (Join-Path $installerDir "AppxManifest.xml") -Raw -Encoding UTF8
        $manifestXml = $manifestXml -replace 'Version="1\.0\.0\.0"', "Version=`"$fourPartVer`""
        [System.IO.File]::WriteAllText((Join-Path $msixStage "AppxManifest.xml"), $manifestXml, [System.Text.Encoding]::UTF8)

        # Render minimal valid MSIX logo PNGs from System.Drawing / icon without external assets bloat
        Add-Type -AssemblyName System.Drawing
        $icoPath = Join-Path $installerDir "app.ico"
        $logoSpecs = @{
            "StoreLogo.png"       = @(50, 50)
            "Square150x150Logo.png" = @(150, 150)
            "Square44x44Logo.png" = @(44, 44)
            "Wide310x150Logo.png" = @(310, 150)
        }
        foreach ($entry in $logoSpecs.GetEnumerator()) {
            $w = $entry.Value[0]
            $h = $entry.Value[1]
            $bmp = New-Object System.Drawing.Bitmap($w, $h)
            $g = [System.Drawing.Graphics]::FromImage($bmp)
            $g.Clear([System.Drawing.Color]::FromArgb(0, 103, 192))
            if (Test-Path $icoPath) {
                $ico = New-Object System.Drawing.Icon($icoPath, 48, 48)
                $drawSize = [Math]::Min($w, $h) - 12
                $x = [int](($w - $drawSize) / 2)
                $y = [int](($h - $drawSize) / 2)
                $g.DrawIcon($ico, (New-Object System.Drawing.Rectangle($x, $y, $drawSize, $drawSize)))
                $ico.Dispose()
            }
            $g.Dispose()
            $bmp.Save((Join-Path $msixStage "Assets\$($entry.Key)"), [System.Drawing.Imaging.ImageFormat]::Png)
            $bmp.Dispose()
        }

        $msixOut = Join-Path $distDir "StartupGuard-v$cleanVer-win-x64.msix"
        if (Test-Path $msixOut) { Remove-Item $msixOut -Force }

        & $makeAppx pack /o /d $msixStage /p $msixOut
        if ($LASTEXITCODE -ne 0) {
            throw "makeappx failed with code $LASTEXITCODE"
        }

        # Create ephemeral anonymous self-signed certificate (Zero PII: no username, no email, no machine domain)
        $cert = New-SelfSignedCertificate `
            -Type Custom `
            -Subject "CN=StartupGuard" `
            -FriendlyName "StartupGuard Self-Signed Test Certificate" `
            -KeyUsage DigitalSignature `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}") `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddYears(3)
        $certThumbprint = $cert.Thumbprint

        $ephemPwdText = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
        $ephemPwd = ConvertTo-SecureString -String $ephemPwdText -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $ephemPwd | Out-Null

        $cerOut = Join-Path $distDir "StartupGuard-TestCert.cer"
        Export-Certificate -Cert $cert -FilePath $cerOut -Type CERT | Out-Null

        & $signTool sign /fd SHA256 /f $pfxPath /p $ephemPwdText $msixOut
        if ($LASTEXITCODE -ne 0) {
            throw "signtool failed with code $LASTEXITCODE"
        }

        Write-Host "Built & signed MSIX: $msixOut"
        Write-Host "Exported anonymous public cert (zero PII): $cerOut"
    }
    finally {
        if ($certThumbprint) {
            Remove-Item "Cert:\CurrentUser\My\$certThumbprint" -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $pfxPath) { Remove-Item $pfxPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $msixStage) { Remove-Item $msixStage -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# 4. Write SHA256 checksums for release notes
$checksumFile = Join-Path $distDir "SHA256SUMS.txt"
$artifacts = Get-ChildItem $distDir -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | Sort-Object Name
$lines = foreach ($f in $artifacts) {
    $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $($f.Name)"
}
[System.IO.File]::WriteAllLines($checksumFile, $lines, [System.Text.Encoding]::UTF8)

Write-Host "=== Release artifacts ready in $distDir ==="
Get-ChildItem $distDir -File | Select-Object Name, Length
