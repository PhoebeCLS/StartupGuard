#Requires -Version 5.1
param(
    [Parameter(Mandatory)]
    [string]$Version,

    [string]$DistDir = "",
    [string]$X64Sha256 = "",
    [string]$Arm64Sha256 = "",
    [string]$OutputDirectory = "",
    [string]$RepoSlug = "PhoebeCLS/StartupGuard",
    [string]$ManifestVersion = "1.10.0"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$cleanVer = $Version.TrimStart('v').Trim()
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($DistDir)) {
    $DistDir = Join-Path $repoRoot "dist"
} else {
    $DistDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DistDir)
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot "packaging\winget\manifests\p\PhoebeCLS\StartupGuard\$cleanVer"
} else {
    $OutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
}

$x64ExeName = "StartupGuard-$cleanVer-x64-self-contained-Setup.exe"
$arm64ExeName = "StartupGuard-$cleanVer-arm64-self-contained-Setup.exe"

if ([string]::IsNullOrWhiteSpace($X64Sha256)) {
    $x64Path = Join-Path $DistDir $x64ExeName
    if (-not (Test-Path -LiteralPath $x64Path)) {
        throw "Missing x64 self-contained installer for hash calculation: $x64Path"
    }
    $X64Sha256 = (Get-FileHash -LiteralPath $x64Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

if ([string]::IsNullOrWhiteSpace($Arm64Sha256)) {
    $arm64Path = Join-Path $DistDir $arm64ExeName
    if (-not (Test-Path -LiteralPath $arm64Path)) {
        throw "Missing arm64 self-contained installer for hash calculation: $arm64Path"
    }
    $Arm64Sha256 = (Get-FileHash -LiteralPath $arm64Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function ConvertTo-YamlScalar {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return "''" }
    return "'" + ($Value -replace "'", "''") + "'"
}

function Write-ManifestFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SchemaType,
        [Parameter(Mandatory)][string[]]$BodyLines
    )
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $header = @(
        "# Created with StartupGuard WinGet manifest generator",
        "# yaml-language-server: `$schema=https://aka.ms/winget-manifest.$SchemaType.$ManifestVersion.schema.json",
        ""
    )
    [System.IO.File]::WriteAllLines($Path, ($header + $BodyLines), [System.Text.UTF8Encoding]::new($false))
}

$packageId = "PhoebeCLS.StartupGuard"
$packageName = "StartupGuard"
$displayNameArp = "StartupGuard (启动项与上下文菜单原生守护)"
$productCode = "{B8E9B7D2-9F5C-4D3B-9C0A-5F1A7D2E410B}_is1"
$baseRepoUrl = "https://github.com/$RepoSlug"
$tagName = "v$cleanVer"
$releaseNotesUrl = "$baseRepoUrl/releases/tag/$tagName"
$x64Url = "$baseRepoUrl/releases/download/$tagName/$x64ExeName"
$arm64Url = "$baseRepoUrl/releases/download/$tagName/$arm64ExeName"

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

# 1. Version manifest
$versionFile = Join-Path $OutputDirectory "$packageId.yaml"
Write-ManifestFile -Path $versionFile -SchemaType "version" -BodyLines @(
    "PackageIdentifier: $packageId",
    "PackageVersion: $cleanVer",
    "DefaultLocale: zh-CN",
    "ManifestType: version",
    "ManifestVersion: $ManifestVersion"
)

# 2. Locale manifests (zh-CN default, zh-TW, en-US)
$locales = @(
    [ordered]@{
        Locale = "zh-CN"
        ManifestType = "defaultLocale"
        ShortDescription = "Windows 10/11 原生自启项、服务、驱动与右键菜单实时守护工具。"
        Description = "StartupGuard 用于监控与管理系统启动程序、Win32 服务、内核驱动、计划任务、系统策略以及经典与 Windows 11 现代右键菜单，支持新增改动先拦截后审核、六维规则演化匹配与桌面沙箱扩展探测。"
        Tags = @("自启管理", "启动项", "右键菜单", "服务管理", "Windows", "WPF")
    },
    [ordered]@{
        Locale = "zh-TW"
        ManifestType = "locale"
        ShortDescription = "Windows 10/11 原生開機啟動項、服務、驅動程式與右鍵選單守護工具。"
        Description = "StartupGuard 用於監控與管理系統啟動程式、Win32 服務、核心驅動程式、排程工作、系統原則以及傳統與 Windows 11 現代右鍵選單，支援新增異動先攔截後審核與規則比對。"
        Tags = @("啟動項", "右鍵選單", "服務管理", "Windows", "WPF")
    },
    [ordered]@{
        Locale = "en-US"
        ManifestType = "locale"
        ShortDescription = "Native Windows 10/11 startup, service, driver, and context menu guard."
        Description = "StartupGuard monitors and manages Windows startup items, Win32 services, kernel drivers, scheduled tasks, system policies, and classic/Windows 11 modern context menus with intercept-before-review protection and adaptive rules."
        Tags = @("startup", "context-menu", "services", "windows", "security", "wpf")
    }
)

foreach ($loc in $locales) {
    $locFile = Join-Path $OutputDirectory "$packageId.locale.$($loc.Locale).yaml"
    $lines = @(
        "PackageIdentifier: $packageId",
        "PackageVersion: $cleanVer",
        "PackageLocale: $($loc.Locale)",
        "Publisher: PhoebeCLS",
        "PublisherUrl: https://github.com/PhoebeCLS",
        "PublisherSupportUrl: $baseRepoUrl/issues",
        "PackageName: $packageName",
        "PackageUrl: $baseRepoUrl",
        "License: GPL-3.0",
        "LicenseUrl: $baseRepoUrl/blob/main/LICENSE",
        "ShortDescription: $(ConvertTo-YamlScalar $loc.ShortDescription)",
        "Description: $(ConvertTo-YamlScalar $loc.Description)",
        "Tags:"
    )
    foreach ($t in $loc.Tags) {
        $lines += "- $(ConvertTo-YamlScalar $t)"
    }
    $lines += @(
        "ReleaseNotesUrl: $releaseNotesUrl",
        "ManifestType: $($loc.ManifestType)",
        "ManifestVersion: $ManifestVersion"
    )
    Write-ManifestFile -Path $locFile -SchemaType $loc.ManifestType -BodyLines $lines
}

# 3. Installer manifest (targets self-contained x64 & arm64 Inno Setup installers)
$installerFile = Join-Path $OutputDirectory "$packageId.installer.yaml"
Write-ManifestFile -Path $installerFile -SchemaType "installer" -BodyLines @(
    "PackageIdentifier: $packageId",
    "PackageVersion: $cleanVer",
    "Platform:",
    "- Windows.Desktop",
    "MinimumOSVersion: 10.0.19041.0",
    "InstallerType: inno",
    "Scope: machine",
    "UpgradeBehavior: install",
    "InstallModes:",
    "- interactive",
    "- silent",
    "- silentWithProgress",
    "InstallerSwitches:",
    "  Silent: /VERYSILENT /NORESTART",
    "  SilentWithProgress: /SILENT /NORESTART",
    "ProductCode: $(ConvertTo-YamlScalar $productCode)",
    "AppsAndFeaturesEntries:",
    "- DisplayName: $(ConvertTo-YamlScalar $displayNameArp)",
    "  Publisher: PhoebeCLS",
    "  DisplayVersion: $cleanVer",
    "  ProductCode: $(ConvertTo-YamlScalar $productCode)",
    "Installers:",
    "- Architecture: x64",
    "  InstallerUrl: $x64Url",
    "  InstallerSha256: $X64Sha256",
    "- Architecture: arm64",
    "  InstallerUrl: $arm64Url",
    "  InstallerSha256: $Arm64Sha256",
    "ManifestType: installer",
    "ManifestVersion: $ManifestVersion"
)

Write-Host "Generated WinGet manifests for $packageId v$cleanVer in $OutputDirectory"
Write-Output $OutputDirectory
