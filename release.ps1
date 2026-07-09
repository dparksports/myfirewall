<#
.SYNOPSIS
    MyFirewall release script — auto-bumps the patch version, builds both
    the CLI and Desktop projects, zips the artifacts, commits the version
    bump, creates a Git tag, and publishes a GitHub release via the REST API.

.PARAMETER BumpType
    Which version component to increment: Major, Minor, or Patch (default).

.PARAMETER Token
    GitHub personal access token (or set env var GITHUB_TOKEN).

.PARAMETER Notes
    Optional release notes. Auto-generated if omitted.

.PARAMETER DryRun
    Print what would happen without making any changes.

.EXAMPLE
    .\release.ps1
    .\release.ps1 -BumpType Minor
    .\release.ps1 -Token ghp_xxx -Notes "Fixed UAC elevation bug"
#>

param(
    [ValidateSet("Major","Minor","Patch")]
    [string]$BumpType = "Patch",
    [string]$Token    = $env:GITHUB_TOKEN,
    [string]$Notes    = "",
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Config ------------------------------------------------------------------

$RepoRoot      = $PSScriptRoot
$Owner         = "dparksports"
$Repo          = "myfirewall"
$CliCsproj     = Join-Path $RepoRoot "MyFirewall.csproj"
$DesktopCsproj = Join-Path $RepoRoot "MyFirewall.Desktop\MyFirewall.Desktop.csproj"
$PublishDir    = Join-Path $RepoRoot "publish"
$CliOut        = Join-Path $PublishDir "cli"
$DesktopOut    = Join-Path $PublishDir "desktop"
$CliZip        = Join-Path $PublishDir "release_cli_win_x64.zip"
$DesktopZip    = Join-Path $PublishDir "release_desktop_win_x64.zip"

# --- Helpers -----------------------------------------------------------------

function Write-Step([string]$msg) {
    Write-Host "`n==> $msg" -ForegroundColor Cyan
}

function Write-OK([string]$msg) {
    Write-Host "    [OK] $msg" -ForegroundColor Green
}

function Write-Fail([string]$msg) {
    Write-Host "    [FAIL] $msg" -ForegroundColor Red
    exit 1
}

function Run([string]$cmd, [string[]]$cmdArgs) {
    if ($DryRun) {
        Write-Host "    [DRY] $cmd $($cmdArgs -join ' ')" -ForegroundColor Yellow
        return
    }
    & $cmd @cmdArgs
    if ($LASTEXITCODE -ne 0) { Write-Fail "$cmd exited with code $LASTEXITCODE" }
}

# --- 1. Read current version from CLI csproj ---------------------------------

Write-Step "Reading current version from $CliCsproj"

[xml]$cliXml = Get-Content $CliCsproj
$currentVer  = $cliXml.Project.PropertyGroup.Version
if (-not $currentVer) { Write-Fail "Could not read <Version> from $CliCsproj" }

$parts = $currentVer -split '\.'
if ($parts.Count -lt 3) { Write-Fail "Expected MAJOR.MINOR.PATCH, got '$currentVer'" }

[int]$maj = $parts[0]
[int]$min = $parts[1]
[int]$pat = $parts[2]

switch ($BumpType) {
    "Major" { $maj++; $min = 0; $pat = 0 }
    "Minor" { $min++;           $pat = 0 }
    "Patch" { $pat++                     }
}

$NewVersion = "$maj.$min.$pat"
$TagName    = "v$NewVersion"

Write-OK "Current: $currentVer  ->  New: $NewVersion"

# --- 2. Ensure the tag doesn't already exist ---------------------------------

Write-Step "Checking that tag $TagName doesn't already exist"

$existingTag = git tag --list $TagName
if ($existingTag) { Write-Fail "Tag $TagName already exists. Aborting." }

# --- 3. Patch both csproj files ----------------------------------------------

Write-Step "Patching version in both .csproj files"

function Set-CsprojVersion([string]$path, [string]$ver) {
    $content = Get-Content $path -Raw
    $content = $content -replace '<Version>[^<]+</Version>',                         "<Version>$ver</Version>"
    $content = $content -replace '<AssemblyVersion>[^<]+</AssemblyVersion>',         "<AssemblyVersion>$ver.0</AssemblyVersion>"
    $content = $content -replace '<FileVersion>[^<]+</FileVersion>',                  "<FileVersion>$ver.0</FileVersion>"
    if (-not $DryRun) { Set-Content $path $content -NoNewline }
}

Set-CsprojVersion $CliCsproj     $NewVersion
Set-CsprojVersion $DesktopCsproj $NewVersion
Write-OK "Patched $CliCsproj"
Write-OK "Patched $DesktopCsproj"

# --- 4. Build & publish CLI --------------------------------------------------

Write-Step "Publishing CLI  ->  $CliOut"

if (-not $DryRun) { New-Item -ItemType Directory -Force $CliOut | Out-Null }

Run "dotnet" @(
    "publish", $CliCsproj,
    "-c", "Release",
    "-r", "win-x64",
    "--self-contained", "true",
    "-p:PublishSingleFile=true",
    "-o", $CliOut
)
Write-OK "CLI published"

# --- 5. Build & publish Desktop ----------------------------------------------

Write-Step "Publishing Desktop  ->  $DesktopOut"

if (-not $DryRun) { New-Item -ItemType Directory -Force $DesktopOut | Out-Null }

Run "dotnet" @(
    "publish", $DesktopCsproj,
    "-c", "Release",
    "-r", "win-x64",
    "--self-contained", "true",
    "-p:PublishSingleFile=true",
    "-o", $DesktopOut
)
Write-OK "Desktop published"

# --- 6. Zip artifacts --------------------------------------------------------

Write-Step "Creating zip archives"

if (-not $DryRun) {
    if (Test-Path $CliZip)     { Remove-Item $CliZip }
    if (Test-Path $DesktopZip) { Remove-Item $DesktopZip }
    Compress-Archive -Path "$CliOut\*"     -DestinationPath $CliZip
    Compress-Archive -Path "$DesktopOut\*" -DestinationPath $DesktopZip
}

Write-OK "$(Split-Path $CliZip -Leaf)"
Write-OK "$(Split-Path $DesktopZip -Leaf)"

# --- 7. Commit version bump --------------------------------------------------

Write-Step "Committing version bump"

Run "git" @("add", $CliCsproj, $DesktopCsproj)
Run "git" @("commit", "-m", "Bump version to $NewVersion")
Run "git" @("push")
Write-OK "Committed and pushed"

# --- 8. Create and push tag --------------------------------------------------

Write-Step "Creating tag $TagName"

Run "git" @("tag", "-a", $TagName, "-m", "Release $NewVersion")
Run "git" @("push", "origin", $TagName)
Write-OK "Tag $TagName pushed"

# --- 9. Create GitHub release via REST API -----------------------------------

Write-Step "Creating GitHub release for $TagName"

if (-not $Token) {
    Write-Fail "No GitHub token found. Set env var GITHUB_TOKEN or pass -Token <your-pat>"
}

if (-not $Notes) {
    $Notes = @"
## MyFirewall $NewVersion

### Downloads
| Asset | Description |
|---|---|
| ``release_cli_win_x64.zip`` | CLI tool (Windows x64, self-contained) |
| ``release_desktop_win_x64.zip`` | Desktop WPF app (Windows x64, self-contained) |
"@
}

$Headers = @{
    Authorization = "token $Token"
    Accept        = "application/vnd.github.v3+json"
}

$Body = @{
    tag_name         = $TagName
    target_commitish = "master"
    name             = "MyFirewall $NewVersion"
    body             = $Notes
    draft            = $false
    prerelease       = $false
} | ConvertTo-Json

if ($DryRun) {
    Write-Host "    [DRY] Would POST to https://api.github.com/repos/$Owner/$Repo/releases" -ForegroundColor Yellow
} else {
    $Release = Invoke-RestMethod `
        -Method      Post `
        -Uri         "https://api.github.com/repos/$Owner/$Repo/releases" `
        -Headers     $Headers `
        -Body        $Body `
        -ContentType "application/json"

    Write-OK "Release created: $($Release.html_url)"

    # --- 10. Upload assets ---------------------------------------------------

    Write-Step "Uploading release assets"

    $UploadBase = $Release.upload_url -replace '\{.*\}', ''

    foreach ($zipPath in @($CliZip, $DesktopZip)) {
        $fileName  = Split-Path $zipPath -Leaf
        $uploadUrl = "${UploadBase}?name=${fileName}"

        Write-Host "    Uploading $fileName ..." -ForegroundColor DarkCyan
        $zipBytes = [System.IO.File]::ReadAllBytes($zipPath)

        Invoke-RestMethod `
            -Method      Post `
            -Uri         $uploadUrl `
            -Headers     $Headers `
            -Body        $zipBytes `
            -ContentType "application/zip" | Out-Null

        Write-OK "Uploaded $fileName"
    }
}

# --- Done --------------------------------------------------------------------

Write-Host ""
Write-Host "  Release $TagName complete!" -ForegroundColor Green
Write-Host "  https://github.com/$Owner/$Repo/releases/tag/$TagName" -ForegroundColor DarkGray
Write-Host ""
