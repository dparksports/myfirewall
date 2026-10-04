# Regenerates the repo infographics (assets/*.png) from the HTML sources
# using headless Microsoft Edge. Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File assets\render_infographics.ps1
param(
    [string]$EdgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
)

$ErrorActionPreference = "Stop"
$assets = $PSScriptRoot

$targets = @(
    @{ Html = "infographic.html"; Png = "infographic.png"; W = 1600; H = 900 },
    @{ Html = "architecture.html"; Png = "architecture.png"; W = 1600; H = 1040 }
)

foreach ($t in $targets) {
    $src  = Join-Path $assets $t.Html
    $out  = Join-Path $assets $t.Png
    $uri  = ([System.Uri]$src).AbsoluteUri
    $size = "$($t.W),$($t.H)"

    Write-Host "Rendering $($t.Html) -> $($t.Png) ($($t.W)x$($t.H) @2x)"
    & $EdgePath --headless=new --disable-gpu --hide-scrollbars `
        --force-device-scale-factor=2 --window-size=$size `
        --screenshot="$out" $uri 2>$null | Out-Null
    Start-Sleep -Milliseconds 500

    if (Test-Path $out) {
        $len = (Get-Item $out).Length
        Write-Host "  OK: $out ($([math]::Round($len/1KB)) KB)"
    } else {
        Write-Warning "  FAILED: $out was not created"
    }
}
