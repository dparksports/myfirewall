<#
.SYNOPSIS
    Diagnostic script - tests Windows Firewall COM API directly.
    Must be run as Administrator (right-click, Run as Administrator).
#>

Write-Host "`n=== MyFirewall Diagnostic ===" -ForegroundColor Cyan
Write-Host ""

# 1. Check elevation
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "[1] Running as Administrator: $isAdmin" -ForegroundColor $(if ($isAdmin) { "Green" } else { "Red" })
if (-not $isAdmin) {
    Write-Host "    *** NOT ELEVATED - this is likely the root cause. ***" -ForegroundColor Red
    Write-Host "    Right-click this script, Run as Administrator" -ForegroundColor Yellow
}

# 2. Try creating the policy object
Write-Host ""
try {
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    Write-Host "[2] HNetCfg.FwPolicy2 created: OK" -ForegroundColor Green
    Write-Host "    Current profile: $($policy.CurrentProfileTypes)"
    Write-Host "    Rule count: $($policy.Rules.Count)"
} catch {
    Write-Host "[2] HNetCfg.FwPolicy2 FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 3. Try creating a rule object
Write-Host ""
$testRuleName = "TCP-Monitor-DIAG-TEST-DELETE-ME"
try {
    $rule = New-Object -ComObject HNetCfg.FWRule
    Write-Host "[3] HNetCfg.FWRule created: OK" -ForegroundColor Green
} catch {
    Write-Host "[3] HNetCfg.FWRule FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 4. Set properties one at a time to find the failing property
Write-Host ""
Write-Host "[4] Setting rule properties one-by-one..." -ForegroundColor Cyan

$steps = @(
    @{ Prop = "Name";            Value = $testRuleName },
    @{ Prop = "Description";     Value = "Diagnostic test rule" },
    @{ Prop = "Protocol";        Value = 6 },
    @{ Prop = "RemoteAddresses"; Value = "23.217.118.213" },
    @{ Prop = "Direction";       Value = 2 },
    @{ Prop = "Action";          Value = 0 },
    @{ Prop = "Enabled";         Value = $true },
    @{ Prop = "Profiles";        Value = 7 }
)

foreach ($s in $steps) {
    try {
        $rule.$($s.Prop) = $s.Value
        Write-Host ("    {0} = {1}  ...  OK" -f $s.Prop, $s.Value) -ForegroundColor Green
    } catch {
        Write-Host ("    {0} = {1}  ...  FAILED: {2}" -f $s.Prop, $s.Value, $_.Exception.Message) -ForegroundColor Red
    }
}

# 5. Try adding the rule
Write-Host ""
try {
    $policy.Rules.Add($rule)
    Write-Host "[5] policy.Rules.Add(): OK - rule added successfully!" -ForegroundColor Green

    # Clean up
    try { $policy.Rules.Remove($testRuleName) } catch {}
    Write-Host "    (Cleaned up test rule)" -ForegroundColor DarkGray
} catch {
    Write-Host "[5] policy.Rules.Add() FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    HResult: 0x$([Convert]::ToString($_.Exception.InnerException.HResult, 16))" -ForegroundColor Red
}

# 6. Also test Protocol=ANY(256) + RemoteAddresses
Write-Host ""
Write-Host "[6] Testing Protocol=ANY(256) + RemoteAddresses (expected to fail)..." -ForegroundColor Cyan
try {
    $rule2 = New-Object -ComObject HNetCfg.FWRule
    $rule2.Name            = "TCP-Monitor-DIAG-ANY-DELETE-ME"
    $rule2.Description     = "Diagnostic: Protocol=ANY + RemoteAddresses"
    $rule2.Protocol        = 256
    $rule2.RemoteAddresses = "23.217.118.213"
    $rule2.Direction       = 2
    $rule2.Action          = 0
    $rule2.Enabled         = $true
    $rule2.Profiles        = 7
    $policy.Rules.Add($rule2)
    Write-Host "    Protocol=ANY + RemoteAddresses: OK (unexpected!)" -ForegroundColor Yellow
    try { $policy.Rules.Remove("TCP-Monitor-DIAG-ANY-DELETE-ME") } catch {}
} catch {
    Write-Host "    Protocol=ANY + RemoteAddresses: FAILED as expected: $($_.Exception.Message)" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Diagnostic Complete ===" -ForegroundColor Cyan
Write-Host ""
