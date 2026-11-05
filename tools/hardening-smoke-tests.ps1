# hardening-round-1 automated smoke tests (task T014)
# Run from an elevated PowerShell against a RUNNING, elevated simplewall.
#
# Covers (see docs/specs/hardening-round-1/design.md):
#   Test-FR08 : bogus WM_NOTIFICATION pointer must be ignored, not crash (FR-08)
#   Test-FR07 : WM_COMMAND KILL/allow while disarmed must not kill/permit (FR-07)
#   Test-FR03 : planted internal-rules file must be ignored (FR-03) - optional, restarts simplewall
#
# Usage:
#   .\tools\hardening-smoke-tests.ps1                     # FR-08 + FR-07-ready checks
#   .\tools\hardening-smoke-tests.ps1 -WithNotification   # also runs the FR-07 gate check (needs a visible notification)
#   .\tools\hardening-smoke-tests.ps1 -TestInternalOverride -ProfileDir "$env:APPDATA\simplewall"
#
# Notes: FR-01/FR-02/FR-05/FR-06/FR-09 are manual procedures -> verification.md

[CmdletBinding()]
param(
    [string]$ProcessName = 'simplewall',
    [switch]$WithNotification,
    [switch]$TestInternalOverride,
    [string]$ProfileDir
)

$ErrorActionPreference = 'Stop'

Add-Type -Namespace Native -Name Win32 -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
'@

# WM_APP = 0x8000; WM_NOTIFICATION = WM_APP + 21 (src/global.h)
$WM_NOTIFICATION = 0x8000 + 21
$WM_COMMAND      = 0x0111
$IDC_KILLPROCESS_BTN = 207   # src/resource.h
$IDC_ALLOW_BTN       = 208

function Get-SimplewallProcess {
    $p = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $p) { throw "simplewall process ('$ProcessName') is not running." }
    return $p
}

# ---------------------------------------------------------------
# Test-FR08: bogus pointer in WM_NOTIFICATION (FR-08)
# Expect: the message is ignored + logged; simplewall keeps running.
# ---------------------------------------------------------------
function Test-FR08 {
    $p = Get-SimplewallProcess
    $before = $p.Id

    # a same-desktop attacker would post exactly this: WM_APP+21 with a forged pointer
    [Native.Win32]::PostMessage($p.MainWindowHandle, $WM_NOTIFICATION, [IntPtr]::Zero, [IntPtr]0xDEADBEEFDEADBEEF) | Out-Null
    [Native.Win32]::PostMessage($p.MainWindowHandle, $WM_NOTIFICATION, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null

    Start-Sleep -Seconds 2

    $p2 = Get-Process -Id $before -ErrorAction SilentlyContinue
    if ($p2) {
        Write-Host "[PASS] Test-FR08: process alive after bogus WM_NOTIFICATION (pid $before)." -ForegroundColor Green
        return $true
    } else {
        Write-Host "[FAIL] Test-FR08: simplewall (pid $before) DIED after bogus WM_NOTIFICATION." -ForegroundColor Red
        return $false
    }
}

# ---------------------------------------------------------------
# Test-FR07: ungated actions on the notification window (FR-07)
# Expect: no process is killed and no PERMIT rule is minted while the
# safety timer has not armed the window.
# Note: the hardened WM_NOTIFICATION handler refuses NULL/unknown
# pointers, so we discover the process's top-level windows directly
# (EnumWindows) and post the gated WM_COMMAND to each of them.
# ---------------------------------------------------------------
function Test-FR07 {
    $p = Get-SimplewallProcess

    $script:targetHwnds = New-Object System.Collections.ArrayList
    $cb = [Native.Win32+EnumWindowsProc]{
        param($hWnd, $lParam)
        [uint32]$pid = 0
        [Native.Win32]::GetWindowThreadProcessId($hWnd, [ref]$pid) | Out-Null
        if ($pid -eq $p.Id) { $script:targetHwnds.Add($hWnd) | Out-Null }
        return $true
    }
    [Native.Win32]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null

    if ($script:targetHwnds.Count -eq 0) {
        Write-Warning "Test-FR07: no windows found for pid $($p.Id)."
        return $null
    }

    Write-Host "[*] Posting gated WM_COMMAND to $($script:targetHwnds.Count) window(s) of pid $($p.Id)..."

    foreach ($h in $script:targetHwnds) {
        # kill attempt while disarmed
        [Native.Win32]::PostMessage($h, $WM_COMMAND, [IntPtr]$IDC_KILLPROCESS_BTN, [IntPtr]::Zero) | Out-Null
        # rule-mint attempt while disarmed (special-rules range start)
        [Native.Win32]::PostMessage($h, $WM_COMMAND, [IntPtr]1000, [IntPtr]::Zero) | Out-Null
        # allow attempt while disarmed
        [Native.Win32]::PostMessage($h, $WM_COMMAND, [IntPtr]$IDC_ALLOW_BTN, [IntPtr]::Zero) | Out-Null
    }

    Start-Sleep -Seconds 2

    Write-Host "[INFO] Test-FR07: gated commands posted. Verify manually that no process was killed and no new PERMIT rule exists (main window -> Rules)."
    return $true
}

# ---------------------------------------------------------------
# Test-FR03: planted internal-rules file must be ignored (FR-03)
# Expect: after restart with a tampered file (blocks stripped, version
# bumped), telemetry addresses remain blocked -> connect fails.
# ---------------------------------------------------------------
function Test-FR03 {
    param([string]$PDir)

    $sourceRules = Join-Path $PSScriptRoot '..\bin\profile_internal.xml'
    if (-not (Test-Path $sourceRules)) { throw "bin\profile_internal.xml not found next to tools\." }
    if (-not $PDir -or -not (Test-Path $PDir)) { throw "Pass -ProfileDir <simplewall config dir>." }

    [xml]$xml = Get-Content $sourceRules -Raw
    # locate a BLOCK rule with a concrete remote address
    $blockRule = $xml.profile.rules.rule | Where-Object { $_.action -eq '0' -and $_.rule_remote } | Select-Object -First 1
    if (-not $blockRule) { throw "No block rule with a remote address found in profile_internal.xml." }
    $blockedAddr = ($blockRule.rule_remote -split ',')[0]

    $stamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $tampered = Join-Path $env:TEMP 'profile_internal_tampered.xml'
    $blockRule.ParentNode.RemoveChild($blockRule) | Out-Null
    # bump version/timestamp so the pre-hardening loader would have preferred this file
    if ($xml.profile.version) { $xml.profile.version = ([int64]$xml.profile.version + 1000).ToString() }
    if ($xml.profile.timestamp) { $xml.profile.timestamp = $stamp }
    $xml.Save($tampered)

    $target = Join-Path $PDir 'profile_internal.xml'
    Copy-Item $tampered $target -Force
    Write-Host "[*] Planted tampered profile_internal.xml (removed rule for $blockedAddr) into $PDir"

    Write-Host @"
[!] Restart simplewall now, then verify:
    1) the log contains 'on-disk internal profile ignored (untrusted source)' (LOG_LEVEL_WARNING)
    2) a connection to $blockedAddr (443/tcp) is still blocked:
       Test-NetConnection $blockedAddr -Port 443  -> must NOT succeed
    3) afterwards delete $target
"@
    return $true
}

# ---------------- main ----------------
$results = @()
$results += Test-FR08

if ($WithNotification) { $results += Test-FR07 }
else { Write-Host "[-] Test-FR07 skipped (pass -WithNotification while a notification is visible)." }

if ($TestInternalOverride) { $results += Test-FR03 -PDir $ProfileDir }

Write-Host ''
Write-Host 'Done. FR-01/FR-02/FR-05/FR-06/FR-09 are manual procedures: see docs/specs/hardening-round-1/verification.md'
