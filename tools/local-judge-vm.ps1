# local-judge-vm.ps1 - the SAC-free local runtime judge (GUI chain, G-5).
#
# WHY THIS EXISTS: Smart App Control re-rolls per-hash cloud verdicts on
# EVERY rebuild (no developer exception exists - see docs/specs/gui/
# runtime-judges.md for the sourced research), so fresh composite builds
# cannot execute on the owner's host. Windows Sandbox is NOT the answer
# (it inherits the host's SAC policy). A full VM without SAC configured
# is the community-recommended and research-verified judge.
#
# USAGE: inside the VM (shared folder or copied tree), from the repo root:
#   powershell -ExecutionPolicy Bypass -File tools\local-judge-vm.ps1
# Artifacts land in judge-output\ beside the repo root (breadcrumb,
# selftest result, comsvcs dump on hang, screenshot on hang).
#
# The logic mirrors the CI selftest step 1:1 (smoke-test.yml) so a VM
# verdict is directly comparable to a runner verdict.

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $repo 'bin\64\simplewall.exe'
if (-not (Test-Path $bin)) { Write-Error "exe missing: $bin"; exit 99 }

$out = Join-Path $repo 'judge-output'
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $out | Out-Null

# crash evidence: full LocalDumps (same keys as the CI step)
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\simplewall.exe" /v DumpFolder /t REG_EXPAND_SZ /d "$out" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\simplewall.exe" /v DumpType /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\simplewall.exe" /v DumpCount /t REG_DWORD /d 3 /f | Out-Null

# portable posture: same bypass as CI (the freeze chain ran through the
# APPDATA profile path; the marker resolves the profile beside the exe)
New-Item -ItemType File -Path (Join-Path (Split-Path -Parent $bin) 'portable.dat') -Force | Out-Null

$p = Start-Process -FilePath $bin -ArgumentList '-gui-selftest' -PassThru
$deadline = (Get-Date).AddSeconds (75)

while (-not $p.HasExited -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }

if (-not $p.HasExited)
{
	Write-Host 'HANG: selftest still running after 75s - comsvcs dump + screenshot'
	Start-Process -FilePath rundll32.exe -ArgumentList "C:\Windows\System32\comsvcs.dll, MiniDump $($p.Id) $out\selftest-hang.dmp full" -Wait -NoNewWindow

	Add-Type -AssemblyName System.Drawing
	Add-Type -AssemblyName System.Windows.Forms
	$b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
	$bmp = New-Object System.Drawing.Bitmap ($b.Width, $b.Height)
	$g = [System.Drawing.Graphics]::FromImage ($bmp)
	$g.CopyFromScreen (0, 0, 0, 0, (New-Object System.Drawing.Size ($b.Width, $b.Height)))
	$g.Dispose ()
	$bmp.Save ((Join-Path $out 'selftest-hang.png'), [System.Drawing.Imaging.ImageFormat]::Png)
	$bmp.Dispose ()

	Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
	Write-Host '--- breadcrumbs:'
	if (Test-Path (Join-Path (Split-Path -Parent $bin) 'breadcrumb.txt')) { Get-Content (Join-Path (Split-Path -Parent $bin) 'breadcrumb.txt') | Set-Content (Join-Path $out 'breadcrumb.txt'); Get-Content (Join-Path $out 'breadcrumb.txt') }
	else { Write-Host 'NO breadcrumb.txt - hung BEFORE init:enter' }

	Write-Error 'selftest hung inside the VM (dump at judge-output\selftest-hang.dmp)'
	exit 1
}

$code = $p.ExitCode
Write-Host "selftest exit code: $code"
if (Test-Path (Join-Path (Split-Path -Parent $bin) 'selftest-result.txt'))
{
	Get-Content (Join-Path (Split-Path -Parent $bin) 'selftest-result.txt') | Set-Content (Join-Path $out 'selftest-result.txt')
	Get-Content (Join-Path $out 'selftest-result.txt')
}

if (Test-Path (Join-Path (Split-Path -Parent $bin) 'crash-report.txt'))
{
	Copy-Item (Join-Path (Split-Path -Parent $bin) 'crash-report.txt') $out -Force
	Get-Content (Join-Path $out 'crash-report.txt')
}

# the GUI testdrive runs after a green selftest (same order as CI)
if ($code -eq 0)
{
	Write-Host 'selftest GREEN - running the gui testdrive'
	powershell -ExecutionPolicy Bypass -File (Join-Path $repo 'tools\gui-testdrive.ps1') -ExePath $bin -OutDir (Join-Path $out 'gui-screens')
	Write-Host "testdrive exit: $LASTEXITCODE"
}

if ($code -ne 0) { Write-Error "composite selftest failed (exit=$code)"; exit 1 }
Write-Host 'JUDGE VERDICT: GREEN'
exit 0
