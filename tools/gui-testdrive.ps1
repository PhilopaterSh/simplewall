# gui-testdrive (G-2, NFR-06/r4): drives the composite shell (-gui) on a
# real desktop session, captures a screenshot per page + the search and
# theme paths, and uploads them as CI artifacts. The screenshots are the
# acceptance evidence — a human (or agent) reads them afterwards.
# Local machines under SAC cannot run fresh builds (per-hash cloud
# verdicts) — this harness is the SAC-free judge path.
param(
	[Parameter(Mandatory = $true)][string]$ExePath,
	[Parameter(Mandatory = $true)][string]$OutDir
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class GuiDrive {
	public delegate bool EnumProc(IntPtr hwnd, IntPtr lparam);
	[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc proc, IntPtr lparam);
	[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
	[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hwnd, StringBuilder sb, int max);
	[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassNameW(IntPtr hwnd, StringBuilder sb, int max);
	[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hwnd);
	[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr FindWindowW(string cls, string title);
	[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr FindWindowExW(IntPtr parent, IntPtr after, string cls, string title);
	[DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr hwnd, uint msg, IntPtr wp, IntPtr lp);
	[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT r);
	[DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr hwnd, out RECT r);
	[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
	[DllImport("user32.dll")] public static extern IntPtr GetProcessWindowStation();
	[DllImport("user32.dll")] public static extern bool GetUserObjectInformationW(IntPtr h, int index, StringBuilder sb, int max, out uint needed);
	[StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
	public static string DesktopName() {
		var sb = new StringBuilder(256); uint n;
		GetUserObjectInformationW(GetProcessWindowStation(), 2, sb, 256, out n); // UOI_NAME
		return sb.ToString();
	}
	public static string WindowsOfPid(uint pid) {
		var sb = new StringBuilder();
		EnumWindows((h, l) => {
			uint wpid; GetWindowThreadProcessId(h, out wpid);
			if (wpid == pid) {
				var t = new StringBuilder(128); GetWindowTextW(h, t, 128);
				var c = new StringBuilder(128); GetClassNameW(h, c, 128);
				sb.Append("[").Append(c).Append("] '").Append(t).Append("' visible=").Append(IsWindowVisible(h)).Append("; ");
			}
			return true;
		}, IntPtr.Zero);
		return sb.ToString();
	}
}
"@

if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$manifest = @{ window_found = $false; shots = @(); errors = @() }

function Save-Shot([string]$name) {
	Start-Sleep -Milliseconds 700
	$r = New-Object GuiDrive+RECT
	[GuiDrive]::GetWindowRect($script:hwnd, [ref]$r) | Out-Null
	$w = $r.R - $r.L; $h = $r.B - $r.T
	if ($w -le 0 -or $h -le 0) { $manifest.errors += "shot $name : bad rect"; return }
	$bmp = New-Object System.Drawing.Bitmap($w, $h)
	$g = [System.Drawing.Graphics]::FromImage($bmp)
	$g.CopyFromScreen($r.L, $r.T, 0, 0, (New-Object System.Drawing.Size($w, $h)))
	$g.Dispose()
	$file = Join-Path $OutDir "$name.png"
	$bmp.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
	$bmp.Dispose()
	$manifest.shots += $name
	Write-Host "SHOT: $name ($w x $h)"
}

function Page([int]$downs) {
	# rail navigation: arrows move the focus, Enter activates (G-1 G1-M5)
	for ($i = 0; $i -lt $downs; $i++) {
		[GuiDrive]::PostMessageW($script:hwnd, 0x0100, [IntPtr]0x28, [IntPtr]0) | Out-Null # VK_DOWN
		[GuiDrive]::PostMessageW($script:hwnd, 0x0101, [IntPtr]0x28, [IntPtr]0) | Out-Null # VK_UP
	}
	Start-Sleep -Milliseconds 300
	[GuiDrive]::PostMessageW($script:hwnd, 0x0100, [IntPtr]0x0D, [IntPtr]0) | Out-Null # VK_RETURN
	[GuiDrive]::PostMessageW($script:hwnd, 0x0101, [IntPtr]0x0D, [IntPtr]0) | Out-Null
	Start-Sleep -Milliseconds 500
}

Write-Host "Launching $ExePath -gui"
$proc = Start-Process -FilePath $ExePath -ArgumentList '-gui' -PassThru

# retry the window find up to ~20s (init + first paint can be slow on a
# cold runner; the G-2 selftest step also runs immediately before us)
$script:hwnd = [IntPtr]::Zero
for ($try = 0; $try -lt 20; $try++) {
	Start-Sleep -Seconds 1
	$script:hwnd = [GuiDrive]::FindWindowW('quietwall_shell', $null)
	if ($script:hwnd -ne [IntPtr]::Zero) { break }
}

if ($script:hwnd -eq [IntPtr]::Zero) {
	$manifest.errors += 'window quietwall_shell not found'
	if ($proc.HasExited) { $manifest.errors += "process exited early, code $($proc.ExitCode)" }
	$manifest.desktop = [GuiDrive]::DesktopName()
	$manifest.process_windows = [GuiDrive]::WindowsOfPid($proc.Id)
	$manifest | ConvertTo-Json | Set-Content (Join-Path $OutDir 'manifest.json')
	Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
	Write-Host 'FAIL: shell window not found'
	Write-Host ("desktop: " + $manifest.desktop)
	Write-Host ("process windows: " + $manifest.process_windows)
	exit 1
}

$manifest.window_found = $true
[GuiDrive]::SetForegroundWindow($script:hwnd) | Out-Null

# page 1: Apps (default) + the search path
$edit = [GuiDrive]::FindWindowExW($script:hwnd, [IntPtr]::Zero, 'EDIT', $null)
if ($edit -ne [IntPtr]::Zero) {
	[GuiDrive]::PostMessageW($edit, 0x000C, [IntPtr]1, [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni('host')) | Out-Null # WM_SETTEXT
	Start-Sleep -Milliseconds 900 # debounce 250ms + repaint
	Save-Shot '1-apps-search'
	[GuiDrive]::PostMessageW($edit, 0x000C, [IntPtr]1, [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni('')) | Out-Null
	Start-Sleep -Milliseconds 900
}
Save-Shot '1-apps'

# pages 2..6 in rail order
Page 1; Save-Shot '2-rules'
Page 1; Save-Shot '3-packs'
Page 1; Save-Shot '4-lockdown'
Page 1; Save-Shot '5-log'
Page 1; Save-Shot '6-settings'

# theme toggle: settings row 5 checkbox (client coords; RTL right side)
$cl = New-Object GuiDrive+RECT
[GuiDrive]::GetClientRect($script:hwnd, [ref]$cl) | Out-Null
$boxX = $cl.R - 200 - 16 - 8 - 8   # rail width + margin + half checkbox
$boxY = 16 + 60 + 4 * 44 + 18      # content.top + gates + theme row center
[GuiDrive]::PostMessageW($script:hwnd, 0x0200, [IntPtr]0, [IntPtr](($boxY -shl 16) -bor ($boxX -band 0xFFFF))) | Out-Null # WM_MOUSEMOVE
[GuiDrive]::PostMessageW($script:hwnd, 0x0201, [IntPtr]1, [IntPtr](($boxY -shl 16) -bor ($boxX -band 0xFFFF))) | Out-Null # WM_LBUTTONUP (scaffold toggles on down; up keeps state clean)
[GuiDrive]::PostMessageW($script:hwnd, 0x0200, [IntPtr]0, [IntPtr](($boxY -shl 16) -bor ($boxX -band 0xFFFF))) | Out-Null
[GuiDrive]::PostMessageW($script:hwnd, 0x0201, [IntPtr]1, [IntPtr](($boxY -shl 16) -bor ($boxX -band 0xFFFF))) | Out-Null
Start-Sleep -Milliseconds 900
Save-Shot '6-settings-light'
[GuiDrive]::PostMessageW($script:hwnd, 0x0201, [IntPtr]1, [IntPtr](($boxY -shl 16) -bor ($boxX -band 0xFFFF))) | Out-Null
[GuiDrive]::PostMessageW($script:hwnd, 0x0200, [IntPtr]0, [IntPtr](($boxY -shl 16) -bor ($boxX -band 0xFFFF))) | Out-Null

Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
$manifest | ConvertTo-Json | Set-Content (Join-Path $OutDir 'manifest.json')
Write-Host "DONE: $($manifest.shots.Count) shots; errors: $($manifest.errors.Count)"
exit 0
