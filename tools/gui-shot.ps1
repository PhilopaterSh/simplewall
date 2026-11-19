$src = @'
[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr FindWindowW(string c, string t);
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
public struct RECT { public int L, T, R, B; }
'@
Add-Type -MemberDefinition $src -Name U32 -Namespace W | Out-Null
Add-Type -AssemblyName System.Windows.Forms,System.Drawing

$h = [W.U32]::FindWindowW('quietwall_shell', $null)
Write-Host "HWND=$h"
if ($h -eq [IntPtr]::Zero) { Write-Host 'NOTFOUND'; exit 1 }

[W.U32]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 1000
$r = New-Object W.U32+RECT
[W.U32]::GetWindowRect($h, [ref]$r) | Out-Null
$w = $r.R - $r.L; $hh = $r.B - $r.T
Write-Host "RECT=$($r.L),$($r.T) ${w} x ${hh}"

$bmp = New-Object System.Drawing.Bitmap $w, $hh
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
$bmp.Save('C:\Users\WDAGUtilityAccount\Desktop\mergetest\shell_live.png')
Write-Host 'SAVED'
