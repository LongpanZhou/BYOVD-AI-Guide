# t4_ioctl.ps1 (agent t4) - Phase A steps 7-8: in-bounds IOCTL battery + the SINGLE
# 0x222028 acceptance probe (wLength=1, 9-byte out). NO 0x222024 / 0x222094.
# Evidence: t4_ioctl.txt
$log = 'C:\Users\vmdebug\Desktop\t4_work\t4_ioctl.txt'
$work = 'C:\Users\vmdebug\Desktop\t4_work'
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t4_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t4_poc.exe"

function ResolveBridgeLink {
  $root = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\{a2a39220-39f4-4b88-aecb-3d86a35dc748}'
  $c = Get-ChildItem $root -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like '*T4SILABSER*' } | Select-Object -First 1
  if ($c) { return ('\\?\' + $c.PSChildName.Substring(4)) } else { return $null }
}
function ResolveComLink {
  $root = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\{86e0d1e0-8089-11d0-9ce4-08003e301f73}'
  $c = Get-ChildItem $root -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like '*T4SILABSER*' } | Select-Object -First 1
  if ($c) { return ('\\?\' + $c.PSChildName.Substring(4)) } else { return $null }
}
function ResolveComDos {
  $ser = Get-ItemProperty 'HKLM:\HARDWARE\DEVICEMAP\SERIALCOMM' -ErrorAction SilentlyContinue
  if ($ser) { $m = $ser.PSObject.Properties | Where-Object { $_.Value -match 'Silabser' } | Select-Object -First 1; if ($m) { return ('\\.\' + $m.Name) } }
  return $null
}

W ("=== t4 ioctl battery {0} ===" -f (Get-Date -Format o))
W ('SCOPE: bounded probes only (0x222008, 0x222080, 0x222098, 0x22209C, 0x22200C) + ONE 0x222028 wLength=1 probe. No 0x222024/0x222094.')
Marker 'ioctl-start'

$targets = @()
$l = ResolveBridgeLink; if ($l) { $targets += ,@('bridge-interface', $l) }
$l = ResolveComLink;    if ($l) { $targets += ,@('comport-interface', $l) }
$l = ResolveComDos;     if ($l) { $targets += ,@('dos-com-name', $l) }
if ($targets.Count -eq 0) { W 'FATAL: no openable interface targets resolved - all IOCTLs skipped (0x222028 NOT sent)'; [IO.File]::WriteAllText($log,$sb.ToString()); exit 3 }

foreach ($t in $targets) {
  W ('--- IOCTL session on {0}: {1} ---' -f $t[0], $t[1])
  $tmp = "$work\t4_ioctl_session.txt"
  if (Test-Path $tmp) { Remove-Item $tmp -Force }
  & $exe $tmp session $t[1] 2>&1 | Out-Null
  $rc = $LASTEXITCODE
  W ('  t4_poc session exit=' + $rc)
  if (Test-Path $tmp) { Get-Content $tmp | ForEach-Object { W ('  ' + $_) } }
  if ($rc -eq 0) { W '  (session succeeded - stopping link fallbacks; 0x222028 acceptance probe dispatched at most once)'; break }
}
Marker 'ioctl-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
