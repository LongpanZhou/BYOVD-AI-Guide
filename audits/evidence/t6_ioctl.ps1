# t6_ioctl.ps1 (agent t6) - Phase A step 7: IOCTL battery (IN-BOUNDS ONLY). Evidence: t6_ioctl.txt
# Only runs if an open succeeded. Uses t6_poc.exe session (scope guards inside the binary).
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t6_work'
$log  = "$work\t6_ioctl.txt"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t6_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t6_poc.exe"

W ("=== t6 ioctl battery {0} ===" -f (Get-Date -Format o))
Marker 'ioctl-start'

# derive candidate paths (prefer the \audioprotection single-open control file; then plain)
$dcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses'
$links = @()
try {
  foreach ($g in (Get-ChildItem $dcRoot -ErrorAction Stop)) {
    foreach ($c in (Get-ChildItem $g.PSPath -ErrorAction SilentlyContinue)) {
      if ($c.PSChildName -match 'T6NVHDA') { $links += ('\\?\' + $c.PSChildName.Substring(4)) }
    }
  }
} catch { W ("DeviceClasses scan ERROR: " + $_.Exception.Message) }

if ($links.Count -eq 0) {
  W 'NO interface link exists - the IOCTL battery CANNOT be delivered (pre-IOCTL open gate).'
  W 'Zero 0x264800 calls were made.'
} else {
  foreach ($link in $links) {
    W ('--- session battery on ' + $link + '\audioprotection ---')
    & $exe "$work\t6_ioctl_session.txt" session ($link + '\audioprotection') 2>&1 | Out-Null
    if (Test-Path "$work\t6_ioctl_session.txt") { Get-Content "$work\t6_ioctl_session.txt" | ForEach-Object { W ('  ' + $_) } }
    W ('--- session battery on plain ' + $link + ' ---')
    & $exe "$work\t6_ioctl_session2.txt" session $link 2>&1 | Out-Null
    if (Test-Path "$work\t6_ioctl_session2.txt") { Get-Content "$work\t6_ioctl_session2.txt" | ForEach-Object { W ('  ' + $_) } }
  }
}

W "--- post-battery service/devnode health ---"
& sc.exe query t6_nvhda 2>&1 | ForEach-Object { W ('  ' + $_) }
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\T6NVHDA\0000") {
  & $exe "$work\t6_ioctl_devstat.txt" devstat 'ROOT\T6NVHDA\0000' 2>&1 | Out-Null
  if (Test-Path "$work\t6_ioctl_devstat.txt") { Get-Content "$work\t6_ioctl_devstat.txt" | ForEach-Object { W ('  ' + $_) } }
}

W "--- System event log (last 8) after battery ---"
try { Get-WinEvent -LogName System -MaxEvents 8 -ErrorAction Stop | ForEach-Object { W ("  [{0}] id={1} prov={2} lvl={3}" -f $_.TimeCreated, $_.Id, $_.ProviderName, $_.Level) } }
catch { W ("  event ERROR: " + $_.Exception.Message) }

Marker 'ioctl-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
