# t6_open.ps1 (agent t6) - Phase A step 6: open tests (admin full token + restricted token).
# Adaptive: derives interface paths from DeviceClasses (T6NVHDA instances), then probes
# plain paths AND the static-audit control names appended (\audioprotection / \audioparameters).
# Evidence: t6_open.txt
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t6_work'
$log  = "$work\t6_open.txt"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Set-Content -Path "$work\t6_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t6_poc.exe"

function PocRun($a1, $a2, $a3) {
  $tmp = "$work\t6_open_last.txt"
  if (Test-Path $tmp) { Remove-Item $tmp -Force }
  & $exe $tmp $a1 $a2 $a3 2>&1 | Out-Null
  if (Test-Path $tmp) { Get-Content $tmp | ForEach-Object { W ('    ' + $_) } }
}

W ("=== t6 open tests {0} ===" -f (Get-Date -Format o))
Marker 'open-start'

# ---- derive candidate interface links from DeviceClasses ----
$dcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses'
$links = @()
try {
  foreach ($g in (Get-ChildItem $dcRoot -ErrorAction Stop)) {
    foreach ($c in (Get-ChildItem $g.PSPath -ErrorAction SilentlyContinue)) {
      if ($c.PSChildName -match 'T6NVHDA') { $links += ('\\?\' + $c.PSChildName.Substring(4)) }
    }
  }
} catch { W ("DeviceClasses scan ERROR: " + $_.Exception.Message) }

if ($links.Count -gt 0) {
  W ("interface links derived: " + $links.Count)
  $links | ForEach-Object { W ('  ' + $_) }
} else {
  W 'no T6NVHDA interface links in DeviceClasses (device did not register an interface)'
}

# ---- raw named-object probes (always) ----
W '--- raw named-object probes (\\.\audioprotection / \\.\audioparameters) ---'
foreach ($n in @('audioprotection','audioparameters')) { PocRun open ('\\.\' + $n) 'C0000000' }

# ---- per-link open matrix ----
foreach ($link in $links) {
  W ('--- open matrix for ' + $link + ' ---')
  foreach ($acc in @('C0000000','80000000','40000000','02000000')) {
    $lbl = switch ($acc) { 'C0000000' {'RW'} '80000000' {'GENERIC_WRITE'} '40000000' {'GENERIC_READ'} '02000000' {'MAXIMUM_ALLOWED'} }
    PocRun open $link $acc
  }
  W ('  --- appended-name opens (FileObject relative name = the single-open control files) ---')
  foreach ($suffix in @('\audioprotection','\audioparameters')) {
    PocRun open ($link + $suffix) 'C0000000'
  }
  W ('  --- single-open proof on suffixed path ---')
  PocRun singleopen ($link + '\audioprotection')
  W ('  --- security descriptor probe ---')
  PocRun sd ($link + '\audioprotection')
  PocRun sd $link
}

# ---- restricted-token opens (same matrix, restricted) ----
$target = $null
if ($links.Count -gt 0) { $target = $links[0] + '\audioprotection' } else { $target = '\\.\audioprotection' }
W ('--- restricted-token open (runas /trustlevel:0x20000) on ' + $target + ' ---')
$restrLog = "$work\t6_open_restricted.txt"
if (Test-Path $restrLog) { Remove-Item $restrLog -Force }
$inner = '"' + $exe + '" ' + $restrLog + ' open ' + $target + ' C0000000'
$ra = & runas.exe /trustlevel:0x20000 $inner 2>&1
$ra | ForEach-Object { W ('  runas: ' + $_) }
Start-Sleep 3
if (Test-Path $restrLog) { Get-Content $restrLog | ForEach-Object { W ('  restricted: ' + $_) } }
else { W '  restricted run produced NO output file (runas may have failed to spawn in this session)' }

# ---- whoami proof for the restricted run context ----
W '--- restricted-token identity proof ---'
$whoLog = "$work\t6_open_whoami.txt"
if (Test-Path $whoLog) { Remove-Item $whoLog -Force }
$ra2 = & runas.exe /trustlevel:0x20000 ('"C:\Windows\System32\whoami.exe" /all > ' + $whoLog) 2>&1
$ra2 | ForEach-Object { W ('  runas: ' + $_) }
Start-Sleep 3
if (Test-Path $whoLog) {
  $w = Get-Content $whoLog
  $w | Select-String -Pattern 'USER NAME|GROUP INFORMATION|Label:|BUILTIN\\Users|BUILTIN\\Administrators|Mandatory' | ForEach-Object { W ('  ' + $_.Line.Trim()) }
} else { W '  whoami under restricted token produced NO output file' }

Marker 'open-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
