# t9 install_adp: stage VBoxNetAdp6 driver package + create/seed the root devnode (t3/t7 recipe)
# Layered install: (1) pnputil add-driver, (2) devnode seed if absent, (3) restart, (4) state forensics
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_install_adp.txt"
"t9_install_adp $(Get-Date -Format o)" | Out-File $out -Encoding ascii
function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

$inf = "$work\VBoxNetAdp6.inf"
Log "--- step 0: sanity ---"
Log ("inf present: " + (Test-Path $inf))
Log ("sys hash: " + (Get-FileHash "$work\VBoxNetAdp6.sys" -Algorithm SHA256).Hash)
Log ("inf hash: " + (Get-FileHash $inf -Algorithm SHA256).Hash)
Log ("pre-existing drivers\VBoxNetAdp6.sys: " + (Test-Path 'C:\Windows\System32\drivers\VBoxNetAdp6.sys'))

Log "--- step 1: pnputil /add-driver VBoxNetAdp6.inf /install ---"
$pn = & pnputil.exe /add-driver $inf /install 2>&1 | Out-String
Log $pn
Log "pnputil exit=$LASTEXITCODE"
# capture the oemXX.inf assigned
$oem = ''
$m = [regex]::Match($pn, 'Published Name\s*:\s*(oem\d+\.inf)', 'IgnoreCase')
if ($m.Success) { $oem = $m.Groups[1].Value }
if (-not $oem) { $m = [regex]::Match($pn, '(oem\d+\.inf)', 'IgnoreCase'); if ($m.Success) { $oem = $m.Groups[1].Value } }
Log "assigned package: $oem"

Log "--- step 2: devnode presence check (hwid sun_VBoxNetAdp) ---"
Log (& powershell.exe -NoProfile -Command "Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { `$_.InstanceId -match 'SUN_VBOXNETADP' } | Format-List InstanceId, Status, Class, Problem, ProblemDescription" 2>&1 | Out-String)

Log "--- step 3: devnode seeding via t3 recipe IF absent ---"
$ek = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\SUN_VBOXNETADP\0000'
$ekBefore = Test-Path $ek
Log ("enum key before mkdev: " + $ekBefore)
# devid ROOT\SUN_VBOXNETADP\0000, parent HTREE\ROOT\0 (proven recipe: create FIRST, seed enum key AFTER)
Log (& "$work\t9_poc.exe" $out mkdev 'ROOT\SUN_VBOXNETADP\0000' 'HTREE\ROOT\0' 2>&1 | Out-String)

Log "--- step 3b: seed enum key (AFTER devnode creation; t3 recipe) ---"
if (-not $ekBefore -and (Test-Path $ek)) {
  # devnode (and its enum key) were created by THIS run - full seeding
  New-ItemProperty -Path $ek -Name 'Service' -Value 'VBoxNetAdp' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'Class' -Value 'Net' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'ClassGUID' -Value '{4d36e972-e325-11ce-bfc1-08002be10318}' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'HardwareID' -Value @('sun_VBoxNetAdp', 'SUN_VBOXNETADP') -PropertyType MultiString -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'ConfigFlags' -Value 0 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'DeviceDesc' -Value 'VirtualBox Host-Only Ethernet Adapter' -PropertyType String -Force | Out-Null
  Log "enum key fully seeded at $ek (t9-created devnode)"
} elseif ((Test-Path $ek) -and -not (Get-ItemProperty $ek -Name 'HardwareID' -ErrorAction SilentlyContinue)) {
  # key exists (hardware-initiated install auto-created it) but has NO HardwareID - add the id fields only
  New-ItemProperty -Path $ek -Name 'Service' -Value 'VBoxNetAdp' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'Class' -Value 'Net' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'ClassGUID' -Value '{4d36e972-e325-11ce-bfc1-08002be10318}' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'HardwareID' -Value @('sun_VBoxNetAdp', 'SUN_VBOXNETADP') -PropertyType MultiString -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'ConfigFlags' -Value 0 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $ek -Name 'DeviceDesc' -Value 'VirtualBox Host-Only Ethernet Adapter' -PropertyType String -Force | Out-Null
  Log "enum key existed without HardwareID - id fields seeded (t9-created devnode)"
} else {
  Log "enum key pre-existing with HardwareID present - NOT touched"
}
# also the driver-key side (t5 lesson layer 1): Class Net service binding
$dk = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
Log ("net class key present: " + (Test-Path $dk))

Log "--- step 3c: pre-create service VBoxNetAdp (t9-owned; absent confirmed earlier) ---"
Log (& sc.exe query VBoxNetAdp 2>&1 | Out-String)
Log (& sc.exe create VBoxNetAdp type= kernel start= demand binPath= "$work\VBoxNetAdp6.sys" 2>&1 | Out-String)
Log (& sc.exe qc VBoxNetAdp 2>&1 | Out-String)

Log "--- step 4: restart device ---"
Log (& pnputil.exe /restart-device 'ROOT\SUN_VBOXNETADP\0000' 2>&1 | Out-String)

Log "--- step 5: post-restart state ---"
Log (& powershell.exe -NoProfile -Command "Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { `$_.InstanceId -match 'SUN_VBOXNETADP' } | Format-List InstanceId, Status, Class, Problem, ProblemDescription" 2>&1 | Out-String)
Log (& "$work\t9_poc.exe" $out devstat 'ROOT\SUN_VBOXNETADP\0000' 2>&1 | Out-String)
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\SUN_VBOXNETADP\0000') {
  "devnode created by t9 $(Get-Date -Format o)" | Out-File "$work\t9_adp_created.txt" -Encoding ascii
  Log 't9_adp_created.txt marker written (cleanup will remove this devnode)'
}
Log '--- service state ---'
Log (& sc.exe query VBoxNetAdp 2>&1 | Out-String)
Log (& driverquery.exe /v 2>&1 | Select-String -Pattern 'VBoxNetAdp' | Out-String)
Log '--- setupapi.dev.log tail (VBox lines, t5 forensics) ---'
$sapi = 'C:\Windows\INF\setupapi.dev.log'
if (Test-Path $sapi) {
  $lines = Get-Content $sapi -ErrorAction SilentlyContinue
  $hits = @(); for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'VBoxNetAdp|sun_VBoxNetAdp|VBoxSup') { $hits += $i } }
  if ($hits.Count -gt 0) {
    $from = [Math]::Max(0, $hits[0] - 12)
    $to = [Math]::Min($lines.Count - 1, $hits[$hits.Count - 1] + 24)
    Log ("setupapi lines " + $from + ".." + $to + ":")
    Log (($lines[$from..$to] | Select-Object -First 90) | Out-String)
  } else { Log 'no VBox lines in setupapi.dev.log' }
} else { Log 'setupapi.dev.log not present' }
"t9_install_adp boundary $(Get-Date -Format o)" | Out-File "$work\t9_alive.txt" -Encoding ascii
exit 0
