# t5_mkdev.ps1 (agent t5) - Phase A step 4: devnode creation + seed + restart.
# PROVEN RECIPE (t1/t3): create devnode FIRST (flags=0, parent HTREE\ROOT\0),
# THEN seed the auto-created enum key, THEN pnputil /restart-device.
# RISK NOTE: restart triggers MiniportInitializeEx -> FUN_140004854 -> NdisRegisterDeviceEx
# with an UNINITIALIZED attributes dword (static audit vpnva.md section 2 Bug) - this call
# may BSOD the VM. All evidence is appended to t5_mkdev.txt progressively; aliveness
# markers are written immediately before and after the restart.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_mkdev.txt"
Remove-Item $log -Force -ErrorAction SilentlyContinue
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"

function Poc($c, $a1, $a2) {
  & $exe $log $c $a1 $a2 2>&1 | Out-Null
  return $LASTEXITCODE
}

WA ("=== t5 mkdev {0} ===" -f (Get-Date -Format o))
Marker 'mkdev-start'

# --- (a) no Enum\ROOT\T5VPNVA keys pre-existing ---
$preExisting = $false
foreach ($k in @('T5VPNVA','T5VPNVA2')) {
  $p = "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\$k"
  if (Test-Path $p) { WA ("PRE-EXISTING KEY (recipe requires none): " + $p); $preExisting = $true }
}
if ($preExisting) { WA "ABORT: remove pre-existing keys first (CR=0x1E otherwise)"; exit 5 }
WA "(a) enum keys T5VPNVA/T5VPNVA2 absent - OK"

# --- (b) create devnode FIRST ---
WA "(b) CM_Create_DevNodeW(ROOT\T5VPNVA\0000, parent=HTREE\ROOT\0, flags=0)"
$rc = Poc 'mkdev' 'ROOT\T5VPNVA\0000' ''
WA ("  poc exit=" + $rc)
if ($rc -ne 0) { WA "ABORT: devnode create failed (see CR above; CR=0x1E would mean keys were seeded first)"; exit 6 }

# --- (c) seed auto-created enum key ---
$k = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\T5VPNVA\0000'
if (-not (Test-Path $k)) { WA "ABORT: enum key was NOT auto-created by CfgMgr: $k"; exit 7 }
WA "(c) seeding enum key: $k"
New-ItemProperty -Path $k -Name 'ConfigFlags' -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $k -Name 'Class' -Value 'Net' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $k -Name 'ClassGUID' -Value '{4d36e972-e325-11ce-bfc1-08002be10318}' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $k -Name 'DeviceDesc' -Value 't5 Cisco VPN VA' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $k -Name 'Service' -Value 't5_vpnva' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $k -Name 'HardwareID' -Value 'ROOT\T5VPNVA' -PropertyType MultiString -Force | Out-Null
WA "  ConfigFlags=0 (DWORD), Class=Net, ClassGUID={4d36e972-...} (Net), DeviceDesc='t5 Cisco VPN VA', Service=t5_vpnva, HardwareID=ROOT\T5VPNVA (MULTI_SZ)"

# --- (d) restart (RISKY: miniport init -> NdisRegisterDeviceEx uninit dword) ---
WA "(d) pnputil /restart-device ROOT\T5VPNVA\0000  (triggers AddDevice/MiniportInitializeEx -> NdisRegisterDeviceEx)"
Marker 'mkdev-BEFORE-restart'
pnputil /restart-device 'ROOT\T5VPNVA\0000' 2>&1 | ForEach-Object { WA ("  " + $_) }
WA ("  pnputil exit: " + $LASTEXITCODE)
Start-Sleep -Seconds 8
Marker 'mkdev-after-restart'

# --- surface quick-check ---
WA "--- quick surface check (Net-class devnode) ---"
$rc = Poc 'devstat' 'ROOT\T5VPNVA\0000' ''
WA ("  devstat exit=" + $rc)
$rc = Poc 'qobj' '\Device' 'VPNVA'
WA ("  qobj \Device filter VPNVA -> matched=" + ($rc -eq 0))
$rc = Poc 'open' '\\.\VPNVA' 'C0000000'
WA ("  open \\.\VPNVA RW -> exit=" + $rc + " (0=open OK, 1=fail)")
try { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object Name | Format-Table Name,InterfaceDescription,Status,MediaConnectState,ifIndex -AutoSize | Out-String -Width 200 | ForEach-Object { WA $_ } } catch { WA ("Get-NetAdapter ERROR: " + $_.Exception.Message) }

if ($rc -ne 0) {
  WA "--- Net-class devnode produced NO openable \Device\VPNVA -> trying System-class variant T5VPNVA2 ---"
  $rc2 = Poc 'mkdev' 'ROOT\T5VPNVA2\0000' ''
  WA ("  mkdev T5VPNVA2 exit=" + $rc2)
  if ($rc2 -eq 0) {
    $k2 = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\T5VPNVA2\0000'
    New-ItemProperty -Path $k2 -Name 'ConfigFlags' -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $k2 -Name 'Class' -Value 'System' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $k2 -Name 'ClassGUID' -Value '{4d36e97d-e325-11ce-bfc1-08002be10318}' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $k2 -Name 'DeviceDesc' -Value 't5 Cisco VPN VA (System class)' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $k2 -Name 'Service' -Value 't5_vpnva' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $k2 -Name 'HardwareID' -Value 'ROOT\T5VPNVA2' -PropertyType MultiString -Force | Out-Null
    WA "  seeded T5VPNVA2: Class=System, ClassGUID={4d36e97d-...}, HardwareID=ROOT\T5VPNVA2, Service=t5_vpnva"
    Marker 'mkdev2-BEFORE-restart'
    pnputil /restart-device 'ROOT\T5VPNVA2\0000' 2>&1 | ForEach-Object { WA ("  " + $_) }
    Start-Sleep -Seconds 8
    Marker 'mkdev2-after-restart'
    $rc2 = Poc 'devstat' 'ROOT\T5VPNVA2\0000' ''
    $rc2 = Poc 'qobj' '\Device' 'VPNVA'
    $rc2 = Poc 'open' '\\.\VPNVA' 'C0000000'
    WA ("  open \\.\VPNVA RW after T5VPNVA2 -> exit=" + $rc2)
    try { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object Name | Format-Table Name,InterfaceDescription,Status,MediaConnectState,ifIndex -AutoSize | Out-String -Width 200 | ForEach-Object { WA $_ } } catch { WA ("Get-NetAdapter ERROR: " + $_.Exception.Message) }
  } else { WA "  T5VPNVA2 mkdev FAILED - variant abandoned" }
}

WA "--- Kernel-PnP/Configuration log (last 12) ---"
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 12 -ErrorAction Stop | ForEach-Object { WA ("  [{0}] id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } }
catch { WA ("  ERROR: " + $_.Exception.Message) }

Marker 'mkdev-done'
