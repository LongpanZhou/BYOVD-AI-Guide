# t5_inf.ps1 (agent t5) - Phase A step 4b: REAL-INF deployment path.
# Static ground truth (vpnva.md): control device \Device\VPNVA is registered from
# MiniportInitializeEx - so the miniport MUST instantiate. The bare-root-devnode recipe
# (t5_mkdev.txt) failed: NdisMAddDevice -> CM_PROB_FAILED_ADD (31) / STATUS_OBJECT_NAME_NOT_FOUND.
# This script uses the actual Cisco driver package (vpnva-6.inf + vpnva-6.cat, WHQL-signed,
# .sys = audited hash) exactly as a real AnyConnect install would deploy it.
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_inf.txt"
Remove-Item $log -Force -ErrorAction SilentlyContinue
function WA($s){ [System.IO.File]::AppendAllText($log, $s + "`r`n") }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"

WA ("=== t5 inf-deploy {0} ===" -f (Get-Date -Format o))
Marker 'inf-start'

# --- 0. remove the failed manual devnodes (results already documented in t5_mkdev.txt) ---
WA "--- pnputil /remove-device on failed manual devnodes ---"
foreach ($id in @('ROOT\T5VPNVA\0000','ROOT\T5VPNVA2\0000')) {
  pnputil /remove-device $id 2>&1 | ForEach-Object { WA ("  " + $_) }
}

# --- 1. add the real Cisco package to the guest DriverStore ---
WA "--- pnputil /add-driver vpnva-6.inf /install ---"
pnputil /add-driver "$work\vpnva-6.inf" /install 2>&1 | ForEach-Object { WA ("  " + $_) }
WA ("  exit: " + $LASTEXITCODE)

WA "--- pnputil /enum-drivers (vpnva context) ---"
$all = pnputil /enum-drivers 2>&1 | Out-String
$lines = $all -split "`r?`n"
for ($i = 0; $i -lt $lines.Count; $i++) {
  if ($lines[$i] -match 'vpnva') {
    $from = [Math]::Max(0, $i - 3); $to = [Math]::Min($lines.Count - 1, $i + 9)
    for ($j = $from; $j -le $to; $j++) { WA ("  " + $lines[$j]) }
    WA "  ---"
  }
}

# --- 2. create devnode ROOT\VPNVA\0000 + seed matching hw-id ---
$rc = & $exe $log mkdev 'ROOT\VPNVA\0000' ''
WA ("  mkdev ROOT\VPNVA\0000 exit=" + $rc)
if ($rc -eq 0) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\VPNVA\0000'
  if (Test-Path $k) {
    New-ItemProperty -Path $k -Name 'ConfigFlags' -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $k -Name 'HardwareID' -Value 'VPNVA' -PropertyType MultiString -Force | Out-Null
    WA "  seeded ConfigFlags=0 (DWORD) + HardwareID=VPNVA (MULTI_SZ) - INF model hw-id match"
  } else { WA "  ABORT: enum key not auto-created" }
} else { WA "  ABORT: mkdev failed" }

# --- 3. restart -> PnP matches INF -> configure/install -> miniport init ---
Marker 'inf-BEFORE-restart'
WA "--- pnputil /restart-device ROOT\VPNVA\0000 (INF install + MiniportInitializeEx) ---"
pnputil /restart-device 'ROOT\VPNVA\0000' 2>&1 | ForEach-Object { WA ("  " + $_) }
Start-Sleep -Seconds 15
Marker 'inf-after-restart'

# --- 4. checks ---
WA "--- checks ---"
$rc = & $exe $log devstat 'ROOT\VPNVA\0000' ''; WA ("  devstat exit=" + $rc)
$rc = & $exe $log qobj '\Device' 'VPNVA'; WA ("  qobj \\Device VPNVA matched=" + ($rc -eq 0))
$rc = & $exe $log open '\\.\VPNVA' 'C0000000'; WA ("  open \\.\VPNVA RW exit=" + $rc)
try { Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object Name | Format-Table Name,InterfaceDescription,Status,MediaConnectState,ifIndex -AutoSize | Out-String -Width 200 | ForEach-Object { WA $_ } } catch { WA ("Get-NetAdapter ERROR: " + $_.Exception.Message) }
WA "--- sc query vpnva ---"
sc.exe query vpnva 2>&1 | ForEach-Object { WA ("  " + $_) }
WA "--- driverquery rows ---"
driverquery /v /fo csv 2>&1 | Select-String -Pattern 'vpnva' | ForEach-Object { WA ("  " + $_.Line) }
WA "--- Kernel-PnP/Configuration log (last 10) ---"
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 10 -ErrorAction Stop | ForEach-Object { WA ("  [{0}] id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } } catch { WA ("  ERROR: " + $_.Exception.Message) }

Marker 'inf-done'
