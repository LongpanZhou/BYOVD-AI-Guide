# t7 inventory: vmci + vsock + b06bdrv baseline (READ-ONLY)
$ErrorActionPreference = 'Continue'
$out = 'C:\Users\vmdebug\Desktop\t7_work\t7_inv.txt'
"t7_inv $(Get-Date -Format o)" | Out-File $out -Encoding ascii

function Log([string]$s) { $s | Out-File $out -Append -Encoding ascii }

# --- 1. driverquery rows ---
Log "=== driverquery /v (vmci|vsock|b06bdrv|bxvbda|nvhda) ==="
$dq = driverquery.exe /v /FO CSV 2>&1
foreach ($l in $dq) { if ($l -match 'vmci|vsock|b06bdrv|bxvbda|nvhda') { Log $l } }

# --- 2. sc query ---
Log "=== sc query ==="
foreach ($svc in 'vmci','vsock','b06bdrv','VMwareTools') { Log (sc.exe query $svc 2>&1 | Out-String) }

# --- 3. service keys ---
Log "=== service registry keys ==="
foreach ($svc in 'vmci','vsock','b06bdrv') {
  $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
  if (Test-Path $k) {
    $p = Get-ItemProperty $k
    Log ("{0}: Start={1} Type={2} ImagePath={3} Group={4}" -f $svc, $p.Start, $p.Type, $p.ImagePath, $p.Group)
  } else { Log "$svc : key ABSENT" }
}

# --- 4. PnP devices ---
Log "=== Get-PnpDevice (vmci/vsock/pci hypervisor-ish) ==="
foreach ($d in (Get-PnpDevice 2>&1)) {
  if (($d.FriendlyName -match 'VMCI|VSOCK|VMware') -or ($d.InstanceId -match 'VMCI|VSOCK')) {
    Log ("{0} | {1} | {2} | {3}" -f $d.Status, $d.Class, $d.InstanceId, $d.FriendlyName)
  }
}
Log "=== PCI VMCI devnode detail ==="
$pci = Get-PnpDevice -InstanceId "*PCI*VEN_15AD*" 2>&1
foreach ($d in $pci) {
  Log ("{0} | {1} | {2}" -f $d.Status, $d.Class, $d.InstanceId)
  $sk = "HKLM:\SYSTEM\CurrentControlSet\Enum\" + $d.InstanceId
  if (Test-Path $sk) {
    $pp = Get-ItemProperty $sk
    Log ("  Service={0} ClassGUID={1} DeviceDesc={2}" -f $pp.Service, $pp.ClassGUID, $pp.DeviceDesc)
  }
}

# --- 5. DeviceClasses keys mentioning vmci/vsock ---
Log "=== DeviceClasses keys containing vmci/vsock/2AF67184 ==="
$dcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses'
foreach ($gk in (Get-ChildItem $dcRoot)) {
  foreach ($ik in (Get-ChildItem $gk.PSPath -ErrorAction SilentlyContinue)) {
    if ($ik.PSChildName -match 'vmci|vsock') {
      $pp = Get-ItemProperty $ik.PSPath
      Log ("{0}\{1} : DeviceInstance={2}" -f $gk.PSChildName, $ik.PSChildName, $pp.DeviceInstance)
    }
  }
}
# bxvbda interface GUID check (target 3 baseline)
Log "=== DeviceClasses {2AF67184-48D3-4e8e-A3FF-969EFF740ED2} (bxvbda, expect absent) ==="
$bxv = Join-Path $dcRoot '{2AF67184-48d3-4e8e-a3ff-969eff740ed2}'
if (Test-Path $bxv) { Get-ChildItem $bxv | ForEach-Object { Log $_.PSChildName } } else { Log "absent" }

# --- 6. Enum\ROOT listing (baseline for target 3) ---
Log "=== Enum\ROOT (baseline) ==="
foreach ($k in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT')) { Log $k.PSChildName }

# --- 7. driver file hashes in guest ---
Log "=== guest driver file SHA-256 (vmci, vsock, bxvbda if present in drivers dir) ==="
foreach ($f in 'C:\Windows\System32\drivers\vmci.sys','C:\Windows\System32\drivers\vsock.sys','C:\Windows\System32\drivers\bxvbda.sys') {
  if (Test-Path $f) { Log ("{0} = {1} size={2}" -f $f, (Get-FileHash $f -Algorithm SHA256).Hash, (Get-Item $f).Length) }
  else { Log "$f = ABSENT" }
}

Log "=== end ==="
exit 0
