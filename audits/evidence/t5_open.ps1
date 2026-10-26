# t5_open.ps1 (agent t5) - Phase A step 6: open tests (admin full token + restricted token).
# Static claim under test (vpnva.md section 4): NO driver-enforced access control; all 14
# IOCTLs FILE_ANY_ACCESS; exposure gated ONLY by the OS default DACL for \Device\VPNVA.
# Evidence: t5_open.txt (+ t5_open_restricted.txt pulled separately)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t5_work'
$log  = "$work\t5_open.txt"
$sb = New-Object System.Text.StringBuilder
function W($s){ $sb.AppendLine($s) | Out-Null }
function Marker($m){ Add-Content -Path "$work\t5_alive.txt" -Value ("alive {0} {1}" -f (Get-Date -Format o), $m) }
$exe = "$work\t5_poc.exe"

function Poc($c, $a1, $a2) {
  & $exe $log $c $a1 $a2 2>&1 | Out-Null
  return $LASTEXITCODE
}

W ("=== t5 open tests {0} ===" -f (Get-Date -Format o))
Marker 'open-start'

W "--- ADMIN (full token) open matrix on \\.\VPNVA ---"
W "  documented device names: \Device\VPNVA + \DosDevices\VPNVA symlink (both resolve via \\.\VPNVA)"
foreach ($acc in @('C0000000','80000000','40000000','02000000','00000000')) {
  $rc = Poc 'open' '\\.\VPNVA' $acc
  W ("  acc=0x" + $acc + " -> exit=" + $rc + " (0=open OK, 1=fail)")
}

W "--- security descriptor (admin token, MAXIMUM_ALLOWED open) ---"
$rc = Poc 'sd' '\\.\VPNVA' ''
W ("  sd exit=" + $rc + " (SDDL text above; static claims NO explicit SD - OS default only)")

W "--- RESTRICTED-TOKEN opens (runas /trustlevel:0x20000) ---"
$restrLog = "$work\t5_open_restricted.txt"
if (Test-Path $restrLog) { Remove-Item $restrLog -Force }
foreach ($acc in @('C0000000','02000000')) {
  $inner = '"' + $exe + '" ' + $restrLog + ' open \\.\VPNVA ' + $acc
  $ra = & runas.exe /trustlevel:0x20000 $inner 2>&1
  $ra | ForEach-Object { W ('  runas: ' + $_) }
  Start-Sleep -Seconds 3
}
Start-Sleep -Seconds 3
if (Test-Path $restrLog) { Get-Content $restrLog | ForEach-Object { W ('  restricted: ' + $_) } }
else { W '  restricted run produced NO output file (runas may have failed to spawn in this session)' }

W "--- Kernel-PnP/Configuration log (last 5, for the record) ---"
try { Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 5 -ErrorAction Stop | ForEach-Object { W ("  [{0}] id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\r?\n', ' | ')) } }
catch { W ("  ERROR: " + $_.Exception.Message) }

Marker 'open-done'
[System.IO.File]::WriteAllText($log, $sb.ToString())
