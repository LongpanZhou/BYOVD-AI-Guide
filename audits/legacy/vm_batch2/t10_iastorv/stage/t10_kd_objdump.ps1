# t10_kd_objdump.ps1 - HOST-side: attach kd over NET, dump \Device\Ide + \Device objects, detach
$ErrorActionPreference = 'Continue'
$kd  = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe'
$dir = 'C:\Users\27175\Desktop\driver_candidates\_vm_batch2\t10_iastorv\kd'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$tlog = "$dir\t10_kd_objdump.log"
$hlog = "$dir\t10_kd_objdump_host.txt"
function Log([string]$s) { [IO.File]::AppendAllText($hlog, $s + "`r`n") }
Remove-Item $tlog -ErrorAction SilentlyContinue

if (-not (Test-Path $kd)) { Log ('FATAL: kd.exe missing'); exit 1 }
$cmds = '!object \Device\Ide; !object \Device; qd'
Log ('kd objdump start ' + (Get-Date -Format o))
$p = Start-Process -FilePath $kd -ArgumentList @('-y', 'SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols', '-k', 'net:port=50001,key=1.2.3.4', '-logo', $tlog, '-c', $cmds) -PassThru -WindowStyle Hidden
Log ('kd pid=' + $p.Id)
Start-Sleep -Seconds 45
if (-not $p.HasExited) {
  Log 'kd still running after 45 s - force-kill (guest should resume)'
  Stop-Process -Id $p.Id -Force
} else { Log ('kd exited rc=' + $p.ExitCode) }
if (Test-Path $tlog) {
  Log '--- transcript ---'
  foreach ($l in [IO.File]::ReadAllLines($tlog)) { Log ('  ' + ($l -replace '[^\x20-\x7E]', '?')) }
} else { Log 'no transcript produced' }
exit 0
