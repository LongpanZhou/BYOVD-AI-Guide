# t10_kd_dispatch.ps1 - HOST-side kd plumbing (run on the HOST, not in-guest) - t6 recipe
#   -phase attach : launch kd (background, logo), let it break in, set bp on iaStorV+0x4c084, continue
#   -phase collect: kill kd, extract the HIT block from the log
# Sequence: attach -> (guest sends ONE 0x4D014 via t10_trigger.ps1) -> collect
param([string]$phase = 'attach')
$ErrorActionPreference = 'Continue'
$kd  = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe'
$dir = 'C:\Users\27175\Desktop\driver_candidates\_vm_batch2\t10_iastorv\kd'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$tlog = "$dir\t10_kd_transcript.log"
$hlog = "$dir\t10_kd_attach.txt"
function Log([string]$s) { [IO.File]::AppendAllText($hlog, $s + "`r`n") }

if (-not (Test-Path $kd)) { Log ('FATAL: kd.exe missing at ' + $kd); exit 1 }

if ($phase -eq 'attach') {
  Remove-Item $tlog -ErrorAction SilentlyContinue
  # initial commands: wait for connect happens implicitly; after break-in, set the breakpoint
  # NOTE: file-RVA of the dispatch is 0x4c084 (true preferred base 0x10000; the audit's
  # 0x14005c084-style numbers are REA label-space, off by 0x10000 in real file RVAs).
  $cmds = '.symfix;.reload nt;lm m iaStorV;bp iaStorV+0x4c084 ".echo ===T10-HIT-START===;r rcx,rdx;dt nt!_IO_STACK_LOCATION poi(@rdx+b8) 0x28;.echo ===T10-HIT-END===;g";g'
  Log ('kd attach start ' + (Get-Date -Format o))
  Log ('kd command line: kd -k net:port=50001')
  Log ('kd -c cmds: ' + $cmds)
  $p = Start-Process -FilePath $kd -ArgumentList @('-y', 'SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols', '-k', 'net:port=50001', '-logo', $tlog, '-c', $cmds) -PassThru -WindowStyle Hidden
  Log ('kd pid=' + $p.Id)
  Start-Sleep -Seconds 25
  if ($p.HasExited) { Log 'WARNING: kd exited during attach (connection issue?)' } else { Log 'kd attached (assumed; verify transcript)' }
  Log 'READY: trigger one 0x4D014 in-guest, then run -phase collect'
  exit 0
}

if ($phase -eq 'collect') {
  Log ('kd collect ' + (Get-Date -Format o))
  Get-Process kd -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep -Seconds 2
  if (Test-Path $tlog) {
    $lines = [IO.File]::ReadAllLines($tlog)
    $i = [Array]::IndexOf($lines, '===T10-HIT-START===')
    if ($i -ge 0) {
      $j = [Array]::IndexOf($lines, '===T10-HIT-END===')
      Log ('HIT FOUND at line ' + $i + ', span ' + ($j - $i))
      foreach ($l in $lines[$i..([Math]::Min($j + 5, $lines.Length - 1))]) { Log ('  ' + ($l -replace '[^\x20-\x7E]', '?')) }
    } else {
      Log 'NO HIT in transcript - breakpoint never fired (report negative)'
      foreach ($l in $lines[([Math]::Max(0, $lines.Length - 40))..($lines.Length - 1)]) { Log ('  tail: ' + ($l -replace '[^\x20-\x7E]', '?')) }
    }
  } else { Log 'FATAL: no transcript file' }
  exit 0
}
Log ('unknown phase: ' + $phase)
exit 1
