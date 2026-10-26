# t10_verify.ps1 - SHA-256 verify every pushed file + record guest-inbox iaStorV.sys if present
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t10_work'
$log  = "$work\t10_verify.txt"
[IO.File]::WriteAllText($log, ("=== t10_verify {0} ===`r`n" -f (Get-Date -Format o)))
function Log([string]$s) { [IO.File]::AppendAllText($log, $s + "`r`n") }
Add-Content -Path "$work\t10_alive.txt" -Value ("alive {0} verify-start" -f (Get-Date -Format o))

$expect = @{
  'iaStorV.sys'         = '30BEE94794953E2DBF0FC5AFCE0566F335AF022E89819DE145329E7C09C636BD'
  't10_poc.exe'         = '33435172960641EC30F72F0179D3AF90DBBAB1D55BAC54E53BA4E0BEA84CC551'
  't10_load.ps1'        = ''
  't10_verify.ps1'      = ''
}
$files = Get-ChildItem $work -File
foreach ($f in $files) {
  $h = (Get-FileHash -Algorithm SHA256 $f.FullName).Hash
  $exp = $expect[$f.Name]
  $mark = ''
  if ($exp -ne '' -and $exp -ne $null) { $mark = $(if ($h -eq $exp) { ' [OK]' } else { ' [MISMATCH-ABORT]' }) }
  Log ($f.Name + ' ' + $f.Length + ' B  SHA=' + $h + $mark)
  if ($mark -eq ' [MISMATCH-ABORT]') { Log 'FATAL: pushed file SHA drift'; exit 2 }
}

# pre-existing guest inbox copy check (never modified - read-only hash)
$inbox = 'C:\Windows\System32\drivers\iaStorV.sys'
if (Test-Path $inbox) {
  $ih = (Get-FileHash -Algorithm SHA256 $inbox).Hash
  $iv = (Get-Item $inbox).VersionInfo.FileVersion
  Log ('inbox iaStorV.sys present: ' + $inbox + ' ' + (Get-Item $inbox).Length + ' B  SHA=' + $ih + '  Ver=' + $iv)
  Log ('inbox equals pushed: ' + ($ih -eq $expect['iaStorV.sys']))
} else {
  Log 'inbox iaStorV.sys: NOT present in guest'
}

Log '--- service pre-check (t10_iastrv must not pre-exist) ---'
& sc.exe query t10_iastrv 2>&1 | ForEach-Object { Log ('  ' + $_) }
Log ('sc exit=' + $LASTEXITCODE)
Add-Content -Path "$work\t10_alive.txt" -Value ("alive {0} verify-done" -f (Get-Date -Format o))
exit 0
