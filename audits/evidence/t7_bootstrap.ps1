# t7 bootstrap: create work dir + aliveness marker (roundtrip read-back on host side)
$ErrorActionPreference = 'Continue'
$out = 'C:\Users\vmdebug\Desktop\t7_work\t7_bootstrap.txt'
New-Item -ItemType Directory -Force -Path 'C:\Users\vmdebug\Desktop\t7_work' | Out-Null
"t7 bootstrap $(Get-Date -Format o)" | Out-File -FilePath 'C:\Users\vmdebug\Desktop\t7_work\t7_alive.txt' -Encoding ascii
try {
  Move-Item -Force 'C:\Users\vmdebug\Desktop\t7_work\t7_bootstrap.txt.tmp' 'C:\Users\vmdebug\Desktop\t7_work\t7_bootstrap.txt' -ErrorAction SilentlyContinue
} catch {}
@(
  "workdir exists: $(Test-Path 'C:\Users\vmdebug\Desktop\t7_work')"
  "alive marker written: $(Test-Path 'C:\Users\vmdebug\Desktop\t7_work\t7_alive.txt')"
  "csc present: $(Test-Path 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe')"
  "kd present: $((Get-Command kd -ErrorAction SilentlyContinue) -ne $null) / path check: $(Test-Path 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe')"
  "whoami: $(whoami)"
  "t1-t6 work dirs present (read-only check, DO NOT TOUCH): $(Get-ChildItem 'C:\Users\vmdebug\Desktop' -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)"
) | Out-File -FilePath $out -Encoding ascii
exit 0
