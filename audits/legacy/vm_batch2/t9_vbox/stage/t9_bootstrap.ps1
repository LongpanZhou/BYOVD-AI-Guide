# t9 bootstrap: create work dir + aliveness marker (t7_bootstrap.ps1 pattern, t9 names)
$ErrorActionPreference = 'Continue'
$out = 'C:\Users\vmdebug\Desktop\t9_work\t9_bootstrap.txt'
New-Item -ItemType Directory -Force -Path 'C:\Users\vmdebug\Desktop\t9_work' | Out-Null
"t9 bootstrap $(Get-Date -Format o)" | Out-File -FilePath 'C:\Users\vmdebug\Desktop\t9_work\t9_alive.txt' -Encoding ascii
@(
  "workdir exists: $(Test-Path 'C:\Users\vmdebug\Desktop\t9_work')"
  "alive marker written: $(Test-Path 'C:\Users\vmdebug\Desktop\t9_work\t9_alive.txt')"
  "csc present: $(Test-Path 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe')"
  "kd present: $((Get-Command kd -ErrorAction SilentlyContinue) -ne $null) / path check: $(Test-Path 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe')"
  "whoami: $(whoami)"
  "prior work dirs present (read-only check, DO NOT TOUCH): $(Get-ChildItem 'C:\Users\vmdebug\Desktop' -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)"
  "pre-existing VBox files in guest drivers (expect none, must stay none before t9 install): sup=" + (Test-Path 'C:\Windows\System32\drivers\VBoxSup.sys') + " adp6=" + (Test-Path 'C:\Windows\System32\drivers\VBoxNetAdp6.sys') + " lwf=" + (Test-Path 'C:\Windows\System32\drivers\VBoxNetLwf.sys')
) | Out-File -FilePath $out -Encoding ascii
exit 0
