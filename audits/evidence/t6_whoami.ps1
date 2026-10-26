# t6_whoami.ps1 - identity proof for the restricted-token run (writes its own output file)
$out = 'C:\Users\vmdebug\Desktop\t6_work\t6_open_whoami.txt'
'WHOAMI (restricted token run)' | Set-Content $out
whoami.exe /all 2>&1 | Out-File $out -Append -Encoding unicode
'=== token summary ===' | Out-File $out -Append
$p = [System.Security.Principal.WindowsIdentity]::GetCurrent()
("User: " + $p.Name) | Out-File $out -Append
("Groups: " + (($p.Groups | ForEach-Object { try { $_.Translate([System.Security.Principal.NTAccount]).ToString() } catch { $_.Value } }) -join '; ')) | Out-File $out -Append
