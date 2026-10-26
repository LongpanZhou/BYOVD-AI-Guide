$ErrorActionPreference = 'Stop'
$inf = 'C:\Windows\Temp\secpol_lockmem.inf'
$db = 'C:\Windows\Temp\secpol_lockmem.sdb'
secedit /export /cfg $inf | Out-Null
$lines = Get-Content $inf
$found = $false
$out = New-Object System.Collections.Generic.List[string]
foreach ($line in $lines) {
    if ($line -match '^\s*SeLockMemoryPrivilege\s*=') {
        $out.Add('SeLockMemoryPrivilege = *S-1-5-32-544')
        $found = $true
    } else {
        $out.Add($line)
    }
}
if (-not $found) {
    $idx = $out.IndexOf('[Privilege Rights]')
    if ($idx -ge 0) { $out.Insert($idx + 1, 'SeLockMemoryPrivilege = *S-1-5-32-544') }
    else { $out.Add('[Privilege Rights]'); $out.Add('SeLockMemoryPrivilege = *S-1-5-32-544') }
}
Set-Content -Path $inf -Value $out -Encoding Unicode
secedit /configure /db $db /cfg $inf /areas USER_RIGHTS | Out-Null
"policy applied" | Out-File C:\Users\vmdebug\Desktop\fuzz_work\lockmem_policy.txt -Encoding UTF8
shutdown.exe /r /t 3 /f
