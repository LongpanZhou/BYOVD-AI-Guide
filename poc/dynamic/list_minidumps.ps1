$out = 'C:\Users\vmdebug\Desktop\fuzz_work\minidumps.txt'
"=== minidumps ===" | Out-File $out -Encoding UTF8
Get-ChildItem 'C:\Windows\Minidump' -Filter *.dmp -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object Name, Length, LastWriteTime |
    Format-Table -AutoSize | Out-File $out -Append -Encoding UTF8
"=== MEMORY.DMP ===" | Out-File $out -Append -Encoding UTF8
Get-Item 'C:\Windows\MEMORY.DMP' -ErrorAction SilentlyContinue |
    Select-Object Name, Length, LastWriteTime |
    Format-Table -AutoSize | Out-File $out -Append -Encoding UTF8
"=== last boot ===" | Out-File $out -Append -Encoding UTF8
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Out-File $out -Append -Encoding UTF8
"=== bugcheck event ===" | Out-File $out -Append -Encoding UTF8
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 3 -ErrorAction SilentlyContinue |
    ForEach-Object { $_.TimeCreated.ToString('s') + '  ' + ($_.Message -replace "`r`n", ' ') } |
    Out-File $out -Append -Encoding UTF8
