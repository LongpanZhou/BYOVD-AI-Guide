@echo off
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /out:"C:\Users\vmdebug\Desktop\t5_work\t5_poc.exe" "C:\Users\vmdebug\Desktop\t5_work\t5_poc.cs" > "C:\Users\vmdebug\Desktop\t5_work\t5_pw_rebuild.txt" 2>&1
echo EXITCODE=%ERRORLEVEL% >> "C:\Users\vmdebug\Desktop\t5_work\t5_pw_rebuild.txt"
