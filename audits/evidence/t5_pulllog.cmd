@echo off
powershell -NoProfile -Command "Get-Content 'C:\Windows\INF\setupapi.dev.log' -Tail 500 | Set-Content 'C:\Users\vmdebug\Desktop\t5_work\t5_setupapi_tail.txt'"
echo EXITCODE=%ERRORLEVEL% >> "C:\Users\vmdebug\Desktop\t5_work\t5_setupapi_tail.txt"
