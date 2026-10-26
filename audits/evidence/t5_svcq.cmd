@echo off
for %%s in (NetSetupSvc netprofm NlaSvc netman Dhcp Dnscache nsI dot3svc) do (
  echo ===== %%s ===== >> "C:\Users\vmdebug\Desktop\t5_work\t5_svc.txt"
  sc query %%s >> "C:\Users\vmdebug\Desktop\t5_work\t5_svc.txt" 2>&1
  sc qc %%s >> "C:\Users\vmdebug\Desktop\t5_work\t5_svc.txt" 2>&1
)
echo done >> "C:\Users\vmdebug\Desktop\t5_work\t5_svc.txt"
