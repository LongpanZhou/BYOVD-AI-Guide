# t9_push.ps1 - host side: push all t9 files into the guest work dir (flat layout)
$ErrorActionPreference = 'Continue'
$vmrun = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$vmx = 'C:\Users\27175\Downloads\Vmware\Windows 10 x64.vmx'
$gu = 'vmdebug'; $gp = '123456'
$stage = 'C:\Users\27175\Desktop\driver_candidates\_vm_batch2\t9_vbox\stage'
$dstRoot = 'C:\Users\vmdebug\Desktop\t9_work'
$files = @(
  't9_poc.exe','t9_poc.cs',
  't9_bootstrap.ps1','t9_stage.ps1','t9_install_adp.ps1','t9_install_lwf.ps1',
  't9_discover.ps1','t9_lwf_fuzz.ps1','t9_adp_probe.ps1','t9_cleanup.ps1','t9_verify.ps1',
  't9_phaseB_STAGED.txt',
  'VBoxSup.sys','VBoxSup.inf','VBoxSup.cat',
  'VBoxNetAdp6.sys','VBoxNetAdp6.inf','VBoxNetAdp6.cat',
  'VBoxNetLwf.sys','VBoxNetLwf.inf','VBoxNetLwf.cat'
)
$log = "$stage\out\t9_push.txt"
"t9_push $(Get-Date -Format o)" | Out-File $log -Encoding ascii
# source subdir map for the payload files (they live under stage\inf\<pkg>\)
$sub = @{
  'VBoxSup.sys' = 'inf\sup'; 'VBoxSup.inf' = 'inf\sup'; 'VBoxSup.cat' = 'inf\sup'
  'VBoxNetAdp6.sys' = 'inf\adp'; 'VBoxNetAdp6.inf' = 'inf\adp'; 'VBoxNetAdp6.cat' = 'inf\adp'
  'VBoxNetLwf.sys' = 'inf\lwf'; 'VBoxNetLwf.inf' = 'inf\lwf'; 'VBoxNetLwf.cat' = 'inf\lwf'
}
foreach ($f in $files) {
  $dir = $stage
  if ($sub.ContainsKey($f)) { $dir = Join-Path $stage $sub[$f] }
  $src = Join-Path $dir $f
  $dst = Join-Path $dstRoot $f
  $r = & $vmrun -T ws -gu $gu -gp $gp copyFileFromHostToGuest $vmx $src $dst 2>&1 | Out-String
  $exists = & $vmrun -T ws -gu $gu -gp $gp fileExistsInGuest $vmx $dst 2>&1 | Out-String
  $ok = $exists -match 'The file exists'
  ("{0,-22} copy={1} exists-check={2}" -f $f, ($r.Trim() -replace '\r?\n', ' '), $ok) | Out-File $log -Append -Encoding ascii
  if (-not $ok) { ("  raw exists-output: " + $exists.Trim()) | Out-File $log -Append -Encoding ascii }
}
"t9_push done $(Get-Date -Format o)" | Out-File $log -Append -Encoding ascii
Get-Content $log
exit 0
