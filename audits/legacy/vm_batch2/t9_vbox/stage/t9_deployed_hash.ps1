# t9_deployed_hash.ps1 - verify the deployed driver copies in guest drivers\ (rule 7)
$ErrorActionPreference = 'Continue'
$work = 'C:\Users\vmdebug\Desktop\t9_work'
$out = "$work\t9_deployed_hash.txt"
"t9_deployed_hash $(Get-Date -Format o)" | Out-File $out -Encoding ascii
foreach ($f in @('C:\Windows\System32\drivers\VBoxNetAdp6.sys', 'C:\Windows\System32\drivers\VBoxNetLwf.sys')) {
  if (Test-Path $f) {
    $h = (Get-FileHash $f -Algorithm SHA256).Hash
    $sig = (Get-AuthenticodeSignature $f).Status
    ($f + ' ' + $h + ' sig=' + $sig) | Out-File $out -Append -Encoding ascii
  } else {
    ($f + ' ABSENT') | Out-File $out -Append -Encoding ascii
  }
}
exit 0
