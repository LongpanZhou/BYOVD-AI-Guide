# get_exports.ps1 <sys file> - dump PE export table names (ASCII-only)
param([Parameter(Mandatory=$true)][string]$file)
$ErrorActionPreference = 'Stop'
$bytes = [IO.File]::ReadAllBytes($file)
$peOff = [BitConverter]::ToInt32($bytes, 0x3c)
$optOff = $peOff + 0x18
$dd = $optOff + 0x70
$expRva = [BitConverter]::ToInt32($bytes, $dd)
$secOff = $optOff + [BitConverter]::ToUInt16($bytes, $peOff + 20)
$nsec = [BitConverter]::ToUInt16($bytes, $peOff + 6)
$map = @()
for ($i = 0; $i -lt $nsec; $i++) {
  $s = $secOff + $i * 40
  $va = [BitConverter]::ToUInt32($bytes, $s + 12)
  $sz = [BitConverter]::ToUInt32($bytes, $s + 8)
  $raw = [BitConverter]::ToUInt32($bytes, $s + 20)
  $map += ,@($va, $sz, $raw)
}
function RvaToOff([int]$rva) {
  foreach ($m in $script:map) {
    if ($rva -ge $m[0] -and $rva -lt ($m[0] + $m[1])) { return $rva - $m[0] + $m[2] }
  }
  return -1
}
$e = RvaToOff $expRva
if ($e -lt 0) { Write-Output "no export dir (rva=0x$('{0:X}' -f $expRva))"; exit 0 }
$nNames = [BitConverter]::ToUInt32($bytes, $e + 24)
$namesRva = [BitConverter]::ToUInt32($bytes, $e + 32)
$no = RvaToOff $namesRva
Write-Output "exports: $nNames"
for ($i = 0; $i -lt $nNames; $i++) {
  $nr = [BitConverter]::ToUInt32($bytes, $no + $i * 4)
  $strOff = RvaToOff $nr
  $end = $strOff
  while ($bytes[$end] -ne 0) { $end++ }
  Write-Output ("  " + [Text.Encoding]::ASCII.GetString($bytes, $strOff, $end - $strOff))
}
exit 0
