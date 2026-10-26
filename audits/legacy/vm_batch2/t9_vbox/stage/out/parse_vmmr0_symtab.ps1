# parse_vmmr0_symtab.ps1 - locate and parse the embedded VBox r0 symbol table in VMMR0.r0
# Format (from supdrv LDR_LOAD validation logic): records of 8 bytes = {u32 nameOff (into strtab), u32 symRva (image offset)}
# The strtab begins at the region holding the mangled names. We find the symtab by scanning
# for runs of 8-byte records whose nameOff and symRva fields stay within plausible ranges,
# anchored on the known strtab.
param([Parameter(Mandatory=$true)][string]$file)
$ErrorActionPreference = 'Stop'
$bytes = [IO.File]::ReadAllBytes($file)
Write-Output ("file len: 0x{0:X}" -f $bytes.Length)

# find the strtab: the IntNetR0IfAbortWait mangled name at 0x1E1F30 was found by string scan.
# Instead of hardcoding, locate the strtab by scanning for the '?IntNetR0Open' name.
$pat = [Text.Encoding]::ASCII.GetBytes('?IntNetR0Open@@')
$strIdx = -1
for ($i = 0; $i -le $bytes.Length - $pat.Length; $i++) {
  $ok = $true
  for ($j = 0; $j -lt $pat.Length; $j++) { if ($bytes[$i+$j] -ne $pat[$j]) { $ok = $false; break } }
  if ($ok) { $strIdx = $i; break }
}
Write-Output ("'?IntNetR0Open@@' found at file offset 0x{0:X}" -f $strIdx)

# PE header: map file offset -> RVA for the section containing it
$peOff = [BitConverter]::ToInt32($bytes, 0x3c)
$optOff = $peOff + 0x18
$secOff = $optOff + [BitConverter]::ToUInt16($bytes, $peOff + 20)
$nsec = [BitConverter]::ToUInt16($bytes, $peOff + 6)
$sections = @()
for ($i = 0; $i -lt $nsec; $i++) {
  $s = $secOff + $i * 40
  $name = [Text.Encoding]::ASCII.GetString($bytes, $s, 8).TrimEnd([char]0)
  $vsize = [BitConverter]::ToUInt32($bytes, $s + 8)
  $va = [BitConverter]::ToUInt32($bytes, $s + 12)
  $rawsize = [BitConverter]::ToUInt32($bytes, $s + 16)
  $raw = [BitConverter]::ToUInt32($bytes, $s + 20)
  $sections += ,@($name, $va, $vsize, $raw, $rawsize)
  Write-Output ("sec {0,-10} va=0x{1:X8} vsz=0x{2:X} raw=0x{3:X8} rsz=0x{4:X}" -f $name, $va, $vsize, $raw, $rawsize)
}
function FileToRva([int]$off) {
  foreach ($sec in $script:sections) {
    if ($off -ge $sec[3] -and $off -lt ($sec[3] + $sec[4])) { return $off - $sec[3] + $sec[1] }
  }
  return -1
}
$strRva = FileToRva $strIdx
Write-Output ("strtab region RVA for '?IntNetR0Open@@': 0x{0:X}" -f $strRva)

# The nameOff field in symtab records is relative to strtab start (image RVA of strtab).
# We don't know strtab RVA base yet; derive it by scanning for symtab records:
# try candidate strtab bases so that many records resolve to printable names.
# Instead scan for symtab directly: records {nameOff u32, symRva u32} where symRva is in
# [0x1000, image size) and 0x400-aligned-ish code range, and nameOff in a tight range.
$cbImageBits = 0
# image size from optional header
$sizeOfImage = [BitConverter]::ToUInt32($bytes, $optOff + 56)
Write-Output ("SizeOfImage: 0x{0:X}" -f $sizeOfImage)

# scan in 8-byte stride for runs of >=16 valid records
$best = $null
$i = 0x1000
$runStart = -1; $runLen = 0; $runs = @()
while ($i -lt $bytes.Length - 8) {
  $a = [BitConverter]::ToUInt32($bytes, $i)
  $b = [BitConverter]::ToUInt32($bytes, $i + 4)
  $valid = ($b -ge 0x1000 -and $b -lt $sizeOfImage -and ($b -band 0xf) -eq 0 -and $a -lt 0x400000)
  if ($valid) {
    if ($runStart -lt 0) { $runStart = $i; $runLen = 1 } else { $runLen++ }
  } else {
    if ($runLen -ge 32) { $runs += ,@($runStart, $runLen) }
    $runStart = -1; $runLen = 0
  }
  $i += 8
}
if ($runLen -ge 32) { $runs += ,@($runStart, $runLen) }
Write-Output "candidate symtab runs (offset, count):"
foreach ($r in $runs) { Write-Output ("  file 0x{0:X}  n={1}" -f $r[0], $r[1]) }
