param([string]$dir, [string]$filesCsv)
foreach ($f in $filesCsv.Split(',')) {
  $p = Join-Path $dir $f
  $b = [IO.File]::ReadAllBytes($p)
  $lfanew = [BitConverter]::ToInt32($b, 0x3C)
  $numSec = [BitConverter]::ToUInt16($b, $lfanew + 6)
  $sizeOpt = [BitConverter]::ToUInt16($b, $lfanew + 20)
  $secStart = $lfanew + 24 + $sizeOpt
  $secs = @()
  for ($s = 0; $s -lt $numSec; $s++) {
    $o = $secStart + $s*40
    $name = ([Text.Encoding]::ASCII.GetString($b, $o, 8)).TrimEnd([char]0)
    $vsize = [BitConverter]::ToInt32($b, $o+8)
    $vaddr = [BitConverter]::ToInt32($b, $o+12)
    $rawsize = [BitConverter]::ToInt32($b, $o+16)
    $rawptr = [BitConverter]::ToInt32($b, $o+20)
    $secs += ,@($name,$rawptr,($rawptr+$rawsize),$vaddr)
    "{0}  {1}: file 0x{2:X}-0x{3:X} RVA 0x{4:X}" -f $f,$name,$rawptr,($rawptr+$rawsize),$vaddr
  }
}
