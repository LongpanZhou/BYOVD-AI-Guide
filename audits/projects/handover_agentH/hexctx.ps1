param([string]$path, [string]$offsetsCsv, [int]$width)
$b = [IO.File]::ReadAllBytes($path)
foreach ($oStr in $offsetsCsv.Split(',')) {
  $o = [Convert]::ToInt32($oStr, 16) - $width
  if ($o -lt 0) { $o = 0 }
  $hex = ($b[$o..($o+2*$width)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
  "  0x{0:X2}: {1}" -f $o, $hex
}
