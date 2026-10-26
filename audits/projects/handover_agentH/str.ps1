param([string]$path, [string]$out)
$bytes = [IO.File]::ReadAllBytes($path)
$n = $bytes.Length
$ascii = New-Object System.Collections.Generic.List[string]
$uni = New-Object System.Collections.Generic.List[string]
# ASCII runs >= 5 printable
$i = 0
$run = New-Object System.Text.StringBuilder
while ($i -lt $n) {
  $b = $bytes[$i]
  if ($b -ge 0x20 -and $b -le 0x7e) { [void]$run.Append([char]$b); $i++ }
  else {
    if ($run.Length -ge 5) { $ascii.Add($run.ToString()) }
    $run.Clear() | Out-Null
    $i++
  }
}
if ($run.Length -ge 5) { $ascii.Add($run.ToString()) }
# UTF-16LE runs: printable followed by 0x00, run of >= 4 units
$i = 0
$run2 = New-Object System.Text.StringBuilder
while ($i -lt ($n - 1)) {
  $b = $bytes[$i]
  if (($b -ge 0x20 -and $b -le 0x7e) -and $bytes[$i+1] -eq 0) { [void]$run2.Append([char]$b); $i += 2 }
  else {
    if ($run2.Length -ge 4) { $uni.Add($run2.ToString()) }
    $run2.Clear() | Out-Null
    if (($b -ge 0x20 -and $b -le 0x7e) -and $bytes[$i+1] -ne 0) { $i++ } else { $i++ }
  }
}
if ($run2.Length -ge 4) { $uni.Add($run2.ToString()) }
$w = New-Object System.IO.StreamWriter($out, $false)
$w.WriteLine("===ASCII===")
foreach ($s in $ascii) { $w.WriteLine($s) }
$w.WriteLine("===UNICODE===")
foreach ($s in $uni) { $w.WriteLine($s) }
$w.Close()
Write-Host ("ASCII={0} UNICODE={1} -> {2}" -f $ascii.Count, $uni.Count, $out)
