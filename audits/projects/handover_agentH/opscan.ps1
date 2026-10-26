param([string]$dir, [string[]]$files)
$patterns = @{
  'wrmsr(0F30)'      = @(0x0F,0x30)
  'rdmsr(0F32)'      = @(0x0F,0x32)
  'lgdt(0F01/2)'     = @(0x0F,0x01,0x02)
  'lidt(0F01/3)'     = @(0x0F,0x01,0x03)
  'sgdt(0F01/0)'     = @(0x0F,0x01,0x00)
  'sidt(0F01/1)'     = @(0x0F,0x01,0x01)
  'lmsw(0F01/6)'     = @(0x0F,0x01,0x06)
  'invd(0F08)'       = @(0x0F,0x08)
  'wbinvd(0F09)'     = @(0x0F,0x09)
  'cli(FA)'          = @(0xFA)
  'out-AL-AA'        = @(0xEE)
  'out-AL-E6'        = @(0xE6)
}
foreach ($f in $files) {
  $p = Join-Path $dir $f
  $b = [IO.File]::ReadAllBytes($p)
  $n = $b.Length
  foreach ($name in $patterns.Keys) {
    $pat = $patterns[$name]
    $hits = New-Object System.Collections.Generic.List[int]
    $pl = $pat.Length
    for ($i = 0; $i -le $n - $pl; $i++) {
      $ok = $true
      for ($j = 0; $j -lt $pl; $j++) { if ($b[$i+$j] -ne $pat[$j]) { $ok = $false; break } }
      if ($ok) { $hits.Add($i); if ($hits.Count -ge 40) { break } }
    }
    if ($hits.Count -gt 0) { "{0}  {1}: {2} hits @ {3}" -f $f, $name, $hits.Count, (($hits | ForEach-Object { '{0:X}' -f $_ }) -join ',') }
  }
}
