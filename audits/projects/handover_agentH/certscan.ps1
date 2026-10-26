param([string]$dir, [string[]]$files)
foreach ($f in $files) {
  $p = Join-Path $dir $f
  $b = [IO.File]::ReadAllBytes($p)
  $lfanew = [BitConverter]::ToInt32($b, 0x3C)
  # PE32+ optional header starts at lfanew+0x18; DataDirectory at +0x70
  $dd = $lfanew + 0x18 + 0x70
  $certRva = [BitConverter]::ToInt32($b, $dd + 4*8)      # index 4 = CertificateTable (file offset for PE)
  $certSize = [BitConverter]::ToInt32($b, $dd + 4*8 + 4)
  "{0}: certTable offset=0x{1:X} size=0x{2:X} (range 0x{1:X}-0x{3:X})" -f $f, $certRva, $certSize, ($certRva+$certSize)
}
