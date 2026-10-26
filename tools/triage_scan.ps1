param([Parameter(Mandatory=$true,ValueFromRemainingArguments=$true)][string[]]$Files)

# triage_scan.ps1 v2
# v1 flagged any driver whose file contained an SDDL literal with ;;;WD.
# That produced ~50% false positives: vendors ship whole descriptor tables
# where most entries are never passed to the create call. v2 parses the PE
# import table and resolves each SDDL string to a virtual address, then looks
# for real code/data references before calling it reachable.

$apiList = @(
 'IoCreateDevice','IoCreateDeviceSecure','IoCreateSymbolicLink','IoRegisterDeviceInterface',
 'WdfControlDeviceInitAllocate','WdfDeviceCreate','WdfDriverCreate','WdfDeviceInitAssignSDDLString',
 'FltRegisterFilter','NdisRegisterDeviceEx','NdisFRegisterFilterDriver','NdisMRegisterMiniportDriver',
 'ZwCreateFile','MmMapLockedPagesSpecifyCache','MmMapLockedPages','MmMapIoSpace','MmCopyMemory',
 'ProbeForWrite','ProbeForRead','SeAccessCheck','ObRegisterCallbacks','PsSetCreateProcessNotifyRoutine',
 'IoAllocateMdl','MmProbeAndLockPages','CmRegisterCallback','MmGetSystemAddressForMdlSafe',
 'RtlInitUnicodeString','IoDeleteDevice','IoAcquireRemoveLock','KeStackAttachProcess',
 'MmGetPhysicalAddress','ZwMapViewOfSection','MmMapViewInSystemSpace'
)
$modList = @('Wdf01000.sys','WdfLdr','wdfldr.sys','ndis.sys','fltmgr.sys','ntoskrnl.exe','hal.dll','ks.sys','tcpip.sys','vwififlt.sys','ndiswan.sys')

# ---------------------------------------------------------------- helpers
function U16([byte[]]$b,[int]$o){ if($o+2 -gt $b.Length){return 0}; [BitConverter]::ToUInt16($b,$o) }
function U32([byte[]]$b,[int]$o){ if($o+4 -gt $b.Length){return 0}; [BitConverter]::ToUInt32($b,$o) }
function U64([byte[]]$b,[int]$o){ if($o+8 -gt $b.Length){return 0}; [BitConverter]::ToUInt64($b,$o) }

function Get-CStr([byte[]]$b,[int]$off){
  $sb = New-Object System.Text.StringBuilder
  while ($off -ge 0 -and $off -lt $b.Length) {
    $c = $b[$off]; if ($c -eq 0) { break }
    [void]$sb.Append([char]$c); $off++
  }
  return $sb.ToString()
}

function Get-AsciiStrings {
  param([byte[]]$Bytes,[int]$Min=4)
  $res = New-Object 'System.Collections.Generic.List[string]'
  $sb  = New-Object System.Text.StringBuilder
  foreach ($b in $Bytes) {
    if ($b -ge 32 -and $b -le 126) { [void]$sb.Append([char]$b) }
    else { if ($sb.Length -ge $Min) { [void]$res.Add($sb.ToString()) }; [void]$sb.Clear() }
  }
  if ($sb.Length -ge $Min) { [void]$res.Add($sb.ToString()) }
  return ,$res
}

function Get-UniStrings {
  param([byte[]]$Bytes,[int]$Off=0)
  $len = $Bytes.Length - $Off
  if ($len -le 0) { return ,(New-Object 'System.Collections.Generic.List[string]') }
  $s = [System.Text.Encoding]::Unicode.GetString($Bytes, $Off, $len)
  return ,($s -split "`0+")
}

# ---------------------------------------------------------------- PE parse
function Get-PeModel {
  param([byte[]]$b)
  $m = @{ Ok=$false; Is64=$false; ImageBase=[uint64]0; Sections=@(); Imports=@() }
  if ($b.Length -lt 0x40) { return $m }
  if ($b[0] -ne 0x4D -or $b[1] -ne 0x5A) { return $m }         # MZ

  $pe = [int](U32 $b 0x3C)
  if ($pe + 24 -gt $b.Length) { return $m }
  if ($b[$pe] -ne 0x50 -or $b[$pe+1] -ne 0x45) { return $m }    # PE

  $numSec  = [int](U16 $b ($pe+6))
  $optSize = [int](U16 $b ($pe+20))
  $optOff  = $pe + 24
  $magic   = U16 $b $optOff
  $is64    = ($magic -eq 0x20B)
  $m.Is64  = $is64
  $m.ImageBase = if ($is64) { U64 $b ($optOff+24) } else { [uint64](U32 $b ($optOff+28)) }

  $secOff = $optOff + $optSize
  $secs = @()
  for ($i=0; $i -lt $numSec; $i++) {
    $o = $secOff + ($i*40)
    if ($o + 40 -gt $b.Length) { break }
    $name = Get-CStr $b $o
    $secs += [pscustomobject]@{
      Name = $name
      VSize= [int](U32 $b ($o+8))
      VA   = [int](U32 $b ($o+12))
      RawSize = [int](U32 $b ($o+16))
      RawPtr  = [int](U32 $b ($o+20))
      Flags   = [uint32](U32 $b ($o+36))
    }
  }
  $m.Sections = $secs

  # import directory (data dir index 1)
  $ddOff = $optOff + $(if ($is64) { 112 } else { 96 })
  $impRva = if ($ddOff + 12 -le $b.Length) { [int](U32 $b ($ddOff + 8)) } else { 0 }

  $rva2off = {
    param([int]$rva)
    foreach ($s in $secs) {
      $span = [Math]::Max($s.VSize, $s.RawSize)
      if ($rva -ge $s.VA -and $rva -lt ($s.VA + $span)) {
        return $s.RawPtr + ($rva - $s.VA)
      }
    }
    return -1
  }

  $imports = New-Object 'System.Collections.Generic.List[string]'
  if ($impRva -gt 0) {
    $rva = $impRva
    for ($guard=0; $guard -lt 512; $guard++) {
      $off = & $rva2off $rva
      if ($off -lt 0 -or $off + 20 -gt $b.Length) { break }
      $oft     = [int](U32 $b ($off))
      $nameRva = [int](U32 $b ($off+12))
      $ft      = [int](U32 $b ($off+16))
      if ($nameRva -eq 0 -and $ft -eq 0) { break }
      $modOff = & $rva2off $nameRva
      $mod = if ($modOff -ge 0) { Get-CStr $b $modOff } else { '?' }

      $thunkRva = if ($oft -ne 0) { $oft } else { $ft }
      $tOff = & $rva2off $thunkRva
      if ($tOff -ge 0) {
        $step = if ($is64) { 8 } else { 4 }
        for ($k=0; $k -lt 4096; $k++) {
          $to = $tOff + ($k*$step)
          if ($to + $step -gt $b.Length) { break }
          $v = if ($is64) { U64 $b $to } else { [uint64](U32 $b $to) }
          if ($v -eq 0) { break }
          $hiBit = if ($is64) { ([uint64]1 -shl 63) } else { ([uint64]1 -shl 31) }
          if (($v -band $hiBit) -ne 0) { continue }
          $hint = & $rva2off ([int]($v -band 0x7FFFFFFF))
          if ($hint -ge 0) { $imports.Add($mod + '!' + (Get-CStr $b ($hint+2))) }
        }
      }
      $rva += 20
    }
  }
  $m.Imports = $imports
  $m.Ok = $true
  return $m
}

# ---------------------------------------------------------------- main
foreach ($f in $Files) {
  if (-not (Test-Path -LiteralPath $f)) { Write-Output ("=== {0} ===`n  MISSING" -f $f); continue }
  $bytes = [System.IO.File]::ReadAllBytes($f)
  $pe    = Get-PeModel $bytes

  $ascii = Get-AsciiStrings -Bytes $bytes -Min 4
  $uniA  = Get-UniStrings -Bytes $bytes -Off 0
  $uniB  = Get-UniStrings -Bytes $bytes -Off 1
  $set   = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($s in $ascii) { [void]$set.Add($s) }
  foreach ($s in $uniA)  { if ($s.Length -ge 4) { [void]$set.Add($s) } }
  foreach ($s in $uniB)  { if ($s.Length -ge 4) { [void]$set.Add($s) } }

  $all = @($ascii) + @($uniA) + @($uniB)
  $dev = New-Object 'System.Collections.Generic.HashSet[string]'
  $sym = New-Object 'System.Collections.Generic.HashSet[string]'
  $reg = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($s in $all) {
    foreach ($m in [regex]::Matches($s,'\\Device\\[A-Za-z0-9_.\-]{1,48}'))    { [void]$dev.Add($m.Value) }
    foreach ($m in [regex]::Matches($s,'\\DosDevices\\[A-Za-z0-9_.\-]{1,48}')) { [void]$sym.Add($m.Value) }
    foreach ($m in [regex]::Matches($s,'\\\?\?\\[A-Za-z0-9_.\-]{1,48}'))       { [void]$sym.Add($m.Value) }
    foreach ($m in [regex]::Matches($s,'\\\\Registry\\[A-Za-z0-9_.\\]{4,80}')){ [void]$reg.Add($m.Value) }
  }

  $apis = New-Object 'System.Collections.Generic.List[string]'
  foreach ($a in $apiList) { if ($set.Contains($a)) { [void]$apis.Add($a) } }
  $mods = New-Object 'System.Collections.Generic.List[string]'
  foreach ($a in $modList) { if ($set.Contains($a)) { [void]$mods.Add($a) } }

  $vi = $null
  try { $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($f) } catch { }

  # ---- imported API names (authoritative, unlike string presence) -------
  $impNames = @()
  if ($pe.Ok) { $impNames = $pe.Imports | ForEach-Object { ($_ -split '!')[-1] } }
  $impSet = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($n in $impNames) { [void]$impSet.Add($n) }

  $secureApi = @()
  foreach ($n in 'IoCreateDeviceSecure','WdmlibIoCreateDeviceSecure','WdfDeviceInitAssignSDDLString') {
    if ($impSet.Contains($n)) { $secureApi += $n }
  }
  $hasNdisDev = $impSet.Contains('NdisRegisterDeviceEx')
  $isKmdf     = $impSet.Contains('WdfVersionBind')
  $hasCreate  = @('IoCreateDevice','WdfDeviceCreate','NdisRegisterDeviceEx') | Where-Object { $impSet.Contains($_) }
  $devCreateShown = @($hasCreate) + @($secureApi)
  if ($devCreateShown.Count -eq 0 -and $isKmdf) { $devCreateShown = @('KMDF-dynamic') }

  # ---- locate SDDL literals and resolve to VA -------------------------
  $sddl = New-Object 'System.Collections.Generic.List[object]'
  $patterns = @(
    @{ Pat='D:P(A;;'; Wide=$false },
    @{ Pat='D:P(A;;'; Wide=$true  }
  )
  foreach ($p in $patterns) {
    $needle = if ($p.Wide) {
      $arr = New-Object 'System.Collections.Generic.List[byte]'
      foreach ($ch in $p.Pat.ToCharArray()) { $arr.Add([byte]$ch); $arr.Add(0) }
      ,$arr.ToArray()
    } else { [Text.Encoding]::ASCII.GetBytes($p.Pat) }

    $start = 0
    while ($start -lt $bytes.Length) {
      $idx = [Array]::IndexOf($bytes, $needle[0], $start)
      if ($idx -lt 0) { break }
      $ok = $true
      for ($k=1; $k -lt $needle.Length; $k++) {
        if (($idx+$k) -ge $bytes.Length -or $bytes[$idx+$k] -ne $needle[$k]) { $ok=$false; break }
      }
      if (-not $ok) { $start = $idx + 1; continue }

      # read the string
      $sb = New-Object System.Text.StringBuilder
      if ($p.Wide) {
        $o = $idx
        while ($o + 1 -lt $bytes.Length) {
          if ($bytes[$o] -eq 0 -and $bytes[$o+1] -eq 0) { break }
          [void]$sb.Append([char]$bytes[$o]); $o += 2
        }
      } else {
        [void]$sb.Append((Get-CStr $bytes $idx))
      }

      # file offset -> RVA -> VA
      $rva = -1
      foreach ($s in $pe.Sections) {
        if ($idx -ge $s.RawPtr -and $idx -lt ($s.RawPtr + $s.RawSize)) { $rva = $s.VA + ($idx - $s.RawPtr); break }
      }
      $va = if ($rva -ge 0) { $pe.ImageBase + [uint64]$rva } else { [uint64]0 }

      $sddl.Add([pscustomobject]@{ Text=$sb.ToString(); Va=$va; Off=$idx; Wide=$p.Wide; Code=0; Data=0; DataAt=[uint64]0; ViaDesc=0 })
      $start = $idx + $needle.Length
    }
  }

  # ---- count real references -------------------------------------------
  if ($pe.Ok -and $sddl.Count -gt 0) {
    $exec = @($pe.Sections | Where-Object { ($_.Flags -band 0x20000000) -ne 0 })
    $targets = New-Object 'System.Collections.Generic.HashSet[uint64]'

    foreach ($s in $exec) {
      $end = [Math]::Min($s.RawPtr + $s.RawSize, $bytes.Length)
      # Opcode-agnostic RIP-relative scan: any disp32 whose next-instruction
      # address + disp lands exactly on an SDDL VA is a code reference.
      # This catches lea, mov, movups, cmpsd and friends without decoding.
      $i = $s.RawPtr
      while ($i -lt $end - 6) {
        $best = -1
        foreach ($mr in [byte]0x05,[byte]0x0D,[byte]0x15,[byte]0x1D,[byte]0x25,[byte]0x2D,[byte]0x35,[byte]0x3D) {
          $hit = [Array]::IndexOf($bytes, $mr, $i, ($end - $i))
          if ($hit -ge 0 -and ($best -lt 0 -or $hit -lt $best)) { $best = $hit }
        }
        if ($best -lt 0) { break }
        $idx = $best
        if ($idx + 5 -lt $bytes.Length) {
          $disp = [BitConverter]::ToInt32($bytes, $idx + 1)
          $nextRva = $s.VA + ($idx + 5 - $s.RawPtr)
          $t = [int64]$pe.ImageBase + [int64]$nextRva + [int64]$disp
          if ($t -ge 0) { [void]$targets.Add([uint64]$t) }
        }
        $i = $idx + 1
      }
    }

    # x86 absolute pushes / movs
    if (-not $pe.Is64) {
      foreach ($s in $exec) {
        $end = [Math]::Min($s.RawPtr + $s.RawSize, $bytes.Length)
        $i = $s.RawPtr
        foreach ($op in 0x68,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF) {
          $i = $s.RawPtr
          while ($i -lt $end - 5) {
            $idx = [Array]::IndexOf($bytes, [byte]$op, $i, ($end - $i))
            if ($idx -lt 0) { break }
            $imm = [uint64](U32 $bytes ($idx+1))
            [void]$targets.Add($imm)
            $i = $idx + 1
          }
        }
      }
    }

    foreach ($e in $sddl) {
      if ($e.Va -ne 0 -and $targets.Contains([uint64]$e.Va)) { $e.Code = 1 }
    }

    # data-section pointer tables — also record where the pointer lives, so a
    # UNICODE_STRING descriptor that is itself lea'd counts as a live reference
    $dataSecs = @($pe.Sections | Where-Object { ($_.Flags -band 0x20000000) -eq 0 })
    foreach ($e in $sddl) {
      if ($e.Va -eq 0) { continue }
      $needle = if ($pe.Is64) { [BitConverter]::GetBytes([uint64]$e.Va) } else { [BitConverter]::GetBytes([uint32]$e.Va) }
      foreach ($s in $dataSecs) {
        $end = [Math]::Min($s.RawPtr + $s.RawSize, $bytes.Length)
        $i = $s.RawPtr
        while ($i -lt $end - $needle.Length) {
          $idx = [Array]::IndexOf($bytes, $needle[0], $i, ($end - $i))
          if ($idx -lt 0) { break }
          $ok = $true
          for ($k=1; $k -lt $needle.Length; $k++) {
            if (($idx+$k) -ge $bytes.Length -or $bytes[$idx+$k] -ne $needle[$k]) { $ok=$false; break }
          }
          if ($ok) {
            $e.Data = 1
            $e.DataAt = $pe.ImageBase + [uint64]($s.VA + ($idx - $s.RawPtr))
            break
          }
          $i = $idx + 1
        }
        if ($e.Data -eq 1) { break }
      }
    }

    # A descriptor that code references makes the string live. Require a real
    # UNICODE_STRING/ANSI_STRING header: Length must equal the string size,
    # MaximumLength must be sane, and Buffer must point back at the literal.
    # A blind "nearby code ref" window over-flags structs that merely embed a
    # pointer, so validate the header instead.
    $descBack = if ($pe.Is64) { 8 } else { 4 }
    foreach ($e in $sddl) {
      if ($e.Data -ne 1 -or $e.DataAt -eq 0) { continue }
      $candVa = [int64]$e.DataAt - $descBack
      if ($candVa -lt 0) { continue }
      if (-not $targets.Contains([uint64]$candVa)) { continue }

      $rva = $candVa - [int64]$pe.ImageBase
      $off = -1
      foreach ($s in $pe.Sections) {
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.RawSize)) { $off = $s.RawPtr + ($rva - $s.VA); break }
      }
      if ($off -lt 0 -or ($off + $descBack + 4) -gt $bytes.Length) { continue }

      $need = if ($e.Wide) { $e.Text.Length * 2 } else { $e.Text.Length }
      $len  = [BitConverter]::ToUInt16($bytes, $off)
      $max  = [BitConverter]::ToUInt16($bytes, $off + 2)
      if ($len -ne $need -or $max -lt $need -or $max -gt ($need + 2)) { continue }

      $ptr = if ($pe.Is64) { [BitConverter]::ToUInt64($bytes, $off + 8) }
             else { [uint64][BitConverter]::ToUInt32($bytes, $off + 4) }
      if ($ptr -ne [uint64]$e.Va) { continue }

      $e.Code = 1; $e.ViaDesc = 1
    }
  }

  # ---- sibling INF (class-installed devices carry DACL there) ----------
  $infSddl = @()
  $dir = Split-Path -Parent $f
  $base = [IO.Path]::GetFileNameWithoutExtension($f)
  $inf = Get-ChildItem $dir -Filter '*.inf' -File -ErrorAction SilentlyContinue |
         Where-Object { $_.BaseName -like "$base*" } | Select-Object -First 1
  if ($inf) {
    # INF comments start with ';'. Strip whole-line and trailing comments before
    # matching, or a commented-out [Security] line reads as an active DACL.
    $lines = Get-Content $inf.FullName -ErrorAction SilentlyContinue
    # INF semicolons inside an SDDL are part of the value, so only whole-line
    # comments (first non-space char is ';') may be dropped.
    $clean = foreach ($ln in $lines) {
      if ($null -eq $ln) { continue }
      if ($ln.TrimStart().StartsWith(';')) { continue }
      $ln
    }
    $txt = ($clean -join "`n")
    foreach ($m in [regex]::Matches($txt,'D:P\(A;;[A-Za-z0-9;()]{4,120}')) { $infSddl += $m.Value }
  }

  # ---- verdict ----------------------------------------------------------
  $live   = @($sddl | Where-Object { $_.Code -eq 1 })
  $dataOnly = @($sddl | Where-Object { $_.Code -eq 0 -and $_.Data -eq 1 })
  $dead   = @($sddl | Where-Object { $_.Code -eq 0 -and $_.Data -eq 0 })
  $open   = @($live | Where-Object { $_.Text -match ';;;(WD|BU|AU)' })

  $reach = 'UNKNOWN'
  if ($open.Count -gt 0)                                 { $reach = 'SDDL-ACTIVE-OPEN' }
  elseif ($live.Count -gt 0)                             { $reach = 'SDDL-ACTIVE-RESTRICTED' }
  elseif ($dataOnly.Count -gt 0 -and $open.Count -eq 0)   { $reach = 'SDDL-UNPROVEN' }
  elseif ($sddl.Count -gt 0)                             { $reach = 'SDDL-DEAD' }
  elseif ($secureApi.Count -gt 0 -or $hasNdisDev)        { $reach = 'SECURE-CALL-NO-LITERAL' }
  elseif ($infSddl.Count -gt 0 -and ($infSddl -match ';;;(WD|BU|AU)')) { $reach = 'INF-SDDL-OPEN' }
  elseif ($hasCreate.Count -gt 0)                        { $reach = 'DEFAULT-ADMIN' }
  elseif ($infSddl.Count -gt 0)                          { $reach = 'INF-SDDL-RESTRICTED' }
  else                                                   { $reach = 'NO-DEVICE' }

  Write-Output ("=== {0} ===" -f (Split-Path -Leaf $f))
  Write-Output ("  size={0}  company={1}  ver={2}" -f $bytes.Length, $vi.CompanyName, $vi.FileVersion)
  Write-Output ("  arch    : {0}" -f $(if(-not $pe.Ok){'?'}elseif($pe.Is64){'x64'}else{'x86'}))
  Write-Output ("  modules : {0}" -f (($mods | Sort-Object) -join ', '))
  Write-Output ("  apis    : {0}" -f (($apis | Sort-Object) -join ', '))
  Write-Output ("  devcreate: {0}" -f (($devCreateShown | Sort-Object -Unique) -join ', '))
  Write-Output ("  device  : {0}" -f (($dev | Sort-Object) -join ' | '))
  Write-Output ("  symlink : {0}" -f (($sym | Sort-Object) -join ' | '))
  Write-Output ("  sddl    : {0}" -f (($sddl | ForEach-Object { $_.Text } | Sort-Object -Unique) -join ' | '))
  if ($sddl.Count -gt 0) {
    $marks = $sddl | ForEach-Object {
      $st = if ($_.Code -eq 1 -and $_.ViaDesc -eq 1) { 'DESC-XREF' }
            elseif ($_.Code -eq 1) { 'CODE-XREF' }
            elseif ($_.Data -eq 1) { 'DATA-XREF' }
            else { 'DEAD' }
      "{0} [{1}]" -f $_.Text, $st
    }
    Write-Output ("  sddl_ref: {0}" -f (($marks | Sort-Object -Unique) -join ' | '))
  }
  if ($infSddl.Count -gt 0) {
    Write-Output ("  inf_sddl: {0}" -f (($infSddl | Sort-Object -Unique) -join ' | '))
  }
  Write-Output ("  reach   : {0}" -f $reach)
  Write-Output ("  regpath : {0}" -f (($reg | Sort-Object | Select-Object -First 8) -join ' | '))
}
