param(
  [Parameter(Mandatory=$true)][string]$Path,
  [Parameter(Mandatory=$true)][string]$Vendor,
  [Parameter(Mandatory=$true)][string]$PackageId,
  [string]$Out   = '',
  [string]$Work  = '',
  [int]$MaxDepth = 4,
  [string]$Index = '',
  [switch]$NoExpand
)

$ErrorActionPreference = 'Continue'
$seven  = 'C:\Program Files\7-Zip\7z.exe'
$tools  = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $tools
$dark   = Join-Path $tools 'wix\dark.exe'
$inno   = Join-Path $tools 'innoextract\innoextract.exe'
$triage = Join-Path $tools 'triage_scan.ps1'
if (-not $Out)   { $Out   = Join-Path $projectRoot 'downloads\_harvest' }
if (-not $Work)  { $Work  = Join-Path $projectRoot 'downloads\_hx' }
if (-not $Index) { $Index = Join-Path $projectRoot 'indexes\collections\collected1\_index.jsonl' }
if (-not (Test-Path $inno))   { Write-Warning "innoextract not found at $inno - Inno Setup <= 6.0.5 packages cannot be extracted this run (see DRIVER_COLLECTION_PLAYBOOK.md section 3)." }
if (-not (Test-Path $triage)) { Write-Warning "triage_scan.ps1 not found at $triage - triage columns will be skipped." }
$index  = $Index

New-Item -ItemType Directory -Force -Path $Out, $Work, (Split-Path -Parent $index) | Out-Null

$tag = ($PackageId -replace '[^A-Za-z0-9._-]','_') + '_' + ([guid]::NewGuid().ToString('N').Substring(0,6))
$root = Join-Path $Work $tag
New-Item -ItemType Directory -Force -Path $root | Out-Null

# ---- stage input -----------------------------------------------------------
# A directory is harvested IN PLACE: Copy-Item silently truncates trees at
# MAX_PATH, which loses deep Electron app.asar.unpacked\...\drivers paths.
$inPlace = $false
if (Test-Path -LiteralPath $Path -PathType Leaf) {
  Copy-Item -LiteralPath $Path -Destination (Join-Path $root (Split-Path -Leaf $Path)) -Force
} elseif (Test-Path -LiteralPath $Path -PathType Container) {
  $root = (Resolve-Path -LiteralPath $Path).Path
  $inPlace = $true
} else {
  Write-Output "STAGE-FAIL $Path"
  exit 1
}

function Expand-ArchiveLike {
  param([string]$File,[string]$Dest)
  $ext = [IO.Path]::GetExtension($File).ToLower()
  New-Item -ItemType Directory -Force -Path $Dest | Out-Null
  switch ($ext) {
    '.cab' {
      & expand.exe $File -F:* $Dest 2>&1 | Out-Null
      if (-not (Get-ChildItem $Dest -File -ErrorAction SilentlyContinue)) {
        & $seven x $File "-o$Dest" -y 2>&1 | Out-Null
      }
    }
    default {
      $o = & $seven x $File "-o$Dest" -y 2>&1
      if ($LASTEXITCODE -ne 0) { return $false }
      # WiX Burn: only UX payload comes out -> decompile
      $isBurn = (Test-Path (Join-Path $Dest 'wixstdba.dll')) -or
                (Test-Path (Join-Path $Dest 'BootstrapperApplicationData.xml'))
      $n = @(Get-ChildItem $Dest -Recurse -File -ErrorAction SilentlyContinue).Count
      if (($isBurn -or $n -lt 3) -and $ext -eq '.exe' -and (Test-Path $dark)) {
        $d2 = "$Dest`_burn"
        & $dark -x $d2 $File 2>&1 | Out-Null
        if (Test-Path $d2) { Get-ChildItem $d2 -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
          $rel = $_.FullName.Substring($d2.Length).TrimStart('\')
          $tgt = Join-Path $Dest $rel
          New-Item -ItemType Directory -Force -Path (Split-Path -Parent $tgt) | Out-Null
          Copy-Item -LiteralPath $_.FullName -Destination $tgt -Force
        } }
      }
      # Inno Setup: 7-Zip only sees the PE stub -> use innoextract
      if ($ext -eq '.exe' -and $n -lt 10 -and (Test-Path $inno)) {
        $d3 = "$Dest`_inno"
        & $inno --silent -e -d $d3 -- $File 2>&1 | Out-Null
        if (Test-Path $d3) {
          Get-ChildItem $d3 -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $rel = $_.FullName.Substring($d3.Length).TrimStart('\')
            $tgt = Join-Path $Dest $rel
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $tgt) | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $tgt -Force
          }
        }
      }
    }
  }
  return $true
}

# ---- recursive expansion ---------------------------------------------------
$archExt = @('.zip','.7z','.cab','.msi','.exe','.rar','.tar','.gz')
$done = New-Object 'System.Collections.Generic.HashSet[string]'
for ($depth = 0; $depth -lt $MaxDepth -and -not $NoExpand; $depth++) {
  $cands = @(Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $archExt -contains $_.Extension.ToLower() -and -not $done.Contains($_.FullName) })
  if ($cands.Count -eq 0) { break }
  foreach ($c in $cands) {
    [void]$done.Add($c.FullName)
    $dest = "$($c.FullName).d"
    if (Test-Path $dest) { continue }
    Expand-ArchiveLike -File $c.FullName -Dest $dest | Out-Null
  }
}

# ---- collect drivers -------------------------------------------------------
$seen = New-Object 'System.Collections.Generic.HashSet[string]'
$found = New-Object 'System.Collections.Generic.List[object]'
foreach ($s in @(Get-ChildItem $root -Recurse -File -Filter *.sys -ErrorAction SilentlyContinue)) {
  if ($s.Length -lt 1024) { continue }
  $h = (Get-FileHash $s.FullName -Algorithm SHA256).Hash
  if (-not $seen.Add($h)) { continue }
  $vdir = $Out
  New-Item -ItemType Directory -Force -Path $vdir | Out-Null
  $base = [IO.Path]::GetFileNameWithoutExtension($s.Name)
  $ext  = [IO.Path]::GetExtension($s.Name)
  $name = "$base`_$($h.Substring(0,8))$ext"
  $dst  = Join-Path $vdir $name
  Copy-Item -LiteralPath $s.FullName -Destination $dst -Force
  $vi = $null; try { $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($dst) } catch {}
  $sig = 'Unknown'; try { $sig = (Get-AuthenticodeSignature $dst).Status.ToString() } catch {}
  $t = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $triage $dst 2>&1 | Out-String
  function Grab([string]$k) {
    if ($t -match "(?m)^[ \t]*$k[ \t]*:[ \t]*(.*)$") { return $Matches[1].Trim() }
    return ''
  }
  $row = [pscustomobject]@{
    PackageId = $PackageId; Vendor = $Vendor; Driver = $name; Bytes = $s.Length
    SHA256 = $h; Company = $vi.CompanyName; Version = $vi.FileVersion; Sig = $sig
    Devices = (Grab 'device'); Symlinks = (Grab 'symlink'); SDDL = (Grab 'sddl')
    Reach = (Grab 'reach'); DevCreate = (Grab 'devcreate'); InfSddl = (Grab 'inf_sddl')
    Apis = (Grab 'apis'); SourcePath = $s.FullName.Replace($root,'')
  }
  [void]$found.Add($row)
  Add-Content -LiteralPath $index -Value ($row | ConvertTo-Json -Compress) -Encoding UTF8
  Write-Output ("DRIVER {0,-32} {1,8} {2,-12} {3,-22} {4}" -f $name, $s.Length, $sig, $row.Reach, $row.SDDL)
}
Write-Output "RESULT $PackageId drivers=$($found.Count)"
if ($found.Count -eq 0) { Write-Output 'NO-DRIVER' }
