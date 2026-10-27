param(
  [Parameter(Mandatory=$true)][string]$SourceDir,
  [Parameter(Mandatory=$true)][string]$OutDir,
  [Parameter(Mandatory=$true)][string]$Manifest,
  [string]$Existing = '',
  [string]$KnownBad = '',
  [switch]$IncludeKnownBad,
  [switch]$UpdateExisting
)

$ErrorActionPreference = 'Continue'
if (-not $Existing) { $Existing = Join-Path $PSScriptRoot '..\indexes\dedupe\existing_hashes.txt' }
if (-not $KnownBad) { $KnownBad = Join-Path $PSScriptRoot '..\indexes\dedupe\known_bad_hashes.txt' }
$Existing = [IO.Path]::GetFullPath($Existing)
$KnownBad = [IO.Path]::GetFullPath($KnownBad)

if (-not (Test-Path -LiteralPath $KnownBad)) {
  Write-Output "KNOWN-BAD LIST MISSING: $KnownBad"
  Write-Output "Refusing to run the dedupe gate without a blocklist."
  Write-Output "Fetch indexes/dedupe/known_bad_hashes.txt from the example branch (see tools/README.md)."
  exit 2
}

function Load-Set([string]$path) {
  $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  if (Test-Path -LiteralPath $path) {
    foreach ($line in [System.IO.File]::ReadLines($path)) {
      $h = $line.Trim()
      if ($h.Length -eq 64) { [void]$set.Add($h) }
    }
  }
  return ,$set
}

$existingSet = Load-Set $Existing
$knownBadSet = Load-Set $KnownBad
$localGate = Join-Path $PSScriptRoot '..\indexes\dedupe\exported_hashes_local.txt'
if (Test-Path -LiteralPath $localGate) { foreach ($h in (Load-Set $localGate)) { [void]$knownBadSet.Add($h) } }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Manifest) | Out-Null

$rows = New-Object 'System.Collections.Generic.List[object]'
$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$acceptedHashes = New-Object 'System.Collections.Generic.List[string]'
$counts = @{ NEW = 0; EXISTING = 0; KNOWNBAD = 0; DUPLICATE = 0; SKIP = 0 }

foreach ($f in @(Get-ChildItem -LiteralPath $SourceDir -Recurse -Filter *.sys -File -ErrorAction SilentlyContinue)) {
  if ($f.Length -lt 4096) { $counts.SKIP++; continue }
  $hash = $null
  try { $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpper() } catch { $counts.SKIP++; continue }
  if (-not $hash) { $counts.SKIP++; continue }

  $status = 'NEW'
  if ($existingSet.Contains($hash)) { $status = 'EXISTING' }
  elseif ($knownBadSet.Contains($hash) -and -not $IncludeKnownBad) { $status = 'KNOWNBAD' }
  elseif (-not $seen.Add($hash)) { $status = 'DUPLICATE' }
  $counts[$status]++

  $copied = ''
  if ($status -eq 'NEW') {
    $base = [IO.Path]::GetFileNameWithoutExtension($f.Name)
    $suffix = "_$($hash.Substring(0,8))"
    if ($base.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) {
      $name = "$base.sys"
    } else {
      $name = "$base$suffix.sys"
    }
    $dst = Join-Path $OutDir $name
    Copy-Item -LiteralPath $f.FullName -Destination $dst -Force
    $copied = $dst
    $acceptedHashes.Add($hash)
  }

  $vi = $null; try { $vi = $f.VersionInfo } catch {}
  $sig = 'Unknown'
  try { $sig = (Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction Stop).Status.ToString() } catch {}
  $signer = ''
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction Stop
    if ($s.SignerCertificate) { $signer = $s.SignerCertificate.Subject }
  } catch {}

  $rows.Add([pscustomobject]@{
    Driver          = $f.Name
    SHA256          = $hash
    SizeKB          = [math]::Round($f.Length / 1KB)
    Company         = $vi.CompanyName
    FileVersion     = $vi.FileVersion
    SignatureStatus = $sig
    Signer          = $signer
    Status          = $status
    OriginalPath    = $f.FullName
    CopiedPath      = $copied
  })
}

$rows | Export-Csv -LiteralPath $Manifest -NoTypeInformation -Encoding UTF8

$updated = 0
if ($UpdateExisting -and $acceptedHashes.Count -gt 0) {
  foreach ($h in $acceptedHashes) {
    if (-not $existingSet.Contains($h)) {
      Add-Content -LiteralPath $Existing -Value $h
      [void]$existingSet.Add($h)
      $updated++
    }
  }
  $overlap = @($knownBadSet | Where-Object { $existingSet.Contains($_) }).Count
  $dedupeSummary = Join-Path (Split-Path -Parent $Existing) 'dedupe_summary.txt'
  @(
    "Existing unique hashes: $($existingSet.Count)",
    "Known-bad hashes (LOLDrivers): $($knownBadSet.Count)",
    "Overlap existing/known-bad: $overlap",
    "Index: $Existing"
  ) | Set-Content -LiteralPath $dedupeSummary -Encoding UTF8
}

$summary = @()
$summary += "Source: $SourceDir"
$summary += "New: $($counts.NEW)"
$summary += "Existing: $($counts.EXISTING)"
$summary += "KnownBad: $($counts.KNOWNBAD)"
$summary += "Duplicate: $($counts.DUPLICATE)"
$summary += "Skipped: $($counts.SKIP)"
$summary += "Manifest: $Manifest"
if ($UpdateExisting) { $summary += "Dedupe index updated: $updated new hashes" }
$summary | Write-Output
