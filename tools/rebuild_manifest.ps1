param(
  [string]$Drivers = '',
  [string]$Manifest = '',
  [string]$NewBatch = 'unassigned'
)

$ErrorActionPreference = 'Stop'
$tools = $PSScriptRoot
$projectRoot = Split-Path -Parent $tools
if (-not $Drivers)  { $Drivers  = Join-Path $projectRoot 'drivers' }
if (-not $Manifest) { $Manifest = Join-Path $projectRoot 'indexes\drivers_manifest.csv' }

$oldBatch = @{}
if (Test-Path -LiteralPath $Manifest) {
  foreach ($row in (Import-Csv -LiteralPath $Manifest)) {
    if ($row.SHA256) { $oldBatch[$row.SHA256.ToUpper()] = $row.Batch }
  }
}

$rows = foreach ($f in (Get-ChildItem -LiteralPath $Drivers -File -Filter *.sys | Sort-Object Name)) {
  $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToUpper()
  [pscustomobject]@{
    Batch    = $(if ($oldBatch.ContainsKey($h)) { $oldBatch[$h] } else { $NewBatch })
    Path     = 'drivers\' + $f.Name
    FileName = $f.Name
    Size     = $f.Length
    SHA256   = $h
  }
}

$rows | Export-Csv -LiteralPath $Manifest -NoTypeInformation -Encoding UTF8
Write-Output ("manifest: {0} rows, {1} unique hashes" -f @($rows).Count, ($rows.SHA256 | Sort-Object -Unique).Count)
