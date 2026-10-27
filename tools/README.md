# tools/

The scripts are **not vendored on this branch**. Fetch them from `example`:

```powershell
$raw  = 'https://raw.githubusercontent.com/LongpanZhou/BYOVD-AI-Guide/example'
$base = "$raw/tools"
'harvest.ps1','filter_new_drivers.ps1','rebuild_manifest.ps1','triage_scan.ps1' |
  ForEach-Object { Invoke-WebRequest "$base/$_" -OutFile "tools\$_" -UseBasicParsing }
Invoke-WebRequest "$raw/indexes/dedupe/known_bad_hashes.txt" `
  -OutFile "indexes\dedupe\known_bad_hashes.txt" -UseBasicParsing
```

`filter_new_drivers.ps1` **refuses to run** if `indexes/dedupe/known_bad_hashes.txt` is missing.

| Script | Purpose |
|---|---|
| `harvest.ps1` | extract `.sys` from installers — never executes them |
| `filter_new_drivers.ps1` | mandatory dedupe gate; the only writer into `drivers/` |
| `rebuild_manifest.ps1` | rebuild `indexes/drivers_manifest.csv` |
| `triage_scan.ps1` | PE import / device / SDDL / reach scan |
