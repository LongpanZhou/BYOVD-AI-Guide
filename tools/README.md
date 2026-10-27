# Tools

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

| Path | What it is |
|---|---|
| `harvest.ps1` | Installer/tree → `.sys` harvester + fingerprint writer |
| `triage_scan.ps1` | PE import, device, SDDL, reach scanner |
| `filter_new_drivers.ps1` | Mandatory dedupe gate |
| `rebuild_manifest.ps1` | Rebuild `indexes/drivers_manifest.csv` from `drivers/` |
| `innoextract/` (local only) | Inno Setup ≤ 6.0.5 extractor; not tracked in this repo |
| `innounp` (on `PATH`) | Inno Setup 6.1+ extractor; `winget install JurgenRathlev.innounp` |
| `vm/never_sleep.bat` | VM power/sleep helper |

## Download workflow

Prerequisite: **7-Zip** at `C:\Program Files\7-Zip\7z.exe`. Optional: WiX in `tools/wix/`.

```powershell
# 1. download into ..\downloads\
# 2. harvest
.\harvest.ps1 -Path ..\downloads\<installer> -Vendor <Vendor> -PackageId <ID> `
  -Out ..\downloads\_harvest -Index ..\indexes\collections\collected<N>\_index.jsonl

# 3. dedupe into the corpus
.\filter_new_drivers.ps1 -SourceDir ..\downloads\_harvest -OutDir ..\drivers `
  -Manifest ..\indexes\collections\collected<N>\manifest.csv `
  -Existing ..\indexes\dedupe\existing_hashes.txt `
  -KnownBad ..\indexes\dedupe\known_bad_hashes.txt `
  -UpdateExisting

# 4. rebuild the manifest
.\rebuild_manifest.ps1 -NewBatch collected<N>
```

WiX `dark.exe` is not retained. Re-install WiX into `tools/wix/` only while unpacking a Burn/MSI
package, then delete it after the batch is accepted.

Full method: [`../DRIVER_COLLECTION_PLAYBOOK.md`](../DRIVER_COLLECTION_PLAYBOOK.md).
Future-download quick-start: [`../downloads/README.md`](../downloads/README.md).
