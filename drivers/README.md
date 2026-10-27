# drivers/ - the corpus

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

**386 `.sys` files, flat, no subfolders.** (`vgk.sys` is local-only at 104 MB; the three verified
driver families - 7 files - were exported out on 2026-10-25 and are intentionally not listed here.)

| Batch | Count |
|---|---:|
| original host | 94 |
| `collected2` | 135 |
| `collected3` | 11 |
| `collected5` (R1-R4) | 41 |
| `collected1` (S1-S6) | 106 |
| **total in repo** | **386** |

Batch counts sum to 387 because the original 94 includes local-only `vgk.sys`; the manifest has
387 rows for the same reason.

Manifest: [`../indexes/drivers_manifest.csv`](../indexes/drivers_manifest.csv) - batch, path, size, SHA-256.

## Rules

- `.sys` only. No installers, `.inf`/`.cat`, archives.
- One copy per SHA-256 - run [`../tools/filter_new_drivers.ps1`](../tools/filter_new_drivers.ps1) before adding.
- Batch provenance lives in the manifest, **never in subfolders**.
- Vendor binaries: **do not load on your host.**

## Add a driver

1. Extract in `../downloads/` via `../tools/harvest.ps1`.
2. Dedupe into here:
```powershell
..\tools\filter_new_drivers.ps1 -SourceDir ..\downloads\_harvest -OutDir . `
  -Manifest ..\indexes\collections\collected<N>\manifest.csv `
  -Existing ..\indexes\dedupe\existing_hashes.txt `
  -KnownBad ..\indexes\dedupe\known_bad_hashes.txt -UpdateExisting
```
3. Log the URL in `../indexes/collections/collected<N>/urls.txt`, then run
   `../tools/rebuild_manifest.ps1 -NewBatch collected<N>`.
   Run this with your local `vgk.sys` present, or its manifest row will be dropped.
4. Clean `../downloads/` (keep only `README.md`, `.gitkeep`).
