# indexes/ - machine-readable state

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

Everything the docs quote as a number comes from here. If a count in a README disagrees with a
file in this folder, this folder wins.

| Path | What it is |
|---|---|
| `drivers_manifest.csv` | Canonical inventory: `Batch, Path, FileName, Size, SHA256` - 387 rows (386 in-repo drivers + local-only `vgk.sys`) |
| `dedupe/existing_hashes.txt` | Hash gate - 925 tracked SHA-256 values |
| `dedupe/known_bad_hashes.txt` | 5,833 LOLDrivers/known-bad SHA-256 values |
| `dedupe/dedupe_summary.txt` | Counts and overlap for the dedupe gate |
| `dedupe/existing_drivers.csv` | Historical hash -> source-path map (paths may predate the flat `drivers/` layout) |
| `collections/` | Per-batch provenance: URLs, manifests, summaries, triage |
| `driverstore/` | DriverStore scan output (discovery artifacts, not audit reports) |

## Regenerating

```powershell
# inventory (scans drivers/ on disk; run with your local vgk.sys present)
tools\rebuild_manifest.ps1

# dedupe counts, atomically, while accepting a batch
tools\filter_new_drivers.ps1 -SourceDir downloads\_harvest -OutDir drivers `
  -Manifest indexes\collections\collected6\manifest.csv -UpdateExisting
```

## Which number is authoritative?

| Claim | Authoritative value |
|---|---|
| Drivers in the repo | **386** `.sys` files |
| Manifest rows | **387** (adds local-only `vgk.sys`) |
| Dedupe hashes | **925** tracked + **7** exported (local gate) = **932** |
| Known-bad hashes | **5,833** |
| Audit reports | `audits/reports/` - 257 Markdown files (some are appendices/group reports) |

Batch counts: `original` 94 (includes `vgk.sys`), `collected2` 135, `collected3` 11,
`collected5` 41, `collected1` 106. These sum to 387 because of `vgk.sys`; visible files sum to 386.
