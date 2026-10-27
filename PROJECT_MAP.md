# Project Map

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

One clean tree. Every driver is in `drivers/`; every current audit is in `audits/reports/`.

## Root

| Path | What it is |
|---|---|
| `START_HERE.md` | Reading order for humans and AI agents |
| `PROJECT_GOAL.md` | Canonical goal, scope, severity, current state |
| `PROJECT_MAP.md` | This file |
| `README.md` | Project overview and top findings |
| `VM_ACCESS.md` | Canonical VM test guest + rules (local gitignored; not in the repo) |
| `DRIVER_COLLECTION_PLAYBOOK.md` | **How to download and harvest new drivers** |
| `downloads/` | Disposable download/extract scratch (gitignored; only `README.md`/`.gitkeep` after harvest) |

## `drivers/` - the corpus

| Path | What it is |
|---|---|
| `drivers/*.sys` | **All 386 drivers, flat, one copy each (verified exports removed).** No subfolders, no installers. |
| `drivers/README.md` | Counts, batch provenance, dedupe rule |

Batch provenance is in `indexes/drivers_manifest.csv` (`Batch` column) and
`indexes/collections/`. Do not recreate `_collected*` folders.

## `audits/` - analysis

| Path | What it is |
|---|---|
| `audits/README.md` | Audits guide + historical-report warning |
| `audits/STATUS.md` | **Single live status/queue source** |
| `audits/scope/` | `AUDIT_SCOPE.md`, `SEVERITY.md`, `STATIC_ANALYSIS_AGENT_PROMPT.md` |
| `audits/reports/` | Per-driver reports, flat (current + retained historical; `STATUS.md` is authoritative) |
| `audits/legacy/` | Historical reports, structure/VM notes, VM batch 2, monitor logs |
| `audits/evidence/` | Dynamic validation logs/scripts (PoCs live in `poc/`) |
| `audits/projects/` | Ghidra/analysis projects (handover_agentH) |

## `poc/` - exploit/harness code

| Path | What it is |
|---|---|
| `poc/README.md` | PoC rules and naming |
| `poc/historical/` | t4-t7 PoC sources/harnesses; t8-t10 runbooks in `audits/legacy/vm_batch2/` |
| `poc/reference/dbk64.sys` | Known-vulnerable Cheat Engine driver; VM calibration only |

Future PoCs go in `poc/<driver>/`. Never run them on the host.

## `indexes/` - machine-readable state

| Path | What it is |
|---|---|
| `indexes/drivers_manifest.csv` | Canonical inventory - 387 rows: 386 in-repo drivers + local-only `vgk.sys` (batch, path, size, SHA-256) |
| `indexes/dedupe/existing_hashes.txt` | dedupe hash gate |
| `indexes/dedupe/known_bad_hashes.txt` | 5,833 LOLDrivers hashes |
| `indexes/dedupe/dedupe_summary.txt` | Counts |
| `indexes/collections/` | Batch metadata, manifests, **download URLs** |
| `indexes/driverstore/` | DriverStore scan outputs |

## `tools/` - extraction and audit helpers

| Path | What it is |
|---|---|
| `tools/harvest.ps1` | Installer/tree -> `.sys` harvester + fingerprint writer |
| `tools/triage_scan.ps1` | PE import, device, SDDL, reach scanner |
| `tools/filter_new_drivers.ps1` | Mandatory dedupe gate |
| `tools/rebuild_manifest.ps1` | Rebuild `indexes/drivers_manifest.csv` from `drivers/` |
| `tools/innoextract/` | Inno Setup extractor |
| `tools/vm/never_sleep.bat` | VM power/sleep helper |

WiX `dark.exe` is not retained. Re-install WiX into `tools/wix/` only while unpacking a Burn/MSI
package, then delete it after the batch is accepted.
