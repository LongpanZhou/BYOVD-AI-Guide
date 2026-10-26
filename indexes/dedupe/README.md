# Dedupe gate

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

| File | What it is |
|---|---|
| `existing_hashes.txt` | known hashes (local-only `exported_hashes_local.txt` also consulted by the gate) |
| `known_bad_hashes.txt` | 5,833 LOLDrivers/known-bad hashes |
| `dedupe_summary.txt` | Counts and overlap |
| `existing_drivers.csv` | Hash → source path (historical; paths may predate the flat `drivers/` layout) |

The mandatory filter is [`../../tools/filter_new_drivers.ps1`](../../tools/filter_new_drivers.ps1).
Pass `-UpdateExisting` so accepting a batch appends its NEW hashes to `existing_hashes.txt` and
regenerates `dedupe_summary.txt` atomically.

After a batch, update every count copy:

- `PROJECT_GOAL.md`
- `START_HERE.md`
- `README.md`
- `audits/STATUS.md`
- `drivers/README.md`
- `DRIVER_COLLECTION_PLAYBOOK.md` (§2.1 and §8)
- `indexes/README.md`
- `indexes/drivers_manifest.csv` (via `tools/rebuild_manifest.ps1`)

Prefer generating these from `indexes/drivers_manifest.csv` instead of hand-editing.
