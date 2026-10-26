# Collections — batch metadata and download history

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

This is where the **download URLs and per-agent manifests** live. The drivers themselves are flat
in `../../drivers/`.

| Path | What it is |
|---|---|
| `original/` | Original 94-driver triage metadata |
| `collected1/` | S1–S6 manifests, summaries, `urls.txt`, triage |
| `collected2/` | `master_drivers.csv`, `_index.jsonl`, `discovered.csv` |
| `collected3/` | `master_drivers.csv`, `_index.jsonl` |
| `collected5/` | R1–R4 manifests, summaries, `urls.txt`, `COLLECTION_REQUIREMENTS.md` |

When adding `collected6`, create `collected6/<agent>/` here and record every official URL. Do not
recreate batch folders at the project root.

Look up a driver's batch in `../drivers_manifest.csv`.
