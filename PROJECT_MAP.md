# Project Map

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

One clean tree. Every folder exists on clone; only instruction files and folder READMEs are
populated. Counts here are **zero by design** - the worked example (386 drivers, 257 reports) is
on [`example`](https://github.com/LongpanZhou/BYOVD-AI-Guide/tree/example).

| Path | What it is |
|---|---|
| `AGENTS.md` | AI operating instructions - the reading order |
| `PROJECT_GOAL.md` | goal, scope, severity |
| `WANTED_LEDGER.md` | accepted vulnerability classes |
| `README.md` | setup |
| `audits/` | `STATUS.md` template, `reports/`, `evidence/`, `scope/`, `projects/` |
| `drivers/` | flat corpus (empty at start) |
| `indexes/` | generated manifest, `dedupe/`, `collections/`, `driverstore/` |
| `poc/` | `dynamic/`, `reference/` |
| `tools/` | shipped scripts (four) + seed blocklist gate |
| `downloads/` | gitignored scratch |
| `guides/` | the five-step method |

Batch provenance goes in `indexes/collections/collected<N>/`; the flat corpus is indexed by
`indexes/drivers_manifest.csv`, which `tools/rebuild_manifest.ps1` regenerates from disk.
