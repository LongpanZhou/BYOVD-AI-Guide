# poc/ — test harness code (VM only)

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

Structure:

| Path | What it is |
|---|---|
| `dynamic/` | **the current harness** — controlled IOCTL self-test + per-driver run scripts |
| `dynamic/results/<date>/` | proof logs for each verified build |
| `historical/` | t4–t7 PoC sources (evidence only; old) |
| `reference/` | `dbk64.sys` — known-bad Cheat Engine driver, VM calibration only |

## Rules

- **VM only.** Never run a harness or driver on the host.
- PoCs are **not** audit reports — write-up belongs in [`../audits/reports/`](../audits/reports/).
- Nothing here is corpus. Don't move files into `drivers/`.
- VM credentials: local gitignored `VM_ACCESS.md` (not in this repo).
