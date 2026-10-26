# audits/

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

Find **kernel memory-write vulnerabilities** in Windows drivers.

## The rules (short)

- Only **memory writes** count. MSR/port/PCI/SMBus/EC/MMIO = `HW-ONLY`, except when they chain into a write.
- Local admin (`R2`) **counts**. Setup cost does **not** disqualify.
- Known-bad / blocklisted = `BLOCKED` — never re-audit, never load.

## Read first

- [../WANTED_LEDGER.md](../WANTED_LEDGER.md) — what counts as a find
- [../PROJECT_GOAL.md](../PROJECT_GOAL.md) — the one-sentence goal
- [scope/AUDIT_SCOPE.md](scope/AUDIT_SCOPE.md) — reach/setup/what counts
- [scope/SEVERITY.md](scope/SEVERITY.md) — MW1–MW4 scale
- [STATUS.md](STATUS.md) — **live queue, always current**

## Folder map

| Path | What it is |
|---|---|
| `STATUS.md` | single queue: verdicts + to-do |
| `scope/` | scope rules + severity scale + agent prompt |
| `reports/` | per-driver reports, flat |
| `evidence/` | harness logs + blocklist checks |
| `legacy/` | historical reports and VM batch 2 |
| `projects/` | Ghidra state (mostly local-only) |

PoCs live in [`../poc/`](../poc/), not here.

## Report notes

- Naming: `<driver>.md` / `<driver>.admin.static.md` = canonical. `.dynamic.md`, `.independent.static.md`, `_detailed`, `_rea` = variants; they must name the canonical file.
- Headers must list: **Reach**, **Setup**, **Write quality**, **Verdict** + code addresses.
- Old reports may say "NO-WRITE because admin-only" or use `WRITE-*` — those are outdated. Current policy: `R2` is in scope; hardware-only = `HW-ONLY`; old `_collected*` paths are aliases for `drivers/` (match by SHA in the manifest).
