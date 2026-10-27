# WANTED ledger - the vulnerabilities this hunt is after

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

> This file is the lab's *wishlist*. Every candidate collected or audited is judged against it.
> Beginners: edit this file to change what your own hunt targets - the rest of the loop
> (collect -> blocklist-check -> audit -> verify) stays the same.

## Wanted (this hunt's focus)

**Kernel memory write (`mem W`)** - a driver in the corpus that, after reaching a caller-controlled
code path, causes (or lets a user-mode attacker produce) a write:

- **destination reachable from user input** (kernel VA, MDL, buffer+offset, pool chunk), and
- **attacker-controlled or attacker-influenced content**, and
- **reachable from a role the driver itself grants** (device open, at least admin-plausible `R2`).

Preferred shape (the MW1 slot):

| Slot | Criteria |
|---|---|
| **MW1 (best)** | Arbitrary kernel VA **destination** + attacker-controlled bytes + admin-reachable load path. No hardware dependency. Driver signed and actually loadable on a default policy machine. |
| MW2 (accepted) | Any kernel-memory write slightly short of MW1 (e.g. arbitrary destination but attacker influences content only indirectly, like a PA copy; or attacker-controlled length only) |
| MW3 / MW4 | Constrained writes: fixed target, limited offset, dependent on composition or hardware, self-chosen content only |
| **Dyn-verified** | Value assigned by running the write in the disposable VM against **our own allocated PFNs**, never a live system address |

## Not wanted (recorded, but do not chase)

| Class | Why it's not this hunt |
|---|---|
| `HW-ONLY` - MSR / port / PCI config / SMBus / EC / MMIO writes | Not kernel memory policy; record them, but they don't score unless they chain into `mem W` |
| Read-only primitives (leaks) alone | Useful support for a write chain, not a write themselves |
| Hardware- or composition-dependent write paths with no user-path entry | Clustered around specific devices; record them in the report, keep them out of the sweep |
| Logic bugs not leading to kernel memory writes (crash-only, EoP-in-user, etc.) | Different hunt |

## How to re-target this ledger (beginners)

When you copy the repo for your own hunt, edit this file only:

1. Change the "Wanted" block to name your class (chunk-overflow write / UAF write / `exec` primitive
   / registry corruption / etc.).
2. Adjust or drop the MW1-MW4 ranking rows you don't care about - but keep one shared vocabulary so
   reports and `STATUS.md` still make sense next to `audits/scope/SEVERITY.md`.
3. Update `PROJECT_GOAL.md` with one sentence so the canonical goal and this ledger never disagree.
4. Update `audits/STATUS.md`'s header line ("Scope: ...") to quote your new target class.

## Current state

- Request: arbitrary **kernel memory write** (mem W), MW1 preferred.
- Live queue: [audits/STATUS.md](audits/STATUS.md) - yours, starts empty
- Evidence: [audits/evidence/](audits/evidence/) and [poc/dynamic/](poc/dynamic/)
- Worked example: the [`example`](https://github.com/LongpanZhou/BYOVD-AI-Guide/tree/example) branch
  shows this ledger applied to a completed run (verified finds kept offline).
