# Audit Status and Queue

**Last updated:** `<yyyy-mm-dd>`
**Scope:** kernel memory-write only; `R2` local administrator is in scope; setup is a severity
field, not a disqualifier; hardware-only writes are `HW-ONLY`.

**This is the single live status source.** Do not copy the queue into other docs.

## Corpus

| Bucket | Count |
|---|---:|
| Original host corpus | 0 |
| `collected1` | 0 |
| **Total** | **0** |

## Current results

| Driver | Verdict | Reach / setup | Report |
|---|---|---|---|
| _(none yet)_ | | | |

## In flight

None.

## Rules

- Only kernel memory writes count; MSR/port/PCI/SMBus/EC/MMIO are `HW-ONLY`.
- `R2` admin paths are in scope.
- One canonical report per driver; update this file after writing the report.
- `BLOCKED` = known-bad/blocklisted, unsigned under HVCI, or unobtainable.
