# Audit: ADP80XX.SYS

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\ADP80XX.SYS` |
| Recorded SHA-256 | `B83072D77685F973701EC6629D8AC2626FDEFD657A4DB9AA7D532960A29FC67C` (matches triage_index.csv; open_binary digest verified `b83072d77685...`) |
| Company/Version | PMC-Sierra 1.3.0.10769 (NT.150223-1854) - 80xx-series SAS RAID storport miniport |
| Method | Static-only audit via REA/Ghidra - **BLOCKED** |
| Verdict | **NO-WRITE (provisional, REA-blocked)** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. **No decompilation was obtained.**

## Entry surface

- Not analyzed: REA bridge contention. The shared Ghidra bridge serves one active Program; parallel agents (A on hcmon/vmci, B on rtwlanu) switched the active target faster than this target's ~5 MB/12k-procedure import+analysis could complete. Multiple `open_binary` binds returned the correct SHA-256 (`target-b83072d77685.sys`), but `binary_overview` consistently served unrelated documents (rtwlanu `d6bd2d1a...`, vmci `023efb61...`, hcmon `94938835...`), and an explicit `document` reference was rejected as "Unknown Ghidra Program identity" (import never completed).
- Attempts: >3 open/overview cycles plus one 75 s paced window. Deferred per loop-breaker rules.

## Memory-write analysis

**BLOCKED: REA bridge contention (target import never completed; analysis data is from other agents' targets, discarded as untrusted).**

Prior-kernel expectations (not evidence): ADP80XX is a StorPort miniport; storport miniports typically create no control device and their SRB plane is admin-gated. A storage-class finding would be an outlier - but this is NOT verified here.

## Memory-touching IOCTL table

Not produced (blocked). No target-owned evidence was collected; anything observed during the blocked attempts belonged to other agents' targets and was discarded.

## Verdict + VM confirmation plan

**NO-WRITE (provisional, REA-blocked - re-audit required).** No target-verified evidence. Re-attempt at end of pass when the bridge is quiet; expected short-form result (no user-openable device) unless recon shows a control device.

VM plan: none until the static audit completes.

*End of report - BLOCKED stub.*
