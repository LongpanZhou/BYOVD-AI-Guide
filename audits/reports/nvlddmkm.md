# Audit: nvlddmkm.sys

> **0%-coverage baseline.** Current-scope coverage is in `nvlddmkm.focused.md` plus
> `nvlddmkm.ioctl.appendix.md`. This file is retained as the historical baseline, not as the
> current verdict.

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\nvlddmkm.sys` |
| Recorded SHA-256 | `71C743AF98CBB9F7924C7366062CBC65D938CDD5007D7FF22225498CF94E2E5C` (matches triage_index.csv row 65; verified before opening; REA open reports the same digest) |
| Company/Version | NVIDIA Corporation, 32.0.15.6094 (triage row). WDDM display miniport. Triage state: **Running** on this host (analysis only; not loaded) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, **deep-form** (the DxgkDdi escape and render callbacks are the user-reachable surface; not reached) |
| Verdict | **None issued. Blocked before analysis.** This is not a NO-WRITE: no sink was found or cleared |
| Coverage | 0%. No procedures, xrefs, or pseudocode were recovered. Nothing in the binary was reviewed |

> **Static-only.** No load, no device open, no escape call, no IOCTL, no packet. Nothing was run on the host.

## Blocker

Ghidra auto-analysis of this 71.8 MB binary did not finish within the 330,000 ms startup deadline (`REA_GHIDRA_STARTUP_TIMEOUT_MS`). Three attempts failed the same way. The open succeeded each time with a matching digest. The first analysis query then timed out. Failed-run IDs (from the error diagnostics): `e150ecae-f333-42c5-bdf6-7d91c8045c77`, `29606fea-ec24-4792-8210-78d9e440eaa3`, `45af5012-3e40-46fb-aac0-2c5b0698ff12`.

The fix belongs to the REA host environment, which was not changed here: raise `REA_GHIDRA_STARTUP_TIMEOUT_MS` above 330000, or set `REA_GHIDRA_DISABLED_ANALYZERS` to skip the expensive analyzers, then re-open.

## Entry surface (planned, not reviewed)

- `DxgkInitialize` call site, its DRIVER_INITIALIZATION_DATA, and the DxgkDdiEscape and render callbacks (reachable from user mode through D3DKMT escape and render).
- Any `IoCreateDevice` or `\Device\` object and its dispatch routine.

## Memory-write analysis (reviewed scope)

Nothing reviewed. The in-scope sinks (user-controlled copy and map lengths or addresses in escape and render handlers, MDL and mapping misuse, pool overflow) were not examined.

## Verdict rationale

No verdict. A verdict needs the escape and render paths reviewed, and those were not reached.

## Open items / next steps

1. Re-run with a higher startup deadline, or with expensive analyzers disabled.
2. Run the standard sweeps (`Mm`, `Io`, `Wdf`, `Probe`, `copy`, `mem`, `(A;`, `\Device\`), then `DxgkInitialize` xrefs.
3. Review DxgkDdiEscape and DxgkDdiRender for copies and maps whose lengths or addresses come from user buffers.

## VM confirmation plan (orchestrator-owned; VM only)

Not started. Any test belongs in a VM, decided by the orchestrator.

## Evidence

No evidence IDs exist for failed calls. The only retained item is the open result (digest `71c743af98cbb9f7924c7366062cbc65d938cdd5007d7ff22225498cf94e2e5c`) and the three failed-run IDs listed under Blocker.
