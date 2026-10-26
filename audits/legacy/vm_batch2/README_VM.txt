Batch 2 — historical fuzz campaign (2026-10-24)
==============================================

> Historical batch notes. Current severity scale: `..\audits\SEVERITY.md`.
> Current status/queue: `..\audits\_admin_scope_backlog.md`.

Targets and guest execution order (one session each, snapshot restore before every session):
  1. t8_amdpsp   amdpsp.sys                  - load attempt, device/ACL discovery, structured sweeps
  2. t10_iastorv iaStorV.sys                 - load attempt, device discovery, MinorFunction gate
  3. t9_vbox     VBoxNetAdp6.sys + VBoxNetLwf.sys (+ VBoxSup.sys invariant check)

The staged copies of the five driver binaries were deleted on 2026-10-24; the canonical copies
remain in the root corpus (`amdpsp.sys`, `iaStorV.sys`, `VBoxNetAdp6.sys`, `VBoxNetLwf.sys`,
`VBoxSup.sys`). The Ghidra projects, runbooks, scripts, and evidence are retained here.

VM access (canonical guest):
  VMX:       C:\Users\27175\Downloads\Vmware\Windows 10 x64.vmx
  vmrun:     C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe
  Snapshot:  pre-driver-tests  (restore BEFORE every session)
  Guest user: vmdebug
  Guest pass: 123456   (full admin token, auto-elevated)
  cmd.exe is broken in-guest -> use powershell.exe -NoProfile -ExecutionPolicy Bypass -File <script>

Reports:    ..\audits\<driver>.dynamic.md
Evidence:   ..\audits\dynamic_evidence\t8_* / t10_* / t9_*

Rules:
- Orchestrator only: VM power ops + snapshot restores + `_ledger.md` consolidation.
- Agents never power off/reset/snapshot the VM.
- Phase-B escalations are STAGED ONLY; orchestrator-gated, never paired, never on the host.
- amdpsp.sys is a LIVE boot-start driver on the host: host stays read-only for it.

STATUS (2026-10-24): campaign complete. Canonical MW verdicts:
  t8 amdpsp   -> MW2 (hardware-gated; surface structurally absent in guest)
  t10 iaStorV -> MW2 (conditional; deliverability hardware-gated)
  t9 VBox pair-> NO-MEMORY-WRITE (shipped invariant holds in VMMR0.r0; Lwf also binding-gated)
  VBoxSup     -> NO-MEMORY-WRITE

End state: VM reverted to pre-driver-tests, powered off, 1 snapshot.
