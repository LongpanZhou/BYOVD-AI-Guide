# Audit: cht4sx64.sys (triage name `cht4iscsi`)

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\cht4sx64.sys` |
| Recorded SHA-256 | `5A7FD2D58C433B9B498A1B37A2F2D877061215360D8E6A752601F2ED4F283A8F` (matches triage_index.csv row 27; verified before opening; REA reports the same digest) |
| Company/Version | Chelsio Communications, 6.11.4.100 (triage row). Image is an iSCSI-offload **StorPort miniport** (`QueueScsiSrb`, `iscsi_scsi_command_alloc` trace tags, `StorPortExtendedFunction` / `StorPortNotification`) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, short-form (no user-openable device) |
| Verdict | **NO-WRITE (coverage-limited, ~45%)** — no caller-controlled kernel write found; the one MDL-building path takes lengths from the storage stack |
| Coverage | Import and route recon; SRB dispatch `FUN_14000E8AC`; MDL path `FUN_140013B8C`; request allocator `FUN_14001FBE8`; both dynamic lookups. Not traced: `FUN_14001AA98` (MDL container allocation), `FUN_14000F390`, `FUN_140014004`, `FUN_1400140E4`, `FUN_1400196CC`, offload/DMA hardware side |

> **Static-only.** No load, no device open, no SRB issued. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- No device object: no `IoCreateDevice`, `IoCreateDeviceSecure`, or `IoCreateSymbolicLink` in the import table, no WDF. A user can reach the SRB path only through the disk/SCSI stack (`\\.\PhysicalDriveN` or SCSI pass-through). That needs admin-level access to the disk device, and the disk ACL was not traced in-file.
- No SDDL, no `ProbeFor*`, no `MmProbeAndLockPages`, no `MmMapIoSpace*`, no `MmMapLockedPagesSpecifyCache` in the import table. Imports of note: `MmBuildMdlForNonPagedPool` (2 xrefs; one in `FUN_140013B8C`), `MmGetSystemRoutineAddress` (3 xrefs; 2 in procedures, 1 data slot).
- Dynamic resolution: `FUN_140033880` resolves `KeGetProcessorNumberFromIndex`; `FUN_140058104` resolves `RtlQueryModuleInformation`. No mapping or probe routine is resolved. No `MmMap*` or `Probe` string in the defined-string inventory.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Write through caller-controlled kernel address | None found | `FUN_14000E8AC` |
| MDL built on the SRB path | `FUN_140013B8C` builds an MDL in the request descriptor. PFN count comes from the 32-bit value at `+0x40 → +0x10` (presumed the SRB data length; the pointer's target was not confirmed). `Size` is stored as a 16-bit field. Taken when the length exceeds `DAT_140048514` (or 0x1FF when flag `+0x171D0` is set) or when a flag bit is set. The PFN container is not sized here; its allocation (`FUN_14001AA98`) was not traced. Lengths come from storport. The miniport's reported maximum was not verified | `ev_bba0cb99…` (`FUN_140013B8C`), `ev_2953bafc…` (`FUN_14000E8AC`), `ev_179656d8…` (`FUN_14001FBE8`) |
| SGL copy into request buffer | Fixed 0x200 bytes (4 × 0x80) when the length is 0x200 | `ev_2953bafc…` |
| Dynamic routine resolution | Two benign names; no mapping or probe API | `ev_fbec465d…` (`FUN_140033880`), `ev_4c4ee7a0…` (`FUN_140058104`), `ev_482da45c…` / `ev_b0ddd277…` (name strings) |

## Verdict rationale

NO-WRITE. The image has no user-openable surface and no probe or mapping APIs. Its only memory-relevant path (MDL build) takes SRB lengths from the storage stack. An overflow would need an SRB longer than the container was sized for, and that would require a length the storport layer does not issue (not verified).

Escalate to **WRITE-MEDIUM** if `FUN_14001AA98` sizes the PFN container below the threshold-derived page count and a non-admin can issue SRBs. Drop or confirm based on the disk-device ACL.

## Open items

- MDL container sizing (`FUN_14001AA98`) against `DAT_140048514` / 0x1FF.
- Miniport-reported `MaximumTransferLength` (HW initialisation, not traced).
- Offload/DMA trust boundary: PDU lengths and completion indices written by hardware. Not reachable by static analysis.
- Disk-device ACL / SCSI pass-through gate (admin-only assumption, not verified in-file).

## VM confirmation plan

Not required for a user-surface test (no user device). Hardware-gated (Chelsio T4 adapter). If the adapter is available in the VM, confirm whether a non-admin can open the disk device (`\\.\PhysicalDriveN`).

## Evidence (REA, retained IDs)

`ev_bba0cb99622b402a2ec3c29606a6dd35ae38e5b7b5a1810641fcaac1fe08b6aa` (`FUN_140013B8C`), `ev_2953bafcb00f605af4987bf9eb6c17360b4474d86cc196a85335a995efca28da` (`FUN_14000E8AC`), `ev_179656d813b28d00285e6ebabc4be7be4395ab4aa48d79f301dd759bef6b5f24` (`FUN_14001FBE8`), `ev_fbec465df642e79f6f88b34bd6b36a6be225831a3430d9cae0e652eb3d7ac501` (`FUN_140033880`), `ev_4c4ee7a0940ed2615923904adaa4d5deed455539a7d9bdd5c9b3fc4aa3d509c9` (`FUN_140058104`), `ev_482da45cabea7691eb5383d8443891667df3d445d9587bc96a80b2ef7cc33ff8` (name string `RtlQueryModuleInformation`), `ev_b0ddd2779b1cbd2740ee5662168caa558237291e0ce0625da8f216928d6aa707` (UNICODE_STRING header), `ev_f9c43e06e44cceb2b66f829165e0e9385d840969ee0475108ea009ce14a441b5` (`Wdf` sweep, empty), `ev_b680c8b1a0f37c8c44661176c7582499cc849f45622967e8055b883a7b27173b` (`Probe` strings, empty), `ev_3f226019c76979a5157bbab39604a8b6f7f5895b4709255f08e077da8fdb9d33` (`MmMap` strings, empty), `ev_559fd09d4e2f3cfcd9edf372ab7ee9d83511e8ce4482d1e47c6f40b2bdabf3f0` (callers of `FUN_140013B8C`).
