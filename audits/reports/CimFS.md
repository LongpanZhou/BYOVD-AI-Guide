# Audit: CimFS.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\CimFS.sys` |
| Recorded SHA-256 | `C3A00CC5774051580015113483BFD516E1F11C720530842DBAFE8B6900746BDE` (verified against triage_index.csv) |
| Company/Version | Microsoft Windows (CN=Microsoft Windows signer; onecore\base\fs\cimfs container image filesystem) |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4 headless + byte-level PE parsing; REA shared bridge contended by parallel agents) |
| Verdict | **NO-WRITE** (control device explicitly admin-gated by SDDL; section mappings are driver-initiated file objects) |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x1C0000000` (document `target-c3a00cc57740.sys`).

## Entry surface

- Full filesystem driver: `IoCreateDevice` + `IoRegisterFileSystem` (sites `0x1C0004468` family, `0x1C0019460`, `0x1C0019EC8`).
- Control device names: `\Device\cimfs` / `\Device\cimfs\control` with link `\DosDevices\CimfsControl` (`STR 1C0011360`–`1C00113B0`).
- **DACL:** the binary contains exactly one SDDL constant — file RVA `0x10E30` = **`"D:P(A;;GA;;;SY)(A;;GA;;;BA)"`** (SYSTEM + Administrators, protected DACL) — applied through the wdmsec-style wrapper (`FUN_1C0019460`: SDDL→SD conversion then post-creation application to the device object). Unprivileged `CreateFile` on `\\.\CimfsControl` is denied by the object manager before any dispatch.
- Mount path (`Cimfs::Mount` `FUN_1C0004468`): the driver itself opens the `.cim` image/region files with `IoCreateFile(desiredAccess 0x120089)` under the kernel token (`Cimfs::OpenRegions`) and maps them with `MmMapViewInSystemSpaceEx` — the caller only names the file; the mapping targets disk files, not attacker memory.

## Memory-write analysis

- **Probe/lock:** `MmProbeAndLockPages` (site `FUN_1C00071DC`) is used on IRP MDLs in the cached-read path (kernel→user read-back through mapped region views); the MDLs originate from the I/O manager (direct IO) — locked before dispatch.
- **Section mapping:** `MmMapViewInSystemSpaceEx` targets driver-opened file objects only (no caller handle ingestion path found in the mount/unmount routes).
- `MmHighestUserAddress` referenced (user VA sanity checks in mapping code — library-style guards).
- Mount-time header validation (`"Mount failed, invalid fs headers"` path, status `0xC0000032`): structural validation with bounded parser shapes; no fixed-destination/user-length mismatch found.
- **Not found:** no `MmMapIoSpace`/`MmGetPhysicalAddress`/`ZwOpenSection` user-addressable mapping paths, no METHOD_NEITHER dispatch of its own, no MSR/GDT/IDT patterns, no user-length-driven fills.

## Memory-touching IOCTL table

All control traffic is FS-system-mediated (mount/unmount via `\\.\CimfsControl`, admin-gated); no per-code in-file copy table. `IOCTL_DISK_GET_DRIVE_GEOMETRY(_EX)` strings are only debug-trace labels in `CIMFS_MOUNT/UNLOAD` traces (`0x1C000236B` region).

## Verdict + VM confirmation plan

**NO-WRITE.** No unprivileged-reachable kernel memory-write primitive: the control surface is admin-gated by its own SDDL, mapped memory is file-backed via driver-initiated opens, and locked pages come from I/O-manager MDLs.

VM plan (orchestrator-owned, non-destructive): open `\\.\CimfsControl` under a restricted token to record ACCESS_DENIED; (separately, out of round-2 scope) an admin-token mount of an unowned file path could be checked for the read-plane access-bypass question.

*End of report.*
