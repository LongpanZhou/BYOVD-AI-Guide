# Audit: amd_xata.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\amd_xata.sys` |
| Recorded SHA-256 | `093c2b57afdc93e667a3ab1f74442dba42b0de2132388e73bdc3d09fdbb1b3d0` (matches triage_index.csv row "amd_xata") |
| Company/Version | Advanced Micro Devices — 1.2.001.0402 built by: WinDDK ("Stor Filter Driver") |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4, x86:LE:64) |
| Verdict | **NO-WRITE** (Coverage ≈ 60%) |

> Static-only. No driver load, no device open, no IOCTL execution. Read-only static analysis only.

---

## Entry surface

AMD storage **upper filter** ("Stor Filter Driver"): uses `IoCreateDevice` + `IoAttachDeviceToDeviceStack`/`IoDetachDevice` to sit above the disk/storage stack. Device objects are **unnamed** (no `\Device\`/`\DosDevices\` strings, no SDDL, no interface GUIDs) — not directly openable; it intercepts I/O addressed to the underlying disk stack.

## Memory-write analysis

- Dynamic-mapping/probing names present (all resolved via `MmGetSystemRoutineAddress`): `MmProbeAndLockPages`, `MmMapLockedPagesSpecifyCache`, `MmBuildMdlForNonPagedPool`, `IoAllocateMdl`/`IoFreeMdl`, `IoBuildDeviceIoControlRequest`, `IoBuildSynchronousFsdRequest`, `IoIs32bitProcess` (`0x1b82a–0x1bc52`) — the standard storage-filter transfer plumbing applied to **class-issued IRPs**; no caller-MDL stashing pattern found.
- Pass-through related config (`AmdXataAtaPassThruTimeOut`, `SpindelTrim*`, `0x15118–0x152c8`) is HKLM admin config; actual pass-through memory safety (probing/locking of user buffers) is owned by the Microsoft class drivers above it.
- No registry `ZwSetValueKey`-on-config surface exposed to user mode; WMI (WmiTraceMessage/EtwRegisterClassicProvider) = telemetry only.
- Absent: `ZwOpenSection`, `\Device\PhysicalMemory`, `MmCopyMemory`, MSR/segment-table code.
- Coverage note: dispatch switch not fully walked (dynamic-resolution thunking obscured call sites; bounded negative searches recorded above); all observed paths operate on kernel-issued I/O.

## Memory-touching IOCTL table

None exposed directly — intercepted pass-through requests are Microsoft-class-gated (admin) and their buffers are probed/locked by the class driver.

## Verdict + VM confirmation plan

**NO-WRITE.** Unnamed filter device, class-gated surfaces, transfer-plumbing-only mapping APIs. VM: not warranted.

*End of report.*
