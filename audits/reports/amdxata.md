# Audit: amdxata.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\amdxata.sys` |
| Recorded SHA-256 | `1FC1D4287DB56A387BDF917C0CB3BFC30CA5D792A350E2EDBBDDEBF8127E1AF9` (verified vs triage_index.csv + local Get-FileHash) |
| Company/Version | Advanced Micro Devices — 1.1.3.277 (NT.150223-1854) "Storage Filter Driver" (in-box; signed CN=Microsoft Windows). Distinct binary from amd_xata.sys (1.2.001.0402, audited separately) |
| Method | Static-only via LOCAL Ghidra 12.1.4 headless (javac-compiled GhidraScript). REA bridge contended → per-protocol fallback; full import/string/priv sweep, 42 functions, 22 decompiled (all non-forwarding dispatches + init chain) |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs (image base `0x1c0000000`).

## Entry surface

Storage **upper filter** over the disk/storage stack (~42 functions). `DriverEntry` (`FUN_1c0008000`) fills 28 MajorFunction slots with the generic pass-through forwarder `FUN_1c00010b0` (acquire remove-lock → `IofCallDriver(lower)` → release) plus specific PnP/power handlers (`FUN_1c00013b0`, `FUN_1c00070f0`, `FUN_1c0001590`/`FUN_1c0001540`); `AddDevice = FUN_1c00063e0`.
`AddDevice`: `IoCreateDevice(DriverObject, 200, NULL /*UNNAMED*/, <deviceType of lower>, FILE_DEVICE_SECURE_OPEN, FALSE, &dev)` → `IoAttachDeviceToDeviceStack`. **No `\Device\` name, no `\DosDevices\` symlink, no device interface, no SDDL** (string inventory has none) — the filter device is **not directly openable**; opens target the underlying disk stack (classpnp DACLs).

## Memory-write analysis

- All request majors are pure forwarding — the filter never inspects, allocates, or mutates caller buffers on the pass-through path (`FUN_1c00010b0` body: remove-lock + `IofCallDriver` only).
- `IoBuildDeviceIoControlRequest`/`IoBuildSynchronousFsdRequest` (`FUN_1c0007188`) are **driver-issued internal requests** (spindle/power control down to the lower stack), kernel-allocated buffers, user-mode unreachable.
- Dynamic resolution (`MmGetSystemRoutineAddress` at `FUN_1c0006000`/`FUN_1c0008000`) resolves **only** `PsGetVersion`, `WmiTraceMessage`, `WmiQueryTraceInformation`, `EtwRegisterClassicProvider`, `EtwUnregister`, `RtlQueryRegistryValuesEx` — **no Mm-map/probe or memory-copy routines**.
- Registry plane: `RtlQueryRegistryValuesEx("amdxata\Parameters")` (HKLM admin config: `AmdXataOptions`, `Spindel{Power,Fua,Control}Flags`) + `ZwSetValueKey` writing 8 bytes from its own extension (`+0x144`) into the device registry key (`FUN_1c0006d90`); `ZwQueryValueKey` helper is fixed-RPC-buffered. No user-controlled pointers/lengths.
- WMI: `IoWMIRegistrationControl(...,0x80010001)` registration is for telemetry routing (WmiTraceMessage classic provider) — no data plane.
- **Absent primitives:** zero `Mm*`/`Se*` imports; no `ZwOpenSection`/`\Device\PhysicalMemory`/`MmCopyMemory`; no METHOD_NEITHER handling of its own (control requests forwarded untouched); instruction sweep = **no privileged instructions** (`priv_ins.txt` = "none"); no MSR/GDT/IDT/CR writes.

## Memory-touching IOCTL table

None of its own — MJ_DEVICE_CONTROL (and every other major) is forwarded to the attached stack unmodified; intercepted pass-through surfaces are classpnp-gated (admin for write access) with buffers probed/locked by the storage stack.

## Verdict + VM confirmation plan

**NO-WRITE.** Unnamed, interface-less filter; forwarding-only dispatch; dynamic imports resolve telemetry/DDI names only; registry writes confined to its own extension and HKLM keys. No unprivileged kernel memory-write primitive.

VM plan (describe only; not warranted): confirm the filter device object is unnamed and not openable (`!object` enum + restricted-token open attempt), verify forwarded control plane behavior — no corruption test indicated.

*End of report.*
