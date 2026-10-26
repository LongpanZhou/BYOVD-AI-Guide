# Audit: amdgpio3.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\amdgpio3.sys` |
| Recorded SHA-256 | `E207002D13CD93817BC976C9A54190152E017A716DC08554A8A69D29947FF9A1` (verified against triage_index.csv; recon.py hash re-verified) |
| Company/Version | Advanced Micro Devices, Inc. 2.0.1.0000 (AMD GPIO Driver) |
| Method | Static-only audit via LOCAL Ghidra 12.1.4 headless + host PE/string recon; REA shared bridge contended (Agent D-validated fallback). No device opened, no IOCTL executed. |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000`.

## Entry surface

KMDF GpioClx **client** driver (GPIOClx/KmdfLibrary bind strings; registration struct memset `0x58`, version 8 → GpioClx2). Client creates **no** named device, interface, or SDDL of its own — no `\Device\`/`\DosDevices\`/GUID/SDDL string exists in the binary (25 UTF-16 strings checked). FDO is GpioClx-owned, unnamed, interface-less; GPIOCTL dispatch belongs to GpioClx (admin-gated). No user-openable surface attributable to this file.

## Memory-write analysis

- **Single `MmMapIoSpace`** (`FUN_1400012a0`, call @ `0x1400012xx`): source = PnP **translated** `CmResourceTypeMemory` descriptor via WDF runtime table (`DAT_140003a88`), resource length gate `≥ 0x20`, fixed map length `0x20`, `MmUnmapIoSpace` teardown in `FUN_1400016bc`. Not attacker-influenced.
- All register writes (`FUN_140001480` mask/unmask/reconfigure family: `*(bankBase + 0x18) &= ~(1 << pin)` etc.) target the **mapped controller BAR** with GpioClx-validated BankID/PinNumber — hardware effect, not kernel-memory writes.
- `memset`/fill sites fixed-size (`0x58`, `0x20`, `200`) on driver-owned buffers; no length-carrying fills.
- No `MmProbeAndLockPages`, `MmMapLockedPages*`, `IoAllocateMdl`, `ProbeFor*`, `ZwOpenSection`, `MmCopyMemory`, no `Se*` imports; import surface is only `MmMapIoSpace/MmUnmapIoSpace/RtlCopyUnicodeString` + WDF bind.
- Privileged-instruction byte scan: hits (`0x1298`, `0x2656`, `0x5b24`…) all in `.rdata`/`.rsrc` data (import names / cert blob) — **none in code sections** (byte-verified against the section table).

## Memory-touching IOCTL table

none (client registers no dispatch of its own; GpioClx owns the queue).

## Verdict + VM confirmation plan

**NO-WRITE.** Leaner sibling of amdgpio2: GpioClx client, unnamed interface-less FDO, one PnP-BAR mapping, fixed-size fills, no user-openable control surface in-file (worst-case-DACL convention moot — no own device object).

VM plan (orchestrator-owned, describe-only): none warranted. If ever dynamic: confirm only with matching ACPI HWID present, no named `\Device\` object, no GPIOCTL interface registered for this controller.

*End of report.*
