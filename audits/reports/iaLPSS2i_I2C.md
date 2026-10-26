# Audit: iaLPSS2i_I2C.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaLPSS2i_I2C.sys` |
| Recorded SHA-256 | `3F1F9EC7571D0F82D3F5BBA298965491260708F05EBAAA2CC23483521A5FF079` (verified vs triage_index.csv, REA `open_binary` + local Get-FileHash) |
| Company/Version | Intel Corporation 30.100.1816.3 — "Intel(R) Serial IO I2C Driver v2"; PCI HWIDs `PCI\VEN_8086&DEV_0ABA` / `DEV_1ABA` |
| Method | Static-only. Full decompile of all 172 functions via **local Ghidra 12.1.4 headless** (REA shared bridge unusable this round: repeated binding theft by parallel agents A/B, fresh-import starvation; every identity cross-checked by SHA-256). String/import recon cross-checked against REA `open_binary` identity + local string dumps. |
| Verdict | **NO-WRITE** (permissive-DACL noted; no user-openable device object and no unbounded kernel write on any surface) |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (`.text` 0x140001000–0x14001DD15, `.rdata` 0x14001E000–0x14001F827, `.data` 0x140020000–0x140020547, `PAGE`, `INIT`, `.rsrc`, `.reloc`).

## Entry surface

- KMDF class-extension client minidriver (SpbCx): KMDF bootstrap → real DriverEntry; DeviceAdd = `FUN_140001000` (`EvtDeviceAdd`, ~309 lines):
  1. `SPB_CONTROLLER_CONFIG` (0x90) filled with the SpbCx callbacks, `SpbDeviceInitConfig` (WDF bind-table call at `DAT_1400202b0+0x1b8`);
  2. `WdfDeviceCreate` (table call at `+600`/`0x258`) creating the **unnamed** controller FDO;
  3. SpbCx bind-class DDIs (`DAT_1400204d8/4e8/4f0/4f8/500`: `SpbControllerCreate`, attribute/queue settings) and `WdfDeviceAssignS0IdleSettings` (`+0x170`);
  4. driver-context init chain (`FUN_1400136a4` ACPI HWID profile detect → `FUN_1400101b4` registry config loader → `FUN_140012504`/`FUN_14000fce0`).
- **SDDL is assigned** on the FDO (`Device ERROR: WdfDeviceInitAssignSDDLString()` log line; SDDL literal in `.rdata` at `0x14001E170`):
  ```
  D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GRGW;;;LS)(A;;GRGW;;;RC)
  ```
  → **Everyone (WD) = GENERIC_READ|GENERIC_WRITE.** Same boilerplate as the Gen1 family. However the FDO is **unnamed** (`WdfDeviceInitAssignName` never called — no `\Device\…` or name-format string beyond the trace label `%ws_%u` used for log context), and **no device interface is registered** (no `{…}` GUID string, no interface-registration log line). An unnamed device object with no interface cannot be opened by user mode, so the Everyone-ACE has no practical open path; worst-case-DACL convention would apply only if a named surface existed.
- SPB **targets** (child PDOs created by SpbCx from ACPI connection resources, e.g. touchpads) are opened only by kernel function drivers via connection IDs — no user-mode API opens SPB targets.
- **Imports (complete):** `EtwWrite/Unregister/Register/ActivityIdControl`, `MmUnmapIoSpace`, `MmMapIoSpaceEx`, `PoRegisterPowerSettingCallback`, `MmMapLockedPagesSpecifyCache`, `wcsnlen`, `wcsncmp`, `IoWMIRegistrationControl`, `RtlCopyUnicodeString`, `RtlCompareMemory`, `MmGetSystemRoutineAddress`, `PoUnregisterPowerSettingCallback`, `RtlInitUnicodeString`, `KeStallExecutionProcessor`, `WdfVersionBind/Unbind/BindClass/UnbindClass`.
- Absent: `Zw*`, `Se*`, `Ob*`, `IoCreateDevice*`, `MmProbeAndLockPages`, `MmBuildMdlForNonPagedPool`, `IoAllocateMdl`, DMA-enabler allocation DDIs, `ZwOpenSection`, `MmCopyMemory`, `Hal*`. (Contrast: the Gen1 I2C driver imports the full MDL kit; Gen2 delegates DMA to WDF/SpbCx.)

## Memory-write analysis

- **MMIO mapping:** `FUN_140005bd0` (EvtDevicePrepareHardware): `MmMapIoSpaceEx(*(pcVar8+4), *(pcVar8+0xc), 0x204)` — PA/length from the translated PnP resource list (1–2 MBARs expected, count-checked: "Incorrect resource count. MMIO:%1 (exp. 1 or 2) INT:%2 (exp. 1)"). ReleaseHardware (`FUN_140006430`) unmaps with the stored length. Not caller-influenced.
- **EvtSpbOther** = `FUN_1400056a0`: completes the SPB request immediately with `STATUS_NOT_SUPPORTED` (0xC00000BB) via `SpbRequestComplete` — **all "Other" IOCTLs rejected unconditionally** (the log lines "Unsupported Other RequestType/IoControlCode" belong to the family's shared traces; the Gen2 driver implements no Other transfer in-file).
- **EvtIoDeviceControl** = `FUN_140005920`: `WdfRequestGetParameters` (`+0x850`, 0x28-byte struct) for logging, then `WdfRequestComplete(request, STATUS_NOT_SUPPORTED)` — **all direct controller-device IOCTLs rejected**.
- **EvtSpbIoSequence** = `FUN_140006a90` ("OnSequence"): request/target context links; `SpbRequestGetTransferFormatParameters`-style DDI fills a 0x20-byte struct; **per-entry length validation `FUN_140008eb0`** — iterates the transfer count and enforces `length ≤ 0x10000` (rejects `0xC000000D` otherwise: "invalid transfer length %4 (size), supported max is 64KB"); then `FUN_140007fb8` (direction/alignment config — alignment rejects 8/16/32 per log), `WdfRequestMarkCancelable` (cancel cb `FUN_1400026c0`), transfer start `FUN_140008c30`. **No inline copy of request data occurs in-file** — buffer access goes through the WDF DMA MDL chain.
- **DMA data movers:** RX filler `FUN_14000c33c` writes FIFO bytes into the **WdfDmaTransaction MDL chain** (`*(param_2+0x58)` linked MDLs, each entry length-checked `uVar6 < *(uint*)(puVar5+5)` before the store; global bound `uVar9 < *(param_2+0x30)`). `MmMapLockedPagesSpecifyCache(mdl, KernelMode, …, 0x40000010)` maps only **already-locked** DMA-chain MDLs into kernel VA (or reuses the cached VA in the descriptor when flag `&5` set). `FUN_140016fb0` maps the same chain (or reuses VA) strictly to **read** the first/last byte for command construction. No caller-MDL→kernel-VA write mapping, no probe-less path (nothing in-file builds an MDL over unprobed user memory).
- **Registry config:** `FUN_1400101b4` reads named DWORD values (`DmaInit`, `DynamicClockGating`, `StandardSpeed_*/FastSpeed*/HighSpeed_* SCL/SDA counters`, `MonitorOn/OffIdleTimeout`) through a helper (`FUN_140010cb8(ctx, name, &ctx+fixed_off, default)`) that stores each value at a **fixed context offset with a default fallback** — fixed 4-byte stores, no length-driven copies. Values later feed hardware timing registers and idle-timeout settings. Admin-writable registry only.
- **Privileged instructions:** byte-scan — `0F 30` (WRMSR) 0 hits; `0F 20/22` (MOV CR) 0 hits; every `0F 01` byte-pair sits in `.rsrc`/`.pdata` (WEVT_TEMPLATE), none executed. No GDT/IDT/MSR touch.

## Memory-touching IOCTL table

| Surface | Path | Result |
|---|---|---|
| Any direct IOCTL to controller FDO | `FUN_140005920` | rejected `STATUS_NOT_SUPPORTED` |
| Any "Other" SPB IOCTL | `FUN_1400056a0` | rejected `STATUS_NOT_SUPPORTED` |
| `EvtSpbIoRead/Write/Sequence` (SpbCx targets, kernel clients) | `FUN_1400083ec`/sibling, `FUN_140006a90` | SpbCx-validated lists; ≤64 KB/entry; MDL-chain-bounded movers; no in-file copies |

## Verdict + VM confirmation plan

**NO-WRITE.** SpbCx controller minidriver: unnamed FDO with no device interface (the Everyone GR+GW ACE is unreachable boilerplate), all custom/direct IOCTLs rejected, transfer requests parsed from SpbCx-validated descriptors with explicit ≤64 KB/entry and alignment checks, DMA through WDF-locked MDL chains mapped KernelMode for reads/bounded fills, registry values stored into fixed context offsets. No unprivileged kernel memory-write primitive exists in-file.

VM plan (orchestrator-owned, describe-only): none warranted. The controller binds only to real LPSS PCI hardware (VEN_8086/DEV_0ABA, 1ABA); without the device, SpbCx never creates the FDO/targets. If hardware is ever present, the described reachability check (open attempt on the unnamed controller + target PDO enumeration from a restricted token) is the non-destructive phase-A test; no corruption test is justified by the static evidence.

*End of report.*
