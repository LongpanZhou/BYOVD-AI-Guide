# DisplayLink dlcdcncm660 - static audit

Scope: `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected3\drivers\DisplayLink\` (KMDF load, NDIS 6.60 miniport, DisplayLink Corp., version 3.83.0.0). Static only: no load, install, or execution. Corpus hashes were recorded before and after analysis and did not change.

Tooling: Ghidra 12.1.4 headless, `DumpAllDecomp.java`, dumps at `C:\Users\<scrubbed>\AppData\Local\Temp\claude\C--Users-<scrubbed>\f675ee28-909f-4610-bb22-f57f1b1e06ab\scratchpad\c3\dlcdcncm660\dump_x64.txt` (524 functions) and `dump_arm64.txt` (339 functions). Neither dump has a timeout or decompile failure. Import tables were parsed directly from the PE files.

## 1. Verdict

**dlcdcncm660_F7F3367C.sys (newest, audited in depth)**
- SHA256 prefix `f7f3367c`, machine AMD64 (0x8664), PE TimeDateStamp 1728287317 (2024-10-07 07:48:37 UTC).
- Verdict: **NO-WRITE**. Disqualified by the NO-SETUP rule. Setup required: **hardware** (plus an INF devnode). The device exists only when DisplayLink USB hardware is attached. The callback audit was not performed.

**dlcdcncm660_0FFDDEF9.sys (older build, 4 s earlier TimeDateStamp, ARM64; diffed only)**
- SHA256 prefix `0ffddef9`, machine ARM64 (0xAA64), PE TimeDateStamp 1728287313 (2024-10-07 07:48:33 UTC).
- Verdict: not audited in depth. Same device family and setup cost (hardware). Diffed against the x64 build.

Diff of 0FFDDEF9 (ARM64) against F7F3367C (x64), as one paragraph: both binaries share the same NDIS 6.60 miniport design, the same characteristics header (size 0x98, NDIS 6.60, driver 3.83), and the same WDFLDR bind imports. The ntoskrnl import set is identical except that the ARM64 build also imports `DbgPrintEx` (the x64 build imports only `vDbgPrintEx`). The UTF-16 string sets differ in two places: the version string reads "3.83.0.0 ARM64 release" instead of "x64 release", and the x64 build has an extra "Insufficient memory." string. The ASCII string diff is code-byte noise and is not meaningful. Dispatch: both builds register their handlers through `NdisMRegisterMiniportDriver` from the DriverEntry tree, but the handler addresses and function layout differ completely, so the ARM64 handler bodies were not reviewed. The two `.inf` files in the canonical folder differ only in the `ntamd64` versus `ntarm64` section lines (lines 21 and 23).

## 2. Evidence blocks

No finding. The only user-facing surface would be NDIS adapter handlers, which exist only after PnP starts a USB devnode (see sections 3 and 8).

## 3. Precondition table (F7F3367C, x64)

| Item | Value |
|---|---|
| Device created in | none in driver code. DriverEntry (`entry` 0x140014ea0) calls `FxDriverEntryWorker` (0x140014ed0), which calls `FUN_14000f630` (0x14000f630). That creates the WDF driver object through `FUN_14000d8a8` (0x14000d8a8, indirect `WdfDriverCreate`) and then calls `FUN_14000e188` (0x14000e188), which calls `NdisMRegisterMiniportDriver`. No `WdfDeviceCreate`, `WdfControlDeviceInitAllocate`, `IoCreateDevice`, or `NdisRegisterDeviceEx` in that tree. NDIS creates the adapter object later, when PnP starts a USB devnode. That path is outside the driver code. |
| WDF AddDevice | none. The `WDF_DRIVER_CONFIG` built in `FUN_14000f630` has `EvtDriverDeviceAdd = NULL` (+0x08), `EvtDriverUnload = NULL` (+0x10), and `DriverInitFlags = 2`. In KMDF 1.11 `wdfdriver.h`, flag 2 is `WdfDriverInitNoDispatchOverride` ("useful for miniports"). Struct layout checked against the same header. |
| Device name | none set by driver. No `\Device\` or `\DosDevices\` strings and no SDDL strings in the dump (0 PAT lines). NDIS assigns the adapter name (not traced). |
| Symbolic link | none set by driver. No `IoCreateSymbolicLink`, `NdisRegisterDeviceEx`, or `WdfDeviceCreateSymbolicLink` in the import table or the DriverEntry tree. |
| DACL and source | none set by driver. No `IoCreateDeviceSecure`, `ZwSetSecurityObject`, or `WdfDeviceInitAssignSDDLString` import, and no SDDL strings. The NCM INF (`dlcdcncm.inf` in `_work\...\DisplayLink_Win10RS.msi.d\disk1.cab.d\`, SHA256 `49f0ce7f...`) has no `Security` line, active or commented. The adapter object DACL created by NDIS was not traced. |
| Setup cost | **hardware** (DisplayLink USB device with a CDC NCM function; the NCM INF lists 564 `USB\VID_17E9&PID_1200..&MI_05 (564 unique PIDs, starting at PID_1200)` hardware IDs) plus a **devnode** (INF-installed KMDF service `dlcdcncm`, StartType 3 = manual, ServiceBinary `%12%\dlcdcncm660.sys`, `Class=net`, IfType Ethernet). |
| Standard-user reachable | No. Not reachable without attached DisplayLink hardware and the INF devnode. |

Package folders: the canonical `drivers\DisplayLink\dlcdcncm660_*.inf` files are **not** the NCM installer. They are `Class=Extension` INFs (`DlAudioExtension_Install`, `S_DriverName=dlusbaudioext`) with 125 `USB\VID_17E9&PID_6000..C05F&MI_02 (125 unique PIDs, PID_6000 to PID_C05F)` hardware IDs. They install no service and no `.sys`. The INF that installs `dlcdcncm660.sys` is the NCM INF, available only in the extracted MSI copy under `_work`. The `_work` copies of both `.sys` files match the canonical hashes.

## 4. Callback table (F7F3367C, x64)

The NDIS `MINIPORT_DRIVER_CHARACTERISTICS` table is built on the stack in `FUN_14000e188`. Slot offsets below are inferred from the decompiled stack layout, not verified against disassembly stores. NDIS names were not verified against `ndis.h`.

| Slot (inferred) | Target | Address | Note |
|---|---|---|---|
| 0x10 | FUN_14000d870 | 0x14000d870 | calls `FUN_14000e148` |
| 0x18 | FUN_14000d740 | 0x14000d740 | reaches `NdisMSetMiniportAttributes` via `FUN_14000dfb4` (0x14000dfb4) and `FUN_140009774` (0x140009774). Probably `MiniportInitializeEx`, unverified. |
| 0x20 | thunk to FUN_14000a3f8 | 0x14000d720 / 0x14000a3f8 | spinlock use |
| 0x28 | FUN_14000df80 | 0x14000df80 | |
| 0x30 | thunk to FUN_14000a658 | 0x14000d7b0 / 0x14000a658 | `KeWaitForSingleObject`, `NdisWaitEvent` |
| 0x38 | thunk to FUN_14000a894 | 0x14000d7d0 / 0x14000a894 | mutex and wait |
| 0x40 | FUN_14000d780 | 0x14000d780 | |
| 0x48 | FUN_14000d820 | 0x14000d820 | |
| 0x50 | FUN_14000d7e0 | 0x14000d7e0 | |
| 0x58 | thunk to FUN_14000a204 | 0x14000d6f0 / 0x14000a204 | |
| 0x60 | thunk to FUN_14000a314 | 0x14000d700 / 0x14000a314 | |
| 0x68 | thunk to FUN_14000a7ac | 0x14000d7c0 / 0x14000a7ac | |
| 0x70 | thunk to FUN_14000a3d4 | 0x14000d710 / 0x14000a3d4 | |
| 0x78 | thunk to FUN_14000ab14 | 0x14000d8a0 / 0x14000ab14 | spinlock flag |
| 0x80 | thunk to FUN_140004ba0 | 0x14000d6e0 / 0x140004ba0 | 3-byte body |

WDF and framework callbacks:
- `WDF_OBJECT_ATTRIBUTES` in `FUN_14000f630`: `EvtCleanupCallback` = FUN_1400040a0 (0x1400040a0), `EvtDestroyCallback` = FUN_1400040f0 (0x1400040f0). These are driver-object callbacks.
- `DriverObject->DriverUnload` (+0x68, x64) = `FxStubDriverUnload` (0x140015000), set in `FxDriverEntryWorker`.
- No IRP `MajorFunction` writes appear in `FxDriverEntryWorker` or `FUN_14000f630`.

## 5. Corruption, not write

None identified. No user-originated buffer path was reviewed, because the device is disqualified.

## 6. Not traced

- **Callback audit not performed** (disqualified). None of the 15 handler bodies were reviewed for user-buffer handling. Only call-site summaries were used.
- **Slot-to-NDIS-name mapping** was not verified against `ndis.h` or against the disassembly stores. The `MiniportInitializeEx` identification at slot 0x18 is inferred from the call chain.
- **Indirect WDF calls**: only `WdfDriverCreate` (`DAT_14001b4f0` in `FUN_14000d8a8`) was mapped, by the six-argument structure match. The function-table index of the other indirect calls was not resolved: `DAT_14001b7a0` (three-argument call in `FUN_14000d8a8`, likely `WdfObjectGetTypedContextWorker`), `DAT_14001b798` (failure path in `FUN_14000f630`), `DAT_14001b500` (trace), and `DAT_14001b7d0` (`FUN_14000dfb4`). None of them is named in the DriverEntry tree as a device-creation call, but the mapping is not complete.
- **Functions decompiled but not reviewed**: all 524 functions are in `dump_x64.txt`. Reviewed: `entry`, `FxDriverEntryWorker`, `FUN_14000f630`, `FUN_14000d8a8`, `FUN_14000e188`, `FUN_14000f340`, `FUN_14000f250`, `FUN_140006010`, the handler stubs (call summaries only), `FUN_140009774` (partial), `FUN_140001050` (`NdisAllocateNetBufferListPool` caller), and `FUN_14000b8cc` (`IoSetDevicePropertyData` caller). The remaining functions were not reviewed.
- **`FUN_140020000`** (called from `entry`, cookie or security check) was not reviewed.
- **`ZwQuerySystemInformation`** (class 0x4c, near the end of the dump) and **`MmGetSystemRoutineAddress`** (resolves `RtlQueryModuleInformation`; the name was decoded from the UNICODE_STRING at 0x140019d48): callers not traced.
- **MDL and mapping imports** (`MmMapLockedPagesSpecifyCache`, `IoBuildPartialMdl`, `IoAllocateMdl`, `MmBuildMdlForNonPagedPool`): not traced for PHYS class. Reachable only after adapter start.
- **NDIS-created adapter object** name, DACL, and creation timing were not traced. This is NDIS behavior, outside the driver code.
- **ARM64 build**: diffed only, as described in section 1.
- **Embedded provenance strings** (`TL-USBNet Driver (NDIS 6.60)`, original filename `tl-usbnet.sys`): noted only, not investigated.

## 7. Next dynamic test

None. The driver is disqualified under the NO-SETUP rule.

## 8. NO-WRITE reason

The missing link is ENTRY POINT: the adapter handlers exist only after PnP starts a DisplayLink USB devnode (hardware plus INF devnode), so they fail the NO-SETUP rule before any sink is considered.
