# Static audit: spacedesk Bus, Audio, KtmInput (drivers\Spacedesk)

Date: 2026-10-24. Vendor: datronicsoft Technology GmbH. All three are x64 KMDF-stub drivers (DRIVER_OBJECT offsets: MajorFunction at +0x70, DriverUnload at +0x68, DriverExtension at +0x30). Static only: nothing was loaded, installed, or started.

Method: Ghidra 12.1.4 headless with the read-only DumpAllDecomp.java on the canonical files. Dumps are in the scratch folder `c3\bak` (ktm_dump.txt: 52 functions; bus_dump.txt: 241; audio_dump.txt: 212; zero decompile failures or timeouts). WDF call targets were mapped with the KMDF 1.15 wdffuncenum.h (indices for the entries used are the same in 1.11, 1.13 and 1.15). Every call site cited below was checked in llvm-objdump output. Corpus hashes of the six in-scope files (3 .sys, 3 .inf) were recorded before and after the audit and are unchanged. The _work copies of all six files have identical SHA256 values. No other build of these three drivers exists in the corpus, so there is no dedupe partner to diff.

## 1. Verdict

- **spacedeskDriverBus.sys**, SHA256 28A16670 8326144C..., PE TimeDateStamp 2026-02-16 06:43:44 UTC, version 1.0.491.50. **NO-WRITE (disqualified).** Setup required: **devnode**. The only device comes from the PnP EvtDriverDeviceAdd (FUN_14001a000). Callback audit not performed, per the brief.
- **spacedeskDriverAudio.sys**, SHA256 913630DD 2BACEBDA..., PE TimeDateStamp 2026-02-16 06:44:34 UTC, version 1.0.491.19. **NO-WRITE (disqualified).** Setup required: **devnode**. The device comes from the PortCls AddDevice (FUN_140018220), which PnP calls.
- **spacedeskKtmInput.sys**, SHA256 3A8501F0 EB0D0CC4..., PE TimeDateStamp 2024-10-09 06:09:47 UTC (INF DriverVer 1.0.462.11). **NO-WRITE (disqualified).** Setup required: **devnode**. The control devices are created inside the PnP EvtDriverDeviceAdd (FUN_140008000), not in DriverEntry.

**Q1, device creation point (one line each).**
- Bus: PnP. EvtDriverDeviceAdd FUN_14001a000 (registered by the WdfDriverCreate call in FUN_14001b000) calls FUN_14000f13c, which calls WdfDeviceCreate. Devnode: `Root\VID_DATRONICSOFT_PID_SPACEDESK_VIRTUAL_BUS_0001` (spacedeskDriverBus.inf).
- Audio: PnP. FUN_14001b000 (DriverEntry body) calls PcInitializeAdapterDriver(..., FUN_140018220). FUN_140018220 calls PcAddAdapterDevice. The WDF EvtDriverDeviceAdd is NULL: the config struct at rbp-0x11 (size 0x20 stored at 0x14001b0d1) has r14 at +8 (stored at 0x14001b0e1). r14 is zeroed at 0x14001b028. WdfDriverCreate is fetched at 0x14001b0ec. Devnode: `{0511CEC1-0EB4-4ADE-9284-CD36606C3906}\VID_DATRONICSOFT&PID_SPACEDESK_VIRTUAL_AUDIO_*` (spacedeskDriverAudio.inf).
- KtmInput: PnP. DriverEntry body FUN_140009000 only calls WdfDriverCreate (call at 0x14000909d). Its EvtDriverDeviceAdd is FUN_140008000 (stored at 0x140009057 into config+8). Devnode: `{0511CEC1-...}\VID_DATRONICSOFT&PID_SPACEDESK_VIRTUAL_MOUSE_0001` (spacedeskktminputmouse.inf). The binary also matches the Root\ mouse and keyboard IDs.

**Q2 answer.** SDDL-ACTIVE-RESTRICTED **holds, for the two control devices**. The literal is `D:P(A;;GA;;;SY)(A;;GA;;;BA)`. It is passed as the SDDL argument of WdfControlDeviceInitAllocate (see section 3). The Ghidra decompile of that call shows only two arguments (Ghidra drops the third); the disassembly shows the third (R8). The literal is not applied to the mini-FDO created by FUN_140001a84, which has no SDDL call. Q2 does not change the verdict, because the device is still PnP-created.

**Q3 answer.** Only uncommented `HKR,,Security` lines apply a DACL.
- Bus, spacedeskDriverBus.inf line 54 (active): `HKR,,Security,,"D:P(A;;GA;;;BA)(A;;GA;;;SY)"      ; Allow generic-all access to Built-in administrators and Local system`. It sits in `[spacedeskDriverBus_Device.NT.AddReg]` (line 52), reached from `[spacedeskDriverBus_Device.NT.HW]` (section header line 49, AddReg reference line 50). Line 55 is `;HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;WD)(A;;GA;;;RC)"`, which begins with `;` and is inactive.
- Audio, spacedeskDriverAudio.inf line 171 (active): `HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)" ; SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RWX_RES_RWX`. It sits in `[spacedeskDriverAudio_Device.NT.HW.AddReg]` (section header line 169), reached from `[spacedeskDriverAudio_Device.NT.HW]` (section header line 166, AddReg reference line 167).
- KtmInput: its INF has no Security line.

**Structural comparison.** All three share the WDF stub pattern (WDFLDR WdfVersionBind/Unbind/BindClass/UnbindClass, the same entry-to-stub-to-DriverEntry-body chain, and the same __GSHandlerCheck and zeroing helpers). Bus and Audio also import WPP (WppAutoLogStart/Stop/Trace). Audio imports PortCls (PcInitializeAdapterDriver, PcAddAdapterDevice, PcNewPort) and Bus uses the WDF child-list and PDO API. Ktm imports only ntoskrnl basics (IoCreateSymbolicLink, Rtl*, DbgPrintEx, Kf*/Ke* IRQL helpers) plus the WDFLDR stubs; its device API is WDF control-device and queue. Shared strings are limited to the version resource (`datronicsoft Technology GmbH`, `Copyright (C) datronicsoft`, `$datronicsoft, Inc`) and the project tree in the PDB path. Bus and Audio build from `D:\SPACEDESK\spacedeskDrivers\trunk\`; Ktm from `E:\V3DDK_DIR\spacedeskDrivers\trunk\`. Shared code was checked at prefix level only, using 24-byte function prefixes (7 to 36 matches per pair, mostly __GSHandlerCheck, the WDF stub, and helper prologues). No application-level function was shown to be byte-identical in full. The rest of the comparison is structural only.

## 2. Evidence blocks

None. No driver reached a finding: all three are disqualified by setup cost, and no sink was traced.

## 3. Precondition table

| Driver | Device created in | Device name | Symlink | DACL (source, address) | Setup cost | Reachable by standard user |
|---|---|---|---|---|---|---|
| Bus | WDF EvtDriverDeviceAdd FUN_14001a000 (config+8 set at 0x14001b0c0, WdfDriverCreate call 0x14001b0f8), then FUN_14000f13c (WdfDeviceCreate, FDO). Child PDOs: FUN_14000ab40 -> FUN_140007c70 -> FUN_14000f954 (WdfDeviceCreate). | None found. Device interface only. No `\Device` or `\DosDevices` literal in the binary. | None. No IoCreateSymbolicLink import, no WdfDeviceCreateSymbolicLink call. | INF line 54 (active, devnode-only): `D:P(A;;GA;;;BA)(A;;GA;;;SY)`. No SDDL call in code (no WdfControlDeviceInitAllocate, no WdfDeviceInitAssignSDDLString). | devnode | No, if the devnode existed (BA and SY only). |
| Audio | PnP AddDevice FUN_140018220, registered by PcInitializeAdapterDriver in FUN_14001b000 (dump line 10223). Calls PcAddAdapterDevice(..., FUN_140018cf0). WDF EvtDriverDeviceAdd is NULL. | None. No IoCreateDevice import. | None. | INF line 171 (active, devnode-only): `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)`. | devnode | Yes, if the devnode existed (WD and RC get RWX per INF). Conditional, not verified at runtime. |
| KtmInput | WDF EvtDriverDeviceAdd FUN_140008000 (config+8 set at 0x140009057). Calls FUN_1400010ec -> FUN_1400011c4 (control devices, WdfDeviceCreate at 0x14000149c). Also FUN_140001a84 (mini-FDO, WdfDeviceCreate). | Mouse: `\Device\spacedeskCtrlvMouse` (VA 0x1400035c0). Keyboard: `\Device\spacedeskCtrlvKbd` (VA 0x140003640). | Mouse: `\DosDevices\spacedeskCtrlvMouse` (VA 0x140003600), created by IoCreateSymbolicLink (IAT call 0x1400015a5, FUN_1400011c4). Keyboard: `\DosDevices\spacedeskCtrlvKbd` (VA 0x140003680), same call. | SDDL literal `D:P(A;;GA;;;SY)(A;;GA;;;BA)` at VA 0x140005140 (.rdata, file 0x3940). UNICODE_STRING at VA 0x140005178. LEA R8,[rip] at 0x140001346 loads it. The call `WdfFunctions+0xc8` (WdfControlDeviceInitAllocate, index 25) at 0x14000135e passes it as the SDDL argument. This runs before the mouse/keyboard branch at 0x1400013a9, so both control devices get the same DACL. Mini-FDO FUN_140001a84: no SDDL call found, so its default DACL is not traced. INF: no Security line. | devnode | No for the control devices (SY and BA only). Disqualified regardless. |

Notes on the INF packages.
- Bus: INF DriverVer 02/16/2026,1.0.491.50, KmdfLibraryVersion 1.15.
- Audio: INF DriverVer 02/16/2026,1.0.491.19, KmdfLibraryVersion 1.15.
- KtmInput: INF DriverVer 10/09/2024,1.0.462.11, KmdfLibraryVersion 1.9. Its copy list (line 52) and ServiceBinary (line 64) name `spacedeskKtmInputMouse.sys`, which is not in the package. The package contains `spacedeskKtmInput.sys` only. Not installed, so this was not verified.

## 4. Callback or IOCTL table

Audited: none, because all three drivers are disqualified. Registration addresses that were verified are listed. Items marked NOT AUDITED are the user-buffer paths a future audit would need.

KtmInput:
| Address | Function | Role / evidence | Status |
|---|---|---|---|
| 0x140008000 | FUN_140008000 | EvtDriverDeviceAdd (set at 0x140009057) | Reviewed (creation path) |
| 0x1400011c4 | FUN_1400011c4 | SKMDeviceControlCreate, sole caller FUN_1400010ec | Reviewed |
| 0x140001a84 | FUN_140001a84 | Mini-FDO create; WdfDeviceCreate, WdfDeviceInitAssignWdmIrpPreprocessCallback | Call graph only |
| 0x1400021cc, 0x1400025dc | FUN_1400021cc, FUN_1400025dc | Queue creators (keyboard and mouse), WdfIoQueueCreate | NOT AUDITED |
| 0x140001720 (kbd), 0x140001890 (mouse) | EvtIoDeviceControl candidates for the control queue, chosen at FUN_1400011c4 | Both call WdfRequestRetrieveInputBuffer (0x868). Queue config field offset not confirmed. | NOT AUDITED (user buffers) |
| 0x140001610, 0x140001690 | File-object callbacks in WDF_FILEOBJECT_CONFIG set in FUN_1400011c4 | Registration offset not confirmed | NOT AUDITED |
| 0x140001cb0 | Control-device cleanup (IoDeleteSymbolicLink, WdfObjectDelete) | Registration not traced | Partly read |
| 0x140001ec0, 0x140002280, 0x140002344, 0x140002690, 0x140002754 | Request processors (WdfRequestSend, Complete, RetrieveInputBuffer) | Call graph only | NOT AUDITED |

Bus:
| Address | Function | Role / evidence | Status |
|---|---|---|---|
| 0x14001a000 | FUN_14001a000 | EvtDriverDeviceAdd (lea 0x14001b0b2, stored 0x14001b0c0) | Reviewed (FDO path) |
| 0x14000f13c | FUN_14000f13c | FDO WdfDeviceCreate, device interface, child-list config | Reviewed (creation only) |
| 0x14000ab40 | FUN_14000ab40 | Child-list create-device callback (registered in FUN_14000f13c) | NOT AUDITED |
| 0x140007c70, 0x14000f954 | PDO path | WdfDeviceCreate for PDO | Call graph only |
| 0x140010b40, 0x140011614, 0x140011964, 0x140011bd0 | Queue creators (WdfIoQueueCreate) | NOT AUDITED |
| 0x1400120d0, 0x140012594 | WdfRequestProbeAndLockUserBufferForRead / ForWrite | NOT AUDITED |
| 0x140001e08, 0x1400095c0 | IoAllocateMdl and MmBuildMdlForNonPagedPool call sites | NOT AUDITED |
| 0x14000207c | FUN_14000207c: MmMapLockedPagesSpecifyCache(MDL, KernelMode, MmCached, ..., NormalPagePriority), result stored to *param_2. Called from FUN_140001f94 (dump line 1017). | NOT AUDITED (MDL sink, not traced to the user buffer source) |
| 0x140010130 | EvtCleanupCallback (set at 0x14001b098) | NOT AUDITED |

Audio:
| Address | Function | Role / evidence | Status |
|---|---|---|---|
| 0x140018220 | FUN_140018220 | AddDevice (PortCls callback) | Reviewed (calls PcAddAdapterDevice) |
| 0x1400184b0 | MajorFunction[0] (+0x70, IRP_MJ_CREATE) | Set in FUN_14001b000 | NOT AUDITED |
| 0x140018310 | MajorFunction[18] (+0x100, IRP_MJ_CLEANUP) | Set in FUN_14001b000 | NOT AUDITED |
| 0x140018b80 | MajorFunction[27] (+0x148, IRP_MJ_PNP) | Set in FUN_14001b000 | NOT AUDITED |
| 0x1400190f0 | DriverUnload (+0x68) | Set in FUN_14001b000 | NOT AUDITED |
| 0x140018cf0 | PcAddAdapterDevice callback | Passed in FUN_140018220 | NOT AUDITED |
| 0x140013610 | WdfDeviceMiniportCreate | Only reference is a pointer at file offset 0x5b00 | NOT AUDITED |
| dump lines 5561 and 6393 | IoRegisterDeviceInterface call sites (functions not named) | Interface GUID DAT_1400067e8 | NOT AUDITED |

## 5. Corruption, not write

None recorded. No callback was audited, so no corruption evidence was gathered.

## 6. Not traced

1. **All callback and IOCTL bodies for the three drivers** (tables in section 4), and every other function in the three dumps except the reviewed chain: FUN_140008000, FUN_1400010ec, FUN_1400011c4, FUN_140009000, FUN_140002ddc, FUN_140001000 (Ktm); FUN_14001a000, FUN_14000f13c, FUN_14001b000, FUN_14001425c, entry at 0x140014230 (Bus); FUN_140018220, FUN_14001b000, FUN_14000515c, entry at 0x140005130 (Audio). These are reviewed for creation only. The dumps contain the full list.
2. **Decompiler argument loss.** Confirmed by disassembly: the SDDL argument of WdfControlDeviceInitAllocate in Ktm (0x14000135e). The Audio WdfDriverCreate (6 arguments, 4 shown) was confirmed at 0x14001b0e5 to 0x14001b104. Not confirmed: the WdfIoQueueCreate output-handle argument (Ktm and Bus), and the WdfDriverCreate arguments in Ktm and Bus (the config and EvtDriverDeviceAdd were confirmed from disassembly).
3. **Devnode premise.** Static evidence shows the device creation is inside EvtDriverDeviceAdd and AddDevice. That these run only for a PnP devnode is standard KMDF/PortCls behaviour, not re-verified by installing. The INF hardware IDs were read, not exercised.
4. **Audio FUN_140013610** (WdfDeviceMiniportCreate). Its trigger is unknown. Its only reference is a pointer at file offset 0x5b00.
5. **Bus child-PDO trigger.** Whether PDOs are created by IOCTL, by the BusPdoAutoCreate registry value, or by the FDO start is not traced. The FDO itself still needs the devnode.
6. **Default DACLs** of the Ktm mini-FDO (FUN_140001a84) and of the Bus FDO and PDOs, where no SDDL is set by the driver. Not traced.
7. **Standard-user devnode creation.** The `{0511CEC1-...}\VID_` hardware IDs in the Ktm and Audio INFs look like software-device IDs. Whether a standard user could create that devnode (for example with a software-device API) was not checked. Binding still needs an installed INF, and the policy treats any devnode as setup cost.
8. **Ktm INF packaging.** The INF names `spacedeskKtmInputMouse.sys` (lines 52, 64), which is absent from the package. Install behaviour was not tested.
9. **Structural comparison** was prefix-level only (24-byte function prefixes). No full-body comparison was done.
10. **Bus MDL and user-buffer sinks** were not traced: IoAllocateMdl in FUN_140001e08 and FUN_1400095c0; MmMapLockedPagesSpecifyCache in FUN_14000207c (called from FUN_140001f94); WdfRequestProbeAndLockUserBuffer* in FUN_1400120d0 and FUN_140012594. The user-buffer source for these was not traced.

## 7. Next dynamic test

None. All three drivers are disqualified by setup cost (devnode).

## 8. NO-WRITE reason

- Bus: the missing link is the ENTRY POINT without a devnode. The only device comes from PnP EvtDriverDeviceAdd, which the NO-SETUP rule excludes.
- Audio: the missing link is the ENTRY POINT without a devnode. The only device comes from PnP AddDevice (PortCls), which the NO-SETUP rule excludes.
- KtmInput: the missing link is the ENTRY POINT without a devnode. The control devices come from PnP EvtDriverDeviceAdd, which the NO-SETUP rule excludes. Its SDDL-ACTIVE-RESTRICTED label holds (SY and BA only), so even with a devnode the control devices would not be reachable by a standard user, as passed to WdfControlDeviceInitAllocate.
