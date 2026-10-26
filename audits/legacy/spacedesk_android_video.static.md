# spacedesk Android / Video capture: static driver audit

Corpus: `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected3\drivers\Spacedesk\` (canonical files; the `_work` MSI-extract copies have identical SHA256).
Method: static only. Ghidra 12.1.4 headless, `DumpAllDecomp.java` (read before running, read-only), one run per driver. No driver loaded, no installer run, no service created.
Corpus integrity: SHA256 of the 3 SYS and 3 INF files recorded before and after analysis; no change.
Scratch dumps: `C:\Users\<scrubbed>\AppData\Local\Temp\claude\C--Users-<scrubbed>\f675ee28-909f-4610-bb22-f57f1b1e06ab\scratchpad\c3\agent-spacedesk\` (`usb_dump.txt`, `ctl_dump.txt`, `vid_dump.txt`).

Scope note: the task assumed all three are KMDF. **spacedeskVideoCapture.sys is not KMDF.** It imports ntoskrnl and ks.sys only (no WDFLDR.SYS). It is WDM/KS.

---

## 1. Verdict

| Driver | SHA256 prefix | PE TimeDateStamp (UTC) | Verdict | Setup required |
|---|---|---|---|---|
| spacedeskDriverAndroidControl.sys | 61FB7284 | 0x6866207D = 2025-07-03 06:17:33 | NO-WRITE (disqualified by setup cost) | devnode (ROOT branch, INF); hardware (USB branch) |
| spacedeskDriverAndroidUsb.sys | D4B4037D | 0x692D2790 = 2025-12-01 05:28:48 | NO-WRITE (disqualified by setup cost) | hardware |
| spacedeskVideoCapture.sys | 86D6AFC6 | 0x68F0A664 = 2025-10-16 08:01:40 | NO-WRITE (disqualified by setup cost) | devnode |

Q1 (where the device is created):
- AndroidControl: WDF `EvtDriverDeviceAdd` (FUN_140009240), not DriverEntry. PnP-created, so disqualified.
- AndroidUsb: WDF `EvtDriverDeviceAdd` (FUN_140007440 calls FUN_140007000, which calls WdfDeviceCreate). PnP-created, so disqualified.
- VideoCapture: PnP `AddDevice` path installed by KsInitializeDriver (called from DriverEntry FUN_14000145c). PnP-created, so disqualified.

Q2 (AndroidUsb binds to USB hardware): **yes.**
- FUN_14000134c calls `WdfUsbTargetDeviceCreateWithParameters` (function-table offset 0xD28, index 421) with USBD client contract 0x602 (`local_res14 = 0x602`), then `WdfUsbTargetDeviceSelectConfig` (0xA50, index 330).
- Also present: `WdfUsbTargetDeviceGetInterface` (0xB50, FUN_1400015AC), pipe configuration (0xAC8, 0xAF0, FUN_1400014CC), `WdfUsbTargetPipeFormatRequestForWrite` (0xAD8, FUN_140001F00), `WdfUsbTargetDeviceResetPortSynchronously` (0xA80, FUN_140001D90).
- INF compatible IDs for real USB hardware (spacedeskdriverandroidusb.inf, all three arch sections): `USB\VID_18D1&PID_2D00`, `USB\VID_18D1&PID_2D01&MI_00`, `USB\VID_18D1&PID_2D01`.
- No `USBD_*` import exists. The USB client API is reached through the WDF function table, so the import table does not show it.

Q3 (INF security line):
- **AndroidControl: active DACL.** Exact line, `spacedeskdriverandroidcontrol.inf` line 69, uncommented:
  `HKR,,Security,,"D:P(A;;GA;;;BA)(A;;GA;;;SY)"      ; Allow generic-all access to Built-in administrators and Local system `
  It sits in `[spacedeskDriverAndroidControl_AddReg]`, which `[spacedeskDriverAndroidControl_Device.NT.HW]` references through `AddReg=`. That section is reached from the `[Standard.NTx86]`, `[Standard.NTamd64]` and `[Standard.ntarm64.10.0...22000]` device lines, so the line applies to an INF install of `ROOT\VID_DATRONICSOFT_PID_SPACEDESK_DRIVER_USB_ANDROID_0001`.
- **VideoCapture: no DACL.** The INF contains no `Security` line at all (case-insensitive grep over the UTF-16 file decoded to UTF-8 returns zero matches). The nearest active HKR line is `HKR,,FriendlyName,,%spcdskVidCap.FriendlyName%` (line 70 of the decoded copy, not a DACL).
- AndroidUsb INF: no `Security` line (grep, no matches).

Q4 (callbacks): no driver qualified, so the four-part callback audit was not run. Callbacks read are listed in section 4.

---

## 2. Evidence block

None. No finding. All three drivers are disqualified by setup cost before the four-part standard applies.

---

## 3. Precondition table

| Field | AndroidControl | AndroidUsb | VideoCapture |
|---|---|---|---|
| Device created in | WDF EvtDriverDeviceAdd `FUN_140009240` @ 0x140009240. Registered in `FUN_14000A000` @ 0x14000A000 (WdfDriverCreate, config +0x08). DriverEntry creates no device. | WDF EvtDriverDeviceAdd `FUN_140007440` @ 0x140007440, which calls `FUN_140007000` @ 0x140007000 (WdfDeviceCreate, index 75, offset 0x258). Registered in `FUN_140008000` @ 0x140008000 (WdfDriverCreate). DriverEntry creates no device. | PnP AddDevice path. DriverEntry `FUN_14000145C` @ 0x14000145C calls KsInitializeDriver. The driver imports no IoCreateDevice; device object creation is delegated to ks.sys (not traced). |
| Device name | None set. No WdfDeviceInitAssignName in mapped calls. | None set (same). | None set in driver. |
| Symlink / interface | None. Device interface via WdfDeviceCreateDeviceInterface (0x268) in `FUN_140009000` @ 0x140009000, GUID at DAT_140006160 (bytes not decoded). | None. Device interface via WdfDeviceCreateDeviceInterface (0x268) in `FUN_140007000`, GUID at DAT_140004140 (bytes not decoded). | KS filter-factory symlinks via KsFilterFactoryGetSymbolicLink, in `FUN_14000D680` (KsCreateFilterFactory at dump line 7148). |
| DACL and source | INF `Security` value (spacedeskdriverandroidcontrol.inf line 69, `D:P(A;;GA;;;BA)(A;;GA;;;SY)`). Driver does not call WdfDeviceInitAssignSDDLString (index 68; no SDDL call in the call map). No IoCreateDeviceSecure or ZwSetSecurityObject import. Whether PnP honors the INF value for this devnode: not traced. | None set by driver. No WdfDeviceInitAssignSDDLString call; no IoCreateDeviceSecure or ZwSetSecurityObject import. INF has no Security line. Default DACL: not traced. | None set by driver. INF has no Security line. KS default DACL: not traced. |
| Setup cost | devnode (ROOT branch, `ROOT\VID_DATRONICSOFT_PID_SPACEDESK_DRIVER_USB_ANDROID_0001`, FUN_140009000). hardware (USB branch: enumerator "USB" and class GUID `{eec5ad98-8080-425f-922a-dabf3de3f69a}`, FUN_140003C74). | hardware (USB device with VID_18D1 PID_2D00/2D01 compatible IDs). | devnode (INF `{0511CEC1-0EB4-4ADE-9284-CD36606C3906}\VID_DATRONICSOFT&PID_SPACEDESK_VIRTUAL_VIDEO_CAPTURE`). |
| Reachable by standard user | No. Needs devnode or USB hardware. If the INF DACL applies, only admin and SYSTEM can open. | No. Needs USB hardware. | No. Needs devnode. DACL not traced. |
| Disqualified | Yes | Yes | Yes |

---

## 4. Callback or IOCTL table

Only the entries listed below were read. Entries marked "call-map only" were identified from the WDF function-table calls, not read in full. Names marked "inferred" come from the WDF config-struct layout in the decompile and were not confirmed from disassembly.

### AndroidControl (`ctl_dump.txt`, 91 functions)

| Address | Name | Role | Notes |
|---|---|---|---|
| 0x140004660 | entry | entry stub | calls FUN_14000A1B0, then FUN_14000468C |
| 0x14000468C | FUN_14000468C | DriverEntry body | WdfVersionBind; calls FUN_14000A000 |
| 0x14000A000 | FUN_14000A000 | WdfDriverCreate | EvtDriverDeviceAdd = FUN_140009240 (config +0x08). No device created. |
| 0x140001590 | FUN_140001590 | registry read | reads "DebugLevel" via FUN_14000185C. No device. |
| 0x140009240 | FUN_140009240 | EvtDriverDeviceAdd | enumerator "ROOT" goes to FUN_140009000. "USB" with WPD class GUID goes to FUN_140003C74. Any other value creates no device. |
| 0x140009000 | FUN_140009000 | ROOT device create | WdfDeviceInitSetFileObjectConfig (0x238), WdfDeviceCreate (0x258), WdfDeviceCreateDeviceInterface (0x268) |
| 0x1400010F0 | FUN_1400010F0 | EvtDeviceFileCreate (inferred) | calls FUN_140002A1C, which calls CmRegisterCallbackEx(FUN_1400028F0). Completes the request (0x838). |
| 0x140002A1C | FUN_140002A1C | registry-callback registration | CmRegisterCallbackEx at call site. Altitude strings 363460, 363470, 363480, 363490, 363500. |
| 0x140001000 | FUN_140001000 | EvtFileCleanup (inferred) | CmUnRegisterCallback |
| 0x14000400C | FUN_14000400C | WdfIoQueueCreate (0x4C0) | default queue. Only EvtIoDefault set (FUN_1400040E0, config +0x10, inferred). |
| 0x1400040E0 | FUN_1400040E0 | EvtIoDefault (inferred) | WdfRequestGetParameters (0x850). Request types 0xE and 0xF complete with status and are not forwarded. Other types go to WdfRequestSend (0x7E8) on WdfDeviceGetIoTarget (0x150 via 0x4E8). On send failure, status is read (0x7F0) and the request is completed (0x838). The handler does not read or write user buffers. |
| 0x140003C74 | FUN_140003C74 | USB-branch device create | call-map only: WdfFdoInitSetFilter (0x408), WdfDeviceCreate (0x258), calls FUN_14000400C. NOT READ. |
| 0x140003E00 | FUN_140003E00 | USB-branch target create | call-map only: WdfUsbTargetDeviceCreateWithParameters (0xD28). NOT READ. |
| 0x1400042F8 | FUN_1400042F8 | USB control transfer | call-map only: WdfUsbTargetDeviceSendControlTransferSynchronously (0xA68). NOT READ. Callers not traced. |
| 0x1400028F0 | registry callback | passed to CmRegisterCallbackEx | NOT READ |

### AndroidUsb (`usb_dump.txt`, 62 functions)

| Address | Name | Role | Notes |
|---|---|---|---|
| 0x140002D10 | entry | entry stub | calls FUN_140002D3C |
| 0x140002D3C | FUN_140002D3C | DriverEntry body | WdfVersionBind; calls FUN_140008000 |
| 0x140008000 | FUN_140008000 | WdfDriverCreate (0x3A0) | EvtDriverDeviceAdd = FUN_140007440 (config +0x08). Driver EvtCleanupCallback = FUN_140007510 (attributes +0x08, inferred). No device here. |
| 0x140007440 | FUN_140007440 | EvtDriverDeviceAdd wrapper | calls FUN_140007000 |
| 0x140007000 | FUN_140007000 | device create | WdfDeviceCreate (0x258). PnP callbacks via 0x1B8: FUN_1400072F0 (+0x28, inferred EvtDevicePrepareHardware), FUN_140001C80 (+0x08, inferred EvtDeviceD0Entry), FUN_140001D90 (+0x18, inferred EvtDeviceD0Exit). WdfCollectionCreate (0x68). WdfDeviceCreateDeviceInterface (0x268). Calls FUN_140007A64 (queue create, not read) and FUN_14000134C (USB target, read). |
| 0x14000134C | FUN_14000134C | USB target create | WdfUsbTargetDeviceCreateWithParameters (0xD28), contract 0x602. WdfUsbTargetDeviceSelectConfig (0xA50). |
| 0x1400015AC | FUN_1400015AC | interface / pipe enumeration | call-map only: WdfUsbTargetDeviceGetInterface (0xB50), WdfUsbInterfaceGetNumConfiguredPipes (0xB60), WdfUsbInterfaceGetConfiguredPipe (0xB68). NOT READ. |
| 0x1400014CC | FUN_1400014CC | pipe configuration | call-map only: WdfUsbTargetPipeSetNoMaximumPacketSizeCheck (0xAC8), WdfUsbTargetPipeConfigContinuousReader (0xAF0). NOT READ. |
| 0x140001F00 | FUN_140001F00 | request path | call-map only: WdfRequestSend (0x7E8), WdfRequestGetParameters (0x850), WdfRequestRetrieveInputMemory (0x858), WdfUsbTargetPipeFormatRequestForWrite (0xAD8), WdfRequestForwardToIoQueue (0x8C8). Probably the queue's request handler. NOT READ. |
| 0x140001C80 | FUN_140001C80 | D0Entry (inferred) | WdfIoTargetStart (0x558). call-map only. |
| 0x140001D90 | FUN_140001D90 | D0Exit (inferred) | WdfIoTargetStop (0x560), WdfUsbTargetDeviceResetPortSynchronously (0xA80). call-map only. |
| 0x140007A64 | FUN_140007A64 | queue create | call-map only: WdfIoQueueCreate (0x4C0), WdfIoQueueReadyNotify (0x530). NOT READ. |

### VideoCapture (`vid_dump.txt`, 270 functions)

| Address | Name | Role | Notes |
|---|---|---|---|
| 0x140012000 | entry | entry stub | calls FUN_14001202C, then FUN_14000145C |
| 0x14000145C | FUN_14000145C | DriverEntry body | KsInitializeDriver(DriverObject, RegistryPath, &PTR_PTR_1400039D0). Saves original DriverUnload and installs FUN_14000C160 at DriverObject+0x68. No device created. |
| 0x14000D680 | FUN_14000D680 | filter-factory creation | partially read (dump lines 7101-7175). KsCreateFilterFactory (line 7148) and KsFilterFactoryGetSymbolicLink. Callers not traced. Rest of body NOT READ. |
| 0x14000C160 | FUN_14000C160 | DriverUnload (installed by FUN_14000145C) | NOT READ |

---

## 5. Corruption, not write

None recorded. No buffer-copy path was reviewed beyond the disqualification evidence.

---

## 6. Not traced

**A. Decompiled but not read.** All functions in the three dumps were decompiled, with no failures. The functions listed in section 4 were read. All others were decompiled only. The full list is the `FUNC` headers in each scratch dump: 56 of 62 in AndroidUsb, about 75 of 91 in AndroidControl, about 265 of 270 in VideoCapture. Notable unread ones: AndroidUsb FUN_140001F00 and FUN_140007A64 (request and queue paths); AndroidControl FUN_140003C74, FUN_140003E00, FUN_1400042F8, FUN_1400028F0.

**B. Timeouts and caps.** Zero "decompile failed" or exception lines in all three dumps. DumpAllDecomp does not truncate output.

**C. Items a verdict depends on, not verified:**
1. AndroidUsb (hardware verdict). The WDF function-table index-to-name mapping uses `wdffuncenum.h` from KMDF 1.15 in the local Windows Kits. That matches the INF `KmdfLibraryVersion = 1.15`. It is not confirmed from disassembly. The EvtDriverDeviceAdd and PnP callback identities depend on config-struct layout inferred from decompiler locals (+0x08, +0x18, +0x28). Not confirmed from disassembly.
2. AndroidUsb: the PnP match of the USB compatible IDs was not exercised. Static only.
3. AndroidControl (devnode/hardware verdict). FUN_140009240 selects the branch from parent-enumerator and class-GUID values read with property IDs 0xF, 6 and 1. Those IDs were not mapped to names. The branch choice rests on the `_wcsicmp` calls against "USB" and "ROOT".
4. AndroidControl: the USB branch (FUN_140003C74) was not read in full. The verdict does not depend on it, because the ROOT branch already needs a devnode.
5. AndroidControl: whether PnP honors the INF `HKR,,Security` value for the ROOT devnode. This affects the DACL row only, not the verdict.
6. VideoCapture (devnode verdict). Device creation is delegated to ks.sys (KsInitializeDriver installs AddDevice, presumed). ks.sys is not in the corpus and was not traced. The verdict assumes AddDevice is the only device-creation path. That fits the driver's imports (no IoCreateDevice) but is not confirmed in ks.sys.
7. VideoCapture: the INF hardware ID form `{GUID}\VID_...` is treated as an INF devnode, per the brief. The PnP enumeration source was not traced.
8. Scope: VideoCapture is WDM/KS, not KMDF (see the scope note at the top).

**D. Dedupe.** The `_work` MSI-extract copies are hash-identical to the canonical files (verified). No other builds of these three families were found in `_collected3`.

---

## 7. Next dynamic test

None. All three drivers are disqualified by setup cost. The disqualification rests on the device-creation path, which is static evidence.

---

## 8. NO-WRITE reason

- **AndroidControl:** ENTRY POINT missing. The device and its default IOCTL queue exist only after PnP creates the ROOT devnode from the INF, or a USB hardware devnode. DriverEntry creates no device.
- **AndroidUsb:** ENTRY POINT missing. The device exists only with USB hardware, since it issues WdfUsbTargetDeviceCreateWithParameters from EvtDriverDeviceAdd.
- **VideoCapture:** ENTRY POINT missing. The device object exists only after PnP AddDevice for an INF devnode. DriverEntry creates no device.
