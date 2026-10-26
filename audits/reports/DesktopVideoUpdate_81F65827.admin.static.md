# Audit: DesktopVideoUpdate_81F65827.sys

| Field | Value |
|---|---|
| File | drivers\DesktopVideoUpdate_81F65827.sys |
| SHA-256 | 81F658278AF06AE31EE6EB406F426A243D3F3A56BAABF14FFBA44644CAB5F6A4 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\DesktopVideoUpdate_81F65827.txt`, 2016 lines, 41 functions, decompile complete); PE import/string triage; Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Blackmagic Design; file version 4.0.2.0; description "Blackmagic Design USB Driver" |
| Signature | Authenticode Valid; WHQL-type chain (CN=Microsoft Windows Hardware Compatibility Publisher) |
| Reach | R3 (devnode / hardware: the driver is loaded by PnP only for an attached Blackmagic USB device) |
| Setup required | hardware |
| Write quality | W0 (no caller-controlled kernel memory write; bounded SystemBuffer and URB transfers only) |
| Severity | NO-MEMORY-WRITE |
| HW-only | no (no MSR, port I/O, PCI config, SMBus/EC or MMIO; the only device I/O is USB transfers to the attached device) |

Legend: "dump lines" are line numbers in the Ghidra dump; "FUN_" addresses are image VAs (image base 0x140000000).

## 1 Internals

- PE32+ x64 (Machine 0x8664, 28,592 bytes, TimeDateStamp 2025-02-25). Imports: ntoskrnl (device/PnP/IRP/pool), USBD (`USBD_GetUSBDIVersion`, `USBD_CreateConfigurationRequestEx`, `USBD_ParseConfigurationDescriptorEx`). No WDF import. No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `MmGetSystemRoutineAddress`, `RtlCopyMemory`, `ProbeForWrite` in the import table (dump lines 2-29).
- Entry: PE entry `entry @ 140007000` (dump 1978-1986) calls `__security_init_cookie` then `FUN_1400013a8`, which is the DriverEntry body.
- No symbolic link and no named device. No `IoCreateDeviceSecure`, no `IoCreateSymbolicLink`, no `ZwSetSecurityObject`.

## 2 Entry / device / interface / effective DACL

- DriverEntry `FUN_1400013a8` (dump 264-277):
  - `DriverExtension->AddDevice` (DRIVER_OBJECT+0x30, +8) = `FUN_140001950` (dump 269).
  - DRIVER_OBJECT+0x68 (DriverUnload slot) = `_guard_check_icall` (dump 270). Ghidra labels the value as the CFG check stub; the real unload routine is not resolved. It does not affect the write analysis.
  - MajorFunction slots set: CREATE (0x70) = `FUN_140001530` (273); CLOSE (0x80) = `FUN_1400014b0` (274); POWER (0x120) = `FUN_140001770` (272); PNP (0x148) = `FUN_140001620` (271); DEVICE_CONTROL (0xE0) = `FUN_140001a20` (275). READ, WRITE and INTERNAL_DEVICE_CONTROL are not set.
- AddDevice `FUN_140001950` (dump 579-617):
  - `FUN_1400015bc` (dump 387-399) calls `IoCreateDevice(DriverObject, 0x80, DeviceName=0, DeviceType=0x22, Characteristics=0, Exclusive=0, &DeviceObject)` at dump 394, then zeroes the 0x80-byte extension (396).
  - `IoAttachDeviceToDeviceStack` at dump 598.
  - `IoRegisterDeviceInterface(PDO, &DAT_140004130, NULL, ...)` at dump 604. GUID bytes at VA 0x140004130 (file offset 0x2930): `{B8719EFC-9A7F-400F-B2AF-285913FBCECC}`.
- Effective DACL: the device has no name and the driver passes no security descriptor (`IoCreateDevice`, not `IoCreateDeviceSecure`). The device object therefore gets the IoCreateDevice default security. The only user-visible name is the PnP device interface above, whose symbolic-link ACL is set by PnP and is not expressed in this image. No SDDL string appears in the strings (triage). Effective access is therefore not fixed by the image; it is hardware-gated (R3) regardless.

## 3 Dispatch and IOCTL table

Dispatch: `FUN_140001a20` (dump 618-956) handles IRP_MJ_DEVICE_CONTROL. Entry gate (dump 646-653): `FUN_14000246c` (dump 1107-1119) increments the in-flight counter and returns FALSE when the device-ready byte (ext+0x38) is 0, which fails the IRP with STATUS_DEVICE_NOT_READY (0xC0000056). Stack layout used: OutputBufferLength at +0x08, InputBufferLength at +0x10, IoControlCode at +0x18 (dump 662-665). SystemBuffer = IRP+0x18 (dump 666).

Every IOCTL code is METHOD_BUFFERED (low 2 bits 0) with FILE_ANY_ACCESS (bits 14-15 = 0). Minimum sizes are the checks in the dispatcher. "Kernel action" names the function reached.

| IOCTL | Method | Access | Input min | Output min | Kernel action (dump lines) |
|---|---|---|---|---|---|
| 0x222000 | BUFFERED | ANY | 0 | 8 | Writes SystemBuffer[0]=5, [1]=0; Info=8 (685-688) |
| 0x22205C | BUFFERED | ANY | 0 | ==4 | Returns ext+0x54 (last lower-stack status); Info=4 (692-695) |
| 0x222080 | BUFFERED | ANY | 0x14, and >= ushort(in[2])+0x14 | 0x14, and >= ushort(in[2])+0x14 | `FUN_140001068` (dump 52-124): builds a control-transfer URB; setup fields from input bytes 0-7, transfer buffer = SystemBuffer+0x14, length = ushort at input+8; Info = len+0x14 (699-705) |
| 0x22208C | BUFFERED | ANY | 0 | 4 | Returns byte ext+0x5C (current config index, set in `FUN_140001000` dump 44); Info=4 (707-711) |
| 0x222090 | BUFFERED | ANY | 4 | 4 | `FUN_140002920` fetches a device descriptor (index = input byte 0) into pool; SystemBuffer[0]=len+4; if len+4 <= out, `memmove(SystemBuffer+4, pool, len)` (713-723) |
| 0x222094 | BUFFERED | ANY | 0 | 4 | Returns byte at (ext+0x68)+4; Info=4 (726-731) |
| 0x222098 | BUFFERED | ANY | 0 | 4 | Returns ushort at (ext+0x68)+10; Info=4 (677-683) |
| 0x22209C | BUFFERED | ANY | 0 | 4 | Returns byte at (ext+0x68)+6; Info=4 (734-740) |
| 0x2220A0 | BUFFERED | ANY | 0 | 4 | Returns ushort at (ext+0x68)+0xC; Info=4 (746-750) |
| 0x2220A8 | BUFFERED | ANY | 0 | 4 | Returns byte at (ext+0x68)+5; Info=4 (752-756) |
| 0x2220AC | BUFFERED | ANY | 0 | 4 | Returns ushort at (ext+0x68)+8; Info=4 (758-762) |
| 0x2220B4 | BUFFERED | ANY | 0 | 4 | Returns byte at (ext+0x68)+0x11; Info=4 (764-768) |
| 0x2220B8 | BUFFERED | ANY | 4 | 0 | `FUN_140001000(index=in[0])`: fetches the config descriptor by index (`FUN_140002920`), rebuilds the parsed tables (`FUN_140002CE4`, dump 1575-1683) and sets ext+0x5C=index on success (771-777) |
| 0x2220BC | BUFFERED | ANY | 8 | 4 | `FUN_140001188` (dump 127-198): matches the 8-byte input filter against the config table; writes SystemBuffer[0]=count and matching indices (bounded by out, 169-171); Info=count*4+4 or 4 (669-674) |
| 0x2220C0 | BUFFERED | ANY | 4 | 4 | Index < ext+0x78 (count); SystemBuffer[0] = byte(entry+5); Info=4 (801-809) |
| 0x2220C4 | BUFFERED | ANY | 4 | 4 | Same index check; byte(entry+2) (811-817) |
| 0x2220C8 | BUFFERED | ANY | 4 | 4 | Same index check; byte(entry+7) (819-825) |
| 0x2220CC | BUFFERED | ANY | 4 | 4 | Same index check; byte(entry+6) (827-833) |
| 0x2220D0 | BUFFERED | ANY | 4 | 4 | Same index check; byte(entry+4) (835-841) |
| 0x2220D4 | BUFFERED | ANY | 8 | 6 | Index and entry-count checks (846-850); writes 6 bytes of endpoint fields into SystemBuffer[0..5]; Info=6 (845-858) |
| 0x2220D8 | BUFFERED | ANY | 0x10, and >= in[1]+0x10 | 0 | Index / entry checks (788-794); `FUN_140002A6C` (dump 1454-1499) transfer with buffer = SystemBuffer+0x10, length in[1] (max-transfer check 1467); direction from the device endpoint descriptor; Info = transferred length (795-797) |
| 0x2220DC | BUFFERED | ANY | 0x10 | in[1] <= out | Index / entry checks (865-871); `FUN_140002A6C` with buffer = SystemBuffer+0, length in[1] (872-876) |
| 0x2220E0 | BUFFERED | ANY | 0 | 0 | `FUN_140002C50` (dump 1551-1570): IOCTL_INTERNAL_USB_RESET_PORT (0x220007) to the lower stack (883-885) |
| 0x2220E4 | BUFFERED | ANY | 0x10, and >= in[1]+0x10 | 0 | Index / entry checks (888-894); `FUN_1400024F8` queue push, max 16 (dump 1173-1190); `FUN_140002B6C` transfer with buffer = SystemBuffer+0x10, length in[1] (895-901) |
| 0x2220E8 | BUFFERED | ANY | 0x10 | in[1] <= out | Index / entry checks (913-919); queue push; `FUN_140002B6C` with buffer = SystemBuffer+0 (920-923) |
| 0x2220EC | BUFFERED | ANY | 8 | 0 (must be 0) | `FUN_140002278(config=in[0], iface=in[1]-1)` (dump 997-1033): builds a URB (function 0x1E) from the pipe/interface table (1006-1027); idx check at 1010 (see §8) (930-931) |
| 0x2220F0 | BUFFERED | ANY | 0 | must be non-zero | SystemBuffer[0] = byte(ext+0x68+0x10); Info=1 (935-938) |
| any other | - | - | - | - | STATUS_INVALID_DEVICE_REQUEST (0xC0000010) (943) |

Lower-stack internal codes issued by the driver (not user-facing): IOCTL_INTERNAL_USB_SUBMIT_URB 0x220003 (`FUN_1400026D4`, dump 1287-1340), IOCTL_INTERNAL_USB_RESET_PORT 0x220007 (`FUN_140002C50`).

## 4 Access-control audit

- The dispatcher performs no `SeAccessCheck`, `SeSinglePrivilegeCheck`, or caller-identity check. IRP_MJ_CREATE (`FUN_140001530`, dump 353-384) checks only a device-started byte (ext+0x11, dump 364), allocates a 0x90-byte file context and increments the open count.
- Gates are therefore: (a) the device-started flag at CREATE, (b) the device-ready byte at each IOCTL (dump 646-653), (c) the table index and length checks listed in §3.
- Any principal that can open the device object (default IoCreateDevice security, or the PnP interface) can issue every IOCTL above. The device exists only while the Blackmagic USB hardware is enumerated, so access is hardware-gated (R3).

## 5 Memory-write trace

Every dereference write in the dump (`*(...) = ...`, grep over the whole file) was checked. Results:

1. SystemBuffer writes at fixed offsets: IOCTLs 0x222000 (dump 686-687), 0x2220F0 (936), 0x22208C/0x222094/0x222098/0x22209C/0x2220A0/0x2220A8/0x2220AC/0x2220B4/0x2220C0-0x2220D0 (807, 738, 853-856). Every one is guarded by the output-length check in §3 (out >= 4, 6, 8). Writes are within the buffer.
2. SystemBuffer writes from `FUN_140001188` (0x2220BC, dump 168, 185): `*param_5 = count` and `param_5[k]` for k <= count. Guard: `param_3 >= (count+1)*4` (169), where param_3 = OutputBufferLength. Else only `*param_4 = 4`.
3. Device-returned descriptor copy (0x222090): `ExAllocatePool(len)` then `memmove(SystemBuffer+4, pool, len)` at dump 719-720. The copy length is the device-supplied ushort. It is only performed when `len+4 <= OutputBufferLength` (718). Source is driver pool holding device data; the caller controls only the index byte.
4. URB transfer buffers (0x2220D8, 0x2220DC, 0x2220E4, 0x2220E8, and 0x222080): the buffer is a SystemBuffer offset and the length is caller-supplied. Bounds are enforced in the dispatcher: `len + 0x10 <= InputBufferLength` (793, 893) or `len <= OutputBufferLength` (870, 918). The URB layer also checks `len <= endpoint max` (`FUN_140002A6C` 1467, `FUN_140002B6C` 1515). Direction comes from the device endpoint table, not from the caller. The buffer stays inside the SystemBuffer allocation (size max(in,out)).
5. Configuration table rebuild (`FUN_140002CE4`, reached from 0x2220B8, dump 1575-1683): writes into pool allocations sized from device-supplied descriptor lengths. `memmove` at dump 1663-1664 and 1667-1668 uses the same length as the allocation (1661, 1665). Lengths come from the device, not the caller.
6. Fixed-offset writes into the device extension (ext+0x5C, 0x68, 0x70, 0x78, 0x80..0x88 queue) and into IRP fields (IoStatus at +0x30/+0x38): dump 44, 232-241, 339-378, 418-454, 518, 569-571, 595-608, 972-984, 1181-1199, 1273-1278, 1306-1379, 1600-1675. These are kernel structures at fixed offsets.
7. Lower-stack URB writes (`FUN_1400026D4`, `FUN_14000283C`): fields of driver-owned URB and IRP structures only.

Conclusion: no write uses a caller-supplied destination pointer, offset or value. All SystemBuffer writes are length-checked against the buffer allocation, and the length fields of the two copy routes are device-supplied (memmove) or bounded (URB). No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection` or `MmGetPhysicalAddress` exists in the imports, and no computed kernel-VA write was found in the decompile.

## 6 Most dangerous exposed capability

The highest-impact exposed behavior is a re-selection of the device configuration (0x2220B8) and raw URB transfers (0x2220D8-0x2220E8). These act on the attached USB device and write only into the SystemBuffer allocation (bounded). No kernel memory write follows from them.

## 7 Verdict

**NO-MEMORY-WRITE.** Reach R3 (devnode/hardware); Setup required: hardware; Write quality W0; load: Authenticode Valid, WHQL-chain signature. HW-only: no (the device I/O is USB transfer only; no HW-ONLY writes).

## 8 Limitations

- The lower stack (USBD / USB bus driver) is not analyzed. URB semantics are taken from the driver's own field writes only.
- DRIVER_OBJECT+0x68 (DriverUnload) label `_guard_check_icall` is unresolved (§2).
- Off-by-one read in 0x2220EC: `FUN_140002278` tests `count < iface` (dump 1010), so iface == count passes and reads the entry at +0x20+count*0x18 (1014). That is a read of the table one entry past the end, and its value is passed to USBD as a handle. It is not a kernel write. The value depends on pool contents, which the driver does not set. Recorded as an unresolved read-only issue.
- PnP, power, start, close and completion routines (`FUN_140001620`, `FUN_140001770`, `FUN_1400014B0`, `FUN_1400017F0`, `FUN_1400018DC`, `FUN_140001408`, `FUN_140001280`, `FUN_140002600/630`, `FUN_14000234C`, `FUN_1400023C4`) were checked by the write-grep and by spot reads. They are kernel-initiated and not reachable from IOCTLs.
- No REA session used. No execution, no driver load, no registry writes.
