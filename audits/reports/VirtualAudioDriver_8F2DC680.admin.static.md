# Audit: VirtualAudioDriver_8F2DC680.sys

| Field | Value |
|---|---|
| File | drivers\VirtualAudioDriver_8F2DC680.sys |
| SHA-256 | 8F2DC680B0D218A18923F56D0B51D43729105072D4676436EB4B697FDFBB9AF3 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\VirtualAudioDriver_8F2DC680.txt`, 8,056 lines, 246 functions, complete). Import and string triage. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | "Windows (R) Win 7 DDK provider"; file version 10.0.10011.16384; "Microsoft Virtual Simple Audio Sample Driver" |
| Signature | Authenticode Valid; signer CN=SignPath Foundation |
| Reach | R3 (devnode: a PnP audio adapter created through the INF / PortCls path) |
| Setup required | devnode |
| Write quality | W0 (no caller-controlled kernel write found in the traced code; PROVISIONAL, see §8) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL) |
| HW-only | no |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 PortCls / KS audio sample driver built on the Fx (KMDF) stub (`FxDriverEntryWorker` dump 1455, `FxStubDriverUnload` dump 1524).
- Imports: ntoskrnl (`IoRegisterDeviceInterface`, `ZwCreateFile`, `ZwWriteFile`, timers, registry, work items), portcls (`PcInitializeAdapterDriver`, `PcAddAdapterDevice`, `PcNewPort`, `PcNewMiniport`, `PcRegisterSubdevice`, `PcRegisterPhysicalConnection`, `PcDispatchIrp`, `PcGetPhysicalDeviceObject`), HAL (`KeQueryPerformanceCounter`), USBD-free.
- No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress, MmGetSystemRoutineAddress, ProbeForWrite, RtlCopyMemory or memcpy import.
- Entry: `entry @ 140002530` (dump 1444) → `FxDriverEntryWorker` (dump 1455-1513, calls `RtlCopyUnicodeString` at dump 1477 for the registry path).

## 2 Entry / device / interface / effective DACL

- Adapter device: `PcAddAdapterDevice` (portcls) creates the FDO; the driver never calls `IoCreateDevice` itself. Subdevices and ports are registered through `PcRegisterSubdevice` / `PcNewPort` / `PcNewMiniport`.
- Interface: `IoRegisterDeviceInterface` (portcls path). No symbolic link is created by the driver and no SDDL or `ZwSetSecurityObject` appears in the image. Effective DACL: default, set by PnP and PortCls; not fixed in the image.

## 3 Dispatch and IOCTL table

- IRP dispatch: `PcDispatchIrp` (dump 3091) handles the IRP path for the PortCls-managed device. The driver does not install its own IRP_MJ_DEVICE_CONTROL routine: no `0x22xxxx` IOCTL codes and no `IoControlCode` comparisons appear in the decompile (grep: none).
- User-reachable surface is KS (property, method, event and stream IRPs routed by PortCls to the miniport). KS property handlers are not traced in this pass (§8).

| Code | Method | Access | Input | Output | Kernel action |
|---|---|---|---|---|---|
| none defined by the driver | - | - | - | - | No custom IOCTL dispatch. Requests go to PortCls via `PcDispatchIrp` (3091). |

## 4 Access-control audit

- No privilege checks in the driver. Access is governed by the KS / PortCls device and the default device security (§2).

## 5 Memory-write trace

- Writes to fixed kernel structures and the miniport state (timers, spin locks, registry values) were not enumerated individually in this pass.
- `ZwWriteFile` sites (dump 7181, 7212, 7215, 7219): debug/log writes to a file handle; the length is a fixed 0x14 or 8 bytes at 7212 and 7219, and the buffer at 7181 is an internal parameter. No caller-controlled length or destination.
- No `memcpy`/`memmove`/`RtlCopyMemory` imports and no calls resolved to a named copy routine in the grep.

## 6 Most dangerous exposed capability

- Not established in this pass. The KS stream path (audio data copied from the KS stream buffer into the miniport ring) is the largest data path and is not traced.

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** No caller-controlled kernel write found in the traced code. The KS property and stream handlers (the user surface) are not traced, so this verdict is not final. Reach R3 (devnode); Setup: devnode; W0 in the traced code. HW-only: no.

## 8 Limitations

- PortCls miniport property/method/stream handlers (the KS surface) are not traced. These are where a user-sized copy into a kernel buffer would sit if one exists.
- The Fx stub's DriverEntry path and PortCls registration callbacks were read only at the level of imports and call sites.
- No REA session used. No execution, no driver load, no registry writes.
