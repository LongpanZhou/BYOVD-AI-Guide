# Audit: deckaud_D525B6F1.sys

| Field | Value |
|---|---|
| File | drivers\deckaud_D525B6F1.sys |
| SHA-256 | D525B6F19557D07E5DB1ECB3F1024C26698C01C9348985DE9D87970652D32D33 |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\deckaud_D525B6F1.txt`, complete). Import triage; grep of the dump for IOCTL comparisons, outbound device-control builders, mapping calls and security calls. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Blackmagic Design; file version 15.3.1; "DeckLink Audio Driver" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher |
| Reach | R3 (devnode / hardware: a DeckLink card must be present for the adapter to start) |
| Setup required | hardware |
| Write quality | W0 (provisional: no caller-controlled kernel write found in the traced code; see section 8) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL) |
| HW-only | no |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 PortCls audio adapter (portcls imports: `PcInitializeAdapterDriver`, `PcAddAdapterDevice`, `PcRegisterSubdevice`, `PcRegisterPhysicalConnection`, `PcNewPort`, `PcNewMiniport`, `PcRegisterAdapterPowerManagement`, `PcNewServiceGroup`).
- ntoskrnl imports: IRP and synchronous FSD builders, `IoGetDeviceInterfaces`, `IoGetDeviceObjectPointer`, `IoGetDeviceAttachmentBaseRef`, `IoSetDevicePropertyData`, `ObfDereferenceObject`, `ExAllocatePoolWithTag`, `KeInitializeMutex`, `ExAllocateTimer`.
- No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress, ZwSetSecurityObject, memcpy or memmove import.

## 2 Entry / device / interface / effective DACL

- Adapter FDO created by `PcAddAdapterDevice` (portcls). The driver does not call `IoCreateDevice` or `IoCreateSymbolicLink` (no such call in the dump). Interfaces are enumerated with `IoGetDeviceInterfaces`.
- No SDDL string and no `ZwSetSecurityObject` in the image. Effective DACL: default (PortCls/PnP), not fixed by the driver.

## 3 Dispatch and IOCTL table

- No custom IOCTL dispatch: a grep of the dump for `== 0x22xxxx` and `== 0x2xxxxx` case labels returns none. The user surface is KS (through PortCls).
- Outbound device-control requests built by the driver (lower stack, not user input):

| Dump line | Code | Input bytes | Output bytes | Note |
|---|---|---|---|---|
| 1773 | 0x222018 | 0x10 (local_90+1) | 8 (local_90) | Sent to the lower device; both sizes are constants. |
| 1848 | 0x222043 | 0 | 8 (`param_1 + 0x50`) | Sent to the lower device with a fixed 8-byte output. |
| 48 | IRP_MJ 0x1B (synchronous FSD request) | - | - | Internal request builder. |

| Code | Method | Access | Input | Output | Kernel action |
|---|---|---|---|---|---|
| none defined by the driver | - | - | - | - | KS-managed; outbound codes above only. |

## 4 Access-control audit

- No privilege or caller-identity check in the driver. Access is governed by PortCls, KS and default device security (section 2).

## 5 Memory-write trace

- No mapping API and no memcpy/memmove imports, so no mapped or bulk copy into kernel memory is visible.
- The outbound IOCTLs (section 3) use constant buffer sizes. Driver-state writes are fixed-offset.
- `_vsnwprintf` (dump 189, 529-536) formats strings into a caller-sized destination (`_Count`); the destination and count are driver-internal.

## 6 Most dangerous exposed capability

- Not established. The KS stream and property paths (through PortCls) are the user surface and were not traced in this pass.

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** No caller-controlled kernel write found in the traced code. Reach R3 (devnode / hardware); Setup: hardware; W0 in the traced code. HW-only: no.

## 8 Limitations

- The PortCls miniport KS property and stream handlers (the user surface) are not traced.
- No REA session used. No execution, no driver load, no registry writes.
