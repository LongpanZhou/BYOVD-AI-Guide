# Audit: mxusbd,1_477EA31C.sys

| Field | Value |
|---|---|
| File | drivers\mxusbd,1_477EA31C.sys |
| SHA-256 | 477EA31CC924DC56361B0460994443DA9A63C2B61D88BC3619D2035479CD905F |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\mxusbd_1_477EA31C.txt`, complete; scratch stem `mxusbd_1_477EA31C`). Device creation (dump 133, 262), dispatch slot (100), IOCTL switches (dump 2063-3140, 3582-4088), and the 0x1B2000 / 0x1B2040 / 0x1B2044 / 0x1B2054 cases read in full (dump 2931-2945, 3078-3143). Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Moxa Inc.; file version 4.1 build 23090720; "MOXA UPort Series Windows Driver" |
| Signature | Authenticode Valid; signer CN=MOXA INC. |
| Reach | R3 (devnode / hardware: a Moxa UPort USB-serial adapter must be attached so that a port structure exists at the index the caller selects). Device-interface ACL not fixed in the image. |
| Setup required | hardware |
| Write quality | W2 (out-of-bounds write into the SystemBuffer pool allocation; the overrun length and the record offsets are controlled by the caller's index range; the record values are device-state fields) |
| Severity | MW3 (`reach=R3 setup=hardware write=W2 load=signed`) |
| HW-only | no (the write is a kernel pool write, not a hardware-only write) |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 WDM serial / USB port driver (Moxa UPort family; the IOCTL switch has two families: 0x1B00xx serial codes and 0x1B2000-0x1B2054 vendor codes). Imports include `USBD_CreateConfigurationRequestEx`, `IoCreateDevice`, `IoCreateSymbolicLink`, `IoRegisterDeviceInterface`, `IoSetDeviceInterfaceState`, `ZwCreateFile`, `IoBuildDeviceIoControlRequest`, `RtlWriteRegistryValue`, `MmGetSystemRoutineAddress`, `WmiSystemControl`, `WmiCompleteRequest`.
- No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress, ProbeForWrite, memcpy or memmove import. No `ZwSetSecurityObject`, no SDDL string.
- Dispatch: `*(param_1+0xE0) = FUN_140003840` (dump 100).

## 2 Entry / device / interface / effective DACL

- `IoCreateDevice(DriverObject, 0x508, 0, DeviceType 0x2A, 0, Exclusive 1, &device)` at dump 133: unnamed FDO, exclusive.
- `IoRegisterDeviceInterface(PDO, &DAT_14000D300, 0, …)` at dump 262. The interface GUID is at VA 0x14000D300 (not decoded in this pass).
- No SDDL string and no security call in the image. Effective DACL: the PnP device-interface default (not fixed by the driver).

## 3 Dispatch and IOCTL table

Two IOCTL switches (dump 2063-3140 and 3582-4088) use the same serial family (0x1B0008-0x1B009C), with the vendor family (0x1B2000, 0x1B2018, 0x1B2040, 0x1B2044, 0x1B2048, 0x1B2054) in the first switch. Codes are METHOD_BUFFERED (low bits 0) with FILE_ANY_ACCESS (bits 14-15 zero). Read cases:

| IOCTL | Input gate | Output gate | Kernel action (dump lines) |
|---|---|---|---|
| 0x1B2000 | - | output >= 4 (2932) | Writes DWORD 0x406 to SystemBuffer[0] (2933). Info 4 (2936). Bounded. |
| 0x1B2040 | input > 3 (3079) | **none** | Reads start index `puVar5[0]` and end index `puVar5[1]` (ushort, 3081-3083). For each index k from start to end (loop 3091-3116), when port structure `lVar11 = *(*(lVar3+0x298+k*8)+0x40)` is non-null, writes a 16-byte record at SystemBuffer + 16×(k − start) (writes at puVar15[-2..1], 3095-3109). Information = 16×(end − start + 1) (3118). **See §5.** |
| 0x1B2044 | device flag (2941); input >= 4 (2942) | - | Calls `FUN_14000AD44` with fixed arguments (2943-2945). Info 0. |
| 0x1B2054 | input > 3 and output > 0x23 (3127) | output >= 0x24 | Reads port flags (3129-3143) and writes fixed fields to the output. Bounded. |
| 0x1B0050 .. 0x1B009C | as in the serial family | as in the serial family | Not traced in full (dump 2482-2935, 3892-4088). |

## 4 Access-control audit

- No privilege or caller-identity check in the IOCTL path. Reach depends on who can open the device object through its PnP interface (not fixed in the image).

## 5 Memory-write trace

**0x1B2040 out-of-bounds write (dump 3078-3118).**

1. The SystemBuffer is `puVar5` (`*(IRP+0x18)`), a METHOD_BUFFERED pool allocation of size `max(InputBufferLength, OutputBufferLength)`.
2. Only `InputBufferLength > 3` is checked (3079). `OutputBufferLength` is not checked anywhere on this path.
3. The caller supplies `start` (`puVar5[0]`) and `end` (`puVar5[1]`), with `start <= end` (3084). The loop visits every index k from `start` to `end`. A record is written only when the port structure at index k exists (`lVar11 != 0`, 3094) and the loop stops after index 0x100 (3092).
4. Each written record is 16 bytes at byte offset `16 × (k − start)` from SystemBuffer (the first record at offset 0). The last write for an existing port at index k ends at `16 × (k − start + 1)`.
5. If that end exceeds the allocation size `max(in, out)`, the write overruns the pool allocation. With the minimum InputBufferLength of 4 and OutputBufferLength 4, the allocation is 4 bytes; a write for an existing port at index k overruns by `16 × (k − start + 1) − 4` bytes.
6. **Caller control:** the overrun length and the offset of each record are set by `start` and `end`; the overrun exists only when a port structure exists at an index in that range (device state, attached hardware). **Value control:** the record fields are port-state values (dump 3095-3102: flags and counters from the port structure at +0x4C7C, +0x4C78, +0x8F6C, +0x8F68, +0x4E98, +0x4EA9). The values are constrained to device-state data; they are not caller-chosen.
7. Information is set to `16 × (end − start + 1)` (3118), which can also exceed the output length; the I/O manager copies no more than the output length back to the caller, so the information value does not widen the write.

Classification: pool out-of-bounds write (W2: size and offset controlled through the caller's index range; values constrained to device state; target is the adjacent pool memory of the SystemBuffer). Requires an attached UPort device (R3 hardware).

Other IOCTL cases read (0x1B2000, 0x1B2044, 0x1B2054) are bounded.

## 6 Most dangerous exposed capability

- IOCTL 0x1B2040: pool overrun by up to 16 × 256 bytes past a small SystemBuffer, with the overrun length set by the index range and the content set by port-state fields, on any system with a UPort device attached at a chosen index.

## 7 Verdict

**MW3 — reach=R3 setup=hardware write=W2 load=signed.** The rated primitive is the unchecked OutputBufferLength on IOCTL 0x1B2040 (§5). The image is Authenticode-signed (Valid). HW-only: no.

## 8 Limitations

- The rest of the serial switch (0x1B0050-0x1B009C, dump 2482-2935 and 3892-4088) was not traced in full; the sibling family (`deckser_65A92D8F`, `mxuport,1_5B845038`) showed fixed-size output writes.
- The port-structure array (`lVar3+0x298`) population and maximum were not resolved; the write requires an attached device at the index in range.
- The device-interface default ACL (who may open the device) was not determined from the image; the reach label R3 reflects the hardware requirement.
- `FUN_14000AD44` (0x1B2044) and the `FUN_140003840` dispatch wrapper were not read in full.
- No REA session used. No execution, no driver load, no registry writes, no exploit developed.
