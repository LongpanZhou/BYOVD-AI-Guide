# Audit: megasr.sys (LSI MegaRAID Software RAID / MegaSR)

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\megasr.sys` |
| SHA-256 | `8A902DDB6016E4D5C28808FBA5741751D94FFBD4B55724D47BBA0A8C29900E53` (575,800 bytes; matches `indexes/drivers_manifest.csv`) |
| Analysis date | 2026-10-25 |
| Method | Static-only: local Ghidra 12.1.4 headless analysis plus `llvm-objdump` 20.1.5 and direct PE parsing. **REA was not used**: four REA audits were already active and the bridge was at capacity. No load, execution, service creation, registry write, or web lookup. |
| Reach tier | **R3 (hardware)** - the port device only exists when a supported MegaRAID/ESRT2 PCI controller is present; a local administrator (**R2**) is the practical opener of the storage device. |
| Setup required | **hardware** |
| Write quality | **W3** (fixed-value, fixed-offset kernel pool store; constrained size/offset) |
| Verdict | **MW4** - `MW4 - reach=R3 setup=hardware write=W3 load=signed` |
| Loadability | Signed, Authenticode **Valid** (Microsoft Windows / WHQL), timestamp 2025-06-19; hash **not** in `indexes/dedupe/known_bad_hashes.txt`. `INIT` is RWX/discardable (era-typical); HVCI was not dynamically tested. |
| HW-only | **No** - the confirmed primitive is a CPU store into nonpaged pool. `StorPortGetDeviceBase`/BAR MMIO is HW-ONLY and is not counted. |
| Historical baseline | `audits/reports/megasr_rea.md` - **requested but not present on disk** (searched `audits/` recursively; no `megasr` report exists). No verdict was inherited. `audits/STATUS.md:123` lists `megasr` as an original-corpus gap assigned to offline Ghidra/objdump. |

## Coverage statement

The image is large: `.text` is `0x699ba` bytes (432,570 bytes) and the `.pdata` table contains 1,275 `RUNTIME_FUNCTION` entries (0x3bc4 / 12). This was a time-boxed pass, not a line-by-line review of the whole binary.

- **Reviewed in depth (~70 functions):** `DriverEntry`/`StorPortInitialize` setup, `HwStartIo` dispatch, the complete `SRB_FUNCTION_IO_CONTROL` handler and all eight inner vendor opcodes, the `SRB_FUNCTION_WMI` handler and the standard `scsiwmi` library, the `SRB_FUNCTION_EXECUTE_SCSI` path, the request/SGL allocator/queue routines, and the six supporting response builders.
- **Coverage estimate:** ~100% of the user-reachable SRB dispatch, `IOCTL_SCSI_MINIPORT`, and WMI entry surface; ~80% of the vendor `SRB_IO_CONTROL` command surface (all eight control codes traced); ~15-20% of total functions. The SCIC/SCIF state machine and hardware-event engine (the majority of `.text`) were sampled through strings, call graph, and the factories that build SCIF requests, not exhaustively decompiled.
- I stopped at this cap rather than stalling. The untraced remainder is predominantly device-event/state-machine code whose data comes from the controller, not directly from the caller.

## 1 Internals

- PE32+ x64, image base `0x10000`, 7 sections, entry RVA `0x62774` (VA `0x72774`), linker/subsystem 6.3, build date 2013-06-03 (file strings report driver version `15.02.2013.0125`).
- Imports are minimal: `storport.sys` (15 functions: `StorPortInitialize`, `StorPortGetDeviceBase`, `StorPortGetPhysicalAddress`, `StorPortGetScatterGatherList`, `StorPortGetUncachedExtension`, `StorPortNotification`, etc.) and `ntoskrnl.exe!ExSystemTimeToLocalTime`. There is **no** `IoCreateDevice`/`IoCreateDeviceSecure`, no `SeAccessCheck`/`SeSinglePrivilegeCheck`, no `MmMapIoSpace`, no `MmMapLockedPagesSpecifyCache`, no `MmCopyMemory`, and no `ZwMapViewOfSection`.
- `DriverEntry` (`0x72774`) runs the CRT/INIT stub at `0xfa008` and jumps to `0x11008`. At `0x11054` it zeroes a `0xd0`-byte `HW_INITIALIZATION_DATA`; the function pointers are `HwInitialize=0x1118c` (`0x1106a`), `HwStartIo=0x121a8` (`0x11099`), `HwInterrupt=0x130c4` (`0x11092`), `HwFindAdapter=0x118dc` (`0x1106f`), `HwResetBus=0x13584` (`0x110a5`), `HwAdapterState=0x11180` (`0x110bb`), with `SrbExtensionSize=0x10` (`0x110fe`). It then loops 30 adapter descriptors at `0x8c528` (stride `0x30`) and calls `StorPortInitialize` through the IAT slot `0x7b048` (`0x11142`).
- The 30 descriptors encode supported PCI IDs, including Intel ICH/ESRT2 functions (`8086:27c3`, `2925`, `3a25`, `2822`, `2826`, `3b25`, `3b2c`, `1c04`, `1d04`, `1c05`, `1e06`, `8c04`, `8c06`, `8c0e`, `1d3e`, `2682`, `2683`, `1d60`-`1d6f`) and LSI SAS (`1000:0057`, `0059`, `0055`). This is the hardware gate.
- There is no driver-owned device object, no symbolic link, no FSCTL, and no `IRP_MJ_DEVICE_CONTROL` dispatch. All user I/O arrives through StorPort, which converts storage IOCTLs into SRBs and calls `HwStartIo` (`0x121a8`).

## 2 Entry / device / interface / effective DACL

- **Device/interface:** StorPort creates the port device (typically `\Device\Scsi\PortN`, exposed as `\\.\ScsiN` and via the disk PDOs such as `\\.\PhysicalDriveN`). The miniport only registers callbacks; it never creates or secures the object. `HwFindAdapter` (`0x118dc`) must match one of the 30 PCI IDs before any device exists.
- **Effective DACL:** StorPort's default storage-port security descriptor. The miniport contributes no SDDL and no access check. `IOCTL_SCSI_MINIPORT` is `CTL_CODE(IOCTL_SCSI_BASE, 0x0402, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)` = **`0x4D008`**; `IOCTL_SCSI_PASS_THROUGH` = **`0x4D004`**; `IOCTL_SCSI_PASS_THROUGH_DIRECT` = **`0x4D014`**. All require `FILE_READ_ACCESS|FILE_WRITE_ACCESS` on the handle, so the practical opener is a local administrator (or SYSTEM). This is **R2 access behind an R3 hardware gate**.
- **Protocol gate, not a security gate:** the `SRB_IO_CONTROL` handler requires the 8-byte `Signature` `"LSILOGIC"` at buffer+4 (`0x123b2`, compared against `0x72d70`). That is a magic value any opener can satisfy; it is not authentication.
- `IOCTL_SCSI_GET_INQUIRY_DATA`, `GET_CAPABILITIES`, and `GET_ADDRESS` are `FILE_ANY_ACCESS` and are serviced by StorPort itself; they do not reach the miniport's data path. The newer `IOCTL_SCSI_MINIPORT_HYBRID/FIRMWARE/DIAGNOSTIC` codes post-date this 2013 miniport and are not handled by it.

## 3 Dispatch and IOCTL table

The driver itself has no `IRP_MJ_DEVICE_CONTROL` handler; StorPort turns the storage IOCTLs into SRBs. The user-to-kernel IOCTL mapping is:

| User IOCTL | Code | Method | Access | Input / output | Kernel path |
|---|---:|---|---|---|---|
| `IOCTL_SCSI_MINIPORT` | `0x4D008` | `METHOD_BUFFERED` | `FILE_READ_ACCESS \| FILE_WRITE_ACCESS` | input `>= 0x1c` (`SRB_IO_CONTROL`); output is caller-sized; the miniport imposes no output-length check | `SRB_FUNCTION_IO_CONTROL` -> `0x12388` |
| `IOCTL_SCSI_PASS_THROUGH` | `0x4D004` | `METHOD_BUFFERED` | `FILE_READ_ACCESS \| FILE_WRITE_ACCESS` | `SCSI_PASS_THROUGH` header + data; `DataTransferLength` comes from the request | `SRB_FUNCTION_EXECUTE_SCSI` -> `0x12480` |
| `IOCTL_SCSI_PASS_THROUGH_DIRECT` | `0x4D014` | `METHOD_BUFFERED` in the current header (historically `METHOD_OUT_DIRECT`) | `FILE_READ_ACCESS \| FILE_WRITE_ACCESS` | `SCSI_PASS_THROUGH_DIRECT` header + user data MDL | -> `0x12480` |
| `IOCTL_SCSI_GET_INQUIRY_DATA`, `GET_CAPABILITIES`, `GET_ADDRESS` | - | `METHOD_BUFFERED` | `FILE_ANY_ACCESS` | StorPort-owned | serviced by StorPort; not forwarded to the miniport data path |
| `IOCTL_SCSI_MINIPORT_HYBRID` / `_FIRMWARE` / `_DIAGNOSTIC` | - | - | - | post-2013 codes | not handled by this miniport |

No `METHOD_NEITHER` IOCTL reaches this image.

`HwStartIo` (`0x121a8`) reads the SRB function byte at SRB+2 (`0x121e5`) and dispatches:

| SRB function | Value | Handler | Action |
|---|---:|---|---|
| `SRB_FUNCTION_EXECUTE_SCSI` | `0x00` | `0x12480` (via `0x1228a`/`0x122a2`) | Builds a SCIF IO request from the SRB CDB and data buffer. Special-cases PathId/TargetId/Lun `3/3/0` with CDB `0x12` (INQUIRY) into a fixed synthetic response. |
| `SRB_FUNCTION_IO_CONTROL` | `0x02` | `0x12388` (via `0x12280`) | The vendor management plane: `SRB_IO_CONTROL` + MegaRAID packet. |
| `SRB_FUNCTION_SHUTDOWN` | `0x07` | `0x13620` (via `0x12272`) | Adapter shutdown/reset path. |
| `SRB_FUNCTION_FLUSH` | `0x08` | inline `0x1226a` | Completes successfully; no data buffer use. |
| `SRB_FUNCTION_ABORT_COMMAND` | `0x10` | `0x14568` (via `0x12228`) | Terminates the referenced SCIF request (`SrbExtension[0]`); no caller buffer write. |
| `SRB_FUNCTION_RESET_BUS` | `0x12` | inline `0x122a9` | No-op success (reset completion); no data-buffer use. |
| `SRB_FUNCTION_WMI` | `0x17` | `0x13f2c` (via `0x1221e`) | Standard `scsiwmi` query/execute-method path; `SCSI_WMI_REQUEST_BLOCK` Length must be `0x58`. |
| anything else | - | `0x122fb` | `SrbStatus=5` (`SRB_STATUS_INVALID_REQUEST`) and complete. |

The vendor `SRB_IO_CONTROL` protocol (all in `0x12388` -> `0x13be0` or `0x13878`):

| Outer `ControlCode` (buffer+0x10) | Inner opcode (buffer+0x34) | Handler | Kernel action |
|---|---|---|---|
| `0xF0010000` or `0xF0020000` | `0xF0010100` | `0x1431c` | Writes fixed identification strings at `buffer+0xbc` up to `+0x67`. |
| `0xF0010000` or `0xF0020000` | `0xF0010200` | `0x14210` (`0x13c7a`) | `memset(buffer+0xbc, 0, 0x70)` then fixed adapter fields. |
| `0xF0010000` or `0xF0020000` | `0xF0010300` | `0x143f8` (`0x13c70`) | **`memset(buffer+0xbc, 0, 0x600)`** then eight adapter-derived dwords at `+0x0/0x100/0x200/0x300/0x400/0x500`. |
| `0xF0010000` or `0xF0020000` | `0xF0010400` | `0x13c68` | `*(u32 *)(buffer+0xbc) = 0`; success. |
| `0xF0010000` or `0xF0020000` | `0xF0010500` | `0x13c51` | No write; returns `SrbStatus=4` (`SRB_STATUS_ERROR`), ReturnCode `3`. |
| `0xF0010000` or `0xF0020000` | `0xF0020100` | `0x13d17` | `StorPortNotification(BusChangeDetected, adapter, byte at buffer+0x38)`. |
| `0xF0010000` or `0xF0020000` | `0xF0020200` | `0x13c9b` | Copies a byte/word from `buffer+0xbc` into fixed adapter fields `+0x390c/+0x390f`; may install a fixed callback at `adapter+0x1e28`. |
| `0xF0010000` or `0xF0020000` | `0xF0020300` | `0x13c8e` | `*(u32 *)(buffer+0xbc) = adapter[0] & 7`. |
| any other inner opcode | - | `0x13878` (`0x12419`) | MegaRAID DCMD/data path: length from buffer+0x30, data VA from buffer+0xbc, SGL built with `StorPortGetPhysicalAddress`, request queued at `0x17af8`. |

`SRB_IO_CONTROL` is `0x1c` bytes: HeaderLength `+0x00`, Signature `+0x04`, Timeout `+0x0c`, ControlCode `+0x10`, ReturnCode `+0x14`, Length `+0x18`. The driver reads `+0x10` (`0x12406`) and the fixed payload offsets `+0x30`, `+0x34`, `+0x38`, `+0xbc`, but **never reads `+0x18`**.

## 4 Access-control audit

- No `SeSinglePrivilegeCheck`, `SeAccessCheck`, `FILE_WRITE_ACCESS` test, caller-identity check, or capability check exists in the image (the import table has no such APIs).
- No SDDL is applied. The object is StorPort's; the only gate is its DACL plus the hardware. A local administrator can open the port device with read/write access.
- The `"LSILOGIC"` signature and the `0xF001/0xF002` control-code family are protocol constants, not secrets.
- The hardware gate is real: without a supported PCI RAID controller, `HwFindAdapter` never matches, StorPort never creates the device, and the IOCTL is unreachable. There is no software-only or devnode-only path in this image.

## 5 Memory-write trace

### 5.1 Primary - fixed-offset 0x600-byte nonpaged-pool zero-fill (confirmed static)

1. `HwStartIo` routes `SRB_FUNCTION_IO_CONTROL` to `0x12388` (`0x12280`).
2. `0x12388` checks only `SRB->DataTransferLength >= 0x1c` (`0x12392`, branch at `0x1239d`), then compares `"LSILOGIC"` at DataBuffer+4 (`0x123b2`-`0x123d9`) and blanks it with eight spaces (`0x123e1`-`0x123fc`).
3. It reads the outer `ControlCode` at DataBuffer+0x10 (`0x12406`) and accepts the `0xF0010000`/`0xF0020000` family (`0x1240a`-`0x12414`). It then reads the inner opcode at DataBuffer+0x34 (`0x12420`) and, for `0xF0010300`, calls `0x13be0` (`0x1244e`).
4. `0x13be0` sets `rdx = DataBuffer + 0xbc` at `0x13bed`, re-reads the opcode at `0x13c0f`, and calls `0x143f8` at `0x13c70`.
5. `0x143f8` executes `memset(DataBuffer + 0xbc, 0, 0x600)` at `0x14414`-`0x1441f` (size `0x600` loaded at `0x14416`), then writes eight adapter-derived dwords at offsets `+0x0/+0x100/...+0x500` within that range.
6. `0x13d34`-`0x13d43` sets `SrbStatus=1` (success) and `ReturnCode=0`; the OOB write is completed before the success status.

**Trigger geometry:** a buffered `IOCTL_SCSI_MINIPORT` input whose `SRB_IO_CONTROL` passes the `0x1c` check, carries `"LSILOGIC"` at +4, outer `ControlCode 0xF0010000` at +0x10, and inner opcode `0xF0010300` at +0x34. The smallest such buffer is `0x38` bytes. The write then covers `DataBuffer+0xbc` through `DataBuffer+0x6bb`: for a `0x38`-byte system buffer, every byte of the `0x600` fill is out of bounds (0x84 bytes past the end at the start, 0x683 at the end). The driver never compares `DataTransferLength` with `0xbc + 0x600`, and never uses `SRB_IO_CONTROL.Length`.

**Control:** target = fixed offset from the caller-sized nonpaged system buffer (not a caller-selected address); value = zero for the bulk, with eight non-caller-controlled adapter dwords; size = fixed `0x600`. This is a genuine kernel pool write (zero-fill) but not a write-what-where.

The same unchecked-offset pattern gives smaller variants:
- `0xF0010400` -> `*(u32 *)(DataBuffer+0xbc) = 0` (`0x13c68`).
- `0xF0020300` -> `*(u32 *)(DataBuffer+0xbc) = adapter[0] & 7` (`0x13c8e`).
- `0xF0010100` -> fixed strings at `DataBuffer+0xbc` up to `+0x67` (`0x1431c`, writes begin at `0x1433b`).
- `0xF0010200` -> `memset(DataBuffer+0xbc, 0, 0x70)` (`0x14231`-`0x14235`).

### 5.2 Secondary - short INQUIRY buffer for the synthetic 3/3/0 target (confirmed static, conditional routing)

In the `SRB_FUNCTION_EXECUTE_SCSI` handler (`0x12480`):

- `0x1249c`-`0x124c9` matches TargetId `3`, PathId `3`, Lun `0`, and CDB[0] `0x12` (INQUIRY).
- `0x124de`-`0x124ee` takes `SRB->DataTransferLength` (SRB+0x10) and `SRB->DataBuffer` (SRB+0x18) and zeroes exactly `DataTransferLength` bytes.
- It then writes a fixed 0x24-byte synthetic response without checking `DataTransferLength >= 0x24`: first byte OR `0x1f` (`0x12503`), 8 bytes at +0x8 (`0x12515`), 4 bytes at +0x20 (`0x12537`), and 0x12 bytes at +0x10 (`0x12556`).
- A short `IOCTL_SCSI_PASS_THROUGH` data buffer (e.g., 1 byte) makes the `+0x20..+0x23` store and the 0x12-byte copy out of bounds. For a buffered pass-through the destination is the kernel system buffer; for a direct pass-through it is the user MDL. This is a fixed-content OOB write (W3-class), conditional on StorPort routing an SRB for the synthetic 3/3/0 target.

### 5.3 SCIC/SCIF DCMD path - resolved by `megasr.dcmd.appendix.md` (W3, not W2)

In `0x13878` (reached for any inner opcode outside the eight fixed handlers):

- `0x138de` loads the data length from `DataBuffer+0x30`; `0x138e5` sets the data VA to `DataBuffer+0xbc`.
- `0x13909` calls `StorPortGetPhysicalAddress(adapter, SRB, current_va, &chunk_len)` and stores the returned PA, VA, and length into the request's SGL at `request+0x70 + 0x18*i` (`0x13932`, `0x1393f`, `0x1394a`).
- The loop stops at 63 entries (`0x13956`), advances the VA by the returned length, and decrements the remaining length. `0x13976`-`0x13994` sets `request+0x50 = DataBuffer`, `request+0x58 = 8`, and `request+0x20 = DataBuffer+0x30` (the caller-controlled length); `0x13a2c` queues the request into the SCIF/SCIC stack.
- There is **no check** that the length at `+0x30` fits within `DataTransferLength - 0xbc`. If StorPort translates VAs beyond the SRB buffer (the driver supplies `DataBuffer+0xbc` as the start), the SGL covers pages after the buffer; a controller read command would DMA disk/firmware data into those pages, and a write command would DMA those pages to the device (info leak).
- Failure handling is also unsafe: if `StorPortGetPhysicalAddress` returns a zero length, `0x1391f`-`0x13932` substitutes the full remaining length and stores the (possibly NULL) returned PA, producing a bogus SGL entry rather than failing the request.

**Resolved (2026-10-25):** the targeted appendix `megasr.dcmd.appendix.md` traces the full
`0x13878` chain. StorPort 10.0.19041 range-checks the VA and returns NULL for out-of-buffer
addresses, so no adjacent-page DMA write occurs. The CPU copy-back is a fixed `DataBuffer+0xbc`
store with reflected/fixed content - **W3**, not W2. The overall verdict therefore remains
**MW4**; this section no longer carries an open W2 candidate.

### 5.4 WMI plane - no caller-controlled store found

- `HwStartIo` routes `SRB_FUNCTION_WMI` (0x17) to `0x13f2c`, which requires SRB Length `0x58`, `DataTransferLength >= 4`, a non-null DataBuffer, and the `WMIFlags` adapter-request bit (`0x13f45`-`0x13f80`).
- It calls the standard `scsiwmi` library at `0x72310` with the WMI subfunction, DataPath (`SRB+0x20`), DataTransferLength, and DataBuffer. The library's query path checks the output size before writing (`0x72310`, subfunction 8: `param_6 < uVar1` -> `STATUS_BUFFER_TOO_SMALL`), and its other paths pass the buffer/length to the registered callbacks.
- The driver's registered callbacks are `0x14044` (query) and `0x14174` (execute method). `0x14044` only writes a 4-byte size and a status after `param_7 >= 4`; `0x14174` changes `adapter+0x3908` and two callback pointers and does not copy caller data.
- Oddity, not a write primitive: inner opcode `0xF0020100` passes a caller-controlled byte from `DataBuffer+0x38` as the third argument to `StorPortNotification(BusChangeDetected, ...)` (`0x13d17`-`0x13d28`). For this notification type the third argument is not a data buffer; at worst it is a robustness/DoS issue, not a caller-controlled store.

### 5.5 Non-findings and residuals

- **No METHOD_NEITHER path.** The reachable IOCTLs are buffered; the miniport never dereferences a raw user pointer. Direct pass-through is converted by StorPort into an MDL/VA.
- **No MMIO/physical-memory mapping API in the driver.** `StorPortGetDeviceBase` is used for adapter BARs (HW-ONLY). There is no `MmMapIoSpace`, no `\Device\PhysicalMemory` mapping, and no caller-controlled PA. `W3P` does not apply.
- **Other physical-address callers:** `0x1148e` (HwInitialize uncached-extension setup, `0x11314`), `0x4ecff`/`0x4ede2` (SMP request buffer builder, `0x4eb4c`), and `0x5013b` (internal address helper, `0x500d8`) all operate on driver-owned or bounds-checked internal ranges; none takes a caller-controlled length. `0x4eb4c` also sizes its pool buffer from internal list entries, not from the IOCTL.
- **Normal SCSI data path:** `0x12480` uses `StorPortGetScatterGatherList` at `0x128c4` and copies the port-provided list into the fixed request frame without a driver-side cap. The request object is `0xd40` bytes (`0x16ffc`: `memset(plVar2-0x1a4,0,0xd40)`), with SGL storage at `+0x70` and 0x18-byte entries. If StorPort ever returns more entries than fit (the driver's own DCMD path deliberately caps at 63), the copy loop would overflow the request object with PA/VA/length values. StorPort normally splits I/O to the miniport's physical-break limit, so this remains a residual, not a confirmed primitive.
- The CDB copy at `0x1261e`-`0x1263b` uses `SRB->CdbLength` (SRB+0xA) into a fixed CDB area at request+0x54. StorPort bounds `CdbLength` to 16 for pass-through CDBs; the driver itself does not check it. Treated as a residual.

## 6 Most dangerous exposed capability

A local administrator on a machine with a supported MegaRAID/ESRT2 controller can send a buffered `IOCTL_SCSI_MINIPORT` request with a short `SRB_IO_CONTROL` buffer (minimum `0x38` bytes to carry the inner opcode) and select inner opcode `0xF0010300`. The driver then zero-fills `0x600` bytes starting at `DataBuffer+0xbc` without checking the buffer length, corrupting adjacent nonpaged pool, and returns success. The value is fixed zero, the offset is fixed, and the device is hardware-gated, so this is a constrained pool-corruption primitive rather than an arbitrary write. The SCIC/SCIF DCMD length trust (section 5.3) is the only candidate for a stronger, data-bearing DMA write; it remains unconfirmed.

## 7 Verdict

**MW4 - reach=R3 setup=hardware write=W3 load=signed.**

Rationale: the confirmed primitive is a real kernel memory write (a fixed-offset, fixed-value `0x600`-byte nonpaged-pool zero-fill, plus smaller fixed stores) reachable by an administrator through `IOCTL_SCSI_MINIPORT` after the hardware gate. Target, value, and size are fixed/narrow (W3), and the controller must be present (R3/hardware), so the matrix gives MW4. The fixed-offset write is not a write-what-where; the stronger W2 DMA path is unresolved and is recorded as a residual. The image is signed and not known-bad, so `BLOCKED` does not apply.

## 8 Limitations

- **REA not used.** Four REA audits were active; the bridge was at capacity. This audit is Ghidra/objdump/PE only. A future REA or dynamic pass should cross-check the `0x12388`/`0x13be0`/`0x13878` trace and the StorPort buffer sizing.
- **Historical baseline missing.** `audits/reports/megasr_rea.md` was requested but does not exist in the tree; no prior verdict was inherited.
- **StorPort allocation not fully traced.** I did not decompile StorPort's `IOCTL_SCSI_MINIPORT` handler to prove whether the SRB DataBuffer is the input system buffer or a `Length`-sized private copy. The driver-side defect is independent of that choice: it validates only `DataTransferLength >= 0x1c` and writes at `+0xbc`; both input-sized and `0x1c+Length`-sized buffers are far below `0x6bc` for a minimal request. A port-side minimum buffer of `>= 0x6bc` would neutralize the OOB, and that was not observed or proven absent.
- **Hardware not present.** No controller was available, so the IOCTL path could not be dynamically confirmed. Static-only per project rules.
- **SCIC/SCIF breadth.** The SAS/SATA state machine and hardware-event handlers (~1,200 functions) were sampled, not exhaustively reviewed. The DCMD SGL path is the part that matters for caller-controlled lengths and is covered above.
- **INQUIRY 3/3/0 path** depends on StorPort routing an SRB for the synthetic target; it was not dynamically verified.
- **HVCI/loadability** was assessed from the Authenticode signature and section flags, not by loading the image.
