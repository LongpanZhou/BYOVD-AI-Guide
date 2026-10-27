# Audit: LSI / Perc SAS miniports (original-corpus gap)

| Field | Value |
|---|---|
| File(s) | `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\lsi_sas.sys`, `lsi_sas2i.sys`, `lsi_sas3i.sys`, `lsi_sss.sys`, `percsas2i.sys`, `percsas3i.sys` |
| SHA-256(s) | `lsi_sas` `36857AFABD064196B7D2A7CFAE3696D96C1FE13431DB49ACE161E706680231DA` ; `lsi_sas2i` `7EA218BB57843B80AB5A987BA915829B8262629F72EEC84238634A016D05504E` ; `lsi_sas3i` `2EE68AFEB6D5EC98A996C1722057275C1648411898359248D390B6AA9F697AB5` ; `lsi_sss` `FFDDB7BA54C999D5689152E4EDACC838A769B6C479F0A0FCF294C8632F4E4C1F` ; `percsas2i` `D6B8116E5C920032A5926D5D047BFD72B05ACBB08E26F177A0B0E6B4EC735FA1` ; `percsas3i` `92017ECB36EAA35AC454E890734915A658EB898C95970531D43C19461BE6562B` |
| Analysis date | 2026-10-25 |
| Method | Static-only: local Ghidra 12.1.4 headless decompilation + `llvm-objdump`/PE parsing + WDK 10.0.26100 headers. **REA cross-check was not used: the shared REA bridge is at capacity (four audits active).** No load, service, registry, install, or execution. |
| Reach tier | **R3** (hardware-gated); the opener is R2 local administrator |
| Setup required | **hardware** (supported LSI/PERC HBA bound to the miniport; no driver-created device to open) |
| Write quality | **W2** (caller-controlled size and content into a fixed per-request kernel frame) for the four LSI builds; **W0** for the two PERC MegaRAID builds |
| Verdict | **MW3** - `reach=R3 setup=hardware write=W2 load=signed` for `lsi_sas`, `lsi_sas2i`, `lsi_sas3i`, `lsi_sss`; **NO-MEMORY-WRITE** - `write=W0` for `percsas2i`, `percsas3i`. Overall **MW3**. |
| HW-only | Partly - the vendor "4.00" diagnostic channel is raw port I/O + fixed-window MMIO and is `HW-ONLY`; the SG-count overflow is a real kernel pool write. |

## 1 Internals

All six images are x64 native (`machine=0x8664`, `subsystem=1`) StorPort miniports. Imports are almost entirely `storport.sys`; `percsas2i`/`percsas3i` additionally import `strstr` and `RtlIsNtDdiVersionAvailable` from `ntoskrnl.exe` (registry string parsing / OS-version selection). None imports `IoCreateDevice`, `IoCreateDeviceSecure`, `IoCreateSymbolicLink`, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, or `ZwMapViewOfSection`. Each `DriverEntry` calls `StorPortInitialize` with a `HW_INITIALIZATION_DATA` that supplies `DeviceExtensionSize` and `SrbExtensionSize`:

| File | Version | Family / architecture | DeviceExtensionSize | SrbExtensionSize |
|---|---|---|---|---|
| `lsi_sas.sys` | 1.34.03.83 | LSI Fusion-MPT SAS (SAS 3000 / 1064-1068), classic `SCSI_REQUEST_BLOCK` | 0x1368 | **0x238** |
| `lsi_sas2i.sys` | 2.00.79.82 | LSI SAS Gen2, `STORAGE_REQUEST_BLOCK` | 0x3D58 | **0x358** |
| `lsi_sas3i.sys` | 2.51.26.80 | Avago SAS Gen3, `STORAGE_REQUEST_BLOCK` | 0xB568 | **0x420** |
| `lsi_sss.sys` | 2.10.61.81 | LSI SSS PCIe/Flash (WarpDrive), `STORAGE_REQUEST_BLOCK` | 0x3B88 | **0x358** |
| `percsas2i.sys` | 6.805.03.00 | MegaRAID (PERC H730-class), classic SRB | 0x8A40 | **0x678** |
| `percsas3i.sys` | 6.604.06.00 | MegaRAID (PERC H740-class), classic SRB | 0x6DC0 | **0x700** |

The `SrbExtensionSize` values are the `HW_INITIALIZATION_DATA` field at struct offset 0x48, set in `entry`/`DriverEntry`: `lsi_sas` `0x1c001b000` (`local_98=0x1368`, `local_90=0x238`), `lsi_sas2i` `0x140001300` (`0x3d58`/`0x358`), `lsi_sas3i` `0x140001530` (`0xb568`/`0x420`), `lsi_sss` `0x00011008` (`0x3b88`/`0x358`), `percsas2i` `0x1c000f000` (`0x8a40`/`0x678`), `percsas3i` `0x140005a00` (`0x6dc0`/`0x700`).

All six are WHQL-signed by `CN=Microsoft Windows, O=Microsoft Corporation` and `Get-AuthenticodeSignature` returns `Valid`; they are HVCI-loadable and are not in `indexes/dedupe/known_bad_hashes.txt`.

## 2 Entry / device / interface / effective DACL

**No device object is created by any of these drivers.** There is no `IoCreateDevice*`, no SDDL string, no DOS-device or symbolic-link string in any of the six images (the only "device-ish" strings are `ScsiMiniPort`, `MofResource`, `DummyDevice`, and the miniport's own `lsi_*`/`PercSas3` identifiers). The drivers attach as function drivers to a PCI adapter and are reached only through the storage stack.

**Entry point.** `\\.\PhysicalDriveN` (or `\\.\ScsiN` / a volume handle) -> `disk.sys`/`classpnp` -> `IOCTL_SCSI_MINIPORT` (METHOD_BUFFERED, `0x4D008`) -> StorPort builds `SRB_FUNCTION_IO_CONTROL` with `Srb->DataBuffer` pointing at the `SRB_IO_CONTROL` in the system buffer -> miniport `HwStartIo`.

**Effective DACL.** Because the driver authors no device, there is no driver SDDL to resolve. The effective gate is the storage device's DACL from `disk.sys`/`classpnp`: by default `SYSTEM` and `Builtin\Administrators` have full access and `BUILTIN\Users` has read access; `IOCTL_SCSI_MINIPORT` requires `FILE_READ_ACCESS|FILE_WRITE_ACCESS`, so a non-admin cannot issue it, while an administrator can. There is no additional driver-level authentication beyond the `SRB_IO_CONTROL` `Signature` bytes that some control codes require; the raw-MPT control code used for the overflow (`0x806D7069`) requires **no signature at all**.

**Setup.** A physical LSI SAS / PERC controller must be present and bound to the miniport; without a device instance `StorPortInitialize` has nothing to start and `HwStartIo` is never called. Therefore `Reach=R3`, `Setup=hardware` (the opener is `R2`).

## 3 Dispatch and IOCTL / SRB_IO_CONTROL table

The user-visible IOCTL is `IOCTL_SCSI_MINIPORT` only. Inside it, the miniports dispatch on `SRB_IO_CONTROL.ControlCode` (offset 0x10) and, for some codes, on `Signature` (offset 0x04, up to 8 bytes). `Length` is at 0x18 and `Data[]` at 0x1C.

### 3.1 `lsi_sas.sys` - `HwStartIo 0x1c0003140` (Function 2 -> `StorPortSynchronizeAccess(FUN_1c0003cf0)`) -> `FUN_1c0006130`

| ControlCode | Signature required | Handler | Action |
|---|---|---|---|
| `1,2,3,4,0xA,0xB,0xC,0xD,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x3C` | `CSMIALL` / `CSMIARY` / `CSMISAS` / `CSMIPHY` | `FUN_1c000b3a8` and per-code workers | CSMI in-band management: adapter info, RAID/PHY topology, SMP pass-through, PHY statistics. Writes fixed-layout responses at fixed `Data` offsets after a declared-`Length` minimum check. |
| `0x800000FF` | none | `FUN_1c0004bb8` | adapter state / abort helper |
| `0x8043494D` | `4.00` | `FUN_1c00066b4` | adapter information block |
| `0x80646A61` | `FwDiag  ` | `FUN_1c0010684` | firmware diagnostic channel |
| `0x8069E6E1` | `InBand  ` | commands 1/2/4/8 in `FUN_1c0006130` | in-band diagnostic buffer upload/download |
| **`0x806D7069`** | **none** | **`FUN_1c00068a8`** | **raw MPT request pass-through - unchecked SG-count copy (section 5)** |
| `0x80727374` | `v93Ap6Q4` | inline in `FUN_1c0006130` | firmware-diag buffer upload; copy is bounded by `*(u32*)(ext+0x1f8)` and `Length` (`uVar2+4 <= Length`) |
| `0x80771959` | `4.00` | `FUN_1c0006130` branch | **`HW-ONLY`**: raw 32-bit MMIO store/load at `CsrBase + caller_u32`, and x86 `IN`/`OUT` at `port_base + caller_u16` (`outl 0x1c00062ea`, `inl 0x1c00062fc`); caller value at `Data+8` |

### 3.2 `lsi_sas2i.sys` - `HwStartIo 0x140002a40` (`Function=0x28`, `SrbFunction=2` -> `StorPortSynchronizeAccess(FUN_140003690)`) -> `FUN_14000c3a0`

| ControlCode | Signature required | Handler | Action |
|---|---|---|---|
| CSMI small codes | `CSMIALL` / `CSMISAS` / `CSMIARY` / `CSMIPHY` | `FUN_140013ba0` | CSMI management, as above |
| `0x800000FF`, `0x8043494D`, `0x804D4150`, `0x80646961` | none / `4.00` / OEM aliases | vendor helpers | adapter info / OEM clones |
| **`0x806D7069`** | **none** | **`FUN_140010720`** | **raw MPT pass-through - unchecked SG-count copy (section 5)** |
| `0x80727374`, `0x80727474` | `v93Ap6Q4` / alias | diag helpers | firmware-diag upload |
| `0x80771959` | `4.00` | `FUN_14000c3a0` branch | `HW-ONLY` MMIO/port I/O |

### 3.3 `lsi_sas3i.sys` - `FUN_14000e7c0`

Observed codes: `0x8043494D`, `0x804D4150`, `0x80646961`, **`0x806D7069` -> `FUN_140013810` (raw MPT pass-through, section 5)**, `0x80727374`, `0x80727474`, `0x80727574`, `0x80727676`, `0x80771959` (`HW-ONLY`). CSMI signature strings are present in `.rdata` (`0x14001e280`-`0x14001e298`) but no small-code CSMI dispatch was observed in the decompiled dispatcher.

### 3.4 `lsi_sss.sys` - `FUN_00015c0c`

Observed codes: `0x800000FF`, `0x8043494D` (`4.00`), `0x80646A61` (`FwDiag  `), **`0x806D7069` -> `FUN_000160c8` (raw MPT pass-through, section 5)**, `0x80727374`. No CSMI small-code dispatch observed.

### 3.5 `percsas2i.sys` / `percsas3i.sys`

No `SRB_IO_CONTROL` control-code compare (`0x80xxxxxx`) exists in either image. `HwStartIo` (`0x1c00040c0` / `0x14000a8a0`) routes `Function 2` into the MegaRAID management path (`FUN_1c00042b4` / `FUN_14000ab60`), which queues the `SrbExtension` (classic SRB+0x38; the extension carries the SRB at +0x500) and executes a hardware mailbox/DCMD through an indirect ops table. Copies observed in these builds are bounded by `DataTransferLength`, `CdbLength` (<=16), or device-reported counts (e.g. `FUN_1c0003da4` correctly copies `min(DataTransferLength,0x68)` to `DataBuffer`); no caller-controlled length into a fixed kernel frame was found.

## 4 Access-control audit

- **Open gate:** storage-device DACL only (SYSTEM/Administrators full; Users read). `IOCTL_SCSI_MINIPORT` needs read+write, so it is R2. No `SeSinglePrivilegeCheck`, `SeAccessCheck`, or caller-identity check in any of the six drivers.
- **Signature "gates":** 4/8-byte ASCII constants (`CSMIALL`, `CSMISAS`, `4.00`, `FwDiag  `, `InBand  `, `v93Ap6Q4`) are protocol markers, not security boundaries - they are public strings in `.rdata`, and the overflow path (`0x806D7069`) does not check one at all.
- **Hardware gate:** binding requires the physical HBA; this is the only meaningful gate and is recorded as `Setup=hardware`.
- There is no devnode created by the driver, so there is no per-device SDDL to weaken.

## 5 Memory-write trace

### 5.1 Primary: unchecked SG-count copy into the per-request extension (all four LSI builds)

`SRB_IO_CONTROL` layout used by all four: `Length` at +0x18, `Data` at +0x1C; the raw-MPT request puts a 16-bit SG count at `Data+2` and the SG list at `Data+8`. `Data` is the kernel system buffer backing the METHOD_BUFFERED `IOCTL_SCSI_MINIPORT`, so both source and destination are kernel addresses.

**`lsi_sas.sys` (classic SRB)** - `HwStartIo 0x1c0003140` case `Function==2` -> `FUN_1c0003cf0` -> `FUN_1c0006130`; `ControlCode==0x806D7069` -> `FUN_1c00068a8`:

1. `0x1c000697f` `addq $0x138,%r14` - destination = `SRB->SrbExtension` (loaded at `0x1c00068d2` from `SRB+0x38`) + `0x138`.
2. `0x1c0006963` `cmpl 0x18(%rax),%edx; jbe` - the **only** bound: computed size (`max(MaxSGList+..., count*4+8, ...)`) must be <= `SrbControl->Length`. This checks the *source* declared length, never the destination capacity.
3. `0x1c00069a7` `movzwl 0x2(%rsi),%eax`; `0x1c00069ab` `shll $0x2,%eax`; `0x1c00069ae` `movslq %eax,%r8`; `0x1c000699d` `leaq 0x8(%rsi),%rdx`; `0x1c00069b1` `call 0x1c0015f40` (`memmove`) - copies `count*4` bytes of caller data from `Data+8` to `SrbExtension+0x138`.
4. `SrbExtensionSize` is **0x238**, so only `0x238-0x138 = 0x100` (256) bytes remain at the destination. `count > 0x40` overflows; `count` is 16-bit, so the write can reach `0x3FFFC` (262,140) bytes past the start of the frame - a pool overflow of up to ~256 KB with fully caller-controlled bytes.

**`lsi_sas2i.sys` (STORAGE_REQUEST_BLOCK)** - `HwStartIo 0x140002a40` (`cmpb $0x28,2(%rdx)`; `SrbFunction` at +0x14) case 2 -> `FUN_140003690` -> `FUN_14000c3a0`; `ControlCode==0x806D7069` -> `FUN_140010720`:

- `0x14001073e` loads `MiniportContext` from `SRB+0x68`; `0x14001082c` `addq $0x158,%r14`; `0x140010850` `shlq $0x2,%r8`; `0x14001085a` `call 0x140018680` (`memmove`) with source `Data+8`.
- Bound at `0x1400107dc` `cmpl 0x18(%rax),%ecx; jbe` is again the declared `Length` only. `SrbExtensionSize` **0x358** -> `0x200` (512) bytes remain at +0x158; `count*4` can exceed it without limit.

**`lsi_sas3i.sys`** - `FUN_14000e7c0` -> `0x806D7069` -> `FUN_140013810`:

- `0x14001398c` `shll $0x2,%r13d` (size = `count*4`); bound at `0x1400139ee` `cmpl 0x18(%rax),%ecx`; `0x140013a97` `addq $0x160,%r15` (destination = `MiniportContext+0x160`); `0x140013ac5` `call 0x140019e00` (memmove) with source `Data+8`.
- `SrbExtensionSize` **0x420** -> `0x2C0` (704) bytes remain; overflow for `count > 0xB0`.

**`lsi_sss.sys`** - `FUN_00015c0c` -> `0x806D7069` -> `FUN_000160c8`:

- `0x160f1` loads `MiniportContext` from `SRB+0x68`; destination `rbp = context+0x158`; bound at `0x1619b` `cmpl 0x18(%rax),%edx`; `0x1620b`/`0x1620f` read and shift `count`; `0x16215` `call 0x20040` (memmove) with source `Data+8`.
- `SrbExtensionSize` **0x358** -> `0x200` bytes remain; same unbounded copy.

**Why the `Length` check does not save it.** The check can be satisfied with a truthful buffer: supply `Length = 0x1008` (a ~4 KB `IOCTL_SCSI_MINIPORT` input buffer) and `count = 0x400`; the source read stays inside the caller's buffer (SG list at `Data+8` = 4 KB), while the destination frame is only 256-704 bytes. No length lie and no out-of-bounds source read are required. The overflow is therefore a straightforward caller-controlled-size, caller-controlled-content kernel pool write.

**What is written and where.** Destinations are StorPort's per-request lookaside allocations (`SrbExtension` / `MiniportContext`) in kernel pool, immediately followed by whatever the allocator placed next; contents are attacker-chosen SG dwords. This is a heap overflow, not an arbitrary write: target control is limited to adjacent pool objects (**W2**), size control is caller-chosen up to the input-buffer size (16-bit count x 4).

### 5.2 Secondary observations (not rated as the primary primitive)

- **CSMI responses and declared `Length`.** Handlers such as `FUN_1c000b3a8` (`lsi_sas`) write fixed structures at `Data` offsets up to 0xCA and gate only on `Length > N`. If the port/class driver does not enforce `SRB_IO_CONTROL.Length <= InputBufferLength-0x1C`, a small buffer with a large declared `Length` would also overflow the METHOD_BUFFERED system buffer with fixed data. This depends on `storport.sys` behavior that was not resolved statically (see Limitations); it is recorded as a residual, not the verdict driver.
- **CSMI 0x17 inline payload** (`lsi_sas` `FUN_1c000bf1c`): copies `uVar2 = Data+0xC` bytes to `SrbExtension+0x158` when `uVar2 <= ReplyBufferSize-0x38`. For the SAS1 frame (0xE0 bytes available at +0x158) this fits only while the firmware-reported reply size stays <= 0x118; `ReplyBufferSize` is adapter/firmware data, not attacker input, so this was not rated, but the invariant is undocumented.
- **InBand command 8** (`lsi_sas` `FUN_1c00100d8`): copies a descriptor length `uVar2` from the driver's diagnostic buffer to `Data+0x4C` with no `Length` check; `uVar2` is a driver/firmware field. Unresolved secondary path.
- **Firmware-response copies** (`lsi_sas` `FUN_1c0007b8c`): copies `*(u32*)(resp+0x18)` bytes from the device response to `SRB->DataBuffer` with no user-length check. Device/firmware-controlled length; out of the R2 threat model.
- **`HW-ONLY` channel** (`0x80771959` + `4.00`): caller-selected 16-bit port and 32-bit MMIO offset/value, `outl 0x1c00062ea` / `inl 0x1c00062fc` and `*(CsrBase + off) = value`. This is raw hardware access (arbitrary port I/O and fixed-window MMIO), not a kernel memory write. It could chain into memory only via a device/DMA reconfiguration, which was not demonstrated.
- **No METHOD_NEITHER / no user-pointer dereference.** All six receive the IOCTL payload through the storage stack's system buffer; there is no `ProbeForWrite`, `MmMapLockedPagesSpecifyCache`, user MDL, `\Device\PhysicalMemory`, or `MmMapIoSpace` path in any image. `StorPortGetPhysicalAddress` is used only on the driver's own frame buffers for hardware DMA, and `StorPortGetDeviceBase` maps the adapter BAR.

## 6 Most dangerous exposed capability

On a machine with a supported LSI SAS HBA (or WarpDrive SSS), an administrator can open the physical drive and issue `IOCTL_SCSI_MINIPORT` with `SRB_IO_CONTROL.ControlCode = 0x806D7069`, `Data+2 = count`, and `Data+8.. = count*4` bytes of SG data. The miniport copies `count*4` bytes into a 0x100-0x2C0-byte tail of its per-request kernel extension after checking only the caller-declared `Length`. Result: a controlled-content pool overflow of up to ~256 KB, adjacent to StorPort request extensions - the strongest memory-corruption primitive in this group. It is hardware-gated, so it is **MW3**, not MW2/MW1.

## 7 Verdict

### Per-file

| File | Verdict | Reach | Setup | Write | Basis |
|---|---|---|---|---|---|
| `lsi_sas.sys` | **MW3** | R3 (opener R2) | hardware | W2 | `0x806D7069` -> `FUN_1c00068a8`; `count*4` -> `SrbExtension+0x138` (0x238 ext, 0x100 window); memmove `0x1c00069b1`; length gate `0x1c0006963` |
| `lsi_sas2i.sys` | **MW3** | R3 (opener R2) | hardware | W2 | `0x806D7069` -> `FUN_140010720`; `count*4` -> `MiniportContext+0x158` (0x358 ext, 0x200 window); memmove `0x14001085a`; gate `0x1400107dc` |
| `lsi_sas3i.sys` | **MW3** | R3 (opener R2) | hardware | W2 | `0x806D7069` -> `FUN_140013810`; `count*4` -> `MiniportContext+0x160` (0x420 ext, 0x2C0 window); memmove `0x140013ac5`; gate `0x1400139ee` |
| `lsi_sss.sys` | **MW3** | R3 (opener R2) | hardware | W2 | `0x806D7069` -> `FUN_000160c8`; `count*4` -> `MiniportContext+0x158` (0x358 ext, 0x200 window); memmove `0x16215`; gate `0x1619b` |
| `percsas2i.sys` | **NO-MEMORY-WRITE** | R3 | hardware | W0 | `Function 2` -> MegaRAID management queue (`FUN_1c00042b4`); hardware mailbox/DCMD; observed copies bounded by `DataTransferLength`/`CdbLength`/device counts; no caller-length kernel frame copy found |
| `percsas3i.sys` | **NO-MEMORY-WRITE** | R3 | hardware | W0 | `Function 2` -> `FUN_14000ab60` via indirect ops table; hardware mailbox/DCMD; no caller-length kernel frame copy found |

### Overall

**MW3 - `reach=R3 setup=hardware write=W2 load=signed`.** Four WHQL-signed LSI SAS/SSS miniports expose a caller-controlled kernel pool overflow through `IOCTL_SCSI_MINIPORT`/`SRB_IO_CONTROL 0x806D7069` with no signature or privilege check beyond the storage-device DACL; exploitation requires a supported HBA (and the ability to issue the IOCTL as administrator). The two PERC MegaRAID builds do not expose an equivalent user-length copy and are `NO-MEMORY-WRITE`; their `IOCTL_SCSI_MINIPORT` path is a hardware mailbox/DCMD interface (`HW-ONLY`). This is not MW2 because the primitive cannot be reached without the physical controller; it is not MW4 because both the overflow size and contents are attacker-controlled.

## 8 Limitations

1. **Static only.** No driver was loaded, no service/registry change was made, and no HBA was present. The pool layout, crash behavior, and reliability of the overflow were not tested.
2. **`storport.sys` not audited.** Whether StorPort/classpnp enforce `SRB_IO_CONTROL.Length <= InputBufferLength-0x1C` was not resolved. This does not affect the destination-side overflow (a truthful 4 KB buffer already overflows), but it does affect the secondary CSMI fixed-write variant and the source-read bounds.
3. **`percsas2i`/`percsas3i` management path.** The IO_CONTROL extension is processed through an indirect ops table (`param_1+0x178`) and a hardware mailbox/DCMD engine; a full symbolic trace of every DCMD builder was not completed. The `NO-MEMORY-WRITE` verdict for these two is based on the absence of a caller-length copy in the observed builders plus the hardware-only data path, and should be re-opened if a DCMD path with a user length field is identified.
4. **Secondary length paths.** The InBand command-8 copy (`FUN_1c00100d8`, `Data+0x4C`), the CSMI 0x17 inline-copy invariant (`FUN_1c000bf1c`, `ReplyBufferSize <= 0x118`), and the firmware-response copy (`FUN_1c0007b8c`) are recorded as unresolved; they depend on driver/firmware-reported lengths rather than direct user input.
5. **No REA cross-check.** REA capacity was exhausted (four active sessions); all claims are from Ghidra 12.1.4 headless decompilation plus `llvm-objdump` disassembly and WDK 10.0.26100 structure definitions. Addresses are static image VAs (bases: `0x1c0000000` for `lsi_sas`/`percsas2i`, `0x140000000` for `lsi_sas2i`/`lsi_sas3i`/`percsas3i`, `0x10000` for `lsi_sss`). No dump/REA evidence IDs exist for this audit.
6. **No proof of exploitability.** No PoC, trigger, or BYOVD instruction is included; the report establishes the primitive and its gate only.
