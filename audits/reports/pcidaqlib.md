# Audit: pcidaqlib (four builds) — Measurement Computing / Digilent PCI-DAQ driver

| Field | Value |
|---|---|
| File(s) | `pcidaqlib_4BEC3036.sys` (x86), `pcidaqlib_7519DAC6.sys` (x86), `pcidaqlib_4D67C576.sys` (x64), `pcidaqlib_7CBCD6B0.sys` (x64) |
| SHA-256(s) | `4bec30361f16cbe1c538fca390aa786e5853697077c449e109b41662ce2ca6bd` (4BEC3036)<br>`7519dac6178b1f7feac3fc60b6ae1c18701118c3dedc61ab0dc6a55baa1c536c` (7519DAC6)<br>`4d67c576de87fe8b128176d67dfe4011b3c635a788e09c1606a43b0bd760cc73` (4D67C576)<br>`7cbcd6b0204dbf41da5b4a99d0ad27e17cadf829dc069329e33de2f862be171c` (7CBCD6B0) |
| Analysis date | 2026-10-25 |
| Method | Static-only. Local Ghidra 12.1.4 headless (JDK 21) full decompile + `objdump` disassembly + hand PE/import/Authenticode parsing. **REA not used**: the shared bridge was occupied by a foreign target (`CBUL32_EB216763.sys`, SHA-256 `eb216763…832189`), so the audit ran entirely offline (gap disclosed in §8). |
| Reach tier | **R3** — the device only opens when the DAQ board attaches (§2.4) |
| Setup required | **hardware** (kernel service to load + Measurement Computing PCI-DAQ card present) |
| Write quality | **W2** — arbitrary kernel VA destination, constrained value/length |
| Verdict | **MW3** — `reach=R3 setup=hardware write=W2 load=signed` |
| HW-only | no (MMIO/BAR accesses are HW-ONLY; the rated primitive is a true kernel-VA write) |

Addresses are image-base-relative VAs (image base `0x10000`); Ghidra and `objdump` agree on
this numbering. Subtract `0x10000` for the RVA / file-mapped offset.

## Per-file table

| File | SHA-256 | Arch | PE TimeDateStamp | Code identical to | Verdict |
|---|---|---|---|---|---|
| `pcidaqlib_4BEC3036.sys` | `4bec30361f16cbe1c538fca390aa786e5853697077c449e109b41662ce2ca6bd` | i386 (PE32) | `0x4C3B3918` (2010-07-12) | — (reference) | **MW3** |
| `pcidaqlib_7519DAC6.sys` | `7519dac6178b1f7feac3fc60b6ae1c18701118c3dedc61ab0dc6a55baa1c536c` | i386 (PE32) | `0x4C3B3918` | `4BEC3036` — all six sections byte-identical | **MW3** |
| `pcidaqlib_4D67C576.sys` | `4d67c576de87fe8b128176d67dfe4011b3c635a788e09c1606a43b0bd760cc73` | AMD64 (PE32+) | `0x4C3B3922` (2010-07-12) | — (reference) | **MW3** |
| `pcidaqlib_7CBCD6B0.sys` | `7cbcd6b0204dbf41da5b4a99d0ad27e17cadf829dc069329e33de2f862be171c` | AMD64 (PE32+) | `0x4C3B3922` | `4D67C576` — all seven sections byte-identical | **MW3** |

**Build comparison (material differences): none in code.**
Each architecture ships twice with identical section content; only the PE checksum
(x86 `0x2A8/0x2EC`, x64 `0x150/0x1A4`) and the appended Authenticode blob differ:

- x86 pair: `.text .rdata .data INIT .rsrc .reloc` all SHA-256-identical; overlay 10 368 vs 20 656 bytes.
- x64 pair: `.text .rdata .data .pdata INIT .rsrc .reloc` all SHA-256-identical; overlay 10 368 vs 20 656 bytes.
- x86 vs x64 is the same source rebuilt: same 33 IOCTL codes, same 0xCC command block, same
  dispatch indices, same helpers. The x64 build adds `IoIs32bitProcess` thunk translation
  (it expands the 32-bit command block into a 64-bit layout in pool before dispatching), and
  uses `0x18`-byte device extensions / `0x1500`-byte contexts versus `0x10` / `0x12F0`.
- A defect in one build is therefore a defect in **all four**.

## 1 Internals

- Image type: native kernel driver (`Subsystem = 1`), no exports, no PnP `AddDevice`
  (no `IoRegisterDriverInitialCallbacks`, no `WdfDriverCreate`). Legacy
  `DriverEntry`-created control device — 32 of them.
- Import surface: `ntoskrnl.exe` (x86 59 / x64 49), `HAL.dll` (`HalGetBusDataByOffset`,
  `HalSetBusDataByOffset`, `HalGetBusData`, `KeQueryPerformanceCounter`,
  `KeStallExecutionProcessor`). Memory-relevant imports: `IoAllocateMdl`,
  `MmProbeAndLockPages`, `MmMapLockedPagesSpecifyCache`, `MmUnlockPages`, `IoFreeMdl`,
  `MmMapIoSpace`, `MmUnmapIoSpace`, `MmGetPhysicalAddress`, `MmAllocateContiguousMemory`.
  **No** `ProbeForRead` / `ProbeForWrite`, **no** `IoCreateDeviceSecure`, **no**
  `SeAssignSecurity` / `RtlCreateSecurityDescriptor`, **no** `ZwMapViewOfSection`.
- Self-identification strings: `"PCI-2500 Device Driver"`, `"pcidaqlib(5.0.1 Build 1)"`,
  `"daqx\\pcidaqlib%u"`, registry path
  `\REGISTRY\Machine\System\CurrentControlSet\Services\Daqx_Present_Devices`.
  The driver accepts PLX bridge IDs `0x10B5:0x9056` and `0x10B5:0x9080`
  (literal compare against `0x905610b5` / `0x908010b5` at the mapped BAR2 + `0x70`).
- Authenticode: `DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1`, subject
  **Digilent, Inc.** (Pullman, WA). Two of the four blobs additionally carry a
  `DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA` countersignature chain.
  No WHQL/attestation signature is present in the certificate table.

## 2 Entry / device / interface / effective DACL

### 2.1 DriverEntry

| Build | DriverEntry | Device loop | Dispatch install |
|---|---|---|---|
| x86 | `entry` @ `0x7C592` → `FUN_0007C520` @ `0x7C520` | `FUN_0007C410` @ `0x7C410` | same function |
| x64 | `0x8B338` → `FUN_0008B290` @ `0x8B290` | `FUN_0008B010` @ `0x8B010` | same function |

`FUN_0007C520` / `FUN_0008B290` first probes the machine
(`FUN_0001CE00` / `FUN_00023BA0`); if that fails the driver returns
`STATUS_DEVICE_DOES_NOT_EXIST` (`0xC00000C0`) and installs nothing. Otherwise it creates
devices for indices `0..31` and returns `STATUS_DEVICE_DOES_NOT_EXIST` if none succeeded.

### 2.2 Device and symbolic link

Per index *n*, `FUN_0007C410` / `FUN_0008B010` builds the names `\Device\pcidaqlib<n>` and
`\DosDevices\pcidaqlib<n>` (prefix string + `\` + `pcidaqlib` + decimal index), then:

```c
IoCreateDevice(DriverObject        /* rcx */,
               0x10 /* x64: 0x18 */,
               &devName,
               0x5000,             /* DeviceType, custom */
               0,                  /* DeviceCharacteristics = 0     */
               0,                  /* Exclusive = FALSE             */
               &deviceObject);
...
((DEVICE_OBJECT*)dev)->Flags |= 0x10;   /* DO_DIRECT_IO */
```

x86 verified in assembly at `0x7C467`; x64 at `0x8B12F`
(`r9d=0x5000`, `[rsp+0x20]=0`, `[rsp+0x28]=0`, `[rsp+0x30]=&devObj`).

User-visible names are therefore `\\.\pcidaqlib0` … `\\.\pcidaqlib31`
(32 concurrent openable instances, each with its own extension).

### 2.3 Effective DACL / SDDL — **not set by the driver**

- `IoCreateDevice` has no security-descriptor parameter and the driver never calls
  `IoCreateDeviceSecure`, never builds an SD, and never writes
  `DeviceObject->SecurityDescriptor`. The only writes the create routine makes to the
  `DEVICE_OBJECT` itself are `Flags |= 0x10` (`+0x1C` x86, `+0x30` x64) and the device
  extension (`+0x28` / `+0x40`); the SD field is never touched.
- No SDDL string exists in either image.
- Therefore the device receives the **object-manager default device DACL**, not a
  driver-chosen one: SYSTEM and BUILTIN\Administrators full control, Everyone read.
  (This is an OS default, not visible in the binary — marked as an inference in §8.)
- Consequence: the driver itself contributes **no** open gate. Whether an unprivileged
  caller can open depends solely on that default.

### 2.4 Open gate: the device only opens when the board attaches

This is the effective gate and it dominates reach. `IRP_MJ_CREATE`
(x86 `FUN_0001C5E0`, x64 `FUN_000237B0`) does:

1. `ext->refcount++`; if `ext->context != 0` (another handle already open) return **success**.
2. `FUN_00020730(0x12F0, 'DxDE', NonPagedPool)` / `ExAllocatePoolWithTag(0x1500, 'Dx32')`
   → per-open context; zero it.
3. `FUN_0001C560` → four `MmAllocateContiguousMemory` buffers, each MDL-locked and mapped
   (§5.2) — internal buffers, no caller input.
4. Build `"\Registry\Machine\System\CurrentControlSet\Services\daqx\pcidaqlib<n>"`, read
   `Flags` and `Protocol` values.
5. `FUN_0001DE00` (`entryInitDevice`): `FUN_000197C0` **CommAttach** — enumerate boards and
   match bus/slot from `Daqx_Present_Devices`; then `FUN_0001F000` **InitializeAndTestComm**
   (FPGA register handshake through the mapped BAR).
6. On success → `STATUS_SUCCESS` and the context is kept. On failure → one retry with
   `Protocol` forced to 6, then `IoStatus.Status = 0x80000010`
   (`STATUS_INVALID_DEVICE_STATE`) and the context is freed (`0x1C6DA`, `0x1C6E1`).

**Static conclusion:** a handle cannot be obtained unless the DAQ board is present and
answers the comm handshake. The dispatcher then additionally requires `ext->context != 0`
(x86 `0x1C75F`, x64 `0x239A1`), returning `0x80000010` otherwise. All 33 IOCTLs are
therefore behind a physical-hardware gate. See §8 for the residual uncertainty.

## 3 Dispatch and IOCTL table

Dispatch installed at `DriverObject + 0x38/0x40/0x70` (x86) and `+0x70/0x80/0xE0/0x68` (x64):

| IRP | x86 | x64 |
|---|---|---|
| `IRP_MJ_CREATE` | `FUN_0001C5E0` @ `0x1C5E0` | `FUN_000237B0` @ `0x237B0` |
| `IRP_MJ_CLOSE` | `FUN_0001CD80` @ `0x1CD80` | `FUN_00023400` @ `0x23400` |
| `IRP_MJ_DEVICE_CONTROL` | `FUN_0001C740` @ `0x1C740` | `FUN_00023970` @ `0x23970` |
| `DriverUnload` | `FUN_0001C890` @ `0x1C890` | `FUN_00023A00` @ `0x23A00` |

No `IRP_MJ_READ`, `IRP_MJ_WRITE`, or `IRP_MJ_INTERNAL_DEVICE_CONTROL` handler is installed.

The dispatch stub (x86 assembly `0x1C740`, x64 `0x23970`) reads
`Irp->Tail.Overlay.CurrentStackLocation` (x86 `+0x60`, x64 `+0xB8`), checks
`MajorFunction == 14`, reads `Parameters.DeviceIoControl.IoControlCode`
(x86 `+0x0C`, x64 `+0x18`), sets `IoStatus.Information = 0xCC` **unconditionally**, and
calls the handler with `Irp->AssociatedIrp.SystemBuffer`
(x86 `+0x0C`, x64 `+0x18`). So every call uses a fixed 204-byte `METHOD_BUFFERED`
command block; no output-length or input-length validation is performed anywhere.

**All 33 codes are `DeviceType 0x5000`, `FILE_ANY_ACCESS`, `METHOD_BUFFERED`** — identical
in both builds (`(code >> 14) & 3 == 0`, `code & 3 == 0`). Because `FILE_ANY_ACCESS`
skips the I/O manager's read/write-access check, a **read-only handle is sufficient**
to reach every code.

| IOCTL | x86 handler | Kernel action |
|---|---|---|
| `0x50002400` | `FUN_0001A3F0` | ADC/board parameter write (board path) |
| `0x50002404` | `FUN_0001A370` | ADC/board parameter read |
| `0x50002408` | `FUN_0001CF30` | fills driver version struct `"V5.0.001"` |
| `0x5000240C` | `FUN_0001BD90` | `dioWrite` — digital output to board |
| `0x50002410` | `FUN_0001BCB0` | `dioRead` — digital input |
| `0x50002414` | `FUN_000140B0` | ADC configuration |
| `0x50002418` | **`FUN_00014180`** | `adcStart` — **caller VA + length locked as DMA write target** (§5.3) |
| `0x5000241C` | `FUN_00012290` | `adcStop` |
| `0x50002420` | `FUN_00013CC0` | `adcArm` |
| `0x50002424` | `FUN_00011E40` | ADC trigger/disarm helper |
| `0x50002428` | `FUN_00011CE0` | `adcSoftTrig` |
| `0x5000242C` | `FUN_00011AE0` | scan-sequence setup |
| `0x50002434` | `FUN_000179F0` | DAC configuration |
| `0x50002448` | `FUN_00017AF0` | DAC channel enable |
| `0x50002454` | `FUN_00017C50` | DAC channel setup — **reads** caller pointers (§5.5) |
| `0x50002458` | `FUN_00018D60` | `dacConfigure` |
| `0x5000245C` | **`FUN_00018EE0`** | `dacStart` — **caller VA + length locked as DMA source** (§5.4) |
| `0x50002460` | `FUN_00018E50` | `dacStop` |
| `0x50002464` | `FUN_00018AB0` | `dacArm` |
| `0x50002468` | `FUN_000189F0` | `dacDisarm` |
| `0x5000246C` | `FUN_00017D30` | DAC trigger |
| `0x50002470` | `FUN_00019070` | DAC status query |
| `0x50002478` | `FUN_00020340` | board status |
| `0x5000247C` | `FUN_00019A70` | capability/board-type decode (reachable before the ADC/DAC gates) |
| `0x50002480` | `FUN_00011B50` | trigger routing |
| `0x50002484` | `FUN_0001D180` / `FUN_00012B50` | `entryGetHWInfo` |
| `0x50002490` | `FUN_00016150` | `calConfigure` — index-bounded write into the driver's own context |
| `0x50002494` | `FUN_000175D0` / `FUN_00016B80` | calibration read/write (board path) |
| `0x50002498` | `FUN_00011B90` | board register access |
| `0x5000249C` | `FUN_00012DF0` | `setOption` |
| `0x500024A0` | `FUN_0001CFE0` | calibration / DAC buffer helper — **reads** caller pointers (§5.5) |
| `0x500024A4` | **`FUN_00021170`** (x64 `FUN_00029660`) | log-drain — **copies up to ~100 KB to a caller-supplied VA** (§5.1) |
| `0x500024A8` | inline in `FUN_0001D2F0` (`0x1D2F0`) / `FUN_00024C00` | **writes 25-byte fixed version string to caller base+offset** (§5.6) |

`0x5000247C`, `0x50002408`, `0x500024A4`, `0x500024A8` are processed *before* the
ADC/DAC-initialised checks; the rest require `ext+0x1BC` (ADC) or `ext+0x1C0` (DAC), which
`FUN_0001DE00` only sets after a successful board attach.

## 4 Access-control audit

| Check | Result |
|---|---|
| Device SD | none supplied → OS default device DACL (§2.3) |
| `IRP_MJ_CREATE` access checks | none (`FUN_0001C5E0`); the only gate is board attach |
| `SeSinglePrivilegeCheck` / `SeAccessCheck` | not imported, not called |
| `FILE_WRITE_ACCESS` requirement | none — all IOCTLs are `FILE_ANY_ACCESS` |
| Caller identity / PID check | none |
| `ProbeForRead` / `ProbeForWrite` on embedded pointers | **absent in all four builds** |
| Input/output length validation | none; `Information` is hard-coded to `0xCC` |
| Raw-pointer (`METHOD_NEITHER`) surface | none — all codes are `METHOD_BUFFERED` |

The driver's security posture is "whatever the default DACL gives, then trust every
pointer in the 204-byte command block". Once a handle exists, an unprivileged caller would
be able to issue every code. **The only thing standing between a caller and §5 is the
physical board attach in `IRP_MJ_CREATE`.**

## 5 Memory-write trace

### 5.1 `0x500024A4` — arbitrary kernel VA write of buffered log text (x86 `FUN_00021170` @ `0x21170`, x64 `FUN_00029660` @ `0x29660`)

Command-block fields (x86, dword indices into the 204-byte block):

| Index | Use |
|---|---|
| `[1]` | flags: bit0 → set log mask from `[2]`; bit1 → drain; bit2 → reset ring |
| `[3]` | requested length |
| `[4]` (x64: qword at `+0x10`) | **destination virtual address** |

```c
_Src   = PTR_log_read;                                  /* ring buffer read pointer */
_Size  = param_1[3];                                    /* caller length, NOT bounded   */
local_8 = FUN_00020f60(param_1[4], (int)_Size, &mdl);   /* caller VA + length            */
...
avail  = PTR_log_end - PTR_log_read;                    /* wrap-adjusted               */
if (_Size > avail) _Size = avail;                       /* clamp to buffered bytes only */
memcpy(local_8, _Src, _Size);                           /* <-- write to caller VA        */
```

`FUN_00020F60` (`utilLockBuffer`, x64 `FUN_00029CD0` @ `0x29CD0`) is the primitive:

```c
mdl = IoAllocateMdl(Buffer, Length, FALSE, FALSE, NULL);
MmProbeAndLockPages(mdl, 0 /*KernelMode*/, 2 /*IoModifyAccess*/);   /* no user-range check */
if (mdl->Flags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL))
    return mdl->MappedSystemVa;                                     /* kernel VA passes through */
return MmMapLockedPagesSpecifyCache(mdl, 0 /*KernelMode*/, 1 /*MmCached*/, NULL, 0, 0x10);
```
Verified in x86 assembly at `0x20FDE` (`push 2; push 0; push eax; call MmProbeAndLockPages`)
and `0x21033` (`push 0x10/0/0/1/0`, `call MmMapLockedPagesSpecifyCache`); the same shape is
present at x64 `0x29D42`–`0x29D57`. `AccessMode = KernelMode` means the address is **not**
validated as user-space, so a kernel VA that is mapped and writable is accepted, and
`MmProbeAndLockPages` even short-circuits the map for system-space buffers
(`MDL_MAPPED_TO_SYSTEM_VA`), returning the same VA.

The whole function is wrapped in a `__try/__except` handler (`ExceptionList`,
`pcStack_10 = FUN_00021360`), so a bad address faults and is swallowed rather than
bugchecking — reliability favours the attacker.

- **Target:** caller-controlled (arbitrary writable kernel VA; on x64 the native path
  takes the full 64-bit value; a WOW64 caller is zero-extended, so only <4 GB).
- **Length:** up to the bytes queued in the 99 999-byte log ring (x86 end `0x7C3B7`,
  start `0x63D18`; x64 end `0x4A7AF`, start `0x32110`). `IoAllocateMdl` receives the
  *unclamped* length, so a huge request is a DoS path rather than extra reach.
- **Value:** **not** caller-controlled — the source is the driver's debug log
  (`s_abcdefghij` ring, appended only by `FUN_00020540` from `FUN_00020BB0`'s
  `vsprintf` of fixed `"PCIDAQLIB: "` messages). Bytes are printable ASCII with
  caller-influenced numeric substitutions.

### 5.2 Internal buffer creation (not a primitive)

`FUN_0001C500` (`0x1C500`) does `MmAllocateContiguousMemory(size)` then hands the
**kernel-owned** VA to `FUN_00020F60`. Called from `IRP_MJ_CREATE` with constants
(`0x100010`, `0x1050`). No caller input.

### 5.3 `0x50002418` — `adcStart`: caller VA becomes the acquisition DMA target (`FUN_00014180` @ `0x14180`)

```c
iVar2 = param_2[1];                                  /* sample count, unbounded */
iVar5 = FUN_00020f60(param_2[3], iVar2 * 2, &mdl);   /* caller VA, count*2 bytes */
*(int *)(ctx + 0x428) = iVar2 * 2;
*(int *)(ctx + 0x418) = iVar5;                       /* mapped VA stored for the ISR/DMA */
*(int *)(ctx + 0x41C) = iVar5;
*(int *)(ctx + 0x420) = mdl;
```
The acquisition engine then writes ADC samples through the stored VA. Target is
fully caller-controlled; length is caller-controlled with **no upper bound** (`count * 2`
can overflow); value is hardware sample data. Gated on `ext+0x1BC` (ADC initialised).

### 5.4 `0x5000245C` — `dacStart`: caller VA becomes the DAC DMA source (`FUN_00018EE0` @ `0x18EE0`)

Same shape with `param_2[5]` / `param_2[3] * 2`, stored at `ctx + 0x46C/0x470/0x474`.
The MDL is created with `IoModifyAccess`, i.e. it is **writable**, but the driver uses it
as a source to feed the DAC, so this is not itself a write primitive.

### 5.5 Caller pointers used as read sources (leak, not write)

- `0x50002454` `FUN_00017C50`: dereferences `param_2[1]`, `param_2[2]`, `param_2[3]` as
  kernel pointers, bounded by the DAC channel count.
- `0x500024A0` `FUN_0001CFE0`: `FUN_00014D50(..., (byte*)param_2[6], ...)` and
  `*puVar1/ puVar1[1]/ puVar1[2]` from `param_2[6]`.
- `0x50002494` / `0x50002490` calibration paths.

These are **arbitrary kernel reads** (no probe). They matter because they can supply the
address needed by §5.1 and they are a KASLR-leak modifier, but they are out of scope on
their own.

### 5.6 `0x500024A8` — fixed 25-byte write to caller base+offset

```c
strncpy(local_50, "pcidaqlib(5.0.1 Build 1)", 25);
if (base /* [2] */ != 0) {
    if (strlen(local_50) + offset /* [3] */ < (char*)length /* [1] */) {   /* self-referential */
        pcVar5 = (char *)(base + offset);
        do { *pcVar5++ = *pcVar4++; } while (...);                          /* no probe */
    }
}
```
Target is caller-controlled (`base + offset`), value is a fixed constant string, length is
fixed at 25 bytes. The "bounds check" compares against a caller-supplied value and does not
constrain the address. This is a narrow, fixed-value arbitrary-address write (W3 quality on
its own).

### 5.7 `MmMapIoSpace` — BAR mapping, **not** caller-controlled

Single call site per build: `FUN_00021070` @ `0x21070` (x64 `FUN_00026FB0` @ `0x26FB0`).

```c
HalGetBusDataByOffset(4, bus, slot, &pa, 0x18, 4);   /* PCI config BAR2 */
va = MmMapIoSpace(*(PHYSICAL_ADDRESS*)&pa, 0x1002, MmNonCached);
HalGetBusDataByOffset(4, bus, slot, &pa, 0x10, 4);   /* PCI config BAR0 */
va = MmMapIoSpace(*(PHYSICAL_ADDRESS*)&pa, 0x100,  MmNonCached);
```
Assembly `0x21075`–`0x21084`: `push 0; push length; push 0; push pa; call MmMapIoSpace`
(high dword forced to 0, cache type `MmNonCached`).

Both the physical address and the length are fixed: the PA comes from the PLX BAR and the
sizes are literals `0x1002` / `0x100`. There is **no caller-controlled PA, offset, length
or cache type** anywhere in either build. Mapping and register accesses through these VAs
are hardware accesses and are **HW-ONLY**. Only `FUN_0001EAD0` (`0x1EAD0`) calls the mapper,
from `FUN_0001ECA0` (`daqPciAttach`) after `HalGetBusData`/`HalSetBusDataByOffset` on the
matched bus/slot.

`MmGetPhysicalAddress` (`FUN_00020980` @ `0x20980`) is used only to build
scatter-gather/DMA descriptors from already-locked buffers (`FUN_000187D0`,
`FUN_0001BF20`, `FUN_00019680`); no PA is returned to the caller and no PA is mapped.

### 5.8 Summary of caller-controlled fields reaching a kernel store

| Source field | Reaches | Value control | Length control |
|---|---|---|---|
| `[4]` + `[3]` of `0x500024A4` | `memcpy` to MDL-mapped caller VA | log text (ASCII) | up to ~100 KB |
| `[2]` + `[3]` of `0x500024A8` | 25-byte constant write to caller VA | fixed string | fixed 25 |
| `[3]` of `0x50002418` | ADC DMA target VA | hardware samples | caller, unbounded |
| `[5]` of `0x5000245C` | DAC DMA source VA | n/a (read) | caller, `size*2` |
| PCI BAR | `MmMapIoSpace` | n/a | fixed `0x1002`/`0x100` |

**No caller-controlled physical address or cache type reaches any mapping in any build.**

## 6 Most dangerous exposed capability

`IOCTL 0x500024A4` (`FUN_00021170` / `FUN_00029660`): a **true kernel virtual-address write**.
The caller supplies any writable kernel VA in the command block; the driver allocates an MDL
over it with `MmProbeAndLockPages(..., KernelMode, IoModifyAccess)`, takes the
`MappedSystemVa`, and `memcpy`s up to ~100 KB of its own log text there. No probe, no
user-range check, no length validation, faults swallowed by SEH.

This is materially different from what the corpus triage assumed. The project note
"admin + physical-memory mapping (`W3P`)" is **not** what the code does: `MmMapIoSpace` is
fixed BAR MMIO, and the dangerous path is an arbitrary-**VA** MDL mapping. Corrected
classification: `W2`, not `W3P`.

`0x50002418` gives a second arbitrary-VA target (a DMA write destination with an unbounded
length), and `0x500024A8` gives a fixed-value arbitrary-VA write.

What keeps this out of MW2/MW1 is not the write itself but the open gate: no board, no handle.

## 7 Verdict

**MW3 — `reach=R3 setup=hardware write=W2 load=signed`.**

Reasoning against `SEVERITY.md`:

- The primitive is a genuine kernel memory write, not a physical-memory mapping, so the
  write quality is **W2** (arbitrary target, constrained value) — not `W3P`, and not `W0`.
  `0x500024A8` alone would be `W3`; `0x500024A4` carries the grade.
- Reach is **R3**: `IRP_MJ_CREATE` refuses to complete (`0x80000010`) unless the driver's
  PCI-DAQ board is present and answers `CommAttach` + `InitializeAndTestComm`. That is a
  hardware/dongle gate the requester does not control.
- Matrix row "R3 hardware/dongle + W2" → **MW3**. `A device not present caps at MW3`; we are
  at MW3 whether the card is present or not.
- Load is `signed` (DigiCert / Digilent, Inc.). None of the four SHA-256 values appears in
  `indexes/dedupe/known_bad_hashes.txt`, so these images are not blocklisted or known-bad.

Had the board been present, this would be **MW2** (an admin-open, arbitrary-kernel-VA write
of constrained content, with a read primitive available to defeat KASLR). The physical gate
is the only thing holding it at MW3.

## 8 Limitations

1. **REA not used.** The shared bridge was already bound to `CBUL32_EB216763.sys`
   (SHA-256 `eb216763ffcd57bbda73957b44cc8c68674c3fddfcce696c8bd2e595e4832189`), i.e. a
   foreign target. Per the fallback rule the audit ran entirely on local Ghidra 12.1.4
   headless plus `objdump`. No REA evidence IDs exist for this report; all claims come from
   the decompiled listing and the disassembly cited above.
2. **Effective SD is an OS default, not image data.** The absence of an explicit SD is
   proven from the binary; the exact DACL that the object manager applies
   (`SYSTEM`/`Administrators` full, `Everyone` read) is a documented platform behaviour and
   was not verified dynamically. Because every IOCTL is `FILE_ANY_ACCESS`, that default
   would *not* block the write paths — only the hardware attach does.
3. **Hardware presence not verified.** No PnP/PCI enumeration was performed (static-only).
   The board-attach requirement is inferred from `FUN_0001DE00` / `FUN_0001C5E0`
   (`0x1C6A9`–`0x1C6DA`) and `FUN_000197C0`; the inverted-looking status convention of
   `FUN_0001DE00` (returns 1 on success) was confirmed by reading its epilogue, but a
   dynamic confirmation on a machine with the card was not possible here.
4. **`MmGetPhysicalAddress` jump table.** `FUN_00020980` decompiled as an unrecovered
   indirect jump over `MmGetPhysicalAddress`; its callers were read individually and all are
   DMA-descriptor builders, but the argument-recovery for those three call sites is
   incomplete in the decompiler output.
5. **HVCI / loadability.** The certificate table holds a DigiCert code-signing chain for
   `Digilent, Inc.` and no WHQL/attestation signature. Whether these 2010-built images load
   on a Secure-Boot/HVCI Windows 10/11 x64 system was not established; it does not change
   the MW3 rating.
6. **Signer identity differs from the product vendor.** The signature subject is
   `Digilent, Inc.` while the version resource says Measurement Computing (a Digilent
   brand). Recorded as an observation only.
7. **Not audited:** the ADC/DAC DMA descriptor programming in `FUN_000187D0` /
   `FUN_0001BF20` beyond confirming it consumes already-locked buffers; a descriptor-level
   bug there could in principle redirect DMA, but no caller-controlled PA reaches it.
