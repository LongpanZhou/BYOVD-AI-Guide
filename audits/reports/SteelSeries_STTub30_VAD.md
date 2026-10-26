# Audit: SteelSeries `STTub30` (×4) and VAD family (`Engine`, `Sonar`)

| Field | Value |
|---|---|
| File(s) | `STTub30_23C68E2F.sys`, `STTub30_4D7F2B9D.sys`, `STTub30_9E1CF7F9.sys`, `STTub30_D1083D40.sys`, `SteelSeries-Engine-VAD_78C729CA.sys`, `SteelSeries-Sonar-VAD_2685B48C.sys` |
| SHA-256(s) | `23C68E2F6C12BF7D422882F69C3339591CD1DD1EDB330C31D5D1659B3CC6718B` · `4D7F2B9D235CEA72EFA4BE2E5A73B2CFFF811E282A6590A6A54624CA3E98C708` · `9E1CF7F9048D4F34FDBF45608022785E5134B7042720FB741C024D1ADB9D2829` · `D1083D4035EFBC9675C50F48434F2566E9FAB6F503E48908E771723721B0EA1B` · `78C729CA45F8BA7EC66988E1B26574655766DD330EEB25A00E44D33E9E927821` · `2685B48C431FBECD4586F72335107A71A2A60C8747AA362979CF059DF8522527` |
| Analysis date | 2026-10-25 |
| Method | Static-only: local Ghidra 12.1.4 headless (full decompile) + `llvm-objdump` 20.1.5 disassembly/PE parse + `Get-FileHash`/`Get-AuthenticodeSignature`. No load, install, service, registry write or IOCTL issued. **REA cross-check not used** — four REA audits were already active (capacity limit per `STATUS.md`); all findings below are from the offline Ghidra/objdump route only. |
| Reach tier | R2 local administrator for `STTub30`; R1 for the two VADs (INF-granted `WD` ACE, inherited from the triage baseline) |
| Setup required | `hardware` (`STTub30`); `devnode` (both VADs) |
| Write quality | **W2** (`STTub30` x64) / **W0** (both VADs) |
| Severity | **MW3** (`STTub30` x64) · **BLOCKED** (`STTub30` i386, architecture) · **NO-MEMORY-WRITE** (Engine VAD, Sonar VAD) |
| Verdict | **MW3** for `STTub30_9E1CF7F9` and `STTub30_4D7F2B9D`; **BLOCKED** for the two i386 builds (same static primitive); **NO-MEMORY-WRITE** for both VADs |
| HW-only | no (no MSR/port/PCI/SMBus/EC or MMIO path in any of the six) |

Verdict line: `MW3 — reach=R3 setup=hardware write=W2 load=signed` for the two x64 `STTub30` builds.

---

## 0. Scope note and delta against the historical baselines

The four historical reports (`steelseries_hid.static.md`, `steelseries_hid_miniport.static.md`,
`steelseries_engine_vad_static.md`, `steelseries_sonar_vad_static.md`) were used only as a map of
where to look. No verdict was inherited.

Two material deltas:

1. **`STTub30` was never actually audited.** The historical miniport note disqualified the family on
   "hardware + devnode" and explicitly recorded that the IOCTL surface was "not enumerated in full".
   Under the current scope hardware is a severity field, not a disqualifier. Enumerating the surface
   this pass produced a real, deterministic pool write (section 5.1) that the baseline never saw.
2. **Sonar's `WRITE-MEDIUM (provisional)` is not sustained.** The old report could not trace the ring
   capacity. This pass traced the allocator: capacity is `2 × size` (`FUN_140002ef4`), which changes
   the reachability argument (section 5.4). It stays an open structural path, not a proven write.

---

## 1. Internals

| Build | Arch | PE timestamp | Version | Size | Signature |
|---|---|---|---|---|---|
| `STTub30_23C68E2F` | i386 (PE32) | 2009-11-10 | 3.0B | 37,912 | Valid, STMicroelectronics |
| `STTub30_4D7F2B9D` | x86-64 (PE32+) | 2009-11-10 | 3.0B | 44,184 | Valid, STMicroelectronics |
| `STTub30_9E1CF7F9` | x86-64 (PE32+) | 2015-04-22 | 3.0C | 54,104 | Valid, STMicroelectronics |
| `STTub30_D1083D40` | i386 (PE32) | 2015-04-22 | 3.0C | 47,832 | Valid, STMicroelectronics |
| `SteelSeries-Engine-VAD_78C729CA` | x86-64 | 2026-09-09 | 1.1.0.0 (INF) | 82,608 | Valid, GN Hearing A/S |
| `SteelSeries-Sonar-VAD_2685B48C` | x86-64 | 2026-04-14 | 15.7.9.759 (INF) | 95,912 | Valid, GN Hearing A/S |

`STTub30` is STMicroelectronics' generic USB function driver ("STTube Driver", `STTub30.sys`,
pool tag `GEN_`/`0x5f4e4547`), re-shipped by SteelSeries. Both VADs are PortCls audio miniports
sharing a common SteelSeries code library.

Sections are cited by VA (image base `0x10000` for `STTub30`, `0x140000000` for the VADs).

---

## 2. Entry / device / interface / effective DACL

### 2.1 `STTub30` (all four builds)

- `entry` `0x18764` → `FUN_00010308` (DriverEntry). It copies `RegistryPath` into a pool block
  (`ExAllocatePoolWithTag`, tag `GEN_`), sets `DriverObject->DriverExtension->AddDevice`, and
  installs the MajorFunction table (`0x1039a`–`0x10412`).
- `AddDevice` = `FUN_0001043c`. It calls `IoCreateDevice(DriverObject, 0x4f8, NULL, 0x22)` at
  `0x104cf`. **The name argument is NULL** — no `\Device\` name, no symbolic link, and no
  `\Device\`/`D:P(` string anywhere in any of the four images.
- Device flags (`_DEVICE_OBJECT+0x30`) are set to **`DO_BUFFERED_IO` (`| 4`)** at `0x1043c` scope,
  and `DO_DEVICE_INITIALIZING` is cleared after `IoAttachDeviceToDeviceStack`. This is what makes
  every `ReadFile`/`WriteFile` use a kernel **system buffer of exactly the requested length** —
  decisive for section 5.1.
- No `IoCreateDeviceSecure`, no SDDL literal, no `SeAccessCheck`/`SeSinglePrivilegeCheck`/
  `RequestorMode` test anywhere in the image. The effective DACL is therefore the `IoCreateDevice`
  default taken from the creating thread's token. `AddDevice` runs in the PnP manager's SYSTEM
  context, so the DACL is SYSTEM + Administrators only → **R2**.
- Access is through the device interface GUID `{CE1125C0-C6DD-11d5-9718-0050041B1E9F}`
  (interface string at `0x16b50`; `IoRegisterDeviceInterface` is imported and the "Device Link"
  registry value names the link suffix). Registering an interface does not add an ACE.
- Caveat: the INF is not part of this `.sys`-only scope. If the packaged INF adds a `Security`
  ACE, the reach would drop to R1. Nothing in the binary does it.

### 2.2 VADs

- Both drivers: `DriverEntry` → `WdfVersionBind` + `PcInitializeAdapterDriver(DriverObject,
  RegistryPath, AddDevice)` (Engine `FUN_14001129c`, Sonar `FUN_140013284`), then hook only
  `MajorFunction[IRP_MJ_PNP]` (`+0x148`). **Neither driver installs its own
  `IRP_MJ_DEVICE_CONTROL` handler**; PortCls owns device-control dispatch.
- Device creation is on the PnP path: `PcAddAdapterDevice(DriverObject, PDO, StartDevice, …)`
  (Engine AddDevice `FUN_14000a220`, StartDevice `FUN_14000a6b0`; Sonar AddDevice
  `FUN_14000c210`, StartDevice `FUN_14000c740`). Root-enumerated devnodes
  `ROOT\VEN_SSGG&DEV_0002` / `DEV_0001` per the INF baseline; `devnode` setup.
- Effective DACL for both is the INF `Security` line quoted in `steelseries_nonrea_triage.md`
  (Engine INF line 123, Sonar line 309):
  `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)`.
  `WD` = Everyone with read/write/execute → **R1** if PnP applies the INF ACE (standard audio
  mechanism; the ACE text is inherited from the baseline, the INF is outside this task's file set).
  The `.sys` images contain no SDDL of their own.

---

## 3. Dispatch and IOCTL table

### 3.1 `STTub30` dispatch (`9E1CF7F9`, identical shape in all four builds)

| DRIVER_OBJECT slot | Offset | Handler | Role |
|---|---|---|---|
| DriverUnload | `+0x68` | `LAB_0001075c` | frees the registry-path copy |
| `IRP_MJ_CREATE` | `+0x70` | `FUN_00011a10` | open a named pipe |
| `IRP_MJ_CLOSE` | `+0x80` | `FUN_00011c10` | close |
| `IRP_MJ_READ` | `+0x88` | `LAB_00014008` → `FUN_00014028(…,0)` | USB IN transfer |
| `IRP_MJ_WRITE` | `+0x90` | `LAB_00014018` → `FUN_00014028(…,1)` | USB OUT transfer |
| `IRP_MJ_DEVICE_CONTROL` | `+0xe0` | `FUN_000126d4` | IOCTL dispatcher |
| `IRP_MJ_CLEANUP` | `+0x100` | `FUN_00011e58` | cancel queued IRPs |
| `IRP_MJ_POWER` | `+0x120` | `FUN_000137ec` | power |
| `IRP_MJ_SYSTEM_CONTROL` | `+0x128` | `FUN_00010770` | WMI |
| `IRP_MJ_PNP` | `+0x148` | `FUN_000107c0` | PnP |

No `IRP_MJ_INTERNAL_DEVICE_CONTROL` handler is installed (`+0xf8` untouched).

### 3.2 `STTub30` IOCTL table

All codes are `0x2220xx`: device type `0x22`, **method `0` = `METHOD_BUFFERED`**, access
`FILE_ANY_ACCESS`. The dispatcher (`FUN_000126d4`) reads `SystemBuffer` from `Irp+0x18`,
`OutputBufferLength` from `IrpSp+0x8`, `InputBufferLength` from `IrpSp+0x10`, and the code from
`IrpSp+0x18`.

| Code | Gate in dispatcher | Kernel action | Sink |
|---|---|---|---|
| `0x222000` | `OutputBufferLength != 0` | writes 1 byte from `*(devExt+0x20)+0x11` to `SystemBuffer[0]` | in bounds |
| `0x222004` | `InputBufferLength != 0` | alloc 9, `GET_DESCRIPTOR` URB, then `memcpy(SystemBuffer, buf, *(USHORT*)(buf+2))` | **OOB write, device-controlled length** (5.3) |
| `0x222008` | `OutputBufferLength >= *lenByte` | `memcpy(SystemBuffer, *(devExt+0x20), *lenByte)` | bounded |
| `0x22200c` | `OutputBufferLength != 0` | 3-byte read of `SystemBuffer`; URB transfer buffer = `SystemBuffer`, length = `OutputBufferLength` | bounded write; 3-byte OOB read |
| `0x222010` | `InputBufferLength == 3` | select config/pipe via `FUN_000110e4` | no buffer write |
| **`0x222014`** | `InputBufferLength != 0 \|\| OutputBufferLength != 0` | dword length at `SystemBuffer+0x10`; `memcpy(pool, SystemBuffer+0x14, len)`; URB; on failure `memset(SystemBuffer, 0, len)`; on success (flag != 0) `memcpy(SystemBuffer, pool, len)` with `pool` zeroed | **arbitrary-length zero-fill OOB write** (5.2) |
| `0x222018` | `InputBufferLength > 1` | pipe reset/abort | no buffer write |
| `0x22201c` | `SystemBuffer != NULL` | `devExt+0x3b8 = *(INT*)SystemBuffer` (timeout) | 4-byte OOB read |
| `0x222020` | `SystemBuffer != NULL`, pipe slots < 10 | `ObReferenceObjectByHandle(*(HANDLE*)SystemBuffer, 0xF0001, …)` → devExt+0x110+[n]*8 | handle ref; 8-byte OOB read |
| `0x222024` | `InputBufferLength >= 2 \|\| OutputBufferLength != 0` | pipe-character swap; writes 1 byte to `SystemBuffer[0]` | 1-byte OOB read |
| `0x222028` | `SystemBuffer != NULL` | `ObReferenceObjectByHandle(*(HANDLE*)SystemBuffer, …)` → devExt+0x180 | handle ref; 8-byte OOB read |
| `0x22202c` | `SystemBuffer != NULL` | `*(UINT32*)SystemBuffer = devExt+0x3bc` (last status) | **4-byte OOB write** when buffer < 4 |
| `0x222030` | `InputBufferLength >= 2 \|\| OutputBufferLength != 0` | writes 2 bytes to `SystemBuffer` | 1-byte OOB write possible; 2-byte OOB read |
| `0x222034` | `InputBufferLength != 0` | `devExt+0x4f2 = SystemBuffer[0]` | in bounds |

### 3.3 VAD dispatch / property tables

- No `IRP_MJ_DEVICE_CONTROL` handler; no IOCTL table of their own. The only user-reachable paths
  are PortCls KS property (`IOCTL_KS_PROPERTY`, `METHOD_NEITHER`) and the KS stream/state calls
  routed by PortCls.
- Engine: `PCPROPERTY` table at `.data 0x1400084f0`, dispatcher `FUN_14000be90`, pin-set
  `{8C134960-51AD-11CF-878A-94F801C10000}`. Pin Id 14 SET `FUN_14000b500` / GET `FUN_14000bc00`;
  pin Id 15 GET `FUN_14000ba5c`; general set Id 0 `FUN_14000b9d4`; audio-type Ids 4/13/55
  `FUN_14000f32c`/`FUN_14000f0ac`/`FUN_14000f1d0`.
- Sonar: dispatcher `FUN_14000e250`; pin Id 14 `FUN_14000dfc0` (GET) / `FUN_14000d8ac` (SET),
  pin Id 15 `FUN_14000de08`; three-property helper `FUN_14000c0f0` → `FUN_140010c24`; BASICSUPPORT
  `FUN_140010d38`; audio Ids 4/13/33/55.
- Both: no `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`,
  `MmProbeAndLockPages`, `IoAllocateMdl`, or `ProbeForRead/Write` import. `MmGetSystemRoutineAddress`
  is used only to resolve `RtlQueryRegistryValuesEx`. No `WRMSR`/`RDMSR` in code.

---

## 4. Access-control audit

| Driver | Gate | Admin can satisfy | Unprivileged can satisfy |
|---|---|---|---|
| `STTub30` | device-object DACL only (`IoCreateDevice`, no SD) | yes (R2) | no |
| `STTub30` | `IRP_MJ_CREATE` name parse (`FUN_00011a10`) | yes — 2-char pipe name, no secret | yes, if DACL allowed |
| Engine VAD | INF `Security` ACE (Everyone `GRGWGX`) + PortCls property routing | yes | yes (R1) |
| Sonar VAD | same | yes | yes (R1) |

`STTub30` performs **no** privilege check, no `RequestorMode` test, no `FILE_WRITE_ACCESS`
inspection, and no authentication handshake. `FUN_00011a10` only validates that the device is
started (`FUN_00012084`), that the create name is 2 hex-range characters, and that the character
maps to a configured pipe slot (`devExt+0x3c2 + n*0x18`, count at `devExt+0x198`). Any opener that
passes the DACL can reach every IOCTL and both read/write directions.

---

## 5. Memory-write trace

### 5.1 `STTub30` — `IRP_MJ_WRITE` zero-fill overflow of the system buffer (all four builds)

Chain: `WriteFile` → `IRP_MJ_WRITE` (`+0x90` → `LAB_00014018`) → `FUN_00014028` →
`FUN_000142f4`.

In `FUN_000142f4` (`9E1CF7F9`):

- `puVar9 = *(ULONG_PTR*)(Irp + 0x18)` = `Irp->AssociatedIrp.SystemBuffer`.
- `puVar1 = devExt + pipeIndex*0x18 + 0x3c0`; `*puVar1` is the endpoint's `wMaxPacketSize`
  (filled from the configuration descriptor by `FUN_000110e4`).
- For a write (`param_3 != 0`):
  `param_5 = maxPacket * (len / maxPacket) + (len % maxPacket ? maxPacket : 0)`
  — i.e. **length rounded up to the packet size**.
- `FUN_00016860(SystemBuffer, 0, param_5)` — **memset into the system buffer**.
- Then the URB is built with `TransferBuffer = SystemBuffer` and
  `TransferBufferLength = param_5` (also rounded up).

Instruction-level (`9E1CF7F9`):

| VA | Instruction | Meaning |
|---|---|---|
| `0x14367` | `lea 0x78(rax+rax*2), rax` / `lea (rsi+rax*8), r15` | pipe descriptor = devExt + pipe*0x18 + 0x3c0 |
| `0x1437a` | `movzwl (r15), ebp` | `ebp = wMaxPacketSize` |
| `0x14386`–`0x1439a` | `idivl`/`divl`/`cmovne`/`imull` | `ebp = round_up(len, maxPacket)` |
| `0x143a7` | `movl ebp, 0x78(rsp)` | rounded length saved |
| `0x143ab` | `call 0x16860` | `memset(SystemBuffer, 0, roundedLen)` |

Because `DO_BUFFERED_IO` is set, the I/O manager allocates the system buffer at **exactly**
`Irpsp->Parameters.Write.Length` bytes. Any `WriteFile` whose length is not a multiple of the
endpoint packet size therefore zero-fills **1 … maxPacket-1 bytes past the allocation**
(64/512/1024 → up to 1023 bytes; the value comes from the USB endpoint descriptor and is
device-controlled). The corruption is immediate, needs no device response, and is repeatable.

Same code in the other builds: `STTub30_4D7F2B9D` at decomp lines 2917–2924;
`STTub30_D1083D40` at its `memset(_Dst,0,param_5)` site (decomp line 2938) with the identical
round-up; `STTub30_23C68E2F` identical.

### 5.2 `STTub30` — IOCTL `0x222014` arbitrary-length pool overflow (all four builds)

Dispatcher gate (`0x12848`–`0x12851`): `InputBufferLength >= 1 || OutputBufferLength >= 1`.
Call site `0x12885` → `FUN_000132a4` (no length arguments are passed).

`FUN_000132a4` (`9E1CF7F9`), instruction-level:

| VA | Instruction | Meaning |
|---|---|---|
| `0x132de` | `movq 0x18(r9), r12` | `r12 = Irp->SystemBuffer` |
| `0x132f8` | `movl 0x10(r12), eax` | `len = *(UINT32*)(SystemBuffer + 0x10)` — **caller-controlled** |
| `0x132fd` | `movl eax, (rsi)` | saved |
| `0x13304`–`0x1330f` | `movq rax,rdx` … `call ExAllocatePoolWithTag` | allocate `len` bytes for the URB buffer |
| `0x13337`–`0x1333b` | `lea 0x14(r14),rdx` / `call 0x16510` | if flag at `SystemBuffer+4` is 0: `memcpy(pool, SystemBuffer+0x14, len)` (transient OOB read) |
| `0x13342`–`0x13344` | `xor edx,edx` / `call 0x16860` | else: `memset(pool, 0, len)` |
| `0x133db` | `call 0x13e78` | submit `IOCTL_INTERNAL_USB_SUBMIT_URB` (`0x220003`), function code taken from `SystemBuffer[0]` |
| `0x133e9`–`0x133f1` | `movl (rsi),r8d` / `xor edx,edx` / `mov r14,rcx` / `call 0x16860` | on URB failure: **`memset(SystemBuffer, 0, len)`** |
| `0x13405`–`0x13414` | `movl (rsi),r8d` / `mov rdi,rdx` / `mov r14,rcx` / `call 0x16510` | on success and flag != 0: **`memcpy(SystemBuffer, pool, len)`** (pool is zeroed on this path) |

No comparison of `len` against `InputBufferLength`, `OutputBufferLength`, or the system-buffer
allocation exists on either branch. Consequences:

- **Failure branch (preferred):** send `0x222014` with a small input buffer (e.g. 0x18 bytes) and
  an invalid URB function in the first word. `FUN_00013e78` returns an error, and the driver
  zero-fills `len` bytes at the system buffer — an **arbitrary-length zero-fill heap overflow**
  (bounded only by what `ExAllocatePoolWithTag(0, len)` can satisfy).
- **Success branch:** the write-back only runs when the flag at `SystemBuffer+4` is non-zero, and
  that same flag made the pool buffer zero-filled, so the write-back is again a zero-fill of `len`
  bytes. With flag == 0 the driver does not write back at all, but still performs a `len`-byte
  OOB read of `SystemBuffer+0x14` into a scratch pool block (transient, freed without disclosure).

The value on every write path is therefore a fixed zero; the **length is fully controlled** in a
32-bit field. A practical value such as `0x1000` with a 0x18-byte input buffer gives a ~0xFE8-byte
zero-fill overflow at a fixed base — a classic pool-grooming primitive.

Same shape in `STTub30_4D7F2B9D` (`FUN_00013260`), `STTub30_D1083D40` (`FUN_000122ce`),
`STTub30_23C68E2F` (`FUN_00012298`).

### 5.3 `STTub30` — IOCTL `0x222004` device-length copy (secondary)

`FUN_00012d60`: allocates a 9-byte transfer buffer, submits `GET_DESCRIPTOR`, then

```
if (urb.TransferBufferLength == 0 || *(USHORT*)(buf + 2) <= requestedLen) {
    memcpy(SystemBuffer, buf, *(USHORT*)(buf + 2));   // no output-length check
    Irp->IoStatus.Information = *(USHORT*)(buf + 2);
}
```

The copied length comes from word 2 of the descriptor (e.g. `wTotalLength` for a configuration
descriptor, `bcdUSB` for a device descriptor), i.e. **device-controlled**, and is never compared
with `OutputBufferLength`. This is the same class of bug as 5.2 but with a device-chosen length.

### 5.4 VADs — no in-image write sink proven

Every in-image copy in both VADs was re-derived and checked:

| Copy | Engine | Sonar | Bound |
|---|---|---|---|
| Pin Id 14 GET | `0x14000bc00` | `0x14000dfc0` | requires `OutputBufferSize >= 0x68`; copies the block's own size dword (0x58/0x68) |
| Pin Id 15 GET | `0x14000ba5c` | `0x14000de08` | `align_up(blockSize,8) + tail <= OutputBufferSize` |
| Three-property / generic helper | `0x14000a100` / `0x14000e748` | `0x14000c0f0` / `0x140010c24` | fixed header sizes 1/8/4/0x30 after an input-length check |
| BASICSUPPORT | `0x14000e85c` | `0x140010d38` | `*outLen >= total` |
| Audio-type set/get | `0x14000f32c` etc. | `0x140011518` etc. | fixed 4 bytes, `FUN_…f4c0(…,4,4)` |
| Stream/format init | `0x14000fba0` | `0x1400124c0` | allocates `cbSize + 0x12`, copies `cbSize` (read-side over-read only) |
| GS failure stub | `0x140003990` | `0x140004080` | ≤ 15 qwords into own frame |
| "copy into object" | `0x14000a070` | `0x14000c070` | **dead code** — zero call sites in the image (confirmed by full disassembly: the only occurrence of the address is the function's own entry) |

**Sonar ring (`FUN_140003080`) — re-assessed, not sustained.** The wrap copy
`FUN_140004580(ringBuf, src+first, len-first)` is not clamped to capacity. But the capacity is set
by `FUN_140002ef4`, which computes `capacity = 2 * param_2` and is called with
`*(int*)(stream+0x80)` (KSSTATE_RUN and after format set). The chunk length passed to the ring is
`min(remaining, block - pos%block)` with `block = *(uint*)(stream+0x88)` (`FUN_140003330`).
An overflow therefore requires `block > capacity`, i.e. `*(int*)(stream+0x88) > 2 * *(int*)(stream+0x80)`.
The two fields are written together only in `FUN_140012030`/`FUN_140012120`, where `+0x80` receives
the rounded buffer size and `+0x88` receives the result of a vtable call — and those same offsets
are read with different widths by the pump (`+0x88` dword block, `+0x90` qword buffer pointer)
than they are written (`+0x90` dword). The object layouts cannot be reconciled from the image
alone, so the trigger is **not demonstrated**. Recorded as an open item, not a write.

**PortCls pointer semantics (both VADs) — external, unresolved.** The property handlers write the
GET result to `*(PVOID*)(request + 0x38)` after checking `*(UINT32*)(request + 0x30)`, and read
input from `*(PVOID*)(request + 0x28)` after checking `*(UINT32*)(request + 0x24)`. They never
probe. Whether those pointers are raw `METHOD_NEITHER` user addresses (in which case a kernel
address would be accepted as a write destination) is decided by `portcls.sys`/`ks.sys`, which are
outside the audited file set. Nothing in either image validates the pointer class, but nothing in
either image proves it is unvalidated upstream. If confirmed, Engine `0x14000bc00` /
Sonar `0x14000dfc0` would be a caller-chosen-destination write of driver format data, bounded to
0x68 bytes → R1 + W2 → **MW2**. Not rated until PortCls is in scope.

### 5.5 Hardware-only check

No `WRMSR`, `RDMSR`, `SGDT`, `LGDT`, `LIDT`, port I/O, PCI config, SMBus/EC or MMIO access exists
in any of the six images. The byte-pattern hits reported by the dump script are data bytes inside
`.rdata` (import/string tables), not instructions. `HW-ONLY` does not apply.

---

## 6. Most dangerous exposed capability

**`STTub30` (x64 3.0C `9E1CF7F9`, and 3.0B `4D7F2B9D`): a deterministic kernel-pool overflow with
attacker-controlled length, reachable by an administrator with the device present.**

The cleanest trigger is a single `WriteFile` of a length that is not a multiple of the endpoint
packet size: the driver rounds the length up and zero-fills the buffered system buffer with the
rounded value (5.1). The same driver additionally exposes IOCTL `0x222014`, which zero-fills an
arbitrarily large caller-chosen length at the same fixed base (5.2). The target is the system-buffer
pool allocation and whatever follows it; the value is a fixed zero; the size is fully controlled in
5.2 and packet-quantised (up to 1023 bytes) in 5.1. Pool grooming is the only remaining work, so
this is a real controlled-length write primitive, not a DoS.

The two VADs expose no comparable in-image sink. Their most interesting residual is the
PortCls-pointer question in 5.4, which is an external dependency rather than a demonstrated
primitive.

---

## 7. Verdict

| File | Build / arch | Setup | Reach | Write | Verdict |
|---|---|---|---|---|---|
| `STTub30_9E1CF7F9.sys` | 3.0C / x64 | hardware | R2 (device DACL) | **W2** | **MW3** |
| `STTub30_4D7F2B9D.sys` | 3.0B / x64 | hardware | R2 | **W2** | **MW3** |
| `STTub30_D1083D40.sys` | 3.0C / i386 | hardware | R2 | W2 (static) | **BLOCKED** (architecture) |
| `STTub30_23C68E2F.sys` | 3.0B / i386 | hardware | R2 | W2 (static) | **BLOCKED** (architecture) |
| `SteelSeries-Engine-VAD_78C729CA.sys` | 1.1.0.0 / x64 | devnode | R1 (INF ACE) | W0 | **NO-MEMORY-WRITE** |
| `SteelSeries-Sonar-VAD_2685B48C.sys` | 15.7.9.759 / x64 | devnode | R1 (INF ACE) | W0 | **NO-MEMORY-WRITE** |

**Overall: `MW3 — reach=R3 setup=hardware write=W2 load=signed`.**

Rationale: the two loadable `STTub30` builds contain a proven kernel-pool write (5.1, 5.2) with
controlled length and a fixed base/value, which is `W2`. The only gate is the physical STMicro USB
device (plus the admin DACL), so `SEVERITY.md` maps `R3`/hardware + `W2` to **MW3**. The i386 builds
carry the identical primitive but are not loadable on x64 → `BLOCKED` per project convention. The
VADs have no proven write → `NO-MEMORY-WRITE`.

Build-difference note (material only): the 3.0B→3.0C x64 delta is code reorganisation
(`FUN_00013260` in 3.0B vs `FUN_000132a4` in 3.0C) but the length handling is byte-for-byte
equivalent; the i386 builds re-implement the same logic with 32-bit offsets. No build fixes any of
the sinks.

---

## 8. Limitations

1. **No REA cross-check.** Four REA audits were active; per the scope rules the offline route was
   used and the REA capacity limit is disclosed. Evidence is Ghidra 12.1.4 decompilation plus
   `llvm-objdump` instruction listings; no REA evidence IDs exist for this report.
2. **No dynamic confirmation.** The overflow sizes and pool adjacency in 5.1/5.2 are derived from
   the code and from standard `METHOD_BUFFERED`/`DO_BUFFERED_IO` semantics; they were not exercised.
3. **INF not in scope.** The `STTub30` DACL conclusion rests on `IoCreateDevice` with a NULL SD
   (admin-only by default). If the shipped INF adds a permissive `Security` ACE, reach drops to R1
   and the rating rises to **MW2** (`R1` + `W2` by matrix). The VAD `WD` ACE is taken from the
   triage baseline, not re-read here.
4. **Root-devnode staging unverified.** An administrator may be able to force-install this function
   driver on a root-enumerated devnode and reach `0x222014` without the physical device (the URB
   would then always fail, making the zero-fill branch deterministic). Whether the INF permits it
   is not established; if it does, setup becomes `devnode` and the rating becomes **MW2**.
5. **Sonar ring capacity vs chunk bound** (5.4) is unresolved because two object layouts share the
   same field offsets. It is the top follow-up for that file.
6. **PortCls `Value`/`OutputBuffer` pointer class** (5.4) is outside the audited images.
7. `0x222004`'s length source (`*(USHORT*)(buf+2)`) is described by its position in a standard USB
   descriptor; the exact descriptor type selected by the caller was not traced through
   `FUN_000110e4`.
8. Inline/SSE copies were not exhaustively censused in the VADs; the `rep movs`/`memmove` census and
   every `FUN_140003fc0`/`FUN_140004580` call site were covered.
9. No exploit code, PoC, or BYOVD instruction is included.
