# Audit: Measurement Computing (MCC) group — 16 drivers (mccfwld / mccusbfn / mcpci / mcusb)

| Field | Value |
|---|---|
| File(s) | `drivers\mccfwld_05370B16.sys`, `mccfwld_2824AC5B.sys`, `mccfwld_5279671E.sys`, `mccfwld_B38AFACA.sys`, `mccusbfn_4ACB9302.sys`, `mccusbfn_5B72FADA.sys`, `mccusbfn_B05491B6.sys`, `mccusbfn_FB822917.sys`, `mcpci_10AB0B68.sys`, `mcpci_3A07C67D.sys`, `mcpci_992CA233.sys`, `mcpci_CF877AAB.sys`, `mcusb_2BA82572.sys`, `mcusb_2C269B0F.sys`, `mcusb_458020DF.sys`, `mcusb_E9D1DC60.sys` |
| SHA-256(s) | see §2 table (16 hashes, each verified against the on-disk file) |
| Analysis date | 2026-10-25 |
| Method | Static-only. PE/import/string/section triage + `.text` hashing; Ghidra 12.1.4 decompilation via REA while the shared bridge was free; **local `objdump` disassembly for the x86 builds after REA was taken over by another agent (see §9)**. No load, no execution, no service, no registry, no web. |
| Reach tier | R3 (hardware) for `mcpci` / `mccusbfn` / `mcusb`; n/a for `mccfwld` |
| Setup required | `hardware` for the three I/O families; none applicable to `mccfwld` (no user-reachable device) |
| Write quality | **W2** (`mcpci`, `mccusbfn`, `mcusb`); **W0** (`mccfwld` x64) |
| Verdict | **MW3 — reach=R3 setup=hardware write=W2 load=signed** (three I/O families); `mccfwld` x64 = **NO-MEMORY-WRITE**, `mccfwld` x86 = **BLOCKED** (architecture) |
| HW-only | yes — `mcpci` additionally hands a **user-mode mapping of its PCI BAR** to any opener (fixed-window MMIO) |

**Overall verdict: MW3.** All twelve I/O-family images (`mcpci` ×4, `mccusbfn` ×4, `mcusb` ×4) contain the same
defect class: a caller-supplied 64-bit **kernel virtual address** is taken from a `METHOD_BUFFERED` input
buffer, wrapped in an MDL with `MmProbeAndLockPages(MDL, KernelMode, …)` — no user-address validation — and
then mapped and used as the device's data buffer. Target address and length are attacker-chosen; the value
is the device's DMA data. That is a real kernel-VA write, but it is hardware-gated, so it scores **MW3**
(R3 + W2), not MW1/MW2. No image exposes `\Device\PhysicalMemory`, `ZwMapViewOfSection`, a caller-controlled
`MmMapIoSpace` physical address, or any user-mode PA mapping — **W3P does not apply to this group**.

---

## 1 Corpus / build map (material differences only)

| Family | Arch | File version | Images | `.text` SHA-256 prefix | Signer | Material difference |
|---|---|---|---|---|---|---|
| `mccfwld` | x86 | 1.0.6.0 | `05370B16`, `B38AFACA` | `abcd7d6b98c95979` (both) | Digilent / MCC | `.text` identical within arch; signer only |
| `mccfwld` | x64 | 1.0.6.0 | `2824AC5B`, `5279671E` | `554dc4e60761baba` (both) | MCC / Digilent | `.text` identical within arch; signer only |
| `mccusbfn` | x86 | 1.0.8.0 | `4ACB9302`, `B05491B6` | `1646f3f5c8362da1` (both) | MCC / Digilent | `.text` identical within arch; signer only |
| `mccusbfn` | x64 | 1.0.8.0 | `5B72FADA`, `FB822917` | `fb8f113824c373ae` (both) | MCC / Digilent | `.text` identical within arch; signer only |
| `mcpci` | x64 | 1.3.4.0 | `10AB0B68`, `3A07C67D` | `1d704dac6cba450a` (both) | MCC / Digilent | `.text` identical within arch; signer only |
| `mcpci` | x86 | 1.3.4.0 | `992CA233`, `CF877AAB` | `e56efe5232f76082` (both) | MCC / Digilent | `.text` identical within arch; signer only |
| `mcusb` | x86 | 1.16.0.0 | `2BA82572`, `2C269B0F` | `920aeaf516bec449` (both) | MCC / Digilent | `.text` identical within arch; signer only |
| `mcusb` | x64 | 1.16.0.0 | `458020DF`, `E9D1DC60` | `a46d91a3c7cbd30e` (both) | MCC / Digilent | `.text` identical within arch; signer only |

All 16 have `ProductVersion 6.74.0.0` and a **valid** Authenticode signature. On-disk size differs inside a
pair (extra certificate padding) but `.text` is byte-identical, so a pair member is one build signed twice.
x86 and x64 are genuinely separate builds: structure offsets and helper layouts differ (e.g. `mccusbfn`
channel stride `0x109a8` x64 vs `0x10958` x86; `mcusb` stride `0x68000`), but the defect is the same.
**No x86/x64 difference changes a verdict.** The only verdict-relevant architecture difference is that the
i386 images cannot load on the x64 host.

---

## 2 Per-file results

| # | File | Arch | SHA-256 | Setup | Write | Verdict |
|---|---|---|---|---|---|---|
| 1 | `mccfwld_05370B16.sys` | x86 | `05370B16E9EBF30AD0FEF6FE7249C039388026C9D96C63D63B78F076098A603B` | n/a | W0 | **BLOCKED** (architecture) |
| 2 | `mccfwld_2824AC5B.sys` | x64 | `2824AC5B44CD526A718D4C54909C52F706B91A2940F7804FAD5BB05AACC55E21` | none | W0 | **NO-MEMORY-WRITE** |
| 3 | `mccfwld_5279671E.sys` | x64 | `5279671EE760069A9DBB9C3054177C3781AF60E7ACC009F52DAFDEEB93C30317` | none | W0 | **NO-MEMORY-WRITE** |
| 4 | `mccfwld_B38AFACA.sys` | x86 | `B38AFACA3E72DB5E0DDE3B969509FE5F4D56FC983B821ED146003E4E42D2E182` | n/a | W0 | **BLOCKED** (architecture) |
| 5 | `mccusbfn_4ACB9302.sys` | x86 | `4ACB9302B3461DE476AFB871772E9D03DC67B6E1B60F1351FD88641724AFD2EC` | hardware | W2 | **MW3** |
| 6 | `mccusbfn_5B72FADA.sys` | x64 | `5B72FADA1428ECE9FF00AE635E0AB8847C7E03F082BB367F41A22E4268A60537` | hardware | W2 | **MW3** |
| 7 | `mccusbfn_B05491B6.sys` | x86 | `B05491B66EA99FD59D0E51C05DED02CC498A92E5A773DA40A2A1088AD319BC9A` | hardware | W2 | **MW3** |
| 8 | `mccusbfn_FB822917.sys` | x64 | `FB822917B64835D3CD8C4422C8E7127B041A5E12FD7D5AAB7FD0B526B1AA99BF` | hardware | W2 | **MW3** |
| 9 | `mcpci_10AB0B68.sys` | x64 | `10AB0B685CBB724290086224F94FF945D2EBDAEBC94DD33B8BA9302251CA8DD5` | hardware | W2 | **MW3** |
| 10 | `mcpci_3A07C67D.sys` | x64 | `3A07C67D67022C4B91C8FD4C38F2324C0F27645DB6C0B8F76F981C24293D9774` | hardware | W2 | **MW3** |
| 11 | `mcpci_992CA233.sys` | x86 | `992CA23383E249D310E4CC5DCD132CE726542A2C9FF1F9E6EE197CBFC2AE0ACA` | hardware | W2 | **MW3** |
| 12 | `mcpci_CF877AAB.sys` | x86 | `CF877AAB540798FB521CFFAE5587F7402F1A8C57584E3E77A4A2CDC822AA7D9F` | hardware | W2 | **MW3** |
| 13 | `mcusb_2BA82572.sys` | x86 | `2BA82572F6927BD8107D375A90D3289FBAD8F4B9AEE5FF86EB284C396C4FEF40` | hardware | W2 | **MW3** |
| 14 | `mcusb_2C269B0F.sys` | x86 | `2C269B0F1EA347BD02A0B656C9D5077AC5DEA3AD395631331EAA080ED63BD08C` | hardware | W2 | **MW3** |
| 15 | `mcusb_458020DF.sys` | x64 | `458020DF5A65BA37EC54D6EC0B699F931EB5BFD02A714BC49B8D3F7701F32344` | hardware | W2 | **MW3** |
| 16 | `mcusb_E9D1DC60.sys` | x64 | `E9D1DC60CF2F6DC98F118838285D716AEE2EC748B2F63B85BFADED02028875D4` | hardware | W2 | **MW3** |

`mccfwld` x64 is rated `Setup: none` because it needs no hardware to be *installed*; it nevertheless exposes
no interface, so nothing is reachable.

---

## 3 Internals (what each family is)

- **`mccfwld` — "MCC Firmware Loader" (KMDF function driver).** Loaded against MCC USB DAQ devices; on
  start it reads the USB device descriptor, picks a firmware image from ~150 KB of images embedded in
  `.data` (e.g. `USB-2404-UI`, `USB-1208MS-10`) and downloads it. Code is split across `.text` (1–2 KB of
  helpers) and `PAGE`/`INIT` (0x3C014+). **No queue, no interface, no symbolic link** (§4).
- **`mccusbfn` — "MCCUSBFN" (KMDF USB function driver, "Fusion" transport).** Per-product pipe tables
  (`0x70A4/0x70A6/0x70A7/0x71C2/0x7270/0x72FD/0x76C4/0x76C6` …), bulk/interrupt pipes, a large per-channel
  context (`0x109a8` x64), scan state machine and a 0x8DE-byte scan descriptor.
- **`mcpci` — "Driver for PCI Devices" (KMDF PCI function driver for PCI-6000-class DAQ boards).** Maps the
  BARs from the PnP resource list, allocates contiguous DMA memory, exposes a `PCI6000_USER_INFO` request
  context, and submits multi-channel scans described by a 0xE4-byte user structure.
- **`mcusb` — "MCUSB" (KMDF USB DAQ driver, v1.16).** Same shape as `mccusbfn` with a different transport
  layer: 0x8DF-byte scan descriptor, `0x68000` per-channel stride, on-disk FPGA/RBF loading via
  `ZwOpenFile`/`ZwReadFile`.

---

## 4 Entry / device / interface / effective DACL

Addresses are Ghidra VAs (image base `0x10000` for every image here); x86 file RVA = VA − `0x10000`.

| Family | `DriverEntry` path | `EvtDriverDeviceAdd` | Device object | Interface GUID | Queue / dispatch |
|---|---|---|---|---|---|
| `mccfwld` x64 | `0x1125C` → `0x3D100` → `0x3D008` | `0x3C014` | `WdfDeviceCreate` @ `0x39858` | **none** | **none** (`WdfIoQueueCreate` never called; no `WdfDeviceCreateDeviceInterface`, no symlink) |
| `mccusbfn` x64 | `0x25100` → `0x25008` | `0x1E014` | `WdfDeviceCreate` @ `0x1B418` | `{9094E991-B0B4-4E1C-AFDF-9AED298F5D1B}` (`WdfDeviceCreateDeviceInterface` @ `0x1B428`, GUID at `0x1A1A8`) | default queue `FUN_00020994`; read/write queues `FUN_000124F8` / `FUN_000126A4` via `WdfDeviceConfigureRequestDispatching` types 3/4 |
| `mcpci` x64 | `0x1795C` → `0x1C0B0` → `0x1C008` | `0x11014` | `WdfDeviceCreate` @ `0x19428` | `{BC20052D-05A9-4CCE-92FD-4A9E769D41D0}` (GUID at `0x18150`) | queue callback `FUN_00011444` (3-arg); device-control gate `FUN_000122A0` |
| `mcusb` x64 | `0x22100` → `0x22008` | `0x1D014` | `WdfDeviceCreate` @ `0x1A418` | `{7AC4DE2F-80E2-4BF0-8EEE-F5D26055F956}` (GUID at `0x191C8`) | default queue `FUN_0001DC18`; read/write queues `FUN_00013230` / `FUN_00013450` |

The same GUIDs are present byte-for-byte in the corresponding x86 builds and in both pair members, i.e. the
interface identity is stable across all four builds of a family.

**Effective DACL.** None of the 16 images contains an SDDL string, a security descriptor, an
`IoCreateDeviceSecure` import, `SeAccessCheck`, or `SeSinglePrivilegeCheck` (verified by import-table walk,
ASCII and UTF-16 string scan, and by reading every `EvtDriverDeviceAdd`). Device creation is plain
`WdfDeviceCreate`, so the device receives the **framework default PnP descriptor: full access to
`NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`, no write access for unprivileged users**. There is also
no `\DosDevices\` / `\??\` name anywhere, so the only user-visible handle is the device interface above
(reachable as `\\?\GLOBALROOT\Device\…` via the interface path) and its DACL is the gate.

**Reach: R3 (hardware); a local administrator satisfies the DACL.** `mccfwld` creates a device object with
no interface and no queue, so it has **no openable user-mode surface at all** — an administrator cannot reach
an IOCTL handler because none exists.

---

## 5 Dispatch and IOCTL table

All MCC control codes are `METHOD_BUFFERED` on device type `0x8000` (`mccusbfn`, `mcusb`) or `0x8678`
(`mcpci`); access bits follow the usual `FILE_WRITE_ACCESS` (`0x6xxx`), `FILE_READ_ACCESS` (`0xAxxx`),
read+write (`0xExxx`) split. Because the method is buffered, **every pointer stored inside the input
structure is pure user data** — which is exactly why the MDL construction below is unsound.

### 5.1 `mcpci`

| Code | Method / access | Input | Kernel action |
|---|---|---|---|
| `0x86782010` | BUFFERED / FILE_ANY_ACCESS (DeviceType `0x8678`, Function `0x804`) | ≥ `0xE4` bytes | `WdfRequestRetrieveInputBuffer(0xE4)` → channel index at `+0xB0`, params at `+0x10..+0x14`, per-channel descriptor pointer at `+0x40/+0x50/+0x60/+0x80/+0xA0`, event handle at `+0xB4` → `FUN_00012C30` builds MDLs and arms the scan |
| (second path) | BUFFERED | output `PCI6000_USER_INFO` | `FUN_00011444` returns **user-mode VAs of the MMIO windows** (see §6.2) |

Gate: `FUN_000122A0` compares the framework request block at `+0x18` against `0x86782010` (`CMP dword ptr
[RSP+0x48], 0x86782010` at `0x122E3`) and a request-type field at `+4` against `0x0E`
(`IRP_MJ_DEVICE_CONTROL`); everything else is passed to the default handler.

### 5.2 `mccusbfn` (`FUN_00020994`, x64)

`0x80006000`, `0x80006004`, `0x80006008`, `0x8000600C`, `0x8000603C`, `0x80006040`, `0x80006044`,
`0x8000A010`, `0x8000A018`, `0x8000A028`, **`0x8000A02C`**, `0x8000A030`, `0x8000A038`, `0x8000A048`,
`0x8000E014`, `0x8000E01C`, `0x8000E020`, `0x8000E024`, `0x8000E034` — all BUFFERED.
Read/write queues additionally accept `IRP_MJ_READ` / `IRP_MJ_WRITE` (cap 0x10000, `FUN_000124F8` /
`FUN_000126A4`).

**`0x8000A02C` (SCAN_INFO_SET)** → `FUN_000219F8`: retrieves a `0x8DE`-byte input buffer and
`memcpy(ctx + 0x10158 + channel*0x109A8, input, 0x8DE)` — a whole caller-controlled channel descriptor,
including the **buffer pointer at `+0x10`** and the **length fields at `+0x6` (i32) and `+0xE` (u16)**.

### 5.3 `mcusb` (`FUN_0001DC18`, x64)

`0x80006000`, `0x80006008`, `0x8000600C`, `0x80006010`, `0x80006034`, `0x8000603C`, `0x80006040`,
`0x80006044`, `0x8000A020`, **`0x8000A024`**, `0x8000A028`, `0x8000A030`, `0x8000A038`, `0x8000E014`,
`0x8000E018`, `0x8000E01C`, `0x8000E02C`, `0x80016000`, `0x80016004`, `0x8001A010`, `0x8001E008`,
`0x8001E00C`, `0x8001E014`, `0x8001E018` — all BUFFERED, plus read/write queues.

**`0x8000A024`** → `FUN_0001EF38`: `memcpy(ctx + 0x10260 + channel*0x68000, input, 0x8DF)` — same
caller-controlled descriptor, with the **buffer pointer at `+0x11`** and **length at `+0x7` / `+0xF`**.

### 5.4 `mccfwld`

No `IRP_MJ_DEVICE_CONTROL` surface. No queue object is ever created, so no IOCTL code exists to enumerate.

---

## 6 Memory-write trace

### 6.1 The shared defect: caller VA → MDL with `AccessMode = KernelMode`

`mccusbfn` (x64), `FUN_00014EE0` / `FUN_000225AC` — the read and write transfer paths:

```c
if (*(u64 *)(ctx + 0x10) == 0 || *(i32 *)(ctx + 6) == 0 || *(u16 *)(ctx + 0xE) == 0) return STATUS_...;
mdl = IoAllocateMdl(*(u64 *)(ctx + 0x10),          /* caller VA, no probe, no validation */
                    *(u16 *)(ctx + 0xE) * *(i32 *)(ctx + 6));  /* caller length, 32-bit */
MmProbeAndLockPages(mdl, 0 /* KernelMode */, 2 /* IoModifyAccess */);
va = MmMapLockedPagesSpecifyCache(mdl, 0 /* KernelMode */, 1 /* MmCached */, NULL, FALSE, 0x10);
```

x86 proof (`mccusbfn_4ACB9302`, identical `.text` in `B05491B6`), `objdump`:

```
150f8: 6a 02                    push $0x2          ; IoModifyAccess
150fa: 57                       push %edi          ; AccessMode = 0  (KernelMode)
150fb: 50                       push %eax          ; MDL
150fc: ff 15 68 7a 01 00        call *0x17a68       ; MmProbeAndLockPages
15116: 6a 10                    push $0x10         ; Priority
15118: 57                       push %edi          ; BugCheckOnFailure = 0
15119: 57                       push %edi          ; RequestedAddress = NULL
1511a: 6a 01                    push $0x1          ; CacheType = MmCached
1511c: 57                       push %edi          ; AccessMode = 0  (KernelMode)
1511d: 50                       push %eax          ; MDL
1511e: ff 15 64 7a 01 00        call *0x17a64       ; MmMapLockedPagesSpecifyCache
```

`mcusb` is the same code shape with `ctx + 0x11`, `+0x7`, `+0xF` (`FUN_000149D0`, `FUN_0001F9FC`; x86
`0x14A78/0x14A90/0x14AB9`, `0x4A78/0x4A90/0x4AB9`).

`mcpci`, `FUN_00012C30` goes one step further — **two** caller pointers:

1. `ptr1 = *(u64 *)(input + 0x40/0x50/0x60/0x80/0xA0)` (per channel), `IoAllocateMdl(ptr1, 99)` +
   `MmProbeAndLockPages(..., KernelMode, IoReadAccess)` + map (`0x12E23/0x12E4D`, `0x12EC2/0x12EF6`).
   The driver then reads `{len2 @ +0x30, ptr2 @ +0x38}` **out of that buffer**.
2. `IoAllocateMdl(ptr2, len2 * 2)` + `MmProbeAndLockPages(..., KernelMode, IoModifyAccess)` + map
   (`0x133DF/0x13409`, `0x13481/0x134B5`) — this becomes the scan DMA buffer.

x86 `mcpci` (`992CA233`, identical `.text` in `CF877AAB`) shows the same two sites at `0x116B5`/`0x116CE`
and `0x1174D`/`0x1176D` with `push $0x2; push %ebx(=0); push MDL`.

**What the caller controls**

| Input | Source | Control |
|---|---|---|
| target VA | `mcpci`: input `+0x40…` and `+0x38` of the first buffer; `mccusbfn`/`mcusb`: blob `+0x10` / `+0x11` | **arbitrary 64-bit kernel VA** |
| length | `mcpci`: `*(u32)(buf+0x30) * 2`; USB: `u16 * i32` | **arbitrary 32-bit** |
| value | device data (PCI scan samples / USB IN payload) | **not directly**, device-dependent |
| trigger | the same IOCTL, or scan/read start | arbitrary |

There is **no** `ProbeForRead`/`ProbeForWrite`, no `MmHighestUserAddress` comparison, no
`ExGetPreviousMode` check, and no `try/except` visible around the probe. An invalid address faults inside
`MmProbeAndLockPages` (the x86 builds do import `RtlUnwind`/`__C_specific_handler`, so a fault may be
converted rather than bugchecking, but that is a reliability detail, not a mitigation).

**Direction.** For the USB families the MDL is the transfer buffer for the pipe: an IN transfer makes the
host controller write device-supplied bytes into the chosen kernel pages, an OUT transfer reads kernel memory
into the device. For `mcpci` the mapped buffer is the scan data buffer written by the board. In every case the
*kernel write target is the caller's address*, which is the primitive.

### 6.2 `mcpci` also hands the PCI BAR to user mode (HW-ONLY)

`FUN_00011D30` walks `WdfCmResourceListGetDescriptor` output and calls
`MmMapIoSpace(descriptor->Memory.Start, descriptor->Memory.Length, 0)` at `0x11DFB` — **the address comes from
the PnP resource list, never from the caller**, so this is *not* a caller-controlled PA. It then builds an MDL
over that mapping (`IoAllocateMdl` + `MmBuildMdlForNonPagedPool`, `0x11E23`).

`FUN_00011444` iterates the five resource records and, for type==memory, maps that MDL with
`MmMapLockedPagesSpecifyCache(mdl, 1 /* UserMode */, 0 /* MmNonCached */, NULL, 0, 0x20)` (`0x115A4` x64;
`0x10A18–0x10A20` x86: `push 0x20 / 0 / 0 / 0 / 1 / MDL`) and stores the resulting **user VAs** into the
`PCI6000_USER_INFO` request context at `+8 + i*8`.

Consequence: any opener gets a writable user-mode mapping of the board's MMIO windows. That is
**`HW-ONLY` (fixed-window device MMIO)** under `SEVERITY.md` — it is not a kernel memory write. Residual: a BAR
that contains a bus-master DMA engine could be programmed from user mode to write physical memory; the
register map is hardware-defined and not present in the `.sys`, so it is recorded as an unresolved residual,
not as a scored primitive.

### 6.3 What is *not* present

- No `\Device\PhysicalMemory`, no `ZwMapViewOfSection`, no `MmCopyMemory`, no `KeStackAttachProcess` in any of
  the 16 images (import walk + string scan).
- No `MmMapIoSpace` with a caller-supplied PA; the only `MmMapIoSpace` (`mcpci`) is resource-list driven.
- No user-mode PA mapping (no `W3P`), therefore no `PhysicalMemory`-style read/write.
- No unchecked `memcpy` into a fixed kernel object on the traced paths. `mcusb`'s `memcpy` sites are bounded:
  the literal-sized ones (`0x8DF`, `0x802`, `0x80`) and the ring-buffer routine at `0x148F8`
  (`min(remaining, limit − offset)`, `0x14950–0x14960`). The `mccusbfn`/`mcusb` descriptor copies are
  fixed-size and target a context field of matching size.
- `mccfwld` imports only `KeBugCheckEx`, `RtlCompareMemory`, `RtlCopyUnicodeString`, `WdfVersionBind/Unbind`
  (plus `memset`, `KeTickCount` on x86). No mapping, no MDL, no probe, no copy-to-user.

---

## 7 Access-control audit

| Check | Result |
|---|---|
| Explicit SDDL / security descriptor | none in any of the 16 |
| `IoCreateDeviceSecure` | not imported |
| `SeAccessCheck` / `SeSinglePrivilegeCheck` / `ExGetPreviousMode` | not imported |
| Named device / DOS symlink | none — interface GUID only (or nothing for `mccfwld`) |
| File-object access bits vs. IOCTL access | codes use `FILE_READ/WRITE_ACCESS` bits, but a buffered control reaches the handler after the DACL check; access bits add nothing |
| Caller identity checks | `mcpci` records `PsGetCurrentProcessId()` for channel ownership (`FUN_00011444`, `FUN_00012C30`); `mccusbfn`/`mcusb` reference an event handle with `ObReferenceObjectByHandle(..., 0x100000, ...)`. These serialise channel ownership; **they do not validate buffer addresses** |
| Gate for the write primitive | device DACL (admin) + physical board present |

`mcpci`'s process-ID/ownership check is the only meaningful state check, and it is passed by any process that
acquired the channel first — it constrains *concurrency*, not the target address.

---

## 8 Most dangerous exposed capability

For all three I/O families: **an administrator (R2) who has the matching MCC board can hand the driver an
arbitrary kernel virtual address and an arbitrary 32-bit length, and have that range locked, mapped and used
as the device's data buffer** — a kernel-VA write with device-controlled contents, crash-first on a bad
address. That is the strongest primitive in the group.

Secondary, `mcpci` only: a **user-mode writable mapping of the board's PCI BAR** handed to any opener
(HW-ONLY, with a device-DMA residual).

`mccfwld` exposes nothing: no interface, no queue, no IOCTL, no memory API.

---

## 9 Method, evidence and the REA gap (disclosure)

- SHA-256 verified for all 16 files before analysis; `.text` hashes computed over the raw section to prove
  intra-pair identity.
- Initial decompilation (`mcpci` x64, `mccusbfn` x64, `mcusb` x64, `mccfwld` x64) was done with REA on the
  shared bridge while it was free; the binary returned matched the requested SHA-256 each time.
- **Mid-audit the REA bridge was taken over by a concurrently running audit**: a call issued against
  `mccusbfn_4ACB9302.sys` came back bound to `rtf64x64_DFB5842C.sys` (image base `0x140000000`). I stopped
  using REA at that point and finished the x86 verification with **local LLVM `objdump` 20.1.5** on
  the files themselves (IAT walk + instruction-level argument check), plus local PE parsing.
- The x86 conclusions therefore rest on disassembly of the exact argument setup (`push $2 / push 0 / push MDL
  / call [IAT]`), which is stronger than a decompiler rendering for this specific question. The x64
  conclusions rest on Ghidra 12.1.4 pseudocode plus the same import/call-site cross-check.
- WDF API names (`WdfDeviceCreate`, `WdfIoQueueCreate`, `WdfDeviceCreateDeviceInterface`,
  `WdfDeviceConfigureRequestDispatching`, `WdfDeviceInitSetIoType`) are **inferred** from call arity,
  structure sizes and ordering: `WDFLDR.SYS` is bound at runtime through `WdfVersionBind`, so no WDF symbol
  name appears in any import table. The *behaviour* cited (device created, interface registered, queue
  created) is observable from the call sequence and the GUID/queue-config blobs; the API labels are the
  conventional reading.

---

## 10 Limitations

1. **DACL is inferred from the framework default.** No SDDL exists in the image. The INF — not in the corpus —
   can add a `Security` value that widens or narrows the descriptor. The opener therefore has to be an
   administrator (R2 to satisfy the ACL); because the board must additionally be present, the report's Reach
   is recorded as R3 with `Setup: hardware`.
2. **Device gating is assumed from the driver model.** `mcpci` is a PCI function driver and
   `mccusbfn`/`mcusb` are USB function drivers; without the matching board (or a spoofed device with the
   right VID/PID) the FDO is never created and none of these paths exist. That is why the verdict is MW3 and
   not MW2 — I did not verify that a software-only devnode can instantiate them.
3. **Value control is not proven arbitrary.** The write payload is board/USB data. An attacker who owns the
   device can influence it (digital input patterns, loopback, crafted firmware), but I did not demonstrate
   arbitrary bytes reach the target.
4. **Exact scan/DMA hand-off not fully traced.** For `mcpci` I traced the MDL construction and storage into
   the channel descriptor; I did not follow every register write that arms the board's engine. For the USB
   families the MDL is passed to the WDF USB target pipe; the framework's own MDL handling was not audited.
5. **No dynamic confirmation.** Nothing was loaded or executed; no crash/behaviour claims are made.
6. **Non-memory IOCTLs are enumerated by code only.** The ~60 control codes in `mccusbfn`/`mcusb` were
   classified by access/method and by their call target where it mattered for memory writes; the remainder
   are configuration/status operations and were not traced instruction-by-instruction.
7. Prior per-file reports `mccfwld_05370B16.admin.static.md` and `mccfwld_B38AFACA.admin.static.md` are
   **superseded for those two files** by this report: they stopped at imports without running a decompiler and
   labelled the family `BLOCKED`, which is correct only for the i386 builds — the x64 siblings are loadable and
   are `NO-MEMORY-WRITE`, not `BLOCKED`.
