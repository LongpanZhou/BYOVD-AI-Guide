# Audit: FPGATEST (C-Media "IsoUsb" USB-audio test driver) - x64 `97A95152` and x86 `DFC3F0A7`

| Field | Value |
|---|---|
| File(s) | `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\FPGATEST_97A95152.sys` (x64)<br>`C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\FPGATEST_DFC3F0A7.sys` (x86) |
| SHA-256(s) | x64 `97A95152030D52E23E0D2C8659A5AC3AA12377C1D36D847A045FE31564C45A98`<br>x86 `DFC3F0A7814EA7031E6F8401A140FF131BEABDA50B50E09FFD81DFF2F050ACA8` |
| Analysis date | 2026-10-25 |
| Method | Static-only. Local Ghidra 12.1.4 headless decompilation of both images, plus `llvm-objdump` instruction checks and `dumpbin`/PE-header/import inspection. No load, execute, install, service creation, or registry access. **REA was not used** (four REA audits were already active, per the capacity limit); no REA evidence IDs are cited. |
| Reach tier | **R3 - hardware** (the FDO exists only when the matching USB device is enumerated). No user-privilege gate: default device DACL + all IOCTLs `FILE_ANY_ACCESS`, so a read-only handle is sufficient. |
| Setup required | **hardware** (USB device bound by the package INF; `AddDevice` is the only device-creation path) |
| Write quality | **W2** - arbitrary kernel-VA target and caller-chosen length, but the bytes written are supplied by the USB peer, not by the IOCTL caller |
| Verdict | **BLOCKED** (static **MW3**) - unsigned x64 image (default DSE/HVCI blocks load); x86 image is a 32-bit kernel image and cannot load on this x64 host |
| HW-only | no |

## Per-file results

| File | Arch | Size | Machine / subsystem | Version | Signature | Load under default DSE | Static primitive | Static severity | Status |
|---|---|---:|---|---|---|---|---|---|---|
| `FPGATEST_97A95152.sys` | x64 (PE32+) | 37,888 | `0x8664`, subsystem Native, OS 6.1 | C-Media 1.0.7.1, "IsoUsb Driver" | **None** (Certificates directory RVA/size = 0; `Get-AuthenticodeSignature` = `NotSigned`) | **No** - unsigned kernel image rejected (`STATUS_INVALID_IMAGE_HASH`); HVCI also blocks | Caller-chosen kernel VA + length locked via `MmProbeAndLockPages(..., KernelMode, IoModifyAccess)` and installed as a USB IN transfer buffer | **MW3** | **BLOCKED** |
| `FPGATEST_DFC3F0A7.sys` | x86 (PE32) | 27,136 | `0x14C`, subsystem Native, OS 6.1 | C-Media 1.0.7.1, "IsoUsb Driver" | **None** (Certificates directory = 0; `NotSigned`) | **No on this host** - 32-bit kernel image cannot load on an x64 kernel. (It would load on 32-bit Windows, where KMCS is not enforced.) | Same primitive, same IOCTLs, same defect | **MW3** | **BLOCKED** |

**Overall verdict: BLOCKED (static MW3).** The static primitive is a real, caller-addressed kernel memory write, but it is hardware-gated and both builds are unloadable as supplied on the audit host.

---

## 1. Internals

Both files are the same product built from `c:\audiotestdriver_new` (PDB paths: `objfre_wnet_amd64\amd64\FPGATEST.pdb` for x64; `objfre_wxp_x86\i386\FPGATEST.pdb` for x86). They are WDM USB function drivers for a C-Media USB audio device:

* `DriverEntry` - x64 `0x11008` (entry thunk `0x1C064`), x86 `0x10664`.
* `AddDevice` - x64 `0x11148`, x86 `0x104A6`; calls `IoCreateDevice` and `IoAttachDeviceToDeviceStack`, i.e. it binds to a PnP USB PDO. It does not create a control device of its own.
* Imports of interest (both builds): `IoAllocateMdl`, `MmProbeAndLockPages`, `MmMapLockedPagesSpecifyCache`, `MmUnlockPages`, `IoFreeMdl`, `IoBuildDeviceIoControlRequest`, `USBD_ParseConfigurationDescriptorEx`, `USBD_CreateConfigurationRequestEx`, `WmiSystemControl`.
* **No** `MmMapIoSpace`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `KeStackAttachProcess`, `IoCreateDeviceSecure`, `RtlSetDaclSecurityDescriptor`, `ZwSetSecurityObject`, or any `Se*` authorization import.
* Both images opt out of ASLR/NX in the PE header (`DllCharacteristics = 0`) and neither has an embedded signature.

## 2. Entry / device / interface / effective DACL

### 2.1 Device creation

| Build | Call site | Arguments |
|---|---|---|
| x64 | `0x11186` | `IoCreateDevice(DriverObject, 0x168, NULL, 0x22 /*FILE_DEVICE_UNKNOWN*/, 0x80 /*FILE_DEVICE_SECURE_OPEN*/, FALSE, &devobj)` |
| x86 | `0x104C7` | `IoCreateDevice(DriverObject, 0xF0, NULL, 0x22, 0x80, FALSE, &devobj)` |

The device is **unnamed** (no `\Device\...` name, no `\DosDevices\...` symlink, no `IoCreateSymbolicLink` import/string in either image). Its only open path is the device interface registered in `AddDevice`:

* x64 `IoRegisterDeviceInterface(..., &GUID, NULL, ...)` at `0x11302`; GUID blob at `0x16200`.
* x86: `IoRegisterDeviceInterface(..., &GUID, NULL, ...)` at `0x105BC`; GUID blob at `0x1353C`.
* GUID (both): **`{db5f3539-8ff8-4cdb-84c5-dd9ea70b1a30}`**.
* Enabled on PnP start: x64 `IoSetDeviceInterfaceState(..., TRUE)` at `0x11698`; x86 equivalent in its start path.

### 2.2 Effective SDDL / DACL

There is **no security descriptor in either image**: `IoCreateDevice` is called with a NULL SD, `IoCreateDeviceSecure` is not imported, there is no SDDL string (`D:P(...)` scan is empty), and there is no `ZwSetSecurityObject`/`RtlSetDaclSecurityDescriptor` path. The FDO therefore receives the I/O manager's **default device DACL**:

```
D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)
```

i.e. `SYSTEM` and `BUILTIN\Administrators` full control, `Everyone` `FILE_GENERIC_READ`. This is OS behaviour, not bytes in the `.sys`; it is corroborated by the absence of any SD-setting code and by `FILE_DEVICE_SECURE_OPEN` being set, which forces the DACL to be evaluated on opens through the interface symlink.

**Consequence:** because every IOCTL is `FILE_ANY_ACCESS` (see section 3), a standard user who can open the interface read-only can issue them. The DACL is therefore **not** an admin gate for the IOCTL surface; the practical gate is hardware presence. At worst (an INF/class-installer `Security` override, not supplied) the same codes remain reachable.

### 2.3 Open gate / privilege checks

There is **no privilege or token check** in either driver: no `SeAccessCheck`, `SeSinglePrivilegeCheck`, `SeExports`, `PsGetCurrentProcess`/token query, or handshake. `IRP_MJ_CREATE` (`0x130D4` / `0x11DC0`) only allocates a 0x10-byte file context and increments a handle counter, and rejects opens while the device is not in state 2 (`STATUS_INVALID_DEVICE_STATE`). `IRP_MJ_CLEANUP`/`CLOSE` free that context and tear down streams.

**Gate summary:** default DACL (world-readable) -> no in-driver auth -> device must be started (`DevExt+0x88 == 2`).

## 3. Dispatch and IOCTL table

Dispatch is a single `IRP_MJ_DEVICE_CONTROL` handler:

* x64 `DRIVER_OBJECT+0xE0` = `FUN_000131E8` (set at `0x11096`); x86 `+0x70` = `FUN_00011E9C` (set at `0x106CB`).
* Only CREATE (`0x70`/`0x38`), CLOSE (`0x80`/`0x40`), DEVICE_CONTROL (`0xE0`/`0x70`), CLEANUP (`0x100`/`0x80`), POWER (`0x120`/`0x90`), SYSTEM_CONTROL (`0x128`/`0x94`) and PNP (`0x148`/`0xA4`) are hooked. There is **no** `IRP_MJ_READ` or `IRP_MJ_WRITE` handler.
* All codes are `CTL_CODE(0x22, function, METHOD_BUFFERED, FILE_ANY_ACCESS)`; the handler reads `SystemBuffer` (x64 `IRP+0x18`, x86 `IRP+0x0C`), `OutputBufferLength` (`IrpSp+0x08` / `+0x04`), `InputBufferLength` (`IrpSp+0x10` / `+0x08`) and `IoControlCode` (`IrpSp+0x18` / `+0x0C`).

| IOCTL | Fn | Method / access | Input length check | Output | Kernel action |
|---|---:|---|---|---|---|
| `0x220000` | 0 | BUFFERED / ANY | none needed | `>= wTotalLength` enforced | Copies the cached configuration descriptor (`wTotalLength` bytes) to `SystemBuffer`. |
| `0x22000C` | 3 | BUFFERED / ANY | **none** (reads 1 byte) | 0 | Looks up a stream by index byte in the device list and tears it down (`FUN_000146C4`). Cross-handle: does not verify the stream belongs to the calling handle. |
| `0x220010` | 4 | BUFFERED / ANY | x64 `== 0x40`; x86 `== 0x28` | 0 | Start stream A: allocates a 200-byte context, builds **3 MDLs from user VAs with `MmProbeAndLockPages(..., UserMode, IoModifyAccess)`**, maps them, starts system thread `FUN_00019448`. |
| `0x220014` | 5 | BUFFERED / ANY | **none** (needs >=0x18 x64 / >=0x10 x86) | 0 | **Control / vendor / class / interface request.** Builds an MDL from a caller VA with `MmProbeAndLockPages(..., KernelMode, ...)` and submits a USB request with caller length. See section 5. |
| `0x220018` | 6 | BUFFERED / ANY | **none** (reads 1 byte) | 0 | Atomically takes the stream pointer from `FileObject->FsContext+8` and stops/frees it (`FUN_0001B590`). |
| `0x22001C` | 7 | BUFFERED / ANY | none | 0 | Starts capture thread `FUN_0001AC18` (no user buffer). |
| `0x220020` | 8 | BUFFERED / ANY | x64 `== 0x40` (WOW64 `== 0x30`); x86 `== 0x28` | 0 | Start stream B: same user-VA MDL pattern (**UserMode** probe), starts thread `FUN_00019008`. |
| `0x220024` | 9 | BUFFERED / ANY | **none** (reads 1 byte) | 0 | Same stream lookup/teardown as `0x22000C`. |
| `0x220028` | 10 | BUFFERED / ANY | none | `>= 4` enforced | Returns the DWORD at `DevExt+0x14C` (x64) / `+0xDC` (x86). |
| `0x22002C` | 11 | BUFFERED / ANY | **none** (reads 1 byte) | 0 | Stream lookup, atomically clears the link and stops the stream. |
| `0x220030` | 12 | BUFFERED / ANY | none | 0 | Starts render thread `FUN_0001AF78` (no user buffer). |
| `0x220034` | 13 | BUFFERED / ANY | **none** (needs >=0x10 x64 / >=0x08 x86) | 0 | **Bulk/interrupt IN** (`TransferFlags = 3`) with caller VA + length. See section 5. |
| `0x220038` | 14 | BUFFERED / ANY | **none** (needs >=0x10 x64 / >=0x08 x86) | 0 | **Bulk/interrupt OUT** (`TransferFlags = 2`) with caller VA + length - kernel **read** sent to the device. |

Functions 1 and 2 (`0x220004`, `0x220008`) are not handled (`STATUS_INVALID_DEVICE_REQUEST`).

## 4. Access-control audit

| Gate | Present? | Notes |
|---|---|---|
| Explicit SDDL / `IoCreateDeviceSecure` | No | NULL SD -> OS default device DACL (`SYSTEM`/`Administrators` full, `Everyone` read) |
| `FILE_DEVICE_SECURE_OPEN` | Yes (`0x80`) | DACL enforced on the interface symlink |
| `SeAccessCheck` / `SeSinglePrivilegeCheck` / token test | No | No `Se*` imports in either build |
| Per-IOCTL access mask | No | All codes `FILE_ANY_ACCESS`; a read-only handle is enough |
| Caller identity / handshake | No | Only the device-state check (`DevExt+0x88 == 2`) |
| Hardware presence | **Yes** | `AddDevice` creates the only device object; streams/pipes come from the USB configuration |

An administrator can satisfy every gate; an unprivileged user with the device can too, because the default DACL grants read and the codes need no write access. The real cost is obtaining/staging the USB device.

## 5. Memory-write trace

### 5.1 The defect: caller VA is locked with `KernelMode`

Three IOCTLs take a **raw pointer and length out of the METHOD_BUFFERED input buffer** and build an MDL without ever validating that the pointer is a user address:

| Build | IOCTL | Handler | `IoAllocateMdl` | `MmProbeAndLockPages` | `MmMapLockedPagesSpecifyCache` |
|---|---|---|---|---|---|
| x64 | `0x220014` | `FUN_0001A270` | `0x1A31C` (`rcx = [SystemBuffer+0x10]`, `edx = word [SystemBuffer+8]`) | `0x1A33C` - `edx = 0` (**KernelMode**), `r8d = 2` (`IoModifyAccess`) | `0x1A377` - `(mdl, KernelMode, MmCached, NULL, FALSE, 0x10)` |
| x64 | `0x220034` / `0x220038` | `FUN_0001AA30` | `0x1AB1C` (`rcx = [buf+8]`, `edx = word [buf]`) | `0x1AB3B` - `edx = 0` (**KernelMode**), `r8d = 2` | `0x1AB65` |
| x86 | `0x220014` | `FUN_00013DDE` | `0x13E24` (`push [buf+0xC]`, `push word [buf+8]`) | `0x13E39` - `push 2; push 0` (**KernelMode**) | `0x13E55` |
| x86 | `0x220034` / `0x220038` | `FUN_00014324` | `0x143B6` (`push [buf+4]`, `push word [buf]`) | `0x143C7` - `push 2; push 0` (**KernelMode**) | `0x143E3` |

`MmProbeAndLockPages(MDL, UserMode, ...)` is the API that rejects kernel addresses; passing `KernelMode` deliberately skips that check. There is no `ProbeForRead`/`ProbeForWrite`, no `MmIsAddressValid`, and no range/alignment test anywhere on these paths. Any **valid, lockable kernel VA** is accepted. (An invalid VA raises inside `MmProbeAndLockPages`, which is not wrapped in SEH here -> bugcheck; that is a DoS, not the write.)

The result of `MmMapLockedPagesSpecifyCache(..., KernelMode, MmCached, ...)` is a **new writable system VA** aliasing the caller's pages. The original PTE protection is not carried into the alias.

### 5.2 What the alias is used for

The mapped VA + caller length + direction are installed in the USB transfer request that the driver submits to the lower USB stack through `IOCTL_INTERNAL_USB_SUBMIT_URB` (`0x220003`) in `FUN_00011C30` (x64; `IoBuildDeviceIoControlRequest` at `0x11C8C`, URB pointer stored at `0x11CAB`). x86: `FUN_00010858`.

* **Bulk path (`0x220034`, deterministic IN).** `0x1AB7B`-`0x1ABB5`: direction flag `3` (`0x220034`, IN) or `2` (`0x220038`, OUT); caller length at `+0x24`; mapped VA at `+0x28`; pipe handle from the endpoint record at `+0x18`. The length is bounded by the pipe's maximum transfer size (`+0x10` of the pipe record) and by the 16-bit field. On an IN transfer the host controller writes the device's data into the alias -> **into the caller-chosen kernel pages**.
* **Control/vendor path (`0x220014`).** Input block (x64): `+0x00` type, `+0x02` request code, `+0x03` direction selector, `+0x04` `wValue`, `+0x06` `wIndex`, `+0x08` length, `+0x10` VA (x86: VA at `+0x0C`). The vendor/class form sets length at `0x1A455` (`[rbx+0x24] = word [rsi+8]`), the mapped VA at `0x1A468` (`[rbx+0x28]`), direction at `0x1A49B` (`[rbx+0x20] = (byte [rsi+3] == 0)`, 1 = IN, 0 = OUT), and the setup packet at `+0x80`. Other request forms set IN directly (e.g. the function-`0x28` form stores `1` at `0x1A74C`). For IN request types the device's answer is written to the caller VA.

Because the length and buffer fields are adjacent in every builder (x64 `+0x24`/`+0x28`; x86 `+0x18`/`+0x1C`), the pair is unambiguously the transfer descriptor used by the lower stack.

### 5.3 Control over target, value, size

| Axis | Control | Evidence |
|---|---|---|
| **Target** | **Arbitrary kernel VA** (no mask, range, alignment, or user/kernel check) | No probe; `KernelMode` lock; MDL alias |
| **Value** | **Device-supplied** - bytes the USB peer returns for the IN request | No driver copy from `SystemBuffer` into the alias; the alias is only installed in the request |
| **Size** | 16-bit (<= `0xFFFF`); bulk additionally <= pipe max transfer size | length loads at `0x1A455` (vendor/class), `0x1A773` (GET_DESCRIPTOR), `0x1ABA5` (bulk); bulk bound check at `0x1AACD` |
| **When** | Device started (`DevExt+0x88 == 2`) and, for bulk, a bulk pipe exists | `0x131E8` state check; `0x1AAC2` pipe-type check |

**Not present in either image:** `MmMapIoSpace`, caller physical address/offset, `\Device\PhysicalMemory`, `ZwMapViewOfSection`, `MmCopyMemory`, `KeStackAttachProcess`, or any fixed-value kernel store at a caller-influenced address. The only fixed stores are to the driver's own device extension and stream contexts, addressed by `ExAllocatePoolWithTag` results, plus the WMI data-block global at `0x17120` (`FUN_000136E8` / `FUN_0001374C`, 4 bytes after an exact-size check). None of them is target-controllable, so none is a memory-write primitive.

### 5.4 The UserMode MDL paths are *not* kernel writes

`0x220010` / `0x220020` build MDLs from user pointers with `MmProbeAndLockPages(..., UserMode, IoModifyAccess)` (x64 handlers `FUN_00014250` / `FUN_00013D3C`; x86 handlers `FUN_00012CA2` / `FUN_000129DE`), then run isochronous threads that fill them. `UserMode` makes the probe reject kernel addresses, so those paths write only to user pages. They are the legitimate streaming path and are not part of the primitive.

## 6. Most dangerous exposed capability

**An unprivileged local user who can open the device interface and who has the matching USB device can make the driver lock an arbitrary kernel VA and hand it to the USB stack as an IN transfer buffer; up to 64 KB of device-returned data is then written through a writable MDL alias into that kernel address.** The same two bulk codes also give the reverse direction (OUT): arbitrary kernel memory is read and sent to the device, which is a kernel-address disclosure only if the device peer is attacker-controlled.

* Target: arbitrary kernel VA, any offset within a page (MDL `ByteOffset` is preserved).
* Value: USB device data. If the peer is an attacker-programmed FPGA/gadget (the driver is literally `audiotestdriver`/`FPGA` test code), this becomes **arbitrary kernel read + write**, i.e. static **MW2** (R3 + W1).
* Without a controlled peer the value is device-defined -> **W2 -> MW3**.
* Crash reliability: an invalid/unlockable VA bugchecks before any write; a valid VA is stable.

## 7. Loadability under default DSE (why BLOCKED)

| Build | PE | Signature | Default x64 DSE | Result |
|---|---|---|---|---|
| x64 | PE32+, machine `0x8664`, subsystem Native, OS 6.1 | No `IMAGE_DIRECTORY_ENTRY_SECURITY` (RVA 0, size 0); `Get-AuthenticodeSignature` = `NotSigned`; no catalog in corpus | Windows x64 requires a Microsoft-issued kernel signature (KMCS); unsigned -> `STATUS_INVALID_IMAGE_HASH` (0xC0000428). HVCI/Memory Integrity blocks unsigned images outright. | **Cannot load** without test-signing/DSE-off and, even then, the real device. |
| x86 | PE32, machine `0x14C`, subsystem Native, OS 6.1 | Unsigned as above | 32-bit Windows does not enforce KMCS, so the image would load on a 32-bit installation. It **cannot** load into an x64 kernel (no 32-bit kernel/WOW64 driver path). | **Cannot load on this host**; only relevant on 32-bit Windows + device. |

Additionally, `DriverEntry` creates **no device**; the FDO is created only by `AddDevice` for a matching PnP USB device. Even with signing bypassed, there is no attack surface without the hardware (or a devnode whose lower stack completes start - a forged root devnode fails the start/select-configuration path and never reaches state 2).

**BLOCKED/static split:** status **BLOCKED** for both builds; the static primitive remains **MW3** and is recorded for reference, consistent with the project's BLOCKED convention.

## 8. x64 vs x86 - material differences

Only mechanically different; the primitive is identical.

| Aspect | x64 `97A95152` | x86 `DFC3F0A7` |
|---|---|---|
| Device extension | `0x168` | `0xF0` |
| Input block `0x220014` | >=0x18 used (VA qword at `+0x10`, length word `+0x08`); no length check | >=0x10 used (VA dword at `+0x0C`, length word `+0x08`); no length check |
| Bulk input block | length word `+0x00`, VA qword `+0x08` | length word `+0x00`, VA dword `+0x04` |
| Stream IOCTL length check | `0x40` native, `0x30` WOW64 (`IoIs32bitProcess` thunk) | `0x28` |
| WOW64 handling | `IoIs32bitProcess` import and thunk in `0x220014` | n/a |
| Kernel MDL defect | Present (`0x1A33C`, `0x1AB3B`) | Present (`0x13E39`, `0x143C7`) |
| Device/interface GUID | `{db5f3539-...}` | `{db5f3539-...}` (same) |
| Loadability | unsigned -> DSE-blocked | 32-bit -> not loadable on x64; loads on 32-bit Windows |
| Static severity | MW3 | MW3 |

No x64-only or x86-only memory-write path; no additional IOCTL in either build.

## 9. Verdict

**BLOCKED (static MW3).** Both builds expose the same caller-addressed MDL kernel-write primitive:

`MW3 - reach=R3 setup=hardware write=W2 load=unsigned/blocked` (x64); `MW3 - reach=R3 setup=hardware write=W2 load=unsigned/blocked-on-x64` (x86).

The primitive is real and the target is fully caller-controlled, but (a) the value is supplied by the USB peer, not the IOCTL caller, and (b) the matching device is required. That places it at **W2 + R3/hardware = MW3**, not MW1/MW2. It is **not MW4**: the target is an arbitrary kernel VA with arbitrary length, not a fixed/narrow write.

Conditional escalation: with an attacker-controlled USB peer (programmable FPGA/gadget), the IN bulk/control paths give arbitrary kernel write and the OUT paths give arbitrary kernel read -> **static MW2** (`R3 + W1`); this is a hardware threat-model change, not a different code path.

## 10. Secondary findings (not the primary write)

1. **Missing `InputBufferLength` checks** on `0x220014`, `0x220034`, `0x220038` (x64 `0x1A270`/`0x1AA30`; x86 `0x13DDE`/`0x14324`). With `METHOD_BUFFERED`, `SystemBuffer` is `max(InputBufferLength, OutputBufferLength)` bytes; the handlers read up to `+0x18` (x64 control) or `+0x10` (x64 bulk) regardless. A short input causes a **pool out-of-bounds read**, and the resulting garbage is used as the MDL VA -> bugcheck or an unintended lock. Not a caller-value write.
2. **Invalid kernel VA -> bugcheck.** `MmProbeAndLockPages(KernelMode)` raises on an invalid address and the calls are not in a `try/except`; `MmMapLockedPagesSpecifyCache` may also return NULL on failure and the NULL is installed as a transfer buffer with a non-zero length.
3. **Cross-handle stream teardown.** `0x22000C` / `0x220024` look up a stream by a caller byte in the device-wide list and free it without checking the calling file object; `0x220018` / `0x22002C` take a pointer out of `FileObject->FsContext` and free it. Concurrent or cross-handle calls can produce UAF/double-free of a pool object. The freed object's address is never caller-chosen, so this is a lifetime bug, not an address-controlled write.
4. **Zero-length MDL.** `0x220010` / `0x220020` do not reject `length == 0`; `IoAllocateMdl(va, 0)` followed by `MmProbeAndLockPages` is a potential bugcheck.

## 11. Limitations

* **REA not used.** Four REA audits were active; this audit is Ghidra 12.1.4 headless + `llvm-objdump`/`dumpbin` only. No REA evidence IDs exist. All addresses are VAs with image base `0x10000`.
* **No dynamic confirmation.** The device was not present and neither driver was loaded; the DACL is the documented OS default (no SD in the image), not a live `!devobj` dump. The claim that the default DACL grants `Everyone` read and that a read-only handle suffices for `FILE_ANY_ACCESS` codes follows the project's existing convention (cf. `b06bdrv`, `CorsairVBusDriver64`), but was not verified against a live object.
* **Transfer-request layout is inferred.** The driver hand-builds USB request blocks that are 8 bytes larger at the header than the public `usb.h` `_URB_HEADER` on both architectures (a pipe-handle field is present and the setup packet sits at `+0x48` x86 / `+0x80` x64). The buffer/length/direction triple is unambiguous, but the exact field names are inferred from USBD conventions and the observed `0x220003` submission; the host-controller write itself was not observed.
* **No INF/catalog in the corpus**, so package-level security overrides and catalog signing could not be checked; only the `.sys` bytes were audited.
* **Hardware not staged**, so pipe availability, maximum transfer size, and the device's willingness to answer IN requests are unverified.
* Scope was limited to the two named files and the memory-write question; no attempt was made to find a signing bypass or to build a PoC.

