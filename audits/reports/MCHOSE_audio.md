# Audit: MCHOSE / BLK2025GHS / OUYU002X1WGHS USB audio family (16 builds)

| Field | Value |
|---|---|
| File(s) | 16 `.sys` files; per-file table in section 2 |
| SHA-256(s) | Full hashes in section 2; all 16 re-computed from the files in `drivers/` |
| Analysis date | 2026-10-25 |
| Method | Static-only: local Ghidra 12.1.4 headless (auto-analysis + targeted decompilation), `llvm-objdump` and direct PE parsing. No load, execution, install, service creation, or registry access. **REA was not used** because four REA audits were already active; no REA evidence IDs. |
| Reach tier | **R3** (hardware + PortCls devnode). The private interface is intended for the vendor's user-mode ASIO component, so **R1 is likely once the headset is attached**; R2 administrator is guaranteed if the inherited DACL is tighter. |
| Setup required | **hardware** (USB headset; the PortCls adapter is created by PnP) |
| Write quality | **W2** (constrained kernel pool OOB write: adjacent-pool target, fixed 32-byte value, caller-controlled trigger/size) |
| Verdict | **MW3** for the 14 x64 builds; **BLOCKED (i386)** for the 2 x86 builds |
| HW-only | no |
| Loadability | Signed, WHCP-valid (`Microsoft Windows Hardware Compatibility Publisher`); x64 builds loadable; x86 builds not loadable on x64 |

## 1. Verdict

**MW3 - reach=R3 setup=hardware write=W2 load=signed.**

The family is not a pure PortCls adapter with no user surface. `DriverEntry` overrides four major functions after `PcInitializeAdapterDriver`, including **`IRP_MJ_DEVICE_CONTROL`**, and `AddDevice` registers two private device interfaces (`CMASIOPrivateInterface`, `CMEnumPrivateInterface`). The device-control handler implements a 23-code private IOCTL protocol.

The material finding is **IOCTL `0x1de038`**: on the 64-bit path it passes the buffered-I/O `SystemBuffer` to a HAL method that unconditionally writes **32 bytes** to it; on the WOW64 path it allocates `OutputBufferLength * 2` bytes and the same method writes 32 bytes. The handler checks only that `InputBufferLength != 0` and `SystemBuffer != NULL`; it never requires the buffer to be 32 bytes. A short buffered IOCTL therefore produces a **kernel pool out-of-bounds write** of 32 bytes of driver list/state data (which contains kernel pointers). When `OutputBufferLength >= 32` the same 32 bytes are returned to the caller, giving a KASLR-relevant pointer leak; a larger output length also returns uninitialized pool tail bytes.

The write is not arbitrary: the destination is the buffered-I/O allocation or the WOW64 conversion pool block, and the value is fixed driver state. It is therefore **W2**, and the hardware/devnode requirement puts it at **MW3** (the same class as the hardware-gated Corsair audio pool overflow). If the deployed INF grants the private interface to the interactive user and the headset is present, the primitive is R1-reachable; the family verdict is still MW3 because the exact USB device must be present.

The two x86 images (`BLK2025GHS_E328A8AA`, `OUYU002X1WGHS_A7108D76`) contain the same IOCTL dispatch constants but are not loadable on x64; they are **BLOCKED (i386)**.

## 2. Files, SHA-256, build identity, per-file result

All signatures are valid; all are WHCP-signed. `Helper` is the VA (image base `0x140000000` for x64) of the 32-byte copy routine reached at vtable slot `+0xa8` by IOCTL `0x1de038` (V9 example: `FUN_1402eec60`). Addresses are for the individual build.

| File | SHA-256 | Arch | Build (UTC) | Version | Helper / dispatch | Verdict |
|---|---|---|---|---|---|---|
| `BLK2025GHS_E328A8AA.sys` | `e328a8aa35d584b8aa5e3cbd8a1a30e13854bf352be143c59c4576f80348888a` | x86 | 2024-10-23 | 10.0.2410.2300 | dispatch constants present; x64 helper pattern absent | **BLOCKED (i386)** |
| `BLK2025GHS_F5CF8A1E.sys` | `f5cf8a1e62594f2f3061dd4e0ce888d3dffab91d65001b4a7a583ffc59aafe89` | x64 | 2024-10-23 | 10.0.2410.2300 | `0x1402ed6c0`; handler `0x1402e57e0` | **MW3 (W2)** |
| `MCHOSE_F9_86F422DE.sys` | `86f422de468ff9f6d0b20494b03474cd87bcf5f7589ce39b376076155dbe26f2` | x64 | 2025-03-20 | 10.0.2021.0831 | `0x1402eecc0`; handler `0x1402e6850` | **MW3 (W2)** |
| `MCHOSE_G9_E066BCBD.sys` | `e066bcbd27fd0656a84a76c36d82b147432cdcaf6fd2f275d335234da8e9b388` | x64 | 2025-03-03 | 10.0.2411.1300 | `0x1402eec60` | **MW3 (W2)** |
| `MCHOSE_G9_II_125CBC32.sys` | `125cbc32f39628c12938f5f8ce25b8a4e288429d1a87b5fbdae522377a35b932` | x64 | 2025-03-04 | 10.0.2502.2700 | `0x1402eecc0` | **MW3 (W2)** |
| `MCHOSE_G9_PRO_25A02326.sys` | `25a02326f91c1d92aab1c575dd2ecb6cb00b5508f8a18909d7f7c216331776fd` | x64 | 2024-11-12 | 10.0.2411.1300 | `0x1402eec60` | **MW3 (W2)** |
| `MCHOSE_K20_C31ADA13.sys` | `c31ada13d8828c6f4d5d231f93bc90070f18491d5fcc1d7d603a9b72eb4d36d5` | x64 | 2025-03-14 | 10.0.2021.0831 | `0x1402eecc0` | **MW3 (W2)** |
| `MCHOSE_K20_PRO_0A34F98C.sys` | `0a34f98c34b482c9b452526c7e37836eedbf14fa856611dd4fb6491c06c5bcf8` | x64 | 2025-10-15 | 10.0.2510.1500 | `0x1402e0b30` | **MW3 (W2)** |
| `MCHOSE_K20_TURBO_BEC117EA.sys` | `bec117eafdfacc5f63672ed51a595e1150bdbc40cd34b669535c4e93f7c46ea5` | x64 | 2026-04-13 | 10.0.2604.1301 | `0x1402e4b10`; handler `0x1402db890` | **MW3 (W2)** |
| `MCHOSE_S9_PRO_A4F4639E.sys` | `a4f4639e5505e24187c314b821904fcea5974fa46ab3b0f42794b1d94cd5f0ec` | x64 | 2024-11-12 | 10.0.2411.1300 | `0x1402eec60` | **MW3 (W2)** |
| `MCHOSE_V9_DD75AEB4.sys` | `dd75aeb4c03db5f4e12b4225af66f2aeee8059aecb511c8f96fde8e602c02783` | x64 | 2024-12-11 | 10.0.2412.1200 | `0x1402eec60`; handler `0x1402e6850` | **MW3 (W2)** |
| `MCHOSE_V9_PRO_7B451A5E.sys` | `7b451a5ec79d7ddd02083af153d77d5f46536f161f3db80341bc90052f0733ea` | x64 | 2024-12-11 | 10.0.2412.1200 | `0x1402eec60` | **MW3 (W2)** |
| `MCHOSE_V9_TURBO_600D_EF5F2159.sys` | `ef5f21599de548f67a29ba61d2c1aa92a7132df78d1b41929a3851025ce77214` | x64 | 2025-12-28 | 10.0.2503.2003 | `0x1402eecc0` | **MW3 (W2)** |
| `MCHOSE_V9_TURBO_6D340ECD.sys` | `6d340ecde8a6c0e61ea371c6aba5b284da7f421057c9e785793745d4d619a472` | x64 | 2025-12-16 | 10.0.2503.2001 | `0x1402eecc0` | **MW3 (W2)** |
| `OUYU002X1WGHS_56F0EDDB.sys` | `56f0eddb54acb003fd5fbedc9b6954675f6485c4ab0ea03f1219a9db54a154f0` | x64 | 2024-09-20 | 10.0.2409.2000 | `0x1402e5e10`; handler `0x1402de7e0` | **MW3 (W2)** |
| `OUYU002X1WGHS_A7108D76.sys` | `a7108d7675e0e90d0aa5a0ed2789f2b206aceeeaff2a4b5a320278b7eade96fe` | x86 | 2024-09-20 | 10.0.2409.2000 | dispatch constants present; x64 helper pattern absent | **BLOCKED (i386)** |

None of the 16 hashes is in `indexes/dedupe/known_bad_hashes.txt`.

## 3. Entry, devices, interfaces, effective DACL

### 3.1 DriverEntry

`entry` at `0x140351200` calls `FUN_140351000`, which calls `PcInitializeAdapterDriver` and then overrides four major functions (`MCHOSE_V9_DD75AEB4`, image base `0x140000000`):

| Offset in `DRIVER_OBJECT` | Major function | Handler |
|---|---|---|
| `0x70` | `IRP_MJ_CREATE` | `FUN_1402e6550` |
| `0x80` | `IRP_MJ_CLOSE` | `FUN_1402e6450` |
| `0xe0` | `IRP_MJ_DEVICE_CONTROL` | `FUN_1402e6850` |
| `0x148` | `IRP_MJ_PNP` | `FUN_1402e6000` |

The remaining major functions stay with PortCls (`PcDispatchIrp`). The `IRP_MJ_CREATE`/`IRP_MJ_CLOSE` handlers compare the file name to `\CMASIOPrivateInterface` and otherwise forward to PortCls. The device-control handler is where the custom IOCTL protocol lives.

### 3.2 AddDevice and interfaces

`FUN_1402e6350` (the AddDevice routine passed to `PcInitializeAdapterDriver`) calls `PcAddAdapterDevice` at `0x1402e6391`, then:

- `0x1402e63ff`: `IoRegisterDeviceInterface(Pdo, &GUID_B8B7AFC6_7A58_4C60_9ED0_A356875F39AD, &Ref_CMEnumPrivateInterface, &devExt+0x270)`
- `0x1402e6422`: `IoRegisterDeviceInterface(Pdo, &GUID_2B487DB7_8EF0_4BF0_9114_75C0F18C416D, &Ref_CMASIOPrivateInterface, &devExt+0x258)`

The reference strings are initialized from wide-string constants at `0x1401580d8` (`CMEnumPrivateInterface`) and `0x140158078` (`CMASIOPrivateInterface`). `FUN_1402e6f80` enables the CMASIO interface only when its subdevice scan sets `bVar2` (`IoSetDeviceInterfaceState(devExt+0x258, 1)`), while the CMEnum interface is enabled unconditionally (`devExt+0x270`).

**There is no `IoCreateDevice`, no `IoCreateDeviceSecure`, no `IoCreateSymbolicLink`, and no SDDL or security-descriptor string in any of the 16 images.** The interfaces are registered on the PortCls FDO/PDO; their DACL is inherited from that PnP device object and is not defined by this driver. The corpus contains no INF, so the deployed DACL cannot be resolved statically from these files.

### 3.3 Open gate and effective access

The only gate in the driver is a **file-name comparison**, not an authorization check:

- `0x1402e6901`: `lea rcx, unicode(\CMASIOPrivateInterface)`
- `0x1402e6908`: `add rdx, 0x58` (`FileObject->FileName`)
- `0x1402e690f`: `RtlCompareUnicodeString(..., CaseInsensitive=1)`
- `0x1402e6917`: mismatch -> `PcDispatchIrp`; match -> custom IOCTL switch

There is no `SeAccessCheck`, no `SeSinglePrivilegeCheck`, no `ProbeForWrite`, and no caller-identity test. Any principal that can open the CMASIO device interface and set that file name reaches the IOCTL surface. The vendor's ASIO component is a user-mode consumer of the same interface, so a functional install must permit the interactive user; the exact DACL still depends on the INF/PortCls version. **R1 is likely with the headset attached; R2 administrator is guaranteed and in scope.**

## 4. Dispatch and IOCTL table

`FUN_1402e6850` reads:

- `IoControlCode` = `[CurrentStackLocation+0x18]`
- `InputBufferLength` = `[CurrentStackLocation+0x10]` (`uVar4`)
- `OutputBufferLength` = `[CurrentStackLocation+0x8]` (`local_res8[0]`)
- `SystemBuffer` = `IRP->AssociatedIrp.SystemBuffer` (`param_2[3]`)
- `FileObject` = `[CurrentStackLocation+0x30]`

All codes are **METHOD_BUFFERED** (low two bits 0); none is METHOD_NEITHER. All use `SystemBuffer`/`FileObject`/scalars; no user pointer is dereferenced directly.

Device type `0x1d` is `FILE_DEVICE_SOUND`; `0x22` is `FILE_DEVICE_UNKNOWN`. Access: 0 = any, 1 = read, 2 = write, 3 = read/write.

| IOCTL | Type/func/access/method | Length checks in handler | Kernel action |
|---|---|---|---|
| `0x223c04` | 0x22 / 0xF01 / 0 / 0 | **none**; reads `*(int*)SystemBuffer` without checking `InputBufferLength` or NULL | Calls the HAL active-set method with a `bool`, then releases; accepted **without** the CMASIO file-name gate. Null-deref DoS if no buffer. |
| `0x1da020` | 0x1d / 0x808 / 2 / 0 | input >= 4; output >= 8 for second call | vtable `+0x78` with the input dword; then vtable `+0x80` with `SystemBuffer` (8-byte getter) |
| `0x1da01c` | 0x1d / 0x807 / 2 / 0 | input >= 4 | vtable `+0x70` with the input dword |
| `0x1da014` | 0x1d / 0x805 / 2 / 0 | input == 8 (x64) or == 4 (WOW64) | vtable `+0x48` with 8-byte buffer / local 4-byte value |
| `0x1da040` | 0x1d / 0x810 / 2 / 0 | input == 8 (x64) or == 4 (WOW64) | vtable `+0xb8` with 8-byte buffer / local 4-byte value |
| `0x1da02c` | 0x1d / 0x80b / 2 / 0 | input >= 4 | vtable `+0x90` with `SystemBuffer` |
| `0x1da030` | 0x1d / 0x80c / 2 / 0 | input >= 4 | vtable `+0x98` with `SystemBuffer` |
| `0x1da03c` | 0x1d / 0x80f / 2 / 0 | none; requires input == 0 or buffer == NULL | vtable `+0xb0` with `FileObject` |
| `0x1da044` | 0x1d / 0x811 / 2 / 0 | requires input == 0 or buffer == NULL | vtable `+0xc0` with the IRP |
| `0x1da04c` | 0x1d / 0x813 / 2 / 0 | requires input == 0 or buffer == NULL | vtable `+0x50` with `FileObject` |
| `0x1da050` | 0x1d / 0x814 / 2 / 0 | input >= 4 | vtable `+0xc8`, then `+0xd0` with `SystemBuffer` |
| `0x1da054` | 0x1d / 0x815 / 2 / 0 | input >= 4 | vtable `+0xd0` with `SystemBuffer` |
| `0x1d6000` | 0x1d / 0x1800 / 1 / 0 | none | vtable `+0x30` with `SystemBuffer`, `&OutputBufferLength` |
| `0x1d6004` | 0x1d / 0x1801 / 1 / 0 | none | vtable `+0x38` with `SystemBuffer`, output length |
| `0x1d600c` | 0x1d / 0x1803 / 1 / 0 | none | vtable `+0x60` with `SystemBuffer`, `&OutputBufferLength` |
| `0x1d6010` | 0x1d / 0x1804 / 1 / 0 | none | vtable `+0x68` with `SystemBuffer`, `&OutputBufferLength` |
| `0x1d6018` | 0x1d / 0x1806 / 1 / 0 | output == 0 -> `0x80000005`, Information=4; output < 4 -> `0xC0000023`; else | vtable `+0x58` with `SystemBuffer`; Information=4 |
| `0x1d6024` | 0x1d / 0x1809 / 1 / 0 | output >= 8 | vtable `+0x80` with `SystemBuffer` |
| `0x1d6028` | 0x1d / 0x180a / 1 / 0 | output >= 4 | vtable `+0x88` with `SystemBuffer`; Information=output length |
| `0x1d6034` | 0x1d / 0x180d / 1 / 0 | output >= 0x10 | vtable `+0xa0` (currently a stub returning 0); Information=output length |
| `0x1d6058` | 0x1d / 0x1816 / 1 / 0 | output >= 4 | vtable `+0xd8` (sets flag bit `0x200` in a state structure); Information=4 |
| `0x1de008` | 0x1d / 0x802 / 3 / 0 | none | vtable `+0x40` with `SystemBuffer`, `OutputBufferLength` |
| **`0x1de038`** | **0x1d / 0x80e / 3 / 0** | **input != 0 and SystemBuffer != NULL only**; no 32-byte requirement | **vtable `+0xa8` writes 32 bytes to `SystemBuffer` (x64) or to a `OutputBufferLength*2` pool block (WOW64)** |

The HAL interface vtable used by `FUN_1402e6850` is based at `0x140145898` in V9; slot `+0xa8` is stored at `0x140145940` and contains `0x1402eec60`. The same slot/helper relationship is present in all 14 x64 builds (section 2 addresses); the slot's base qword in each build is the QueryInterface thunk (`0x140124bd0` in V9).

## 5. Access-control audit

| Check | Result |
|---|---|
| `IoCreateDeviceSecure` / explicit SDDL | absent |
| `SeAccessCheck` / `SeSinglePrivilegeCheck` | absent |
| `ProbeForRead` / `ProbeForWrite` | absent |
| `IoGetCurrentIrpStackLocation` | absent; direct IRP offsets used |
| File-name gate | `FileObject->FileName == \CMASIOPrivateInterface`, case-insensitive; not an authorization check |
| Interface DACL | inherited from the PortCls FDO/PDO; not visible in the `.sys`; no INF in corpus |
| Caller identity | not checked |
| IOCTL access bits | read/write per code; no driver-side check beyond the file name |

The two interfaces are registered on the same FDO that the vendor's user-mode ASIO component opens. This is strong evidence that the deployed DACL permits the interactive user; the driver itself adds no second gate. An administrator can always open the interface (R2), and R1 is likely with the headset present.

## 6. Memory-write trace

### 6.1 Exact path

1. Caller opens the CMASIO device interface and sends `DeviceIoControl(0x1de038, inLen=L_in, outLen=L_out)`. The handler's file-name gate at `0x1402e6901` must match `\CMASIOPrivateInterface`.
2. `FUN_1402e6850` at `0x1402e6d9c` checks only `L_in != 0` and `SystemBuffer != NULL`.
3. `IoIs32bitProcess` at `0x1402e6db0` selects the path.
4. **x64 path** (`0x1402e6e7f`-`0x1402e6ea1`): calls vtable `+0xa8` with `(this, FileObject, SystemBuffer, SystemBuffer, &L_out)`. `SystemBuffer` is the METHOD_BUFFERED allocation of size `max(L_in, L_out)`.
5. **WOW64 path** (`0x1402e6dc1`-`0x1402e6e33`): `ExAllocatePoolWithTag(NonPagedPool, L_out*2, 'adap')`, sets `L_out *= 2`, calls vtable `+0xa8` with the pool block, then copies `L_out>>3` dwords from the pool block to `SystemBuffer`.
6. Vtable slot `+0xa8` is `0x1402eec60` (V9; per-build addresses in section 2). At `0x1402eec6b`-`0x1402eec7f` it executes:
   - `movups 0x98(%rcx), %xmm0; movups %xmm0, (%r9)`
   - `movups 0xa8(%rcx), %xmm1; movups %xmm1, 0x10(%r9)`
   - i.e. a **32-byte unconditional write** to the fourth argument (`r9`), with no length argument and no check.
7. On x64, `r9 = SystemBuffer`; on WOW64, `r9 = pool block`. There is no intermediate 32-byte stack buffer.

### 6.2 Why it is out of bounds

- **x64:** `SystemBuffer` is allocated as `max(L_in, L_out)`. With `L_in = 1..16` and `L_out = 0`, the allocation is 1..16 bytes; the helper writes 32 bytes. The overflow is 16..31 bytes into adjacent pool (subject to allocator rounding), including two kernel list pointers.
- **WOW64:** the pool block is `L_out*2`. With `L_out = 1..8`, the block is 2..16 bytes; the helper writes 32 bytes, an overflow of 16..30 bytes (larger `L_out` up to 15 requests 18..30 bytes, which allocator rounding may partly absorb). The subsequent copy loop stays within `SystemBuffer`, so the overflow is the helper's 32-byte store.
- The helper does not inspect `param_5` (the output-length pointer). The handler does not inspect `L_out` before the call. There is no `ProbeForWrite`, no `RtlCopyMemory` bounds check, and no output-length validation.

### 6.3 Value and target control

- **Destination:** adjacent nonpaged pool / the buffered-I/O SystemBuffer allocation; not an arbitrary kernel address. The caller can choose the small allocation size (1..16 on x64; 2..30 on WOW64) and can groom pool adjacency, but cannot supply a destination pointer.
- **Value:** 32 bytes read from `this+0x98`. `FUN_1402e8050` at `0x1402e8050` walks `param_1+0x98` as a `LIST_ENTRY` (`plVar1 = param_1+0x98; plVar5 = *plVar1; ...`), so the copied block begins with two kernel list pointers plus two further state qwords. The value is fixed driver state, not caller data.
- **Size:** fixed 32 bytes; the overflow length is set by the small allocation, not by a separate length field.

### 6.4 Leak side effect

For the x64 path, after the helper returns, `FUN_1402e6850` sets `IRP->IoStatus.Information = L_out` (`0x1402e6eb6`). If `L_out >= 32`, the I/O manager copies the 32 bytes of list/state data (kernel pointers) back to the caller; if `L_out > 32`, the remaining bytes are uninitialized `SystemBuffer` pool tail. This is a KASLR-relevant information leak attached to the same IOCTL. It is not counted as a separate memory write but raises the practical value of the primitive.

### 6.5 Rating

- **W2:** real kernel pool OOB write, but constrained target (adjacent pool) and fixed value (driver list/state); no write-what-where and no caller-chosen destination.
- **MW3:** the write requires the specific USB headset and the PortCls devnode; per `SEVERITY.md`, `R3` + `W2` (hardware-gated constrained write) is MW3. If the deployed INF grants the private interface to the interactive user, the same primitive is R1-reachable once the device is attached; the family still requires the hardware. A reviewer who scores reach independently of the hardware gate could call it an MW2 candidate, but the hardware-specific device makes MW3 the defensible family verdict.

## 7. Other paths checked (negative results)

| Path | Result |
|---|---|
| `MmMapIoSpace`, `MmGetPhysicalAddress`, `MmCopyMemory`, `ZwMapViewOfSection`, `ZwOpenSection`, `MmProbeAndLockPages` | **Not imported / not present** in any of the 16 images. No physical-memory or user-MDL path. |
| `MmMapLockedPagesSpecifyCache` | Only in `FUN_1402f94f0` (V9): `ExAllocatePoolWithTag(0x200, size+0x28, 'USbd')` -> `IoAllocateMdl(buffer, size+0x28, 0, 1)` -> `MmBuildMdlForNonPagedPool` -> `MmMapLockedPagesSpecifyCache(mdl, 1 /*KernelMode*/, 1 /*MmCached*/, ...)`. The MDL describes driver-owned nonpaged pool, the allocation and MDL lengths are the same computed value, and no user pointer is passed to `MmProbeAndLockPages`. The old report's conclusion on this path is retained. |
| Audio stream size arithmetic | `FUN_1402f94f0` computes `local_d4` from `local_d8 * rate * 0x28 / 1000`; allocation, MDL, and mapped length all use `local_d4+0x28`. A zero bit depth can make `local_d8 == 0` and divide by zero (DoS), but it does not create a caller-chosen destination write. |
| `IRP_MJ_DEVICE_CONTROL` METHOD_NEITHER | None. All 23 codes are METHOD_BUFFERED; no `IoGetCurrentIrpStackLocation`; no direct user-pointer dereference. |
| USB internal requests (`IoBuildDeviceIoControlRequest` at `FUN_1402f59f0`, `FUN_1402f6000`) | Buffers come from driver state / the buffered SystemBuffer; no user pointer or caller-chosen kernel address. |
| Config file (`ZwCreateFile` `FUN_14034cef4`, `ZwReadFile` `FUN_14034d3c4`) | Opens/reads the driver's `MCHOSE_*.INI` (`MCHOSE_V9.INI`, `%s\ASIO`); file/config path only. |
| Registry (`ZwCreateKey`/`ZwSetValueKey` at `FUN_1402f1d38`) | Device settings; no kernel memory write. |
| WMI (`IoWMIRegistrationControl`; callback `FUN_1402e7670`) | WMI data copies are bounded by the supplied size (`param_3`), with `0xC000000D` on too-small buffers; no unbounded write found. |
| `0x223c04` | No filename gate and no input-length check; reads `SystemBuffer` as a dword. With zero-length buffers this is a NULL-deref bugcheck (DoS), not a memory write. |
| Other custom IOCTLs | Several pass `SystemBuffer`/`OutputBufferLength` to vendor HAL methods with incomplete output-length checks (`0x1d6000`, `0x1d6004`, `0x1d600c`, `0x1d6010`, `0x1de008`); only `0x1de038` has an established 32-byte unbounded write. These remain residual review items, not separate MW findings. |

## 8. Most dangerous exposed capability

The CMASIO private IOCTL `0x1de038` gives a **kernel pool OOB write of 32 bytes of kernel list/state data** with a caller-controlled small allocation, plus a KASLR-relevant 32-byte pointer leak when the output length is at least 32. It is gated by the CMASIO file name and the USB headset/PortCls devnode, not by an access check. This is a constrained but real kernel memory write (W2), rated **MW3** for the hardware-gated family.

## 9. Build/family differences

- **14 x64 builds:** identical primitive. The handler constant sequence (`0x1da020`, `0x1da050`, `0x1de008` -> `0x1de038`) and the exact 32-byte helper (`0F 10 81 98 00 00 00 33 C0 41 0F 11 01 0F 10 89 A8 00 00 00 41 0F 11 49 10 C3`) are present in all of them. The helper address varies (`0x1402eec60`, `0x1402eecc0`, `0x1402e0b30`, `0x1402e4b10`, `0x1402ed6c0`, `0x1402e5e10`); the slot is `+0xa8` in each vtable.
- **BLK2025GHS:** older 2024 build; the x64 `F5CF8A1E` has the primitive but lacks the `0x223c04` code. The x86 `E328A8AA` is not loadable on x64.
- **K20_PRO / K20_TURBO:** newer 2025/2026 builds with extra CUSB channel-conversion/topology units; the `0x1de038` primitive and helper are unchanged.
- **OUYU002X1WGHS:** separate product name/PDB path (`CM002X1_OUYU_OY_Wireless_Gaming_Device`); same primitive in the x64 `56F0EDDB`; the x86 `A7108D76` is BLOCKED.
- **No material difference** in the dispatch, file-name gate, or the 32-byte write across the x64 family.

## 10. Limitations and unresolved paths

- **Effective DACL is not resolved.** The driver sets no SDDL and creates no device object; the interface DACL comes from the PortCls FDO/PDO, and no INF is in the corpus. The R1/R2 distinction therefore rests on the deployed INF and the fact that the vendor's ASIO component is user-mode. R2 is guaranteed and in scope either way.
- **No dynamic confirmation.** No headset was attached, no driver was loaded, and no IOCTL was sent. The overflow is established statically from the length contract and the unconditional 32-byte store.
- **Vtable identity** is resolved from the object layout, the vtable base `0x140145898`, slot `+0xa8` at `0x140145940`, and the decompiled handler call. Some neighboring wrapper methods are thunks; their exact semantics are not all resolved.
- **The `this+0x98` block** is shown to be a `LIST_ENTRY` by `FUN_1402e8050`; the exact meaning of the two non-list qwords is not resolved. The block is fixed driver state, not caller data.
- **x86 builds** were not fully decompiled because they are not loadable on x64; the dispatch constants are present but the 32-bit helper did not match the x64 signature. They are BLOCKED, not rated.
- **REA cross-check was not used** because four REA audits were active; all results are from local Ghidra/objdump/PE parsing. No web, no external lookups, no load/execute/install/service/registry.
- Addresses in the text are for `MCHOSE_V9_DD75AEB4` unless another build is named; image base `0x140000000` for x64.

## 11. Historical baseline correction

The prior report `audits/reports/mchose_audio.static.md` concluded **NO-WRITE** for all 14 families. Its "no control device" observation is technically true - the driver never calls `IoCreateDevice` or `IoCreateSymbolicLink` - but it **missed the two `IoRegisterDeviceInterface` interfaces and the custom `IRP_MJ_DEVICE_CONTROL` override**. The prior report also stopped at the MDL path and did not enumerate the private IOCTL protocol. The MDL conclusion (driver-owned pool, KernelMode mapping, no user pointer) is retained. Under the current R2-inclusive, hardware-inclusive scope, the family is **MW3**, not NO-WRITE.
