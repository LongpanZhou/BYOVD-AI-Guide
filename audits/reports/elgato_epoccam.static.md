# Audit: Elgato / Kinoni EpocCam virtual camera (`kinonivd`, `kinonivad`)

| Field | Value |
|---|---|
| Files | `drivers\Elgato\kinonivd_844635B5.Sys` (camera minidriver)<br>`drivers\Elgato\kinonivad_AECF289A.sys` (virtual audio miniport) |
| SHA-256 | `844635b5562cb2010285125fb216504ae1e2f03ce1874220af0d0a4630b2c291`<br>`aecf289a83f1acb87d13831ab519b31a5317d012661524bd755d682c4f66b03c` |
| Architecture | **x86 (PE32 / coff-i386)** for both. Device IDs in the INFs are `NTx86`. |
| Method | Static-only (REA / Ghidra 12.1.4). No driver loaded, no device opened, no IOCTL issued. |
| Verdict | **NO-WRITE** (no kernel memory-write primitive found) |
| Setup required | **devnode** - and additionally a **32-bit** Windows host |

> Addresses for `kinonivd` are linked VAs at image base `0x400000`; for `kinonivad` at image base `0x400000`. Both binaries are 32-bit kernel images and therefore **cannot be loaded by an x64 Windows kernel**, irrespective of the DACL. This alone removes them from the "no-setup" candidate set on any x64 test VM.

## 1. Device surface and creation trigger

### kinonivd (EpocCam camera, AVStream/KS)

DriverEntry is `FUN_00401262` @ `0x401262` (reached from `entry` @ `0x6d8000`):

```
0x401262  KsInitializeDriver(DriverObject, RegistryPath, &PTR_PTR_0041991c)  ; KSDEVICE_DESCRIPTOR
0x40126c  DAT_006c3d3c = *(DriverObject + 0x70)      ; save ks.sys MJ_DEVICE_CONTROL
0x401272  *(DriverObject + 0x70) = FUN_00401080      ; install vendor MJ_DEVICE_CONTROL
```

- `KsInitializeDriver` only registers the minidriver and installs ks.sys dispatch. The FDO is created when the PnP manager starts the devnode.
- The filter factory is created in `FUN_006c7e70` (`KsCreateFilterFactory` call site `0x6c7ec4`):

```
iVar4 = KsCreateFilterFactory(DeviceObject,          // *(ctx+0xc)
                              FilterDescriptor,      // *(tbl+4+off)
                              RefString,             // *(tbl+off)
                              0,                     // SecurityDescriptor = NULL
                              8, 0, 0, &Factory);
```

  `SecurityDescriptor = NULL` means ks.sys applies its default device security descriptor.
- Interfaces registered by the INF (`kinonivd_844635B5.inf:64-67`): `KSCATEGORY_CAPTURE` and `KSCATEGORY_VIDEO_CAMERA`, filter GUID `{4EE16166-F358-4F10-8889-93107806B7A7}` and `GLOBAL`.
- The INF installs a **root-enumerated** device: `[AvsCamera.Device.NTx86] %AvsCamera.DeviceDesc%=AvsCamera,KINONIVD` (`kinonivd_844635B5.inf:47-48`). Creating the devnode is a Setup operation.
- No `IoCreateDevice`, no `IoCreateSymbolicLink`, and no `\Device\...` / `\DosDevices\...` string exists in the image (import/string scan). There is no legacy control device.

### kinonivad (Kinoni Virtual Audio Device, PortCls)

```
entry @ 0x56006 -> PcInitializeAdapterDriver(DriverObject, RegistryPath, AddDevice=FUN_0005436a)
```

PortCls creates the adapter FDO in the PnP `AddDevice` path. Again no `IoCreateDevice` and no device-name string. Setup is a devnode.

## 2. Effective DACL

**Important correction to the briefing:** in this collected package the `Security` value is **commented out**, not active.

`kinonivd_844635B5.inf:39-45` (identical block in `kinonivad_AECF289A.inf:39-45`):

```
; Uncomment the following lines to add security ACLs.
;
;[AvsCamera.Device.NT$ARCH$.HW]
;AddReg = AvsCamera.NTamd64.HW.AddReg
;
;[AvsCamera.Device.NT$ARCH$.HW.AddReg]
;HKR,,Security,, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGWGX;;;WD)(A;;GRGX;;;RC)"
```

- There is **no `D:P(...)` string in either binary** (`search_strings "D:P"` -> empty) and no `Security` string.
- Therefore the filter device is created with the **default I/O-manager / KS device descriptor**, not the quoted SDDL. That default is not provable from the image; a camera endpoint must be openable by ordinary users for DirectShow/MediaFoundation, so assume at least `GR` and probably `GRGW` for `WD`.
- `kinonivd_844635B5.inf:45` is also the only place the "known context" SDDL appears - it is a comment. Treat the SDDL claim in the briefing as **not applicable to this package**.

## 3. Handler / property table

The two property-set arrays were recovered from `.rdata` and parsed with the ks.h `KSPROPERTY_ITEM` layout (stride `0x28`: `PropertyId`, `Get` +0x04, `MinProperty` +0x08, `MinData` +0x0c, `Set` +0x10, `GetSupported` +0x14). Stride was verified by array adjacency (e.g. 6 items @ `0x4199d0` end exactly at the next set's `0x419ac0`).

Array A @ `0x419c20` (11 sets, includes the vendor sets) and array B @ `0x419d28` (6 sets, a subset plus the per-frame set). Which array is attached to the filter vs. to a pin was not resolved; both are reached through the same `KSFILTER_DESCRIPTOR`/`KSPIN_DESCRIPTOR_EX` chain.

| Set GUID | Name | Items | Get / Set handlers |
|---|---|---|---|
| `{9d12d198-f86c-4fed-b023-5d87653da793}` | vendor (Kinoni) | 1 | `0x6c5300` / `0x6c5360` (0x20-byte struct) |
| `{785e8f49-63a2-4144-ab70-ffb278fa26ce}` | vendor | 1 | `0x6c5480` / `0x6c54e0` (8 bytes) |
| `{43964bd3-7716-404e-8be1-d299b20e50fd}` | vendor | 1 | `0x6c53c0` / `0x6c5420` (8 bytes) |
| `{6a2e0670-28e4-11d0-a18c-00a0c9118956}` | `PROPSETID_VIDCAP_VIDEOPROCAMP` | 2 | `0x6c4b70`/`0x6c4bd0`, `0x6c4c30`/- |
| `{9d3d7bbf-5c6d-4138-bb00-584edd20f7c5}` | camera profile | 1 | `0x6c5540` / - |
| `{1cb79112-c0d2-4213-9ca6-cd4fdb927972}` | `KSPROPERTYSETID_ExtendedCameraControl` | 33 | paired `0x6c55a0`+N / `0x6c5600`+N |
| `{f1f3e261-dee6-4537-bff5-ee206db54aac}` | `KSPROPERTYSETID_PerFrameSetting` | 3 | `0x6c9ca0`, `0x6c9e40`; **Set-only** `0x6c86a0` |
| `{c6e13370-30ac-11d0-a18c-00a0c9118956}` | `PROPSETID_VIDCAP_CAMERACONTROL` | 8 | `0x6c6bc0`+ / `0x6c6c20`+ |
| `{c6e13360-30ac-11d0-a18c-00a0c9118956}` | `PROPSETID_VIDCAP_VIDEOPROCAMP` | 6 | `0x6c4c90`+ / `0x6c4cf0`+ |
| `{05dc8943-b9fb-4201-808f-6e91451c4760}` | vendor | 1 | `0x6c5110` / `0x6c5170` (single dword at filter+0x2b0) |
| `{571c92c9-13a2-47e3-a649-d2a778166384}` | per-frame/profile | 12 | item table did not parse with 0x28 stride - not decoded |

Every vendor handler follows one shape (example `0x6c5170`):

```
uVar1 = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
if (uVar1 == 0)            return 0x80000005;   // STATUS_BUFFER_TOO_SMALL
if (uVar1 < 4)             return 0xC0000023;   // STATUS_BUFFER_TOO_SMALL
if (Buffer == NULL)        return 0xC000000D;   // STATUS_INVALID_PARAMETER
*(filter + 0x2b0) = *Buffer;                     // fixed-offset store
```

### Custom IOCTL surface (not KS-mediated)

`FUN_00401080` @ `0x401080` (installed as `IRP_MJ_DEVICE_CONTROL` at DriverEntry) handles three vendor codes and forwards everything else to the saved ks.sys handler:

| IOCTL | Method | Action |
|---|---|---|
| `0x222000` | BUFFERED | `memcpy(driver_buf, SystemBuffer, InputBufferLength)` if `InputBufferLength <= capacity`; then 12-byte reply |
| `0x222008` | BUFFERED | requires In/Out `>= 0x74`; vtable call, 0x74-byte reply |
| `0x22200c` | BUFFERED | requires In/Out `>= 0x74`; vtable call, 0x74-byte reply |

`0x222000/8/c` are `FILE_DEVICE_UNKNOWN` (0x22), function 0x800/0x802/0x803, access bits 0.

## 4. Write sinks (decompiled)

**(a) Custom IOCTL 0x222000 - `FUN_00401080`, memcpy at `0x401203`:**

```
puVar7  = IrpSp->Parameters.DeviceIoControl.InputBufferLength;  // IrpSp + 0x08
local_64 = SystemBuffer;                                        // from the IRP
pcVar2 = *(code **)(*DAT_006c3d40 + 0x44);
guard_check_icall(&local_6c,&local_70,local_60,0);
(*pcVar2)();                       // returns dst = local_6c, capacity = local_70
if (puVar7 <= local_70) {
    memcpy(local_6c, local_64, (size_t)puVar7);                 // 0x401203
}
```

The copy is length-bounded by a capacity returned from the same vtable call that produced the destination. There is **no user-controlled destination pointer**; the destination comes from a driver-internal object (`DAT_006c3d40`, a .bss global that is NULL until the filter initialises).

**(b) Per-frame-settings SET - `FUN_006ce270` @ `0x6ce270`, memcpy at `0x6ce2e5`:**

```
uVar1 = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
if (uVar1 < 0x28) return 0xC0000023;
iVar4 = FUN_006cb3da(param_3, uVar1, &local_8);   // parser, 0x6cb3da
if (iVar4 >= 0) {
    _Dst = ExAllocatePoolWithTag(*param_3, 1, 'PFS-');
    memcpy(_Dst, param_3, *param_3);              // 0x6ce2e5
}
```

`FUN_006cb3da` (3 652 bytes) validates, before any use:
`param_2 != 0 && param_2 >= param_1[0] && param_1[0] >= 0x28 && param_1[8] == 1 && 1 <= param_1[1] <= 0x200`, then walks each nested element and rejects `element_size < 0x10` or `element_end > frame_end` (`0x6cb49x`-`0x6cb5xx`). The `memcpy` length and the allocation size are the same validated header field.

**(c) Per-frame-settings GET - `FUN_006c9e40` @ `0x6c9e40`, memcpy at `0x6c9e8b`:**

```
_Src  = *(filter + 0x24);  _Size = *_Src;
if (OutLen == 0)      return 0x80000005;
else if (OutLen < _Size) return 0xC0000023;
else memcpy(param_3, _Src, _Size);                // 0x6c9e8b
```

**(d) Vendor SET handlers** (`0x6c5360`, `0x6c54e0`, `0x6c5420`, `0x6c5170`) store fixed-size (4/8/0x20-byte) structures into fixed offsets of the filter object after checking `OutputBufferLength`. No user-supplied length or offset reaches the store.

No `MmMapIoSpace`, `MmGetPhysicalAddress`, `MmMapLockedPages*`, `ZwMapViewOfSection`, or `ProbeForWrite` import exists in either binary. `kinonivad` imports only PortCls/KS and ordinary pool/timer routines.

## 5. Validation gaps / residual unknowns

1. **`0x222000` capacity semantics.** The bound `puVar7 <= local_70` is only as sound as the vtable method at `+0x44`. `DAT_006c3d40` is zero at rest and is populated at filter start, so the callee cannot be resolved statically from this image alone. If that method returns a pointer-sized field rather than a byte capacity, the check is ineffective. This is the single unproven link in the chain.
2. **`0x222008/0x22200c`** check only that both buffer lengths are `>= 0x74`, then write exactly `0x74` bytes to `SystemBuffer`; the vtable callee (`+0x44`/`+0x48`) is likewise runtime-initialised.
3. **Per-frame parser.** The bounds logic is present and consistent for the paths reviewed; only the top-level header size/count and nested element sizes are trusted, and both are range-checked against the buffer. No integer-truncation path was found, but the 3 652-byte function was not exhaustively reviewed on every branch (e.g. `local_128 + 0x10` arithmetic at `0x6cbd..`).
4. **DACL is not a mitigation here.** Because the custom IOCTLs are `METHOD_BUFFERED`, the I/O manager does not require `FILE_WRITE_ACCESS` on the handle; a `GR`-only handle reaches the dispatch. The driver performs no `IoValidateDeviceIoControlAccess` and no access check of its own.

## 6. Setup required

**devnode.** Both drivers are PnP-only (no device created at DriverEntry). `kinonivd` needs a root-enumerated `KINONIVD` devnode from its INF; `kinonivad` needs the PortCls audio devnode. In addition both images are **32-bit**, so a 64-bit test VM cannot load them at all.

Under the no-setup rule this is **disqualified twice** (devnode + wrong architecture).

## 7. Next dynamic test (only if an x86 VM is warranted)

1. On a disposable 32-bit VM, `devcon install kinonivd.inf KINONIVD`, start the service, confirm `\Device\...` and the `KSCATEGORY_VIDEO_CAMERA` interface appear.
2. As a standard user, open the filter via the device interface and send `IOCTL 0x222000` with `InputBufferLength` = 0, 1, 0x74, 0x1000 and `OutputBufferLength` = 0x10, under Driver Verifier (Special Pool + Pool Tracking). The interesting observation is whether the `memcpy` at `0x401203` is reached at all with the large length, and what `local_70` is.
3. Send the same three IOCTLs with `METHOD_NEITHER`-style callers (DeviceIoControl always uses the code's own method; instead vary buffer alignment and use a read-only output buffer) to exercise the probe behaviour.
4. `KSPROPERTY_TYPE_SET` on `{f1f3e261-...}` id 2 with hand-built PFS buffers: valid 0x28 header, count 0x200, nested element size 0x10, and a truncated final element. Expect `0xC000000D`; a bugcheck or pool corruption would contradict this report.

*End of report.*
