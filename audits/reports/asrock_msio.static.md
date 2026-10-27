# ASRock / MICSYS / Nuvoton port-I/O & physical-memory drivers - static audit

Scope (all under `drivers\ASRock\`):

| file | arch | size | family | verdict |
|---|---|---|---|---|
| `MsIo64_E6AA2306.sys` | x64 | 34552 | MICSYS MsIo **v1.3** | **WRITE-MEDIUM** primitive, *blocked by token check* (all 4 IOCTLs call `SeTokenIsAdmin`) |
| `MsIo32_774DFF2B.sys` | x86 | 28920 | MICSYS MsIo **v1.3** | **WRITE-HIGH - unprivileged path (32-bit only)** via IOCTL `0x80102048` (IOPM grant, no token check) |
| `MsIo64_CFCF32F5.sys` | x64 | 17424 | MICSYS MsIo **v1.2** | **WRITE-HIGH** primitive, *blocked by DACL* (default admin-only) |
| `MsIo32_E8B2D697.sys` | x86 | 7680 | MICSYS MsIo **v1.2** | **WRITE-HIGH** primitive, *blocked by DACL* (default admin-only) |
| `MyPortIO_x64_958A6EAE.sys` | x64 | 20184 | Nuvoton MyPortIO 1.1.2026.0429 | **WRITE-LOW** (port range limited to SMBus window), *blocked by DACL* |
| `MyPortIO_x86_0F631435.sys` | x86 | 19160 | Nuvoton MyPortIO 1.1.2026.0429 | **WRITE-LOW**, *blocked by DACL* |
| `SONiXDDRx64_D045DB68.sys` | x64 | 43168 | SONiX DDR5 SPD/SMBus | **WRITE-MEDIUM** (arbitrary `out`, PCI cfg write), *blocked by DACL* |
| `AsrNfDrv000_A7F562E0.sys` | x64 | 73088 | ASRock/Nuvoton I2C bus (KMDF) | **NO-WRITE** (no port/phys-memory sink) |

All addresses are virtual addresses (image base `0x10000` for the MsIo files, `0x140000000` for SONiX/AsrNfDrv).

---

## 1. Which device-creation API is actually used, with which SDDL?

### MsIo v1.3 (both arches) - `IoCreateDeviceSecure`, *not* plain `IoCreateDevice`

`DriverEntry` does **not** call `IoCreateDevice`. It calls a local wrapper that resolves the API at runtime:

* x64 `MsIo64_E6AA2306.sys`, `DriverEntry` = `FUN_00011a60` @ `0x11a60`:

```
00011aa7  LEA RAX,[0x13368]            ; &UNICODE_STRING DefaultSDDLString
00011aae  MOV [RSP+0x40],R11           ; arg 9 = &DeviceObject
00011ab3  MOV [RSP+0x38],0x0           ; arg 8 = DeviceClassGuid = NULL
00011abc  MOV [RSP+0x30],RAX           ; arg 7 = SDDL
00011ac1  LEA R8,[RSP+0x58]            ; arg 3 = &"\Device\MsIo"
00011ac6  MOV R9D,0x8010               ; arg 4 = DeviceType 0x8010
00011acc  XOR EDX,EDX                  ; arg 2 = 0 (extension size)
00011ace  MOV RCX,RBX                  ; arg 1 = DriverObject
00011ad6  MOV dword ptr [RSP+0x20],0x100   ; arg 5 = FILE_DEVICE_SECURE_OPEN
00011ade  CALL 0x00016010
```

* x86 `MsIo32_774DFF2B.sys`, `DriverEntry` = `FUN_00011fb0` @ `0x11fb0`: same 9 arguments, SDDL pointer `&DAT_000132b8`, class GUID `0`, followed by `CALL 0x00015064`.

The wrapper is `FUN_00016010` (x64) / `FUN_00015064`->`FUN_00015005` (x86). It resolves the API by name and **falls back to a private re-implementation** of `IoCreateDeviceSecure` if the export is missing:

```c
// x64 FUN_00016010 @ 0x16010
RtlInitUnicodeString(local_38, L"IoCreateDeviceSecure");
DAT_00014358 = (code *)MmGetSystemRoutineAddress(local_38);
if (DAT_00014358 == (code *)0x0) DAT_00014358 = FUN_00016110;   // local fallback
(*DAT_00014358)(param_1, ... , param_7 /*SDDL*/, param_8 /*class GUID*/, param_9 /*out DevObj*/);
```

The fallback `FUN_00016110` @ `0x16110` does `IoCreateDevice` (`0x1625c`), builds an SD from the SDDL text, then `ObOpenObjectByPointer` + `ZwSetSecurityObject`, i.e. the same DACL either way.

**Dead-literal finding: REFUTED for these two files (with a caveat).**

The SDDL argument is a `UNICODE_STRING` **descriptor**, not the string body:

```
x64  0x13368: 56 00 58 00 00 00 00 00 10 33 01 00 00 00 00 00
             len=0x56 (86 B = 43 chars), max=0x58, Buffer=0x13310
x86  0x132b8: 56 00 58 00 60 32 01 00
             len=0x56, max=0x58, Buffer=0x13260
```

The code `LEA`s the **descriptor address** (`0x11aa7: LEA RAX,[0x13368]`; x86 `FUN_00011fb0` loads `&DAT_000132b8`), while the ASCII/UTF-16 text lives elsewhere (`0x13310` / `0x13260`). A "refs to the string bytes" scan therefore reports **0 xrefs even though the string is live**. This is exactly the failure mode behind the `SDDL-UNPROVEN` / `refs=0` triage mark.

Effective SDDL (43 chars, verified byte-for-byte at `0x13310` / `0x13260`):

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR;;;WD)
```

-> SYSTEM full, Administrators read/write/execute, **Everyone (WD) GENERIC_READ**.

The other six SDDL literals in the 7-entry table (`...WD)(...RC)`, `...GRGWGX;;;WD`, etc.) have no descriptor referencing them and are genuinely dead.

*(Aside, verified against the live `ntoskrnl.exe` on this machine: `IoCreateDeviceSecure` @ `0x140738840` tests `R8` (DeviceName) for NULL and treats `[rbp+0x78]` (DeviceClassGuid) as optional - `CMP qword ptr [RBP+0x78],R10 / JZ 0x1407388cd`. So the NULL class GUID at arg 8 does **not** make the create fail.)*

### MsIo v1.2 (both arches) - plain `IoCreateDevice`, no SD

```c
// x64 FUN_00011800 @ 0x11800 (call at 0x11858)
iVar1 = IoCreateDevice(param_1, 0, local_30, 0x8010, 0, 0, &local_38);
// x86 FUN_000119b8 @ 0x119b8
iVar1 = IoCreateDevice(param_1, 0, local_10, 0x8010, 0, 0, &local_8);
```

No SDDL, no `IoCreateDeviceSecure` import -> the I/O manager applies the default device DACL (SYSTEM + BUILTIN\Administrators full control).

### MyPortIO (Nuvoton)

```c
// x64 FUN_14000107c @ 0x14000107c
uVar2 = IoCreateDevice(param_3, 0x50, local_28, param_2 /*0x22*/, 0x100, 0, param_4);
// then IoCreateSymbolicLink(L"\\DosDevices\\MyPortIODev", L"\\Device\\MyPortIO0")
```

Plain `IoCreateDevice` -> default admin-only DACL.

### SONiXDDRx64

Creates `\Device\SONiXDDR_0_0_0_1` (+ `\DosDevices\SONiXDDR_0_0_0_1`) through a dynamically resolved `IoCreateDeviceSecure` (name string at `0x140003330`, resolved in `FUN_140001000`), then applies post-creation security settings that are **read from the device's registry key** (`FUN_14000762c` -> `CmRegUtilWstrValueGetFullBuffer(..., 0x140003448 /*"Security"*/, ...)` -> `SeCaptureSecurityDescriptor`). Compiled default is `D:P(A;;GA;;;SY)(A;;GA;;;BA)`.

---

## 2. Effective DACL (cited)

| driver | create path | effective DACL | who can open |
|---|---|---|---|
| MsIo64 v1.3 (`0x11ade` -> `0x16010`) | `IoCreateDeviceSecure` | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR;;;WD)` (`0x13368`->`0x13310`) | **Everyone read**; admins RWX |
| MsIo32 v1.3 (`0x11fb0` -> `0x15064`) | `IoCreateDeviceSecure` | same string (`0x132b8`->`0x13260`) | **Everyone read**; admins RWX |
| MsIo64 v1.2 (`0x11858`) | `IoCreateDevice` | default device SD | Administrators / SYSTEM only |
| MsIo32 v1.2 (`0x119b8`) | `IoCreateDevice` | default device SD | Administrators / SYSTEM only |
| MyPortIO x64/x86 | `IoCreateDevice` | default device SD | Administrators / SYSTEM only |
| SONiX | `IoCreateDeviceSecure` + registry `Security` | compiled default `D:P(A;;GA;;;SY)(A;;GA;;;BA)`; runtime value from `HKLM\...\Class\{...}\Security` | Administrators / SYSTEM only (unless an admin rewrites the key) |
| AsrNfDrv | KMDF `WdfDeviceCreate` (no SDDL) | default | Administrators / SYSTEM only |

**The v1.3 DACL is *not* admin-only - it grants Everyone `GENERIC_READ`.** That is the only permissive DACL in this entire driver set. It matters because the driver never calls `IoValidateDeviceIoControlAccess`, and all MsIo IOCTLs are `FILE_ANY_ACCESS`, so a read-only handle is a valid IOCTL handle.

---

## 3. IOCTL tables

All four MsIo families use device type `0x8010`, `METHOD_BUFFERED`, `RequiredAccess = FILE_ANY_ACCESS` (bits 14-15 = 0), i.e. any handle access suffices if the driver does not check.

### MsIo64 v1.3 (`MsIo64_E6AA2306.sys`) - dispatch `FUN_00011580` @ `0x11580`

| IOCTL | handler | buffer gate | admin gate | action |
|---|---|---|---|---|
| `0x80102040` | `0x118f4` | `[rsp+..] == 0x28` (40 B in/out) | `SeTokenIsAdmin` @ `0x1192e` | `FUN_000111f0`: map physical -> user VA |
| `0x80102044` | `0x11811` | `== 0x28` | @ `0x1184b` | `FUN_00011500`: unmap |
| `0x80102050` | `0x11719` | `>= 7` | @ `0x11741` | `in` byte/word/dword from port |
| `0x80102054` | `0x11618` | `>= 7` | @ `0x11640` | `out` byte/word/dword to port |

Port struct (7 B): `{USHORT Port; ULONG Value; UCHAR Width;}` packed.

### MsIo32 v1.3 (`MsIo32_774DFF2B.sys`) - dispatch `FUN_00011944` @ `0x11944`

| IOCTL | cmp addr | handler | admin gate | action |
|---|---|---|---|---|
| `0x80102040` | `0x11989` | `0x11c9f` | yes | map physical |
| `0x80102044` | `0x11994` | `0x11beb` | yes | unmap |
| **`0x80102048`** | `0x1199f` | **`0x11b9e`** | **NO** | **IOPM: `MmAllocateNonCachedMemory(0x2000)`, zero, `Ke386IoSetAccessProcess` @ `0x11bc4`, `Ke386SetIoAccessMap(1,buf)` @ `0x11bcf`** |
| **`0x8010204c`** | `0x119aa` | **`0x11b6a`** | **NO** | free IOPM / `Ke386IoSetAccessMap` restore |
| `0x80102050` | `0x119b5` | `0x11a9e` | yes | `READ_PORT_*` |
| `0x80102054` | `0x119c0` | `0x119dd` | yes | `WRITE_PORT_*` |

### MsIo64 v1.2 (`MsIo64_CFCF32F5.sys`) - dispatch `FUN_000114c0` @ `0x114c0`

| IOCTL | buffer gate | admin gate | action |
|---|---|---|---|
| `0x80102040` | `len != 0` | none | `FUN_00011090` map physical |
| `0x80102044` | `len != 0` | none | `FUN_00011430` unmap |
| `0x80102050` | `len != 0` | none | `in` |
| `0x80102054` | `len != 0` | none | `out`, blocks only ports `0x66`, `0x92`, `0xCF9` |

### MsIo32 v1.2 (`MsIo32_E8B2D697.sys`) - dispatch `FUN_00011628` @ `0x11628`

Same four as x64 v1.2 **plus** `0x80102048` "ENABLEDIRECTIO" and `0x8010204c` "DISABLEDIRECTIO" (IOPM), neither with any token check.

---

## 4. Write sinks (decompiled lines)

**MsIo64 v1.3 - port write, `FUN_00011580` @ `0x11618`:**

```
000116e3  MOVZX EDX,R8W
000116e7  MOV EAX,dword ptr [RSP+0x8a]
000116ee  OUT DX,EAX            ; WRITE_PORT_ULONG  (width byte from struct+6 == 4)
000116f4  MOVZX EDX,R8W
000116f8  MOVZX EAX,word ptr [RSP+0x8a]
00011700  OUT DX,AX             ; WRITE_PORT_USHORT
00011707  MOVZX EDX,R8W
0001170b  MOVZX EAX,byte ptr [RSP+0x8a]
00011713  OUT DX,AL             ; WRITE_PORT_UCHAR
```

Port filter `FUN_000110a0`: allows `0xCF8`, `0xCFC`, `0xCFE`, and `[DAT_00014338 .. +0xD]` (SMBus I/O base). Everything else -> `0xC0000022`.

**MsIo32 v1.3 - IOPM install, `0x11b9e` (target of the `0x80102048` compare at `0x1199f`):**

```
00011b9e  PUSH 0x2000
00011ba3  CALL [0x1303c]        ; MmAllocateNonCachedMemory(0x2000)
00011bb2  MOV ECX,0x800
00011bb9  STOSD.REP ES:EDI      ; zero the 8 KiB bitmap
00011bbb  PUSH 0x1
00011bbd  CALL [0x13058]        ; IoGetCurrentProcess
00011bc4  CALL 0x123b0          ; Ke386IoSetAccessProcess(process)
00011bcf  CALL 0x123a4          ; Ke386SetIoAccessMap(1, zeroed bitmap)
00011bd7  MOV [EAX+0x10],EDI    ; stash buffer in the file object
```

An all-zero I/O permission bitmap means **ring-3 `IN`/`OUT` to every port** for the calling process - the CPU consults the IOPM because CPL 3 > IOPL.

**MsIo64 v1.2 - port write `FUN_000114c0`:**

```c
uVar11 = uVar9 & 0xffff;
if (((uVar11 != 0x66) && (uVar11 != 0x92)) && (uVar11 != 0xcf9)) {
  if (cVar1 == '\x01') out(local_res10,uStackX_12);
  else if (cVar1 == '\x02') out(local_res10,uVar6);
  else if (cVar1 == '\x04') out(local_res10, CONCAT22(...));
}
```

**Physical-memory mapping:**

* v1.3 x64 `FUN_000111f0` @ `0x111f0` - `\Device\PhysicalMemory` + `ZwOpenSection(0xF001F)` + `ZwMapViewOfSection(..., ProcessHandle = -1)` into the **caller's** address space, size clamped to 4 bytes; range-checked twice:
  * `FUN_000110e0` - `MmGetPhysicalMemoryRanges()`, requires `[addr, addr+len]` inside one RAM range;
  * `DAT_00014328` (chipset MCFG/MMIO base read via PCI `0xCF8/0xCFC` in DriverEntry) `<= addr <= +0x10000000`. Note the compare truncates to 32 bits: `(param_1 & 0xffffffff) < DAT_00014328`.
* v1.2 x64 `FUN_00011090` @ `0x11090` - same mapping but **only** the MCFG-window check, no `MmGetPhysicalMemoryRanges` (that API is not even imported).
* v1.2 x86 `FUN_000111d8` @ `0x111d8` - MCFG window only.

---

## 5. Validation gaps

1. **No `IoValidateDeviceIoControlAccess` call.** Both v1.3 drivers resolve the pointer once at init (`RtlInitUnicodeString(L"IoValidateDeviceIoControlAccess")` + `MmGetSystemRoutineAddress`, stored in `DAT_00014360`/`_DAT_00014360`) and **never call it** - the stored pointer has no code reference. A read-only handle is therefore enough for every IOCTL. The `RequiredAccess` bits in the IOCTL codes are 0 anyway.
2. **Admin check is only `SeTokenIsAdmin`**, which is present on all four x64 v1.3 IOCTLs but **absent on the two x86-v1.3 IOPM IOCTLs** (`0x80102048`/`0x8010204c`) and on *every* IOCTL of the v1.2 and MSI MSIO builds.
3. **v1.3 x64 physical map** is constrained twice - but the two constraints are mutually exclusive in practice: `FUN_000110e0` requires the range to be inside a `MmGetPhysicalMemoryRanges()` **RAM** range, while `DAT_00014328` is an **MMIO** base taken from PCI config (`0xCF8/0xCFC`, masked `0xFC000000`), and the second check requires the address inside `[base, base+0x10000000]`. A RAM page will normally fail the MMIO-window test and vice versa, so IOCTL `0x80102040` is effectively dead on both v1.3 builds (needs dynamic confirmation). **v1.2 physical map** has only the MMIO-window check (same practical dead-end); the **MSI MSIO64 / MSI MSIO32** variants drop *all* address checks and map `[addr, addr+len]` for any address and arbitrary length (see `msi_ntiolib.static.md`), and **SMI_IO**/`amifldrv`/`EVGA` do no validation at all.
4. **Port writes**: v1.3 uses a 3-entry allowlist (`0xCF8/0xCFC/0xCFE` + SMBus base..+0xD); v1.2 blocks only `0x66`/`0x92`/`0xCF9`, i.e. essentially arbitrary port I/O. `0xCF9` (reset) is blocked but `0xCF8/0xCFC` PCI config is not - a user can reprogram BARs / enable bus-master DMA.
5. **IOPM path (x86 only)**: zeroes the entire 8 KiB bitmap -> unrestricted user-mode port I/O. No privilege check, no way to scope it down.
6. **IRP_MJ_CREATE** (`pcVar8[0] == 0`) only `DbgPrint`s - no `FILE_WRITE_ACCESS` check, no `SeAccessCheck`.

---

## 6. Setup required

* **none** beyond the driver being installed and its service started (`\Device\MsIo`, `\DosDevices\MsIo` exist unconditionally after `DriverEntry`; no hardware probe is needed for device creation).
* No devnode, no PnP, no firmware/hardware dependency for the port/IOPM IOCTLs. (The v1.3 *physical-map* IOCTL additionally needs `DAT_00014328 != 0`, i.e. a recognised Intel/AMD chipset; it returns `0xC000000D` otherwise.)
* **x86 caveat:** `MsIo32` is a 32-bit kernel driver - it cannot be loaded on x64 Windows. The unprivileged IOPM path is therefore reachable only on 32-bit Windows.

---

## 7. Next dynamic test (recommended, not performed here)

1. On a 32-bit Windows 10/11 scratch VM with `MsIo32` v1.3 installed: as a standard user, `CreateFileW(L"\\\\.\\MsIo", GENERIC_READ, ...)` -> expect **success** (DACL `GR` to WD).
2. `DeviceIoControl(h, 0x80102048, NULL, 0, NULL, 0, ...)` -> expect `STATUS_SUCCESS`; then execute `IN AL,DX` / `OUT DX,AL` from the same process to a harmless port (e.g. `0x80`) and confirm no `#GP`.
3. For `MsIo64` v1.3: repeat step 1 (expect success), then `0x80102054` -> expect `0xC0000022`; this confirms the token check is the only barrier.
4. For v1.2/MSIO: CreateFile as standard user -> expect `ERROR_ACCESS_DENIED` (DACL).

---

## 8. Ranking within this group

1. **`MsIo32_774DFF2B.sys` (v1.3, x86)** - only driver in the whole collection whose DACL lets a non-admin open the device *and* which then hands out an unchecked I/O-privilege primitive. Effective on 32-bit Windows only.
2. **`MsIo64_E6AA2306.sys` (v1.3, x64)** - strongest code (kernel-mapped physical + port I/O) but every IOCTL is `SeTokenIsAdmin`-gated; DACL is permissive, so the device is *openable* but not *usable* by a standard user.
3. `MsIo64_CFCF32F5` / `MsIo32_E8B2D697` (v1.2) - no token check at all, arbitrary port write + physical map; only the default admin-only DACL stops them.
4. `SONiXDDRx64` - arbitrary `out` + `HalSetBusDataByOffset` (PCI config), no token check, admin-only DACL.
5. `MyPortIO` - restricted to the SMBus window (`0xB00-0xB0F`, `0xCF8/0xCFC`); admin-only DACL.
6. `AsrNfDrv` - KMDF I^2C bus driver; no port or physical-memory primitive.

> **Bottom line for ASRock:** the `SDDL-UNPROVEN` triage result is a false negative caused by descriptor indirection, and the v1.3 DACL is *Everyone-readable*, not admin-only. On x64 the token check still blocks abuse; on x86 the `0x80102048` IOPM IOCTL is an unprivileged hardware-level primitive.
