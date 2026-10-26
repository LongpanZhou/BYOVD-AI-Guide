# Audit: S3 — Moxa / Digi / Perle USB-serial drivers

> **Correction:** the per-file `mxusbd` reports are authoritative at **MW3** (R3/hardware,
> W2 pool OOB). The group summary’s MW2 was a matrix error; use MW3.

**Scope:** 14 exact `.sys` images in `drivers\`. Kernel memory-write only; `R2` local administrator is in scope; hardware-only writes are `HW-ONLY`; setup is a severity field, not a disqualifier.

**REA disclosure:** No REA session was opened for this audit. The shared REA bridge was already at its four-session limit. All work below is local, static, offline: Ghidra 12.1.4 headless decompilation, `llvm-objdump` PE import parsing, and PowerShell hash/signature/version checks. Nothing was loaded, executed, installed, or written to the registry.

Canonical header:

| Field | Value |
|---|---|
| File(s) | 14 files: `mxuport,1_5B845038.sys`, `mxuport,2_5A9003D4.sys`, `mxusbd,1_477EA31C.sys`, `mxusbd,2_4DD6AB6A.sys`, `mxuwdrv2,1_AAFCCE25.sys`, `mxuwdrv2,2_F6F46E85.sys`, `mxuwdrv2,3_96105CDC.sys`, `DigiRlPt_8107C7F3.sys`, `DigiRlPt64_73D96004.sys`, `edgeser_8C42B1CE.sys`, `edgeser64_F1915F2D.sys`, `IonEnum_7439AFF2.sys`, `ionenum64_F6C87E28.sys`, `TruePort_47710BD8.sys` |
| SHA-256(s) | 14/14 verified with `Get-FileHash -Algorithm SHA256`; full values in §2 |
| Analysis date | 2026-10-25 |
| Method | Static-only: local Ghidra 12.1.4 headless decompilation (one dump per AMD64 image), `llvm-objdump -p` PE import/architecture parsing, version resources, `Get-AuthenticodeSignature`. REA not used (capacity). No web, no execution, no load, no service, no registry. |
| Reach tier | R2 for the signed x64 images whose device objects carry the default admin DACL (including `mxusbd`'s 0x2A control interface); R3 for the remaining hardware/interface-only function devices. All require the physical adapter/port (`Setup: hardware`). |
| Setup required | hardware |
| Write quality | **W2** for `mxusbd` ×2 (unchecked `0x1B2040` output write); **W0** for the other 12 |
| Verdict | **MW2** for `mxusbd` ×2 (hardware-gated pool OOB write); **NO-MEMORY-WRITE** for the other 5 signed AMD64 images; **BLOCKED** for 4 architecture-unloadable and 3 signing-unloadable images. No MW1. |

## 1. Internals

All 14 are WDM serial/port drivers built around the standard serial IOCTL contract (`DeviceType 0x1B`, `IOCTL_SERIAL_* 0x1B00xx`) plus vendor extensions:

- **Moxa `mxuport`** — USB serial function driver; creates a named `\Device\mxuportN` FDO (type 0x1B, extension 0x968), a `\DosDevices\` symbolic link, and forwards port work down the stack. Both builds are the same code.
- **Moxa `mxusbd`** — USB serial bus/function driver; creates an unnamed 0x2A control FDO (extension 0x508) and unnamed 0x1B serial FDOs (extension 0x9038), registers a device interface, and exposes Moxa vendor control codes `0x4042xxx` and `0x1B2xxx` in addition to the serial set. **The 0x2A device-control path has an unchecked output write at `0x1B2040` (MW2; §6).**
- **Moxa `mxuwdrv2`** — UPort 1110/1130/1150 bus/port driver; class-library-style dispatch, creates named port PDOs and a `\DosDevices\` link with `IoCreateUnprotectedSymbolicLink` (NULL-DACL link; target DACL still default). The ARM64 build is the same source line at 4.3 Build 26010215.
- **Digi RealPort (`DigiRlPt*`)** — serial-over-TCP driver; creates a 0x1B serial FDO, 0x22 control devices (one with a GUID symlink `{6A4C3815-AAAC-4d03-ABE2-0ECCD5C3D088}`), a type-4 TDI device and `\Device\PS_`/`PSPDO_` devices. Builds internal non-paged MDLs for its own buffers only.
- **Digi Edgeport (`edgeser*`)** — USB serial function driver; creates `\Device\EdgeSer%u` / `\Device\USBSERIAL%03u` and `\DosDevices\COM%u` / `USBSERIAL%03u` links; per-port IOCTL vtable dispatch.
- **Digi `IonEnum*`** — serial-port enumerator (serenum) function driver; unnamed 0x2A FDO, `IoRegisterDeviceInterface`, one registry-query IOCTL.
- **Perle `TruePort`** — serial-over-network driver; unnamed 0x22 control device (extension 0x325D8), named `\Device\TPPort` 0x1B ports (extension 0xBF8), `\DosDevices\` link, and a second port-device dispatch path for `0x222000`.

No image imports `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `KeStackAttachProcess`, `IoCreateDeviceSecure`, `SeAccessCheck`, or `ProbeForWrite`. The only `Mm*` imports in the corpus are `MmGetSystemRoutineAddress`, `MmBuildMdlForNonPagedPool`, `MmLockPagableDataSection`/`MmUnlockPagableImageSection`, and `MmQuerySystemSize`.

## 2. Per-file results

| # | File | Arch | Signature | SHA-256 | Device / open gate | Reach / setup | Write | Verdict |
|---:|---|---|---|---|---|---|---|---|
| 1 | `mxuport,1_5B845038.sys` | AMD64 | Valid, CN=MOXA INC. | `5B8450383B795A49F948CDCA7924E178853B01519260615ED752FB799019BA3B` | `\Device\mxuportN` + `\DosDevices\` link; IoCreateDevice default DACL | R2 / hardware | W0 | **NO-MEMORY-WRITE** |
| 2 | `mxuport,2_5A9003D4.sys` | AMD64 | Valid, CN=MOXA INC. | `5A9003D405A5575FAAE41D564F68B71692A9AE885920BF361903EB16EAF42F94` | same as #1; code identical | R2 / hardware | W0 | **NO-MEMORY-WRITE** |
| 3 | `mxusbd,1_477EA31C.sys` | AMD64 | Valid, CN=MOXA INC. | `477EA31CC924DC56361B0460994443DA9A63C2B61D88BC3619D2035479CD905F` | unnamed 0x2A control + 0x1B serial FDOs; admin-open interface | R2 / hardware | **W2** | **MW2** (0x1B2040 unchecked output write) |
| 4 | `mxusbd,2_4DD6AB6A.sys` | AMD64 | Valid, CN=MOXA INC. | `4DD6AB6A9474BFE2E647D4DF3BC7A24FD37E8148104D1887F9A7F5FC07ED9CA2` | same as #3; code equivalent | R2 / hardware | **W2** | **MW2** (0x1B2040 unchecked output write) |
| 5 | `mxuwdrv2,1_AAFCCE25.sys` | AMD64 | Valid, CN=MOXA INC. | `AAFCCE2545DB9419E881E5800C50A92D1720EC81B80524BCC7226DB5874610C5` | named port PDO + unprotected `\DosDevices\` link; target default DACL | R2 / hardware | W0 | **NO-MEMORY-WRITE** |
| 6 | `mxuwdrv2,2_F6F46E85.sys` | AMD64 | Valid, CN=MOXA INC. | `F6F46E859336A75EF3D32C0B86B54DF47913DB34EAF71D3B06D7892568305BA4` | same as #5; code identical | R2 / hardware | W0 | **NO-MEMORY-WRITE** |
| 7 | `mxuwdrv2,3_96105CDC.sys` | ARM64 (`0xAA64`) | Valid, MS WHCP | `96105CDCFC5D2027D74D17B04BC375F241B57B8A643409B68AA1834F46C6AAFE` | same driver line; not loadable on x64 | n/a | W0 (static) | **BLOCKED** (architecture) |
| 8 | `DigiRlPt_8107C7F3.sys` | x86 (`0x014C`) | NotSigned | `8107C7F3D71C50A93FF50AD24F932549FDCE819D8C7FAA60CDF7ED716718E35B` | 0x1B/0x22/TDI devices; not loadable on x64 | n/a | W0 (static) | **BLOCKED** (architecture) |
| 9 | `DigiRlPt64_73D96004.sys` | AMD64 | **NotSigned** | `73D96004F9C0FF425ECAB1B8BE1647A7D9F2851411EA64CDB0D70FF10E02F5A6` | 0x1B serial, 0x22 control (`{6A4C3815-…}`), TDI, `\Device\PS_`; default DACL | R3 / hardware | W0 | **BLOCKED** (signing); static NO-MEMORY-WRITE |
| 10 | `edgeser_8C42B1CE.sys` | x86 (`0x014C`) | Test-signed (`WDKTestCert`) | `8C42B1CE8A88789CD9CBBE76DC682868640326E565A5CEA603A2D25547070492` | `\Device\EdgeSer%u` + `\DosDevices\COM%u`; not loadable on x64 | n/a | W0 (static) | **BLOCKED** (architecture) |
| 11 | `edgeser64_F1915F2D.sys` | AMD64 | Test-signed (`WDKTestCert`, `UnknownError`) | `F1915F2D5DD1EB85A851AB7E56FEAEEF8C21DEDBF03AEA5DB72E78314892E9AF` | `\Device\EdgeSer%u` + `\DosDevices\COM%u`; default DACL | R2 / hardware | W0 | **BLOCKED** (signing); static NO-MEMORY-WRITE |
| 12 | `IonEnum_7439AFF2.sys` | x86 (`0x014C`) | NotSigned | `7439AFF2D771A161F4ACE940037C871F32EBB90F9241E4E3425918470088A0F1` | serenum 0x2A FDO + interface; not loadable on x64 | n/a | W0 (static) | **BLOCKED** (architecture) |
| 13 | `ionenum64_F6C87E28.sys` | AMD64 | **NotSigned** | `F6C87E28A8C69B6F1E6B4F61231B79536E82D2B2160669933549E201A65E0549` | unnamed 0x2A serenum FDO + `IoRegisterDeviceInterface`; default DACL | R3 / hardware | W0 | **BLOCKED** (signing); static NO-MEMORY-WRITE |
| 14 | `TruePort_47710BD8.sys` | AMD64 | Valid, CN=Perle Systems Limited | `47710BD892EFB49085CB01B79063496F964F494571645B666C407A0B8646698F` | unnamed 0x22 control + `\Device\TPPortN` 0x1B ports + `\DosDevices\`; default DACL | R2 / hardware | W0 | **NO-MEMORY-WRITE** |

Build-family notes:

- `mxuport` #1/#2 decompile identically except the image name; one analysis covers both.
- `mxusbd` #3/#4 differ only in a few decompiler argument renderings (remove-lock/pool-call signatures); the IOCTL switch and bounds are the same.
- `mxuwdrv2` #5/#6 decompile identically except the image name; #7 is the ARM64 build of the same 4.3 source line.
- Digi x86 and x64 pairs are the same file versions (RealPort 4.8.488.0; Edgeport/IonEnum 6.04.001). The x64 members are audited below; the x86 members are blocked only by architecture.

## 3. Entry / device / interface / effective DACL

| Driver | DriverEntry | Device creation | Name / link / interface | Effective DACL |
|---|---|---|---|---|
| `mxuport` | `0x140001000` (entry `0x14000a000`) | `IoCreateDevice(DriverObject, 0x968, name, 0x1b)` in `FUN_140001170` | `\Device\mxuportN`; `IoCreateSymbolicLink` of `\DosDevices\…` | No SDDL, no `IoCreateDeviceSecure`, no `ZwSetSecurityObject`; IoCreateDevice default (SYSTEM + Administrators). R2. |
| `mxusbd` | `0x140001000` (entry `0x140010000`) | `FUN_140001128`: `IoCreateDevice(..., 0x508, 0, 0x2a, ...)`; `FUN_140006344`: `IoCreateDevice(..., 0x9038, 0, 0x1b, ...)` | unnamed FDOs; `IoSetDeviceInterfaceState` at `FUN_140001128`; `\mxucom%04d`/`\mxup%04d` names stored for the serial class | IoCreateDevice default; no SDDL/Secure call. R2 (admin) + hardware; the 0x2A interface is the MW2 path. |
| `mxuwdrv2` | `0x140001ef4` (entry `0x14001a000`) | `IoCreateDevice(..., param_7+8, name, ...)` in `FUN_1400013c8` | named PDO from the UMP/UPort templates; `IoCreateUnprotectedSymbolicLink` in `FUN_14000f294` builds `\DosDevices\` + name | Link is NULL-DACL (unprotected); target device is IoCreateDevice default. R2. |
| Digi RealPort | `0x140038000` (entry `0x140038000`) | `FUN_1400034bc` (0x1B, 0xac0), `FUN_140003d20` (0x22, 0x388), `FUN_14000422c` (type 4, 0xc50), `FUN_140004e0c` (0x22, 0x38, GUID name + symlink) | `\Device\PS_`, `\Device\PSPDO_`, `\Device\Tcp`, GUID `{6A4C3815-AAAC-4d03-ABE2-0ECCD5C3D088}` | IoCreateDevice default; no SDDL/Secure call. R3. |
| Digi Edgeport | `0x1400361b0` (entry `0x140055000`) | `FUN_140002788` (control, 0x22, 0x4e0); `FUN_140017328` (named, 0x22, 0x4e0) + `IoCreateSymbolicLink` in `FUN_1400187a8` | `\Device\EdgeSer%u`, `\Device\USBSERIAL%03u`, `\DosDevices\COM%u`, `\DosDevices\USBSERIAL%03u` | IoCreateDevice default; no SDDL. R2. |
| Digi IonEnum | `0x14000a000` | `IoCreateDevice(DriverObject, 0x108, 0, 0x2a)` in `FUN_140008000` | unnamed FDO; `IoRegisterDeviceInterface(param_2, &DAT_140003210, …)` | IoCreateDevice default; no SDDL. R3. |
| Perle TruePort | `0x14000f970` | `FUN_140015780`: `IoCreateDevice(..., 0x325d8, 0, 0x22)`; `FUN_140016200`: `IoCreateDevice(..., 0xbf8, name, 0x1b)` | unnamed control device; `\Device\TPPortN` + `\DosDevices\` link; interface GUID at `0x1400114f8` | IoCreateDevice default; no SDDL/Secure call. R2. |

**Effective-DACL statement.** None of the 14 images contains an SDDL string, calls `IoCreateDeviceSecure`, calls `ZwSetSecurityObject`, or imports `SeAccessCheck`. The device objects therefore receive the I/O manager's default device security (full control to SYSTEM and the local Administrators group; no explicit `Everyone`/`Users` ACE in the image). The one exception in mechanism is `mxuwdrv2`'s `IoCreateUnprotectedSymbolicLink`, which gives the *link* a NULL DACL while the target device keeps the default DACL. An INF or device-interface security descriptor could widen or narrow this; no INF is in the corpus, so the image-level gate is recorded as R2. `ionenum64`/`mxusbd` devices are unnamed and reached through their interfaces, hence R3.

## 4. Dispatch and IOCTL table

### 4.1 Dispatch table

| Driver | CREATE | CLOSE | READ | WRITE | DEVICE_CONTROL | INTERNAL_DEVICE_CONTROL | Other |
|---|---|---|---|---|---|---|---|
| `mxuport` | `0x1400046b0` | `0x140004660` | `0x140004cb0` | `0x140004f10` | **`0x140001cb0`** | `0x140002330` | CLEANUP `0x140001c70`; PNP `0x1400032f0`; POWER `0x140005140` |
| `mxusbd` | `0x140007fb0` | `0x140007f80` | `0x140008d80` | `0x1400090d0` | **`0x140003840`** | `0x140003640` | — |
| `mxuwdrv2` | all majors → `0x140001e70` (per-device class dispatch); IOCTL switch **`0x1400088a0`** | | | | | | `0x222080` class callback |
| Digi RealPort | `0x1400050b8` | `0x14000211c` | `0x140024894` | `0x1400278b0` | **`0x140004d3c`** → `0x140001afc` | `0x140004cc0` | CLEANUP `0x140001d5c`; FLUSH `0x140025a00` |
| Digi Edgeport | `0x140038c40` | `0x140038b20` | `0x1400390f0` | `0x140039150` | **`0x140035fb0`** → per-port vtable, serial switch `0x14000a710` | `0x1400360b0` | CLEANUP `0x140035f20` |
| Digi IonEnum | `0x1400019f0` | `0x1400019f0` | — | — | **`0x140001da0`** | — | PNP/POWER set in `FUN_14000a000` |
| Perle TruePort | control `0x1400064c0`; port `0x140007770` | `0x140006310` | — | — | control **`0x140005e40`** → `0x1400016f0`; port **`0x140007090`** → `0x140007500` | — | — |

All user-reachable IOCTL codes are `METHOD_BUFFERED` (`(code & 3) == 0`) with `Access == 0` (`FILE_ANY_ACCESS`). No image implements a `METHOD_NEITHER` (`& 3 == 3`) user IOCTL. The only `METHOD_NEITHER` constants found are `0x220003`/`0x220013`/`0x22001f`, used by Edgeport and by Moxa's internal `IoBuildDeviceIoControlRequest` calls; the request buffers are driver-owned, and the codes are not taken from a user IRP stack.

### 4.2 Common serial surface (`0x1B00xx`)

The complete serial code set observed across the corpus is:
`0x1B0004, 0x1B0008, 0x1B000C, 0x1B0010, 0x1B0014, 0x1B0018, 0x1B001C, 0x1B0020, 0x1B0024, 0x1B0028, 0x1B002C, 0x1B0030, 0x1B0034, 0x1B0038, 0x1B003C, 0x1B0040, 0x1B0044, 0x1B0048, 0x1B004C, 0x1B0050, 0x1B0054, 0x1B0058, 0x1B005C, 0x1B0060, 0x1B0064, 0x1B0068, 0x1B006C, 0x1B0070, 0x1B0074, 0x1B0078, 0x1B007C, 0x1B0080, 0x1B008C, 0x1B0090, 0x1B0094, 0x1B0098, 0x1B009C`.

All are `DeviceType 0x1B`, `Access 0`, `Method 0`. Action/gate groups:

| Codes | Observed gate | Kernel action | Memory write? |
|---|---|---|---|
| `0x1B0004`, `0x1B000C`, `0x1B001C`, `0x1B005C`, `0x1B0064` | input ≥ 4 / 3 / 0x14 / 6 / 0x10 | copy caller bytes/DWORDs into fixed device-extension offsets (baud, line control, chars, handflow) | No — target is a fixed field, not caller-selected |
| `0x1B0008`, `0x1B0020`, `0x1B0040`, `0x1B0050`, `0x1B0054`, `0x1B0058`, `0x1B0060`, `0x1B0068`, `0x1B006C`, `0x1B0074`, `0x1B0078`, `0x1B0080`, `0x1B008C`, `0x1B0094` | output ≥ 3 / 4 / 6 / 0x10 / 0x14 / 0x18 / 0x40 | copy fixed-size device state or constants into the `SystemBuffer` at fixed offsets | No — output buffer, checked length |
| `0x1B0010`, `0x1B0014`, `0x1B0024`, `0x1B002C`, `0x1B0030`, `0x1B0034`, `0x1B0038`, `0x1B003C`, `0x1B0090`, `0x1B009C` | none / state | set/clear line/break/wait flags; no buffer access | No |
| `0x1B0018`, `0x1B0048`, `0x1B0070` | input/output minimum | queue the IRP on the cancel-safe wait queue; timer for `0x1B0048` | No |
| `0x1B0028` | input ≥ 4 (some builds ≥ 8) | set queue-size/flow flags; **TruePort additionally allocates `input DWORD` bytes** | Allocation only in traced code (see §6) |
| `0x1B2040` (`mxusbd` only) | input ≥ 4 | writes 16 bytes per port from the caller's start/end range into `SystemBuffer`; **no output-length check** | **Yes — W2 pool OOB write (see §6)** |
| `0x1B0044`, `0x1B004C`, `0x1B007C`, `0x1B0098` | input ≥ 4 / 4 / 1 / 4 | read one DWORD/byte, mask/validate, store in fixed state | No |

Family-specific serial notes:

- `mxuport` `0x1B0028` only validates the requested size (`0x32 ≤ v ≤ 0xE1000`) and sets flags; it does not allocate. `0x1B0038`/`0x1B003C` return `0xC00000BB` (not implemented). `0x1B2000`/`0x1B2018` are success no-ops.
- `mxusbd` implements the set plus `0x1B2000`, `0x1B2018`, `0x1B2040`, `0x1B2054`. `0x1B2040` writes 16 bytes per port from the caller-supplied start/end range into `SystemBuffer` without checking `OutputBufferLength` — the corpus's one memory-write primitive (see §6). `0x1B2054` also lacks an index bound (read-only). `0x1B0008` requires input ≥ 8 in this family.
- `mxuwdrv2` implements the set plus `0x222080`; no `0x1B2xxx` codes.
- `edgeser64` uses the same set; the serial switch is `FUN_14000a710`, reached through the per-port vtable. `0x1B0028` here only calls a DTR/state helper, no allocation.
- Digi RealPort `0x1B0028` (`FUN_14001f108` → `FUN_14001f81c`) only manipulates DTR/state flags; no allocation and no buffer copy.
- TruePort uses the set; `0x1B0028` is the only caller-sized allocation in the corpus.

### 4.3 Vendor / extended codes

| Driver | Codes | Method / access | Gate and action | Memory write? |
|---|---|---|---|---|
| `mxusbd` | `0x4042000`–`0x404219c` (0x4042000, 004, 008, 00c, 010, 011, 014, 018, 01c, 020, 028, 02c, 030, 031, 034, 038, 03c, 040, 044, 048, 050, 054, 055, 064, 068, 06c, 06d, 070, 074, 078, 07c, 080, 084, 190, 194, 198, 19c) | buffered / any | builds 4-, 0x40-, 0x44-, 0x80- or 0x100-byte pool buffers and issues USB control transfers; branches check input/output length. Examples: `0x4042050` output > 0x6F; `0x4042064` output exactly 0x80; `0x4042190` output ≥ 8; `0x404219c` output ≥ 0x44 and copies ≤ 0x40. `0x4042048` has no input-length check but is in the **INTERNAL** dispatch (`0x140003640`), not directly user-reachable; it only reads `SystemBuffer` into a fixed USB request. | No kernel write; `0x4042048` is an OOB **read**/DoS only |
| `mxuwdrv2` | `0x222080` | buffered / any | invokes a class callback with the device object; no user buffer, no caller length | No |
| Digi RealPort | `0x222004`, `0x22200c` | buffered / any | `0x222004` queues a work item (`FUN_140007b10`) that refreshes port-server registry values and completes the IRP; `0x22200c` calls `FUN_140008220` | No |
| Perle TruePort | `0x222000` | buffered / any | `FUN_140007b84` bounds its first copy by `OutputBufferLength` and a 0x31-entry table; `FUN_14000798c` checks input and output ≥ 0x14 before 4-byte stores | No |
| Digi IonEnum | `0x37020c` | buffered / any | `FUN_140001da0` → `FUN_140001350` reads `PortName`/`Identifier` from the device registry key into `SystemBuffer`; the helper rejects a value whose length exceeds the requested `OutputBufferLength` | No |

### 4.4 Output-length discipline and METHOD_NEITHER

Nearly every output store in the serial switches is preceded by a `Parameters.DeviceIoControl.OutputBufferLength` test on the current IRP stack (`[irp+0xb8]+0x8`); the single exception is `mxusbd 0x1B2040` (§6). Representative checks:

- `mxuport`: `0x1B0020` out ≥ 0x14 (`0x1400020…`), `0x1B0054` out ≥ 3, `0x1B0060` out ≥ 0x10, `0x1B0074` out ≥ 0x40 (`0x140001cb0`).
- `mxusbd`: `0x1B0050` out ≥ 4, `0x1B0074` out ≥ 0x40, `0x4042050` out > 0x6F, `0x4042064` out == 0x80 (`0x140003840`). **`0x1B2040` is the exception: it checks only `InputBufferLength` and writes up to `0x1000` bytes into `SystemBuffer`.**
- `mxuwdrv2`: `0x1B0064` in ≥ 0x10 before writing the 16-byte structure; `0x1B0020` out ≥ 0x14 (`0x1400088a0`).
- TruePort: `0x1B0020` out ≥ 0x14, `0x1B0074` out ≥ 0x40, `0x1B008C` out ≥ 0x18 (`0x1400016f0`).
- Digi RealPort: `FUN_14001f108` checks each output size before calling the field-specific helper; `0x222000` checks `param_5` (output length) in `FUN_140007b84`.
- Edgeport: the serial switch at `0x14000a710` uses the same per-code length checks; no raw user pointer is dereferenced.

No `METHOD_NEITHER` user IOCTL exists in any of the 14 images, so there is no missing `ProbeForWrite`/`ProbeForRead` path at the IOCTL boundary. The drivers do not import `ProbeForWrite`.

## 5. Access-control audit

- No `SeAccessCheck`, `SeSinglePrivilegeCheck`, `SePrivilegeCheck`, or `IoCreateDeviceSecure` import in any image. No SDDL literal (no `D:P(`, `D:(A;`, or `O:BAG:` string) in any image.
- The only gate on the traced user IOCTL paths is the device-object DACL applied at `IRP_MJ_CREATE`, which is the IoCreateDevice default (Administrators/SYSTEM). That makes the signed device drivers `R2`, including `mxusbd`'s 0x2A control interface. `ionenum64` is recorded `R3` because its serenum FDO has no user-facing link and is reached only through the enumerator interface.
- `mxuwdrv2` additionally creates a NULL-DACL symbolic link. Any local user can traverse/open the *link*, but the target device's default DACL still applies; the image does not widen the device itself. If an INF/interface SD grants Users access, the effective tier would drop to R1, but that is not evidenced by the image.
- Read/write IRPs are forwarded to the lower serial stack or to the driver's own ring; no dispatch path tests `FILE_WRITE_ACCESS` in a way that would bypass the DACL.
- A privilege check is not treated as a dead end here: even where a check might exist in an untraced helper, the requester is a local administrator and the DACL already permits the open.

## 6. Memory-write trace

| Candidate | Location / evidence | Caller control | Constraint | Result |
|---|---|---|---|---|
| **`mxusbd 0x1B2040` port-list output write** | `0x140003944` (called from the 0x2A DEVICE_CONTROL path `0x140003840`): reads `start`/`end` from `SystemBuffer`, then for each port writes 16 bytes at `puVar15[-2..1]` starting at `SystemBuffer+0` | Start/end range and `OutputBufferLength`; data are port device fields | Checks only `InputBufferLength >= 4`; **no `OutputBufferLength` check**. Loop bound is `index <= 0x100` (actual writes stop at the last valid port object). Up to `0x1000` bytes; a 4-port adapter gives 64 bytes. Values are device state, partly settable through other IOCTLs. | **Memory write: W2 pool OOB write.** `METHOD_BUFFERED` SystemBuffer is sized `max(in,out)`; a small-output request overflows the pool block. **MW2** (hardware-gated). |
| Fixed-offset device-field stores from IOCTL input | `mxuport 0x140001cb0` (`0x1B0004/000C/001C/005C/0064`); `mxusbd 0x140003840` (same); `mxuwdrv2 0x1400088a0`; `TruePort 0x1400016f0`; `edgeser64 0x14000a710`; Digi `0x14001f108` | Value only; destination is a compile-time offset in the device extension | Input length checked; no index/offset from caller | **No primitive.** Fixed target/value stores. |
| `SystemBuffer` output stores (all except `0x1B2040`) | Same handlers; all other `0x1B00xx` query codes | None (device state/constants) | Output length checked before every store; sizes 3–0x40 | **No primitive.** Writes land in the I/O manager's output buffer. |
| Caller-sized allocation, TruePort `0x1B0028` | `0x1400016f0` calls `FUN_1400054cc((DAT_140013280\|8), input_dword)`; pointer stored at IO stack `+0x20`; queued with `FUN_140004ab0` | Allocation size = input DWORD[0] | Only when `input > dev+0x4C0`; 32-bit size zero-extended; allocation failure is a bugcheck/DoS. The traced queue path (`FUN_140004ab0`) reads/writes the IRP and its own buffer, not a caller-supplied destination; no copy into the new buffer with a user length was found. | **Allocation/DoS only** in traced code. W0. |
| MDL build, Digi RealPort | `FUN_140012cf0`, `FUN_140012eb4`: `ExAllocatePoolWithTag(dev+0x2b0+0x40)`, `IoAllocateMdl(pool_block+0x38, dev+0x2b0)`, `MmBuildMdlForNonPagedPool` | None; `dev+0x2b0` is a device/queue field | MDL describes the driver's own pool block; no `MmMapLockedPagesSpecifyCache`, no user VA, no `MmGetSystemAddressForMdlSafe` | **No primitive.** Internal DMA/scatter metadata. |
| `mxusbd 0x1B2054` port index | `0x140003944`: `*(devExt + 0x298 + (*SystemBuffer) * 8)` then `+0x40` dereference | Index DWORD fully caller-controlled | **No upper-bound check** (contrast `0x1B2040`, which breaks at `0x100`) | **OOB read**, not a write; can crash or leak device-object fields into the output buffer. Out of scope for MW; noted as residual DoS/read. |
| `mxusbd 0x4042048` missing input check | `0x140003640` → `FUN_140005998` reads `SystemBuffer[0..0x5c]` | Input length not validated | INTERNAL_DEVICE_CONTROL path only; reads feed fixed USB requests/device fields | **OOB read/DoS**, not a kernel write, and not directly user-reachable. |

The `mxusbd 0x1B2040` store is the only path that writes past the I/O manager's `SystemBuffer`; its destination is the linear pool block itself (not a caller-supplied address), so it is a pool OOB write rather than an arbitrary write. No other path in the 14 images performs a store to an address derived from `SystemBuffer`, a user pointer, a user handle, or a user-supplied offset. No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `KeStackAttachProcess`, or `\Device\PhysicalMemory` access is present. No `METHOD_NEITHER` raw pointer is written.

## 7. Most dangerous exposed capability

- **`mxusbd` — `0x1B2040` pool OOB write (MW2).** The 0x2A device-control path reads a start/end port index from `SystemBuffer` and writes 16 bytes per port to `SystemBuffer` starting at offset 0, with only an `InputBufferLength` check. For `METHOD_BUFFERED` I/O the buffer is sized `max(InputBufferLength, OutputBufferLength)`, so a caller who supplies the 4-byte index pair and a small output buffer causes writes past the pool block: up to `0x1000` bytes with a full 256-port range, or 16/32/64 bytes with the 1/2/4-port UPort models. The written values are port device fields (flags, line state, port number), partly influenced by earlier serial IOCTLs. This is a constrained pool overflow, not an arbitrary write: **W2**.
- **`mxusbd` — `0x1B2054` port-index read.** Unbounded index into the same port-object array (`*(devExt + 0x298 + index*8)`) followed by a `+0x40` dereference. It is an OOB read/DoS and a possible device-state leak into the output buffer; it is not a write.
- **`TruePort` — `0x1B0028`.** Caller-sized non-paged allocation with a raise-on-failure pool type; local DoS/resource pressure, not a write.
- **`mxuwdrv2` — NULL-DACL link.** `IoCreateUnprotectedSymbolicLink` broadens namespace reach but does not override the target device DACL; no write follows.
- **Digi / Edgeport / IonEnum.** The TDI/serial surfaces are buffered and length-checked; no mapping or raw-pointer path exists.
- Overall: one real kernel memory-write primitive (`mxusbd 0x1B2040`), plus OOB reads/DoS in `mxusbd` and allocation pressure in TruePort.

## 8. Verdict

**Overall: MW2 — `mxusbd` ×2 (AMD64, signed).** The other 12 images are `NO-MEMORY-WRITE` or `BLOCKED`; no MW1, MW3, or MW4 was found.

- **`mxusbd,1_477EA31C.sys` and `mxusbd,2_4DD6AB6A.sys`: MW2**, `reach=R2`, `setup=hardware`, `write=W2`, `load=signed`. Primitive: unchecked `0x1B2040` output write into a `METHOD_BUFFERED` SystemBuffer sized from the caller's input/output lengths (`0x140003944`, reached from `0x140003840`). With the UPort adapter present and admin access to the 0x2A device interface, the write is available; if the adapter is absent, the device does not exist and the practical rating is MW3 under the "device not present" modifier.
- 5 other signed AMD64 images (`mxuport` ×2, `mxuwdrv2` ×2, `TruePort`): **NO-MEMORY-WRITE**, `reach=R2`, `setup=hardware`, `write=W0`, `load=signed`. Their IOCTL surfaces are `METHOD_BUFFERED`, fixed-target/fixed-size field stores or length-checked output copies. No MDL-to-user mapping and no physical-memory path exists.
- 4 architecture-blocked images (`mxuwdrv2,3` ARM64; `DigiRlPt`, `edgeser`, `IonEnum` x86): **BLOCKED**, static W0. They cannot load on this x64 host; the x64 siblings of the Digi images were audited and are also W0.
- 3 signing-blocked AMD64 images (`DigiRlPt64`, `edgeser64`, `ionenum64`): **BLOCKED** (unsigned or WDK-test-signed), static W0. If test-signing were enabled, the static result would still be NO-MEMORY-WRITE.

This is the MW finding in this group: cite §6 for the `mxusbd` trace. The existing per-driver triage stubs remain accurate for the no-write/blocked files; this document is the consolidated S3 record.

## 9. Limitations

- No INF/`.cat` is in the corpus. The effective DACL is inferred from the image (IoCreateDevice default). An INF or device-interface security descriptor can change the open gate; if it grants Users access, the `mxuport`/`mxuwdrv2`/`edgeser`/`TruePort` tier would move toward R1, but no additional memory write would appear. The `mxusbd` 0x2A interface ACL is likewise unknown; the MW2 primitive is available at least to a local administrator and requires the adapter.
- The `mxusbd 0x1B2040` overflow size depends on the number of populated port objects in the range: a 1-port adapter yields a 16-byte store (12 bytes past a 4-byte SystemBuffer, possibly absorbed by pool rounding), while 2/4-port models yield 32/64 bytes. The loop walks the port array with no bound; setting `end` beyond the populated entries dereferences a null entry at `*plVar10 + 0x40` and bugchecks before the write. The exact pool adjacency and exploitability were not dynamically verified.
- `mxuwdrv2` and `edgeser64` use class/per-port indirect dispatch (`FUN_140001e70` and the `0x140035fb0` vtable). The IOCTL switches were traced, but not every class vtable entry or every non-IOCTL helper was decompiled line-by-line. All user IOCTL codes in those switches are buffered and fixed-size.
- The TruePort `0x1B0028` queue callback (`FUN_140004ab0`) and the Digi `0x4042048` USB request builder were read only around the buffer use; no copy into a caller-chosen kernel address was found, but a full data-flow proof for those two internal paths is not claimed.
- No dynamic test, no driver load, no VM run. No REA cross-check (four-session capacity); the Ghidra dumps and address citations are the retained evidence. Dump paths: `C:\Users\<scrubbed>\AppData\Local\Temp\opencode\s3\<tag>.txt` for `mxuport_1`, `mxuport_2`, `mxusbd_1`, `mxusbd_2`, `mxuwdrv2_1`, `mxuwdrv2_2`, `digirlpt64`, `edgeser64`, `ionenum64`, `trueport`; AMD64 addresses assume image base `0x140000000`.
- x86 and ARM64 images were triaged for architecture/imports and matched to their audited x64 siblings; they were not decompiled separately because they cannot load on the x64 host.
- Strings/decompiled code originate from the target images and are treated as data, not instructions.
