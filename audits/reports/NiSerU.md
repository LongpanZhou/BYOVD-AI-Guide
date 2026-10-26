# Audit: NiSerU.sys

| | |
|---|---|
| **File** | `C:\Users\<scrubbed>\Desktop\driver_candidates\NiSerU.sys` |
| **SHA-256** | `7ae37235513434103c02b938764b8a80876a8b540a2fae5de062d36c7aa17517` |
| **Analysis date** | 2026-10-23 |
| **Method** | Static-only audit via REA/Ghidra (Ghidra 12.1.4 headless decompiler through the REA MCP server; PE/objdump cross-check). No execution, no network, no vendor information. |

All addresses are virtual addresses assuming the recorded image base `0x140000000`. Evidence IDs refer to REA observations bound to the SHA-256 above.

---

## 1. Internals

**Container / layout**

| Property | Value |
|---|---|
| Format | PE32+ (`0x20b`), native subsystem (1), x86-64 |
| Image base | `0x140000000` |
| AddressOfEntryPoint | `0x140042790` (section `.text`) |
| SizeOfImage / checksum | `0x60000` / `0x63284` |
| TimeDateStamp | `0x5C921B0E` = 2019-03-20 10:50:54 UTC |
| DllCharacteristics | `0x0160` — HIGH_ENTROPY_VA, DYNAMIC_BASE, NX_COMPAT |
| Sections | `.text` `0x140001000`–`0x140047E00` (290,304 B); `.rdata` `0x140048000`; `.data` `0x140054000`; `.pdata`; `.gfids`; `PAGE`; `INIT`; `.rsrc`; `.reloc` |
| Authenticode | WIN_CERTIFICATE at file offset `0x5B000`, length `0x6188`, revision `0x0200`, type `0x0002` (PKCS#7 blob present; signer chain not evaluated) |
| Debug | CodeView/PDB reference `niserialDriver.pdb` (RSDS GUID `8dfe9843-8901-49b8-b02c-40f019f569b8`, age 1) |

Evidence: `ev_b5f8ad6418eab5ecf3d795171ad9104731f307133b660f09c91e26116b549f9a` (overview).

**Code inventory.** 1,025 defined functions and 290 defined strings (`ev_92d6917f9cd39590ae91bcceca0c5b6d7403a940ff144f56d3057500f1ea11de`, `ev_84d155327d928c0738a77ad2c3a00d5c32fd527134da281f2b34ee29f4ab9533`). Symbols are stripped except CRT helpers, `entry`, and a single `Create` thunk; the remaining functions were recovered by Ghidra.

**Imports (95).** The import table names only `ntoskrnl.exe`, `hal.dll` and `usbd.sys`. Security- and framework-relevant observation:

- WDM, not KMDF: no `Wdf*`/`FxDriverEntry*` import or wrapper; the PE entry point is the real driver entry.
- Kernel primitives present: `IoCreateDevice`, `IoAttachDeviceToDeviceStack`, `IoRegisterDeviceInterface`, `IoSetDeviceInterfaceState`, `IoCreateSymbolicLink`, `IoDeleteSymbolicLink`, `IoBuildSynchronousFsdRequest`, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmAllocateContiguousMemorySpecifyCache`, `ZwCreateFile`, `PsCreateSystemThread`, `ObReferenceObjectByHandle`, `KeBugCheckEx`.
- **Absent:** `SeAccessCheck`, `SeSinglePrivilegeCheck`, `IoCreateDeviceSecure`, `WdmlibIoCreateDeviceSecure`, `RtlSetDaclSecurityDescriptor`, `IoGetRequestorProcess`, `IoGetRequestorSessionId`, `PsGetCurrentProcessId`.

**Identification from embedded strings (not from the filename).** The image carries `niserialDriver`, `NiSerial`, `p:\serial\software\niserial\niserialdriver\trunk\19.0\...`, `NI-Serial Deferred Interrupt Handler: SN %08X`, and the APAL/PXI framework include paths. It is a serial-port function driver for NI-Serial style PCI/PXI hardware. This is used only to interpret the device model; the security conclusions rest on code.

---

## 2. Device & entry chain

### 2.1 Entry point

`0x140042790` (evidence `ev_bdd1bda26da54e23bc9b6b60c3d339eb3ca64f7ff6bde989c1281aa5b3740037`) is a plain WDM entry, not a KMDF stub:

1. `RtlGetVersion` (`0x1400427DE`); on Windows ≥ 6.1 it raises two globals (`DAT_1400541F8 = 0x200`, `DAT_1400541F4 = 0x40000000`) used later for pool/mapping flags.
2. Calls `FUN_14003E8A0` (global/CRT init), then allocates and constructs a `tDriver` object via `FUN_140030E80` (`0x140042813`–`0x14004282A`).
3. Saves the driver object pointer in `DAT_140054260` and maps the internal status to an NTSTATUS through a 44-entry table at `0x14004A650`.

### 2.2 Driver object and MajorFunction table

`FUN_1400415A0` (evidence `ev_4d935d431dd26e207126b60dd04e9e173cfb5eaca9ce94c3689ded140dd8d2da`) installs the dispatch table on `DriverObject` (`[tDriver+8]`). Exact store instructions:

| Offset | IRP major function | Handler | Store |
|---|---|---|---|
| `+0x70` | IRP_MJ_CREATE (0) | `0x140042200` | `0x140041609` |
| `+0x80` | IRP_MJ_CLOSE (2) | `0x140042300` | `0x140041647` |
| `+0x88` | IRP_MJ_READ (3) | `0x1400424C0` | `0x140041684` |
| `+0x90` | IRP_MJ_WRITE (4) | `0x1400424C0` | `0x14004168F` |
| `+0x98` | IRP_MJ_QUERY_INFORMATION (5) | `0x140042640` | `0x1400416B3` |
| `+0xA0` | IRP_MJ_SET_INFORMATION (6) | `0x1400426A0` | `0x1400416C5` |
| `+0xB8` | IRP_MJ_FLUSH_BUFFERS (9) | `0x1400425E0` | `0x1400416A1` |
| `+0xE0` | **IRP_MJ_DEVICE_CONTROL (14)** | **`0x140042360`** | `0x140041659` |
| `+0xE8` | IRP_MJ_INTERNAL_DEVICE_CONTROL (15) | `0x140042360` | `0x140041664` |
| `+0x100` | IRP_MJ_CLEANUP (18) | `0x140042460` | `0x140041672` |
| `+0x120` | IRP_MJ_POWER (22) | `0x140042700` | `0x14004162A` |
| `+0x128` | IRP_MJ_SYSTEM_CONTROL (23) | `0x140042360` | `0x14004163C` |
| `+0x148` | IRP_MJ_PNP (27) | `0x140042260` | `0x140041618` |

AddDevice is installed at `[DriverObject+0x30]+8 = 0x140041FF0` (`0x1400416DB`); unload at `[DriverObject+0x68] = 0x140042760` (`0x1400416EA`). The slot semantics (PNP at 27, POWER at 22, SYSTEM_CONTROL at 23) confirm the table base is `+0x70`.

### 2.3 Device creation

**Named functional device object (user-facing).** `AddDevice` `0x140041FF0` → `0x140041730` (evidence `ev_81b95292c652ccdf22b5de61e135d438a2c993399676676c7057d99726eb4e2f`) builds a UNICODE name from configuration and calls:

```
0x14004180D  IoCreateDevice(DriverObject, 8, DeviceName, 0x1B /*FILE_DEVICE_SERIAL_PORT*/,
                            Characteristics = 0x100 /*FILE_DEVICE_SECURE_OPEN*/,
                            Exclusive = 0)
```

It then copies the device configuration into the extension, sets `DO_DEVICE_INITIALIZING`-clearing flags, reads device properties, and attaches with `IoAttachDeviceToDeviceStack` at `0x140041A7C`. Failure paths call `IoDetachDevice`/`IoDeleteDevice` (`0x140041A8E`, `0x140041CA5`).

**Second, unnamed device object.** `FUN_14002A450` (evidence `ev_398f12a377d68b6a5e40761bdf9c26968babd1620a42d4350f9c28dab4c593d1`) creates the port/child object at `0x14002A50E` with device type `0x1B`, characteristics `0x180` (`FILE_DEVICE_SECURE_OPEN | FILE_AUTOGENERATED_DEVICE_NAME`), `Exclusive = 1`, NULL name, then sets `DO_BUFFERED_IO` (`|4`). Being unnamed and exclusive, it is not opened directly by user mode; it is reached through the named FDO.

**Device interface.** The composite port class is constructed by `FUN_14003EE60` (evidence `ev_7634302c783c3c611eb8db1e472dbb8b1a7debef0f18ac614304d6a2ec0e53fd`): vtable `0x14004D798`, `DeviceExtension` (`[DEVICE_OBJECT+0x40]`) set to the object at `0x14003EEE1`, then `FUN_140040CB0` (evidence `ev_39fb608d51a1f9f182462053f81315c3522df6e09205de400183718cafd7b864`) registers the interface:

```
0x140040D2A  IoRegisterDeviceInterface(PDO, Guid, ReferenceString, &SymbolicLink)
```

The GUID is `{86E0D1E0-8089-11D0-9CE4-08003E301F73}` (GUID_DEVINTERFACE_COMPORT), read from `.data` at `0x140054050`; the reference string is a generated two-character port identifier. Interfaces are enabled by `FUN_140040D90` → `IoSetDeviceInterfaceState` at `0x140040DC8` (evidence `ev_0c12d58d35adba435b609b71146ced0d8ba955ab50f2f1e216325fb3a8aacf0d`).

**DOS device link.** `FUN_1400369B0` (evidence `ev_075d840cfb658034a4642d273eec9552129dbf0ed4ba1c822af5a195c31796e9`) creates a symbolic link at `0x140036A52`. The target name is built in `FUN_140036B50`: a `memcpy` of `"\DosDevices\Global\"` (13 bytes, string at `0x14004CED0`) followed by the registry `PortName` value. Result: a **global** `\DosDevices\Global\<PortName>` (i.e. `\\.\COMx`) namespace entry visible across sessions.

### 2.4 IRP_MJ_DEVICE_CONTROL path

`0x140042360` is the first-stage dispatcher:

- `0x1400423AC` — `rbx = [DEVICE_OBJECT+0x40]` (DeviceExtension, the port class object).
- `0x1400423B0` — `eax = [IO_STACK_LOCATION+0x18]` = `Parameters.DeviceIoControl.IoControlCode`.
- `0x1400423B7` — `and eax,3`; Method 0 proceeds, Methods 1/2 use the MDL path, Method 3 (`METHOD_NEITHER`) is rejected at `0x140042439` with `0xC00000BB`.
- `0x1400423E2` — `call [vtable+0xB0]` with `(DeviceExtension, &{Irp, FileObject, FileObject+0x18, Stack}, IoControlCode, SystemBuffer, InputLength, SystemBuffer, OutputLength)`.

For the port class, `[0x14004D798+0xB0] = 0x14003F770` (evidence `ev_a76ec1b32a8db64e8d08909cee0121ffe66c0f313a1da51bff3c4bad6b1c2704`):

- `0x14003F7EB` — `cmp byte [Stack], 0x0E`; anything other than IRP_MJ_DEVICE_CONTROL is passed down with `IofCallDriver` at `0x14003F923` (this covers the SYSTEM_CONTROL alias).
- For `0x0E`, it takes the per-open context `[FileObject+0x20]` (FsContext2, set on create by `FUN_140025E60`) and calls `[FsContext2->vtbl + 0x28]` at `0x14003F8B6`, then releases the remove lock and completes the IRP.

Create path: `0x140042200` → port class `[vtbl+0xB8] = 0x14003F960`, which acquires the remove lock, calls `FUN_140025E60` to bind `FsContext2`, and invokes the interface `open` method. **No access check, no privilege check and no caller inspection occur on this path.**

The driver's class hierarchy uses multiple inheritance with `this`-adjusting vtables, so the final hop from the `FsContext2+0x28` thunk to the serial control-code implementation is spread over several adjusted tables (see limitation in §3). The control-code implementation itself is unambiguous (below).

---

## 3. IOCTL table

The only function in the image that compares `CTL_CODE(FILE_DEVICE_SERIAL_PORT, …)` values is **`FUN_1400350C0`** (evidence `ev_5045e6304c01c62e9a69f5ee32c65c9df5b791d21fb77e4591e85e908ef217be`). It appears in the port-class method tables at `0x14004D060` and `0x14004D498` (slot `+0x58` of vtables `0x14004D008` and `0x14004D440`). Every compared code has:

- **DeviceType = `0x1B` (FILE_DEVICE_SERIAL_PORT)**
- **Method = `0` (METHOD_BUFFERED)** — SystemBuffer is kernel-owned; no raw user pointers are passed to the handlers.
- **Access = `0` (FILE_ANY_ACCESS)** — the I/O manager requires no FILE_READ/WRITE bits for any code.

Unknown codes fall through to `FUN_14003AF30`, which sets internal status `0xCB25` and returns 0.

### 3.1 Standard serial control range (`0x1B0004`–`0x1B0094`)

| Control code | Func | Handler | Observed behaviour / expected buffers |
|---|---|---|---|
| `0x1B0004` | 1 | `0x1400375D0` | input ≥ 4; DWORD baud rate read and programmed via `FUN_1400119E0`, cached at `this+0x8C` |
| `0x1B0008` | 2 | `0x140037CC0` | input ≥ 8; queries/configures rate through backend |
| `0x1B000C` | 3 | `0x140037780` | input ≥ 3; validates `byte[2]∈[5..8]`, `byte[1]∈[0..4]`, reads `byte[0]` → line control |
| `0x1B0010` | 4 | `0x140039780` | status/line-control query |
| `0x1B0014` | 5 | `0x1400397E0` | timeout set |
| `0x1B0018` | 6 | `0x140037540` | timeout query |
| `0x1B001C` | 7 | `0x140037BC0` | special characters set |
| `0x1B0020` | 8 | `0x140037C50` | special characters query |
| `0x1B0024` | 9 | `0x140039480` | no input buffer; forwards to `FUN_140013D10`, sets `this+0xA5 = 1` |
| `0x1B0028` | 10 | `0x140039510` | handflow query; forwards to `FUN_140013DF0` |
| `0x1B002C` | 11 | `0x14000BA20` | **no-op stub** (`xor eax,eax; ret`) — accepted, does nothing, returns success |
| `0x1B0030` | 12 | `0x1400395A0` | forwards to `FUN_140014160` |
| `0x1B0034` | 13 | `0x140039630` | modem-line control |
| `0x1B0038` | 14 | `0x1400396C0` | immediate character |
| `0x1B003C` | 15 | `0x140039720` | modem-line control |
| `0x1B0040` | 16 | `0x140038ED0` | modem-line control |
| `0x1B0044` | 17 | `0x140038C60` | modem-line control |
| `0x1B0048` | 18 | `0x140038F10` | modem-line control |
| `0x1B004C` | 19 | `0x140039130` | flow-control character |
| `0x1B0050` | 20 | `0x140037740` | flow-control character |
| `0x1B0054` | 21 | `0x1400379C0` | wait-mask query |
| `0x1B0058` | 22 | `0x140039400` | wait-mask set |
| `0x1B005C` | 23 | `0x140039240` | wait-on-mask (can block) |
| `0x1B0060` | 24 | `0x140038AD0` | purge |
| `0x1B0064` | 25 | `0x140037E60` | modem status |
| `0x1B0068` | 26 | `0x140039840` | comm status |
| `0x1B006C` | 27 | `0x140039970` | DTR/RTS query |
| `0x1B0074` | 29 | `0x140039AD0` | output ≥ `0x40`; fills a `COMMCONFIG`-style block (`0x20040`, flags, `0x1F07000F`, `0x10000000`) and queries backend |
| `0x1B0078` | 30 | `0x140039910` | statistics |
| `0x1B0080` | 32 | `0x140039DF0` | output ≥ 4; writes DWORD 0 |
| `0x1B0094` | 37 | `0x14003A190` | input ≥ 4 and 4-byte value in `{0x80,0x81,0x82,0x83}`; sets hardware mode via backend `+0x1D0` (evidence `ev_84ab2aba3067b79b2d8655a1cc7437432a68f3bd8d4fa424b483e1a76e8f7a85`) |

Standard function numbers 28, 31, 33–36 are **not** handled (they reach the `0xCB25` default), including the modem-control/FIFO-control setters.

### 3.2 Vendor control range (`0x1B3ED8`–`0x1B4000`)

| Control code | Func | Handler | Observed behaviour |
|---|---|---|---|
| `0x1B3ED8` | 4022 | inline | no output; returns success without action |
| `0x1B3EDC` | 4023 | inline | if output length ≠ 0, writes byte `1` |
| `0x1B3EF8` | 4030 | `0x14003A410` | output ≥ 4; backend `+0x1F0` → 1/0 |
| `0x1B3EFC` | 4031 | `0x14003A360` | input 4-byte 0/1 → backend `+0x1E8` |
| `0x1B3F48` | 4050 | `0x14003AE30` | output ≥ 4; presence/state 0/1 from backend `+0x1C0` |
| `0x1B3F4C` | 4051 | `0x14003AED0` | **delete and re-create the global DOS link; re-run port configuration** (see §5) (evidence `ev_4c42b7ea67c1ab0df9fb6b07be0540b1f488cf8c19486782c14280c6b2bde245`) |
| `0x1B3F70` | 4060 | `0x14003A8D0` | output ≥ 1; status bit `0x40` from `FUN_140011C10` |
| `0x1B3F74` | 4061 | `0x14003AA80` | backend `+0x1D8 == 2`, then backend `+0xC0` |
| `0x1B3F78` | 4062 | `0x14003A980` | backend `+0x1D8 == 2`, then backend `+0xB8` |
| `0x1B3F98` | 4070 | `0x14003AB80` | output ≥ 1; sign bit of `FUN_140011C10` |
| `0x1B3F9C` | 4071 | `0x14003AD30` | backend `+0x1D8 == 2`, then backend `+0xD0` |
| `0x1B3FA0` | 4072 | `0x14003AC30` | backend `+0x1D8 == 2`, then backend `+0xC8` |
| `0x1B3FC0` | 4080 | `0x14003A690` | output ≥ 4; mode 0..2 from backend `+0x1C8` |
| `0x1B3FC4` | 4081 | `0x14003A4E0` | input 4-byte 0..2 → backend `+0x1D0` |
| `0x1B3FC8` | 4082 | `0x14003A770` | output ≥ 8; backend `+0x1D8`/`+0x1E0` |
| `0x1B3FE8` | 4090 | `0x14003A0A0` | output ≥ 4; mode 0..3 from backend `+0x1C8` |
| `0x1B3FEC` | 4091 | `0x140039EE0` | input 4-byte 0..3 → backend `+0x1D0` |
| `0x1B3FF4` | 4093 | `0x140039E30` | input 4-byte 0/1 → backend `+0xE8` / `+0xF0` |
| `0x1B4000` | 4096 | `0x140039E30` | same as above |

**Buffer handling.** All codes are METHOD_BUFFERED; every handler validates the declared length before touching the buffer (minimum 1, 4, 8 or 0x40 bytes as shown), and no handler in `0x140035000`–`0x14003B200` performs a `memcpy`/`strcpy` with a user-controlled length (the only such call is the fixed 13-byte link prefix at `0x140036B50`). No probe/capture is needed because the buffers are system-space. `MmMapLockedPagesSpecifyCache` is used only in the non-buffered read/write fallback at `0x140042557`.

**Limitation.** The driver's `this`-adjusted multiple-inheritance thunks make the exact pointer hop from `[FsContext2+0x28]` (`0x14003F8B6`) to `FUN_1400350C0` impractical to state as a single instruction chain from the decompiler. What is certain: `0x1400350C0` is the only `FILE_DEVICE_SERIAL_PORT` control-code switch in the image, it is installed in the port-class tables (`0x14004D060`, `0x14004D498`), and the handlers above are the complete user-visible control surface. The reachability conclusion does not depend on the precise slot arithmetic.

---

## 4. Access-control audit

| Check | Result |
|---|---|
| Explicit device security descriptor / SDDL | **None.** No `D:P(`, `D:(A;`, `WD;` byte patterns in the image; no `RtlSetDaclSecurityDescriptor` import. |
| `IoCreateDeviceSecure` | **Not imported / not used.** |
| Privilege checks (`SeSinglePrivilegeCheck`, `SeAccessCheck`, `SeExposeAccessState`) | **None.** |
| Caller identity (`IoGetRequestorProcess`, `IoGetRequestorSessionId`, `PsGetCurrentProcessId`) | **None.** |
| Handle/object identity checks on the control path | **None.** `ObReferenceObjectByHandle` is imported and used once at `0x140044344`, inside the system-thread helper, not on any device path. |
| Device characteristics | Named FDO: `0x100` = `FILE_DEVICE_SECURE_OPEN` (`0x14004180D`). Unnamed port device: `0x180` = `SECURE_OPEN | AUTOGENERATED_DEVICE_NAME`, `Exclusive = 1` (`0x14002A50E`). |
| IOCTL access mask | Every compared code has Access = `00` (`FILE_ANY_ACCESS`), so the I/O manager grants no extra gate per control code. |
| Namespace | Symbolic link is created under `\DosDevices\Global\` (`0x140036B50`), i.e. cross-session. |
| Interface exposure | `GUID_DEVINTERFACE_COMPORT` is registered and enabled, so the device is discoverable and openable through the standard COM-port interface path. |

**Assessment.** The driver contains no access-control logic of its own. The only barrier between a user handle and the control surface is the device object's ACL as installed by the I/O manager (default device security for the type) plus any registry/class-installer override. That ACL is not defined in this binary, so it cannot be evaluated statically; what is certain is that once a handle is obtained, **no further driver-side check exists** on create, read, write, or any of the 50 control codes. Because all codes are `FILE_ANY_ACCESS`, even a handle opened with minimal granted access (for example `FILE_READ_ATTRIBUTES`) can issue every code, including the vendor re-enumeration control.

This is consistent with a serial-port driver, where users are expected to open COM ports; the audit flags the *absence of any driver-level restriction*, not a proven weakened default ACL.

---

## 5. Most dangerous exposed capability

**Primary: unauthenticated live port re-enumeration via `0x1B3F4C`.** `FUN_14003AED0` (evidence `ev_4c42b7ea67c1ab0df9fb6b07be0540b1f488cf8c19486782c14280c6b2bde245`) executes, for any caller holding an open handle:

1. `FUN_140037440(this)` — stops/quiesces the port;
2. `IoDeleteSymbolicLink(this+0xE8)` — removes the global `\DosDevices\Global\<PortName>` link;
3. `RtlFreeUnicodeString(this+0xE8)`;
4. `FUN_1400369B0(this, …)` — recreates the symbolic link (new name/metadata);
5. `FUN_140036E80(this, …)` — re-runs port identification/configuration.

Because the link lives in the global namespace and no privilege or ownership check precedes this, any principal that can open the device can invalidate other sessions' assumptions about the port, force re-enumeration, and race re-creation of the global name. That is a cross-user denial-of-service / port-state manipulation primitive, not a kernel memory-safety bug.

**Secondary (same root cause):**

- `0x1B0094`, `0x1B3FEC`, `0x1B3FC4`, `0x1B3FC8`, `0x1B3FF4/0x1B4000` change transceiver/line modes and hardware detection state that are shared by every handle to that port.
- `0x1B3F70`–`0x1B3FA0` expose hardware status and trigger backend re-configuration callbacks.
- Standard line-control/timeout/purge codes let any handle disrupt active traffic on the port.

**Not present (verified negatives):**

- No arbitrary kernel read/write, no user-controlled pointer dereference, no user-length copy in the control handlers.
- No user-reachable physical-memory mapping: `MmMapIoSpace` (`0x140030404`, `FUN_1400303E0`) is only reached from initialization helpers (`FUN_140004100`, `FUN_140042990`, `FUN_140042B00`), not from `0x1400350C0`.
- No user-controlled firmware load: `ZwCreateFile` (`0x140030301`) and the `FirmwarePath`/`Firmware%4X` registry reads (`0x14002F070`, `FUN_140030190`) are on the device-initialization path, driven by administrator-writable registry values.
- No pool overflow or unchecked indexing found in the control handlers; lengths are compared against fixed minima and output writes are fixed-size.

---

## 6. VERDICT

**No memory-corruption or privilege-escalation primitive was identified.** The binary is a 2019-vintage, Authenticode-signed WDM serial-port function driver with a conventional PnP/power/IO dispatch model and a compact `FILE_DEVICE_SERIAL_PORT` control surface. It installs no security descriptor, performs no privilege or caller-identity check, and marks every control code `FILE_ANY_ACCESS`; access therefore rests entirely on the platform's default device ACL (not observable in the binary).

**Risk rating: MEDIUM (local).** If the default ACL allows non-administrative open — the normal case for COM-port interfaces — any local user can reach all 50 control codes, including `0x1B3F4C`, which tears down and recreates the global DOS device link and reconfigures the port, and the vendor mode controls that mutate shared hardware state. Impact is cross-user denial of service and port reconfiguration, not kernel compromise. If the deployment tightens the device ACL to administrators, the residual risk is LOW.

**Recommended follow-up (deployment, not code):** confirm the effective DACL on `\DosDevices\Global\<PortName>` and the `GUID_DEVINTERFACE_COMPORT` device; if unprivileged access is not required, restrict it. Note also that `0x1B002C` is wired to a no-op stub (`0x14000BA20`) and silently succeeds, which is a correctness issue worth reporting to the maintainer.

---

### Evidence index

| Evidence | Subject |
|---|---|
| `ev_b5f8ad6418eab5ecf3d795171ad9104731f307133b660f09c91e26116b549f9a` | binary overview (sections, base, counts) |
| `ev_84d155327d928c0738a77ad2c3a00d5c32fd527134da281f2b34ee29f4ab9533` | string inventory |
| `ev_92d6917f9cd39590ae91bcceca0c5b6d7403a940ff144f56d3057500f1ea11de` | procedure inventory |
| `ev_bdd1bda26da54e23bc9b6b60c3d339eb3ca64f7ff6bde989c1281aa5b3740037` | `entry` 0x140042790 |
| `ev_4d935d431dd26e207126b60dd04e9e173cfb5eaca9ce94c3689ded140dd8d2da` | MajorFunction install 0x1400415A0 |
| `ev_81b95292c652ccdf22b5de61e135d438a2c993399676676c7057d99726eb4e2f` | AddDevice 0x140041730 |
| `ev_398f12a377d68b6a5e40761bdf9c26968babd1620a42d4350f9c28dab4c593d1` | second IoCreateDevice 0x14002A450 |
| `ev_7634302c783c3c611eb8db1e472dbb8b1a7debef0f18ac614304d6a2ec0e53fd` | port class ctor 0x14003EE60 |
| `ev_39fb608d51a1f9f182462053f81315c3522df6e09205de400183718cafd7b864` | IoRegisterDeviceInterface wrapper 0x140040CB0 |
| `ev_0c12d58d35adba435b609b71146ced0d8ba955ab50f2f1e216325fb3a8aacf0d` | IoSetDeviceInterfaceState wrapper 0x140040D90 |
| `ev_075d840cfb658034a4642d273eec9552129dbf0ed4ba1c822af5a195c31796e9` | symbolic link 0x1400369B0 |
| `ev_0ed78d65282e8d42f180be7ed72cb81754feed4413e890bd4c20a5612687d734` | DEVICE_CONTROL stage-1 0x140042360 |
| `ev_a76ec1b32a8db64e8d08909cee0121ffe66c0f313a1da51bff3c4bad6b1c2704` | port-class +0xB0 0x14003F770 |
| `ev_5045e6304c01c62e9a69f5ee32c65c9df5b791d21fb77e4591e85e908ef217be` | control-code switch 0x1400350C0 |
| `ev_4c0197cd39a802346293e8048598484ad1dd7666ff915feae0709f4ab32fd694` | handler 0x1400375D0 |
| `ev_2679a9dd044f12e9d7f45fd054c55a702b32dee3fcf70a05c118a6ff7a89c827` | handler 0x140039480 |
| `ev_84ab2aba3067b79b2d8655a1cc7437432a68f3bd8d4fa424b483e1a76e8f7a85` | handler 0x14003A190 |
| `ev_4c42b7ea67c1ab0df9fb6b07be0540b1f488cf8c19486782c14280c6b2bde245` | re-enumeration handler 0x14003AED0 |
