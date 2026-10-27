# Audit: iDisplay (WDDM display + display filter) and Prolific PL2303 serial - nine builds

| Field | Value |
|---|---|
| File(s) | `drivers/idisplay,1_FA82D229.sys`, `drivers/idisplay,2_287771E7.sys`, `drivers/idisplay,3_36C72B1E.sys`, `drivers/idisplay,4_3D882F1C.sys`, `drivers/idisplayfilter,1_8A87907A.sys`, `drivers/idisplayfilter,2_1993A861.sys`, `drivers/plser_063783A4.sys`, `drivers/plser64_61A861A2.sys`, `drivers/plser64_1_709ACAA8.sys` |
| SHA-256(s) | see per-file table (section 0) |
| Analysis date | 2026-10-25 |
| Method | Static-only, offline: SHA-256 verify, PE/section diff, local **Ghidra 12.1.4 headless** (decompiler) + `objdump` disassembly cross-checks. REA **not** used: the shared bridge is at capacity (`audits/STATUS.md` section In flight - "Agents 5-6 are explicitly offline"), and three other REA audits are active. No load, install, service, registry write, or execution. |
| Reach tier | **R1** for object open on all three device families (Prolific `\Device\ProlificSerialN`: Everyone `GRGW`; iDisplay `\Device\idisplaywddm`: Everyone `GR` = read-only). **R3** for device existence (Prolific hardware / iDisplay devnode+composition). |
| Setup required | **hardware** (Prolific PL2303 DUT) ; **devnode** (iDisplay filter attaches to the PCI root complex; iDisplay display miniport registers with `\Device\DxgKrnl`) |
| Write quality | **W0** |
| Verdict | **NO-MEMORY-WRITE** (all nine files) |
| HW-only | **no** - no MSR / port I/O / PCI-config / SMBus / fixed-window MMIO write path was found to rate |

## 0 Per-file summary

| # | File | Arch | Build (PE ts) | Role | Exposed object | Effective open rights | IOCTL memory-write path | W | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `idisplay,1_FA82D229.sys` | i386 | 2017-06-30 | WDDM display-only miniport | **none** (no device object); `\BaseNamedObjects\iDisplayController` section, **NULL DACL** | section: Everyone full | none - no IRP dispatch exists | W0 | **NO-MEMORY-WRITE** |
| 2 | `idisplay,2_287771E7.sys` | i386 | 2017-06-30 | same as #1 (all sections byte-identical) | same | same | same | W0 | **NO-MEMORY-WRITE** |
| 3 | `idisplay,3_36C72B1E.sys` | x86-64 | 2017-06-30 | WDDM display-only miniport | **none**; same section | section: Everyone full | none - no IRP dispatch exists | W0 | **NO-MEMORY-WRITE** |
| 4 | `idisplay,4_3D882F1C.sys` | x86-64 | 2017-06-30 | same as #3 (`.text` identical) | same | same | same | W0 | **NO-MEMORY-WRITE** |
| 5 | `idisplayfilter,1_8A87907A.sys` | i386 | 2014-01-17 | WDM filter on PCI root complex | `\Device\idisplaywddm` | **Everyone `GR` (read-only)**; BA `GRGWGX` | none - `IRP_MJ_DEVICE_CONTROL` is a NULL-lower pass-through | W0 | **NO-MEMORY-WRITE** |
| 6 | `idisplayfilter,2_1993A861.sys` | x86-64 | 2017-06-30 | same filter, x64 | `\Device\idisplaywddm` | **Everyone `GR` (read-only)**; BA `GRGWGX` | none - same | W0 | **NO-MEMORY-WRITE** |
| 7 | `plser_063783A4.sys` | i386 | 2025-11-03 | KMDF PL2303 serial | `\Device\ProlificSerialN` (+ COM symlink) | **Everyone `GRGW` (read+write)** | 240 IOCTLs, **all METHOD_BUFFERED / FILE_ANY_ACCESS**, WDF system buffers only | W0 | **NO-MEMORY-WRITE** |
| 8 | `plser64_61A861A2.sys` | x86-64 | 2025-11-03 | same, x64 | same | same | same | W0 | **NO-MEMORY-WRITE** |
| 9 | `plser64_1_709ACAA8.sys` | x86-64 | 2025-11-06 | same, x64 (newest) | same | same | same | W0 | **NO-MEMORY-WRITE** |

SHA-256:

```
idisplay,1_FA82D229.sys         FA82D229E8AB478198C1415B3E77F0A303EC27B9076652F1531DE44094014BBB
idisplay,2_287771E7.sys         287771E78834AF54A5DF10D071AE0B49E1E7641B98BBF9A0BD510E3D88256451
idisplay,3_36C72B1E.sys         36C72B1EFEE5ABB01B458868F338BD90B0D20AE43E5FD432A7B6489933B6FF69
idisplay,4_3D882F1C.sys         3D882F1C79CAB11AE66C70723A7AC1D309E7281A82575420D170B7A3C2A380D3
idisplayfilter,1_8A87907A.sys   8A87907A72837F014417B6545DFF61EFF4A079C65F51918D5064F8C66CD6C191
idisplayfilter,2_1993A861.sys   1993A86196AC2F9E5C58F3E4324A9D0BBC84F18F446887739E33B36389985187
plser_063783A4.sys              063783A43ACDA804DD2C6CE17C3BD0A922DC7148E054B4A7783105A4D1A150D7
plser64_61A861A2.sys            61A861A20F8FF1815EE7CACBEF1FE5DB443B4421671E01F4B48E7E90334906DF
plser64_1_709ACAA8.sys          709ACAA8F806EFA4DFDC0479B3761E5889880C05273901D0B0C7AC918509F7DD
```

All nine carry an embedded `WIN_CERTIFICATE` (PE security directory, 0x1C18-0x4F60 bytes). None of the nine hashes is in
`indexes/dedupe/known_bad_hashes.txt`. Loadability: signed; no blocklist hit; no missing-component flag.

## 1 Internals

### 1.1 iDisplay display miniports (`idisplay,1`-`idisplay,4`)

* PE32 (1/2) and PE32+ (3/4), `Subsystem = NATIVE`, 32-40 KB, PDB
  `C:\Users\Admin\Documents\idisplay-win\install\Driver\WDDM\{Win32|x64}\idisplay.pdb`.
* Both are **WDDM display-only miniports**. They do **not** create a device object (no `IoCreateDevice` import,
  no string, no dynamic resolve). They register with `Dxgk`: the x86 build's `FUN_004073A0` copies a 0x2A-dword
  initialization table (version word `0x6003`) and jumps through a resolved pointer; the x64 build's
  `FUN_140001B44` builds the 0x150-byte table and `FUN_140005330` resolves and calls `DxgkInitialize` on
  `\Device\DxgKrnl`.
* Their only user-visible surface is a named **section**, `\BaseNamedObjects\iDisplayController`, created by
  `FUN_0040175c` (x86) / `FUN_1400018cc` (x64).
* `idisplay,1` vs `idisplay,2`: `.text`, `.rdata`, `.data`, `INIT`, `PAGE` are **byte-identical** SHA-256 per
  section; the files differ only in the signature/overlay block. `idisplay,3` vs `idisplay,4`: `.text` identical;
  `.rdata` differs only in the 20 bytes of the debug-directory build timestamp (`0x59561CD1` vs `0x59560E8F`).
  **No material x86/x64 or build-to-build difference.**

### 1.2 iDisplay filter (`idisplayfilter,1` x86 2014, `idisplayfilter,2` x64 2017)

* WDM function/filter driver (`Subsystem = NATIVE`), PDB
  `D:\GitHub\idisplay-win\truewddm\{Win7Release|x64\Win7Release}\idisplayfilter.pdb`.
* `AddDevice` creates an **unnamed** filter FDO and attaches it to the PCI root complex:
  `IoCreateDevice(DriverObject, 0x30|0x48, NULL, type, 0x100, FALSE, &devobj)` at `FUN_00401270` (x86) /
  `FUN_1400012d0` (x64). The filter only binds when the lower device's `DevicePropertyHardwareID` is
  `ACPI\PNP0A03`, `ACPI\PNP0A08`, `ACPI\VEN_PNP&DEV_0A03` or `ACPI\VEN_PNP&DEV_0A08`.
* A second, **named** device `\Device\idisplaywddm` is created lazily inside the
  `IRP_MN_QUERY_DEVICE_RELATIONS` completion routine (`FUN_0040206e` / `FUN_14000255c`) and appended to the
  returned device-relations list. It has **no symbolic link**; it is reachable only by NT name.
* Statically linked `wdmlib` supplies `WdmlibIoCreateDeviceSecure` -> `IoDevObjCreateDeviceSecure` ->
  `IoCreateDevice` + `ObOpenObjectByPointer`/`ZwSetSecurityObject`.

### 1.3 Prolific PL2303 serial (`plser`, `plser64`, `plser64_1`)

* KMDF drivers bound dynamically (`WdfVersionBind`; imported from `wdfldr`), serial-port function driver with a
  large Prolific-specific miniport. `plser` = x86, the two `plser64*` = x64, all built 2025-11-03/06.
* The three builds differ throughout `.text` (separate compilations/versions), but have an identical import
  profile and identical device/IOCTL design (section 3.3). No import of `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`,
  `MmProbeAndLockPages`, `MmCopyMemory`, `MmGetPhysicalAddress`, `ZwMapViewOfSection`, `HalTranslateBusAddress`
  in any of the three.

## 2 Entry / device / interface / effective DACL

### 2.1 iDisplay display miniports - no device, NULL-DACL section

`FUN_0040175c` / `FUN_1400018cc`:

```
RtlCreateSecurityDescriptor(&sd, 1);
RtlSetDaclSecurityDescriptor(&sd, TRUE, NULL, FALSE);   // DaclPresent, Dacl = NULL
... ZwCreateSection(&h, 0xF0003, &oa, &sd, ..., SEC_COMMIT, ...);
    if (STATUS_OBJECT_NAME_COLLISION) ZwOpenSection(&h, 0xF0003, &oa);
... ZwMapViewOfSection(h, -1, &base, 0, 0, 0, &viewSize /*0 = whole*/, ViewShare=1, 0, PAGE_READWRITE);
```

* The section has a **NULL DACL** -> any user can open/map/write it (`\BaseNamedObjects` is user-creatable).
* Both object-creation and object-open paths pass access mask `0xF0003` (`SECTION_ALL_ACCESS`).
* No device object, no symbolic link, no IRP entry point, no IOCTL. The only "interface" is this shared section.
* The driver polls it in a system thread `FUN_00401a70` (x86) / `FUN_140001d0c` (x64): three slots of
  `0x40030` bytes, magic `0xFEEEDEAD` at slot+0, two 16-bit fields at slot+4 and slot+6, a status dword at slot+8.

### 2.2 iDisplay filter - `\Device\idisplaywddm` is **Everyone read-only**

The `DefaultSDDLString` argument of `WdmlibIoCreateDeviceSecure` is a `UNICODE_STRING` in `.rdata`:

| Build | UNICODE_STRING VA | `Length`/`MaxLength` | Buffer VA | String |
|---|---|---|---|---|
| x86 `8A87907A` | `0x00403358` | `0x6E` / `0x70` | `0x004032E8` | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR;;;WD)(A;;GR;;;RC)` |
| x64 `1993A861` | `0x140004460` | `0x6E` / `0x70` | `0x1400043F0` | `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR;;;WD)(A;;GR;;;RC)` |

Effective DACL (protected, no inheritance):

| Trustee | Rights |
|---|---|
| `SY` SYSTEM | `GA` (GENERIC_ALL) |
| `BA` Builtin Administrators | `GRGWGX` (generic read + write + execute) |
| **`WD` Everyone** | **`GR` - generic read only** |
| `RC` RESTRICTED_CODE | `GR` |

Why this is authoritative and not overridden:

* `DeviceClassGuid` argument = `NULL`, so `IoDevObjCreateDeviceSecure` takes
  `PpRegStateInitEmptyCreationSettings` (no class-key read); `local_1c[0] & 2 == 0` is therefore true, and the
  code path is `SeSddlSecurityDescriptorFromSDDL(DefaultSDDLString, 1, ...)` ->
  `PpRegStateLoadSecurityDescriptor` -> `IopDevObjApplyPostCreationSettings` ->
  `ObOpenObjectByPointer(..., 0x200, ...)` + `ZwSetSecurityObject`. The default SDDL wins.
* Both builds contain **seven** SDDL strings (`0x4031D8...0x4033E0` / `0x1400042B8...0x140004500`), including an
  "open" `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)`. Cross-reference analysis (Ghidra
  reference manager, plus raw pointer scan) shows **only the index-4 UNICODE_STRING above is referenced by code** -
  x86 `puVar12 = &DAT_00403358` in `FUN_0040206e`; x64 the create call passes `&DAT_140004460` from
  `FUN_14000255c`. The other six are dead `.rdata` - there is **no runtime selector** for an "open" variant in
  these two images.
* Triaged "open/restricted variants" therefore resolve to **restricted only** for both filter binaries.

`\Device\idisplaywddm` device flags: `DeviceType 0x23` (FILE_DEVICE_UNKNOWN), `Characteristics 0x100`
(FILE_DEVICE_SECURE_OPEN), `Exclusive = FALSE`. No symbolic link.

### 2.3 Prolific - `\Device\ProlificSerialN` is **Everyone read+write**

`EvtDeviceAdd` = `FUN_14004E680` (x64 `709ACAA8`; same layout in the other two builds):

```
0x14004E6FF..0x14004E710  WdfFunctions[0x230](Globals, DeviceInit, 0x100, TRUE)   // SetCharacteristics: FILE_DEVICE_SECURE_OPEN
0x14004E71D               lea r8, [0x1400477D8]                                    // &UNICODE_STRING SDDL
0x14004E730               WdfFunctions[0x220](Globals, DeviceInit, &sddl)          // WdfDeviceInitAssignSDDLString
(then)                    WdfFunctions[0x1F0](Globals, DeviceInit, 1)              // exclusive
(then)                    WdfFunctions[0x210](Globals, DeviceInit, 0x1B)           // FILE_DEVICE_SERIAL_PORT
```

The `UNICODE_STRING` at `0x1400477D8` (`Length 0x72`, `MaxLength 0x74`, `Buffer 0x140047760`) points at:

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)
```

Effective DACL:

| Trustee | Rights |
|---|---|
| `SY` | `GA` |
| `BA` | `GRGWGX` |
| **`WD` Everyone** | **`GRGW` - generic read + generic write** |
| `RC` | `GR` |

Same SDDL string and same `{0x72,0x74,buffer}` `UNICODE_STRING` exist in `plser_063783A4` (x86, string VA
`0x43A6E0`, `UNICODE_STRING` VA `0x43A750`) and `plser64_61A861A2` (string VA `0x140046790`, `UNICODE_STRING`
VA `0x140046808`). Device name is
formatted at runtime: `FUN_14001FAE8(buf, L"%ws%d", L"\\Device\\ProlificSerial", index)` with the `\Device\ProlificSerial`
literal at `0x140051440`.

**Net:** an unprivileged user can open `\Device\ProlificSerialN` **with read+write**, and can open
`\Device\idisplaywddm` **read-only** (admins get write). The iDisplay filter device is not symbolically linked, so
it is reachable only via its NT path.

## 3 Dispatch and IOCTL table

### 3.1 iDisplay display miniports - no dispatch table at all

No `IRP_MJ_*` handler exists because no device object exists. The DXGK initialization table
(`FUN_140001B44`, version `0x6003`) installs `DxgkDdi*` callbacks only. The driver is reached through
`Dxgk`/`D3DKMT` (R3 composition), not through an opened device and not through an IOCTL.

### 3.2 iDisplay filter - every major function is a NULL-lower pass-through

| Build | DriverEntry | `MajorFunction[0..27]` | `[22]` POWER | `[27]` PNP | `AddDevice` | `Unload` |
|---|---|---|---|---|---|---|
| x86 `8A87907A` | `FUN_00407006` | `FUN_00401F82` | `FUN_00401ED6` | `FUN_00401534` | `FUN_00401270` | - |
| x64 `1993A861` | `FUN_140009008` | `FUN_14000241C` | `FUN_140002324` | `FUN_140001664` | `FUN_1400012D0` | `LAB_140002410` |

`FUN_14000241C` (and `FUN_00401F82`) does only:

```
IoAcquireRemoveLockEx(DeviceExtension + lock, Irp, ...);
Irp->CurrentLocation++; Irp->Tail.Overlay.CurrentStackLocation++;
IofCallDriver(*(PDEVICE_OBJECT *)(DeviceExtension + 0x10), Irp);   // x86: +0x08
IoReleaseRemoveLockEx(...);
```

**There is no `IRP_MJ_DEVICE_CONTROL` / `IRP_MJ_INTERNAL_DEVICE_CONTROL` / `IRP_MJ_READ` / `IRP_MJ_WRITE`
handler.** For the filter FDO, `DeviceExtension+0x10` is the attached lower device (set in `AddDevice`). For the
**control** device, the extension is zeroed by `IoCreateDevice` and only `[0] = 2` and the remove lock are
initialised - `DeviceExtension+0x10` stays **NULL**.

Consequences:

* **No IOCTL writes kernel memory** - there is no IOCTL path. `IOCTL` table: *empty*.
* Statically, any IRP sent to `\Device\idisplaywddm` (create/open, read, write or IOCTL) reaches
  `IofCallDriver(NULL, Irp)` and bugchecks the machine. That is an unprivileged **DoS**, explicitly out of
  scope for this project (no memory write, no value/target control).
* `IRP_MN_QUERY_INTERFACE` (minor 8) on the control device is the only non-forwarded leaf: it fills an
  `INTERFACE` with five stubs (`FUN_140001130`, `FUN_1400010E8`, `FUN_1400010A0`, `FUN_140002780`,
  `FUN_140001058` = `InterfaceRef`/`InterfaceDereference`/`GetDmaAdapter`/`SetBusData`/`GetBusData`), all of
  which `return 0` and write nothing.

### 3.3 Prolific - 240 IOCTLs, all METHOD_BUFFERED / FILE_ANY_ACCESS

`EvtIoDeviceControl` = `FUN_140001B00` (x64 `709ACAA8`; 49 KB, jump-table style dispatch on `IoControlCode`).
The handler calls `FUN_14000E220(code)` for a trace name, then dispatches on an exact-code binary search.

| Class | Codes | Count | Method | Access | Input | Output | Kernel action |
|---|---|---|---|---|---|---|---|
| Standard serial | `0x1B0004`-`0x1B009C` (30 codes in the `0x1B00xx` serial block) | 30 | **0 = METHOD_BUFFERED** (all) | **0 = FILE_ANY_ACCESS** (all) | `WdfRequestRetrieveInputBuffer` (table slot `+0x868`) | `WdfRequestRetrieveOutputBuffer` (slot `+0x870`) | Update driver-owned UART/serial state, timed-out/pended wait-mask, stats, handflow; write small fixed-size results (<= `sizeof(ULONG)`/`SERIAL_*` struct) to the WDF output buffer |
| Prolific vendor | `0x222000`-`0x222Bxx` (device type 0x22, function 0x800-) | **210** | **0 = METHOD_BUFFERED** (all) | **0 = FILE_ANY_ACCESS** (all) | same slot `+0x868` | same slot `+0x870` | Wrap the WDF buffer with `WdfMemoryCreatePreallocated` (slot `+0x608`) and hand it to a USB control/bulk transfer; read PL2303 OTP/EEPROM/GPIO/PWM, rewrite friendly name, recycle port |

* Verified exhaustively on the extracted comparison set: **all 240 codes have `code & 3 == 0`** and
  `(code >> 14) & 3 == 0`. There is no METHOD_NEITHER, no METHOD_IN_DIRECT, no METHOD_OUT_DIRECT code in the
  dispatch. The only non-multiple-of-4 constant in the function (`0x222581`) is the binary-search upper bound,
  not a handled code. (The driver's own code->name table at `FUN_14000E220` is scrambled - e.g. it labels
  `0x1B0008` "SET_QUEUE_SIZE" - so the raw codes above are the authoritative enumeration, not those strings.)
* Because every code is METHOD_BUFFERED, the I/O manager owns the system buffer; the input and output lengths
  passed to the driver are the *actual* buffer lengths. `WdfRequestRetrieve{Input,Output}Buffer` re-check the
  minimum length and return the real length in the out-parameter that the handlers then use
  (`local_98` -> e.g. `FUN_14001432C(ext, buf, len, &written)`, `FUN_1400214E8(..., buf, len, ...)`).
* No `ProbeForRead`/`ProbeForWrite` is imported or needed. No `WdfRequestRetrieveUnsafeUser*` slot is used
  (the unsafe variants sit at different table offsets; only `+0x868`/`+0x870` appear as retrievers, 159 + 107
  call sites).

## 4 Access-control audit

| Check | iDisplay display | iDisplay filter | Prolific |
|---|---|---|---|
| `SeSinglePrivilegeCheck` / `SeAccessCheck` / `IoValidateDeviceIoControlAccess` | none | none (`IoValidateDeviceIoControlAccess` imported but never called) | none |
| `FILE_WRITE_ACCESS` check on opener | n/a (no device) | DACL only: Everyone `GR`, admin `GRGWGX` | DACL only: Everyone `GRGW` |
| Caller identity / handshake | none | none | none |
| Admin can satisfy the gate | n/a | yes (`GRGWGX`) | yes |
| Unprivileged can satisfy the gate | n/a | **open: yes (read)**; write: no | **open: yes (read+write)** |

Both filter builds import `RtlCreateSecurityDescriptor`, `RtlSetDaclSecurityDescriptor`, `RtlAddAccessAllowedAce`,
`RtlAbsoluteToSelfRelativeSD`, `SeCaptureSecurityDescriptor`, `RtlLengthSecurityDescriptor`, `RtlLengthSid`,
`ZwOpenKey/ZwCreateKey/ZwQueryValueKey/ZwSetValueKey`, `ZwSetSecurityObject` - but these are the statically linked
`wdmlib`/`SepSddl*` helpers used by `WdmlibIoCreateDeviceSecure`; no driver-authored registry-driven DACL path
was found. The seven SDDL strings are data only; only index 4 is referenced.

## 5 Memory-write trace

### 5.1 iDisplay filter - no write sink

There is no caller-controlled destination, no pool copy, no `memcpy`/`RtlCopyMemory` into a caller address, no
MDL, no `MmMapIoSpace`, no `ZwMapViewOfSection`, and no IOCTL handler at all. The only writable kernel object the
driver creates is the control device's own `DEVICE_OBJECT`/extension, written at fixed offsets
(`[0] = 2`, remove lock).

Residual (non-write): the NULL-lower-device pass-through described in section 3.2 is a reliable unprivileged **bugcheck**.

### 5.2 iDisplay display - MDL path exists, but no attacker-directed write

`FUN_140002C0C` is a DXGK DDI (referenced only from the initialization table at `local_58`, i.e. index 29; not
called from any IOCTL). It:

```
mdl = IoAllocateMdl(param_2[2] /* caller VA */, stride(ext,*param_2) * param_2[5], 0,0,0);
MmProbeAndLockPages(mdl, (param_2[2] <= MmUserProbeAddress) ? UserMode(1) : KernelMode(0), IoReadAccess);
if (MDL flags need mapping) va = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, 0x10);
... copies param_2[7] + param_2[10] 16-byte rectangle descriptors into a pool block sized (p7 + p10 + 3)*0x10 ...
IoQueueWorkItem(..., FUN_140002418, ...);    // type 3 => MmUnlockPages + IoFreeMdl
```

* The **AccessMode is derived from the address** (`addr <= MmUserProbeAddress`) rather than from
  `Irp->RequestorMode`. That is an unusual and fragile pattern and is recorded as a residual.
* However, static tracing of `FUN_140002418` shows the work item only (a) copies fixed-size descriptors into a
  correctly sized `ExAllocatePoolWithTag(..., 'IDFB')` block (allocation `(p7 + p10 - 1 + 4) * 0x10` =
  `0x30 + (p7+p10)*0x10`), and (b) on type 3 unlocks/frees the MDL. **No store through the mapped VA and no
  store through `param_2[2]` was found.**
* The DDI is reachable only from `Dxgk` (R3 composition), not from an opened device or an IOCTL.
* `MmGetPhysicalAddress` is used once, in `FUN_14000363C` (`stubQueryAdapterInfo`), to report the PA of the
  driver's own `MmAllocateContiguousMemorySpecifyCacheNode` framebuffer to `Dxgk`. The PA is not exposed to user
  mode and is not writable by the caller. This is **not** a W3P surface.

Fixed-offset write in the section thread: `*(u32 *)(slot + 8) = 0` for each of three slots. Value fixed (0),
offset fixed (+8), destination inside a user-writable section -> not a kernel memory write.

### 5.3 Prolific - no kernel memory write

| Candidate | Present? | Notes |
|---|---|---|
| Caller-controlled destination pointer | **no** | no handler stores through a value taken from the request |
| Caller-controlled length into a kernel buffer | **no** | lengths come back from `WdfRequestRetrieve*` and match the actual buffer |
| `memcpy`/`RtlCopyMemory` with attacker length | **no** (`memcpy`/`memmove` are imported only in the x86 build; the traced copies act on internal, size-computed buffers) | `ExAllocatePool2` appears 3x with internal sizes only |
| `MmMapIoSpace` / `MmMapLockedPagesSpecifyCache` / `MmProbeAndLockPages` / `MmGetPhysicalAddress` | **no imports** | |
| `ZwMapViewOfSection` on `\Device\PhysicalMemory` | **no** | |
| MDL mapped writable into user mode | **no** | |
| `METHOD_NEITHER` without probe/capture | **no** | all 240 codes are METHOD_BUFFERED |
| Missing output-length check | **no** | WDF min-length retrieval + real length returned |
| Fixed-address write redirectable by another IOCTL | **no** | |

The only "writes" the driver performs are (a) to the WDF system buffer that the I/O manager owns,
(b) to driver-allocated pool (`'COMX'`/`'IDFB'` tags) with internally computed sizes, and (c) to the USB device
through `WdfUsbTargetPipe*` / vendor control transfers - the last is **HW-ONLY** and does not count.

## 6 Most dangerous exposed capability

1. **Prolific, R1, read+write open, 240 buffered IOCTLs, no write primitive.** The full serial + vendor IOCTL
   surface is reachable by an unprivileged user on a machine with a PL2303 attached, but every buffer is a WDF
   system buffer and every sink is driver state or USB. This is a well-formed, fully open attack surface with a
   **W0** write quality.
2. **iDisplay filter, R1 read-only open, no IOCTL handler.** The interesting capability is not a write: any IRP to
   `\Device\idisplaywddm` is forwarded to a NULL lower device, i.e. a one-call unprivileged bugcheck. Out of
   scope (DoS-only), noted as residual.
3. **iDisplay display, R1 NULL-DACL shared section.** A user can create `\BaseNamedObjects\iDisplayController`
   before the driver loads with an arbitrarily small size; the driver opens the existing section, maps it, and
   reads three `0x40030` slots and writes `0` at `slot+8`. That is an out-of-view kernel read (and a possible
   fixed-value OOB store) that ends in a bugcheck. Crash-first, fixed value, fixed offset -> at most MW4-class if
   it were in scope, and it is **not** a controlled kernel write. Recorded as residual.
4. The display driver's `MmProbeAndLockPages` AccessMode-by-address pattern (section 5.2) is the only construct in the
   set that *looks* like a write-what-where building block; it is a DDI-only path and no store through the
   mapping was found.

No MW1-MW4 primitive was established for any of the nine files.

## 7 Verdict

**NO-MEMORY-WRITE - reach=R1 (open) / R3 (device) - setup=hardware (Prolific) / devnode (iDisplay) - write=W0 - load=signed.**

| File | Write | Verdict | One-line reason |
|---|---|---|---|
| `idisplay,1_FA82D229.sys` | W0 | **NO-MEMORY-WRITE** | No device object, no IRP dispatch; NULL-DACL section is an input channel only |
| `idisplay,2_287771E7.sys` | W0 | **NO-MEMORY-WRITE** | Code-identical to #1 |
| `idisplay,3_36C72B1E.sys` | W0 | **NO-MEMORY-WRITE** | No device object; MDL path is a DDI source, not a store |
| `idisplay,4_3D882F1C.sys` | W0 | **NO-MEMORY-WRITE** | Code-identical to #3 |
| `idisplayfilter,1_8A87907A.sys` | W0 | **NO-MEMORY-WRITE** | Everyone is read-only; no device-control handler; all majors pass through |
| `idisplayfilter,2_1993A861.sys` | W0 | **NO-MEMORY-WRITE** | Same design, x64 |
| `plser_063783A4.sys` | W0 | **NO-MEMORY-WRITE** | 240 METHOD_BUFFERED IOCTLs, WDF buffers, no MDL/MMIO/PA |
| `plser64_61A861A2.sys` | W0 | **NO-MEMORY-WRITE** | Same design, x64 |
| `plser64_1_709ACAA8.sys` | W0 | **NO-MEMORY-WRITE** | Same design, x64, newest build |

**Overall verdict: NO-MEMORY-WRITE (W0) for all nine files.**

## 8 Build comparison (material differences only)

| Pair | Result |
|---|---|
| `idisplay,1` <-> `idisplay,2` | All PE sections byte-identical; only signature/overlay differs. Treat as one binary. |
| `idisplay,3` <-> `idisplay,4` | `.text`/`.data`/`INIT`/`PAGE` identical; `.rdata` differs only in the 20-byte debug build timestamp. Treat as one binary. |
| `idisplay,1/2` (x86) <-> `idisplay,3/4` (x64) | Same driver model, same section name, same NULL-DACL construction, same 3x`0x40030` layout, same MDL routine family. Only ILP32/ILP64 offsets differ. |
| `idisplayfilter,1` (x86, 2014) <-> `idisplayfilter,2` (x64, 2017) | Same device name, same seven SDDL data strings, **same effective index-4 SDDL** (Everyone read-only), same all-majors pass-through, same control-device NULL lower. Different compilations, no material security difference. |
| `plser` (x86) <-> `plser64`/`plser64_1` (x64) | All three assign the same Everyone-`GRGW` SDDL and expose the same 240-code all-buffered IOCTL dispatch. `plser64_1` is a later build (2025-11-06) than `plser64` (2025-11-03); the interface and IOCTL design are unchanged, and no new memory primitive appears. |

Triaged claim "iDisplay devices ... open/restricted variants": **not confirmed for these two images** - the
"open" (`GRGWGX` for Everyone) SDDL is present only as unreferenced `.rdata`. Both shipped filter binaries apply
the restricted (Everyone `GR`) descriptor.

## 9 Limitations

* **No REA evidence.** The shared REA bridge was at capacity (`STATUS.md` section In flight lists three active REA
  audits and marks this group offline). All findings are Ghidra 12.1.4 headless + `objdump`; no Evidence IDs.
  Dump artifacts: `%TEMP%\opencode\idp\*.txt` (per-binary decompilation), scripts `DumpAll.java`, `Refs.java`.
* Static only. No dynamic confirmation of the DACL, the NULL-lower-device bugcheck, or the section-size OOB.
* The iDisplay DXGK initialization table (version `0x6003`, 42 pointers) was not mapped entry-by-entry to
  `DxgkDdi*` names (no WDK headers/PDB in the workspace); DDI reach is therefore bounded to "reachable from
  `Dxgk`/`D3DKMT` (R3), not from an IOCTL".
* The 210 Prolific vendor IOCTLs were enumerated exhaustively by control code and their buffer discipline was
  verified across the dispatch (`+0x868`/`+0x870` only, all methods buffered), but only a representative subset
  of handler bodies (`FUN_140013C70`, `FUN_14001432C`, `FUN_140014CE4`, `FUN_1400182D0`, `FUN_1400214E8`) was
  traced to the USB layer. A logic bug inside an untraced vendor handler cannot be excluded by this pass.
* `plser`/`plser64_61A861A2` were decompiled in names-only mode; their SDDL, device name, imports and IOCTL set
  were confirmed by data/string/import analysis and by parity with `plser64_1`, not by full decompilation of
  `EvtIoDeviceControl` in each build.
* `iDisplay,3/4`'s `FUN_140002C0C` MDL path deserves a focused follow-up if the DDI can be driven by a
  user-supplied VA through `D3DKMT` - that was not established here, and no store through the mapping was found.
