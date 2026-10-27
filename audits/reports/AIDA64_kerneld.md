# Audit: AIDA64 kerneld-x64.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected5\agentR4\new\kerneld-x64_AE6B4853.sys` |
| SHA-256 | `AE6B4853E9C2D433D0955627EDABA8FBB88BEF0CAFBB1F9DF87A796A8EAB0069` |
| Size | 81,304 bytes |
| Analysis date | 2026-10-24 |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4); no execution, no load, no service creation |
| Reach tier | R2 - local administrator |
| Setup required | none (driver load; default admin-only DACL) |
| Write quality | W2 - constrained physical write, arbitrary after BAR reprogram |
| Verdict | **MW2** - reach=R2 setup=none write=W2 load=signed |
| Identity | AIDA64 Kernel Driver 3.0.1022.0, internal name `LLKD`, original name `kerneld.x64`; Authenticode **Valid**, signer `CN=FinalWire Kft., O=FinalWire Kft., L=Budapest, C=HU` (DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1) |
| PDB | `LLKD.pdb`, GUID `d46e8ba7-0c9c-4c19-9d1b-ddb525380b46`, age 1 |
| PE timestamp | 2026-08-16 11:27:58Z |

> Scope note: the requester has local administrator rights, therefore the default admin-only device DACL is in scope. The gate and the exact primitive are reported below. The DACL itself is not embedded in the image; it is supplied by the I/O manager (see section 4).

---

## 1. Internals

### 1.1 Image layout

| Segment | VA range (image base `0x10000`) | Notes |
|---|---|---|
| Headers | `0x10000`-`0x10400` | PE32+ |
| `.text` | `0x11000`-`0x1de00` | all driver code **and string literals** (device names at `0x1dc80`) |
| `.rdata` | `0x1e000`-`0x1ec00` | IAT at `0x1e000`, whitelist tables at `0x1e140`/`0x1e5c0` |
| `.data` | `0x1f000`-`0x209e8` | globals, MMIO cache |
| `.pdata` | `0x21000`-`0x21200` | x64 unwind |
| `INIT` | `0x22000`-`0x22600` | entry `0x22064` (RVA `0x12064`) |
| `.rsrc` | `0x23000`-`0x23400` | version resource |

The driver has 78 procedures and 66 defined strings (`ev_b8fa8f4b4f3fd4a1fc70e9ff451ae3541aa96467f4bedef1da4a271fdbca9d07`). It is small, single-purpose, and was built with the WDK 7600.16385 WDM headers (`c:\winddk\7600.16385.1\inc\ddk\wdm.h`, string at `0x1db20`).

### 1.2 Imports actually present

IAT at `0x1e000`; names resolved from the PE import directory:

| IAT slot | Import | Relevance |
|---|---|---|
| `0x1e0c8` | `IoCreateDevice` | device creation |
| `0x1e0b0` | `IoCreateSymbolicLink` | `\DosDevices\AIDA64Driver` |
| `0x1e0f8` | `MmMapIoSpace` | **direct physical mapping** |
| `0x1e050` | `MmUnmapIoSpace` | unmap |
| `0x1e008` | `HalGetBusDataByOffset` | PCI config read |
| `0x1e000` | `HalSetBusDataByOffset` | PCI config write |
| `0x1e0b8` | `MmIsAddressValid` | kernel pointer walk |
| `0x1e068` | `IoGetDeviceObjectPointer` | device-object walk |
| `0x1e070`/`0x1e0e0` | `ZwQueryValueKey`/`ZwOpenKey` | ACPI `Configuration Data` |
| `0x1e0e8` | `KeBugCheckEx` | crash helper (`FUN_0001d578`) |
| `0x1e090` | `IofCompleteRequest` | IRP completion |

### 1.3 Important negative findings

* **No `IoAllocateMdl` and no `MmMapLockedPagesSpecifyCache`.** The supplied triage's MDL claim is not supported by the import table; the driver uses `MmMapIoSpace`/`MmUnmapIoSpace` directly (`0x110c9`, `0x11119`, `0x1b63c`). This makes the physical access *more* direct, not less.
* **No `ProbeForRead`/`ProbeForWrite`.** There is no user-address validation anywhere in the dispatch path.
* **No `SeAccessCheck`, `SeSinglePrivilegeCheck`, `SeExports`, token or process checks.** No `Se*` import is present at all.
* **No `IoCreateDeviceSecure`, `RtlSetDaclSecurityDescriptor`, or SDDL string.** `IoCreateDevice` is called with a NULL security descriptor.
* No `MmGetSystemRoutineAddress`, no `ZwOpenProcess`, no `KeStackAttachProcess`, no registry write.

### 1.4 Character

`kerneld-x64.sys` is a hardware-inspection/benchmark access driver: raw port I/O, PCI configuration space, MSR access, device MMIO, firmware/ACPI table parsing, keyboard-controller and chipset SMI access. It is not a filesystem, network, or filter driver.

---

## 2. Entry, device, and dispatch

### 2.1 Entry

```
0x22064 entry:
  0x2206e  CALL 0x22008        ; __security_cookie init (KUSER_SHARED_DATA)
  0x2207d  JMP  0x12808        ; DriverEntry
```

`FUN_00022008` initializes the stack cookie from `0xFFFFF78000000320` and its complement (`ev_31bb6622793d99735cb0f05409dc51a55ce9f20a9fd874c921d68bbc5b6d2c23`).

### 2.2 DriverEntry (`0x12808`)

| Step | Address | Action |
|---|---|---|
| Device name | `0x1281b` | `RtlInitUnicodeString(..., L"\\Device\\AIDA64Driver")` - string at `0x1dc80` |
| OS checks | `0x12882`-`0x129d4` | `PsGetVersion`; sets feature globals for 6.x/10.0 |
| Device creation | `0x12a08` | `IoCreateDevice(DriverObject, 0, &name, 0x8011, 0, TRUE, &DeviceObject)` |
| Dispatch[IRP_MJ_DEVICE_CONTROL] | `0x12a27` | `DriverObject+0xe0 = 0x12a84` |
| Dispatch[IRP_MJ_CLOSE] | `0x12a2e` | `DriverObject+0x80 = 0x12a84` |
| Dispatch[IRP_MJ_CREATE] | `0x12a35` | `DriverObject+0x70 = 0x12a84` |
| DriverUnload | `0x12a39` | `DriverObject+0x68 = 0x1d308` |
| Symlink | `0x12a54` | `IoCreateSymbolicLink(L"\\DosDevices\\AIDA64Driver", device)` - string at `0x1dcb0` |
| Error path | `0x12a60` | `IoDeleteDevice` on symlink failure |

Key parameters (`0x129ef`-`0x12a08`): DeviceType `0x8011` (proprietary), DeviceCharacteristics `0`, **Exclusive = TRUE** (`byte [RSP+0x28] = 1`), **NULL security descriptor**. There is no `IoCreateDeviceSecure`, so the device inherits the I/O manager's default driver-object DACL.

`FUN_0001d308` (unload, `ev_b5e93dc35037471639bb8aa97dc3297df5e8c224506be8853d85babf1ba51c86`) unmaps the cached MMIO slots, deletes the symbolic link, and deletes the device.

### 2.3 Dispatch (`0x12a84`, ~43 KB, 9,905 instructions)

```
0x12a84  MOV  R12, RDX                     ; R12 = IRP
0x12ac3  MOV  [RDX+0x30], 0                ; IoStatus.Status = STATUS_SUCCESS
0x12ac7  MOV  [RDX+0x38], 0                ; IoStatus.Information = 0
0x12afa  MOV  RAX, [R12+0xb8]              ; CurrentStackLocation
0x12b02  MOV  RSI, [R12+0x18]              ; AssociatedIrp.SystemBuffer
0x12b15  CMP  byte ptr [RAX], 0x0e         ; MajorFunction == IRP_MJ_DEVICE_CONTROL?
0x12b18  JNZ  0x1d2c1                      ;   no -> complete success (CREATE/CLOSE)
0x12b1e  MOV  EAX, [RAX+0x18]              ; IoControlCode
0x12b0c  MOV  R14D, [RAX+0x10]             ; InputBufferLength
```

Consequences:

* `IRP_MJ_CREATE` and `IRP_MJ_CLOSE` share the handler but immediately jump to `IofCompleteRequest` with `STATUS_SUCCESS`; no access check, no state, no reference.
* Every IOCTL is `METHOD_BUFFERED`; `SystemBuffer` is at IRP+0x18 and its length is `max(InputBufferLength, OutputBufferLength)`, but the driver uses only `InputBufferLength` (`R14D`) and writes `IoStatus.Information = InputBufferLength` on success.
* The 153-code switch is a compiler-generated binary search over `IoControlCode` starting at `0x12b21` (`CMP EAX, 0x80112170`). Default/unknown codes set `0xC000000D` (`STATUS_INVALID_PARAMETER`) and complete.

---

## 3. IOCTL table

### 3.1 Encoding

All 153 codes lie in the contiguous range `0x80112040`-`0x801122a0`, step 4. Decoding `CTL_CODE(DeviceType, Function, Method, Access)`:

| Field | Value |
|---|---|
| DeviceType | `0x8011` |
| Access | `0` = `FILE_ANY_ACCESS` |
| Method | `0` = `METHOD_BUFFERED` |
| Function | `0x810` ... `0x8A8` |

Examples: `0x801120e4` = Function `0x839`; `0x8011215c` = `0x857`; `0x80112160` = `0x858`; `0x80112240` = `0x890`; `0x80112244` = `0x891`; `0x80112288` = `0x8A2`; `0x801122a0` = `0x8A8`.

Because Access = 0, any handle that can open the device can issue every code; there is no per-function IRP access mask check.

### 3.2 Handler families

Ranges are inclusive, step 4, and cover every one of the 153 codes. `InLen` is the required `InputBufferLength`; `-` means only `!= 0` is checked. The last column gives the `CMP EAX,<code>` switch site; verified instruction sites are added where the exact operation matters.

| Codes | InLen | Kernel action | Switch / key site |
|---|---|---|---|
| `0x80112040`-`0x80112048` | - | Unimplemented; returns `0xC000000D` | `0x12b75` |
| `0x8011204c` | - | **RDMSR**: index = input[0], tested against a 288-entry (`0x120`) whitelist at `0x1e140`; returns EDX:EAX at +4/+8 | `0x12b96`; table `0x13e2c`; `RDMSR 0x13e47` |
| `0x80112050` | - | PCI config capability access: reads/writes offsets `0x44`/`0x48` (AGP/PCIe cap), returns byte | `0x12ba1` |
| `0x80112054` | - | Large PCI-config tweak: reads/writes offsets `0x54`,`0xf4`,`0xf0`,`0x74`,`0x40`,`0x08`; calls `FUN_000110ac/0x110fc` at `BAR+0x3418`; GPU/chipset-specific | `0x12bac`; `0x12ecb`, `0x12f5f` |
| `0x80112058` | - | `IN AL, DX` (port I/O, blocklist checked) | `0x12bb7`; `0x12c80` |
| `0x8011205c` | - | `OUT DX, AL` (blocklist checked) | `0x12bc2`; `0x12c40` |
| `0x80112060` | - | `IN AX, DX` | `0x12bc9`; `0x12bf6` |
| `0x80112064` | - | `OUT DX, AX` | `0x12b60`; `0x13ede` |
| `0x80112068` | - | `IN EAX, DX` | `0x13efd`; `0x1408a` |
| `0x8011206c` | - | `OUT DX, EAX` | `0x13f08`; `0x1404a` |
| `0x80112070`-`0x80112080` | - | Unimplemented | `0x13f13` |
| `0x80112084` | - | **WRMSR**: index = input[0], 84-entry (`0x54`) whitelist at `0x1e5c0`; value = input[2]:input[1] | `0x13f4a`; `0x13f84`, `WRMSR 0x13fb4` |
| `0x80112088`-`0x80112090` | - | Unimplemented | `0x13f51` |
| `0x80112094` | - | PCI config **write** to bus 0/dev 0/fn 0 offsets `0xE8`/`0xEC` (fixed `0x800000E8`/`0x800000EC`) | `0x140d9` |
| `0x80112098` | - | PCI config **read 16-bit**: bus/dev/fn/offset from input[0..3]; Hal or CF8/CFC | `0x140e4`; `FUN_00011474` |
| `0x8011209c` | - | PCI config **write 16-bit** (read-modify-write low word); refuses offsets `0x10`-`0x27` (BARs) | `0x140ef`; `FUN_0001156c` |
| `0x801120a0` | - | PCI config **read 32-bit** | `0x140fa`; `FUN_00011358` |
| `0x801120a4` | - | PCI config **write 32-bit**; refuses offsets `0x10`-`0x27` (BARs) | `0x14105`; `FUN_000113e4` |
| `0x801120a8`-`0x801120ac` | - | Unimplemented | `0x14110` |
| `0x801120b0` | - | PIT channel 2 gating and TSC timing via ports `0x43`/`0x42`/`0x61` | `0x14126` |
| `0x801120b4` | - | Unimplemented | `0x140b9` |
| `0x801120b8` | - | No-op success | `0x1441a` |
| `0x801120bc` | - | `IoGetDeviceObjectPointer` + `MmIsAddressValid` walk of device/driver objects -> info leak | `0x14425` |
| `0x801120c0` | - | Unimplemented | `0x14430` |
| `0x801120c4` | - | Pulse a checked port and time with `RDTSC` | `0x1443b` |
| `0x801120c8`-`0x801120cc` | - | Unimplemented | `0x14446` |
| `0x801120d0` | - | Checked port + MSR `0xE7`/`0xE8` timing loop | `0x1445c` |
| `0x801120d4` | - | Unimplemented | `0x14463` |
| `0x801120d8` | - | Second device/driver object walk (`MmIsAddressValid`) -> info leak | `0x12b36` |
| `0x801120dc`-`0x801120e0` | - | Unimplemented | `0x15d36` |
| `0x801120e4` | - | **Unchecked `OUT` byte**: port = input[3] & 0xFFFF, value = input[0] & 0xFF; then two `OUT 0xEB` | `0x15d4c`; call `0x1664c` -> `0x1d400` |
| `0x801120e8` | - | Port sequence through checked helper | `0x15d57` |
| `0x801120ec` | - | Port sequence through checked helper | `0x15d62` |
| `0x801120f0` | - | `OUT 0xB2`, `OUT 0x84` (chipset SMI) | `0x15d6d`; `0x1640d` -> `0x1d4c8` |
| `0x801120f4` | - | Checked port + Intel uncore MSRs `0x832`/`0x838`/`0x83E` timing | `0x15d78` |
| `0x801120f8` | - | MSR read/write sequence | `0x15d83` |
| `0x801120fc` | - | MSR read/write sequence | `0x15d8e` |
| `0x80112100` | - | 8042 keyboard controller command `0x80` via ports `0x66`/`0x62` | `0x15d21`; `0x166d6` -> `0x12350` |
| `0x80112104` | - | Unimplemented | `0x1672a` |
| `0x80112108` | - | 8042 KBC command `0x81` (two data bytes) | `0x16735`; `0x1692e` -> `0x12350` |
| `0x8011210c`-`0x80112118` | - | Unimplemented | `0x16740` |
| `0x8011211c` | - | Port sequence through checked helper | `0x1676c` |
| `0x80112120` | - | Port sequence through checked helper | `0x16777` |
| `0x80112124` | - | Unimplemented | `0x15d0c` |
| `0x80112128` | - | `OUT 0xB2`, `OUT 0x84` | `0x1698f`; `0x16ff5` -> `0x1d508` |
| `0x8011212c` | - | `OUT 0xB0`, `OUT 0x84` | `0x1699a`; `0x16fcb` -> `0x1d450` |
| `0x80112130` | - | `OUT 0xB0` | `0x169a5`; `0x16fa1` -> `0x1d490` |
| `0x80112134` | - | Returns `0x3FE` | `0x169b0` |
| `0x80112138` | `0x48` | Intel vendor gate; read config dword at user-selected offset input[4], cache as physical base `DAT_0001f124`; `MmMapIoSpace(base + input[9], input[10])` (window <= `0x20000`) -> caller pointer | `0x169bb`; `0x1f124` |
| `0x8011213c` | `0x48` | Same pattern with `input[9] + BAR`; vendor-gated | `0x169c6` |
| `0x80112140` | `0x48` | Cached base `DAT_0001f138` + input[9] -> caller pointer | `0x169d1`; `0x1f138` |
| `0x80112144` | `0x48` | Cached base `DAT_0001f148` + input[9] -> caller pointer | `0x169dc`; `0x1f148` |
| `0x80112148` | `0x48` | BAR + input[9] -> caller pointer | `0x169e7` |
| `0x8011214c` | `0x48` | BAR + input[9] -> caller pointer | `0x1697a` |
| `0x80112150` | `0x48` | `FUN_000120d4` reads chipset ports `0x22`/`0x23` for TOLUD (`0x40000000`/`0x80000000`/`0xC0000000`), maps that + length -> caller pointer | `0x170d8`; `0x1776f`, `0x120d4` |
| `0x80112154` | `0x48` | Class `0x0403` device (multimedia/audio function, typically GPU HDMI audio): byte write to `BAR+8`, dword read at `BAR+0xC` | `0x170e3`; `0x17661` |
| `0x80112158` | `0x48` | BAR + input[9] -> caller pointer | `0x170ee`; `0x17552` |
| `0x8011215c` | `0x48` | **Read dword** at 64-bit `BAR + input[0xc]`; config word `0x0403` gate | `0x170f9`; handler `0x1745c`; `FUN_000110ac 0x174f6` |
| `0x80112160` | `0x48` | **Write dword** `input[0xd]` to 64-bit `BAR + input[0xc]`; config word `0x0403` gate | `0x17104`; handler `0x1736e`; `FUN_000110fc 0x17407` |
| `0x80112164` | `0x48` | AMD `0x1002`: BAR + offset dword read | `0x1710f`; handler `0x172ad` |
| `0x80112168`-`0x8011216c` | `0x48` | PCI config reads | `0x1711a` |
| `0x80112170` | `0x48` | Class `0x0C0010`: **write dword** `input[0xd]` to `BAR + input[0xc]` | `0x12b21`; handler `0x17814` |
| `0x80112174`-`0x801121bc` | `0x48` | Vendor-gated (ALi `0x10b9`, Realtek `0x10ec`, Intel `0x8086`, NVIDIA `0x10de`, `0x1142`, SiS `0x1039`, ...) 4-byte reads/writes at `BAR + input[0xc]`, values from `input[0xd]` | `0x1790f` |
| `0x801121c0`-`0x80112208` | `0x48` | Same vendor-gated BAR + offset read/write family; several copy larger device/ACPI data to the caller pointer | `0x178e5` |
| `0x8011220c` | `0x48` | AMD `0x1002`: `FUN_00011700` writes `input[0xd]` to `BAR + input[0xc]` | `0x178d0`; handler `0x19a0a` |
| `0x80112210`-`0x80112228` | `0x48` | AMD/device GPU BAR register read/write (e.g. byte at `BAR+8`, dword at `BAR+0xC`) | `0x19abc` |
| `0x8011222c`-`0x80112238` | `0x48` | Map fixed BIOS windows `0xC0000`, `0xD0000`, `0xE0000`, `0xF0000` (0x10000 each) -> caller pointer | `0x19b09` |
| `0x8011223c` | `0x48` | Scan `0xF0000` for SMBIOS `_DMI_`, map BIOS-provided address, copy length -> caller pointer | `0x1a389`; handler `0x1b82b` |
| `0x80112240` | `0x48` | Scan top 4 MB (`0xFFC00000`-`0xFFFFFFFF`) for `!!AG`/`GESA`/`AGSE` markers; **`strncpy` to caller pointer with length `input[10]-1`** (unbounded) | `0x1a394`; handler `0x1b6a9`; `strncpy 0x1b759`/`0x1b793`/`0x1b7cd` |
| `0x80112244` | `0x48` | `MmMapIoSpace(input[9] - 0x400000, input[10])` (i.e. `0xFFC00000 + input[9]`), copy -> caller pointer | `0x1a39f`; handler `0x1b603`; map `0x1b63c`; copy `0x1b655` |
| `0x80112248` | `0x48` | AMD `0x1002` GPU: PCI config writes at `0x30`, register dump at `0x90`/`0x94`/`0x194`/`0x1A0`/`0x1A8`/`0x1C8`/`0x1CC`/`0xC40` -> caller pointer | `0x1a3aa`; handler `0x1aabe` |
| `0x8011224c`-`0x80112250` | `0x48` | AMD GPU MMIO read/copy | `0x1a3b5` |
| `0x80112254`-`0x80112258` | `0x48` | Vendor/PCI-gated BAR dword reads (`0x6766`, ...) | `0x1a3cb` |
| `0x8011225c`-`0x8011226c` | `0x48` | GPU/PCI MMIO reads guarded by vendor/device IDs | `0x1baff` |
| `0x80112270`-`0x80112284` | `0x28` | **ACPI table read**: map `0xE0000` (0x20000), find `RSD PTR `, follow RSDT/XSDT entry `input[2] < 1000`, map target, copy -> caller pointer | `0x1bb36`; handler `0x1d0b2` |
| `0x80112288` | - | **Kernel pointer leak**: `input[0] + cached device object pointer`, `MmIsAddressValid`, walk list at +0x30, return up to 0x400 pointers + type IDs | `0x1c972`; handler `0x1cf41` |
| `0x8011228c` | - | **Set CR4.PCE** (`BTS RAX, 8`) | `0x1c97d`; `0x1cf20`-`0x1cf28` |
| `0x80112290` | - | **Clear CR4.PCE** (`BTR RAX, 8`) | `0x1c988`; `0x1ceff`-`0x1cf07` |
| `0x80112294` | - | **Read CR4** into output | `0x1c993`; `0x1cec9` |
| `0x80112298` | `0x48` | Intel CPU-model gate; read/write fixed physical `0xFE001560` via `FUN_000110ac/0x110fc` | `0x1c99e`; `0x1ce5c` |
| `0x8011229c` | - | `WBINVD` | `0x1c9a9`; `0x1cd0f` |
| `0x801122a0` | - | `HalGetBusDataByOffset`/`HalSetBusDataByOffset` for a list of Intel GPU IDs; clears bit 19 of one config dword; copies 0x100 bytes of config space to output | `0x1c9b4`; handler `0x1c9c9` |

### 3.3 Notes on the table

* "Unimplemented" handlers set `IoStatus.Status = 0xC000000D` and write nothing; they are still reachable and return quickly.
* Several handlers only require `InputBufferLength != 0`; there is no upper bound. `0x8011228c`, `0x80112290`, and `0x8011229c` have no length check at all.
* Success paths generally set `IoStatus.Information = InputBufferLength`, not the number of bytes actually produced.
* `0x80112138` caches the first config-derived base in `DAT_0001f124` under a one-shot flag `DAT_0001f120`; later calls reuse it even if the bus/dev/fn differ. This is a stateful cross-call behavior, not a per-call validation.

---

## 4. Access-control audit

### 4.1 Gate

| Gate | Observation | Cite |
|---|---|---|
| Device object DACL | `IoCreateDevice` is called with a **NULL** security descriptor. The image contains no SDDL, no `IoCreateDeviceSecure`, no `RtlSetDaclSecurityDescriptor`, and no DACL bytes. The device therefore receives the I/O manager's default driver-object DACL. Supplied triage: default admin DACL. | `0x129ef`-`0x12a08`; imports |
| Symbolic link | `\DosDevices\AIDA64Driver` -> user-visible `\\.\AIDA64Driver` | `0x1dcb0`, `0x12a54` |
| Exclusive open | `Exclusive = TRUE` (`byte [RSP+0x28] = 1`), so only one open handle at a time | `0x129ff` |
| IRP_MJ_CREATE | Same handler; MajorFunction != `0x0E` -> immediate `STATUS_SUCCESS`; no token/ACL check | `0x12b15`, `0x12b18` |
| Per-IOCTL access | Access bits = 0 (`FILE_ANY_ACCESS`) for all 153 codes | section 3.1 |
| Privilege checks | None. No `Se*` import, no `PsGetCurrentProcess`, no token query, no IRQL restriction | import table |
| User-address probing | None. No `ProbeForRead`/`ProbeForWrite`; pointers from the input buffer are dereferenced directly | import table; `0x1b612` |

**Conclusion:** the sole gate is the device DACL, i.e. local administrator (per triage/default). Once an administrator opens the handle, every code is available; there is no second gate.

### 4.2 What is not checked

* The 64-bit value at input offset `0x40` (used as a destination pointer) is checked only for `!= 0` (`0x1b612`). It is never classified as user vs kernel, never probed, and never bounded.
* `InputBufferLength` is checked against the expected structure size (`0x48`/`0x28`), but `OutputBufferLength` is never consulted.
* PCI bus/device/function and register offset values are not range-checked (except the `0x10`-`0x27` BAR-offset exclusion in `0x8011209c`/`0x801120a4`).
* DMA/physical addresses derived from config space are not validated against the device's declared BAR size.

---

## 5. Most dangerous exposed capability

### 5.1 Attacker-value physical write at `BAR + offset` - **primary**

`0x80112160` (Function `0x858`) is the cleanest memory-write primitive:

```
handler 0x1736e
  0x1736e  checks InLen == 0x48, input[0] == 0x48
  0x173..  FUN_00011474(bus,dev,fn, 0x0A)  -> config word must equal 0x0403 (multimedia/audio, usually GPU HDMI audio)
  0x173..  FUN_00011358(bus,dev,fn, 0x10/0x14) -> 64-bit BAR
  0x17407  CALL FUN_000110fc(BAR + input[0x30], high32, input[0x34])
```

`FUN_000110fc` (`0x110fc`) does exactly:

```
0x11119  CALL [0x1e0f8]   ; MmMapIoSpace(PhysicalAddress = (hi<<32)|lo, 4, 0)
0x1112c  MOV  [RAX], EBX  ; write attacker dword
0x1112e  CALL [0x1e050]   ; MmUnmapIoSpace
```

Properties:

* **Write-what:** fully attacker-controlled 32-bit value (`input[0xd]`, offset `0x34`).
* **Write-where:** 64-bit physical address `BAR + input[0xc]`; `input[0xc]` is an unchecked 32-bit offset, so the reachable window is `BAR` ... `BAR + 0xFFFFFFFF` (up to 4 GB).
* **Gate:** only a PCI class/vendor test (e.g. config word `0x0403` for `0x80112160`; vendor `0x1002`/`0x10de`/`0x8086`/`0x10b9`/`0x10ec`/`0x1039`/`0x1142`/`0x6766` for siblings). Any machine with a matching GPU/audio/bridge device satisfies it.
* **No bounds check** against the BAR size, no alignment requirement, no `ProbeForWrite`.

The sibling handlers are the same primitive with different gates:
`0x8011215c` read (handler `0x1745c`, call `0x174f6`), `0x80112170` write (class `0x0C0010`, handler `0x17814`), `0x80112198` write (SiS `0x1039`), `0x801121f8` write (NVIDIA `0x10de`), `0x8011220c` write (AMD `0x1002`), plus the families in `0x80112174`-`0x80112208`.

**Why this is a true memory write:** on a typical system the display BAR is placed high (e.g. `0xE0000000`). Adding a 32-bit offset reaches `0xE0000000`-`0x1DFFFFFFF`. On a machine with >4 GB RAM, `0x100000000`-`0x1DFFFFFFF` is RAM, including kernel pool and code pages. The same primitive can read those addresses (`0x8011215c`), so an attacker can scan for a target and then overwrite it 4 bytes at a time.

### 5.2 Kernel virtual-address destination write - **secondary, write-where with firmware data**

Many handlers take the 64-bit value at input+0x40 and pass it as the destination of `FUN_00011308` (`memcpy`) or `strncpy`, with no user/kernel classification:

```
0x1b612  CMP qword ptr [RSI+0x40], 0     ; only "non-NULL" is required
0x1b63c  CALL MmMapIoSpace(...)
0x1b655  CALL 0x11308(RCX=mapped, RDX=[RSI+0x40], R8D=length)
0x1b660  CALL MmUnmapIoSpace
```

Examples:

* `0x80112244` (`0x1b603`): copies up to 4 MB from `0xFFC00000 + input[9]` to the pointer; length `input[10]` up to `0x400000`.
* `0x80112240` (`0x1b6a9`): `strncpy(ptr, mapped + 8, input[10] - 1)`; `input[10]` is only required to be `> 0x3FF`, so the copy length is **effectively unbounded** and can overflow any kernel buffer at the chosen address.
* `0x80112238`/`0x8011222c`-`0x80112234`: fixed 64 KB BIOS copies to `ptr`.
* `0x80112138`-`0x80112158`, `0x80112210`-`0x80112228`, `0x80112270`-`0x80112284`: device MMIO/ACPI copies to `ptr`.

On a SMAP-enabled system a *user* VA destination faults; a *kernel* VA destination succeeds, which is exactly the attacker's choice. The written bytes are firmware/device data, not arbitrary attacker bytes, so this is a corruption primitive rather than a clean write-what-where. `0x80112240` is the worst of the family because the length is attacker-controlled and unbounded.

### 5.3 Unchecked port output - **enables the chain**

`0x801120e4` (Function `0x839`) calls `FUN_0001d400` (`0x1d400`) with the raw input buffer:

```
0x1d40d  MOV  EAX, [R8]       ; value = input[0]
0x1d418  MOV  EDX, [R8+0xc]   ; port  = input[3]
0x1d424  OUT  DX, AL          ; arbitrary port write
0x1d425  OUT  0xEB, AL
0x1d427  OUT  0xEB, AL
```

There is **no call to `FUN_000122d8`**, the blocklist used by every other port handler (`0x122d8`, blocklist comparisons `0x122e9`-`0x1233d`, deny return `0x12342`). Therefore this one code can write a byte to *any* x86 I/O port, including:

* `0xCF8`/`0xCFC` - PCI configuration address/data, allowing arbitrary config writes, including BARs (`0x10`-`0x27`) that `0x8011209c`/`0x801120a4` deliberately refuse to modify;
* `0x64` - keyboard controller reset;
* `0x70` - RTC/NMI;
* `0xB2` - SMI.

Combined with the physical write primitive, an administrator can reprogram a device BAR to a chosen physical base and then use `0x80112160` to write arbitrary dwords anywhere in physical memory. That upgrades section 5.1 from "BAR-relative" to a fully arbitrary physical write.

### 5.4 Kernel pointer disclosure

`0x80112288` (`0x1cf41`) adds an attacker-chosen 64-bit offset to the cached device-object pointer `DAT_000201b8`, checks `MmIsAddressValid`, then walks a `LIST_ENTRY` at +0x30 and returns up to 0x400 pointers plus a type dword (`FUN_000122b4`, `0x122b4`) to the output buffer. This leaks kernel addresses (KASLR/pointer values) and is the reconnaissance half of the chain.

### 5.5 Other notable but lower-impact primitives

* **WRMSR whitelist** (`0x80112084`, `WRMSR 0x13fb4`): 84 entries (`0x1e5c0`): `0xEE`, `0x150`, `0x186`-`0x18D`, `0x199`, `0x19C`, `0x1A0`, `0x1A4`, `0x1FC`, `0x30A`, `0x30B`, `0x38D`, `0x38F`, `0x610`, `0x832`, `0x838`, `0x83E`, `0x1234`, `0x80868010`, `0xC0010000`, `0xC0010015`, `0xC001001F`, `0xC0010055`, `0xC0010200`-`0xC001020B`, `0xC0010230`-`0xC001025F`. It does **not** include `LSTAR (0xC0000082)`, `STAR (0xC0000081)`, `GS_BASE/KERNEL_GS_BASE (0xC0000101/0xC0000102)`, or `EFER (0xC0000080)`, so it is not a direct ring-0 control-flow hijack. It can still destabilize/patch PMU and chipset behavior.
* **RDMSR whitelist** (`0x8011204c`, `RDMSR 0x13e47`): 288 entries at `0x1e140`, including `0xC0000080`-`0xC0000089` (read-only).
* **Port blocklist** (`0x122d8`): denies `<0x10`, `0x20`, `0x60`, `0x64`, `0x70`, `0x80`-`0x8F`, `0xA0`, `0xC0`-`0xCF`, `0xD0`-`0xDF`, `0x170`-`0x17F`, `0x1F0`-`0x1FF`, `0x376`, `0x3E0`-`0x3EF`, `0x3F6`. Everything else (including `0xCF8`/`0xCFC`, `0x2E`/`0x4E`, `0xB2`) is allowed by the checked handlers; `0x801120e4` bypasses even this.
* **CR4.PCE toggle** (`0x8011228c`/`0x80112290`) lets a user-mode caller execute `RDPMC`; low impact.
* **`WBINVD`** (`0x8011229c`) is a system-wide cache invalidation, a DoS/hardware-state primitive.

### 5.6 Is it a true kernel memory write?

**Yes, with qualifications.**

* **True physical memory write:** `0x80112160` and siblings write an attacker-chosen 32-bit value to an arbitrary offset from a config-derived 64-bit physical base, with no size bound. On a machine whose device BAR sits below the RAM aperture, the window reaches RAM. This is a genuine, stable physical-write backdoor.
* **True kernel virtual-address write (constrained data):** the input+0x40 destination family writes up to megabytes of firmware/device data to any canonical kernel VA, with no probe or classification; `0x80112240` additionally has an attacker-controlled, effectively unbounded length.
* **Not present:** a single IOCTL that takes an arbitrary physical address *and* arbitrary bytes *and* writes them, with no gate. The path is instead: unchecked port write (`0x801120e4`) -> rewrite a BAR -> `0x80112160` -> arbitrary physical write; or `0x80112288` -> leak -> `0x80112240`/`0x80112244` -> kernel-VA corruption.

For a BYOVD scenario this is more than sufficient: the driver is signed, admin-loadable, exposes a stable IOCTL interface, leaks kernel pointers, and provides a repeatable 4-byte physical read/write plus a bulk firmware-to-VA write.

---

## 6. VERDICT

**Signed, admin-only hardware-access driver with a confirmed kernel memory-write primitive.**

| Question | Answer |
|---|---|
| Device reachable by local administrator? | **Yes** - `\\.\AIDA64Driver`, default driver-object DACL, `Exclusive=TRUE`; no secondary token check |
| Arbitrary kernel virtual write? | **Partially** - destination VA fully controlled (input+0x40), content is firmware/device data; length unbounded in `0x80112240` |
| Arbitrary physical write? | **Yes** - 4-byte attacker value at `BAR + 32-bit offset` (`0x80112160` family); fully arbitrary after `0x801120e4` reprograms the BAR |
| Arbitrary physical read? | **Yes** - `0x8011215c` family (same window), plus firmware/ACPI/BIOS reads |
| Kernel pointer leak? | **Yes** - `0x80112288` device-object list walk |
| MSR control? | **Whitelisted** - 288 read / 84 write indices; no LSTAR/STAR/GS_BASE/EFER write |
| Port I/O? | **Yes** - checked blocklist except the unchecked `0x801120e4` byte write |
| PCI config? | **Yes** - arbitrary bus/dev/fn/offset read; write refuses `0x10`-`0x27` only in `0x9C`/`0xA4`, bypassable via `0x801120e4` |
| MDL abuse? | **No** - no `IoAllocateMdl`, no `MmMapLockedPagesSpecifyCache`; direct `MmMapIoSpace` |
| Memory-safety bug? | **No classic overflow found** - the risk is intentional, insufficiently validated hardware access |

**Risk:** High for an administrator-loaded signed-driver (BYOVD) scenario. The driver converts admin rights into physical memory read/write and kernel pointer disclosure. It is **not** an unprivileged or remote escalation: the DACL gate is administrator.

**Recommended remediation (for the vendor):** replace `MmMapIoSpace`-based IOCTLs with `MmMapLockedPagesSpecifyCache` on caller MDLs; validate that the input+0x40 pointer is a user-mode address and probe it; bound every offset against the actual BAR size; remove `0x801120e4`'s unchecked `OUT` or route it through `FUN_000122d8`; enforce `OutputBufferLength`; and restrict the physical windows to the specific device registers the product needs.

---

## 7. Limitations

1. **Static only.** No driver load, no IOCTL fuzzing, no runtime DACL inspection, no `MmMapIoSpace` success/failure observation. The "default admin DACL" is supplied triage plus the absence of an explicit SD; it was not read from a live device object.
2. **Decompiler artifacts.** Ghidra pseudocode uses `in()`/`out()` intrinsics and `undefined*` types; the 43 KB dispatch function's C rendering is a reconstruction, not source. All conclusions above were cross-checked against the instruction listing where it matters (`0x1b603`-`0x1b660`, `0x1b759`, `0x13f84`/`0x13fb4`, `0x1736e`/`0x17407`, `0x1745c`/`0x174f6`, `0x1cf20`-`0x1d2c1`).
3. **Handler coverage.** All 153 codes are enumerated and their families identified, but not every vendor/device branch of the 43 KB switch was decompiled line-by-line. The device-read family (`0x80112174`-`0x80112208`) shares the same `FUN_000110ac`/`FUN_000110fc` pattern; individual vendor gates may differ.
4. **SMAP behavior.** Modern Windows enables `CR4.SMAP`; a user-mode VA destination in section 5.2 would fault. A kernel VA destination works. This was not tested dynamically.
5. **Physical layout.** The claim that `BAR + offset` reaches RAM depends on the machine's PCI resource assignment and RAM size; it was not verified on hardware. The primitive itself (no bounds check, attacker value) is code-level confirmed.
6. **Signature.** Authenticode chain validated locally (`Valid`, FinalWire Kft./DigiCert), but revocation, timestamp countersignature, and catalog trust were not independently verified.
7. **Session isolation.** The shared REA MCP endpoint was concurrently used by other analyses and changed targets mid-query. All evidence below was collected in a private REA stdio session bound to SHA-256 `AE6B...0069`; stale results from other targets were discarded.

### Evidence index

| Evidence ID | Operation | Subject |
|---|---|---|
| `ev_b8fa8f4b4f3fd4a1fc70e9ff451ae3541aa96467f4bedef1da4a271fdbca9d07` | `binary_overview` | PE layout, 78 procs, 66 strings |
| `ev_252c2484b35fa3453a8301be5d9f2c43ce07244654dd1ee26c2ebb5a59d068fa` | `list_procedures` | 78 locals + imports |
| `ev_c1ac1b1ca4860ca72107895540ba23ba921fe8e7c7a4b523f222343735df0e68` | `list_strings` | device names, version strings |
| `ev_88477f4e63c19a993f630ead6013657c580b6a41e1acc21a7a0692882ffceafb` | `analyze_function 0x12808` | DriverEntry |
| `ev_5f77a7422bf4c250fd8d3c7f236f294dc7c3b5bd3398905e356fd389cb9ae259` | `analyze_function 0x22064` | entry |
| `ev_73d08dbbda4c7bbe29cae86ac313000afdf4fb12f3e59c2121759bd433a87396` | `read_function_instructions 0x12a84` | 9,905-instruction dispatch |
| `ev_4a46852a4d58b0a5a37f81c20bfdb02f511948bb254cd14bae0f1cf6fc6be512` | `procedure_pseudo_code 0x12a84` | 6,702-line switch |
| `ev_8ad9c5d5d52aac1a270f1a51482b1109dc465714911412b6b2590167d44a1caf` | `analyze_function 0x122d8` | port blocklist |
| `ev_8a2e28e8093e2f69591bb7fa1540ba153925f0adbdce2d30b557dc55f7bea84a` | `analyze_function 0x110ac` | 4-byte physical read |
| `ev_174a73d4d3dca5f8112bebabcde021fe4eb320b9f50e492d7cdb280f0f44c0e9` | `analyze_function 0x110fc` | 4-byte physical write |
| `ev_a665c53b7dec193e97fa803ebabaa1722969aa118437c530e9bfd3ea7b589cb6` | `analyze_function 0x11308` | `memcpy` wrapper |
| `ev_32e1972fcdeb7b9cfadf03c26ab5d046ffabb0c6ed722518c491f104fb71ca6f` | `analyze_function 0x11358` | PCI dword read |
| `ev_b9e6d7a334fd6b0bc78de80a59d97ebab5cdcfb8e230643c3ab6a57148b81274` | `analyze_function 0x11474` | PCI word read |
| `ev_8a88c0c819045bd1d14d2daa490bbc4af80f778bd70431f490dceb1eb53f3c62` | `analyze_function 0x1156c` | PCI word write |
| `ev_03bed089c92c5d519fe3b91a8b82c1fdb0b3f6dc7982be45e9d64ec615c1a7e8` | `analyze_function 0x113e4` | PCI dword write |
| `ev_0bb5af6cf2f68bc229715892f777a3b9db0ca533a3e55703d55d303f6d2b8ff7` | `analyze_function 0x120d4` | TOLUD via ports 0x22/0x23 |
| `ev_a2554e3943860442079485ad8791b3f0bddedc52921c5563da62e63e9cf818e2` | `analyze_function 0x1d400` | unchecked `OUT` |
| `ev_9de428c8724707d5715e7fbbaa031cd67f235196dbbe5a05aef361fe91f693d2` | `analyze_function 0x1d450` | SMI `0xB0`/`0x84` |
| `ev_c98b2acb9db618717945a62c56c582845a723eab7b91f5b7a60009f0c9fb4ad0` | `analyze_function 0x1d4c8` | SMI `0xB2`/`0x84` |
| `ev_d14b6cfba0be7343df0f56c26fa546bb6de4fc882aedb845b783d624f19e4315` | `analyze_function 0x1d508` | SMI `0xB2` |
| `ev_e00f7b22a0284fdfe6c253c4618d9d38df9416a73f38235ce21cc5bd25182617` | `analyze_function 0x12350` | 8042 KBC |
| `ev_82aa25b4c31d9c0e9a8f2e4a0922e955569ce2f2eba8d4d39053ade7654c823a` | `analyze_function 0x12484` | ACPI `Configuration Data` |
| `ev_b5e93dc35037471639bb8aa97dc3297df5e8c224506be8853d85babf1ba51c86` | `analyze_function 0x1d308` | unload |
