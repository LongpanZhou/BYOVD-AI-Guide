# spacedeskDriverBus.sys - admin-reach static memory-write audit

| Field | Value |
|---|---|
| File | `drivers/spacedeskDriverBus.sys` (manifest batch: collected3; previously `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected3\drivers\Spacedesk\spacedeskDriverBus.sys` (122,992 bytes)) |
| SHA-256 | `28A166708326144C8F451AF1DA52DCC0681D1375915FCD6C8B37664E2D257C95` (Get-FileHash) |
| Company and version | datronicsoft Technology GmbH; FileVersion 1.0.491.50; ProductVersion 1.0.491.50 |
| Signature status and signer | Valid (Get-AuthenticodeSignature). Signer: `CN=Datronicsoft Inc., O=Datronicsoft Inc., L=Pasig, C=PH` |
| Method | static, Ghidra 12.1.4 headless decompile dump (`ghidra_dump\out\spacedesk_bus.txt`, 241 functions, `=== DONE functions=241` present) |
| Analysis date | 2026-10-24 |
| Reach tier | R3 (setup is composition). The device DACL is BA and SY only, so the caller must be a local administrator. |
| Setup required | composition (devnode install of the bus; a registered child driver is also needed for the IOCTL 0x224540 path, see section 2) |
| Verdict | **MW3 - reach=R3 setup=composition write=W3P load=signed** (static, conditional). Scale: `audits\scope\SEVERITY.md`. The earlier WRITE-* labels are retired. |
| Severity | MW3 |
| Write quality | W3P (physical-memory mapping only; the mapped pages are chosen by the caller-shaped MDL; no store through the mapping in this driver) |

> Static analysis only. The driver was not loaded, installed, started or executed. No test code was written or run. This report describes gates and primitives. It contains no operating steps.

Line numbers below refer to `spacedesk_bus.txt`. Function names are the Ghidra names in that dump.

## 1. Entry surface

- **Entry and driver init.** `entry` (line 10335) calls `FUN_14001b1a4` and `FUN_14001425c` (lines 10346-10397). `FUN_14001425c` calls `WdfVersionBind` and then `FUN_14001b000`. The driver is a KMDF 1.15 stub (INF line 76).
- **Device creation.** The FDO and child PDOs are created through KMDF. Per the earlier legacy audit (`audits\legacy\spacedesk_bus_audio_kbd.static.md`, section 2), `EvtDriverDeviceAdd` is `FUN_14001a000`, the FDO is created in `FUN_14000f13c`, and child PDOs are created in `FUN_14000f954` (line 7502). Those WDF table calls are indirect in this dump and were not re-verified here. The child PDO callbacks visible in this dump are `FUN_14000fbe0` (line 7581) and `FUN_14000fa90` (line 7546). No IOCTL queue configuration for the child PDO is visible.
- **Symbolic link and device name.** No `\Device\` or `\DosDevices\` literal appears in the dump, and there is no `IoCreateSymbolicLink` import. The legacy audit states the FDO exposes a device interface only. The interface GUID was not identified in this pass.
- **IOCTL dispatch.** `FUN_140010c20` (lines 8066-8320) is the IOCTL switch. It is assigned as a queue callback in `FUN_140010b40` (line 8053: `local_40 = FUN_140010c20;`). The field offset in the WDF queue config is not confirmed.
- **Effective DACL.** `spacedeskDriverBus.inf`:
  - Line 54 (active, in `[spacedeskDriverBus_Device.NT.AddReg]`, reached from `[spacedeskDriverBus_Device.NT.HW]` at lines 49-50): `HKR,,Security,,"D:P(A;;GA;;;BA)(A;;GA;;;SY)"`. Only Built-in Administrators and SYSTEM receive GENERIC_ALL.
  - Line 55 is commented out (`;HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;WD)(A;;GA;;;RC)"`). It would widen access to Everyone and Restricted Code, and it is **not active**.
  - Line 53: `DeviceCharacteristics` 0x0100 (FILE_DEVICE_SECURE_OPEN).
  - No SDDL call is visible in the dump (`WdfDeviceInitAssignSDDLString` and similar are indirect calls). Effective DACL as far as static analysis can tell: SYSTEM GA and Administrators GA, applied to the devnode's device object by PnP from the HW-key `Security` value.
  - **Unknown:** whether a user-mode open path to the FDO exists at all (interface GUID and symbolic link not identified), and whether WDF applies a different SDDL.
- **PnP.** Root devnode `Root\VID_DATRONICSOFT_PID_SPACEDESK_VIRTUAL_BUS_0001` (INF lines 40-44). Installing it requires administrator rights.
- **Internal IOCTLs.** A second dispatcher (`FUN_140011760`, lines 8360-8417, codes 0x224c03, 0x224c07, 0x224c0b) runs on the `uStack_30` IOCTL field. Only `FUN_14000a52c` (0x224c03) was read: it copies the requester's image path into a 0x200-byte stack buffer with `memcpy_s` (bounded).

## 2. Memory-write analysis (every dangerous call site)

| # | Site (line) | Containing function | Address, length or value source | Gate | Result |
|---|---|---|---|---|---|
| 1 | `MmMapLockedPagesSpecifyCache` (624) | `FUN_14000207c` (607-638), called from `FUN_140001f94` (532 and 2269) | Path A (532): MDL built on driver-owned region. Path B (2269): MDL pointer = **input qword 0 of IOCTL 0x224540** (line 2247) | See 1a and 1b below | Path A: kernel VA of driver pool returned to caller (disclosure). Path B: physical-page mapping primitive (section 2.1) |
| 1a | IOCTL 0x224400 path (line 1761, `FUN_140004750` 1716-1784) | `FUN_140001e08` (515-546): `IoAllocateMdl` (523), `MmBuildMdlForNonPagedPool` (531) | Region base chosen by input +0x10 through `FUN_140003f98` (lines 1507-1528): selector 9 -> `ctx+0x19058`; selector 10 -> `ctx`; selector 11 -> `ctx+0x4b108` or `ctx+0x320b0` (input +0x18 selects). Length fixed at 0x19020. MDL is built by the kernel on driver memory | Input length >= 0x1c and output >= 8 (line 1721). Region selector must be 9/10/11 | Kernel VA of driver memory returned to the caller. No caller-chosen address |
| 1b | IOCTL 0x224540 path (line 2269, `FUN_140005b84` 2203-2302) | `FUN_140001f94` (575-606) -> `FUN_14000207c` | MDL = input qword 0 (2247), output = caller's 0x10-byte buffer | See the list below | Physical-page mapping (section 2.1) |
| 2 | `IoAllocateMdl` (523; 4224) | `FUN_140001e08`; `FUN_1400095c0` (4186-4239, VA = `ctx+0x19058` or `ctx+0x4b108`, length min(param_3, 0x19000)) | Driver region | Region selector | Driver memory only. `FUN_1400095c0` is bus-interface slot +0x78 (`FUN_1400090bc` line 4024); no in-driver caller |
| 3 | `MmBuildMdlForNonPagedPool` (531; 4232) | as above | Driver pool | - | Not caller-controlled |
| 4 | `MmUnmapLockedPages` (562) | `FUN_140001f04` (548-574). Callers: 1818 (0x224404), 2346 (0x224544), 7872 and 7889 (child cleanup) | Stored MDL and mapped VA in the slot. The Ghidra decompile shows the call with no arguments, so the actual arguments are not recovered | Slot must be occupied | For the child slot the stored MDL is the caller-supplied value. Whether unmapping a caller-shaped MDL is safe: **NEEDS-DYNAMIC** |
| 5 | `IoFreeMdl` (within `FUN_140001f04`) | as above | Region MDL only (slot flag set to 1 in `FUN_140001e08` at line 541) | - | Child MDL is not freed by the driver (slot flag is 0 on the `FUN_140001f94` success path, line 594) |
| 6 | `memcpy_s` (683, 790, 1901, 2169, 2694, 2814, 3002, 4818, 5953, 6318) | various | 683 and 2694: fixed 0x58 and 0x80 copies. 790: fixed 4. 1901 and 2169: fixed 0xc4 copies from input entries (see 6a). 2814: fixed 0x80 into a 0xa8 pool block. 3002: destination 0x100 bounded by `memcpy_s`. 4818: 0x200 stack buffer. 5953: destination pool sized `2 * param_4` with overflow check (`FUN_14000cbe0` 5929-5966). 6318: destination pool sized by the registry value (`FUN_14000d808` 6264-6331) | - | All bounded. Only 6a is a concern |
| 6a | `FUN_140004cc8` (IOCTL 0x22408c, 1836-1972): `memcpy_s` source `local_60[0] + 0x20 + i*0xc4` (1901) | Loop count `i < input[+0x1c]` (1950). Only `input length >= 0xe4` (1858) and `count >= 1` (1872) are checked | The count is not checked against the actual input length | Admin only | **Out-of-bounds read of the request buffer** (information disclosure into child descriptions). Writes go to fixed-size WDF memory (0xc4 and 0x14) and are not overflowed |
| 7 | Dynamic routine names (`MmGetSystemRoutineAddress`: 6721, 11379-11393) | `FUN_14000e0d0` (6567-6770, line 6721); `FUN_14001a314` (11370-11395) | PsGetVersion, WmiTraceMessage, WmiQueryTraceInformation, EtwRegisterClassicProvider, EtwUnregister, RtlQueryRegistryValuesEx | - | No memory-write routine resolved |
| 8 | `ZwEnumerateKey` (6281, 6298), `ZwOpenKey` (6906) | `FUN_14000d808` (6264-6331, bounded copy), `FUN_14000e888` (6857-6966, line 6906) | Registry reads | - | Not memory writes |
| 9 | `IoSetDeviceInterfacePropertyData` (7185), `IoSetDevicePropertyData` (7636) | `FUN_14000f014` (7164-7195), `FUN_14000fbe0` (7579-7670) | PnP property data | - | Not kernel memory writes. Data source not traced |
| 10 | `PsLookupProcessByProcessId`, `SeLocateProcessImageName` (4804-4805) | `FUN_14000a52c` (internal 0x224c03) | Requester PID from child context | Child with a process ID | Read only, bounded copy (item 6) |

### 2.1 IOCTL 0x224540 (`FUN_140005b84`): the physical-page mapping primitive

Call chain: `FUN_140010c20` line 8276 -> `FUN_140005b84` (2203) -> `FUN_14000a830` (2249, child lookup) -> `FUN_140001a20` (2260) -> `FUN_140001f94` (2269) -> `FUN_14000207c` (624) -> `MmMapLockedPagesSpecifyCache(MDL, KernelMode, MmCached, NULL, FALSE, NormalPagePriority)`.

Gates, in order:

1. Input length >= 0x1c and output length >= 0x10 (line 2221). Method BUFFERED, access READ.
2. Input +0x18 must be 0 (line 2246).
3. Child lookup `FUN_14000a830` (4886-4950). It walks the child list and returns a child only when all three hold:
   - child context first qword == input qword 0 (line 4935);
   - child context second qword == input qword 1 (line 4935);
   - child type field at child context +0x110 == input +0x10 (line 4938).
   Child type must be 9, 10 or 11 (see the creation gate in item 4).
4. Child creation is controlled by IOCTL 0x22408c (`FUN_140004cc8`), which needs administrator access and copies caller-supplied 0xc4-byte child descriptions. Descriptions with a type outside 9, 10, 11 are refused (`FUN_140003f98` returns NULL). So an administrator supplies the identity and type fields of each description. That the copied fields become the child context fields is inferred (section 5).
5. `FUN_140001a20(child + 0x4d8)` must succeed (line 2260). That requires child +0x4e0 to hold a non-null callback. The only writers of child +0x4d8 and +0x4e0 are the bus-interface functions `FUN_140009c20` (line 4428) and `FUN_140009ca0` (line 4442), which are interface slots +0x68 and +0x70 (`FUN_1400090bc`, lines 4009-4028). The callback is therefore supplied by a kernel client that uses the bus interface. The Audio driver does not call those slots (checked in the Audio dump: no uses of +0xd8 or +0xe0). **Gate: a registered child driver.** Which driver does this is not established.
6. Child slot +0x4c0 must be empty (`FUN_140001f94` line 578).

Resulting primitive, as far as static analysis shows:

- The caller supplies an 8-byte MDL pointer (equal to the child identity qword 0). The kernel reads MDL fields from the caller's address space (no probe of the MDL structure in this path). The kernel builds a kernel-mode RW mapping of the PFNs listed in that MDL and writes the mapped kernel VA into the caller's output (line 624, `*param_2 = uVar1`). Target: any physical pages whose PFNs the caller places in the MDL, subject only to whatever `MmMapLockedPagesSpecifyCache` validates (MDL flags, ByteCount and the PFN array). That validation was not evaluated here (**NEEDS-DYNAMIC**).
- The driver stores the mapping in child +0x4c0 and +0x4c8. Nothing in the dump reads child +0x4c8 (grep for `0x4c8` finds no use). No code path writes through the mapped VA in this driver, so the mapping is returned to the caller but never stored through. A kernel VA returned to user mode cannot be dereferenced by the caller.
- After success, the driver reads 4 bytes from the caller's MDL at +0x28 (line 2278) and stores them at output +0x08.

Classification: a physical-memory mapping with write permission, selected by the caller through the MDL. It is a primitive, but this driver does not perform the write itself. Under `audits\scope\SEVERITY.md` this is MW3: a physical-address-only mapping (PA-only writes are MW3 by definition), admin-only, with composition as setup and no in-driver store.

### 2.2 IOCTL 0x224400 / 0x224404 (region mapping)

Maps a driver-owned frame region (base chosen by the selector in item 1a, length `0x19020`) into kernel VA and returns that VA in the 8-byte output (line 1761 -> 624). It is not caller-controlled memory. Result: kernel VA disclosure of driver memory to an administrator (**information only**). Unmap at 0x224404 (`FUN_140004a6c` line 1818) releases it.

## 3. Memory-touching IOCTL table

The method and access values are decoded from the code. Rows marked "reach only" were not read in full. The reach column lists memory-related APIs reachable in each handler's visible call graph (direct calls only; WDF indirect calls are invisible).

| IOCTL (method, access) | Handler (dump lines) | Input checks observed | Memory effect and primitive | Reach tier |
|---|---|---|---|---|
| 0x224000 (BUFFERED, READ) | `FUN_140002e3c` (1043-1150) | reach only | Pool alloc and free only | local administrator |
| 0x224004 (BUFFERED, READ) | `FUN_140003478` (1220-1274) | reach only | Pool free only | local administrator |
| 0x224008 (BUFFERED, READ) | `FUN_1400031fc` (1151-1219) | reach only | No memory API | local administrator |
| 0x22400c (BUFFERED, READ) | `FUN_140002c84` (998-1042) | reach only | Pool free only | local administrator |
| 0x224010 (BUFFERED, READ) | `FUN_140002acc` (953-997) | reach only | No memory API | local administrator |
| 0x224080 (BUFFERED, READ) | `FUN_140005524` (2045-2118) | reach only | `memcpy_s` in reach (bounded, see section 2 item 6) | local administrator |
| 0x224084 (BUFFERED, READ) | `FUN_140005248` (1973-2044) | reach only | `memcpy_s` in reach (bounded) | local administrator |
| 0x224088 (BUFFERED, READ) | `FUN_1400057dc` (2119-2202) | reach only | `memcpy_s` in reach (bounded) | local administrator |
| 0x22408c (BUFFERED, READ) | `FUN_140004cc8` (1836-1972) | input length >= 0xe4 only; count checked >= 1 | Child description add. Out-of-bounds **read** of the request buffer (section 2 item 6a). No write primitive | local administrator |
| 0x224140, 0x224144, 0x224148, 0x22414c (BUFFERED, READ) | `FUN_1400064c8`, `FUN_140006660`, `FUN_1400067f8` (`memcpy_s` in reach, bounded), `FUN_14000641c` | reach only | No write primitive found | local administrator |
| 0x2241c0, 0x2241c4 (BUFFERED, READ) | `FUN_14000f564`, `FUN_14000f700` | reach only | No memory API | local administrator |
| 0x2241c8, 0x2241cc (BUFFERED, READ) | `FUN_1400062a0`, `FUN_1400061a8` | reach only | No memory API | local administrator |
| 0x224400 (BUFFERED, READ) | `FUN_140004750` (1716-1784) | input >= 0x1c, output >= 8; region selector 9/10/11 | Driver-region MDL and kernel VA returned (disclosure). No caller-chosen address | local administrator |
| 0x224404 (BUFFERED, READ) | `FUN_140004a6c` (1785-1835) | input >= 0x1c; region selector | Unmaps the region | local administrator |
| 0x224408 (BUFFERED, READ) | `FUN_140003fcc` (1531-1611) | reach only | No memory API | local administrator |
| 0x22440c (BUFFERED, READ) | `FUN_1400042f4` (1612-1658) | reach only | No memory API | local administrator |
| 0x224410 (BUFFERED, READ) | `FUN_1400044e0` (1659-1715) | reach only | No memory API | local administrator |
| 0x224540 (BUFFERED, READ) | `FUN_140005b84` (2203-2302) | Gates 1-6 in section 2.1 | **Physical-page mapping with write permission**, MDL chosen by the caller (section 2.1). W3 | local administrator + composition |
| 0x224544 (BUFFERED, READ) | `FUN_140005ee4` (2304-2366) | input >= 0x30; child lookup | Unmaps child slot via `MmUnmapLockedPages` with a caller-chosen MDL (arguments not recovered; NEEDS-DYNAMIC). No write | local administrator |
| 0x224580 (BUFFERED, READ) | `FUN_140002550` (834-906) | output >= 4 (line 842); WDF retrieves a 4-byte and a 0x34-byte input (lines 842-857); child lookup | No memory API in reach | local administrator |
| 0x224940 (BUFFERED, READ) | `FUN_1400038e0` (1319-1392) | input parsed by `FUN_140011f18` (pointer and size checks; length gate not traced); child lookup | Indirect 0x7c allocation (tag 0x45737542), child state update. No write primitive | local administrator |
| 0x224944 (BUFFERED, READ) | `FUN_140003c54` (1393-1506) | reach only | No memory API | local administrator |
| 0x224c03, 0x224c07, 0x224c0b (internal) | `FUN_14000a52c` (4772-4837), `FUN_14000a194`, `FUN_14000a250` | - | Image path copy (bounded) | not reachable from a user open (internal dispatcher) |

## 4. Verdict and dynamic confirmation plan

**Verdict: MW3 - reach=R3 setup=composition write=W3P load=signed (static, conditional).**

- Reach: local administrator only. The active DACL is BA and SY (section 1).
- Setup: composition. The bus needs installing (devnode), and the IOCTL 0x224540 path needs a child whose driver has registered a callback through the bus interface (section 2.1, gate 5).
- Primitive: an MDL chosen by the caller is passed to `MmMapLockedPagesSpecifyCache` in kernel mode. The result is a writable kernel mapping of caller-chosen physical pages, whose VA is returned to the caller. This driver never writes through it.
- Why not MW2 or MW1: no store through the mapping exists in this driver, and the caller cannot dereference the returned kernel VA from user mode.
- Matrix note: the `audits\scope\SEVERITY.md` matrix row for R3 composition with `W3P` (PA-only) is MW3.
- Why not NO-MEMORY-WRITE: the mapping is a physical-memory mapping with write permission, selected entirely by the caller. That is a path to a kernel write for a component that performs one.

**Dynamic confirmation (described only, not run):**

1. Confirm the effective DACL of the installed FDO and of the interface, and whether a user-mode open path exists. This decides whether the verdict stays at local-administrator reach.
2. Confirm whether `MmMapLockedPagesSpecifyCache` accepts a caller-shaped MDL (flag and PFN validation) on the target build.
3. Identify which registered child driver calls bus-interface slots +0x68 and +0x70. Only that driver can satisfy gate 5 in section 2.1.
4. Confirm the arguments of `MmUnmapLockedPages` in `FUN_140001f04` and whether unmap of a caller-shaped MDL is safe.
5. Confirm the out-of-bounds read in `FUN_140004cc8` (count versus input length) and whether it leaks data into a readable child description.

## 5. Limitations

- **WDF indirect calls.** Every WDF call goes through a CFG-guarded pointer (`PTR__guard_dispatch_icall_1400161b0`), and the table index is lost in the dump. WdfDeviceCreate, WdfIoQueueCreate, the WdfRequestRetrieve/Copy family, WdfChildList and any SDDL call are therefore not visible here. The legacy audit mapped some indices from `wdffuncenum.h`, but those mappings were not re-verified in this pass.
- **Copy sinks behind WDF request APIs** (WdfMemoryCopy*, WdfRequestRetrieve*) are invisible. Copy coverage of the IOCTL handlers is partial. Items marked "reach only" in section 3 were not traced line by line.
- **Child identity source.** The link from the 0xc4 descriptions (IOCTL 0x22408c) to the first 16 bytes of the child context is inferred from the match logic in `FUN_14000a830`. It was not traced through the WDF child-list callbacks.
- **Child callback registration.** Only the interface functions `FUN_140009c20` and `FUN_140009ca0` write child +0x4d8 and +0x4e0. Which external driver calls them was not analyzed. The Video driver shares the interface GUID `{08654ede-305b-4715-9f7b-b4ce60b5b74c}` (GUID found in its binary), but its code was not analyzed.
- **User-mode open path** to the FDO was not established (no interface GUID or symbolic link identified).
- **The earlier legacy verdict** (`audits\legacy\spacedesk_bus_audio_kbd.static.md`: NO-WRITE, disqualified by devnode setup cost, "no sink traced") is superseded. The sink is now traced (section 2.1). Its verdict rested on the setup-cost rule, which the current scope no longer applies.
