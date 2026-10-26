# spacedeskDriverAudio.sys - admin-reach static memory-write audit

| Field | Value |
|---|---|
| File | `drivers/spacedeskDriverAudio.sys` (manifest batch: collected3; previously `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected3\drivers\Spacedesk\spacedeskDriverAudio.sys` (128,632 bytes)) |
| SHA-256 | `913630DD2BACEBDA06FD30A832CCA6ABA29BC703700A857663254E383DEEB5AA` (Get-FileHash) |
| Company and version | datronicsoft Technology GmbH; FileVersion 1.0.491.19; ProductVersion 1.0.491.19 |
| Signature status and signer | Valid (Get-AuthenticodeSignature). Signer: `CN=Datronicsoft Inc., O=Datronicsoft Inc., L=Pasig, C=PH` |
| Method | static, Ghidra 12.1.4 headless decompile dump (`ghidra_dump\out\spacedesk_audio.txt`, 212 functions, `=== DONE functions=212` present) |
| Analysis date | 2026-10-24 |
| Reach tier | R3 (devnode-installed device). The active INF DACL grants Everyone read, write and execute on the device; not confirmed at runtime. |
| Setup required | devnode (installed by `spacedeskDriverAudio.inf`; no hardware) |
| Verdict | **NO-MEMORY-WRITE — reach=R3 setup=devnode write=W0 load=signed** (static). Scale: `audits\scope\SEVERITY.md`. |
| Severity | NO-MEMORY-WRITE |
| Write quality | W0 (no kernel memory write found) |

> Static analysis only. The driver was not loaded, installed, started or executed. No test code was written or run. This report describes gates and primitives. It contains no operating steps.

Line numbers refer to `spacedesk_audio.txt`. Function names are the Ghidra names in that dump.

## 1. Entry surface

- **Entry and DriverEntry.** `entry` (line 2127) leads to the DriverEntry body `FUN_14001b000` (lines 8141-8244). That function calls `PcInitializeAdapterDriver(DriverObject, RegistryPath, FUN_140018220)` at line 8219. The path from `entry` to `FUN_14001b000` (which passes through `FUN_14000515c`, line 2138, and the WDF stub helpers) was not traced in full.
- **WDF.** No WDF `EvtDriverDeviceAdd` is installed (per the legacy audit, `audits\legacy\spacedesk_bus_audio_kbd.static.md` section 2; not re-verified here). The driver is a PortCls adapter.
- **AddDevice.** `FUN_140018220` (lines 6893-6918) calls `PcAddAdapterDevice(..., FUN_140018cf0, ...)` at line 6905.
- **Dispatch table.** Set in `FUN_14001b000` after `PcInitializeAdapterDriver` (lines 8221-8223):
  - IRP_MJ_CREATE (offset 0x70) -> `FUN_1400184b0` (6973-7026), which calls `PcDispatchIrp` at line 7007.
  - IRP_MJ_CLEANUP (offset 0x100) -> `FUN_140018310` (6919-6972), which calls `PcDispatchIrp` at line 6953.
  - IRP_MJ_PNP (offset 0x148) -> `FUN_140018b80` (7177-7225). It handles PnP minors 0x02, 0x04 and 0x17 itself and calls `PcDispatchIrp` at line 7206.
  - All other major functions, including IRP_MJ_DEVICE_CONTROL, READ and WRITE, remain PortCls defaults. PortCls is not in the dump.
- **Device and interfaces.** The PnP-created device for `{0511CEC1-0EB4-4ADE-9284-CD36606C3906}\VID_DATRONICSOFT&PID_SPACEDESK_VIRTUAL_AUDIO_*` (INF lines 42-54). KS interfaces come from the `AddInterface` lines 138-151: KSCATEGORY_AUDIO, KSCATEGORY_RENDER, KSCATEGORY_REALTIME, KSCATEGORY_CAPTURE and KSCATEGORY_TOPOLOGY, for the WaveSpeaker, TopologySpeaker, WaveMicIn and TopologyMicIn subdevices. These are the user-reachable surface.
- **Effective DACL.** `spacedeskDriverAudio.inf`:
  - Line 171 (active, in `[spacedeskDriverAudio_Device.NT.HW.AddReg]`, reached from `[spacedeskDriverAudio_Device.NT.HW]` at line 167): `HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)"`. SYSTEM gets GENERIC_ALL. Administrators, **Everyone (WD)** and Restricted Code get GENERIC_READ, GENERIC_WRITE and GENERIC_EXECUTE.
  - Line 170: `DeviceType` 0x1D (FILE_DEVICE_SOUND).
  - No commented-out `Security` line exists in this INF.
  - Unknown: the DACL on the interface symbolic links (assumed to follow the device object), and whether a user open succeeds at runtime.
- **Outbound IOCTL.** `DriverEntry` builds an IOCTL with code `0x220020` (line 8184) and sends it to the lower device through `FUN_140004df0` (line 8215). That IOCTL is not handled by the Bus dispatcher in this dump.

## 2. Memory-write analysis (every dangerous call site)

The import list (EXT block, lines 1-52 of the dump) contains no `MmMapIoSpace`, `MmMapLockedPages*`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `KeStackAttachProcess`, `HalSetBusData*`, `ZwOpenSection`, `RtlCopyMemory`, `memcpy` or `memmove`. It also has no `IoCreateDevice` import, and no MSR or port intrinsics appear in the dump. Bulk copies therefore cannot come from an import. The helper search below covers inline copies.

| # | Site (line) | Containing function | Address, length or value source | Gate | Result |
|---|---|---|---|---|---|
| 1 | `IoBuildSynchronousFsdRequest` (1836), `IofCallDriver` (1849) | `FUN_140004b18` (1824-1857) | Builds an IRP_MJ_PNP with MinorFunction 8 (QUERY_INTERFACE) to the lower device. Interface GUID `{08654ede-305b-4715-9f7b-b4ce60b5b74c}` (VA 0x1400067b8), size 0xa0, version 3 | Called from `FUN_140013610` (line 4055) during device start. No user-controlled input | Kernel-only. The result is the bus interface table at device-extension +0x70 |
| 2 | Interface slot calls (3293, 3881, 4407, 4788) | `FUN_140012420`, `FUN_1400133d0`, `FUN_140014220`, `FUN_140014c80` | Slot +0xf0, +0x100, +0x108 and +0x90 (interface base +0x70, so slot offsets +0x80, +0x90, +0x98, +0x20 respectively) | Flag at device +0x110 (set to 1 by `FUN_140013610` line 4058) | See 2a and 2b |
| 2a | `FUN_140014c80` (4776-4786) | passes caller values `param_2` (u32) and `param_3` (u8) to slot +0x20 | Slot +0x20 is `FUN_140009210` in the bus (`FUN_1400090bc` table; section 2.1) | Flag at +0x110 | Value-only. See 2.1 |
| 2b | `FUN_140012420`, `FUN_1400133d0`, `FUN_140014220` | slot +0x80 (`FUN_140009470`), +0x90 (`FUN_140009bb0`), +0x98 (`FUN_14000a070`) with one argument (the context) | Context only | Flag at +0x110 | No caller-controlled address or length |
| 3 | `FUN_14000207c` (833-867) | ring position update | Adds a count to `*(param_1[1])` and returns a flag. No copy, no address from input | - | Counter update only |
| 4 | `FUN_140002de0` (1296-1409), `FUN_140002b70` (1223-1294), `FUN_140002a00` (1183-1222) | ring and timing helpers reached from handler targets | Writes to fields of the stream object (+0x90, +0xd0, +0xf0 and others), bounded by ring size arithmetic | - | Counter and state writes only |
| 5 | Output builders `FUN_140015444` (5096-5163), `FUN_140015594` (5164-5232) | Write a header and records into the caller's output buffer | Count is a ushort (`param_2 * 0x10 + 0x38` is at most 0x100028, so no 32-bit overflow). Output length is checked against the record size and falls back to 0x28 | Output buffer length | Bounded writes into a user buffer, not kernel memory |
| 6 | `ZwSetValueKey` (3638), `ZwCreateKey` (3528), `ZwOpenKey` (3514) | Function around 3480-3650 | Registry values from the property payload | Driver registry key | Registry writes, not kernel memory writes |
| 7 | `ExAllocatePoolWithTag`, `ExAllocateTimer`, `ExSetTimer` (7928) | various | Fixed or driver-internal sizes | - | Not memory-write primitives |
| 8 | Dynamic routine names via `MmGetSystemRoutineAddress` (1872, 7451-7465) | `ZwQueryInformationProcess` (1871); `PsGetVersion`, `WmiTraceMessage`, `WmiQueryTraceInformation` (7451-7465, decoded in the PE: the first name at VA 0x14001a700 is `PsGetVersion`) | Names fixed at compile time | - | No memory-write routine resolved |

### 2.1 Bus interface slots reached from user-influenced code

The Audio driver calls four slots of the bus interface (interface base is device +0x70). The bus side of each slot was read in `spacedesk_bus.txt`. The interface table is built in `FUN_1400090bc` (bus lines 3969-4038). It is a stack object with `Size = 0xa0` and `Version = 3` (line 4009), and the function pointers at the offsets below (line 4011-4028).

| Audio slot (device +) | Interface offset | Bus function | Bus lines | Effect |
|---|---|---|---|---|
| +0x90 | +0x20 | `FUN_140009210` (ctx, char, uint) | 4039-4102 | Calls `FUN_1400024bc` (bus 795-832), which stores the caller's u32 into fixed child-context fields (+0x4b8, +0x4bc, +0x1c0 or +0x310) selected by child type. Then `FUN_140006e9c` (bus 2798-2832) copies a fixed 0x80-byte request to a queue and waits for it |
| +0xf0 | +0x80 | `FUN_140009470` (ctx, char) | 4137-4185 | Sets a per-region flag and event pointer (region base +0x19038 to +0x19040; region base is ctx+0x19058 or ctx+0x4b108). No caller-controlled address |
| +0x100 | +0x90 | `FUN_140009bb0` (ctx) | 4405-4418 | Calls `FUN_140001c90` on a fixed child-context object (no caller-controlled address) |
| +0x108 | +0x98 | `FUN_14000a070` (ctx) | 4617-4686 | Not analyzed in depth; called with only the context pointer from Audio |

The value written by `FUN_1400024bc` is the caller's u32, stored at a fixed offset in the child context. No address is computed from the value. The write is therefore a state update (W0), not a memory write with a caller-chosen target.

**Open point.** `FUN_140014c80` (the u32 and u8 caller) has no direct call site in the dump. It is reached through a runtime pointer that was not located. Whether a user-influenced KS payload reaches it was not established. The analysis above covers what the call does if it is reached.

## 3. Memory-touching IOCTL and IRP table

Audio has no custom IOCTL handler of its own. User IOCTLs (KS property, method and event, and stream IRPs) are handled by PortCls through `PcDispatchIrp`. The KS property and method tables were not decoded. The handler set below is taken from code pointers in the data sections (54 pointers from `.rdata` and `.data` into `.text`, mapped to their functions by RVA + 0x140000000).

| Handler target (RVA, Ghidra name) | Size | Reach to memory-write or mapping API (visible call graph) |
|---|---|---|
| 0x1000 (`FUN_140001000`), 0x1040, 0x1060, 0x1070, 0x1160, 0x1210, 0x1230, 0x1240, 0x12f0, 0x1310 | small | None found (stubs and small helpers) |
| 0x1910, 0x1950, 0x1970, 0x1990, 0x19b0, 0x19c0 | 9 to 52 | Only `FUN_1400019c0` reaches `KfRaiseIrql` (via `FUN_140002110`). IRQL raise, not a write |
| 0x1a40, 0x1a60, 0x1a70, 0x1d60, 0x1d80, 0x1d90, 0x1da0, 0x1dc0, 0x1dd0 | small | None found |
| 0x2580, 0x2810, 0x2950, 0x2a00, 0x2b70 (`FUN_140002b70`, 618 bytes), 0x2de0 (`FUN_140002de0`, 853 bytes) | 166 to 853 | None found except the ring and counter writes in section 2, items 3 and 4 |
| 0x4f60 (`_guard_check_icall` stub), 0x5660, 0x5690, 0x56a0 (`NonDelegatingQueryInterface`), 0x5700 (`NonDelegatingRelease`), 0x5790 and 0x57b0 (`_guard_dispatch_icall` stubs) | small | None reaches a memory API |

The reach test used this API set: `MmGetSystemRoutineAddress`, `ZwSetValueKey`, `ZwCreateKey`, `ZwOpenKey`, `IoSetDeviceInterfacePropertyData`, `IoRegisterDeviceInterface`, `IofCallDriver`, `IoBuildSynchronousFsdRequest`, `PcNewPort`, `PcNewMiniport`, `PcRegisterSubdevice`, `PcRegisterPhysicalConnection`, `ExAllocatePoolWithTag`, `ExAllocateTimer`, `KfRaiseIrql`, `PcGetPhysicalDeviceObject`, `IoGetDeviceProperty`, `ZwEnumerateKey`, `ZwEnumerateValueKey`, `RtlCopyUnicodeString` and `IoOpenDeviceInterfaceRegistryKey`.

Other memory-touching code visible in the dump (not on a user path): `FUN_140013860` (4075-4300) writes stream-local output pointers through a miniport callback, with no user-controlled address. `FUN_140013610` (3992-4071) is the device-start bus query (section 2, item 1).

## 4. Verdict and dynamic confirmation plan

**Verdict: NO-MEMORY-WRITE — reach=R3 setup=devnode write=W0 load=signed (static).**

- No kernel memory write with a user-controlled address or length was found in the driver's own code.
- No memory-mapping, MDL-lock or physical-mapping API is imported or reachable from any handler target.
- The only user-influenced path into the bus interface (section 2.1, slot +0x20) writes a value to a fixed offset in the bus child context. It does not compute an address from the value.
- Reach is unprivileged (Everyone RWX on the device object), so the DACL is open to unprivileged users, but setup is devnode, which makes the reach R3. It contains no write primitive in the code analyzed.

**Dynamic confirmation (described only, not run):**

1. Confirm the effective DACL of the installed audio device object and of its interface symbolic link, and confirm whether a non-administrator open succeeds.
2. Confirm which PortCls path, if any, reaches `FUN_140014c80` from a KS payload and with what u32 and u8 values.
3. Confirm the bus-side behavior of slot +0x20 (`FUN_140009210`) on the target build, including `FUN_140006e9c`'s queue consumer, which was not traced.

## 5. Limitations

- **PortCls internals.** PortCls is a system component and is not in the dump. Its KS property dispatch, property-table validation and the miniport COM methods (indirect calls through vtables) were not analyzed.
- **KS property tables** were not decoded. The handler set in section 3 is inferred from data-section code pointers and may be incomplete.
- **Indirect calls.** Many calls go through CFG-guarded pointers (`PTR__guard_dispatch_icall_1400061f8`), and their targets are not visible.
- **WDF calls** are not used in the Audio driver (PortCls), but the stub helpers still call WDF through indirect pointers. Their targets were not resolved.
- **`FUN_140014c80`** has no visible caller (section 2.1, open point).
- **Bus side of the interface.** Only the Bus functions reached through slots +0x20, +0x80, +0x90 and +0x98 were read. The Video driver shares the GUID but was not analyzed.
- **The earlier legacy verdict** (`audits\legacy\spacedesk_bus_audio_kbd.static.md`: NO-WRITE, disqualified by devnode setup cost, "no sink traced") is consistent with this result for the Audio driver. Its reach rule is updated here to R1 from the active INF DACL.
