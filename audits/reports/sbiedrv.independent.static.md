# Audit: Sandboxie `SbieDrv.sys` (5.73.2) - independent cross-check

> **Independent pass - not the canonical verdict.** Canonical report: `sbiedrv.admin.static.md`
> (**MW2**, trusted-caller heap overflows at commands `0x12340043` / `0x12340049`). This pass used
> offline `llvm-objdump` after the shared REA session returned foreign binaries. It confirms the
> device/PID gate and adds a fixed window-station write at command `0x12340037` (**MW4**), but it
> did **not** trace the internal copy lengths at `0x12340043` / `0x12340049`. Its "no overflow"
> conclusion is therefore not adopted. Treat the MW2 canonical report as controlling; this file is
> an appendix for the fixed-write finding and the evidence-gap disclosure.

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected3\drivers\Sandboxie\SbieDrv.sys` |
| SHA-256 | `B2BFAC3C9FD4C378400EE4821A34773CCBAF71BB1E836C7A03ACC9A9AB3CFE96` (verified twice, `Get-FileHash`) |
| Analysis date | 2026-10-24 |
| Method | Static-only. PE parse + LLVM `llvm-objdump` 20.1.5 disassembly of the verified file; no load, no execution, no registry/service writes |
| Reach | **R2** (local administrator). Device open is not the gate; the real gate is a caller-PID check against the SbieSvc process, satisfiable from admin by running in that service context |
| Setup required | **none** (driver is the installed Sandboxie kernel service `SbieDrv`; installation itself needs admin) |
| Write quality | **W3** (fixed/narrow kernel write, caller-controlled value only) |
| Severity | **MW4 (independent pass; disputed - canonical is MW2)** |
| Canonical report | `sbiedrv.admin.static.md` (**MW2**) |
| HW-only | **no** |

Product: Sandboxie-Plus 5.73.2.0, `FileDescription = Sandboxie Kernel Mode Driver`, `InternalName = SbieDrv`, `OriginalFilename = SbieDrv.sys`, PDB `D:\a\Sandboxie\Sandboxie\Sandboxie\Bin\x64\SbieRelease\SbieDrv.pdb`, link date 2026-08-16.
Signature: Authenticode **Valid**, signer `CN=Microsoft Windows Hardware Compatibility Publisher` (WHQL), RFC-3161 timestamped - loadable under HVCI.

---

## 1 Internals

- PE32+ x86-64, `ImageBase 0x140000000`, `AddressOfEntryPoint 0x3D700`, `SizeOfImage 0x45000`, 8 sections (`.text` RVA `0x1000` size `0x303AE`, `.rdata`, `.data`, `.pdata`, `INITDATA`, `INIT` RVA `0x3D000`, `.rsrc`, `.reloc`), `DllCharacteristics` = HIGH_ENTROPY_VA | DYNAMIC_BASE | FORCE_INTEGRITY | NX_COMPAT | GUARD_CF.
- Two personalities in one binary:
  1. a **file-system minifilter** (`FLTMGR.SYS!FltRegisterFilter`), and
  2. a **control device** `\Device\SandboxieDriverApi` with a command API.
- Imports of interest (IAT RVA): `FltRegisterFilter 0x32000`, `IoCreateDevice 0x325f0`, `ZwCreateFile 0x32120`, `ZwDeviceIoControlFile 0x32538`, `ZwCreateSection 0x32198`, `ZwMapViewOfSection 0x321a0`, `IoAllocateMdl 0x32288`, `MmProbeAndLockPages 0x32270`, `MmMapLockedPagesSpecifyCache 0x32280`, `MmProtectMdlSystemAddress 0x32278`, `KeStackAttachProcess 0x32480`, `ProbeForRead 0x32680`, `ProbeForWrite 0x32670`, `SeSinglePrivilegeCheck 0x32308`, `SeFilterToken 0x325c0`, `SeTokenIsAdmin 0x324b8`, `ObOpenObjectByPointer 0x32238`, `ZwSetSecurityObject 0x32330`, `RtlAddAccessAllowedAceEx 0x32208`, `RtlSetDaclSecurityDescriptor 0x321c8`, `LpcRequestPort 0x32368`.
- **Not present**: `MmCopyMemory`, `MmMapIoSpace`, `MmGetPhysicalAddress`, `HalGetBusDataByOffset`, `WRMSR`/`RDMSR`, port I/O. There is no physical-memory path in this build.
- `KeBugCheckEx` is imported (liveness checks), `KeEnterCriticalRegion/KeLeaveCriticalRegion`, `PsSetCreateProcessNotifyRoutineEx`, `PsSetLoadImageNotifyRoutine`, `CmUnRegisterCallback`, WFP callout registration (`FwpsCalloutRegister1`, `FwpmFilterAdd0`, objects `SbieSublayer`/`SbieCallout`/`SbieFilter`).

## 2 Entry / device / interface / effective DACL

`DriverEntry` = `0x14003D700`. Sequence: `RtlGetVersion` (`0x14003D732`), stash `DriverObject` at `0x140039D08` (`0x14003D760`), `call 0x14003D984` (init), pick up driver object `0x140010124`, build security descriptors `0x1400084F8`, then a long chain of init routines (`0x14003D877` ... `0x14003D90E`).

### 2.1 Device creation (single `IoCreateDevice`)

`0x14003D000` -> creates the control device:

| Field | Value | Site |
|---|---|---|
| Name | `\Device\SandboxieDriverApi` (UTF-16 @ RVA `0x40490`) - `RtlInitUnicodeString` into stack `UNICODE_STRING` | `0x14003D0DC` |
| `DeviceType` | `0x22` (`FILE_DEVICE_UNKNOWN`) | `0x14003D0FE` (`r9d`) |
| `DeviceCharacteristics` | `0x100` (`FILE_DEVICE_SECURE_OPEN`) | `0x14003D106` |
| `Exclusive` | `0` | `0x14003D0FA` (`bl = 0`) |
| `DeviceObject` out | `0x1400396A8` | `0x14003D0E9` |
| Call | `IoCreateDevice` | `0x14003D10E` |

No device symbolic link is created: `IoCreateSymbolicLink` is not imported at all, and no `\DosDevices\...` string exists. The device is opened by its NT name only - exactly what the driver's own kernel client does at `0x1400241B8` (`ZwCreateFile(\Device\SandboxieDriverApi, GENERIC_READ|GENERIC_WRITE, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE)`). (`ZwCreateSymbolicLinkObject` at `0x1400124B3` is used for command `0x11` namespace links, not for the device.)

**Effective DACL.** The driver never calls `IoCreateDeviceSecure`, never supplies an SDDL, and never applies a security descriptor to the device object:

- No SDDL literal exists in the image (`D:`/`O:`/`S-1-...` strings absent).
- `g_ApiSd` (`0x140039820`) built at `0x1400084F8` is **not** attached to the device. It is used only for directory objects: `0x1400122A0` builds `OBJECT_ATTRIBUTES.SecurityDescriptor = g_ApiSd` (`0x140012409`) and calls `ZwCreateDirectoryObject` (`0x1400124D6`), then `ZwSetSecurityObject(handle, ..., g_SbieSd)` (`0x1400124F7`, `g_SbieSd` = `0x140039830`).
- `g_ApiSd` DACL content (`0x1400084F8`): ACEs granting `0x10000000` (GENERIC_ALL) to **`S-1-5-11` (Authenticated Users)** @ `0x1400391F0` (`0x140008582`) and **`S-1-1-0` (Everyone)** @ `0x140039200` (`0x1400085A4`); SACL built at `0x14000860A`-`0x14000862F` (`SYSTEM_MANDATORY_LABEL_ACE`, mask `1`, SID `S-1-16-4096`) and applied at `0x140008736`.

Therefore the device keeps the I/O-manager **default device DACL** derived from the LocalSystem creator token (SYSTEM/Administrators full control, read to Everyone). Because IOCTL `0x222007` uses `FILE_ANY_ACCESS`, an ordinary opener needs no write access at all. **The DACL is not the security boundary; the PID check in section 4 is.** This is stated as the effective DACL, not as a permissive-driver finding: the only user-reachable IOCTL then requires the SbieSvc identity.

### 2.2 Dispatch installation

`0x14003D0B3`-`0x14003D0D0` and `0x14003D13F`:

| `DRIVER_OBJECT` field | Value | Meaning |
|---|---|---|
| `+0x50` FastIoDispatch | pool `0xE0` bytes, `SizeOfFastIoDispatch = 0xE0`, `FastIoDeviceControl = 0x140001D50` | user IOCTLs arrive via the fast-I/O path (`0x14003D093`, `0x14003D0B3`) |
| `+0x70` MajorFunction[IRP_MJ_CREATE] | `0x140002600` | increments open count; `STATUS_DEVICE_NOT_READY` if count == -1 |
| `+0x100` MajorFunction[IRP_MJ_CLEANUP] | `0x140002590` | decrements open count |
| `+0x30` DO_DEVICE_INITIALIZING | cleared (`btr [dev+0x30], 7`, `0x14003D13F`) | device goes live |

`IRP_MJ_DEVICE_CONTROL` is deliberately **not** set: the device is served exclusively through `FastIoDeviceControl`. `IRP_MJ_CREATE` performs **no** access check (no `FILE_WRITE_ACCESS`, no token test) - opening is DACL-only.

`0x14003D214` is the command registrar: allocates a `0x278`-byte table (79 entries) and stores `table[code - 0x12340001] = handler` (`0x14003D27A`-`0x14003D285`).

### 2.3 Minifilter registration

`0x14003DF96` `FltRegisterFilter(DriverObject, &FLT_REGISTRATION @ 0x14003C000, &g_Filter @ 0x140039878)`; start at `0x14003DFC6` (`FltStartFiltering`). `FLT_REGISTRATION` (`0x14003C000`): Size `0x68`, Version `0x0202`, Flags `1`; ContextRegistration `0x14003C068` (empty, first entry `0xFFFF` = end); OperationRegistration `0x14003C0A0`:

| IRP_MJ_* | Pre-op |
|---|---|
| `IRP_MJ_CREATE` (0) | `0x140009280` |
| `IRP_MJ_CREATE_NAMED_PIPE` (1) | `0x140009280` |
| `IRP_MJ_SET_INFORMATION` (6) | `0x140009280` |
| `IRP_MJ_CREATE_MAILSLOT` (0x13) | `0x140009280` |

No post-ops; no `IRP_MJ_DEVICE_CONTROL`/`IRP_MJ_FILE_SYSTEM_CONTROL` interception. The filter adds no second control device.

## 3 Dispatch and IOCTL table

### 3.1 FastIoDeviceControl `0x140001D50`

`BOOLEAN FastIoDeviceControl(FileObject, Wait, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, IoControlCode, IoStatusBlock, DeviceObject)`.
The code reads `IoControlCode` from `[rsp+0xE0]`, `InputBuffer` from `r8`, `InputBufferLength` from `r9d`, `IoStatusBlock` from `[rsp+0xE8]`. Mode split (this is the key structural fact):

- `0x140001D8B` `ExGetPreviousMode` -> **KernelMode only** for `0x222008` (`0x140001D8F`).
- `0x140001DEB` -> **KernelMode only** for `0x22200C` (`0x140001DEF`).
- `0x140001E48` -> **UserMode only**, and only `0x222007` (`0x140001E58`); everything else `STATUS_INVALID_DEVICE_REQUEST` (`0xC0000010`) or `0xC0000148`.

| IOCTL | CTL_CODE decode | Method | Access | Input size | Output size | Reach | Kernel action |
|---|---|---|---|---|---|---|---|
| `0x00222007` | dev `0x22`, func `0x200`, m `1`, a `3` | METHOD_IN_DIRECT | FILE_READ_ACCESS\|FILE_WRITE_ACCESS | 8..0x40 (checked `0x140001E6A`: `len-8 <= 0x38`) | 0 | **UserMode only** | Copies <=0x40 bytes to a 0x40-byte kernel stack block after `ProbeForRead(buf, 0x40, 8)` (`0x140001EA6`), then `code = msg[0]`; `code-0x12340001 <= 0x4E` indexes the command table and calls `handler(ctx, &msg, cb)` (`0x140001ED2`-`0x140001F05`). |
| `0x00222008` | dev `0x22`, func `0x200`, m `2`, a `0` | METHOD_OUT_DIRECT | FILE_ANY_ACCESS | exactly `0x38` (`0x140001D9C`) | 0 | **KernelMode only** | `SeFilterToken([buf], [buf+8], [buf+0x10], [buf+0x18], [buf+0x20], [buf+0x28], [buf+0x30])` (`0x140001DD8`). |
| `0x0022200C` | dev `0x22`, func `0x200`, m `3`, a `0` | METHOD_NEITHER | FILE_ANY_ACCESS | exactly `0x30` (`0x140001DFC`) | 0 | **KernelMode only** | `0x140001E2B` -> `0x140024360` -> `0x1400010A9`, which invokes the runtime-resolved **unhooked `SeFilterToken` entry** `[0x140039AC8]` with the caller's fields (token/restricted-SID pointers). `[0x140039AC8]` is derived at init (`0x140040354`-`0x1400403C1`) by name-resolving `SeFilterToken` (`0x1400410C0`) and scanning its body past the hot-patch stub. |

Because `0x222008`/`0x22200C` are gated on `PreviousMode == KernelMode`, they are **not** reachable from user mode or from an administrator; they exist for the driver's own kernel client and for other kernel callers. The single user-reachable entry point is `0x222007`.

### 3.2 Command table (`msg[0]`, registered at `0x14003D214`)

Handler signature `NTSTATUS handler(PVOID ctx, MSG *msg, PVOID cb)`; `ctx = NULL` for the SbieSvc caller, otherwise a registered sandbox-process context. Message layout: `+0x00` command, `+0x08` arg/pointer, `+0x10` pointer, `+0x18` pointer/len, `+0x20`, `+0x28`, `+0x30`, `+0x38`.

| Code | Handler | Kernel action |
|---|---|---|
| `0x12340001` | `0x140002500` | Cleanup-time release: copies a `UNICODE_STRING` via `0x14002CD40`, frees it, writes magic `0x57230` to `[msg+0x10]` (`0x14000256F`). |
| `0x12340003` | `0x140002690` | Service-call proxy: `msg[0x10]` code mapped to `0x4102xxxx`/`0x8102xxxx`/`0xC102xxxx` (`0x1400026B4`-`0x140002720`), `msg[0x18]` = `UNICODE_STRING*` probed/copied, `msg[0x20]` = PID; packages and hands to `0x140016F18` -> `0x14000191C` (LPC request to SbieSvc). |
| `0x12340007` | `0x140019310` | Returns driver strings to `msg[0x10]/[0x18]/[0x20]` (probed), 4-byte value to `msg[0x28]`, qword `[ctx+0x38]` to `msg[0x30]` (8-byte `ProbeForWrite` `0x140019454`). |
| `0x12340008` | `0x140019490` | Context bookkeeping, no user pointer. |
| `0x12340009` | `0x140019F80` | Context query, no user pointer. |
| `0x1234000A` | `0x140019B90` | Process flag set (write to context), `ProbeForWrite` on output. |
| `0x1234000B` | `0x140019060` | Config get/set with `ProbeForRead`/`ProbeForWrite`. |
| `0x1234000C` | `0x14001E640` | `ProbeForWrite(msg[0x10], 4, 4)` then write dword (`0x14001E688`); reads dword from `msg[0x08]` after `ProbeForRead`; may call `PsSetThreadHardErrorsAreDisabled` path. Service-only (returns `0xC0000002` if ctx != NULL). |
| `0x1234000F` | `0x140004100` | Stores/validates a path string; `ProbeForRead`/`ProbeForWrite`, `RtlFreeUnicodeString`. |
| `0x12340010` | `0x1400043F0` | Config update under `ExAcquireResourceExclusiveLite`; PID check. |
| `0x12340011` | `0x1400122A0` | `ZwCreateDirectoryObject` / `ZwCreateSymbolicLinkObject` with `g_ApiSd`, then `ZwSetSecurityObject(g_SbieSd)` (`0x1400124F7`). |
| `0x12340012` | `0x1400125A0` | `SeSinglePrivilegeCheck` (`0x140012694`) gate, then `ObOpenObjectByPointer`/`ZwDuplicateObject` handle work. |
| `0x12340014` | `0x14000A8D0` | `ZwCreateFile` + `ZwSetInformationFile` on a sandbox path, `ObOpenObjectByPointer`, handle->object conversion. |
| `0x12340015` | `0x140007820` | Config + `KeSetEvent`, PID check. |
| `0x12340016` | `0x14000D570` | Sets global byte `0x140039A10`. |
| `0x12340017` | `0x1400083B0` | Registry/config update under exclusive resource. |
| `0x1234001B` | `0x14001E970` | Allocates/releases the context's `0x28` buffer (`0x14001EA86`, `0x14001EAEB`); dword out to `msg[0x10]` after 4-byte probe. Service-only. |
| `0x1234001E` | `0x140014DA0` | Wait/yield loop, `ProbeForWrite`. |
| `0x1234001F` | `0x14000A050` | `ObReferenceObjectByHandle` + `ProbeForWrite`. |
| `0x12340020` | `0x14000A700` | Config update under exclusive resource. |
| `0x12340022` | `0x14000A310` | `IoCreateFileSpecifyDeviceObjectHint` + `RtlInitUnicodeString`, `ProbeForRead`/`ProbeForWrite`. |
| `0x12340024` | `0x14001A050` | Session/token query (`PsReferenceImpersonationToken`, `SeQuerySessionIdToken`). |
| `0x12340025` | `0x140009CD0` | Context query, `ProbeForRead`. |
| `0x12340026` | `0x140001F70` | Copies two driver strings into user `UNICODE_STRING`s via `0x140001C18` (probes dest header 0x10, then dest buffer). |
| `0x12340027` | `0x140009F10` | Context update, `ProbeForWrite`. |
| `0x1234002A` | `0x140012940` | `ZwOpenDirectoryObject`, `ProbeForRead`. |
| `0x1234002B` | `0x140021DE0` | `ProbeForWrite(msg[0x10], 8, 8)`; `SeTokenIsAdmin`; `ZwOpenProcess` with access `0x400` (admin, PID not in sandbox table) else `0`; returns handle to `msg[0x10]` (`0x140021EFD`). Sandbox-context only. |
| `0x1234002C` | `0x140019570` | `ObReferenceObjectByHandle`/`ObOpenObjectByPointer`, dword/qword out after `ProbeForWrite`. |
| `0x1234002D` | `0x140007750` | `RtlFreeUnicodeString`. |
| `0x1234002E` | `0x14001E820` | `ZwQueryInformationToken` on `[ctx+8]`; qword (PID) out after 8-byte `ProbeForWrite` (`0x14001E94F`). |
| `0x1234002F` | `0x1400129F0` | `ZwOpenSymbolicLinkObject` + `ZwQuerySymbolicLinkObject`. |
| `0x12340030` | `0x140014F00` | `ZwOpenKey`, string copy, `ProbeForRead`/`ProbeForWrite`. |
| `0x12340031` | `0x140015030` | `ZwOpenKey` + `ZwSetSecurityObject`. |
| `0x12340033` | `0x140002EB0` | `ObReferenceObjectByHandle` + session check. |
| `0x12340034` | `0x14001C1E0` | Process info; reads target PEB via `0x14001BE18` (attach + `ProbeForRead`). |
| `0x12340035` | `0x140020780` | Dumps a driver list to a user buffer: `ProbeForWrite(buf, count*stride+0x90, 4)` (`0x140020802`), writes header + `0x40`-stride entries, string copy `0x14002CD40` + NUL at `0x140020897`. Service-only. |
| `0x12340036` | `0x14001FBC0` | `PsImpersonateClient`, `ProbeForRead`/`ProbeForWrite`, `ExRaiseStatus`. |
| `0x12340037` | `0x14000D4A0` | **Narrow kernel write** - see section 5.1. Service-only. |
| `0x1234003A` | `0x14001EF10` | `IoCreateFileSpecifyDeviceObjectHint`/`ObReferenceObjectByName` by name from message. |
| `0x1234003F` | `0x14001ECB0` | Context query; dword out after `ProbeForWrite`. |
| `0x12340040` | `0x140002010` | Config get/set with `ProbeForRead`/`ProbeForWrite`, PID. |
| `0x12340041` | `0x1400028B0` | Config get/set with probes. |
| `0x12340042` | `0x140013B40` | `PsLookupProcessByProcessId` + deref. |
| `0x12340043` | `0x140013EE0` | Process flag update, critical region. |
| `0x12340044` | `0x140002A00` | Version/flags query. `msg[8]==0`: 4-byte out; `==-1`: 4/8-byte out; `==-2`: `size>=0x4A`, `ProbeForWrite(ptr, size, 2)` then 0x4A-byte fixed struct copy (`0x140002B62`-`0x140002BA7`). |
| `0x12340045` | `0x140024500` | Handle->object query, qword out after `ProbeForWrite`. |
| `0x12340046` | `0x140002D20` | Config string read, `ProbeForRead`. |
| `0x12340047` | `0x140002270` | Config/state copy with probes. |
| `0x12340048` | `0x14001EB20` | Context query, dword out after `ProbeForWrite`. |
| `0x12340049` | `0x14000A5D0` | Registry/config write, PID. |
| `0x1234004A` | `0x14000AD60` | Registry/config write, PID. |
| `0x1234004B` | `0x1400191D0` | `ZwQueryInformationProcess`, `ZwSetInformationProcess`, `ZwTerminateProcess`. |
| `0x1234004C` | `0x14001E740` | Context query (`ProbeForRead`). |
| `0x1234004D` | `0x14001F410` | Context query (`ProbeForRead`). |
| `0x1234004E` | `0x1400045C0` | Config update, PID, `ProbeForRead`. |
| `0x1234004F` | `0x140003030` | Config read, `ProbeForRead`. |

Codes `0x02,0x04,0x05,0x06,0x0D,0x0E,0x13,0x18,0x19,0x1A,0x1C,0x1D,0x21,0x23,0x28,0x29,0x32,0x38,0x39,0x3B,0x3C,0x3D,0x3E` are unregistered -> `0xC0000010`.

## 4 Access-control audit

1. **Device open** - DACL only; `IRP_MJ_CREATE` (`0x140002600`) performs no access check and merely bumps `0x140039028`. Effective DACL = default device SD (section 2.1). Any local user can obtain a handle to `\Device\SandboxieDriverApi`; this is *not* the boundary.
2. **Primary gate** - `0x140001E85`: `PsGetCurrentProcessId()` vs `g_ServicePid` (`0x1400396A0`). On mismatch, `0x1400182D0(0,0)` looks the PID up in the sandbox-process table `0x140039C80`; lookup failure -> `STATUS_PROCESS_IS_TERMINATING` (`0xC000010A`) at `0x140001F20`. So the only accepted callers are **SbieSvc** (SYSTEM) and **registered sandboxed processes**.
3. **Secondary gate** - handler-level context checks: `ctx == NULL` (service) or `ctx != NULL` (sandbox). Examples verified: `0x1234000C` returns `0xC0000002` when `ctx != 0` (`0x14001E657`); `0x12340035`/`0x12340037` return `0xC0000022` when `ctx != 0` (`0x1400207BC`, `0x14000D4C5`); `0x1234002B` returns `0xC0000002` when `ctx == 0` (`0x140021DFB`).
4. **Privilege checks** - `SeSinglePrivilegeCheck` at `0x140012694` (command `0x12`) and `SeTokenIsAdmin` at `0x140021E41`/`0x140021E61` (command `0x2B`) are the only explicit privilege gates, both satisfiable by an administrator.
5. **PROCESS/THREAD access** - all process/thread handles come from `ObReferenceObjectByHandle` (user handle, access-checked by the object manager) or `PsLookupProcessByProcessId` (bounded by the PID gate); no raw handle from the message is used without object-manager validation.

## 5 Memory-write trace

### 5.1 The only kernel-memory write: command `0x12340037`

`0x14000D4A0` (registered for `0x12340037`):

- Requires service context (`0x14000D4C5` `test rcx,rcx; jne 0xC0000022`) and `Windows >= 8` (`0x14000D4AA`).
- `msg[8]` is taken as the 32-bit **value** (`0x14000D500` `mov edi,[rdi+8]`).
- Target is resolved from kernel state: `0x14000D5F8` -> `IoGetCurrentProcess` -> `PsGetProcessWin32WindowStation` -> `ObReferenceObjectByHandle(ExWindowStationObjectType)` -> `object + *(WORD*)0x140039860` (`0x14000D653`).
- The `+0x8` count and `[obj]` array pointer are read (`0x14000D515`-`0x14000D51B`); index `r8 = [0x1400398D8]`, stride `r9 = [0x1400398D4] << 2`.
- Loop `0x14000D52F`-`0x14000D550`: for each entry whose current dword is `0`/`1` or in a small range (`and eax,-2; je` / `(eax + 0xFFFFF000) & 0xFFFFCFFF == 0`), it executes **`mov dword ptr [rdx + 4*r8], edi`** (`0x14000D544`).

The offsets `0x140039860/0x1400398D4/0x1400398D8` are not caller supplied: `0x14000D67C` discovers them by scanning the window-station object for the marker dwords `0x111111/0x222222/0x333333/0x444444` then `0x4000` (`0x14000D6A0`-`0x14000D765`). If the markers are absent, `0x1400398D8 = -1` and the command fails. This is Sandboxie's GUI-isolation patch of the win32k window-station object.

**Classification: target = fixed offset inside a kernel object (not caller-selected); value = caller-controlled 32-bit; size = fixed 4 bytes; iteration/selection constrained by the object's own contents.** No way to redirect the base pointer, index, or stride from the message. This is W3.

### 5.2 Every other write goes to user memory, after a probe

All message pointers are `ProbeForWrite`-guarded and length-checked before any store. Representative traces:

- `0x140001C18` (used by command `0x26` and many string returns): `ProbeForRead(dst,0x10)`, `ProbeForWrite(dst,0x10)`, `ProbeForWrite(dst->Buffer, max_chars, 2)`, then `memcpy` - `0x140001C52`, `0x140001C60`, `0x140001C8E`, `0x140001CA2`.
- `0x140002A00` (command `0x44`): `ProbeForWrite(ptr, size, 4)` with `size = msg[0x18]`, then writes 4/8 bytes only if `size >= 4/8` (`0x140002B0A`, `0x140002B23`, `0x140002B3B`), and `ProbeForWrite(ptr, size, 2)` with `size >= 0x4A` before the 0x4A-byte struct (`0x140002B62`-`0x140002BA7`).
- `0x140020780` (command `0x35`): probe uses `count * stride + 0x90` (`0x1400207F3`-`0x140020802`) while the loop uses the live list (`0x140020867`); a list-growth race could overrun the *probed* size, but the destination is always the caller's user VA, so the worst case is a user-memory overrun, not a kernel write.
- Commands `0x0C`, `0x1B`, `0x2E`, `0x2B`, `0x45` each perform an explicit `ProbeForWrite` with the exact size written (4 or 8 bytes) at `0x14001E6A9`...`0x14001E955`, `0x140021E18`, `0x140024622`.

### 5.3 The requested primitives, individually

| Primitive | Presence | Assessment |
|---|---|---|
| `MmCopyMemory` | **not imported / not referenced** | n/a |
| `KeStackAttachProcess` | 3 sites: `0x14001BEA9` (fn `0x14001BE18`), `0x140020EFF` (fn `0x140020E74`), `0x14003FA29` (INIT `0x14003F86C`) | `0x14001BE18` attaches only to read the target PEB / `UNICODE_STRING` with `ProbeForRead` (`0x14001BEBC`, `0x14001BED0`, `0x14001BEE4`, `0x14001BF2F`) into a freshly allocated pool buffer - **read-only, no write to the target**. `0x140020E74` validates handles only. `0x14003F86C` is one-shot init. |
| `IoAllocateMdl` + `MmProbeAndLockPages` + `MmMapLockedPagesSpecifyCache` | single site `0x14000E6D8` | Allocates **its own** 0x1000 pool page (`0x14000E74C`), `IoAllocateMdl` (`0x14000E786`), `MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess)` (`0x14000E7AF`), `MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority)` (`0x14000E7FA`), then `MmProtectMdlSystemAddress` (`0x14000E81D`). Caller supplies **no** PA, length, or cache type - a private scratch mapping, **not** a user-controlled mapping. |
| `ZwMapViewOfSection` | single site `0x140008232` | `ZwCreateFile` of a **driver-composed module path** (`0x140003E74` formats it into `0x14002DFF0`), `ZwCreateSection(SEC_IMAGE)`, `ZwMapViewOfSection(..., ViewShare=1, ...)` (`0x140008232`), then PE-header validation (`MZ`/`PE`, `0x14000824B`-`0x1400082A0`). Used to load Sbie's own helper image, not `\Device\PhysicalMemory`; no caller offset/length. |
| `MmMapIoSpace` / MSR / port I/O / PCI | **absent** | no `HW-ONLY` component in this build. |

### 5.4 Code-patching engine (present, but not reachable from the API)

`0x140001000` clears CR0.WP, `0x14000100C` restores it; `0x14000E014` writes a 12-byte `mov eax,imm32; jmp rax` trampoline over a target function (or rewrites an existing hot-patch prologue at `mov [target+6], hook`), then re-enables WP. It is called from `0x14000DFA0` (a message-shaped function), and `0x14000DFA0` has **no** xref anywhere in the image (only its own definition at `0x14000DFA0`; no pointer in `.rdata`/`.data`), and `0x14000E014` likewise has no caller. Neither address appears in the 56-entry command table. **Conclusion: dead/unreferenced in this build** - not a reachable write. Even if reachable, the hook target would be a resolved kernel function address, not a message field.

## 6 Most dangerous exposed capability

The narrow window-station write of command `0x12340037` is the only kernel-memory store with caller-influenced data. Everything else the API can do is user-memory output (probe-checked), handle acquisition (`0x2B`, `0x12`), process control (`0x4B`), directory/registry security application (`0x11`, `0x31`), or the LPC proxy to SbieSvc (`0x03`). The most *powerful* capability in practice is the service API as a whole (`0x03` -> `0x14000191C` LPC request), which runs as SYSTEM but stays in user mode.

## 7 Verdict

**MW4 - reach=R2 setup=none write=W3 load=signed.**

- No arbitrary or constrained (W1/W2) kernel write exists: no caller-controlled destination, length, or source reaches a kernel store; every API pointer is `ProbeForWrite`-checked and size-checked; the MDL/mapping paths operate on driver-owned memory.
- The single kernel-memory store (`0x14000D544`, command `0x12340037`) writes a caller-chosen 32-bit value to a **fixed, discovery-derived offset** inside the current process's window-station object, and only after Sbie's own marker scan succeeds. That is a narrow/fixed write -> **W3 -> MW4**.
- Reach is R2: opening the device only needs the default DACL, but the command requires the SbieSvc process identity (`PsGetCurrentProcessId == g_ServicePid`), which an administrator can satisfy by controlling that service; the sandbox-process branch is limited to processes already registered by the driver. No unprivileged (R1) route was found.
- Loadable: WHQL-signed, valid, timestamped, HVCI-compatible.

## 8 Limitations

1. **Tooling deviation (important for the ledger).** The shared REA/Ghidra MCP session was contaminated by concurrent targets: `list_documents` returned `CoreTemp_ALSysIO64Legacy_x64_A0484FDC.sys` (`ev_81d5b5c08a6519d5b94dff77234d0874e478488d287251e934329f9bacc0c33b`), and two `open_binary` calls on the SHA-256-verified SbieDrv file returned a Corsair `cuevhid` program (`ev_3f4391e1ae825f25c2667eee392e7d65a6c27a6b20d4bd9576946ef5741c1a51`, 66 procedures) and an `ALSysIO64Legacy` program (`ev_1d17f545cad2ea80c8433b996ac83ae1751d78bc076c541310de3b1e2323a599`, procedures `ev_d952f80abfca07fb48300ddb06ae603490976c2ae8be7789b2831cb7d7a7c2ab`, strings `ev_e6b8d135ea9b3d0e1524ed879653c37b6309a473c3cc726c4105b7833a3457f5`), and a `Sandboxie` string search on that program returned empty (`ev_02c028dcc697ea47e178192009162f46b2317b93ad2c5e3cbe1907d03aedbd1a`). All code addresses in this report were therefore produced by an offline, read-only `llvm-objdump 20.1.5` disassembly of the re-hashed file (no load/execution). No REA evidence ID describes this exact binary; that is an evidence gap.
2. Linear disassembly may misclassify data-in-code; the hook cluster (`0x14000E014`, `0x14000DFA0`) could be reached through a runtime-built pointer table that a linear sweep cannot see. Reachability of that cluster is *unknown*, not proven absent.
3. 56 handlers were reviewed by entry conditions, probes, and callee set; a per-handler interprocedural trace of `0x140002C20`/`0x14000191C` (the LPC/API proxy) was not completed.
4. The window-station offset discovery (`0x14000D67C`) is heuristic and build-dependent; on a machine without Sbie's marker dwords the write does not fire.
5. No runtime verification (no load, no service creation, no registry writes) - per the memory-write-only, static-only rule. The concrete default device DACL was not observed on a live system; section 2.1 states the mechanism (no explicit SD) and the standard object-manager default, which the conclusion does not depend on because the PID gate, not the DACL, is the boundary.
