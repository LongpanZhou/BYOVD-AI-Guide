# Audit: vmnetuserif.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\vmnetuserif.sys` |
| Recorded SHA-256 | `1191DD88953DBF63EE7A51182FFC019E75D78FCB13B8790644139EF9273656E4` (verified against triage_index.csv; recon.py hash re-verified) |
| Company/Version | Broadcom Inc. 17.6.0.0 (VMware network application interface driver; PDB `bora-24031532\vmnet\release\win-kernel\userif`) |
| Method | Static-only audit via LOCAL Ghidra 12.1.4 headless (37 fns decompiled + targeted asm for `FUN_140002778`/`FUN_14000220c`/`FUN_140001d80`); REA shared bridge contended 4-way (A/B/C3) -> Agent D-validated fallback used. No device opened, no IOCTL executed. |
| Verdict | **NO-WRITE** (every copy probed/bounded; MDL kit is the correct probe-UserMode->map-KernelMode pattern on the caller's own pages; open is authz-gated) |

> Static-only. No driver was loaded, no device was opened, and no IOCTL was executed. Addresses are linked VAs at image base `0x140000000` (local Ghidra program `vmnetuserif.sys`). WDM driver (no WDF); thin proxy over `VMNET.SYS` (`VNet_*` imports). Note: an earlier draft of this report used an inverted KPROCESSOR_MODE reading; all mode arguments below are asm-verified with the correct enum (KernelMode=0, UserMode=1).

## Entry surface

- `DriverEntry` (`FUN_140001000` @ `0x140001000`): `IoCreateDevice(DriverObj, ExtSize=0, L"\Device\VMnetUserif", DeviceType=0x22 FILE_DEVICE_UNKNOWN)` + `IoCreateSymbolicLink(L"\DosDevices\VMnetUserif")`. **No SDDL / `IoCreateDeviceSecure`** -> the device object carries the I/O-manager default SD (documented default: System + Administrators only).
- Dispatch (`DRIVER_OBJECT+0x70` MajorFunction base): MJ_CREATE=`FUN_140001d80`, MJ_CLOSE=`FUN_140001280`, MJ_READ=`FUN_140001e90`, MJ_WRITE=`FUN_1400020d0`, MJ_DEVICE_CONTROL=`FUN_1400013a0`; FastIoDispatch (`FAST_IO_DISPATCH.FastIoControl@+0x50` = `FUN_140001b70`).
- **MJ_CREATE gate** (`FUN_140001d80` @ `0x140001d80`): rejects directory opens (`Parameters.Create.Options & 1`), then `FUN_14000220c` - builds an ACL in pool: ACE1 = SID read from `\Registry\Machine\SOFTWARE\Wow6432Node\VMware, Inc.\SID` (`RtlQueryRegistryValues` @ `0x140002324`, ACE mask `0x1f01ff` @ `0x140002341`), ACE2 = `S-1-5-32-544` (subauths `0x20,0x220` @ `0x1400023d5/23ef`), ACE3 = `S-1-5-18` (subauth `0x12` @ `0x14000247a`), all `0x1f01ff` (FILE_ALL_ACCESS). Calls `SeAccessCheck` @ `0x140002634` (GenericMapping from `IoGetFileObjectGenericMapping`, DesiredAccess from `Parameters.Create.SecurityContext`, subject context from the same structure) and on success requires `GrantedAccess == DesiredAccess` (`0x14000263e`).
  - **Gate verdict (asm-verified):** the `SeAccessCheck` AccessMode stack arg (`[rsp+0x38]` @ `0x14000261f`) is `1` = **UserMode** - the DACL check is *real*. DACL admits only the registry VMware SID, Administrators, and System; **an unprivileged user fails the check -> `0xC0000022` returned by the driver** (`0x140001dc1`), and the device-SD default denies the open even earlier. (This matches the parallel vmx86 conclusion; no reachability nuance.)
- No other device/interface is published.

## Memory-write analysis

All copy sites go through `FUN_1400031c0` (memcpy) - every call site is length-gated; user buffers are always probed **before** copy, in the caller's own thread context:

- **The MDL kit (`FUN_140002778` @ `0x140002778`, used by `0x8102206C` -> `FUN_140002a40`)** - the only mapping code in-file, and it is the **correct** pattern:
  - `IoAllocateMdl(callerVA, 4, 0, TRUE, 0)` @ `0x140002799`; **`MmProbeAndLockPages(MDL, UserMode, IoWriteAccess)`** (asm `0x1400027b1-b7`: `R8D=1`->`DL`=1=UserMode, `R8D=1`=IoWriteAccess) - **probed** write-lock: invalid or read-only pages raise; kernel VAs raise at the user-mode probe. The two caller pointers come from `SystemBuffer+0x10/+0x18` (ioctl `0x8102206C`, InLen==0x28, `*(u32*)buf==6`).
  - `MmMapLockedPagesSpecifyCache(MDL, **KernelMode**, MmCached, 0, FALSE, NormalPagePriority|MdlMappingNoWrite|global)` @ `0x1400027fa-0x140002806` (`XOR EDX,EDX`=KernelMode; `MdlFlags&0x5` pre-check reuses `MDL->MappedSystemVa`) - maps the caller's **own probed user pages** into a system-VA alias (with a read-only mapping hint) so the kernel can touch them from arbitrary thread context. No kernel memory is ever mapped or written.
  - The packet-enqueue paths `FUN_1400028dc` (@ `0x1400028dc`, locked OR) / `FUN_140002958` (@ `0x140002958`) execute `*(volatile u32*)systemVA |= *(u32*)(SystemBuffer+0x24)` - the write lands in **the caller's own user page through the alias**. No privilege gain (caller-owned page); no kernel-memory write.
- **MJ_READ (`FUN_140001e90`) / FastIO-read (`0x81022200`)**: kernel packet -> `Irp->UserBuffer`/FastIO output, `ProbeForWrite` first, length `min(pktLen, reqLen)`. Kernel->user, probed, bounded - safe.
- **MJ_WRITE (`FUN_1400020d0`) / FastIO-write (`0x81022204`)**: len gate `0xE <= len < 0x2401`, `VNet_PacketAllocate(len)`, `ProbeForRead` first, copy user -> freshly allocated packet. User->kernel into a same-length allocation - safe.
- **MJ_DEVICE_CONTROL (`FUN_1400013a0`, ~25 codes `0x81022004-0x81022098`, all METHOD_BUFFERED + FILE_ANY_ACCESS, custom device type `0x8102`)**: all writes are fixed-size stores into `SystemBuffer` (allocation `max(InLen,OutLen)` >= every store) behind explicit per-code InLen/OutLen gates (`0x81022004` Out>=6; `0x81022008` In==0x10/Out>=4; `0x81022010` In==4; `0x81022014` Out>=4; `0x8102201C` Out>=0x48; `0x81022020` In==0x48; `0x81022024` In==8; `0x81022044` In 4/0x2C; `0x81022048/4C` In==0; `0x81022050/54` In==8; `0x81022068` Out==4; `0x8102206C` In==0x28; `0x81022080` In 0xC/0x10; `0x8102208C` In==0xCC & [0]<0x21 (<=0x1F8 B fill into vmnet obj); `0x81022090` In==1; `0x81022094` Out==4; `0x81022088/3C/40/70` -> `VNet_CallBridge`).
- Cross-module caveat: `VNet_CallBridge(code, &len, SystemBuffer)` and `VNet_SetStats/SetMacAddr/AllocateMemory` pass in-file-validated buffers to `VMNET.SYS`; if vmnet.sys mis-sized a copy, the defect lives there (out of this file's scope).
- Residual (non-write, admin-gated, out of scope): `FUN_140002d14` references user-supplied event handles with `ObReferenceObjectByHandle(..., SYNCHRONIZE, ExEventObjectType, **UserMode=1**)` - correct mode (the sibling `0x8102202C` handler uses `Irp->RequestorMode` identically). `MmProbeAndLockPages` raising on a malformed `0x8102206C` pointer is a potential unhandled-exception DoS only for callers that already passed `SeAccessCheck` (admin/System/VMware-SID) - no unpriv reach.
- No `wrmsr`/`rdmsr`/`sgdt`/`lgdt`/`mov cr*` in code sections (byte-scan hits sit in the Authenticode cert blob / `.rdata` import-name data - false positives); no `\Device\PhysicalMemory`, no `MmMapIoSpace`, no `MmCopyMemory`, no METHOD_NEITHER (`code&3==0` for every code).

## Memory-touching IOCTL table

MJ_DEVICE_CONTROL (`FUN_1400013a0`), all METHOD_BUFFERED + FILE_ANY_ACCESS: see the gated list in Memory-write analysis above; the only copy-capable data paths (`0x81022044`, `0x81022080`, `0x81022084`, `0x8102208C`, `0x8102206C`) are length-gated or probed as described. MJ_READ/WRITE + FastIO `0x81022200/04`: probed, min-length, safe directions.

## Verdict + VM confirmation plan

**NO-WRITE.** The single kernel-mapping path is the textbook-safe one (`MmProbeAndLockPages` at **UserMode** with `IoWriteAccess`, then a **KernelMode** system-VA alias of the caller's own pages with a read-only mapping hint); the resulting kernel OR-write lands in the caller's own user page and grants no privilege. Every other copy is probed or length-gated, and the device itself is authz-gated twice (device-SD default + real UserMode `SeAccessCheck`).

VM plan (orchestrator-owned, describe-only):
1. **Gate test (non-destructive):** medium-IL shell `CreateFile("\\\\.\\VMnetUserif")` -> expect `ERROR_ACCESS_DENIED` (device-SD / SeAccessCheck). Elevated shell -> success.
2. **Behavioral check (admin, non-destructive):** `0x8102206C` (InLen 0x28, `[0]=6`, `+0x10/+0x18` = aligned user pointers, `+0x24` = flag dword), then connect a vnet (`0x81022044`) and enqueue via FastIO `0x81022204`; verify the flag dword appears in the user buffer (notification mechanism, not corruption).
3. No corruption test is warranted by the static evidence.

*End of report.*
