# Audit: HP / Realtek `rtf64x64_DFB5842C.sys` (NDIS 6.40 LWF)

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\rtf64x64_DFB5842C.sys` |
| SHA-256 | `DFB5842CBF748C9707B7369907C23B73218C58B593F2ED589357753EB36DA40E` |
| Size / MD5 | 72,344 bytes / `C2DF4EF50269589C836C0A0B737F2EF0` |
| Analysis date | 2026-10-25 |
| Method | Static-only: Ghidra 12.1.4 through the REA MCP provider (headless) plus LLVM `objdump` 20.1.5 and PE/import checks. No load, execute, install, service, or registry access. |
| Reach tier | **R1** for the device object and IOCTLs (Everyone `GRGW`, all IOCTLs `FILE_ANY_ACCESS`); **R3 / composition** to create a usable adapter context |
| Setup required | **composition** — NDIS LWF must be bound to a running miniport; a service-only start creates the device but leaves the context list empty |
| Write quality | **W1** — fully caller-chosen 64-bit target; value is constrained by queued-packet/OID content (see §5.4) |
| Severity | **MW2** |
| Verdict | **MW2 — reach=R1 setup=composition write=W1 load=signed** |
| HW-only | no |
| Supersedes | `audits/reports/hp_rtf64x64.static.md` (old scope). Its `WRITE-HIGH` label is **not** inherited. |

**Verdict in one line.** The image exposes a real, caller-targeted kernel virtual-address write
(`0x88992274`, `0x889922BC`, `0x88992288`) from a world-writable device, but the write is only
reachable after the NDIS LWF is bound to a running miniport and the per-adapter context pointer is
leaked. A bare service start creates `\Device\RTF64` but no context; every keyed IOCTL then returns
`0xC0010006`. The old `WRITE-HIGH` therefore maps to **MW2** here, not MW1: the write is
composition-gated and leak-assisted.

**Scope correction — the three named `0x8000` CTL_CODEs are not in this file.** The task names
`0x8000203C` (write), `0x80002038` (read), and `0x80002050` (pointer leak). None of those constants
occurs in `rtf64x64_DFB5842C.sys`: the little-endian byte patterns `3C 20 00 80`, `38 20 00 80`,
`50 20 00 80`, and even `00 20 00 80` all return **zero hits**; the dispatch comparisons cover only
`0x88992264`–`0x889922DC`; the only `0x8000xxxx` immediates are NDIS status values such as
`0x80000005` (e.g. `0x140003DA0`, `0x1400073CC`, `0x140007464`). The old HP report does **not**
contain those three codes either. They are the `bxvbda.sys` (QLogic VBD) primitives documented in
`b06bdrv_detailed.md` V20–V22. The actual HP primitives are mapped in §3.4 and §5. Re-rating a
nonexistent HP `0x8000203C` would be a cross-report conflation.

---

## 1. Internals and build identity

- PE32+ x86-64, native subsystem, image base `0x140000000`, `SizeOfImage` `0x12000`, NDIS 6.40
  LightWeight Filter. Version `3.15.1128.2025`; internal name `rtfilter`; PDB path
  `D:\WorkingSpace\GitServer\Dragon\WinpkFilter_V2\kernel\LWF\sysw10x64\Release\x64\rtf64x64.pdb`
  (`.rdata` at `0x14000A4A0`). Build timestamp 2025-11-28.
- Authenticode: **valid**, signer `CN=Realtek Semiconductor Corp.` (DigiCert Trusted G4 Code
  Signing RSA4096 SHA384 2021 CA1), timestamped 2025. The SHA-256 is **not** in
  `indexes/dedupe/known_bad_hashes.txt`. Loadability under HVCI was not dynamically verified; see
  §9.
- Imports are a normal NDIS LWF set: `NdisFRegisterFilterDriver`, `NdisRegisterDeviceEx`,
  `NdisFOidRequest`, `NdisFIndicateReceiveNetBufferLists`, `NdisFSendNetBufferLists`,
  `MmMapLockedPagesSpecifyCache`, pool APIs, `ObReferenceObjectByHandle`, WPP APIs. There is **no**
  `ProbeForRead`, `ProbeForWrite`, `SeAccessCheck`, `SeSinglePrivilegeCheck`, `MmMapIoSpace`,
  `MmCopyMemory`, `MmGetPhysicalAddress`, or `ZwMapViewOfSection` import/string in the image.
- `DriverEntry` is `FUN_14000e000` (`0x14000E000`, 1416 bytes). The PE entry stub at `0x14000E590`
  calls the security-cookie initializer and then `FUN_14000e000`.
- DriverEntry order: WPP init (`0x14000D10C`, `0x14000D07C`), static-filter init
  (`FUN_1400015D8`, call at `0x14000E246`), global intermediate buffer (`FUN_1400028E4`, call at
  `0x14000E26A`), then `NdisFRegisterFilterDriver` at `0x14000E47F`, `NdisAllocateNetBufferListPool` at `0x14000E4C5`,
  and device registration `FUN_14000410C` at `0x14000E4EE`. The device is created **before and
  independently of** any `FilterAttach`.

## 2. Entry, device, interface, effective DACL

### 2.1 Device creation

`FUN_14000410C` (`0x14000410C`) is the only device-creation path. It:

- zeroes a 28-entry `MajorFunctions` table (`0x1400041CB`, size `0xE0`);
- sets `IRP_MJ_CREATE` (index 0) to `FUN_1400040A0` at `0x1400041D7`;
- sets `IRP_MJ_CLOSE` (index 2) to `FUN_1400040A0` at `0x1400041EB`;
- sets `IRP_MJ_CLEANUP` (index 0x12) to `FUN_1400040A0` at `0x1400041E2`;
- sets `IRP_MJ_DEVICE_CONTROL` (0x0E) and `IRP_MJ_INTERNAL_DEVICE_CONTROL` (0x0F) to
  `FUN_140003E60` at `0x1400041F6` / `0x1400041FA`;
- initializes `\Device\RTF64` (`0x140009270`) and `\DosDevices\RTF64` (`0x140009290`) with
  `RtlInitUnicodeString` at `0x1400041FE` / `0x140004216`;
- builds `NDIS_DEVICE_OBJECT_ATTRIBUTES` on the stack: header `0x380185` at `0x140004273`,
  DeviceName at `+0x38` (`0x140004251`), SymbolicName at `+0x40` (`0x14000425B`), MajorFunctions
  at `+0x48` (`0x140004264`), ExtensionSize `0x10` at `0x14000427B`, DefaultSDDLString at `+0x58`
  (`0x14000426E`), DeviceClassGuid NULL at `0x140004246`;
- calls `NdisRegisterDeviceEx` at `0x140004283`;
- on success writes `'DRTF'` (`0x46544452`) and the filter handle into the device extension via
  `NdisGetDeviceReservedExtension` at `0x140004295`/`0x14000429A`.

`IRP_MJ_READ` (3), `IRP_MJ_WRITE` (4), `IRP_MJ_FSCTL` (0x0D), and `IRP_MJ_SYSTEM_CONTROL` (0x17)
remain NULL. `WriteFile`/`ReadFile` therefore return `STATUS_INVALID_DEVICE_REQUEST`; the only user
surface is `DeviceIoControl`.

### 2.2 Effective DACL

The SDDL string is at **`0x1400091D0`** (57 UTF-16 characters, 114 bytes). It is copied to the
stack by the `MOVAPS` sequence at `0x140004132`–`0x1400041A6`; the `UNICODE_STRING` at
`[rsp+0x20]` is given `Length=0x72`, `MaxLength=0x74` at `0x1400041AD`, and its buffer points to
the stack copy at `0x1400041B5`. That structure is passed as `DefaultSDDLString` to
`NdisRegisterDeviceEx` at `0x14000426E`/`0x140004283`. No other code sets a device or symlink
security descriptor.

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)
```

| ACE | SID | Access | Effective meaning |
|---|---|---|---|
| `(A;;GA;;;SY)` | LocalSystem | `GENERIC_ALL` | full control |
| `(A;;GRGWGX;;;BA)` | Built-in Administrators | `GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE` | admin read/write/execute |
| `(A;;GRGW;;;WD)` | **Everyone** | `GENERIC_READ + GENERIC_WRITE` | **any local user can open read/write** |
| `(A;;GR;;;RC)` | Restricted Code | `GENERIC_READ` | read-only |

`D:P` means a protected DACL with no inherited ACEs. The effective result is that **any local user,
including a medium-integrity non-admin process, can open `\\.\RTF64` with `GENERIC_READ |
GENERIC_WRITE`**. The device is not admin-gated by its DACL. The symlink does not add a stronger
gate; no separate symlink SDDL is set.

There is **no device interface GUID** registered for this device. The `{3138E428-BF0B-4EB8-9914-
C5524A9C5273}` GUID at `0x14000E600` is the NDIS filter's `UniqueName` in the filter-driver
characteristics, not a `GUID_DEVINTERFACE_*` registration. The only user-visible path is the
`\DosDevices\RTF64` symlink.

## 3. Dispatch and IOCTL table

### 3.1 Dispatch path

`FUN_140003E60` (`0x140003E60`) is the `IRP_MJ_DEVICE_CONTROL` / `IRP_MJ_INTERNAL_DEVICE_CONTROL`
handler. It reads the current stack location at `IRP+0xB8`, rejects a NULL `FileObject`
(`[stack+0x30] == 0`), reads `IoControlCode` from `[stack+0x18]`, `InputBufferLength` from
`[stack+0x10]`, `OutputBufferLength` from `[stack+0x08]`, and `SystemBuffer` from `IRP+0x18`.
It never reads `Irp->RequestorMode`, never calls `ProbeForRead`/`ProbeForWrite`, and has no
`SeAccessCheck`/`SeSinglePrivilegeCheck`.

Two codes are special-cased before the main switch:

```
140003F2C  LEAL 0x7766DD7C(R15), EAX      ; R15 = IoControlCode
140003F33  TESTL 0xFFFFFFFB, EAX          ; zero for 0x88992284 or 0x88992288
140003F38  JE   0x140003FE7
...
140003F62  CALL FUN_1400016CC
```

`0x88992284` (SET) and `0x88992288` (QUERY) therefore go directly to `FUN_140006EB4`; all other
codes go to `FUN_1400016CC` (`0x1400016CC`). The main switch compares `0x88992264` through
`0x889922DC` (see the immediate scan at `0x14000173A`–`0x140002336`). Unknown codes return
`0x10001`.

### 3.2 Context-key gate

Most handlers call `FUN_1400042F0` (`0x1400042F0`) with the first qword of `SystemBuffer`. The
lookup walks the circular list at `DAT_14000B130` and compares each node address to that qword.
On a match it also requires **`*(int *)(ctx + 0x60) == 6`** (`0x1400043D9`; `cmpl $0x6,
0x60(%rbx)`). If the list node is not found, or the state is not 6, it returns NULL and the
handler returns `0xC0010006`. The state is set to **3** by `FilterAttach` (`0x1400058F4`) and
`FilterPause` (`0x140005C07`), and to **6** only by a successful `FilterRestart`
(`0x140006136`). A leaked context is therefore usable only while the filter is running.

The key is the context pointer itself. `0x88992268` leaks it (§5.7); it is not a secret or a random
cookie. The state-6 requirement is an additional precondition the old report did not mention.

### 3.3 Full IOCTL table

All codes use `DeviceType = 0x8899`, `Access = 0` (`FILE_ANY_ACCESS`), `Method = 0`
(`METHOD_BUFFERED`). `BUF` below means METHOD_BUFFERED; `ANY` means FILE_ANY_ACCESS. “key” means
the first qword of `SystemBuffer` must be a live context pointer in state 6; failure returns
`0xC0010006`.

| Code | Fn | Method/Access | In / Out | Gate | Kernel action | Write class |
|---|---|---|---|---|---|---|
| `0x88992264` | 0x899 | BUF/ANY | Out ≥ 4 | none | `*SystemBuffer = 0x00030003`; `Information=4` | W0 (output buffer only) |
| `0x88992268` | 0x89A | BUF/ANY | Out ≥ 0x2284 | none | zero 0x2284; `FUN_140004444` dumps up to 32 contexts; `Information=0x2284` | W0; **kernel pool pointer leak at out+0x2004+8*i** |
| `0x8899226C` | 0x89B | BUF/ANY | In ≥ 0x10 | key/state 6 | `FUN_140007350(ctx, *(u64*)(buf+8))` builds an NBL from the descriptor and sends it | W0; reads attacker pointer; driver-owned NBL copy |
| `0x88992270` | 0x89C | BUF/ANY | In ≥ 0x10 | key/state 6 | `memmove(pool, *(u64*)(buf+8), *(u32*)(src+0x14)+0x135)`; indicate up the stack | W0 for kernel write; **kernel read into receive path (indirect)** |
| **`0x88992274`** | 0x89D | BUF/ANY | In ≥ 0x10 | key/state 6; queue non-empty | pop queue entry; `memmove(*(u64*)(buf+8), entry, *(u32*)(entry+0x14)+0x135)`; `Information=0x10` | **W1 arbitrary-target kernel write** |
| `0x88992278` | 0x89E | BUF/ANY | In ≥ 0xC | key/state 6 | `ctx+0x280 = *(u32*)(buf+8)` | W3 fixed ctx write (capture/queue flags) |
| `0x8899227C` | 0x89F | BUF/ANY | In ≥ 8 | key/state 6 | flush `ctx+0x260` queue to free list; `ctx+0x284 = 0` | W0/W3 fixed ctx |
| `0x88992280` | 0x8A0 | BUF/ANY | In ≥ 0x10 | key/state 6; IRQL 0 | `ObReferenceObjectByHandle(*(u64*)(buf+8), ExEventObjectType)` → `ctx+0x288` | W0 object ref |
| `0x88992284` | 0x8A1 | BUF/ANY | In == Out > 0x10; `len+0x10 ≤ In` | key/state 6 | `NdisFOidRequest(SET)`: OID=`*(u32*)(buf+8)`, InformationBuffer=`*(u64*)(buf+0x10)`, len=`*(u32*)(buf+0xC)` | W0 for kernel write; **OID set reads caller pointer** |
| **`0x88992288`** | 0x8A2 | BUF/ANY | same as 0x8A1 | key/state 6 | `NdisFOidRequest(QUERY)` writes OID result to `*(u64*)(buf+0x10)`, len=`*(u32*)(buf+0xC)` | **W1 arbitrary-target kernel write (value OID-dependent)** |
| `0x8899228C` | 0x8A3 | BUF/ANY | In ≥ 8 | none; IRQL 0 | `ObReferenceObjectByHandle(*(u64*)buf, ExEventObjectType)` → `DAT_14000B0E0` | W0 object ref |
| `0x88992290` | 0x8A4 | BUF/ANY | In ≥ 8 | none; IRQL 0 | same → `DAT_14000B0E8` | W0 object ref |
| `0x88992294` | 0x8A5 | BUF/ANY | In ≥ 8 | key/state 6 | `*SystemBuffer = ctx+0x284`; `Information=4` | W0 read-back (queue count) |
| `0x88992298` | 0x8A6 | BUF/ANY | In ≥ 0xC | key/state 6 | `*(u32*)(buf+8) = ctx+0x280`; `Information=0xC` | W0 read-back |
| `0x889922B0` | 0x8AC | BUF/ANY | In ≥ 8; Out ≥ 0x41804 | key/state 6 | `FUN_140002E14` bulk dump; `Information=0x41804` | W0 |
| `0x889922B4` | 0x8AD | BUF/ANY | In ≥ 0x18 | key/state 6 | loop `count=*(u32*)(buf+8)`, descriptors at `buf+0x10+8*i`; `FUN_140007350` sends each | W0; reads attacker pointers; count not bounded by In |
| `0x889922B8` | 0x8AE | BUF/ANY | In ≥ 0x18 | key/state 6 | loop; `memmove(pool, desc, len+0x135)`; indicate | W0 for kernel write; **kernel read into receive path (indirect)**; count not bounded |
| **`0x889922BC`** | 0x8AF | BUF/ANY | In ≥ 0x18 | key/state 6; queue entries | loop `count=*(u32*)(buf+8)`; `memmove(*(u64*)(buf+0x10+8*i), entry, len+0x135)`; `Information=InLen` | **W1 arbitrary-target kernel write (xN)** |
| `0x889922C0` | 0x8B0 | BUF/ANY | In ≥ 0xC | key/state 6 | `ctx+0x29D = 1` | W3 fixed ctx |
| `0x889922C4` | 0x8B1 | BUF/ANY | In ≥ 0xAC | key/state 6 | `ctx+0x2A4 = *(u32*)(buf+8)`; copy 0xA0 from `buf+0xC` to `ctx+0x2A8` | W3 fixed ctx |
| `0x889922C8` | 0x8B2 | BUF/ANY | In ≥ 9 | key/state 6 | `ctx+0x29F = (buf+8 == 1)` | W3 fixed ctx |
| `0x889922CC` | 0x8B3 | BUF/ANY | In ≥ 9 | key/state 6 | `ctx+0x2A1 = (buf+8 == 1)` | W3 fixed ctx |
| `0x889922D0` | 0x8B4 | BUF/ANY | In ≥ 9 | key/state 6 | `ctx+0x2A2 = (buf+8 == 1)` | W3 fixed ctx |
| `0x889922D4` | 0x8B5 | BUF/ANY | In ≥ 9 | key/state 6 | `*(u8*)(buf+8) = ctx+0x2A1`; `Information=InLen` | W0 read-back; output length not checked |
| `0x889922D8` | 0x8B6 | BUF/ANY | In ≥ 9 | key/state 6 | same for `ctx+0x2A2` | W0 read-back |
| `0x889922DC` | 0x8B7 | BUF/ANY | In ≥ 4 | key/state 6 | sets `ctx+0x240..0x24C`; OID `0xFC01020C` set from `ctx+0x240`, len 0x1C; returns `0x10001` | W3 fixed ctx |
| `0x8899229C`–`0x889922AC` | 0x8A7–0x8AB | BUF/ANY | — | no handler | default `0x10001`; constants appear only in the WPP trace formatter | W0 |

The fixed ctx writes are listed for completeness; none of them gives a caller-chosen destination.
The three arbitrary-target writes are bolded.

### 3.4 The `0x8000` cross-check (requested codes)

| Requested code | Present in this image? | Actual HP equivalent |
|---|---|---|
| `0x8000203C` “arbitrary write” | **No** — zero byte hits; no dispatch comparison | `0x88992274`, `0x889922BC` (queue `memmove`), `0x88992288` (OID query write) |
| `0x80002038` “arbitrary read” | **No** — zero byte hits | `0x88992270`/`0x889922B8` (attacker-pointer read into receive path), `0x88992284` (OID set source); neither is a direct read-to-user |
| `0x80002050` “pointer leak” | **No** — zero byte hits | `0x88992268` (context pointer at out+0x2004+8*i) |

The old HP report (`hp_rtf64x64.static.md`) also contains none of the three `0x8000` codes; it
analyses `0x889922xx`. Those `0x8000` codes are from `bxvbda.sys` (`b06bdrv_detailed.md` V20–V22),
a different driver and a different hash. This audit does not manufacture an HP `0x8000203C`
finding.

## 4. Access-control audit

### 4.1 Gates that exist

1. **Device DACL.** Everyone `GRGW`; all IOCTLs `FILE_ANY_ACCESS`. A standard user can open and
   issue every code. No admin token or privilege is required. This is **R1**.
2. **Context key.** The first qword of the input must equal a live context pointer, and
   `ctx+0x60` must be 6. Failure returns `0xC0010006`. The pointer is leaked unauthenticated by
   `0x88992268` (§5.7), so this is not a secrecy gate.
3. **Composition.** A context exists only after `FilterAttach` (and a successful
   `FilterRestart`). A bare service start leaves `DAT_14000B130` pointing to itself. This is the
   only real gate on the write primitive; it is **R3/composition** and requires admin/network
   configuration to stage (unless the vendor already installed and bound the LWF).

### 4.2 Gates that do not exist

- No `SeAccessCheck`, `SeSinglePrivilegeCheck`, or `RequestorMode` test anywhere in the dispatch
  path. A standard user opener is treated exactly like an administrator.
- No `ProbeForRead`/`ProbeForWrite`; embedded pointers in the METHOD_BUFFERED buffer are used
  directly as kernel pointers.
- No `MmIsAddressValid`/range/alignment check on the write targets.
- No per-IOCTL access mask: `Access=0` on every code.
- No authentication handshake, cookie, or random key. The “key” is the leaked context pointer.

### 4.3 Reach conclusion

**R1 for the device and every IOCTL.** The write primitive is R1 **after** the LWF is bound; the
binding itself is R3/composition and is normally done by the HP/Realtek installer. On a host where
the package is already installed and the filter is bound to the on-board Realtek NIC, a
medium-integrity user needs no further setup. On a host where it is not bound, an administrator can
install/bind the LWF, but an unprivileged user cannot. The canonical report therefore records
`reach=R1` (DACL) and `setup=composition` (context), and rates **MW2**.

## 5. Memory-write trace

### 5.1 `0x88992274` — arbitrary-target `memmove` (queue write)

Switch compare at `0x14000176E`; branch at `0x1400017EF`. The handler:

```
1400017EF  CMP  R15D, 0x10                 ; InLen >= 0x10
1400017F9  LEA  RDX, [RSP+0x48]
1400017FE  MOV  RCX, [RSI]                 ; key = *(u64*)SystemBuffer
140001801  CALL FUN_1400042F0              ; context lookup, state 6
140001812  LEA  R15, [RAX+0x270]           ; queue spinlock
140001842  LEA  RAX, [R14+0x260]           ; queue head is ctx+0x260
140001849  MOV  RBX, [RAX]                 ; first entry
14000189F  MOV  R8D, [RBX+0x14]            ; packet-block data length
1400018A3  ADD  R8, 0x135                  ; + block header
1400018AA  MOV  RDX, RBX                   ; src = packet block
1400018AD  MOV  RCX, [RSI+0x8]             ; dst = *(u64*)(SystemBuffer+8)
1400018B1  CALL 0x140007A00                ; memmove(dst, src, len)
```

`FUN_140007A00` is the compiler's `memmove` (forward/reverse/vector copy; `0x140007A00`). The
destination is a raw 64-bit qword taken from the input buffer; there is no check that it is a user
address, a kernel address, aligned, or mapped. The source is a queued driver packet block (the
WinpkFilter custom block, not an NBL); the length is `block->0x14 + 0x135`, bounded by the max
packet size (`ctx+0x1CC`). `Information` is set to 0x10. After the copy the block is returned to
the free list at `ctx+0x1F8` (`0x1400018C7`).

**Target control: full.** Any canonical 64-bit address. **Value control: constrained.** The copied
bytes are the packet-block header plus packet data. In this block, the list/metadata fields occupy
`+0x00..+0x34`, the packet payload starts at **`+0x34`**, and trailing block metadata fills the
rest of the `len+0x135` copy. The caller can choose `dst = field - 0x34` so the controlled payload
lands on the intended field, but the preceding 0x34 bytes are written too. **Size control:
packet-length-dependent**, up to the max packet size.

### 5.2 `0x889922BC` — arbitrary-target `memmove`, N-at-a-time

Switch compare at `0x140001F03`; branch at `0x140001FF1`. The handler:

```
140001FF1  CMP  R15D, 0x18                 ; InLen >= 0x18
140002003  CALL FUN_1400042F0              ; key/state 6
14000201E  LEA  R14, [RAX+0x270]           ; queue lock
140002025  CMP  [RSI+8], R13D              ; count = *(u32*)(buf+8)
...
1400020BC  MOV  R8D, [RAX+0x14]            ; packet-block data length
1400020C0  ADD  R8, 0x135
1400020CA  MOV  RDX, RAX                   ; src = packet block
1400020CD  MOV  RCX, [RSI+RCX*8+0x10]      ; dst = *(u64*)(buf+0x10+8*i)
1400020D2  CALL 0x140007A00                ; memmove
```

The target is a caller-supplied array of 64-bit addresses at `SystemBuffer+0x10+8*i`; the count is
`*(u32*)(SystemBuffer+8)`. There is no check that the array fits in `InputBufferLength`; only
`InLen >= 0x18` is checked. For `count=1` the target is fully controlled and inside the input. For
`count>1` the driver reads the target array past the declared input (pool OOB read) and writes one
queued entry per target. The loop breaks when the queue is empty. `Information` is set to
`InputBufferLength`, which can exceed the caller's output buffer (user-side overcopy/DoS, not a
kernel write).

**Target control: full for the entries supplied in the input; pool-derived for the OOB tail.**
**Value control: same as §5.1.** **Size control: one entry per target.**

### 5.3 `0x88992288` — OID query into a caller-chosen pointer

`0x88992288` is special-cased at `0x140003F2C` and dispatched to `FUN_140006EB4` at
`0x14000405C`. The argument setup at `0x140004042`–`0x14000405C` is:

```
140004042  CMP  R15D, 0x88992284
140004049  MOV  R9D, [RDI+8]               ; OID = *(u32*)(buf+8)
140004050  SETE R8B                        ; 1 = SET (0x88992284), 0 = QUERY (0x88992288)
140004054  LEA  RAX, [RDI+0x10]            ; buffer = SystemBuffer+0x10
14000405C  CALL FUN_140006EB4
```

Inside `FUN_140006EB4` (`0x140006EB4`):

```
140007029  MOV  [RDI+0x28], RAX            ; InformationBuffer = *(u64*)(buf+0x10)
14000702D  MOV  [RDI+0x30], R12D           ; InformationBufferLength = *(u32*)(buf+0xC)
140007031  MOV  [RDI+0x20], ESI            ; Oid = *(u32*)(buf+8)
14000707E  CALL NdisFOidRequest            ; thunk at 0x14000798C
```

For `0x88992288` (`RequestType = NdisRequestQueryInformation`), NDIS/the miniport **writes** the
OID result to `InformationBuffer`. The pointer is the raw qword at `SystemBuffer+0x10`; there is no
probe, no user/kernel distinction, no range check. The length is the caller-supplied
`*(u32*)(buf+0xC)`, checked only as `len + 0x10 <= InLen` and `InLen == OutLen > 0x10`. The check
ensures the OID data length fits the input buffer; it does **not** ensure the 8-byte pointer field
at `buf+0x10` is fully inside the buffer (with `InLen` 0x11–0x17 the qword is partly read from
adjacent pool memory — an OOB read/DoS, not a controlled target).

The driver's own code proves the query path writes to the supplied pointer:

- `FilterAttach` (`0x1400054B0`) queries OID `0x1010A` into `ctx+0x1CC` (4 bytes) and OID `0x10115`
  into `ctx+0x1C8` (4 bytes);
- `FilterRestart` (`0x140005D90`) queries the same OIDs and OID `0xFC01020B` into a stack buffer
  (0x9C bytes).

These are the same `FUN_140006EB4`/`NdisFOidRequest` path with a caller-supplied buffer. An attacker
can substitute any kernel address and any supported OID. The value is the miniport's query result
(max frame size, TCB count, offload config, multicast list, etc.), not an arbitrary byte string.
**Target control: full. Value control: OID-dependent (W2). Size control: OID-dependent, bounded by
the caller length.**

### 5.4 Is the target truly caller-chosen or constrained?

**Truly caller-chosen** for all three write paths:

- `0x88992274`: `dst = *(u64*)(SystemBuffer+8)`, one qword, no validation.
- `0x889922BC`: `dst[i] = *(u64*)(SystemBuffer+0x10+8*i)`, an array, no validation.
- `0x88992288`: `InformationBuffer = *(u64*)(SystemBuffer+0x10)`, one qword, no validation.

The constraints are on **preconditions**, not on the destination: a live context in state 6, a
non-empty queue for `0x88992274`/`0x889922BC`, and a supported OID for `0x88992288`. The destination
itself is not range-checked, alignment-checked, or restricted to user addresses. The only practical
limitation is that the target must be mapped and writable or the write faults (bugcheck); the
leaked context pointer supplies a known writable kernel address. This is a true write-what-where,
not a fixed-offset or driver-owned write.

Value control is weaker: the queue paths write packet-block metadata plus packet payload; the OID
path writes an OID result. That is why the report uses **W1 for target control** but records the
value constraint explicitly. The old report's “arbitrary write” is correct on the target axis; its
“arbitrary read” claims are weaker (§5.7).

### 5.5 Queue reachability (`0x88992274` / `0x889922BC`)

The queue is at **`ctx+0x260`** (not `ctx+0x4c`; `0x4c` is the qword index the decompiler prints,
which is byte offset `0x260`). It is initialized by `FUN_140001000` from `FilterAttach`
(`0x1400058FC`), and its count is `ctx+0x284`.

The queue is fillable by the attacker:

1. `0x88992278` sets `ctx+0x280` from `*(u32*)(buf+8)` (`0x1400017A4`). These are the per-context
   capture/queue flags.
2. The send path `FUN_140002654` and receive path `FUN_1400024A8` check those flags
   (`ctx+0x280 & 5` / `& 0xA`) and call `FUN_1400012A4` to select a filter action.
3. With the global static-filter table `DAT_14000B0D0` empty (its `.data` initial value is zero),
   `FUN_1400012A4` returns **3** (queue) at `0x1400012DE`. Action 3 inserts the packet block at
   `ctx+0x260` and increments `ctx+0x284` (`0x140002566`–`0x14000258B` for receive,
   `0x140002729`–`0x140002737` for send).
4. The attacker can read the queue count with `0x88992294` (`0x140001C3E` returns `ctx+0x284`) and
   generate local traffic (e.g. a packet with a chosen payload) until the count is non-zero.
5. `0x88992274` then pops one entry and writes it to the chosen target; `0x889922BC` pops up to
   `count` entries and writes each to its chosen target.

The old report's caveat “the queue may be empty” is factually true but understates the path: the
flags and the default action make the queue fillable by ordinary local traffic. The remaining
uncertainty is the exact NDIS send/receive path selected on a given adapter; see §9.

### 5.6 Fixed/driver-owned writes (not the verdict driver)

| Code | Target | Size/value | Class |
|---|---|---|---|
| `0x88992278` | `ctx+0x280` | 4-byte flags | W3 fixed |
| `0x889922C4` | `ctx+0x2A4`, `ctx+0x2A8` | 4 bytes + 0xA0-byte copy | W3 fixed |
| `0x889922DC` | `ctx+0x240..0x24C` | fixed fields; OID set | W3 fixed |
| `0x889922C0` | `ctx+0x29D` | 1 byte | W3 fixed |
| `0x889922C8` | `ctx+0x29F` | 1 byte | W3 fixed |
| `0x889922CC` | `ctx+0x2A1` | 1 byte | W3 fixed |
| `0x889922D0` | `ctx+0x2A2` | 1 byte | W3 fixed |
| `0x8899227C` | queue/free list | list manipulation | W0/W3 |

These require a valid context but do not let the caller choose the address. The `0x889922C4` copy
is 0xA0 bytes from `buf+0xC` to `ctx+0x2A8`, and the check is `InLen >= 0xAC`; the source ends at
`buf+0xAC`, so there is no over-read (the old report's “0xA8 bytes” is off by 8).

### 5.7 Reads and leaks (context for the write)

| Code | What it does | Direct to user? |
|---|---|---|
| **`0x88992268`** | `FUN_140004444` zeroes 0x2284 and dumps up to 32 contexts. At `0x14000459B` it stores each context pointer at **`out+0x2004+8*i`**; the copy to `SystemBuffer` is at `0x1400045FF`. | **Yes — unauthenticated kernel pool pointer leak.** The pointer is also the context key. |
| `0x88992270` | `memmove(pool, *(u64*)(buf+8), *(u32*)(src+0x14)+0x135)` (`0x1400019A1`/`0x1400019B3`), then `NdisFIndicateReceiveNetBufferLists` (`0x1400019C3`). | **No direct copy.** The data is copied into a driver packet block and indicated up the receive path; a raw socket may or may not see it, and the bytes must look like a packet. It is a kernel read into the receive stack, not a read-to-user API. |
| `0x889922B8` | Loop mirror of `0x88992270`; `memmove(pool, desc, len+0x135)` then indicate. | Same indirect behaviour. |
| `0x88992284` | OID SET reads from `*(u64*)(buf+0x10)`; the miniport consumes the data. | No direct copy to the caller. |
| `0x8899226C` / `0x889922B4` | Descriptor reads from attacker pointers; `FUN_140007350` builds an NBL and sends it. The NBL data copy is at `0x140007566` (destination is the driver's NBL buffer, length checked against `ctx+0x1CC`). | No direct copy. |
| `0x88992294` / `0x88992298` / `0x889922D4` / `0x889922D8` | Fixed context read-backs. | Yes, but only driver-owned fields (queue count, flags). |
| `0x889922B0` | Bulk dump of the context list. | Yes, but driver-owned adapter data. |

The only direct, unauthenticated kernel address leak is **`0x88992268`**. It leaks a **pool**
pointer (the context), not the `ntoskrnl`/driver image base. It defeats the key gate and gives a
known writable kernel target; it is not a full KASLR image-base leak. The old report's
“removing KASLR as a barrier” is stronger than the evidence.

### 5.8 Memory-write APIs that are absent

- No `MmMapIoSpace`, `MmCopyMemory`, `MmGetPhysicalAddress`, `ZwMapViewOfSection`, or
  `\Device\PhysicalMemory` access. **No W3P physical-memory primitive.**
- No `WRITE_PORT_*`/`READ_PORT_*`, MSR, PCI config, SMBus/EC, or fixed-window MMIO. **No HW-ONLY
  path.**
- `MmMapLockedPagesSpecifyCache` at `0x14000751B` is used only on the NBL's own MDL in
  `FUN_140007478`, to copy packet data into a driver-owned NBL buffer; it is not caller-mapped and
  is not a memory-write primitive.
- The `NdisFOidRequest` path is the only indirect kernel write; the `memmove` paths are direct.

## 6. Setup and reachability

### 6.1 Device exists without a miniport; context does not

- `DAT_14000B130` is initialized to point to itself in DriverEntry (`0x14000E475`); the list is
  empty.
- `FilterAttach` (`FUN_1400054B0`, `0x1400054B0`) is the **only** writer of the context list. It
  allocates a context (`FUN_14000543C`), sets state 3 (`0x1400058F4`), initializes the queue
  (`0x1400058FC`), and inserts the context at `0x14000592F`–`0x140005951`.
- `FilterRestart` (`FUN_140005D90`, `0x140005D90`) sets state 6 at `0x140006136` after the
  per-context pool/OID setup. `FilterPause` (`FUN_140005BA0`, `0x140005BA0`) sets state 3 at
  `0x140005C07`. `FilterDetach` (`FUN_140005980`) removes the node and frees it.
- No IOCTL, registry value, or DriverEntry path allocates/inserts a context. The only way to get
  one is for NDIS to call `FilterAttach`, which happens when the LWF is bound to a miniport.
- The device object and `\DosDevices\RTF64` are created in DriverEntry **before** any attach, so
  they exist with an empty list.

### 6.2 Configuration table

| Configuration | `\Device\RTF64` | Context list | Arbitrary write reachable? |
|---|---|---|---|
| `sc create`/`sc start` only (no INF/binding; if `NdisFRegisterFilterDriver` succeeds) | yes | empty (`DAT_14000B130` self) | **No.** Keyed IOCTLs return `0xC0010006`; `0x88992268` returns count 0 and 0x2284 zeros; only `0x88992264`, `0x88992268` (count 0), `0x8899228C`, `0x88992290` do anything, all buffer/object-bounded. |
| INF install + LWF bound to a running NIC, filter restarted | yes | ≥1, state 6 | **Yes.** Unauthenticated leak + key → `0x88992274`/`0x889922BC`/`0x88992288`. |
| INF install + filter attached but paused/not restarted | yes | context state 3 | **No.** Lookup requires `ctx+0x60 == 6`; all keyed IOCTLs return `0xC0010006`. |

### 6.3 Can the LWF be instantiated without a bound miniport?

**The device, yes. The usable context, no.** A bare service start creates the device object but
`FilterAttach` is only called by NDIS when a filter module is attached to a miniport. There is no
user-mode or IOCTL path that manufactures a context. Therefore:

- **Service-only is inert** for the write primitive. This is the decisive setup finding.
- **Composition is required**: the LWF must be installed and bound to at least one running
  miniport. This is a larger NDIS stack, not a devnode and not a physical dongle. An administrator
  can stage it with a real NIC or a virtual/loopback miniport; an unprivileged user cannot.
- On a normal HP machine where the vendor package has already installed and bound the LWF to the
  on-board Realtek NIC, the attacker-side setup is effectively **none**; the unauthenticated chain
  is live. The canonical rating still records `setup=composition` because the binding is the
  prerequisite that may be absent on an arbitrary host.

### 6.4 Old-report setup table vs current

The old report's table is essentially correct: service-only creates the device and leaves the
context list empty; the normal INF/bound state is live. This re-audit adds the **state-6**
requirement (attach alone is not enough; the filter must be restarted) and the fact that the queue
can be filled by the caller, which the old report treated as an uncertain precondition.

## 7. Most dangerous exposed capability and severity

### 7.1 Chain

1. A standard user opens `\\.\RTF64` (Everyone `GRGW`; no admin token).
2. `0x88992268` returns the context pointer array at `out+0x2004`; the first live pointer is both
   the kernel pool address disclosure and the key for every privileged IOCTL.
3. `0x88992294` confirms the queue count; `0x88992278` sets the capture/queue flags.
4. The user generates local traffic; the send/receive path queues packet blocks at `ctx+0x260`
   (default filter action 3 when the static table is empty).
5. `0x88992274` (one entry) or `0x889922BC` (N entries) writes the queued packet blocks to
   caller-chosen 64-bit kernel addresses. `0x88992288` gives a queue-free OID-query write to a
   caller-chosen address once the context is live.

The result is a **kernel virtual-address write with a fully caller-chosen destination**, from a
world-writable device, after a leak that any opener can perform. The value is constrained, and a
bad destination bugchecks, but the leaked context supplies a known writable target.

### 7.2 Severity reasoning

| Candidate | Why not |
|---|---|
| **MW1** | Requires `Setup: none` and a ready arbitrary write. Here a usable context requires an NDIS LWF binding (composition), and the key comes from a leak. Not MW1 on the canonical scale. On an HP host where the vendor already bound the filter, the attacker-side setup is effectively none; that host is MW1-equivalent in practice. |
| **MW2** | **Selected.** A real arbitrary-target kernel VA write, but composition-gated and leak-assisted. This matches the canonical `rtf64x64 composition` MW2 example in `SEVERITY.md`. |
| MW3 | Not physical-memory-only; the writes are kernel VA, not PA mappings. |
| MW4 | The target is not fixed; it is a fully caller-chosen 64-bit address. |
| NO-MEMORY-WRITE | Rejected: `0x88992274`/`0x889922BC`/`0x88992288` write to caller-chosen kernel VAs; this is not HW-ONLY, a fixed output buffer, or an info-leak-only path. |
| BLOCKED | Signed (Authenticode valid), not in `known_bad_hashes.txt`, component present. HVCI not disproven. |

**Final:** `MW2 — reach=R1 setup=composition write=W1 load=signed`.

## 8. Discrepancies vs the old report

| Old report claim | Current finding |
|---|---|
| `WRITE-HIGH` | **MW2**; old label not inherited. |
| Device SDDL `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)`; Everyone `GRGW` | **Confirmed** at `0x1400091D0`; effective R1. |
| `0x88992268` leaks context pointers at `out+0x2004+8*i`; no key | **Confirmed**; pointer store `0x14000459B`; copy `0x1400045FF`. |
| Key = first qword = list-node address | **Confirmed**, plus the omitted **`ctx+0x60 == 6`** state check at `0x1400043D9`. Attach alone sets 3; restart sets 6. |
| `0x88992274` writes `*(u64*)(buf+8)` from the queue; `len = entry->0x14 + 0x135` | **Confirmed** (`0x1400018AD`, `0x1400018B1`). Queue head is **`ctx+0x260`**, not `ctx+0x4c` (qword-index/byte-offset confusion). |
| `0x88992274` requires a non-empty queue; may return `0xC0000001` | **Confirmed**, but the queue is fillable: `0x88992278` flags, default action 3 at `0x1400012DE`, inserts at `ctx+0x260` (`0x140002566`, `0x140002737`). |
| `0x889922BC` writes N queued packets to `buf+0x10+8*i` | **Confirmed** (`0x1400020CD`, `0x1400020D2`); count is not bounded by `InLen`, so the target array can be read OOB (DoS/read). |
| `0x88992288` OID query writes to `*(u64*)(buf+0x10)` | **Confirmed** (`0x140007029`, `0x14000707E`); the driver's own `0x1010A`/`0x10115`/`0xFC01020B` queries prove the path. Value is OID-dependent. |
| `0x88992270` “arbitrary read” | **Partly.** It is a kernel read into a driver packet block that is then indicated as an NBL up the receive path (`0x1400019B3`/`0x1400019C3`), not a direct read-to-user. The direct leak is `0x88992268`. |
| `0x88992284` “arbitrary read” | OID SET reads from a caller pointer; the miniport consumes the data. Not a direct user leak. |
| `0x889922C4` copies 0xA8 bytes | Actual **0xA0** bytes from `buf+0xC`; check `InLen >= 0xAC`; the source ends at `buf+0xAC`, no over-read. |
| `0x889922D4`/`D8` set `Information=InputBufferLength` | Confirmed; user-side overcopy/DoS, not a kernel write. |
| WMI is not an independent write | **Confirmed**: `IRP_MJ_SYSTEM_CONTROL` is NULL; the `IoWMIRegistrationControl` call at `0x14000D113` is WPP trace registration, not a data provider. |
| Setup: composition | **Confirmed**; device at service start, context only after `FilterAttach` + state 6. |
| `0x8000203C`/`0x80002038`/`0x80002050` | **Not in this image**; those are `bxvbda.sys` codes. The HP equivalents are in §3.4. |

## 9. Limitations

- **Static only.** No driver load, service creation, registry write, or dynamic IOCTL. The
  effective DACL is derived from the `DefaultSDDLString` passed to `NdisRegisterDeviceEx`; a
  runtime `!sd`/security-descriptor dump was not performed.
- **OID value control is miniport-dependent.** The driver's own queries prove that OIDs `0x1010A`,
  `0x10115`, and `0xFC01020B` write to the supplied buffer. Arbitrary-content OIDs (e.g. a
  set-then-query multicast list) were not dynamically verified. The queue path is the better
  value-controlled write.
- **Queue fill depends on the NDIS path.** With the static-filter table empty, `FUN_1400012A4`
  returns action 3 and the send/receive paths queue matching packets; the exact adapter/path
  selection and the effect of the `ctx+0x280` flags on a given NIC were not dynamically tested.
- **Leaked pointer is a pool pointer, not an image base.** It defeats the key gate and gives a
  known writable target, but exploitation would still require a target layout; this report does not
  analyse one and contains no exploit code.
- **Loadability under HVCI** was not dynamically verified. The Authenticode signature is valid,
  the hash is not in `known_bad_hashes.txt`, and the image is a normal NDIS LWF; no evidence of a
  block was found. If a runtime HVCI block is confirmed, the status becomes `BLOCKED` while the
  static primitive remains MW2.
- **No PDB symbols.** Ghidra function names (`FUN_*`, `DAT_*`) are synthetic; the PDB is referenced
  but not loaded. Addresses are image-base-relative (`0x140000000`).
- **The `0x8000` codes are absent.** If the requester intended a different HP build, that build has
  a different SHA-256 and must be re-audited; this report is only valid for
  `DFB5842CBF748C9707B7369907C23B73218C58B593F2ED589357753EB36DA40E`.
- **Method disclosure.** REA's Ghidra 12.1.4 provider was available and used for decompilation;
  `objdump` (LLVM 20.1.5, msys64 clang64) was used for independent instruction/PE cross-checks. No local
  Ghidra 12.1.4 installation was present on this host. REA evidence IDs retained for the
  decompilation cross-checks: `ev_46b4be0ef392b8179fb1a8e04e861090edc996b2f6ea4f582d94d75b7b99e64e`
  (binary overview), `ev_a2caf257a4d1c26f15c6639ad7ec3d4258131ae19f00b00738c77cbf1ed58240` (batch
  decompile), `ev_bcba534a18ecf7d3081950030e4a637346e55f3b86af5a8d064854f43d04b183` (DriverEntry).
  The report's cited instruction addresses were re-checked against the raw PE with `objdump`.

## 10. Address index

| Address | Meaning |
|---|---|
| `0x14000E000` | `DriverEntry` (`FUN_14000e000`) |
| `0x14000E590` | PE entry stub |
| `0x14000E47F` | `NdisFRegisterFilterDriver` call |
| `0x14000E4C5` | `NdisAllocateNetBufferListPool` call |
| `0x14000E4EE` | `FUN_14000410C` device-registration call |
| `0x14000410C` | device registration (`NdisRegisterDeviceEx`) |
| `0x1400091D0` | SDDL string (UTF-16, 57 chars) |
| `0x140009270` / `0x140009290` | `\Device\RTF64` / `\DosDevices\RTF64` |
| `0x140004132`–`0x1400041A6` | SDDL stack copy |
| `0x1400041AD` | `UNICODE_STRING` length 0x72 / max 0x74 |
| `0x140004283` | `NdisRegisterDeviceEx` call |
| `0x1400041CB` | `MajorFunctions` memset (0xE0) |
| `0x1400041D7` / `0x1400041EB` / `0x1400041E2` | CREATE / CLOSE / CLEANUP entries |
| `0x1400041F6` / `0x1400041FA` | DEVICE_CONTROL / INTERNAL_DEVICE_CONTROL entries |
| `0x140003E60` | `IRP_MJ_DEVICE_CONTROL` handler |
| `0x140003F2C` | `0x88992284`/`0x88992288` special-case |
| `0x140003F62` | call to `FUN_1400016CC` |
| `0x1400042F0` | context lookup |
| `0x1400043D9` | `cmpl $0x6, 0x60(%rbx)` state-6 check |
| `0x140004444` | context dump / leak |
| `0x14000459B` | context pointer store at `out+0x2004` |
| `0x1400045FF` | dump copy to `SystemBuffer` |
| `0x1400016CC` | main IOCTL switch |
| `0x14000176E` | `0x88992274` compare |
| `0x1400018AD` / `0x1400018B1` | `0x88992274` dst load / `memmove` |
| `0x140001F03` | `0x889922BC` compare |
| `0x1400020CD` / `0x1400020D2` | `0x889922BC` dst load / `memmove` |
| `0x140004042` | `0x88992284`/`0x88992288` argument setup |
| `0x14000405C` | call to `FUN_140006EB4` |
| `0x140006EB4` | OID request builder |
| `0x140007029` | `InformationBuffer` assignment |
| `0x14000702D` | `InformationBufferLength` assignment |
| `0x140007031` | OID assignment |
| `0x14000707E` | `NdisFOidRequest` call |
| `0x1400054B0` | `FilterAttach` |
| `0x1400058F4` | state 3 at attach |
| `0x14000592F`–`0x140005951` | context list insertion |
| `0x1400058FC` | queue init at `ctx+0x260` |
| `0x140005D90` | `FilterRestart` |
| `0x140006136` | state 6 at restart |
| `0x140005BA0` | `FilterPause` |
| `0x140005C07` | state 3 at pause |
| `0x140005980` | `FilterDetach` |
| `0x1400017A4` | `ctx+0x280` flags write (`0x88992278`) |
| `0x140001C3E` | queue-count read (`0x88992294`) |
| `0x1400012DE` | default filter action 3 |
| `0x140002566`–`0x14000258B` | receive-path queue insert / count |
| `0x140002729`–`0x140002737` | send-path queue insert / count |
| `0x140007350` | descriptor → NBL send |
| `0x140007478` | NBL builder |
| `0x14000751B` | `MmMapLockedPagesSpecifyCache` (NBL MDL only) |
| `0x140007566` | NBL data copy (driver-owned destination) |
| `0x140007A00` | `memmove` |
| `0x1400019A1` / `0x1400019B3` / `0x1400019C3` | `0x88992270` src / `memmove` / indicate |
| `0x14000B130` | context list head |
| `0x14000B140` | context list spinlock |
| `0x14000B0D0` | global static-filter table |
| `0x14000B0D8` | global NBL pool |
| `0x14000B118` | device object |
| `0x14000B158` | filter handle |

## 11. References

- `audits/reports/hp_rtf64x64.static.md` — old-scope report; superseded by this file.
- `audits/reports/b06bdrv_detailed.md` — `bxvbda.sys` V20–V22; source of the `0x8000203C`,
  `0x80002038`, `0x80002050` codes that the task attributed to this driver.
- `audits/scope/SEVERITY.md` — MW1–MW4 scale; `rtf64x64 composition` is the canonical MW2 example.
- `audits/scope/AUDIT_SCOPE.md` — reach/setup fields and what counts.
- `audits/STATUS.md` — historical `WRITE-HIGH` entry for HP `rtf64x64`; this report replaces that
  verdict for the exact hash.
