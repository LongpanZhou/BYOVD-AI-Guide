# Static audit - `rtf64x64_DFB5842C.sys` (HP / Realtek NDIS LWF, 3.15.1128.2025)

| | |
|---|---|
| Target | `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected2\drivers\HP\rtf64x64_DFB5842C.sys` |
| Size / MD5 | 72,344 bytes / `c2df4ef50269589c836c0a0b737f2ef0` |
| Type | NDIS 6.40 LightWeight Filter (LWF), x64, PE32+ |
| Internal name | `rtf64` - "Realtek NDIS LightWeight Filter (NDIS 6.40)" |
| Tooling | Ghidra 12.1.4 headless, static only. No driver loaded, no VM touched. |

---

## 1. Verdict

**WRITE-HIGH**

The driver exposes a *user-controlled kernel pointer dereference* through its IOCTL interface, and it hands the attacker the key needed to reach it:

1. `\Device\RTF64` is created in **DriverEntry** with `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)` - **Everyone gets `GRGW`** (read+write).
2. IOCTL **`0x88992268`** (no key required) returns a 0x2284-byte dump that contains, at offset `0x2004 + 8*i`, the **kernel virtual address of every attached adapter context** (`FUN_140004444`).
3. That pointer is the lookup key for every privileged IOCTL (`FUN_1400042f0` compares the first qword of the user buffer to list-node addresses).
4. With a valid key, several IOCTLs take further qwords out of the same METHOD_BUFFERED buffer and use them **as kernel pointers without any validation**:
   * `0x88992288` -> `NdisFOidRequest(Query, InformationBuffer = *(u64*)(buf+0x10), len = *(u32*)(buf+0xC))` - NDIS/miniport **writes the OID result to an arbitrary address** ("write-what-where", content partly attacker-selectable via a prior `0x88992284` OID set). **No queue/state precondition** beyond the context key.
   * `0x88992274` / `0x889922BC` -> `memmove(dst = *(u64*)(buf+8) [+8*i], src = queued packet, len = packet_len+0x135)` - **arbitrary kernel write** (requires a non-empty per-context queue, see section 6).
   * `0x88992270` / `0x88992284` -> the mirror image: `memmove(src = attacker pointer)` / OID set - **arbitrary kernel read**.

**Caveat that matters for grading (see section 9):** steps 2-4 require at least one adapter context, i.e. the filter must be *attached to a NIC*. Attachment happens only via `FilterAttach` (`FUN_1400054b0`), which is the **only** place the context list `DAT_14000b130` is populated. A bare `sc create` + `sc start` creates the device (and its weak DACL) but leaves the list empty, so every privileged IOCTL returns `0xC0010006`. In the driver's **normal installed state** (HP/Realtek LWF bound to the on-board Realtek NIC - no extra hardware, no devnode) the full chain is live for any local user.

---

## 2. Device surface and when it is created

`FUN_14000e000` = **DriverEntry** (`0x14000e000`, size 1416). Order of operations:

```
14000e47f  CALL NdisFRegisterFilterDriver        ; -> DAT_14000b158 (filter handle)
14000e4..  NdisAllocateNetBufferListPool
14000e4ee  CALL FUN_14000410c                    ; <-- FilterRegisterDevice
```

`FUN_14000410c` (`14000410c`, "==>FilterRegisterDevice") is the only device-creation path. It is called **once, from DriverEntry, immediately after `NdisFRegisterFilterDriver` succeeds** - *before and independently of* any `FilterAttach`. `FilterAttach` (`FUN_1400054b0`, string `"===>FilterAttach: NdisFilterHandle %p"`) only allocates the per-adapter context and links it into `DAT_14000b130`; it does not create the device.

So:

* `\Device\RTF64` + `\DosDevices\RTF64` exist as soon as the service starts and `NdisFRegisterFilterDriver` returns success.
* The device's security descriptor is fixed at creation from the SDDL below; it does not depend on any adapter.
* The device's `ExtensionSize` is `0x10`; after creation the driver writes a `'DRTF'` (`0x46544452`) tag and the filter handle into the reserved extension (`14000429a`).

---

## 3. Effective DACL (call-site + decompiled snippet)

Attributes structure built on the stack at `[rsp+0x30]`, passed as arg 2 to `NdisRegisterDeviceEx` (`140004283`). Layout matches the WDK `NDIS_DEVICE_OBJECT_ATTRIBUTES` (`km\ndis.h`, 10.0.26100.0): `Header / DeviceName / SymbolicName / MajorFunctions / ExtensionSize / DefaultSDDLString / DeviceClassGuid`, `NDIS_SIZEOF_..._REVISION_1 = 0x38`.

```
140004132  0f 28 05 97 50 00 00   MOVAPS  XMM0, [0x1400091d0]      ; "D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)"
...
14000419b  48 8d 45 70            LEA     RAX, [RBP+0x70]          ; stack copy of the SDDL (57 chars)
1400041ad  c7 44 24 20 72 00 74 00 MOV     dword [RSP+0x20], 0x740072  ; UNICODE_STRING: Length=0x72, MaxLength=0x74
1400041b5  48 89 44 24 28         MOV     [RSP+0x28], RAX          ;   -> Buffer
...
140004246  48 83 64 24 60 00      AND     qword [RSP+0x60], 0      ; DeviceClassGuid = NULL
140004251  48 89 44 24 38         MOV     [RSP+0x38], RAX          ; DeviceName     = &"\Device\RTF64"
14000425b  48 89 44 24 40         MOV     [RSP+0x40], RAX          ; SymbolicName   = &"\DosDevices\RTF64"
140004260  48 8d 45 90            LEA     RAX, [RBP-0x70]          ; 28-entry MajorFunctions table
140004264  48 89 44 24 48         MOV     [RSP+0x48], RAX          ; MajorFunctions
140004269  48 8d 44 24 20         LEA     RAX, [RSP+0x20]
14000426e  48 89 44 24 58         MOV     [RSP+0x58], RAX          ; DefaultSDDLString = &SDDL_UNICODE_STRING
140004273  c7 44 24 30 85 01 38 00 MOV     dword [RSP+0x30], 0x380185 ; NDIS_OBJECT_HEADER{Type=0x85, Rev=1, Size=0x38}
14000427b  c7 44 24 50 10 00 00 00 MOV     dword [RSP+0x50], 0x10   ; ExtensionSize = 16
140004283  e8 d8 35 00 00         CALL    NdisRegisterDeviceEx
```

Decompiled equivalent (`FUN_14000410c`):

```c
RtlInitUnicodeString(local_1a0, L"\\Device\\RTF64");
RtlInitUnicodeString(local_190, L"\\DosDevices\\RTF64");
local_1d4 = 0;  local_1a8 = 0;
local_1d0 = local_1a0;   local_1c8 = local_190;
local_1c0 = local_178;   /* MajorFunctions[28] */
local_1b8 = 0x10;        /* ExtensionSize                    */
local_1b0 = local_1e8;   /* UNICODE_STRING {0x72,0x74,"D:P(A;;GA;;;SY)..."} */
local_1d8 = 0x380185;    /* Header                           */
uVar1 = NdisRegisterDeviceEx(DAT_14000b158, &local_1d8, &DAT_14000b118);
```

SDDL string at `0x1400091d0` (UTF-16, `0x72` = 114 bytes, `0x74` max):

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)
      ^SY=Full     ^BA=GRGWGX  ^WD=GRGW (Everyone) ^RC=GR
```

`P` = protected (no inheritance). Effective result: **any authenticated local user (indeed `Everyone`) can open the device with `GENERIC_READ|GENERIC_WRITE`.**

---

## 4. Dispatch handlers

`MajorFunctions` is a 28-entry table (`0xE0` bytes = 28x8, `memset` at `1400041cb`, size `0xe0`) filled at these sites:

| index | IRP major | handler | set at |
|---|---|---|---|
| 0x00 | `IRP_MJ_CREATE` | `FUN_1400040a0` (0x1400040a0) | `1400041d7` |
| 0x02 | `IRP_MJ_CLOSE` | `FUN_1400040a0` | `1400041eb` |
| 0x0E | `IRP_MJ_DEVICE_CONTROL` | `FUN_140003e60` (0x140003e60) | `1400041f6` |
| 0x0F | `IRP_MJ_INTERNAL_DEVICE_CONTROL` | `FUN_140003e60` | `1400041fa` |
| 0x12 | `IRP_MJ_CLEANUP` | `FUN_1400040a0` | `1400041e2` |
| all others (incl. **0x03 READ, 0x04 WRITE**, 0x0D FSCTL, 0x17 SYSTEM_CONTROL) | - | **NULL** | - |

* `FUN_1400040a0` is a shared trivial create/close/cleanup handler: it switches on `Irp->Tail.Overlay.CurrentStackLocation->MajorFunction` (`**(char**)(irp+0xb8)`), bumps/decrements a global open counter `DAT_14000b120`, and completes with `IoStatus.Status = 0` / `Information = 0`.
* `FUN_140003e60` is the device-control handler. It reads
  `StackLocation+0x18` = `Parameters.DeviceIoControl.IoControlCode`,
  `+0x10` = `InputBufferLength`, `+0x08` = `OutputBufferLength`,
  and `Irp->AssociatedIrp.SystemBuffer` (`irp+0x18`).
  It never looks at `Irp->UserBuffer` (`irp+0x70`), never checks `RequestorMode`, and contains **no `ProbeForRead` / `ProbeForWrite`** (neither is imported).
* **`IRP_MJ_WRITE` is not hooked** - `WriteFile()` on the device is completed by the I/O manager with `STATUS_INVALID_DEVICE_REQUEST`. There is no `WRITE` code path at all.

---

## 5. IOCTL table

All codes share `DeviceType = 0x8899`, `Access = 0` (**FILE_ANY_ACCESS**), `Method = 0` (**METHOD_BUFFERED**), function `0x899..0x8B7`. Because the access bits are 0, no additional access check is done on `DeviceIoControl` - the `WD` `GRGW` ACE is sufficient.

Two dispatch layers:
* `FUN_140003e60` special-cases `0x88992284` / `0x88992288` (OID pass-through), then calls
* `FUN_1400016cc(ioctl, SystemBuffer, InLen, SystemBuffer, OutLen, &written)` for everything else.

Buffer layout for keyed calls: `buf+0x00` = **context key** (kernel pointer to an adapter context), `buf+0x08` / `buf+0x10...` = payload; some payload fields are dereferenced as pointers.

| IOCTL | func | InLen req | OutLen req | block | what it does | sink |
|---|---|---|---|---|---|---|
| `0x88992264` | 0x899 | - | >=4 | `140001ab9` | writes `0x00030003`, `Information=4` | benign (buffer) |
| **`0x88992268`** | 0x89A | - | **>=0x2284** | `140001a89` | `FUN_140004444`: dumps up to 32 adapter records; **stores each context pointer at `out+0x2004+8*i`**; `Information=0x2284` | **kernel pointer leak** |
| `0x8899226C` | 0x89B | >=0x10 | - | `140001a1a` | `FUN_140007350`: builds NBL from `*(u64*)(buf+8)` descriptor and `NdisFSendNetBufferLists` | reads attacker pointer |
| **`0x88992270`** | 0x89C | >=0x10 | - | `140001958` | `memmove(kalloc, *(u64*)(buf+8), *(u32*)(src+0x14)+0x135)`; indicate + queue | **arb read** |
| **`0x88992274`** | 0x89D | >=0x10 | - | `1400017ef` | pops one queued packet, `memmove(*(u64*)(buf+8), entry, entry->0x14+0x135)`, `Information=0x10` | **arb WRITE** |
| `0x88992278` | 0x89E | >=0xC | - | `140001784` | `ctx+0x280 = *(u32*)(buf+8)` | ctx only |
| `0x8899227C` | 0x89F | >=8 | - | `140001adb` | flush `ctx+0x4c` queue back to `ctx+0x1f8` free list | ctx only |
| `0x88992280` | 0x8A0 | >=0x10 | - | `140001d79` | `ObReferenceObjectByHandle(*(u64*)(buf+8), 0x100000, ExEventObjectType, 1)` -> `ctx+0x288` | handle-checked |
| **`0x88992284`** | 0x8A1 | `InLen==OutLen`, >0x10, `*(u32*)(buf+0xC)+0x10 <= InLen` | same | `140004042` | `NdisFOidRequest(Set, Oid=*(u32*)(buf+8), InformationBuffer=*(u64*)(buf+0x10), Len=*(u32*)(buf+0xC))` | **arb read** (src ptr) |
| **`0x88992288`** | 0x8A2 | idem | idem | `140004042` | same but **Query** -> NDIS **writes** OID data to `*(u64*)(buf+0x10)` | **arb WRITE** |
| `0x8899228C` | 0x8A3 | >=8 | - | `140001ce8` | `ObReferenceObjectByHandle(*(u64*)buf)` -> global `DAT_14000b0e0` | handle-checked |
| `0x88992290` | 0x8A4 | >=8 | - | `140001c57` | same -> `DAT_14000b0e8` | handle-checked |
| `0x88992294` | 0x8A5 | >=8 | - | `140001c22` | returns `*(u32*)(ctx+0x284)`, `Information=4` | read-back helper |
| `0x88992298` | 0x8A6 | >=0xC | - | `140001bdd` | writes `*(u32*)(ctx+0x280)` to `buf+8`, `Information=0xC` | read-back helper |
| `0x889922B0` | 0x8AC | >=8 | **>=0x41804** | `140001e76` | `FUN_140002e14`: dumps up to 256 entries x 0x418 B from `ctx+0x210` | bulk info dump |
| `0x889922B4` | 0x8AD | >=0x18 | - | `140002252` | loop `count=*(u32*)(buf+8)`, descriptors at `buf+0x10+8*i` -> `FUN_140007350` send each | reads attacker pointers |
| `0x889922B8` | 0x8AE | >=0x18 | - | `14000217e` | same but `memmove(kalloc, desc, len+0x135)` + indicate + queue | **arb read** |
| **`0x889922BC`** | 0x8AF | >=0x18 | - | `140001ff1` | pops `count` queued packets into `*(u64*)(buf+0x10+8*i)` destinations | **arb WRITE (xN)** |
| `0x889922C0` | 0x8B0 | >=0xC | - | `140001fc5` | `ctx+0x29d = 1` | ctx only |
| `0x889922C4` | 0x8B1 | >=0xAC | - | `1400022d0` | `ctx+0x2a4 = *(u32*)(buf+8)`; copies 0xA8 B from `buf+0xC` into `ctx+0x2a8` | bounded ctx write |
| `0x889922C8` | 0x8B2 | >=9 | - | `140002343` | `ctx+0x29f = (*(u8*)(buf+8)==1)` | ctx only |
| `0x889922CC` | 0x8B3 | >=9 | - | `14000244b` | `ctx+0x2a1 = ...` | ctx only |
| `0x889922D0` | 0x8B4 | >=9 | - | `140002421` | `ctx+0x2a2 = ...` | ctx only |
| `0x889922D4` | 0x8B5 | >=9 | - | `140002401` | reads `ctx+0x2a1` to `buf+8` | read-back |
| `0x889922D8` | 0x8B6 | >=9 | - | `1400023d1` | reads `ctx+0x2a2` to `buf+8` | read-back |
| `0x889922DC` | 0x8B7 | >=4 | - | `14000233c` | configures `ctx+0x240`, then `FUN_140006eb4(..., OID 0xfc01020C ..., ctx+0x240, 0x1c)`; returns `0x10001` | ctx only |
| `0x8899229C...0x889922AC` | 0x8A7-0x8AB | - | - | not in `FUN_1400016cc` | returns `0x10001` (these constants appear only in the WPP trace formatter `FUN_1400030d0`) | - |

`FUN_1400030d0` looks like a second dispatcher but is **only** called from `FUN_1400030b4`, the WPP trace-string builder - it is a `switch(ioctl)` that formats a debug message, not a handler.

---

## 6. Write sinks (with the decompiled lines)

### S1 - `0x88992288`, OID query into an attacker pointer

`FUN_140003e60` @ `140003fe7...14000405c`:

```c
puVar7 = *(undefined8 **)(param_2 + 0x18);          // SystemBuffer
puVar10 = FUN_1400042f0((undefined8 *)*puVar7, &local_res18);   // ctx lookup by leaked key
if (puVar10 != 0) {
  uVar3 = *(uint *)(lVar5 + 0x10);                  // InputBufferLength
  if ((uVar3 == *(uint *)(lVar5 + 8)) && (0x10 < uVar3) &&
      (uVar4 = *(uint *)((longlong)puVar7 + 0xc), (ulonglong)uVar4 + 0x10 <= (ulonglong)uVar3)) {
      FUN_140006eb4((longlong)puVar10, param_2,
                    (uint)(uVar1 == 0x88992284),     // 1 = SET, 0 = QUERY
                    (ulonglong)*(uint *)(puVar7 + 1),        // OID      = *(u32*)(buf+8)
                    (longlong)(puVar7 + 2),                  // BUFFER   = *(u64*)(buf+0x10)  <-- USER CONTROLLED
                    uVar4, uVar4, 0);                        // LENGTH   = *(u32*)(buf+0xC)
  }
}
```

`FUN_140006eb4` stores the pointer/length straight into the `NDIS_OID_REQUEST` and hands it to NDIS:

```c
plVar10[7] = param_5;                       /* request+0x28 : InformationBuffer       */
*(undefined4 *)(plVar10 + 8) = param_6;     /* request+0x30 : InformationBufferLength */
...
uVar8 = NdisFOidRequest(*(undefined8 *)(param_1 + 0x10));   /* ctx->NdisFilterHandle */
```

For `0x88992288` (`RequestType = NdisRequestQueryInformation`) NDIS/the miniport **writes** the OID result to that address; for `0x88992284` it **reads** from it. No probe, no `RequestorMode` check, no kernel-address validation. Content control: set an OID with attacker data (`0x88992284`, e.g. `OID_802_3_MULTICAST_LIST`) then query it (`0x88992288`) into the target address.

### S2 - `0x88992274`, arbitrary kernel write (`memmove` destination)

`FUN_1400016cc` @ `1400018b1` (block entered from `CMP R14D,0x88992274` / `JZ 1400017ef`):

```asm
14000189f  MOV R8D, dword ptr [RBX + 0x14]     ; len  = queue_entry->Length
1400018a3  ADD R8, 0x135
1400018aa  MOV RDX, RBX                        ; src  = queue_entry (kernel)
1400018ad  MOV RCX, qword ptr [RSI + 0x8]      ; dst  = *(u64*)(SystemBuffer + 8)   <-- USER CONTROLLED
1400018b1  CALL 0x140007a00                    ; memmove
```

Decompiled:

```c
FUN_140007a00((undefined8 *)param_2[1], plVar2,
              (ulonglong)*(uint *)((longlong)plVar2 + 0x14) + 0x135);
```

`FUN_140007a00` is `memmove(dst, src, len)` (arg order verified at every other call site, e.g. `FUN_140004444`: `FUN_140007a00(param_1 /*user out*/, puVar7 /*kernel dump*/, 0x2284)`).

Preconditions: valid context key at `buf+0`; `InLen > 0x10`; the queue `ctx+0x4c` non-empty. The queue is drained one entry per call and refilled by the driver's packet path (entries are queued while the adapter is busy/paused and are recycled to the free list at `ctx+0x1f8`); if it is empty the IOCTL returns `0xC0000001` and performs no copy.

Same pattern, N-at-a-time, at `0x889922BC`:

```asm
1400020c7  MOV ECX, R13D
1400020ca  MOV RDX, RAX
1400020cd  MOV RCX, qword ptr [RSI + RCX*8 + 0x10]   ; dst = *(u64*)(buf + 0x10 + 8*i)
1400020d2  CALL 0x140007a00
```

### S3 - `0x88992270`, arbitrary kernel read (mirror sink)

```asm
1400019a1  MOV RDX, qword ptr [RSI + 0x8]   ; src = *(u64*)(SystemBuffer+8)   <-- USER CONTROLLED
1400019a5  MOV R8D, dword ptr [RDX + 0x14]  ; len = *(u32*)(src+0x14)  (dereference of attacker pointer)
1400019a9  ADD R8, 0x135
1400019b0  MOV RCX, RAX                     ; dst = kernel allocation
1400019b3  CALL 0x140007a00                 ; memmove
```

The copied data is then indicated up the stack (`FUN_1400073e0` -> `NdisFIndicateReceiveNetBufferLists`) and/or queued, giving a path to read kernel memory back to user mode.

### S4 - indirect sinks (`NdisFSendNetBufferLists` / MDL mapping)

`0x8899226C` -> `FUN_140007350(ctx, *(u64*)(buf+8))`, `0x889922B4` -> same in a loop. The "descriptor" is read from the attacker pointer (`+0x14` length, `+0x1c`, `+0x2c` fields), then `FUN_140007478` builds an NBL (`NdisAllocateNetBufferList`, `MmMapLockedPagesSpecifyCache` @ `14000751b`) and the packet is transmitted. Attacker-controlled descriptor contents produce out-of-bounds reads and MDL manipulation; not needed for the primary primitive.

### Not present

No `MmMapIoSpace`, no `WRITE_PORT_*`, no DMA APIs, no `MmCopyMemory`, no `Zw*` section mapping, no `IoCreateDeviceSecure` (the DACL comes from `DefaultSDDLString`). `MmMapLockedPagesSpecifyCache` is used only on NBL MDLs in the packet path.

---

## 7. Validation gaps

1. **Unvalidated embedded pointers in a METHOD_BUFFERED IOCTL.** The I/O manager copies the *buffer*, but the driver treats `buf+8` / `buf+0x10` as **kernel pointers** (`0x8899226C/70/74/84/88/B4/B8/BC`). This is the classic METHOD_NEITHER bug class, reached through a buffered IOCTL.
2. **No probing at all.** `ProbeForRead`/`ProbeForWrite` are not imported. `RequestorMode` is never inspected.
3. **Handle/key disclosure.** `0x88992268` returns raw kernel addresses of the driver's contexts (`*(u64*)(out+0x2004+8*i)`), removing KASLR as a barrier. The same pointer is the authorization key for all privileged IOCTLs (`if (puVar4 == param_1)` in `FUN_1400042f0`), so the "key" is neither secret nor random.
4. **Unbounded loop counts.** `0x889922B4/B8/BC` take `count = *(u32*)(buf+8)` and index `buf+0x10+8*i` with only `InLen >= 0x18` checked - an out-of-bounds read of the pool block and then wild-pointer dereference (DoS, and another read primitive).
5. **Output length trust.** Several paths set `IoStatus.Information` to a fixed size (0x2284, 0x41804, 0x10, 0xC) that is compared with `OutputBufferLength` in *some* branches only (`0x88992294`, `0x889922D4`, `0x889922D8` set `Information` without an `OutLen` check; `0x889922D4/D8` even set `Information = InputBufferLength`, `uVar18 = param_3`). For METHOD_BUFFERED the copy-back length is taken from `IoStatus.Information`, so an over-long value can fault on the user side (DoS), but it does not corrupt kernel memory.
6. **No integer-overflow guard needed**: the `*(u32*)(buf+0xC) + 0x10 <= InLen` check is done in 64-bit (`lea rcx,[rax+0x10]; cmp rcx,rdx`), so it does not wrap.
7. **Context pointer on a world-writable device.** `WD:GRGW` + FILE_ANY_ACCESS IOCTLs = the whole interface is reachable by any user; the only "gate" is a leaked pointer.

---

## 8. WMI

`FUN_14000d07c` / `FUN_14000d000` are the **WPP trace provider** init/cleanup, not an RTF64 data provider:

```
14000d0fd  LEA  RAX, [0x14000d250]
14000d104  MOV  qword [0x14000b160], RAX
14000d10b  MOV  EDX, 0x80010001
14000d110  MOV  RCX, RBX                ; RBX = &DAT_14000b160 (a .data global, not a DEVICE_OBJECT)
14000d113  CALL qword [0x14000a128]     ; -> IoWMIRegistrationControl
```

* The object passed to `IoWMIRegistrationControl` is the global `DAT_14000b160`, and the action `0x80010001` is not one of `WMIREG_ACTION_REGISTER/DEREGISTER/REREGISTER` - this is WPP's legacy tracing registration block, not a WMI data block on `\Device\RTF64`.
* `FUN_14000d250` is a MOF-style query/set callback (returns `0xC0000010`, `0xC0000023`, `0xC0000295`). Its "set" branch writes only **fixed-offset fields** of a driver instance (`*(u64*)(inst+0x18)`, `*(u32*)(inst+0x2c)`, `*(u8*)(inst+0x29)`) from the WMI input buffer, after a GUID match on the instance list, with the usual `OutBufferSize` checks. It is bounded and driver-owned.
* `\Device\RTF64`'s `MajorFunctions[IRP_MJ_SYSTEM_CONTROL]` (index 0x17) is **NULL**, so no WMI IRP to this device reaches that callback.

**Conclusion:** the WMI code is not an independent kernel-write primitive. It is worth one dynamic confirmation (return value of `IoWMIRegistrationControl`) but it does not change the verdict.

---

## 9. Setup required: **composition**

| Configuration | `\Device\RTF64` present | Context list | Arbitrary R/W reachable |
|---|---|---|---|
| `sc create rtf64x64 type= kernel` + `sc start` (no INF, no binding) | yes, **if** `NdisFRegisterFilterDriver` returns success | empty | **no** - every keyed IOCTL returns `0xC0010006`; only `0x88992264`, `0x88992268` (returns count 0), `0x8899228C`, `0x88992290` do anything, all buffer-bounded |
| Normal INF install of the LWF on the on-board Realtek NIC (driver's shipping state) | yes | **>=1 context** | **yes - full chain** |

Justification: `FilterAttach` (`FUN_1400054b0`) is the **only** writer of the global list:

```c
FUN_140001000(local_120 + 0x4c);
DAT_14000b148 = KeAcquireSpinLockRaiseToDpc(&DAT_14000b140);
if ((longlong **)DAT_14000b130[1] != &DAT_14000b130) { /* list integrity check */ }
*plVar13         = (longlong)DAT_14000b130;
plVar13[1]       = (longlong)&DAT_14000b130;
DAT_14000b130[1] = (longlong)plVar13;
DAT_14000b130    = plVar13;
```

No devnode and no extra hardware are needed - the driver is an LWF that binds to whatever NIC is already present. It is *not* "device load only": the write primitives require that binding.

---

## 10. Next dynamic test (do **not** run in this session)

Run inside a VM snapshot; use a **medium-integrity, non-admin** process (the DACL already allows it). Watch for `0xC0010006` vs `STATUS_SUCCESS`.

1. **Confirm the device and binding**
   * `WinObj` / `NtObjectManager`: `\Device\RTF64` + `\DosDevices\RTF64` exist.
   * `Get-NetAdapterBinding -Name <NIC> -ComponentID rtf64x64` -> `Enabled = True` (this is what populates the context list).
2. **Open** `\\.\RTF64` with `GENERIC_READ|GENERIC_WRITE`, `FILE_SHARE_READ|WRITE`, `OPEN_EXISTING`.
3. **Leak the key** - `DeviceIoControl(h, 0x88992268, NULL, 0, out, 0x2284, &ret, NULL)`:
   * `*(u32*)out` = adapter count. If `0`, stop: no context, primitives unreachable (this is the sc-only case).
   * `ctx = *(u64*)(out + 0x2004)` - should look like `0xFFFF8xxx_xxxxxxxx`.
4. **Validate the key** - `DeviceIoControl(h, 0x88992294, in={ctx}, 8, out, 4, ...)`. Expect `STATUS_SUCCESS` and `Information = 4`; `0xC0010006` means the key was rejected.
5. **Prove destination control (safe)** - `0x88992288`, `InLen = OutLen = 0x18`, buffer = `{ ctx, oid = OID_GEN_RCV_OK(0x00020103), len = 4, buffer = <user-mode address> }`. If the driver honours the embedded pointer, the OID result lands in the user buffer (this also proves an arbitrary **kernel** write, since the same field accepts a kernel address).
6. **Prove a kernel write, self-verifying** - repeat step 5 with `buffer = ctx + 0x280` and `len = 4`, then read the field back with `0x88992298` (returns `*(u32*)(ctx+0x280)` at `buf+8`). A changed dword proves the write landed in kernel memory at an attacker-chosen address, using a field that is not a pointer (low risk of an immediate bugcheck).
7. **Prove the `memmove` write path (queue-dependent)** - generate traffic on the bound NIC (or pause/restart the adapter) to populate `ctx+0x4c`, then `0x88992274` with `buf+8 = ctx+0x280`; read back as in step 6. If it returns `0xC0000001`, the queue is empty - this path is not reliably reachable, and step 6 (OID) remains the primary proof. (This path writes `0x135 + packet_len` bytes - do **not** aim it at a live structure.)
8. **Negative control** - `WriteFile()` on the handle must return `STATUS_INVALID_DEVICE_REQUEST` (no `IRP_MJ_WRITE` handler), and `0x8899229C` must return `0x10001`.

Expected failure modes if the analysis is wrong: step 3 returns count 0 (not installed/bound), step 4 `0xC0010006` (key mismatch -> lookup is not by pointer), or step 5 leaves the user buffer untouched (the field is not `InformationBuffer`). Any of those downgrades the finding to *no user-controlled write*.

---

## 11. Limits of this audit

* Purely static; no execution, no VM, no kernel debugger. The key->lookup semantics and the `memmove` direction were proven from the code (arg order verified across four call sites), not from a live run.
* The `IoWMIRegistrationControl` call's runtime return value was not observed (see section 8).
* `NdisFOidRequest` forwards to the miniport: whether a given OID actually writes `len` bytes into `InformationBuffer` depends on the miniport's OID handler; `OID_GEN_*` / `OID_802_3_MULTICAST_LIST` are the obvious candidates for the dynamic test.
* Whether a bare `sc create` / `sc start` gets past `NdisFRegisterFilterDriver` depends on the NDIS filter registration keys (normally installed by the INF); this does not affect the installed-state verdict, only the "no-INF" column of section 9.

---

### Address index

| Address | Meaning |
|---|---|
| `0x14000e000` | DriverEntry |
| `0x14000e47f` | `NdisFRegisterFilterDriver` call |
| `0x14000e4ee` | `FUN_14000410c` (device registration) call |
| `0x14000410c` | FilterRegisterDevice: `RtlInitUnicodeString` x2 + `NdisRegisterDeviceEx` |
| `0x1400091d0` | SDDL string (UTF-16) |
| `0x140009270` / `0x140009290` | `\Device\RTF64` / `\DosDevices\RTF64` |
| `0x1400041cb` | `memset(MajorFunctions, 0, 0xE0)` |
| `0x1400040a0` | IRP_MJ_CREATE / CLOSE / CLEANUP handler |
| `0x140003e60` | IRP_MJ_DEVICE_CONTROL / INTERNAL_DEVICE_CONTROL handler |
| `0x1400016cc` | main IOCTL switch |
| `0x1400042f0` | context lookup (compares `buf[0]` to list-node address) |
| `0x140004444` | adapter dump (leaks context pointers at `+0x2004`) |
| `0x140006eb4` | OID request builder -> `NdisFOidRequest` |
| `0x140007a00` | `memmove` |
| `0x1400054b0` | FilterAttach (populates `DAT_14000b130`) |
| `0x14000b130` | adapter context list head |
| `0x14000b120` | open handle counter |
| `0x14000d07c` / `0x14000d000` | WPP trace register / deregister |
