# NZXT `cam_driver_mb` — static audit

**Binary:** `drivers\NZXT\cam_driver_mb_A9C246FD.sys`
**Size / arch:** 72,224 bytes, x64 PE, image base `0x180000000`
**SHA-256:** `A9C246FD1466C017AC61768E75BFC19DFE7BEE5AF683935BF78716EFF5F3794E`
**Framework:** KMDF, bound dynamically through `WdfVersionBind` (WDFLDR.SYS); all WDF services are indirect calls through the table at `DAT_18000D338`.
**Tooling:** Ghidra 12.1.4 headless, full function decompile + targeted disassembly of `DriverEntry` (`0x18000F000`) and `EvtIoDeviceControl` (`0x180002CB0`).

## Verdict

**NO-WRITE (kernel memory).**

The control device **is real and is openable by Everyone**, and the SDDL literal **is genuinely used** — the previous `SDDL-UNPROVEN` tag was a false negative caused by the SDDL `UNICODE_STRING` sitting immediately *before* the text and by the KMDF call being indirect (`[table+0xC8]`). However, every user-controlled value ends up in either (a) a Super-I/O port write (`OUT 0x2E/0x2F`), (b) an MMIO store through a mapping created from a **chip-table-derived physical base**, or (c) the driver's own device context. There is no IOCTL that supplies a kernel pointer, a physical address, a length used in a copy, or an index into a function pointer table. No memory-corruption primitive was found.

## 1. Device surface

`DriverEntry` `0x18000F000` creates a **WDF control device** (not a PnP FDO) unconditionally:

| Item | Value | Evidence |
|---|---|---|
| Device name | `\Device\CAMDriverMB` | `UNICODE_STRING` @ `0x18000B220` (len 0x26), buffer `0x18000B1F8`; passed to table `+0x218` (`WdfDeviceInitAssignName`) |
| Symbolic link | `\DosDevices\CAMDriverMB` | `UNICODE_STRING` @ `0x18000B280` (len 0x2E), buffer `0x18000B24C`; passed to `+0x280` (`WdfDeviceCreateSymbolicLink`) |
| Create | `WdfDeviceCreate` (`+0x258`) @ `0x18000F6xx` | decompiled `DriverEntry` |
| Queue | `WdfIoQueueCreate` (`+0x4C0`), parallel, default queue | `WDF_IO_QUEUE_CONFIG` size 0x60, `DispatchType=2`, `DefaultQueue=1` |
| IOCTL callback | `FUN_180002CB0` | `WDF_IO_QUEUE_CONFIG.EvtIoDeviceControl` (config offset 0x28) |

Because it is a control device created at `DriverEntry`, `CreateFile("\\\\.\\CAMDriverMB")` succeeds as soon as the driver is loaded; no hardware, PnP devnode or child device is needed.

## 2. Effective DACL — SDDL is live

At `0x18000F1A4`:

```
18000F19A  4C 8D 05 47 C0 FF FF      LEA R8,[0x18000B1E8]      ; &UNICODE_STRING(SDDL)
18000F1A1  48 89 F2                  MOV RDX,RSI               ; WDFDRIVER
18000F1A4  FF 90 C8 00 00 00         CALL qword ptr [RAX+0xC8] ; WdfControlDeviceInitAllocate
```

`0x18000B1E8` is a valid `UNICODE_STRING`: `Length=0x72`, `MaximumLength=0x74`, `Buffer=0x18000B170`, and the buffer decodes to:

```
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)
```

Effective DACL (protected, no inheritance):

| SID | Access | Meaning |
|---|---|---|
| `SY` SYSTEM | `GA` | GENERIC_ALL |
| `BA` Builtin\Administrators | `GRGWGX` | generic read/write/execute |
| `WD` Everyone | `GRGW` | **generic read + generic write** |
| `RC` Restricted Code | `GR` | generic read |

The caller needs `FILE_WRITE_ACCESS` for the `0x8000A0xx` IOCTLs; `GENERIC_WRITE` in the Everyone ACE satisfies it.

## 3. IOCTL table

Dispatch is a range check at `0x180002D93`–`0x180002DB0`:

```
LEA EAX,[RBX+0x7FFF6000]   ; EAX = code - 0x8000A000
CMP EAX,0x18
JA  default
LEA RCX,[0x18000C204]      ; 25-entry jump table
MOVSXD RAX,[RCX+RAX*4] / ADD RAX,RCX / JMP RAX
```

Only five entries are real; all other indices (and `0x18000342A` handles the two `0x80006xxx` codes):

| IOCTL | Device / Func | Method | Access | Handler | Behaviour |
|---|---|---|---|---|---|
| `0x8000A000` | 0x8000 / 0x800 | BUFFERED | WRITE | `0x180002DB2` | input length must be exactly 1; byte 0 = sub-command 0..0xC; jump table `0x18000C364` → SIO/GPIO/hwmon operations |
| `0x8000A004` | 0x8000 / 0x801 | BUFFERED | WRITE | `0x1800034DA` | 1-byte in / 1-byte out; device-state machine dispatch (`0x18000C300`) |
| `0x80006008` | 0x8000 / 0x802 | BUFFERED | READ | `0x180003A39` | 0x2D-byte sensor/status snapshot (sentinel-filled dwords, then per-channel data) |
| `0x8000A00C` | 0x8000 / 0x803 | BUFFERED | WRITE | `0x180003615` | 0xB-byte in / 1-byte out, state-gated |
| `0x80006010` | 0x8000 / 0x804 | BUFFERED | READ | `0x180003442` | 4-byte in / 4-byte out, writes `4` to the output dword |
| `0x8000A014` | 0x8000 / 0x805 | BUFFERED | WRITE | `0x180003845` | 3-byte in, state-gated |
| `0x8000A018` | 0x8000 / 0x806 | BUFFERED | WRITE | `0x1800038D3` | 0x22-byte in; validates bytes 0, 0x1F, 0x20/0x21 then dispatches (`0x18000C268`) |
| all method variants (`…0001`–`…0018`) | — | NEITHER/DIRECT | — | `0x180003C14` | complete with the current status, no action |

Length handling is exact, e.g. `0x8000A000`: `CMP RAX,1 / JNZ default`; `0x8000A00C`: `CMP RAX,0xB`; `0x8000A018`: `CMP RAX,0x22`. The sub-command byte is bounded (`CMP byte ptr [RBX],0xC / JA default`).

## 4. Write sinks

### 4a. Super-I/O port I/O (hardware, not memory)

`0x180005B32` (`cmd 0x0B`), `0x180005CD2` (`cmd 0x07/0x08`), `0x180005D6F` (`cmd 0x09/0x0A`):

```
MOV DX,0x2E
MOV AL,0x87
OUT DX,AL
OUT DX,AL
MOV AL,0x20
OUT DX,AL
MOV DX,0x2F
IN  AL,DX
```

The index/value pairs written after chip detection (e.g. `OUT 0x2E,0x07; OUT 0x2F,0x0B; OUT 0x2E,0x60 …`) come from the user buffer, but the *port* is fixed at `0x2E/0x2F` and the register sequence is hard-coded. This is a hardware write, not a kernel-memory write.

### 4b. `MmMapIoSpaceEx` + store (hardware, fixed bases)

Only two physical bases exist in the image:

* `0x180006310` / `0x18000A20C`: `MmMapIoSpaceEx(0xFEC40000, 0xC, 0x204)` — the fixed LPC/eSPI MMIO window.
* `0x180006729`, `0x180006746` and the inlined copy at `0x1800076E7`:

```c
uVar41 = MmMapIoSpaceEx((uint)uVar177 + iVar38 + (uint)(byte)uVar55 * 0x10000, 4, 0x204);
...
MmUnmapIoSpace(uVar41,4);
```

`uVar177`/`uVar55` are entries of the static descriptor table `PTR_DAT_18000B680`, selected by the **detected SIO chip ID** (`0xD428`, `0xD800`, `0xD440`, `0x2186`, `0x2885`, …); `iVar38 = *(int *)(&UNK_18000B690 + chip*0x18)` is the table's base. Neither value is reachable from an IOCTL. The store into the mapped dword is the hardware register write.

No `HalSetBusData*` import and no user-supplied physical address; the only `HalGetBusDataByOffset` calls (`0x180005222`, `0x180005470`) read PCI config for `(bus 4, dev 0x80/0, off 0x9F)`.

### 4c. Context writes (bounded, fixed offsets)

`0x1800012F0` (device cleanup/state) and the sub-handlers write only into `MOTHERBOARD_DEVICE_CONTEXT` at fixed offsets (`+0x28`, `+0x260 + idx*0x10`, `+0x3A0`, …). The MMIO pointer table itself is the only array indexed by a value derived from an input byte (`*(byte *)(lVar4+0x11D)`), and that byte is a **device-state index** written by the driver's own state machine, not by the user.

## 5. Validation gaps

* `0x8000A000`/`0x8000A018` accept a variable number of trailing bytes but only read fixed offsets; no length-driven copy.
* The `SeSinglePrivilegeCheck(10, …)` helper at `0x1800013E0` (LUID 10 = `SeSystemProfilePrivilege`) has no call site in the decompiled image and no reference from the queue config; it appears to be dead/unused, so it does not gate any IOCTL.
* No `ProbeForWrite`/`ProbeForRead` is needed because every IOCTL is `METHOD_BUFFERED` (KMDF supplies a probed system buffer).
* `0x8000A004`/`0x8000A00C`/`0x8000A014` branch on `MOTHERBOARD_DEVICE_CONTEXT+0x28` (state 2..7) before touching hardware; out-of-range states fall to a default that completes without action.

## 6. Setup required

**none** for device reachability — the control device and symlink are created in `DriverEntry`. In practice the driver must be installed/loaded (NZXT CAM service), which is a composition step; there is no hardware dependency, no devnode and no user interaction.

## 7. Next dynamic test

1. As a standard user, `CreateFile("\\\\.\\CAMDriverMB", GENERIC_READ|GENERIC_WRITE)` → expect success (confirms the SDDL is applied at runtime, not just present).
2. `DeviceIoControl(0x80006008, out=0x2D)` → expect `STATUS_SUCCESS` and a populated snapshot; `0x8000A000` with a 1-byte input `0x00..0x0C` → expect hardware side effects, not a crash.
3. Under Driver Verifier (special pool, I/O verification) + KD, break on `MmMapIoSpaceEx` and confirm the three arguments are always table-derived for repeated random IOCTL fuzzing (all 5 real codes, random lengths 0..0x100).
4. Fuzz the `0x8000A018` 0x22-byte structure (bytes 0, 0x1F, 0x20/0x21) looking for a state-machine index outside 0..4; the table dispatch at `0x1800039F0` masks the index, so expect no OOB.

**Bottom line:** the permissive DACL is a real exposure of a hardware-control interface to unprivileged users (fan/RGB/GPIO/SMBus-adjacent operations on the motherboard), but it is **not** a kernel memory-write primitive.
