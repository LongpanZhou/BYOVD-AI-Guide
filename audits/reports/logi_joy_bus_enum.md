# Audit: logi_joy_bus_enum.x64.sys

> **File:** `C:\Users\<scrubbed>\Desktop\driver_candidates\logi_joy_bus_enum.x64.sys`
> **SHA-256:** `79065269b2009dae18cdf5d9090fe8bab98dcfc1c52e66f91d62f47038192e9b`
> **Analysis date:** 2026-10-23
> **Method:** Static-only audit via REA/Ghidra

SHA-256 `79065269b2009dae18cdf5d9090fe8bab98dcfc1c52e66f91d62f47038192e9b` · Evidence `ev_63b915908c65ec029025845e0fdce08d0a114357ba0dbb0a524f9d4c8f83bef0` (open/binary overview). All addresses below are image-relative to base `0x140000000` and were read directly from the loaded image. No web lookups, no external information about the file, vendor, or similar drivers — all conclusions from disassembly of this binary.

## 1. Internals

| Property | Observed value | Source |
|---|---|---|
| Format / arch | PE32+ (magic `0x20B`), x86-64, IMAGE_DLL 0x22, 8 sections | optional header @ file `0x100` |
| Entry point | `AddressOfEntryPoint = 0x9090` → `entry @ 0x140009090` (INIT), optional header @ `0x140000110` | read_bytes Evidence `ev_f1e5ba21…` |
| Subsystem | `SUBSYSTEM_NATIVE (1)` — kernel-mode driver | `0x140000144` |
| Build hardening | `DLLCharacteristics 0x4160` = ASLR + NX + CFG; `/GS` (`__security_check_cookie` 0x140002da0), `_guard_dispatch_icall` 0x140002dd0, LoadConfig dir present | data dirs |
| Framework | **WDM, not KMDF**. Entry is a plain `DriverEntry`; imports are raw ntoskrnl WDM calls (`IoCreateDevice`, `IoAttachDeviceToDeviceStack`, `IoCsq*`, `PsSetCreateProcessNotifyRoutine`, `Po*` — single import library `ntoskrnl.exe`, string `0x14000969e`) | 47 external imports |
| Sections | `.text` `0x140001000–0x140003400`, `.rdata`, `.data`, PAGE `0x140007000–0x140008800`, INIT `0x140009000–0x140009800` | segment list, Evidence `ev_63b91590…` |
| Resources (.rsrc) | Version block: `CompanyName "Logitech"`, `FileDescription "Logitech G Drivers"`, `InternalName/Product "Logitech G Drivers"`, `FileVersion/ProductVersion "2026.0.0.0"`, `LegalCopyright "Copyright © Logitech, Inc. 2024"` | strings `0x14000a0c2–0x14000a30a` |
| Signature | Authenticode certificate directory present: RVA `0x6000`, size `0x5188` (~20.9 KB payload) | data dirs |
| PDB | RSDS reference `logi_joy_bus_enum.x64.pdb` GUID `04cf7861-c3c9-4a57-9c86-acf439a5909e` | overview limitations |
| Notable strings | debug tag `Logi_Joy_Bus_Enum:` (`0x1400032b0`), `Remove Fields: Size:%d UniqueId:%d Type:%d` (`0x1400032e0`), `NumPDOs:%d KeyboardId:%d MouseID:%d JoystickId:%d` (`0x140003310`), HWIDs `LGHUBDevice\VID_046D&PID_C232` / `…C231` (`0x140008600/640`), compatible ID `LGHUBDevice\LGHUBCompatibleVirtualDevice` (`0x140008530`), device-instance fmts `Logitech_`, `LGVirHid`, `%ws%ws%02d`, `AD_%x_%04x` (`0x1400085b0/510/5d0`) | list_strings |
| Embedded HID data | Interface GUID `{DFBEDCDD-2148-416D-9E4D-CECC2424128C}` at `0x140004380`; two **HID report descriptors**: keyboard(+integrated mouse), 63 bytes @ `0x140004390`; mouse-only, 67 bytes @ `0x1400043d0` (usage pages 0x05/0x07 key range 0xE0‑0xE7, 16 buttons, 16-bit rel X/Y, wheel 0x38, consumer page 0x0C) — both copied verbatim into child-PDO exts when children are created | read_bytes |
| Absent | **No `Se*`/`Zw*`/`Dd*` imports, no SDDL/security-descriptor strings anywhere in the binary, no `IoCreateDeviceSecure`, no `MmIsAddressValid`, no output-dbg anti-analysis** | full import + string inventory |

Function count 131 (`list_procedures`). This is a small (~13 KB of live code) custom-WDM **bus-filter driver** that enumerates virtual HID children ("PDOs") and lets user mode create/remove them and feed their input reports.

## 2. Device & entry chain

**Entry chain:** `entry @ 0x140009090` → `FUN_1400090bc` (`__security_init_cookie`, `0x1400090bc`) → **DriverEntry `FUN_140009000` @ `0x140009000`** (INIT).

DriverEntry (`0x140009000`, verified in assembly):

- Sets `DRIVER_OBJECT+0x68` (DriverUnload) → `FUN_140007080`; that unload only does `PsSetCreateProcessNotifyRoutine(FUN_140001000, TRUE)` (`0x14000708d`).
- MajorFunction writes (base `+0x70` on x64):

| Slot (IRP) | Handler | Addr |
|---|---|---|
| `MJ_CREATE (0)` **and** `MJ_CLOSE (2)` | shared minimal completeness check | `FUN_140007000` |
| `MJ_DEVICE_CONTROL (0x0E)` | **IOCTL dispatcher** | `FUN_140007090` |
| `MJ_INTERNAL_DEVICE_CONTROL (0x0F)` | HID-internal protocol (kernel-only) | `FUN_1400012f0` |
| `MJ_SYSTEM_CONTROL (0x17)`, `MJ_DEVICE_CHANGE (0x18)` | forward down via `IofCallDriver` | `FUN_1400010a0` |
| `MJ_PNP (0x1B)` | PnP state machine | `FUN_140007f80` |
| all other slots | untouched → NT loader default `IopInvalidDeviceRequest` (returns `STATUS_INVALID_DEVICE_REQUEST`) | — |

- `DRIVER_EXTENSION` → `AddDevice = FUN_1400079a0` (`MOV qword ptr [RAX+0x8], RCX`, `0x140009074`).
- Registers process-notify callback: `PsSetCreateProcessNotifyRoutine(FUN_140001000, FALSE)` (`0x14000907f`). `FUN_140001000` (`0x140001000`) only *deletes* a PID from `.data` array `0x140005090` (count `0x140005088`, max 16) on process exit.

**AddDevice `FUN_1400079a0` (`0x1400079a0`):**

- `IoCreateDevice(DriverObject, 0xC8, NULL, 0x2A, 0, TRUE(Exclusive), &FDO)` — assembly `0x1400079c0: MOV byte ptr [RSP+0x28], BL (=1)`: **Exclusive=1**, **DeviceName=NULL** (unnamed), DeviceType `0x2A`; flags: set `DO_POWER_PAGABLE (0x2000)` `0x1400079f8`, clear initialization after attach.
- `IoRegisterDeviceInterface(PDO, &MIB_GUID 0x140004380, NULL, ext+0x88)` (`0x1400079f0…0x140007a70`) — **this interface is the only user-mode attack surface**; the FDO itself is unnamed.
- `IoAttachDeviceToDeviceStack` → filter over the PDO it was loaded for.

**FDO PnP `FUN_140007cd0` (`0x140007cd0`):** state machine in `ext+0x0C`; on `IRP_MN_START_DEVICE` (minor 0) it forwards down (`FUN_1400080c4`) and then **enables the device interface** `FUN_140008170` (`0x140008170` → `IoSetDeviceInterfaceState(ext+0x88, TRUE)`) and sets state=1. Interface is disabled on stop (`0x140007fd0` → `IoSetDeviceInterfaceState(FALSE)`) and on REMOVE/SURPRISE_REMOVAL (minors 2/0x17).

**PDO PnP `FUN_1400073ec` (`0x1400073ec`)** handles child devices: RUN-STATE transitions, REMOVE via `FUN_140008018` (flushes parked IRPs through `IoCsqRemoveNextIrp` — `FUN_140001708`, then `IoDeleteDevice`, `0x140008118`), QUERY_CAPABILITIES `FUN_1400075a4`/`0x1400072a4`, QUERY_INTERFACE `FUN_140007848`, QUERY_ID `FUN_140007670` (`0x140007670`: returns stored multi-sz `LGHUBDevice\VID_046D&PID_C232/C231`, compatible ID `LGHUBDevice\LGHUBCompatibleVirtualDevice`, or instance IDs `%02d` / `AD_%x_%04x`), device-text `FUN_1400078f8` (`"Logitech_LGVirHid…"`, `0x140007970`).

**Child PDO support:** FDO ext keeps a protected child list (spinlock `ext+0x48`, list head `ext+0x30`, count `ext+0x40` — insert `FUN_14000255c` `0x14000255c`, delete `FUN_140002990`); `FUN_1400010bc` finds a child by 32-bit ID under `KeAcquireSpinLockRaiseToDpc` (`0x1400010bc–0x14000110e`).

## 3. IOCTL table

**Dispatch `FUN_140007090` (`0x140007090–0x1400072a2`), the user-mode-reachable surface.** The switch is a decrement-compare cascade over `IoControlCode` (assembly `0x1400070ff – 0x14000713d`). Validation compares `inLen/outLen/SystemBuffer[0]` against `SL+8/0x10/0x18`. All 8 codes decode as DeviceType=`0x2A`, **METHOD_BUFFERED (method 0)**, **FILE_ANY_ACCESS (access 0)**. Gating prelude: device must have `ext+0x08 != 0` (ready) and `ext+0x0C != 6` (removal state), else `STATUS_NO_SUCH_DEVICE/0xC0000056` (`0x1400070b6–0x1400070ca`).

| # | Control code | Validation at addr | Handler (`Addr`) | Kernel action |
|---|---|---|---|---|
| 1 | `0x2A2000` func 0x800 | in==out, inLen>`0xBA`, buf[0]`==0xB7` | `FUN_140007ad8 @ 0x140007ad8` | **stub** — `ret 0xC0000002 (NOT_IMPLEMENTED)` |
| 2 | `0x2A2004` func 0x801 | inLen==12 && buf[0]==12 (`0x140007227`) | `FUN_140002744 @ 0x140002744` | **REMOVE child PDO** by type (0x6B keyboard/0x6D mouse/0x6A joystick) + uniqueId; `ObfDereferenceObject` on 3 object refs (`0x140002808–0x140002830`), list unmark, `ext+0x40` count--, `IoInvalidateDeviceRelations(FDO ext+0x20, 0)` (`0x140002838`) — triggers PnP removal. Debug-prints NumPDOs/IDs |
| 3 | `0x2A200C` func 0x803 | (none on buffer) (`0x140007203`) | `FUN_140001930 @ 0x140001930` | **KEYBOARD report injection**: find child by `ext+0x9C` (KeyboardId) → pop pending input-report IRP from child queue (`FUN_1400015b0 @ 0x1400015b0`, list `childExt+0x68`, spinlock `+0x60`) → zero-fill the queued IRP buffer (`FUN_1400030c0`) → `memcpy min(inLen, queuedLen)` **attacker bytes** (`FUN_140002e00`) → completes popped IRP with `IoStatus.Information=written` (`0x1400019cb`) |
| 4 | `0x2A2010` func 0x804 | (none on buffer) (`0x1400071df`) | `FUN_140001a10 @ 0x140001a10` | **MOUSE injection**, same mechanics, child from `ext+0xA0`; additional masking: if `FUN_14000118c` (PID-list nonempty) and queuedLen>5 → zeroes 4 bytes at `poppedIRP buffer+2` (`0x140001adc`) |
| 5 | `0x2A203C` func 0x80F | (none on buffer) (`0x1400071b4`) | `FUN_140001864 @ 0x140001864` | **JOYSTICK injection**, child from `ext+0xA4` |
| 6 | `0x2A2040` func 0x810 | in==out==8 && buf[0]==8 (`0x140007189`) | `FUN_140007ae0 @ 0x140007ae0` | **CREATE child PDO**: buf[4] picks type (0x6B keyboard → requires `ext+0x9C==0`; 0x6D mouse → `ext+0xA0==0`); `IoCreateDevice(driver, 0x118, NULL, 0x2A, 0x80, Exclusive=0, &PDO)` (assembly `0x140007b67–0x140007b96`, `MOV byte ptr [RSP+0x28], DIL` where DIL=0) → NonPagedPoolNx alloc tag `wmbe` (`0x140007bc1`), copy HWID (`C232/C231`) + report descriptor (`0x140004390`/`0x1400043D0`) → `FUN_140007ed4` wires child ext (remove-lock, `KeInitializeSpinLock` queue `+0x60`, CSQ `0x1400024ec` — `IoCsqInitialize`, link into FDO list `FUN_14000255c`) → `IoInvalidateDeviceRelations` and stores new unique ID into `ext+0x9C/0xA0/0xA4` |
| 7 | `0x2A2044` func 0x811 | **no buffer check at all** (`0x140007176`) | `FUN_140001160 @ 0x140001160` | **Register caller**: `PsGetCurrentProcessId()` appended to global PID array `0x140005090` (count `0x140005088`), max 16 (else `0xC0000055`). Uniqueness unchecked, **no locking** (count is a plain `DWORD` in .data) |
| 8 | `0x2A2048` func 0x812 | in==out==132 && buf[0]==132 (`0x140007146`) | `FUN_14000112c @ 0x14000112c` | **Dump the tracked PID list** (up to 16×8 bytes) into the caller's `SystemBuffer+4`, Information=0x84 |
| – | default | | `0x140007267` | `0xC000000D (INVALID_PARAMETER)` |

MJ_IOCTL completes always with the computed status (`0x14000726c–0x140007277`); note the status returned to user is 0 for cases 3–5 *even when no child/pending IRP was found* (success masks failures — hides errors from callers).

**Kernel-only `MJ_INTERNAL_DEVICE_CONTROL` `FUN_1400012f0` (`0x1400012f0–0x1400014db`)** (not user-reachable: cannot be issued from user mode; cited for completeness of the inter-driver protocol with the companion virtual-HID minidriver):

- `0x2A2014` (`0x1400013d6`) return VID/PID/version triple into `IRP.UserBuffer`; `0x2A2018` (`0x1400013ec`) copy report descriptor pool (`ext+0x58`, len `ext+0x50`) into `UserBuffer`.
- `0x2A200C/0x2A2010` duplicate cases 3/4 handlers; `0x2A201C`, `0xB01A8` → transparent forward down; default `0xC00000BB`.
- `0x2A2023` → `FUN_140001620` (`0x140001620`): **parks the incoming IRP PENDING** on `childExt+0x68` queue with cancel routine `FUN_1400014e0` and returns `STATUS_PENDING` — this is the mechanism holding the "input report request" that the IOCTLs above complete.
- `0x2A2027` → `FUN_140002218`/`FUN_140001e94`; `0x2A202F/33/37/3B` → `FUN_1400020A8/0x14000212C/0x140002170/0x1400021D4` → common `FUN_140001bf8` (`0x140001bf8`): builds MDL-backed clone (`IoAllocateIrp/IoAllocateMdl/MmBuildMdlForNonPagedPool`, tag `vrph`), parks caller IRP in the child CSQ (`ext+0x98`, tag `xtcx`), `IofCallDriver` down, returns `STATUS_PENDING`; `0x2A2028` → `FUN_140001b00` (pop queued IRP, zero-fill, copy `min(queuedLen, ctl+8)` bytes from control buffer).

## 4. Access-control audit

**Verdict: nothing in this driver gates anything about the caller.**

- **Create path:** `MJ_CREATE` handler `FUN_140007000` (`0x140007000–0x14000705f`) returns `STATUS_SUCCESS` for any caller whenever the device is present (`ext+0x08 != 0`) and not removing (`ext+0x0C != 6`). It never consults `PsGetCurrentProcessId`, a privilege, a SID, or a session. The interface enabling (`FUN_140008170 @ 0x140008170`) likewise just flips `IoSetDeviceInterfaceState`.
- **IOCTL path:** dispatcher `0x140007090` performs *parameter* validation only (lengths/magic). Cases 3–5 (report injection) and 2 (device removal) are reachable by **any process** that can open the device; cases 7/8 actively invite self-registration and full dumping of the PID list — **the tracked-PID array is written by one IOCTL and read only by the dump IOCTL and the exit callback** (`0x140001000`, `0x14000112c`, `0x140001160`); it is never consulted as an ACL. The mouse masking tied to the PID list (`FUN_14000118c` check in `FUN_140001a10` `0x140001ad6`) only zeroes four bytes of a report; it does not block the call.
- **SD/SDDL:** both `IoCreateDevice` calls are plain (`0x140007967` FDO, `0x140007b96` child PDOs); no `SecurityDescriptor` is ever set (`IoCreateDeviceSecure` unused), and there is no SDDL string among all 83 strings. No `SeSinglePrivilegeCheck`, `SeAccessCheck`, `RtlAddAccessAllowedAce`, `ZwSetSecurityObject` etc. are even imported. Whether the device interface symlink (created against the *filtered device's* PDO in `AddDevice`, `0x1400079f0`) can be opened by low-privilege callers therefore depends solely on the **OS default security descriptor of that PDO**, which this driver contributes nothing to.
- **Exclusivity in practice:** the FDO is created with `Exclusive=1` (`0x1400079c0`), but it is unnamed and the interface symlink resolves against the PDO, so this flag is at most incidental protection for user-mode opens and does not encode any identity rule. Child PDOs are created `Exclusive=0`, unnamed (`0x140007b31 XOR EDX, EDI … [RSP+0x28]=0`).
- Minor hardening gaps noticed along the way: `FUN_140001160`'s count mutation on the PID array is not synchronized (concurrent register/exit races can push the count past the array, in `.data`); the same PID can be added repeatedly to fill all 16 slots.

## 5. Most dangerous exposed capability

**Unprivileged synthetic-HID input injection + PnP virtual-device manipulation through `DeviceIoControl`, once the device interface is open:**

- **Input injection (primary):** IOCTL `0x2A200C` (keyboard), `0x2A2010` (mouse), `0x2A203C` (joystick) — dispatcher `0x140007203`, `0x1400071df`, `0x1400071b4`; injectors `FUN_140001930`/`0x140001a10`/`0x140001864`. An arbitrary caller writes attacker-chosen bytes over whichever IRP the **system-side HID consumer has parked pending** against the virtual keyboard/mouse/joystick child (parked by `FUN_140001620` `0x140001620` returning `STATUS_PENDING` for internal control `0x2A2023`). Attacker bytes are zero-padded into the parked buffer (`FUN_140002e00` copy, bounded `min(inLen, queuedLen)` — no overflow, but **no content restriction whatsoever**), then completed as a successful HID input report. Against the companion virtual-HID deployment whose descriptors live in this same binary (63/67-byte keyboard/mouse descriptors at `0x140004390`/`0x1400043D0`), this covers the entire key/modifier/button/relative-X/Y/wheel entity range defined by those descriptors — i.e., the OS-level event stream produced by these "hardware" devices becomes whatever the caller decides.
- **Device fabrication/removal (supporting):** `0x2A2040` (`FUN_140007ae0` `0x140007ae0`) creates new keyboard/mouse PDOs that immediately trigger `IoInvalidateDeviceRelations` (`0x140007c34`) and get picked up by the PnP/HID stack; `0x2A2004` (`FUN_140002744` `0x140002744`) removes them including `ObfDereferenceObject` of referenced objects. Any user can spawn and yank these children (also a persistent PnP churn/DoS knob: keep yanking what the service creates).
- **Information disclosure (minor):** `0x2A2048` (`FUN_14000112c` `0x14000112c`) reveals up to 16 tracked PIDs (~which process holds the device) to any caller.

Practical exploitation requires (a) the device interface open (subject only to the PDO's OS default security — not to anything this driver enforces; see §4) and (b) for full input effect, a HID consumer bound above the child (the parked-IRP model). Even without (b), create/remove alone exposes arbitrary users to the machine's PnP surface.

## 6. VERDICT

**Yes — a user-callable exploitable primitive exists.** This driver's entire purpose is exposing a privileged operation set (create/delete kernel device objects, inject input-report bytes into in-kernel HID consumers, manipulate PnP) through a `DeviceIoControl` interface that it deliberately leaves unauthenticated: no `IoCreateDeviceSecure`, no SDDL, no privilege check, no caller identity ever validated on the create or control paths (Evidence: `FUN_140007000 @ 0x140007000`, `FUN_140007090 @ 0x140007090`, no `Se*` imports, no SD strings; `FUN_140008170 @ 0x140008170` enables the interface unconditionally on START). The only behavioral sanity checks anywhere are buffer-length/magic checks (cases 1, 2, 6, 8) and a per-PDO conditional — none of which bind to *who* is calling. An attacker at **medium integrity / standard user** who can open the device interface (the driver adds zero friction of its own) can, at minimum, create and destroy enumerated HID devices at will, and — once the companion virtual-HID consumer is bound — **originate full-range mouse/keyboard input reports directly kernel-side via `0x2A200C/0x2A2010`** (keystroke/mouse injection/silent control of the machine's input stream) and learn tracked PIDs via `0x2A2048`. The `0x2A2000` case (func 0x800, the only "wide-buffer" variant with a 0xB7 magic) is a repudiated stub (`0x140007ad8` → `0xC0000002`), so the "command channel" surface stops at the eight codes above.

Severity: **High** (user-mode-to-kernel control of device topology and synthetic input; exploitation requires only a standard-user process and this driver being present/loading; integrity levels and device-object default SD may reduce some PnP effects but nothing in the binary itself prevents them). **Privilege assumption: none beyond "a process that can open the device-interface handle."** Remediation: gate the IOCTL dispatcher on a service-only check or rebuild with `IoCreateDeviceSecure` and an explicit SDDL; the tracked-PID facility (0x2A2044/0x2A2048) should at minimum be synchronized and uniqueness-checked.
