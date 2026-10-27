# MSI RTCore family - static audit (reference only)

Scope: `_collected2\drivers\MSI\RTCore32_*`, `RTCore64_*`, `RTCoreMini32_*`, `RTCoreMini64_*`.
Method: static only. Ghidra 12.1.4 headless, `DumpAllDecomp.java`. Nothing loaded, installed, or executed.
Policy: MSI Afterburner family, excluded from the hunt by the playbook and the audit brief. Reference only.

## 1. Verdict

| Build (newest first) | SHA256 (prefix) | PE timestamp | Verdict |
|---|---|---|---|
| RTCore32 `1E0A3CF8` | 1E0A3CF8 | 2024-04-14 | **WRITE-PHYS-MEDIUM-BLOCKED** (primary); also WRITE-PORT-HIGH-BLOCKED (I/O port), WRITE-PORT-MEDIUM-BLOCKED (MSR), WRITE-PORT-MEDIUM-BLOCKED (PCI config) |
| RTCore32 `6F818DAF` | 6F818DAF | 2020-06-18 | Same family. Not traced separately; older build, same device name and DACL literal. |
| RTCore64 `A4F44E26` | A4F44E26 | 2024-04-14 | Structural match to RTCore32 (see section 3). Gate code **not re-traced**; verdict by analogy: WRITE-PHYS-MEDIUM-BLOCKED, WRITE-PORT-*-BLOCKED. |
| RTCore64 `40061B30` | 40061B30 | 2020-06-18 | Same family. Same SDDL and device strings. Not traced separately. |
| RTCoreMini32 `8EDBEAD1` | 8EDBEAD1 | 2024-04-14 | No physical-map import. Port, MSR, PCI present. Gates **not traced**. Verdict: WRITE-PORT-*-BLOCKED (provisional). |
| RTCoreMini64 `014599A7` | 014599A7 | 2024-04-14 | Same family as RTCoreMini32. Not traced. |

Every result is `-BLOCKED`: the device DACL is `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (SYSTEM and Administrators only).

Setup cost: **none**. The driver creates its own device in `DriverEntry`, so there is no devnode. The block is the DACL, not the setup.

## 2. Primary finding (RTCore32 `1E0A3CF8`) - evidence block

These are four separate findings. They are not averaged.

**PHYS (constrained target, arbitrary value)**
- ENTRY POINT: `\\.\RTCore32` -> symlink `\DosDevices\RTCore32` (VA `0x13000`) -> device `\Device\RTCore32` (VA `0x1302c`). IOCTL `0x80002040` (map) then `0x8000204C` (write). Dispatch: `IRP_MJ_DEVICE_CONTROL` (`DriverObject+0x70`, x86 layout) -> `FUN_0001148e` @ `0x1148e`.
- SINK: `FUN_0001148e` @ `0x1148e`, IOCTL `0x8000204C` branch: `*(char|short|uint *)(puVar2[5] + puVar2[2]) = puVar2[7]`. Width from `puVar2[6]` (1, 2 or 4). The mapping base is `MmMapIoSpace` in `FUN_000113de` @ `0x113de`.
- CONTROL: `puVar2[0..1]` = physical base (lo, hi), `puVar2[2..3]` gets the mapped VA, `puVar2[4]` = length, `puVar2[5]` = offset, `puVar2[6]` = width, `puVar2[7]` = value. Mapping and write are bounds-checked by `FUN_000110d6` @ `0x110d6`: `offset + width <= mapping size`, and the stored physical base must match.
- CLASS: **PHYS**.
- Target constraint (the reason this is MEDIUM, not HIGH): `FUN_00011190` @ `0x11190` gates every physical base. It allows only:
  1. the legacy option-ROM window `[0xC0000, 0xE0000)` (checked via `FUN_0001114c` @ `0x1114c`, args `0xc0000, 0x20000`), or
  2. a 16 MB window starting at a **memory BAR of a PCI function whose base class is 0x03 (display)**. Bus, slot, and BAR index come from the input. Class is read with `HalGetBusDataByOffset` at config offset `0x0B`.
  
  Any other physical address returns FALSE. The section map IOCTL `0x80002000` (`FUN_0001124a` @ `0x1124a`) calls the same gate before `ZwMapViewOfSection` on `\Device\PhysicalMemory`.

**PORT - I/O (arbitrary port, arbitrary value)**
- IOCTL `0x80002014` (byte), `0x80002018` (word), `0x8000201C` (dword) -> `out(port, value)` with `port = *puVar2`, `value = puVar2[1]`.
- Gate: `FUN_0001145a` @ `0x1145a`. Returns FALSE only for port `0xCFC` when CF8 bit 31 is set and the register is in the BAR window (`0x10-0x27`). All other ports pass. This is a narrow carve-out, not an allow-list.
- Verdict: **WRITE-PORT-HIGH-BLOCKED**.

**PORT - MSR (arbitrary value, denylist target)**
- IOCTL `0x80002034` -> `wrmsr(index, value)`; `0x80002030` -> `rdmsr`.
- Gate: `FUN_00011120` @ `0x11120`. Denies `0x174-0x176` and `0xC0000080-0xC0000084`. Everything else passes. It is a denylist.
- Verdict: **WRITE-PORT-MEDIUM-BLOCKED** (target constrained by denylist; value arbitrary).

**PORT - PCI config (constrained offset)**
- IOCTL `0x80002054` -> `HalSetBusDataByOffset(4, bus, slot, value, offset, width)`. Bus, slot, function, and offset come from the input.
- Gate: offset must be `< 0x10` or `> 0x27`, so BAR registers are excluded. Width 1, 2, or 4. No bus or function check.
- Verdict: **WRITE-PORT-MEDIUM-BLOCKED**.

## 3. Precondition table

| Build | Device created in | Device name / DACL | Source address | Setup cost | Reach |
|---|---|---|---|---|---|
| RTCore32 `1E0A3CF8` | `DriverEntry` (`entry` @ `0x1603e` -> `FUN_0001192e` @ `0x1192e`) | `\Device\RTCore32` via `IoCreateDeviceSecure`; SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | literal `0x11e3e`, reference `0x11953` | none | admin-only |
| RTCore32 `6F818DAF` | same pattern (not traced) | same family strings | - | none | admin-only (assumed) |
| RTCore64 `A4F44E26` | `DriverEntry` (`entry` @ `0x18064` calls `FUN_00011b30`; callee not traced) | `\Device\RTCore64`, SDDL literal at `0x12200`; `\DosDevices\RTCore64` at `0x142e0` | literal `0x12200` | none | admin-only (by literal) |
| RTCoreMini32 `8EDBEAD1` | `DriverEntry` (`entry` @ `0x1603e` calls `FUN_00011390`; callee not traced) | `\Device\RTCoreMini32`; SDDL literal at `0x11870` | literal `0x11870` | none | admin-only (by literal) |

Single device per build, as far as traced. RTCore32: one device-creation call site, from `entry` -> `FUN_0001192e`. No `IoRegisterDeviceInterface` in any build's import list, so no interface alternate path. For RTCore64 and RTCoreMini32 the `IoCreateDevice` call-site count is 2 (the wrapper plus an internal reference); the device-creation callees were not traced in full, so "single device" is confirmed only for RTCore32.

## 4. IOCTL table (RTCore32 `1E0A3CF8`, function `FUN_0001148e` @ `0x1148e`)

| IOCTL | Operation | Handler / gate | Attacker input | Verdict |
|---|---|---|---|---|
| `0x80002000` | map `\Device\PhysicalMemory` to user | `FUN_0001124a` -> gate `FUN_00011190` | phys base, length | (map primitive; see PHYS) |
| `0x80002004` | `ZwUnmapViewOfSection` | - | section VA | n/a |
| `0x80002008` / `200C` / `2010` | `in` byte / word / dword | none | port | READ |
| `0x80002014` / `2018` / `201C` | `out` byte / word / dword | `FUN_0001145a` (narrow) | port, value | **WRITE-PORT-HIGH-BLOCKED** |
| `0x80002028` | status query | - | - | n/a |
| `0x8000202C` | write global accumulator `DAT_000131e8` | - | value | not a device-write primitive |
| `0x80002030` / `2034` | `rdmsr` / `wrmsr` | `FUN_00011120` (denylist) | MSR index, value | **WRITE-PORT-MEDIUM-BLOCKED** |
| `0x80002040` | map physical range (kernel `MmMapIoSpace`) | `FUN_000113de` -> `FUN_00011190` | phys base, length, BAR index, bus/slot/fn | (map; see PHYS) |
| `0x80002044` | unmap | `FUN_0001108a` | mapping index | n/a |
| `0x80002048` | read through mapping | `FUN_000110d6` | offset, width | READ |
| `0x8000204C` | **write through mapping** | `FUN_000110d6` (bounds) | offset, width, value | **WRITE-PHYS-MEDIUM-BLOCKED** |
| `0x80002050` | PCI config read | `HalGetBusDataByOffset` | bus, slot, offset | READ |
| `0x80002054` | PCI config write | offset filter (`<0x10` or `>0x27`) | bus, slot, offset, value | **WRITE-PORT-MEDIUM-BLOCKED** |

## 5. Corruption, not write

- None found in the RTCore32 handler. Input lengths are checked on every branch (`uVar7 == 8`, `== 0x30`, `== 0x18`, `== 0xc`).

## 6. Next dynamic test (described, not run)

- Confirm the DACL in the VM only, after DriverEntry creates the device: `CreateFile("\\\\.\\RTCore32")` from a standard-user token should return `0xC0000022` (ACCESS_DENIED). If it succeeds, the verdict changes from BLOCKED to reachable and this report must be reopened.
- For RTCore64 and RTCoreMini, the same DACL check, plus a trace of the write gate, before any verdict is upgraded from provisional.

## 7. Notes

- Reference only, per the brief. Primitives are documented for comparison; no exploit or test code is included.
- The RTCore32 primitive is constrained (MEDIUM) by the physical-target gate. A plain "RTCore arbitrary physical write" description is wrong for this build.
- Blocklist status is taken from the playbook (`DRIVER_COLLECTION_PLAYBOOK.md` section 2). It was not checked against the Microsoft list in this pass.
