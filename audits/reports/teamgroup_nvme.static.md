# TeamGroup `nvme_*.sys` - static audit

Family: **StorPort NVMe miniport**, Windows DDK build 6.3.9600.17038 (PE TS 2014-12-08). Six builds, all the same date and version:

| Build | Size | SHA256 (prefix) |
|---|---|---|
| `45635E0B` | 104288 | 45635E0B... (**audited**) |
| `A9B48787` | 104288 | A9B48787... |
| `77C8809A` | 90976 | 77C8809A... |
| `FFD83A43` | 91488 | FFD83A43... |
| `E4AB6E36` | 78688 | E4AB6E36... |
| `35B2D3D4` | 66912 | 35B2D3D4... |

Only `45635E0B` was dumped. The other five share the family, version, and PE timestamp. The master table lists the same API set for all six. They were not individually dumped.

Method: static only. Ghidra 12.1.4 headless, `DumpAllDecomp.java`. Nothing loaded or installed.

## 1. Verdict

**NO-WRITE** - disqualified by policy: the driver is a storage miniport that exists only when a TeamGroup NVMe controller is present (hardware), and its device stack is created by PnP (devnode). No control device of its own.

## 2. What it is

- Imports `StorPortInitialize`, `StorPortExtendedFunction`, `StorPortGetScatterGatherList`, `StorPortGetPhysicalAddress`, `StorPortRegistryRead`, `StorPortNotification`, `StorPortSetDeviceQueueDepth`, `StorPortPause`/`Resume`/`Busy`, plus `MmGetPhysicalAddress` (NTOSKRNL) and `KeStallExecutionProcessor` (HAL). That is a StorPort miniport: it is driven by the storage stack through SRBs.
- No `IoCreateDevice`, `IoCreateSymbolicLink`, or `IoRegisterDeviceInterface` import. No `\Device\` or `\DosDevices\` string. The miniport creates no openable device.
- `entry` @ `0x140012898` -> `FUN_140016000` (init) and `FUN_14000dd78` (`DriverEntry` body, which calls `StorPortInitialize`).

## 3. Precondition table

| Item | Result |
|---|---|
| Control device | None |
| Openable name | None (the disk device is created by the storage stack for the adapter) |
| Entry path | SRB from storport, only after an NVMe PCI controller enumerates |
| Setup cost | **hardware** (NVMe controller, PCI) + **devnode** (PnP) |
| Disqualifiers under the brief | Both: hardware and devnode |

## 4. Sinks (for completeness)

| Class | Found |
|---|---|
| PHYS | `MmGetPhysicalAddress` and `StorPortGetPhysicalAddress` (translation of buffers the stack supplies; not an attacker-chosen target) |
| KVA | None API-level |
| PORT | None found (no `WRITE_PORT` or `HalSetBusData` import). The NVMe register path was **not traced**: `StorPortGetDeviceBase` is imported, but its only reference in the dump is the import thunk. |

Scatter-gather use: `StorPortGetScatterGatherList` is called from `FUN_1400047a0` @ `0x1400047a0` and `FUN_140004888` @ `0x140004888`. These handle stack-supplied buffers, not user-supplied addresses.

## 5. Storport SRB shape (brief item)

The brief lists "storport SRB DataTransferLength vs actual copy" as a known shape. It was **not traced**: the disqualifier means the check would not change the verdict. If the policy ever admits hardware-bound drivers, this is the first thing to trace in `FUN_14000dd78`'s `BuildIo` and `StartIo` callbacks.

## 6. Corruption, not write

- Not assessed beyond the import table (see section 5).

## 7. Next dynamic test (described, not run)

None planned. Hardware and devnode disqualify it.

## 8. NO-WRITE reason (one line)

StorPort miniport with no control device; it is driven only by SRBs from the storage stack on an NVMe controller, which is hardware, and by PnP, which is a devnode.
