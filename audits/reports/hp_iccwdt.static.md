# HP `ICCWDT_C4876B04.sys` - static audit

Identity: **Intel Watchdog Timer driver (Intel WDT)**, version 11.7.0.1017, PE TS 2024-05-14, SHA256 `c4876b0465f1848b71e6e5334515fea100ffd1b803ffcd6c7cf56abb1128de25`. Shipped under HP. Not a generic device-object driver. It is a **KMDF watchdog with MMIO resources and a WMI interface**, so the surface is PnP plus WMI, not a named device.

Method: static only. Ghidra 12.1.4 headless, `DumpAllDecomp.java`. Nothing loaded or installed.

## 1. Verdict

**NO-WRITE** - disqualified by policy: needs the Intel WDT hardware (its MMIO resource is assigned by the platform) and a PnP devnode. The driver publishes no openable name. The WMI write path was not traced to its callers (see section 5), so the surface is documented but not fully characterized.

## 2. What it is (the question the brief asked)

- **Framework:** KMDF. `WdfVersionBind`/`WdfVersionUnbind` are imported from `WDFLDR.SYS`. `entry` @ `0x1400011a0` -> `FxDriverEntryWorker` @ `0x140001070`.
- **Device object:** none created by the driver. No `IoCreateDevice` import. The device comes from the KMDF PnP path (`EvtDriverDeviceAdd`), which needs the PnP-enumerated platform device.
- **Hardware resource:** `EvtDevicePrepareHardware` = `FUN_140007330` @ `0x140007330`. It walks the `CM_RESOURCE_LIST` and, for each memory descriptor (type `0x03`), calls `MmMapIoSpace(descriptor.PA, descriptor.Length, 0)` at line 2682 of the dump. The physical base comes from the **platform resource assignment**, not from user input.
- **WMI:** `IoWMIRegistrationControl` at lines 2920 and 2952 of the dump (`PTR_LOOP_140004028` with `0x80000002`; `DAT_140004fa0` with `0x80010001`). The WMI data block exposes the watchdog controls (`IccWdtGetWdtStatus`, `IccWdtStartWdtOnNextOSBoot`, and similar, by name in the string table).
- **Power:** `PoRegisterPowerSettingCallback` (display-state callbacks, `IccWdtRegisterForDispStatePwrSettingsCallbacks`).
- **Name check:** no `\Device\` or `\DosDevices\` string in the binary. No `IoCreateSymbolicLink`. Nothing for a standard user to open by name.

## 3. Precondition table

| Item | Result |
|---|---|
| Device object created by the driver | No. KMDF PnP device only |
| Openable device name | None |
| User-reachable interface | WMI data block (namespace-gated by WMI, not by a driver DACL) |
| MMIO window | From platform resource (`CM_RESOURCE` type `0x03`), mapped by `FUN_140007330` |
| Setup cost | **hardware** (Intel WDT platform device, ACPI/PCI) + **devnode** (PnP enumeration) |
| Disqualifiers under the brief | Both: hardware and devnode |

## 4. Sinks

| Class | Found | Where |
|---|---|---|
| PHYS / MMIO | Yes, but window is platform-assigned | `MmMapIoSpace` in `FUN_140007330` @ `0x140007330` (line 2682) |
| KVA | No API-level sink | No `MmCopyMemory`, `ZwMapViewOfSection` import |
| PORT | No | No port intrinsic or HAL bus-data import |

## 5. Callback / WMI table

| Callback / registration | Address | Notes |
|---|---|---|
| `entry` | `0x1400011a0` | WDF stub entry |
| `FxDriverEntryWorker` | `0x140001070` | WDF stub |
| `EvtDevicePrepareHardware` | `0x140007330` | maps MMIO from resource list |
| WMI registration | lines 2920, 2952 of dump | `IoWMIRegistrationControl` |
| WMI write path (`IccWdtWriteHWRegister`) | **not located** | The trace string at `0x140002920` is not referenced from any decompiled function body in the dump, so its callers were not found by xref. |
| Power-setting callback (`IccWdtConsDispStatePwrSettingsCallback`) | by name in string table | not traced in full |

**Not traced:** the WMI `SetInstance` / `ExecuteMethod` handlers and the register-write helper. This is the only place a user-controlled offset could reach the mapped MMIO. Because the device is hardware- and devnode-gated, the verdict does not depend on it, but it is the gap in this report.

## 6. Corruption, not write

- Not assessed. The WMI input handler was not traced (section 5).

## 7. Next dynamic test (described, not run)

None planned. The device needs Intel WDT hardware and a devnode, so the policy disqualifies it before a dynamic test would be considered. If the policy ever allows it, the first test is to check whether the WMI write-register path bounds the offset to the mapped window length (`*(pcVar4+0xc)` from the resource).

## 8. NO-WRITE reason (one line)

Surface is a PnP-enumerated KMDF device whose MMIO base comes from the platform, plus WMI; the driver publishes no openable name and needs hardware and a devnode, which the policy disqualifies.
