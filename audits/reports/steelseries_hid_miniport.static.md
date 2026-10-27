# SteelSeries HID / USB miniports - static audit

Families in scope: **hidkmdf** (6 builds), **xusb21** (4 builds), **STTub30** (4 builds, listed under Priority A in the brief).
Method: static only. Ghidra 12.1.4 headless, `DumpAllDecomp.java`. Nothing loaded or installed.

## 1. Verdicts

| Family | Newest build audited | Date / version | Verdict | Disqualifier |
|---|---|---|---|---|
| `hidkmdf` | `117F6300` (SHA256 `117F6300...`) | 2020-09-25, 10.0.10011.16384 | **NO-WRITE** | hardware (HID device) + devnode |
| `xusb21` | `0AABCEB6` (SHA256 `0AABCEB6...`) | 2009-08-13, 9.18.1034.0 | **NO-WRITE** | hardware (USB controller) + devnode |
| `STTub30` | `9E1CF7F9` (SHA256 `9E1CF7F9...`) | 2015-04-22, 3.0C | **NO-WRITE** | hardware (STMicro USB device) + devnode |

Other builds in each family were not dumped:
- `hidkmdf`: `AFBBA1BA`, `B6CCCC46`, `60D9E781` share the 2020-09-25 date. `19D8C116` and `4E1A5F19` are 2017-08-14. All use the same HID minidriver framework.
- `xusb21`: `9D614C5D` (same build date as `0AABCEB6`), `785DEFAE` and `B7A7A906` (2009-04-08, 9.18.1015.0).
- `STTub30`: `D1083D40` (same 3.0C build as `9E1CF7F9`), `23C68E2F` and `4D7F2B9D` (2009-11-10, 3.0B). Their device-creation call sites were not located by the same pattern.

## 2. The three families

### hidkmdf - KMDF HID minidriver (`117F6300`)

- Imports `HidRegisterMinidriver` from `HIDCLASS.SYS` and `WdfVersionBind` from `WDFLDR.SYS` (KMDF). Entry `entry` @ `0x1400011c0` -> `FxDriverEntryWorker`.
- No `IoCreateDevice` / `IoCreateSymbolicLink` import. No device name. The device is the HID child created by `HIDCLASS` for the attached hardware.
- User input reaches the driver only through HID class IRPs for that device (feature and output reports). Those exist only with the HID hardware attached.
- The brief's shape "HID report length vs buffer length" was **not traced**. The disqualifier makes the check moot for this verdict.

### xusb21 - Microsoft XUSB bus driver (`0AABCEB6`)

- KMDF (`WdfVersionBind`, `WDFLDR.SYS`). Imports BCrypt (KSECDD), `PoSetSystemState`, `RtlCopyUnicodeString`. Entry `entry` @ `0x1d62c` -> `FxDriverEntryWorker`.
- Strings are USB and XUSB device-ID formats (`USB\VID_%04X&PID_%04X...`, `XUSB\TYPE_%02X\...`). It enumerates child devices from a USB controller, so it needs an Xbox-class controller attached.
- No `MmMapIoSpace`, no port intrinsic, no `ZwCreateFile`, no `IoRegisterDeviceInterface` import in the dump.
- The four builds are Microsoft's XUSB driver as shipped inside the SteelSeries package. The version strings match the XUSB build line, not a SteelSeries build.

### STTub30 - STMicroelectronics generic USB function driver (`9E1CF7F9`)

- Imports `IoCreateDevice`, `IoRegisterDeviceInterface`, `IoSetDeviceInterfaceState`, `IoAttachDeviceToDeviceStack`, `USBD_*`, and registry APIs (`ZwOpenKey`, `ZwSetValueKey`, `ZwQueryValueKey`). That is a PnP USB function driver.
- `IoCreateDevice(param_1, 0x4f8, NULL, 0x22)` in `FUN_0001043c` @ `0x1043c` (`9E1CF7F9`, dump line 500; `4D7F2B9D` at dump line 498). **The name argument is NULL**, so the device has no name. There is no `\Device\` or `\DosDevices\` string in the binary.
- Access is through `IoRegisterDeviceInterface`, which runs only when the STMicro USB device enumerates. The master table's `DEFAULT-ADMIN` label is therefore wrong: the correct description is **PnP interface, hardware-only**.
- **Sink check:** `MmMapIoSpace`, `HalGet/SetBusData*`, `ZwMapViewOfSection`, `MmCopyMemory`, and `wrmsr` were each counted at **0** in all four STTub30 dumps.

## 3. Precondition table

| Family | Device object | Name | Interface | Setup cost | Hardware |
|---|---|---|---|---|---|
| hidkmdf | HID child (by `HIDCLASS`) | none | HID class | devnode | HID device |
| xusb21 | child devices (XUSB bus) | XUSB IDs (not openable names) | - | devnode | Xbox-class USB controller |
| STTub30 | yes, unnamed, AddDevice | none | `IoRegisterDeviceInterface` | devnode | STMicro USB device |

## 4. Callback / IOCTL summary

- **hidkmdf:** HID minidriver callbacks registered through `HidRegisterMinidriver`. Not enumerated in full (disqualified).
- **xusb21:** KMDF queue and bus callbacks. Not enumerated in full (disqualified).
- **STTub30:** `entry` @ `0x18764` (`9E1CF7F9`; `0x186e4` in `4D7F2B9D`). `IoCreateDevice` call in `FUN_0001043c` @ `0x1043c` (whether this is the AddDevice routine was not confirmed). USB transfers through `USBD_*`. Not enumerated in full (disqualified).

## 5. Corruption, not write

- Not assessed for any family (the disqualifier makes the buffer review unnecessary for this verdict).

## 6. Next dynamic test (described, not run)

None planned. All three need the hardware and a devnode, so the policy disqualifies them before a dynamic test is considered.

## 7. NO-WRITE reasons (one line each)

- **hidkmdf:** HID minidriver; its only input is HID reports from attached hardware, through a devnode.
- **xusb21:** XUSB bus driver; its child devices exist only with an attached USB controller, through a devnode.
- **STTub30:** unnamed PnP device with no sink class; reachable only through the device interface that exists with the attached STMicro USB device.
