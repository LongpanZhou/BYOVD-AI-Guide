# Audit: SteelSeries `sshid` and `hidkmdf` core builds - kernel memory-write re-audit

| Field | Value |
|---|---|
| File(s) | `sshid_19A13E79.sys`, `sshid_45CC60FB.sys`, `sshid_4FE83B22.sys`, `sshid_72565A1F.sys`, `sshid_7DA7D360.sys`, `sshid_ADD52989.sys`, `sshid_ECC0EDB7.sys`, `hidkmdf_117F6300.sys`, `hidkmdf_19D8C116.sys`, `hidkmdf_4E1A5F19.sys`, `hidkmdf_60D9E781.sys`, `hidkmdf_AFBBA1BA.sys`, `hidkmdf_B6CCCC46.sys` |
| SHA-256(s) | Per-file table in section 1 (all 13 full hashes) |
| Analysis date | 2026-10-25 |
| Method | Static-only: local Ghidra 12.1.4 headless (`analyzeHeadless` + `DumpAllDecomp.java`; per-build dumps in `C:\Users\<scrubbed>\AppData\Local\Temp\opencode\ss_hid\`), cross-checked with `objdump` 2.41. No REA session was used (three other REA audits active; bridge at capacity per `audits/STATUS.md`). No load, execution, service creation, registry write, install, or web lookup. |
| Reach tier | **R1** for the `sshid` control device (Everyone `GRGW` DACL); **R3** for `hidkmdf` (HID hardware/devnode) |
| Setup required | **service** for `sshid` (SteelSeries Engine service loads the driver; no hardware required); **hardware + devnode** for `hidkmdf` |
| Write quality | **W0** |
| Verdict | **NO-MEMORY-WRITE** for the loadable x64 builds; **BLOCKED** (i386-only, not loadable on x64) for six builds. No MW1-MW4. |
| HW-only | no (no MSR/port/PCI/SMBus/MMIO path in any build) |

---

## 1. Files, integrity, and build clustering

SHA-256 was recomputed with `Get-FileHash -Algorithm SHA256`; every hash matches the filename prefix. All 13 images have `Authenticode Status = Valid`; none is in `indexes/dedupe/known_bad_hashes.txt`.

| File | SHA-256 | Arch | Version | Signer | Size |
|---|---|---|---:|---|---:|
| `sshid_19A13E79.sys` | `19A13E79F0754F3E9D310880429FF64A1449A677BF9FE7E5A1008DFF7FC426A4` | x64 | 2.7.1.0 | SteelSeries ApS | 57,440 |
| `sshid_45CC60FB.sys` | `45CC60FB5A237AB6959C917B2C7B9764E39B1F00D533E526726A12765EEBB750` | i386 | 2.7.1.0 | SteelSeries ApS | 51,248 |
| `sshid_4FE83B22.sys` | `4FE83B22EC1E8E42A66F97FB2F87BD7D90E37D4B38BD19DF9892D463942D3802` | i386 | 2.7.1.0 | SteelSeries ApS | 52,808 |
| `sshid_72565A1F.sys` | `72565A1FCB602AB02EFEFFDEB1C737EC0564920D1EE75B294D2D24D0A7F963CA` | x64 | 2.7.1.0 | SteelSeries ApS | 55,392 |
| `sshid_7DA7D360.sys` | `7DA7D360AA1FF5BCB1D57FAC307528A75335D7AF74C10556E48790761C467992` | x64 | 2.7.1.0 | SteelSeries ApS | 55,392 |
| `sshid_ADD52989.sys` | `ADD529899D3062F7BF556BAC9D6620D197FBB77151697BEEE3359EC90EC631A5` | x64 | 2.11.5.0 | Microsoft WHCP | 65,696 |
| `sshid_ECC0EDB7.sys` | `ECC0EDB7996E19385692F2D1F2B0CC677EBE1108D0676F6E2AB69E12D61F1D19` | i386 | 2.7.1.0 | SteelSeries ApS | 51,248 |
| `hidkmdf_117F6300.sys` | `117F63004271E1F83ABED8AB212A0BB29740D6F4FE53EDD112AEC53E53D1ACD8` | x64 | 10.0.10011.16384 | Microsoft WHCP | 25,928 |
| `hidkmdf_19D8C116.sys` | `19D8C1166BFA0030864EB29D8E6B260AB6DC4066451BA58457EA364A0DA4F5BC` | x64 | 10.0.10011.16384 | SteelSeries ApS | 26,376 |
| `hidkmdf_4E1A5F19.sys` | `4E1A5F19AF2BCDE4748B685C4C777E6CD5C12DC4AF00BF98040BB61D92E4F635` | i386 | 10.0.10011.16384 | SteelSeries ApS | 24,272 |
| `hidkmdf_60D9E781.sys` | `60D9E781533926AAB6D8AE8CB11F7B1FFAC5B92B0DA7BD372260AA2CC800AB91` | x64 | 10.0.10011.16384 | Microsoft WHCP | 25,920 |
| `hidkmdf_AFBBA1BA.sys` | `AFBBA1BA4DBDCAF8CE13BC3514538E2929E2906E6568D175E90768D6AA5592CE` | i386 | 10.0.10011.16384 | Microsoft WHCP | 24,384 |
| `hidkmdf_B6CCCC46.sys` | `B6CCCC464CF4333F964B90DBC1E3B0C55160D88960B4AB3CFF670A601AC06E93` | i386 | 10.0.10011.16384 | Microsoft WHCP | 24,376 |

**Build clustering (section-by-section SHA-256, so PE timestamps/signatures do not hide code identity):**

- `sshid_45CC60FB` === `sshid_ECC0EDB7`: all section hashes identical (`.text` `752080AE...`); only PE header/signature/timestamp differ.
- `sshid_72565A1F` === `sshid_7DA7D360`: all section hashes identical (`.text` `699F83F9...`).
- `hidkmdf_117F6300` === `hidkmdf_60D9E781`: all section hashes identical (`.text` `C3000B2F...`).
- `hidkmdf_AFBBA1BA` === `hidkmdf_B6CCCC46`: all section hashes identical (`.text` `DE2CF738...`).
- Unique code images: `sshid` 5 (`19A13E79`, `45CC60FB`/`ECC0EDB7`, `4FE83B22`, `72565A1F`/`7DA7D360`, `ADD52989`); `hidkmdf` 4 (`117F6300`/`60D9E781`, `19D8C116`, `4E1A5F19`, `AFBBA1BA`/`B6CCCC46`).

The six i386 images (`sshid_45CC60FB`, `sshid_4FE83B22`, `sshid_ECC0EDB7`, `hidkmdf_4E1A5F19`, `hidkmdf_AFBBA1BA`, `hidkmdf_B6CCCC46`) are **BLOCKED** for this host: `Machine = 0x014C`, not loadable on x64. Their static code is audited below and adds no primitive; they do not change the x64 verdict.

**Relationship to the historical baselines.** `audits/reports/steelseries_hid.static.md` audited only `sshid_ADD52989` and did not enumerate the 2.7.1.0 code; this re-audit independently re-derived `ADD52989` from its own dump and added the six other `sshid` builds. `audits/reports/steelseries_hid_miniport.static.md` audited only `hidkmdf_117F6300` and stopped at the hardware disqualifier; this re-audit traces all six `hidkmdf` builds and the full registration/forwarder path. No historical verdict was inherited.

---

## 2. Internals

### 2.1 `sshid` - SteelSeries HID proxy / control device

All seven builds are KMDF drivers bound through `WdfVersionBind`/`WdfVersionBindClass` (imports only `WDFLDR.SYS`; the `Wdf*` APIs are indirect calls through a per-driver function table). The representative import set is small: `ntoskrnl.exe` (`DbgPrintEx`, `ExEventObjectType`, `ObReferenceObjectByHandle`, `ObfDereferenceObject`, `KeSetEvent`, `RtlCopyUnicodeString`, `sqrt`), `HAL.dll` (`KeQueryPerformanceCounter`), and `WDFLDR.SYS`; individual builds vary slightly. **No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `MmGetPhysicalAddress`, `ZwMapViewOfSection`, `IoAllocateMdl`, `MmProbeAndLockPages`, `MmAllocateContiguousMemory`, port-I/O, MSR, PCI-config, SMBus/EC, or `\Device\PhysicalMemory` path is imported or present.**

`DriverEntry` is the function reached from the KMDF stub; it creates a **control device in `DriverEntry`**, so the device exists as soon as the service starts - it is not a PnP FDO and does not need a devnode or hardware. The device is named `\Device\SSengine`, published as `\DosDevices\SSengine` (`\\\\.\\SSengine`), and its `WDF_IO_QUEUE_CONFIG` is a single 0x60-byte queue with `EvtIoDeviceControl` at config offset `+0x28`; all other queue callbacks are zero. There is no read/write/internal-IOCTL queue.

Representative build anchors:

| Build | `DriverEntry` | `EvtIoDeviceControl` | Device name literal | Symlink literal |
|---|---:|---:|---|---|
| `ADD52989` | `0x14000D000` | `0x14000D360` | `0x14000DC10` | `0x14000DC40` |
| `19A13E79` | `0x140009000` | `0x140009360` | `0x140009BC0` | `0x140009BF0` |
| `72565A1F` / `7DA7D360` | `0x14000A000` | `0x14000A300` | `0x14000AAD0` | `0x14000AB00` |
| `45CC60FB` / `ECC0EDB7` | `0x00407000` | `0x004072B0` | `0x00407974` | `0x00407996` |
| `4FE83B22` | `0x00408000` | `0x004082E0` | `0x004089F4` | `0x00408A16` |

### 2.2 `hidkmdf` - Microsoft HID-KMDF interface filter

`hidkmdf` is the generic Microsoft HID-KMDF minidriver/filter (`OriginalFilename HIDKMDF.SYS`, version 10.0.10011.16384), shipped inside the SteelSeries package. Imports: `HIDCLASS.SYS!HidRegisterMinidriver`, `ntoskrnl` (`IofCallDriver`, `PoCallDriver`, `PoStartNextPowerIrp`, `KeBugCheckEx`, `RtlCopyUnicodeString`), and `WDFLDR.SYS`. **No device-creation, security, memory-mapping, MDL, or port-I/O imports.**

- `entry` (`0x1400011C0` in `117F6300`/`19D8C116`; `0x004010C4` in `4E1A5F19`) calls the KMDF worker (`FxDriverEntryWorker` at `0x1400011F0` in `117F6300`, `FUN_1400011EC` in `19D8C116`, or the equivalent at `0x004011B0` in `AFBBA1BA`), which binds WDF and then calls the minidriver registration function (`0x140007000` in `117F6300`; `0x140008000` in `19D8C116`; `0x00405000` in the i386 builds).
- The registration function fills the `DRIVER_OBJECT.MajorFunction[]` array with one forwarder (`0x140001000` / `0x00401000`) and sets the power entry to a `PoStartNextPowerIrp`/`PoCallDriver` forwarder (`0x140001040` / `0x00401030`), then calls `HidRegisterMinidriver` with `DeviceExtensionSize = 0`. There is **no `WdfDeviceCreate`, `IoCreateDevice`, `IoCreateSymbolicLink`, `WdfDeviceCreateSymbolicLink`, `WdfDeviceInitAssignSDDLString`, or `IoRegisterDeviceInterface` call in any of the six images.**
- The forwarder copies the current `IO_STACK_LOCATION` to the next location (a fixed IRP-owned structure) and calls `IofCallDriver`; it never reads or writes the request's user buffer. `hidkmdf` therefore has no user IOCTL dispatch of its own: user IOCTLs on the HID collection are handled by HIDCLASS, and only HID class IRPs are forwarded down the stack.

---

## 3. Entry / device / interface / effective DACL

### 3.1 `sshid` - the `GRGW` DACL is live in all seven builds

The only SDDL string in any `sshid` image is **variant A**:

```text
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)
```

A raw UTF-16 scan of all seven images finds exactly one `D:P(A;;GA;;;SY)...` string and **zero** occurrences of the `GRGWGX;;;WD` variant B. So the broader `GRGWGX`/Everyone-RWX form is **not used** by any build in this set; the effective form is Everyone `GENERIC_READ|GENERIC_WRITE`, protected (`P`), with no inherited ACE able to tighten it.

The string is not dead. In every build it is passed as the SDDL argument to the control-device init allocator whose return value is the `WDFDEVICE_INIT` later consumed by `WdfDeviceCreate`:

| Build | SDDL `UNICODE_STRING` | Buffer | `Length`/`Max` | Call-site evidence |
|---|---:|---:|---|---|
| `ADD52989` | `0x140009578` | `0x140009500` | `0x72`/`0x74` | `14000D128 LEA R8,[0x140009578]`; `14000D143 CALL [+0xC8]`; return stored and passed to `+0x258` (`WdfDeviceCreate`) |
| `19A13E79` | `0x140006228` | `0x1400061B0` | `0x72`/`0x74` | `140009128 LEA R8,[0x140006228]`; `140009143 CALL [+0xC8]`; return `0x38(%rsp)` passed to `+0x258` |
| `72565A1F` / `7DA7D360` | `0x140006258` | `0x1400061E0` | `0x72`/`0x74` | `14000A116 LEA R8,[0x140006258]`; `14000A127 CALL [DAT_1400071A8]`; return passed to `DAT_140007338` (`WdfDeviceCreate`) |
| `45CC60FB` / `ECC0EDB7` | `0x004051DC` | `0x00405168` | `0x72`/`0x74` | `DriverEntry 0x00407000`: `puVar7 = &DAT_004051DC`; call returns `local_60`, used as the init pointer in the create call at `DAT_004061A4` |
| `4FE83B22` | `0x004061DC` | `0x00406168` | `0x72`/`0x74` | `DriverEntry 0x00408000`: `puVar7 = &DAT_004061DC`; same init -> create -> symlink sequence |

The called entry has the `WdfControlDeviceInitAllocate(Driver, SDDLString)` signature: it takes the WDF driver handle plus the `UNICODE_STRING`, returns a pointer, and the pointer is checked for null then passed as `WDFDEVICE_INIT **` to the create call. (The exact function-table index is KMDF-version-specific; the signature and the returned init are decisive.) After the SDDL call the sequence is a device-init option call (`+0x1F0`, argument 0 - consistent with `WdfDeviceInitSetIoType(init, WdfDeviceIoBuffered)`), `WdfDeviceInitAssignName(init, &name)` (`+0x218`), `WdfDeviceCreate(&init, NULL, &device)` (`+0x258`), `WdfDeviceCreateSymbolicLink(device, &link)` (`+0x280`), `WdfIoQueueCreate` (`+0x4C0`). There is no later security assignment, no `WdfDeviceInitSetFileObjectConfig` security callback, and no `IoCreateDeviceSecure` fallback.

**Effective DACL for every `sshid` build:** `SYSTEM` all; Builtin Administrators read/write/execute; **Everyone read/write**; Restricted Code read. Because the DACL is protected, a parent device or service cannot tighten it. The control device's DACL governs opens to `\Device\SSengine` itself; any child HID PDOs are separate device objects and do not broaden this gate. The open gate is therefore **R1**: any local user who can call `CreateFile` on `\\\\.\\SSengine` with `GENERIC_READ|GENERIC_WRITE` can reach all IOCTLs. No privilege check, `SeAccessCheck`, `SeSinglePrivilegeCheck`, `FILE_WRITE_ACCESS` test, requestor-mode test, or handshake exists in any `sshid` dispatcher (grep of all five unique images: zero hits).

**Interface GUID:** the control device has no device-interface GUID; only the named control device and its `\DosDevices` symlink are created in `DriverEntry`. A `WdfDeviceCreateDeviceInterface` call for the control device is absent, and the image contains no interface GUID string.

### 3.2 `hidkmdf` - no image-owned device or DACL

`hidkmdf` creates no device, no symbolic link, no interface, and contains no SDDL string. Its only reachable surface is the HID collection created by `HIDCLASS` when the supported HID hardware enumerates; the collection's security descriptor comes from `HIDCLASS`/the HID INF, not from this image. The image contributes no IOCTL dispatch: it forwards every IRP to the lower transport. Its reach is therefore **R3 (hardware + devnode)**, and its own DACL is **not applicable / not in the image**.

---

## 4. Dispatch and IOCTL table

All `sshid` IOCTLs are `CTL_CODE(0xC0DE, function, METHOD_BUFFERED, FILE_ANY_ACCESS)`; every function code is a multiple of 4, so the method bits are 0 and the access bits are 0. There is no `METHOD_NEITHER`, `METHOD_IN_DIRECT`, or `METHOD_OUT_DIRECT` code in any build. The single queue delivers only `EvtIoDeviceControl`; read/write/internal-IOCTL requests are not dispatched to a driver callback.

`B/ANY` = `METHOD_BUFFERED` / `FILE_ANY_ACCESS`. Handler addresses are the 2.11.5.0 (`ADD52989`) and 2.7.1.0 (`19A13E79` / `72565A1F`) functions; the i386 2.7.1.0 builds use the same code set with shifted addresses.

| Code | Fn | Method/Access | Input | Output | 2.11.5 handler | 2.7.1 handler | Kernel action |
|---|---:|---|---:|---:|---:|---:|---|
| `0xC0DE0000` | 0 | B/ANY | - | - | inline | inline | set global flag `DAT_...B7C0`/`...7390` = 0 |
| `0xC0DE0004` | 1 | B/ANY | - | - | inline | inline | set global flag = 1 |
| `0xC0DE0008` | 2 | B/ANY | 0x814 | - | `FUN_1400014B8` | `FUN_14000148C` / `FUN_140001458` | validate input[0x10] < 0x101; for each child, copy 0x814 to a `WDFMEMORY` and send vendor IOCTL `0x6F72634D` to the HID target |
| `0xC0DE000C` | 3 | B/ANY | 0x10 | - | `FUN_1400017CC` | `FUN_1400017A0` / `FUN_140001714` | compare 0x10-byte descriptor/string against child list; remove/reset matching child |
| `0xC0DE0010` | 4 | B/ANY | 4 | - | `FUN_140001668` | `FUN_14000163C` / `FUN_1400015D8` | VID/PID lookup; reset matching child |
| `0xC0DE0014` | 5 | B/ANY | 0x38 | - | `FUN_140001CB8` | `FUN_140001C88` / `FUN_140001B74` | write 10 dwords + count into child ctx base `+0x168`, field `+0x38` (fixed offsets) |
| `0xC0DE0018` | 6 | B/ANY | 0x38 | - | `FUN_140002160` | `FUN_140001E88` / `FUN_140001D58` | write 10 dwords into child ctx base `+0x168`, field `+0x60` (fixed) |
| `0xC0DE001C` | 7 | B/ANY | 0x14 | - | `FUN_140002488` | `FUN_140001F0C` / `FUN_140001DD4` | write byte + dword fields into child ctx base `+0x168`, fields `+0x350...` (2.11) or `+0x290...` (2.7) |
| `0xC0DE0020` | 8 | B/ANY | 0x18 | - | `FUN_140002068` | `FUN_140001D90` / `FUN_140001C6C` | write 2 dwords into child ctx base `+0x168`, fields `+0x398/0x39C` (2.11) or `+0x2B8/0x2BC` (2.7) |
| `0xC0DE0024` | 9 | B/ANY | 0x18 | - | `FUN_140001FE4` | `FUN_140001D0C` / `FUN_140001BF0` | write dword into child ctx base `+0x168`, field `+0x3A0` (2.11) or `+0x2C0` (2.7) |
| `0xC0DE0028` | A | B/ANY | 0x18 | - | `FUN_1400020EC` | `FUN_140001E14` / `FUN_140001CE8` | write byte into child ctx base `+0x168`, field `+0x3A4` (2.11) or `+0x2C4` (2.7) |
| `0xC0DE002C` | B | B/ANY | 8 | - | `FUN_140001C58` | `FUN_140001C28` / `FUN_140001B18` | `ObReferenceObjectByHandle(handle, 2, ExEventObjectType, 1, &global, 0)`; store referenced event in global |
| `0xC0DE0030` | C | B/ANY | - | >=0x50 | `FUN_140001BB4` | `FUN_140001B84` / `FUN_140001A84` | `memset(out,0,0x50)`, fill 0x50-byte device/status list (8-byte entries from child VID/PID fields), `WdfRequestSetInformation(outLen)` |
| `0xC0DE0034` | D | B/ANY | - | - | `FUN_140001AC0` | `FUN_140001A90` / `FUN_1400019B0` | enumerate/reset all children; no user buffer |
| `0xC0DE0038` | E | B/ANY | 0x814 | - | `FUN_140001960` | `FUN_140001934` / `FUN_140001878` | validate input[0x10] < 0x101; copy 0x814 to `WDFMEMORY`; send vendor IOCTL `0x6F72634D` |
| `0xC0DE003C` | F | B/ANY | 0x10 | - | `FUN_14000261C` | - | write 2 dwords + flag into child ctx base `+0x168`, fields `+0x3A8/0x3AC/0x3B0` |
| `0xC0DE0040` | 10 | B/ANY | 0x18 | - | `FUN_1400022F4` | - | write flag/double into child ctx base `+0x168`, fields `+0x370/0x378` |
| `0xC0DE0044` | 11 | B/ANY | 0xB0 | - | `FUN_140001E4C` | - | write 10 16-byte entries into child ctx base `+0x168`, fields `+0x98/+0xA0...` |

The `0xC0DE0008`/`0xC0DE0038` vendor IOCTL (`0x6F72634D`, ASCII "Mcro") is a fixed 0x814-byte blob sent to a child HID target via `WdfIoTargetSendIoctlSynchronously`; it is not a kernel-memory write and no length is taken from the caller beyond the fixed 0x814.

---

## 5. Access-control audit

- **`sshid`:** the only gate is the variant-A DACL. Everyone has `GRGW`; all IOCTLs are `FILE_ANY_ACCESS`, so a plain `CreateFile` with read or write access is sufficient. There is no `SeAccessCheck`, `SeSinglePrivilegeCheck`, `FILE_WRITE_ACCESS` check, requestor-mode check, caller-identity check, or device-interface allow-list. This is **R1** after the SteelSeries service has loaded the driver; the service is an installation/loading step, not a per-open gate. The requester's admin access is not needed to open the device.
- **`hidkmdf`:** no image-owned DACL or IOCTL handler. The HID collection's DACL is `HIDCLASS`'s; the image only forwards IRPs. Reach is **R3** and requires the HID hardware/devnode.
- **Setup:** `sshid` = `service` (SteelSeries Engine); no hardware or devnode. `hidkmdf` = `hardware` (supported HID device) plus `devnode`.

---

## 6. Memory-write trace

### 6.1 `sshid` - every write is fixed-target/fixed-size

| Caller-controlled source | Kernel destination | Size | Constraint / evidence |
|---|---|---|---|
| IOCTL `0x14` input `+8...` | child ctx base `+0x168`, fields `+0x38...` | fixed scalar block + 10 dwords | `FUN_140004EAC`/`FUN_140005AF8`/`FUN_1400049BC`: fixed 10-dword loop; destination is `ctx+0x168`, where `ctx` comes from the VID/PID lookup (`FUN_1400094E4` / `FUN_14000D530`), never from the input pointer |
| IOCTL `0x18` input `+8...` | child ctx base `+0x168`, fields `+0x60...` | fixed scalar block + 10 dwords | `FUN_140004F0C`/`FUN_140005BC4`/`FUN_140004A1C`: fixed 10-dword loop |
| IOCTL `0x1C` input `+8...` | child ctx base `+0x168`, fields `+0x350...` (2.11) or `+0x290...` (2.7) | fixed scalar stores | `FUN_140004F40`/`FUN_140005C28`/`FUN_140004A50`: fixed scalar stores |
| IOCTL `0x20` input `+8...` | child ctx base `+0x168`, fields `+0x398/0x39C` or `+0x2B8/0x2BC` | 2 dwords | fixed scalar stores |
| IOCTL `0x24` input `+0x10` | child ctx base `+0x168`, field `+0x3A0` / `+0x2C0` | 4 bytes | fixed scalar store |
| IOCTL `0x28` input `+0x14` | child ctx base `+0x168`, field `+0x3A4` / `+0x2C4` | 1 byte | fixed scalar store |
| IOCTL `0x3C` input `+8...` | child ctx base `+0x168`, fields `+0x3A8/0x3AC/0x3B0` | 2 x 4 + 1 byte | fixed scalar stores (2.11.5 only) |
| IOCTL `0x40` input `+0x10` | child ctx base `+0x168`, fields `+0x370/0x378` | 1 + 8 bytes | fixed scalar stores (2.11.5 only) |
| IOCTL `0x44` input `+8...` | child ctx base `+0x168`, fields `+0x98/+0xA0...` | 10 x 16 bytes | `FUN_140005B2C`: fixed 10-iteration loop, reads <=0xA8 bytes from a 0xB0 input |
| IOCTL `0x08`/`0x38` input | driver-allocated `WDFMEMORY` (0x814) | 0x814 | `WdfMemoryCreate(...,0x814)` + `WdfMemoryCopyFromBuffer(mem,0,input,0x814)`; input length pre-checked `>=0x814`; then sent to the HID target |
| IOCTL `0x30` output buffer | system output buffer | 0x50 | `WdfRequestRetrieveOutputBuffer(req,0x50)`; `memset(out,0,0x50)`; fill 0x50 from a global device/status list |

**Context bounds.** The `ADD52989` child context is created in `FUN_14000D64C` and zeroed with `FUN_140008700(ctx+0x34, 0, 0x4EC)`, covering `ctx+0x34...ctx+0x520`; the highest 2.11.5.0 IOCTL write is `ctx+0x168+0x3B0 = ctx+0x518` (1 byte), inside that range. The 2.7.1.0 builds zero `ctx+0x34...ctx+0x438` (`FUN_140009600` in `19A13E79`, `FUN_14000A578` in `72565A1F`); their highest IOCTL write is `ctx+0x168+0x2C4 = ctx+0x42C` (1 byte), also inside. All context writes are therefore in-bounds for the driver's own allocation, not merely fixed-offset.

**No caller-chosen arbitrary kernel destination exists.** For the context-update IOCTLs, the caller can select among existing child contexts by supplying a VID/PID, but cannot supply a kernel pointer or an offset: the context pointer (`ctx`) comes from the driver's child list and is a driver-owned WDF object context, not a pointer read from the input buffer. The destination offsets are compile-time constants. The sizes are compile-time constants, not caller lengths.

**No caller-chosen write size exists.** Every input handler first checks the WDF-provided input length against a constant (`0x10`, `0x14`, `0x18`, `0x38`, `0xB0`, `0x814`) and then copies exactly that constant or a smaller fixed field. The largest variable-looking value, the 0x814-blob length, is fixed at 0x814 in `WdfMemoryCreate` and in the copy; a larger caller buffer is truncated, a smaller one is rejected.

**No METHOD_NEITHER/user-pointer handling.** Every code in both sets is METHOD_BUFFERED (18 codes in 2.11.5.0, 15 in 2.7.1.0); `WdfRequestRetrieveInputBuffer`/`RetrieveOutputBuffer` return the I/O manager's kernel system buffer, not a user virtual address. There is no raw `Type3InputBuffer`, no `UserBuffer` dereference, and no missing `ProbeForWrite`/`ProbeForRead` because no user pointer is used. The absence of `ProbeForWrite` is therefore not a defect here.

**No MDL/MMIO/physical path.** The import and code scans find zero uses of `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `MmGetPhysicalAddress`, `ZwMapViewOfSection`, `IoAllocateMdl`, `MmProbeAndLockPages`, `MmAllocateContiguousMemory`, `MmAllocatePagesForMdl`, `WRMSR`/`RDMSR`, port I/O, PCI config, SMBus/EC, or `\Device\PhysicalMemory`. `KeQueryPerformanceCounter` is the only HAL call and is a timing source, not an MMIO path.

**HID report-descriptor path is not a kernel write.** The 0x814 blob is copied *from* the caller's system buffer *into* a driver-owned `WDFMEMORY`, then sent to the child HID target. The driver's descriptor parser (`FUN_140003CC0` in `ADD52989` and its counterparts in the 2.7.1.0 images) writes only fixed scalar fields into the child sub-context (offsets `+0x47`, `+0x4C`, `+0x70`, `+0x94`, ... relative to the `+0x168` sub-context); its loop index is bounds-checked against the descriptor length at `desc+0x10`, and no indexed write to the context was found. The descriptor comes from the HID device, not from the IOCTL caller.

**One residual, out of scope:** `0xC0DE0030` checks `OutputBufferLength >= 0x50` and fills only 0x50 bytes, but then calls `WdfRequestSetInformation(request, OutputBufferLength)`. For an output length greater than 0x50, the I/O manager can copy the whole system buffer back to the caller, including bytes beyond the 0x50 written by the driver. That is a potential unprivileged kernel-pool **information leak** (KASLR-relevant if the leaked bytes contain kernel pointers), not a memory write; it is outside this audit's goal and is not rated MW. It does not chain to a write in this driver because there is no write-what-where sink.

### 6.2 `hidkmdf` - no write sink

The forwarder copies the current `IO_STACK_LOCATION` (a fixed IRP-owned 0x48-byte structure) to the next stack location and calls `IofCallDriver`; the power forwarder calls `PoStartNextPowerIrp`/`PoCallDriver`. There is no buffer copy, no `memcpy`/`RtlCopyMemory`, no MDL, no MMIO, no user-pointer dereference, and no IOCTL parsing. No kernel memory write exists in the image.

---

## 7. Most dangerous exposed capability

**`sshid` (R1, service setup):** any local user can open `\\\\.\\SSengine` read/write and reach the 15-18 IOCTLs. The capability is HID device configuration/reset, a fixed 0x814-byte vendor blob to a HID child, an event-object reference, and a 0x50-byte device/status readback. The most dangerous *side effect* is the `0xC0DE0030` over-disclosure of uninitialized system-buffer bytes when the caller asks for more than 0x50 bytes (info leak, out of scope). There is **no kernel memory write**.

**`hidkmdf` (R3, hardware/devnode):** no user-reachable driver-owned IOCTL surface and no write sink; only HID class IRP forwarding.

---

## 8. Verdict

**Overall: `NO-MEMORY-WRITE` (W0) for the loadable x64 builds; six i386 builds are `BLOCKED` (architecture) with the same static W0 result. No MW1-MW4.**

| Family | Loadable builds | Effective surface | DACL / gate | Reach / setup | Write | Verdict |
|---|---|---|---|---|---|---|
| `sshid` | `ADD52989`, `19A13E79`, `72565A1F`, `7DA7D360` | `\Device\SSengine` + `\DosDevices\SSengine` control device; 15-18 buffered IOCTLs | Everyone `GRGW` (variant A, live); no other check | R1 / service | W0 | **NO-MEMORY-WRITE** |
| `sshid` | `45CC60FB`, `ECC0EDB7`, `4FE83B22` | same code model, but i386 | same SDDL in the image | R1 if loadable / service | W0 (static) | **BLOCKED** (i386) |
| `hidkmdf` | `117F6300`, `60D9E781`, `19D8C116` | no device/interface of its own; HIDCLASS-owned HID collection; forwarder only | no image-owned DACL | R3 / hardware + devnode | W0 | **NO-MEMORY-WRITE** |
| `hidkmdf` | `4E1A5F19`, `AFBBA1BA`, `B6CCCC46` | same generic filter, i386 | no image-owned DACL | R3 if loadable | W0 (static) | **BLOCKED** (i386) |

The `GRGW`/`GRGWGX` question is resolved: **all seven `sshid` builds use the Everyone-`GRGW` variant A and actually pass it to the control-device init allocator; the `GRGWGX` variant B is absent.** The open DACL is real, but the exposed surface contains no caller-controlled arbitrary kernel destination, no caller-controlled length, no METHOD_NEITHER pointer, and no MDL/MMIO/physical path. The 2.7.1.0 and 2.11.5.0 differences are IOCTL-count/context-offset differences; none adds a memory-write sink.

---

## 9. Limitations

- **Static only.** No driver was loaded, executed, installed, or registered; no service or registry change was made. The DACL/open behavior and the 0x30 over-disclosure are static inferences, not dynamically confirmed.
- **Primary engine:** local Ghidra 12.1.4 headless (`C:\tools\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat`, `DumpAllDecomp.java`) with `objdump` 2.41 cross-checks. **No REA session was used** because three other REA audits were active and the bridge was at capacity per `audits/STATUS.md`; there are no REA evidence IDs for this report.
- **KMDF function-table indices are version-specific.** The SDDL binding is established from the call signature (driver handle + `UNICODE_STRING` -> returned `WDFDEVICE_INIT` consumed by `WdfDeviceCreate`) and the SDDL buffer contents, not from a symbol name. The exact public API names for `+0xC8`, `+0x1F0`, `+0x218`, `+0x258`, `+0x280`, and `+0x4C0` are inferred from their argument patterns.
- **Child context bounds** were recovered from the initialization zeroing (`ctx+0x34...ctx+0x520` in 2.11.5.0; `ctx+0x34...ctx+0x438` in 2.7.1.0); all fixed IOCTL writes fall inside those ranges. The exact `WDF_OBJECT_ATTRIBUTES.ContextSizeOverride` field was not separately decoded, but the zeroing range and the driver's own field accesses bound the context.
- **`hidkmdf`'s effective HID collection DACL** is set by `HIDCLASS`/the HID INF, not by this image, and was not resolved. The image itself creates no device and has no IOCTL handler.
- **i386 images** (`Machine = 0x014C`) cannot be loaded on this x64 host; their static code is reported only as a reference and is `BLOCKED` for loadability.
- **No web lookup** and **no exploit code/PoC** were used. The 0x30 information-leak observation is recorded as a residual, out-of-scope note only.
