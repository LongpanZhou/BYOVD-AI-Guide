# Audit: S1/S2 remaining — Realtek USB audio, libusb0, libusbK, MOZA

| Field | Value |
|---|---|
| File(s) | `drivers\RtUsbA64_154FA6AC.sys`, `drivers\libusb0_8058F2AF.sys`, `drivers\libusb0_AA7D75A4.sys`, `drivers\libusbK_1DF66FF2.sys`, `drivers\libusbK_6265AE9A.sys`, `drivers\MOZAUSBDriver_8AAC3D7C.sys`, `drivers\MOZAWindowsDriver_06676A68.sys`, `drivers\MOZAWindowsDriver_3331E368.sys` |
| SHA-256(s) | See §2 table (all eight hashes re-computed and matched to `indexes\drivers_manifest.csv`) |
| Analysis date | 2026-10-25 |
| Method | Static-only. Local Ghidra 12.1.4 headless (`analyzeHeadless`, full auto-analysis + decompile of every function), LLVM `llvm-objdump` 20.1.5 PE/import parser, PowerShell `Get-FileHash` / `Get-AuthenticodeSignature`. No load, execution, service creation, registry write, or web lookup. **REA cross-check not used: four REA audits are already active (STATUS.md "In flight"), so no REA session was opened and no REA evidence IDs exist.** |
| Reach tier | R2/R3 — see per-file table. Functional gate is device presence, not a driver access check. |
| Setup required | `devnode` (libusb0/libusbK) or `hardware` (RtUsbA64, MOZA); `n/a` for the three non-x64 images. |
| Write quality | W3 (one file, narrow fixed-size over-write); W0 (four files); not assessed (three non-loadable files). |
| Verdict | **MW4** for `MOZAWindowsDriver_06676A68.sys`; **NO-MEMORY-WRITE** ×4; **BLOCKED** ×3. No MW1/MW2/MW3 in this set. |

Legend: addresses are VAs at the PE image base reported by Ghidra (`0x140000000` for the x64 Realtek/MOZA images, `0x00010000` for libusb0/libusbK x64, `0x00400000` for the x86 MOZA image). "dump line" refers to the local Ghidra decompile dump kept under `%TEMP%\opencode\s1s2\`.

## 1 Scope, prior work, and method

- Eight exact files assigned in STATUS.md §In flight item 6 and the rolling queue item 11. All are `collected1`.
- SHA-256 verified for all eight before analysis; all eight are absent from `indexes\dedupe\known_bad_hashes.txt` and all eight carry a valid Authenticode signature.
- Function-level decompilation was run on the five x64 images: RtUsbA64 (997 functions), libusb0_8058F2AF (66), libusbK_1DF66FF2 (73), MOZAUSBDriver (38), MOZAWindowsDriver_06676A68 (64). The three i386 images were PE/import-triaged only and are `BLOCKED` on architecture.
- Existing reports were read first (hard rule 0): `libusbK_6265AE9A.admin.static.md`, `MOZAUSBDriver_8AAC3D7C.admin.static.md`, `MOZAWindowsDriver_06676A68.admin.static.md`, `MOZAWindowsDriver_3331E368.admin.static.md`. This report is the assigned consolidated batch audit; it re-verifies those four and **supersedes the 06676A68 verdict** (see §4.5) with the reason stated there. No other file was modified.
- Every claim below is from the decompiled code or the PE headers; no dynamic evidence is used.

## 2 Files, hashes, loadability, and signatures

| File | Arch | SHA-256 | Authenticode | Loadable on this x64 host |
|---|---|---|---|---|
| `RtUsbA64_154FA6AC.sys` | x64 | `154FA6AC634C8BFDF12025FD7A3C9643B5CAC0D76D206062F0DAED21057FB7B9` | Valid — CN=Realtek Semiconductor Corp. | yes |
| `libusb0_8058F2AF.sys` | x64 | `8058F2AFE6EF96A7D2DED432997FD8655970C9EA75A938EE4557D6A2CB4CC989` | Valid — CN=Travis Lee Robinson | yes |
| `libusb0_AA7D75A4.sys` | i386 | `AA7D75A4D01B405AAB7C848674BBED392B64C6E374E20FD72ADC3C96294E2F00` | Valid — CN=Travis Lee Robinson | **no (PE32 i386)** |
| `libusbK_1DF66FF2.sys` | x64 | `1DF66FF22E2EAEC27180756D90926CA5B07E8BCF6B0E4E3C56471E63A3A05FA6` | Valid — CN=Travis Lee Robinson | yes |
| `libusbK_6265AE9A.sys` | i386 | `6265AE9AE5C49F515613F0B749AD8390A1B34CA326203318BFFEB6C2C281D2D0` | Valid — CN=Travis Lee Robinson | **no (PE32 i386)** |
| `MOZAUSBDriver_8AAC3D7C.sys` | x64 | `8AAC3D7CB51B42D101B7A32D0DC903E4C580B4440466ADC4081E502B497C9D6C` | Valid — CN=Microsoft Windows Hardware Compatibility Publisher | yes |
| `MOZAWindowsDriver_06676A68.sys` | x64 | `06676A680A5A6D0DB83A0A6EBEDB75AD55701879D74022CCB42FB8E566BE7AC9` | Valid — CN=Microsoft Windows Hardware Compatibility Publisher | yes |
| `MOZAWindowsDriver_3331E368.sys` | i386 | `3331E3685BDF45F4C8DD02569E7B537A23504BB1351970C97F655EA49ED16B46` | Valid — CN=Microsoft Windows Hardware Compatibility Publisher | **no (PE32 i386)** |

`BLOCKED` for the three i386 images is an architecture block, not a known-bad/blocklist block. None of the eight hashes is on the 5,833-entry known-bad list.

## 3 Per-file results

| File | Device / interface | Effective DACL and open gate | Custom IOCTL surface | Kernel memory write | Verdict |
|---|---|---|---|---|---|
| `RtUsbA64_154FA6AC.sys` | KS filter FDO for the Realtek USB audio device; multiple private device interfaces registered; no named control device | No SDDL string and no `IoCreateDevice` import. Descriptor is the KS/PnP default for the filter FDO; driver has no `SeAccessCheck`/`SeSinglePrivilegeCheck`. Gate = USB audio device present; custom codes are `FILE_ANY_ACCESS`, so any handle with device read/write can call them once the interface is open. | 0x220400–0x22040B, 0x220C00–0x220C27, 0x225C00–0x225EF3, 0x226000–0x22600B, and IOCTL 0x2F0003 (KS property set). Buffered, FILE_ANY_ACCESS. | No caller-chosen address/length. 0x220C08/0x220C0C map **driver-allocated** non-paged-pool audio buffers to user mode (fixed target, driver-chosen length) and 0x220C0C leaks 0x88 bytes of device-context pointers; no arbitrary kernel write. | **NO-MEMORY-WRITE** (W0); kernel-VA leak + intended shared-buffer mapping noted |
| `libusb0_8058F2AF.sys` | WDM FDO `\Device\libusb0-N` + symlink `\DosDevices\libusb0-N` + device interface | `IoCreateDevice` with no SDDL and no access check; default device-object DACL; globally visible symlink. Gate = INF/devnode installed and USB device bound; ordinary libusb0 clients run non-admin. | 0x222004–0x222444 family, buffered control/config codes plus IN/OUT_DIRECT transfer codes 0x222029/0x22204D/0x22202E/0x222052 | All input/output comes from `Irp->AssociatedIrp.SystemBuffer` (buffered) or the I/O manager's locked MDL (direct). `MmMapLockedPagesSpecifyCache` is used only to translate that already-locked MDL in the large-transfer completion and then copy received bytes into it. No caller pointer used as a kernel destination. | **NO-MEMORY-WRITE** (W0) |
| `libusb0_AA7D75A4.sys` | same family, 32-bit | n/a | not analysed beyond imports | n/a | **BLOCKED** (PE32 i386) |
| `libusbK_1DF66FF2.sys` | KMDF FDO, libusbK device interface; reference string `\DosDevices\libusb0-` | WDF default device security; no SDDL, no access check; interface GUID supplied through `DeviceInterfaceGUIDs`. Gate = devnode/hardware. | same 0x222xxx family as libusb0, plus 0x222448/0x22244D/0x222452/0x222455/0x22245A | Buffers captured through `WdfRequestRetrieveInputBuffer` / `WdfRequestRetrieveOutputBuffer`; no `Mm*` mapping, no physical-memory or section API; unhandled codes forwarded to the lower USB target. No caller-controlled destination. | **NO-MEMORY-WRITE** (W0) |
| `libusbK_6265AE9A.sys` | same family, 32-bit | n/a | not analysed beyond imports | n/a | **BLOCKED** (PE32 i386) |
| `MOZAUSBDriver_8AAC3D7C.sys` | KMDF PnP FDO; interface GUID `{B040EED8-6579-4B34-8376-ABF03CAAA913}`; no named device, no SDDL | WDF default security; no access check; hardware-gated | 0x222008 handled; every other code forwarded unchanged to the lower WDF I/O target | 0x222008 writes four fixed bytes `{01,00,00,00}` into a WDF-validated output buffer (min 4). No other local write. | **NO-MEMORY-WRITE** (W0) |
| `MOZAWindowsDriver_06676A68.sys` | KMDF PnP FDO; PnP device-interface notification; no named device, no SDDL | WDF default security; no access check; hardware-gated. Any opener can send the codes. | 0x222000/04/08/0C/10/14/18/1C/20 (buffered, ANY); 0xB0191 (IN_DIRECT), 0xB0192 (OUT_DIRECT); other codes forwarded | **0x22200C with OutputBufferLength = 0x22 writes 0x2A bytes through a 0x22 request — an 8-byte over-write of the declared buffered output buffer.** Values come from device context; 4 of the 8 bytes are attacker-influenced via 0x222014. The in-context writes of 0x222014/0x222010 are W0 by themselves. | **MW4** — R3, hardware, W3, signed |
| `MOZAWindowsDriver_3331E368.sys` | same MOZA family, 32-bit | n/a | not analysed beyond imports | n/a | **BLOCKED** (PE32 i386) |

## 4 Dispatch and IOCTL evidence

### 4.1 RtUsbA64_154FA6AC.sys — no caller-controlled kernel destination

- Entry `0x140095000` → `0x1400504C0`; `KsInitializeDriver` at `0x1400504C0` (dump 56293–56349). The driver replaces the WDM driver-object handlers:
  - `IRP_MJ_DEVICE_CONTROL` (+0xE0) → `0x14002C880`
  - `IRP_MJ_INTERNAL_DEVICE_CONTROL` (+0xE8) → `0x14002C6F0`
  - `IRP_MJ_CREATE`/`CLOSE`/`CLEANUP` (+0x68/0x70/0x80) → `0x14002E620` / `0x14002C5E0` / `0x14002C4D0`
  - `IRP_MJ_PNP` (+0x148) → `0x14002D1C0`
- No `IoCreateDevice` import: device objects come from `KsCreateFilterFactory` (`0x14002E6A4`, `0x14003C0D8`). No SDDL string exists in the image (string scan found only the `\DosDevices\%ws\%ws.dat` data-file format used with `ZwCreateFile`). Effective security is the KS filter's default descriptor; the driver itself performs no access check.
- Device interfaces: `0x140023758` (GUIDs `0x140067328`, `0x140067358`), `0x14002AF38` (`0x140067318`, `0x140067308`, `0x140067368`), and `IoRegisterDeviceInterface` at `0x14002AF38` dump 32394–32489. Names in the image include `rtUsbInterface`, `rtUsbInterface4UI`, `rtUsbInterfaceForForte`.
- `0x14002C880` dispatch ranges and actions:
  - `0x220400–0x22040B` → `0x14002D2B4`: vendor USB control transfers; writes only `puVar9+2` inside `uVar2` (OutputBufferLength) bytes, loop count `OutputBufferLength>>2` (dump 33288–33352). Bounded.
  - `0x220C00–0x220C27` → `0x14002E1A4` (index `(code-0x220C00)>>2`): see below.
  - `0x225C00–0x225EF3` → `0x14002D510` → `0x140020DE8` (KS property path).
  - `0x226000–0x22600B` → `0x14002D574`: 4-byte write to SystemBuffer only when OutputBufferLength ≥ 4 (dump 33403–33460).
  - `0x2F0003` (KS property set): compares the property GUIDs at `local_b8`, writes fixed-size records to the SystemBuffer after per-branch length checks (`0x3f < uVar18`, `uVar18 < 0x18` rejects, etc.).
- `0x14002E1A4` (0x220C00 family, dump 34008–34237):
  - index 1 (0x220C04): copies `min(OutputBufferLength, 0x1C)` bytes from device context `+0x25A0` to the output buffer.
  - index 2 (0x220C08): requires OutputBufferLength ≥ 0x18; `memset(_Dst, 0, OutputBufferLength)`; then if `ctx+0x1DA8` exists, builds an MDL over `ctx+0x1DA8` with length `ctx+0x1DB0`, `MmBuildMdlForNonPagedPool`, and `MmMapLockedPagesSpecifyCache(..., UserMode, ...)`; returns the user VA and length. `ctx+0x1DA8` is allocated by the driver itself (`ExAllocatePoolWithTag`, dump 25327/25390, size derived from the stream format at `param_1+0x164`), not from an IOCTL address.
  - index 3 (0x220C0C): same mapping, plus copies 0x88 bytes of device-context fields (`+0x21F0`…`+0x2270`) to the output buffer — a kernel-VA/pointer disclosure.
  - index 7 (0x220C1C): writes 4 bytes (device value) if OutputBufferLength ≥ 4; index 8 (0x220C20): `*_Dst` selects a driver flag at `+0xBF4` (fixed write).
  - Conclusion: the only user-writable kernel pages are the driver's own **audio data buffers**, at driver-chosen addresses and lengths. No IOCTL accepts an address, physical address, or length for the mapping. This is the intended shared-audio-buffer path, not a caller-controlled memory write; the pointer leak is out of scope by itself.
- The other `MmMapLockedPagesSpecifyCache` use (`0x14004EF00`, dump 55293) maps the **streaming IRP's** MDL (the audio engine's buffer) in KernelMode and zeroes `uVar19` bytes of it; that is a user/audio-engine buffer, not kernel memory.

### 4.2 libusb0_8058F2AF.sys — SystemBuffer/MDL only

- `DriverEntry` at `0x00013640`: installs `0x0001140C` into all 0x1C major-function slots, `AddDevice = 0x000136B8`, `Unload = 0x00013D64`.
- `AddDevice` `0x000136B8`: `IoCreateDevice(driver, 0xA5E0, name)` at dump 1751, `IoCreateSymbolicLink` at 1756, `IoRegisterDeviceInterface` at 1801. No SDDL is passed and no `SeAccessCheck`/`SeSinglePrivilegeCheck` is imported. Effective DACL = default device-object DACL; the symlink is global (`\DosDevices\libusb0-`), so the open gate is devnode installation/device binding, not a driver ACL.
- `IRP_MJ_DEVICE_CONTROL` reaches `0x00012784`. It reads `SystemBuffer = *(IRP+0x18)` (dump 1045), OutputBufferLength `[IO_STACK+8]`, InputBufferLength `[IO_STACK+0x10]`, IoControlCode `[IO_STACK+0x18]` (dump 1048–1050). There is no METHOD_NEITHER raw-pointer path.
- IOCTL surface (0x222xxx family; the low two bits give the method, and codes not handled below are forwarded):
  - Buffered, FILE_ANY_ACCESS: `0x222004`, `0x222008`, `0x22200C`, `0x222010`, `0x222014`, `0x222018`, `0x22201C`, `0x222020`, `0x222024`, `0x222030`, `0x222034`, `0x222038`, `0x22203C`, `0x222040`, `0x222044`, `0x222048`, `0x222054`, `0x222058`, `0x22205C`, `0x2223FC`, `0x222400`, `0x222404`, `0x222408`, `0x222410`, `0x222418`, `0x22241C`, `0x222420`, `0x222424`, `0x222429`, `0x22242E`, `0x222430`, `0x222434`, `0x222438`, `0x222440`, `0x222444`.
  - IN_DIRECT: `0x222029` (interrupt/bulk write), `0x22204D` (isochronous write).
  - OUT_DIRECT: `0x22202E` (interrupt/bulk read), `0x222052` (isochronous read).
- Traced writes to caller-visible memory:
  - `get_object_name` (`0x00012784`, dump 1475–1491): copy length `min(OutputBufferLength, strlen)-1` into SystemBuffer, then a NUL at that offset. Bounded.
  - `get_device_property` (`0x222400`, dump 1402–1413): `IoGetDeviceProperty(..., OutputBufferLength, SystemBuffer, ...)` after zeroing OutputBufferLength bytes. Bounded by the API contract.
  - `set_pipe_policy`/`get_pipe_policy` (`0x222418`/`0x22241C`, dump 1425–1467): require InputBufferLength > 0x18 / OutputBufferLength > 3 and write 4 bytes at fixed struct offsets. Bounded.
  - Bulk/isochronous transfers: output buffer is the I/O manager's locked MDL for the OUT_DIRECT request. `0x000160A0` computes the buffer VA from `Mdl->StartVa + Mdl->ByteOffset` (dump 3720), allocates a partial MDL over the **same source MDL** (`IoAllocateMdl` 3783, `IoBuildPartialMdl` 3789), and the completion `0x00016754` maps it (`MmMapLockedPagesSpecifyCache`, 3990) and copies `uVar10` bytes at 4005. Lengths are the validated transfer lengths, not caller pointers.
  - `0x222004`/`0x22200C` etc. build stack URBs (`0x000112D0`, `0x000157D8`, `0x00015914`) and issue `0x220003` to the USB stack; no kernel destination is taken from the input structure.
- No `MmMapIoSpace`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `MmProbeAndLockPages` or `ProbeForWrite` import exists. `MmMapLockedPagesSpecifyCache` is reached only through the completion path above, over an MDL the I/O manager already built and locked.

### 4.3 libusbK_1DF66FF2.sys — KMDF port of the same interface

- KMDF image (`WdfVersionBind`/`Unbind` imports; Fx stub entry `0x00017D64` → `0x00017C3C`). WDF handles are used through `DAT_0001AEB8`; no WDM device creation import.
- The IOCTL dispatcher is `0x00015570` (dump 3242–4061), reached from the WDF device-control callback. It captures the output buffer with `DAT_0001AAA0` (WdfRequestRetrieveOutputBuffer) and the input with the corresponding retrieve call; all writes in the dispatcher are to WDF-validated buffers or to stack URB/context structures (e.g. dump 3308/3311/3330 are one-byte writes after a min-1 retrieval).
- Codes are the libusb0 family plus `0x222448`, `0x22244D`, `0x222452`, `0x222455`, `0x22245A`. Transfer codes 0x222029/0x22202E/0x22204D/0x222052 are handled by the transfer helpers (`0x00011F34`, `0x000122A8`, `0x00012358`, `0x0001240C`), which build URB structures over WDF-captured buffers and forward them to the lower USB target.
- No mapping/physical-memory/MDL API is imported at all (imports: ntoskrnl `KeBugCheckEx`, `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `RtlCopyUnicodeString`, `RtlGUIDFromString`, `IoGetCurrentProcess`, `DbgPrint`; USBD; WDFLDR). No caller pointer becomes a kernel destination; unhandled codes are forwarded unchanged, so any effect belongs to the lower driver.

### 4.4 MOZAUSBDriver_8AAC3D7C.sys — one fixed four-byte response

- `EvtDriverDeviceAdd` `0x1400062A0` → `0x140006000`; default queue with `EvtIoDeviceControl = 0x1400014A0` and `EvtIoInternalDeviceControl = 0x140001180` (dump 1067–1098). Device interface GUID `{B040EED8-6579-4B34-8376-ABF03CAAA913}`. No SDDL and no named device.
- `0x1400014A0` (dump 154–218): only `0x222008` is handled. It rejects OutputBufferLength == 0, retrieves the output buffer with minimum 4 bytes, writes `{01,00,00,00}` at `0x1400014A0` dump 197–200, and completes with Information 4. All other codes go to `WdfRequestSend` on the lower target (dump 209–216). No caller-controlled destination, length or value.

### 4.5 MOZAWindowsDriver_06676A68.sys — 8-byte over-write of a buffered output buffer

- Entry `0x140003A90` → DriverEntry `0x140003ABC`; `EvtDriverDeviceAdd` path registers a PnP notification at `0x140002634` (dump 1135) and creates the default queue at `0x140002718` with `EvtIoDeviceControl = 0x140002800` (dump 1169) and `EvtIoInternalDeviceControl = 0x140003160` (dump 1170). No SDDL string, no named device; WDF default security. Gate = MOZA hardware present.
- `0x140002800` dispatch (dump 1177–1458): buffered codes `0x222000`, `0x222004`, `0x222008`, `0x22200C`, `0x222010`, `0x222014`, `0x222018`, `0x22201C`, `0x222020`; `0xB0191` IN_DIRECT; `0xB0192` OUT_DIRECT; all others forwarded.
- **The write (0x22200C):** at dump 1215–1241 the code accepts `OutputBufferLength` values 0x22 and 0x2A (`(param_3 - 0x22) & 0xFFFFFFFFFFFFFFF7 == 0`), sets the retrieval size to 0x2A only when the caller asked for 0x2A, otherwise 0x22, then calls `0x1400017FC(selector, ctx, output)`. `0x1400017FC` (dump 414–459) unconditionally performs five 8-byte stores at `output+0x00..0x27` and a 2-byte store at `output+0x28` — 0x2A bytes total — for selectors 0, 1 and 2. With `OutputBufferLength = 0x22` (34), offsets 0x22–0x29 are written past the declared output buffer.
  - Method is BUFFERED, so the output pointer is the IRP SystemBuffer and the over-write is past a 34-byte pool allocation into adjacent pool. The eight bytes are context data; selector 1 sources them from `ctx+0x57A5..0x57AC`, of which the odd bytes (`0x57A5/A7/A9/AB`) are settable through `0x222014` (`ctx+0x5657+2*input[2i]`, dump 1396). Thus size is fixed (8), target is adjacent pool (not caller-chosen), and 4 of 8 value bytes are attacker-influenced.
  - Caveat: x64 pool allocations are rounded to 16-byte blocks, so a 34-byte request may occupy a 48-byte block and absorb the 8 bytes in slack. Cross-allocation corruption is therefore **not proven statically**; the defect is a real length-validation bug and a W3-class narrow write at most. No crash or overflow was executed or tested.
- The other writes are W0 by themselves: `0x222014` writes a caller-chosen byte value into one of 256 fixed slots in the device context (`ctx+0x5657+2*input[2i]`, dump 1396–1397); `0x222010` writes 128 fixed 1-bit flags (`ctx+0x565A+2k`, dump 1361–1374); `0x222008` writes the 4-byte version; `0xB0191` writes a byte into the first free slot of a 10-slot table (`0x1400015DC`); `0xB0192` writes one byte to the WDF request context. None uses a caller-supplied address or length.
- The earlier report `MOZAWindowsDriver_06676A68.admin.static.md` rated this image MW3/W2 from the in-context slot write. That write is confined to the device's own context and cannot leave it; the only out-of-object write is the 0x22200C over-write. This report therefore supersedes the verdict with **MW4/W3**.

### 4.6 MOZAWindowsDriver_3331E368.sys and the two i386 libusb images

- All three are PE32 (i386, machine 0x14C) and cannot be loaded by the x64 kernel on this host. `MOZAWindowsDriver_3331E368.sys` is the same MOZA KMDF family (imports `IoRegisterPlugPlayNotification`, `RtlCompareMemory`, WDFLDR); it is `BLOCKED` on architecture and was not decompiled. `libusb0_AA7D75A4.sys` and `libusbK_6265AE9A.sys` are the 32-bit builds of the two families above; they are `BLOCKED` for the same reason. No write quality is assigned to a non-loadable image.

## 5 Access-control summary

- None of the eight imports `SeAccessCheck`, `SeSinglePrivilegeCheck` or `SePrivilegeCheck`, and none performs a caller-identity check. There is no driver-level admin gate anywhere in this set. (libusb0's `ObReferenceObjectByHandle` import is used for its own device-object reference in `AddDevice`, not to identify the caller.)
- None of the eight carries an SDDL string (`D:…`) or calls `IoCreateDeviceSecure` / `WdfDeviceInitAssignSDDLString`. Effective descriptors are the platform defaults for the device object class:
  - libusb0/libusbK: default WDM/WDF device DACL on `\Device\libusb0-N` plus the global `\DosDevices\libusb0-N` symlink; gate is devnode installation, not an ACL.
  - MOZA: WDF default device/interface security; gate is the MOZA device being present.
  - RtUsbA64: KS filter default security on the audio function device; gate is the Realtek USB audio device being present. Realtek's custom IOCTLs are `FILE_ANY_ACCESS`.
- Consequently every "openable control device" in this set is gated by **device presence/installation**, which is `R3`/`setup=devnode|hardware`, not by an admin-only DACL. The important result is that even with that open gate there is no arbitrary kernel write to reach.

## 6 Overall verdict

**MW4 — `reach=R3 setup=hardware write=W3 load=signed`** for `MOZAWindowsDriver_06676A68.sys` only: `0x22200C` accepts a 0x22-byte buffered output buffer but writes 0x2A bytes, an 8-byte over-write of the declared buffer, partially attacker-valued via `0x222014`; target is adjacent pool and cross-allocation corruption is not established (allocator rounding may absorb it). No MW1, MW2 or MW3 primitive was found in any of the eight files. The remaining loadable files are **NO-MEMORY-WRITE (W0)**: RtUsbA64's only user-writable kernel pages are its own driver-allocated audio buffers (driver-chosen address/length, intended sharing) and its `0x88`-byte pointer leak is info-leak-only; libusb0/libusbK keep every copy inside the SystemBuffer, a WDF-captured buffer, or an already-locked direct-I/O MDL; MOZAUSB writes four fixed bytes. The three i386 images are **BLOCKED** (architecture).

## 7 Limitations

- No REA session was opened (four already active); this audit is Ghidra/objdump only and has no REA evidence IDs. A future REA pass could cross-check the libusb0 large-transfer URB/MDL path and the RtUsbA64 KS property branches.
- The 06676A68 over-write's real pool layout was not measured and WDF's exact buffered-output allocation size was not resolved; the MW4 rating is the narrow-write ceiling, not a demonstrated corruption.
- RtUsbA64 is 997 functions; the audit traced the device-control dispatch and every `MmMapLockedPagesSpecifyCache`/`IoAllocateMdl` site, but the internal KS property handler `0x140020DE8` and the 0x225C00 property family were reviewed only at their entry points, not line-by-line. No caller address/length reached a mapping in the traced code.
- libusbK's WDF function-table indices are unnamed; callback and buffer-retrieval identification is by the indirect-call table and surrounding struct stores.
- Forwarded requests (libusbK, MOZA) are executed by the lower device stack, which is outside these images.
- No driver was loaded, installed, or executed; no registry or service changes; no web lookup.
