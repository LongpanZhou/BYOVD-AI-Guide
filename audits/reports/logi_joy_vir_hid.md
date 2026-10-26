# Audit: logi_joy_vir_hid.x64.sys

| Field | Value |
|---|---|
| File name | `logi_joy_vir_hid.x64.sys` |
| Recorded SHA-256 | `fd9bb208da3931926c771d3fee0fa7533e54dc876dcbd830cfdbe28e76d04911` |
| Analysis date | 2026-10-23 |
| Method | Static-only audit via REA/Ghidra |

Scope note: all statements below come from disassembly/decompilation of this single binary (Ghidra 12.1.4 provider, image base `0x140000000`, Evidence ev_b99f6d07a5f85207750e567c33df010d6630fda5768bb311df788f212c94e34c). No web resources, no vendor information, no dynamic execution were used. Structure types are not asserted anywhere the PDB (`logi_joy_vir_hid.x64.pdb`, GUID `ab8a292a-85e4-4f6c-8b99-cc4f42307daa`, RSDS, not available) was not available; offsets are always given as observed byte offsets.

---

## 1 Internals

**Container.** 64-bit PE kernel driver, x86_64, image base `0x140000000`. `.text` `0x140001000–0x140001e00` (3.5 KB), `.rdata` `0x140002000–0x140002800`, `.data` `0x140003000–0x140003200`, `.pdata`, `PAGE` `0x140005000–0x140005600`, `INIT` `0x140006000–0x140006400`, `.rsrc`, `.reloc` (binary_overview, ev_b99f6d07…).

**Version resource** (`.rsrc`, strings 0x140007118–0x14000730a): `CompanyName` "Logitech", `FileDescription`/`InternalName`/`ProductName` "Logitech G Drivers", `FileVersion`/`ProductVersion` "2026.0.0.0", `LegalCopyright` "Copyright © Logitech, Inc. 2024".

**Unusual section.** A non-image, 6,224-byte data blob is mapped far outside the image at `0xff00000000–0xff00001850` (Ghidra block `tdb`). Contents are opaque zero/binary bytes (reads of 0xff00000000 and 0xff000002d0 return only zeroes; Evidence ev_50902570630bb4f1751e0535d8c17d1931cbb8eba422ee4b6a37f024e6c6f472, ev_007f554fd90614efe9fbb44bf16b993b0aeec7b9cdcaf64f03f31c88cdc00046). No instruction in any analyzed procedure references the `0xff…` range. It carries no code and no reachable capability; provenance of the blob is unknown — recommend byte-comparison against an authentic copy of the same driver rather than accepting this file uncritically (binary-diff recommendation, not a code finding).

**Framework.** This is a **WDM HID minidriver**, not a KMDF driver: the only HIDCLASS import is `HidRegisterMinidriver` (thunk `0x14000156c` → `EXTERNAL:0x1`; sole call site `0x1400060b8`, xref Evidence ev_20c99888c7ea058373b1c5d0faff9ac9b6504a9e4d4f65a7e010befdd49fa9fe). There are **no** framework imports (WdfDriverCreate/WdfDeviceCreate/WDF loader absent) — so no WDF queue/IO callback surface and none to audit.

**Complete static-import surface (14 functions, from the import-directory-derived external inventory):**

| Module | Import |
|---|---|
| HIDCLASS.SYS | `HidRegisterMinidriver` |
| NTOSKRNL.EXE | `IoBuildDeviceIoControlRequest`, `IofCallDriver`, `IofCompleteRequest`, `ExAllocatePoolWithTag`, `ExFreePool`, `KeSetEvent`, `KeInitializeEvent`, `KeWaitForSingleObject`, `PoStartNextPowerIrp`, `RtlInitUnicodeString`, `RtlQueryRegistryValues`, `MmGetSystemRoutineAddress`, `wcslen` |

Note what is **absent**: no `IoCreateDevice*`/`IoCreateDeviceSecure`, no `UnicodeString`/security-descriptor APIs, no token/privilege APIs (`SeSinglePrivilegeCheck`, `SeAccessCheck` absent), no process/thread APIs, no `Zw*` file/registry/process handles, no `MmMap*`/`MmCopyMemory`, no hard-error/power-profile/sp弊端 primitives. Pool tags used: `'LJOY'` (`0x594f4a4c`, allocation at `0x140001387`, size = context value at ctx+0x10). C runtime surface is compiler-generated only: `memmove` `0x140001780`, `memset` `0x140001a40`/`0x140001b80` (+CPU-feature gate `__isa_available_init`-equivalent `0x140001630` writing `DAT_140003040`).

**Dynamic resolution — single instance.** `MmGetSystemRoutineAddress` is called exactly once, in `0x14000144c–0x14000156b`, to resolve the UTF-16 name `RtlQueryRegistryValuesEx`(string at `0x140001c30`); if resolution returns NULL it falls back to the static import `RtlQueryRegistryValues` (`0x140001547–0x14000155a` region). The resolved routine is used solely to read its **own service key subkey** `LGVirHid\Parameters` value `DebugLevel` (strings `0x1400061b0`, `0x140006190`); result stored to `.data` `0x140003080` (`0x140006110`). No write path to the registry exists in the binary.

**Hardening.** `/GS` stack cookies: cookie init `0x14000614c`, checks (`0x14000600a–0x1400060c5`, `0x140001458–0x140001441`, `0x14000519c-...` etc.), `__security_check_cookie` `0x140001700`, `__GSHandlerCheck`+`__GSHandlerCheckCommon` `0x1400015a0/0x1400015c0`. CFG: `_guard_check_icall` `0x140001590`, `_guard_dispatch_icall` `0x140001730`/thunk `0x140001750`, used on every indirect call target (visible in guard-dispatch injections around the `IofCallDriver`/`IofCompleteRequest` tail calls).

**Strings.** The complete inventoried string set (44 strings) contains **no SDDL string, no security-descriptor text, no GUID*, and no device-interface strings**; all of them are: the registry path/value, the `RtlQueryRegistryValuesEx` name, the runtime-built trace prefix `LGVirHid::` (written at `0x14000602e–0x140006036` into `.data 0x140003090`, constants `0x646948726956474c`, `0x3a3a`), the import-name pool in `INIT` (`0x1400062a2–0x1400063ea`: `HidRegisterMinidriver`, `HIDCLASS.SYS`, `KeInitializeEvent`, `KeWaitForSingleObject`, `IoBuildDeviceIoControlRequest`, `IofCallDriver`, `IofCompleteRequest`, `ExAllocatePoolWithTag`, `ExFreePool`, `KeSetEvent`, `PoCallDriver`, `PoStartNextPowerIrp`, `RtlInitUnicodeString`, `RtlQueryRegistryValues`, `MmGetSystemRoutineAddress`, `wcslen`, `ntoskrnl.exe`) and the `.rsrc` version fields. The PDB RSDS path `logi_joy_vir_hid.x64.pdb` is embedded (GUID above).

---

## 2 Device & entry chain

**Entry point.** Optional-header `AddressOfEntryPoint` = `entry` at `0x140006120` (INIT). Chain: `0x140006120` → cookie init `0x14000614c` → DriverEntry `0x140006000`.

**DriverEntry, `0x140006000–0x140006120` (complete assembly inspected).** It performs a single registration:

1. Writes the global trace prefix `LGVirHid::` into `.data 0x140003090` (`0x14000602e–0x140006036`).
2. Reads `DebugLevel` from `\Registry\Machine\...\Services\LGVirHid\Parameters` via `0x1400060d8` → registry wrapper `0x14000144c` (above) → `.data 0x140003080`.
3. Populates the DRIVER_OBJECT (assembly addresses in parentheses):
   - `IRP_MJ_INTERNAL_DEVICE_CONTROL` (major 15, DriverObject+0xE8) = `0x140001200` (`0x140006042–0x140006049`)
   - `IRP_MJ_PNP` (major 27, DriverObject+0x148) = `0x140005280` (`0x140006050–0x14000605e`)
   - `IRP_MJ_QUERY_SECURITY` (major 20, DriverObject+0x120) = `0x1400013f0` (`0x140006065–0x14000606c`)
   - `IRP_MJ_SET_SECURITY` (major 21, DriverObject+0x128) = `0x140001430` (`0x140006073–0x14000607a`)
   - `DRIVER_EXTENSION->AddDevice` (DriverObject+0x30 → +8) = `0x140005030` (`0x140006081–0x140006089`)
   - `DriverUnload` (DriverObject+0x68) = `0x140005060` (a bare `RET`, `0x140005060–0x140005062`) (`0x140006089–0x140006095`)
   - All other `MajorFunction` slots remain the PnP-manager default.
4. Builds a `HID_MINIDRIVER_REGISTRATION` (stack, `0x140006099–0x1400060b3`): `Revision=1`, `DriverObject`, `RegistryPath` (Irp from loader, `RDX`), device-extension size `0x38`, polling flag `0`, and calls `HidRegisterMinidriver` (thunk `0x14000156c`) at `0x1400060b8`.

**No device is created by this binary.** Module-wide search: zero calls to `IoCreateDevice`/`IoCreateDeviceSecure`/`WdfDeviceCreate` (absent from imports), and `AddDevice` (`0x140005030`, 34 bytes) only: increments a device counter `.data 0x1400030ac`, stores its first DriverObject pointer into `.data 0x140003088` (xref-verified: the global has exactly one other code reference — the write at `0x140005043`; no reader), and clears `DO_DEVICE_INITIALIZING` (`BTR [RDX+0x30], 0x7` at `0x14000504a`) on the device object **created and owned by HIDCLASS** (as is standard for minidrivers). Consequently there is **no device interface registration** (no `WdfDeviceCreateDeviceInterface`, no `IoRegisterDeviceInterface` import or call) and **no control device** in this artifact. The user-visible device/interface and its security descriptor belong to HIDCLASS, outside this binary.

**PnP handler `0x140005280` (`PAGE`, switch on `IO_STACK_LOCATION+1` minor code, self-contained no security behavior):**

| minor | code path | effect |
|---|---|---|
| 0 START | `0x140005355–0x140005371` | passdown via `0x1400053d8` (offset-bump + completion callback `0x1400013d0` = `KeSetEvent`, return `0xC0000016`), then `0x14000547c`: re-init context, state=0, then `0x14000519c`: two synchronous private control requests (see §3 codes `0x2A805/0x2A806`) to fetch descriptor data into ctx (`+4/+8/+0xC/+0x10`) and a pooled (`LJOY`, `0x140001380`) buffer at ctx+0x18; state = 2 (started) on success or 6 (fetch failed) at `0x140005543/0x14000554d`; Irp completed `0x14000537b` |
| 1 QUERY_REMOVE | `0x1400052c2` | passdown (`0x14000533a`) |
| 2 REMOVE | `0x1400052c7–0x14000533b` | if removal-pending flag ctx+0x30 ≠ 0 → passthrough-complete; else cleanup `0x1400053a0` = state {2,5,7} → 5, counter `0x1400030ac` decrement (`0x140005000`), free ctx buffer (`0x140005170`); `Irp->IoStatus=0`; completes via `0x14000537b` (`IofCompleteRequest`, IAT slot `0x140002020`) |
| 3 CANCEL_REMOVE | `0x1400052cc` | passdown |
| 4 STOP | `0x14000530f–0x140005326` | `0x1400054e8` (state→3, helper `0x140005064` sends down a synchronous cancel request code `0x2a201c`, buffer freed), passdown, state→4 |
| 9 QUERY_CAPABILITIES | `0x1400052ec–0x14000530d` | passdown; on success ORs bit `0x200` into the capabilities block word at response+4 (`0x140005308`) — an in-context capability flag; no privileged behavior |
| 0x13 QUERY_ID | `0x1400052dd–0x1400052e0` | passdown |
| 0x17 SURPRISE_REMOVAL | `0x1400052e2–0x1400052ea` | state→5, removal flag ctx+0x30 → 1, then `0x14000532e` cleanup path as above |
| default | `0x14000533a` | passdown (`IofCallDriver` IAT `0x140002018`) |

The context referenced everywhere by `DeviceObject+0x40 → +0x10` (state byte at +0x28, removal/busy flag at +0x30, descriptor words at +0x04/+0x08/+0x0C/+0x10, `.LJOY` buffer pointer+length at +0x18) is the minidriver's per-device context; it is bound to the debug `DebugLevel` global in `0x140005008` (`*(ctx+8)=&DAT_140003080`, tag `0x4d4548` at ctx+0).

**Effects on other devices in the stack:** only standard upward/downward IRP forwarding (`IoSkipCurrentIrpStackLocation` idiom: `INC byte ptr [Irp+0x43]; ADD qword ptr [Irp+0xb8], 0x48` at `0x14000533a–0x140005340` and `0x14000113f–0x1400010cd`), and normal completion.

---

## 3 IOCTL table

`IRP_MJ_DEVICE_CONTROL` is **not hooked** by DriverEntry (only majors 15/27/20/21 are); the module itself never exposes user-mode-issued control codes. The only control-code switch is inside the **internal** dispatch `0x140001200` (`IRP_MJ_INTERNAL_DEVICE_CONTROL`, reachable only from kernel components — HIDCLASS and drivers above it; user mode cannot post an internal-device-control IRP). Decoded switch (Further decoded: control code = `Device<<16 | Access<<14 | Function<<2 | Method`; all method access constants are as stored):

| Control code | dev / fn / method / access-mask | handler | kernel action (with size checks) |
|---|---|---|---|
| `0x000B0003` | `0x0B`/`0x00`/METHOD_NEITHER/0 (ANY) | `0x1400010d0` (`0x1400012e4`) | Writes a fixed 9-byte descriptor (`0x00012109`, `0x0100`, byte `0x22`, word from ctx+0x10) into the buffer pointer supplied by the caller at `Irp+0x70`; requires caller-stated length (stack+8) ≥ 9 (`0x1400010d8–0x1400010e1`) else `STATUS_BUFFER_TOO_SMALL` (`0xC0000023`); sets `Irp->Information = 9` |
| `0x000B0007` | `0x0B`/`0x01`/METHOD_NEITHER/0 (ANY) | `0x1400011a8` (`0x1400012da`) | Copies **ctx-derived** data (`(ctx+0x10)` length bytes from `(ctx+0x18)` buffer) into the caller buffer at `Irp+0x70` using `memmove 0x140001780` bounded by the caller's own length check (`0x1400011bb–0x1400011c4`); sets length; else `0xC0000023` |
| `0x000B000B` | `0x0B`/`0x02`/METHOD_NEITHER/0 (ANY) | passdown wrapper at `0x1400012c9–0x1400012c4` | requires an attached device at ctx-encoder `DeviceObject+0x40→+8` (`0x14000129e–0x1400012ab` else `0xC000000E`, `STATUS_NO_SUCH_DEVICE`); forwards IRP via inline skip+`IofCallDriver` in `0x140001090` with internal tag `0x2a2023` |
| `0x000B000F` | `0x0B`/`0x03`/METHOD_NEITHER/0 (ANY) | passdown at `0x140001306–0x1400012c9` | same as above, tag `0x2a2027` |
| `0x000B0013` | `0x0B`/`0x04`/METHOD_NEITHER/0 (ANY) | `0x14000127d–0x140001299` | requires `Irp+0x70 != 0` **and** current-stack parameter `+0x10 != 0` (`0x14000127f–0x140001289`), then success with `Irp->Information = 0` (no data copy); else `0xC00000E8` |
| `0x000B001F` | `0x0B`/`0x07`/METHOD_NEITHER/0 (ANY) | `0x140001276–0x140001278` | immediate success, no data |
| `0x000B0023` | `0x0B`/`0x08`/METHOD_NEITHER/0 (ANY) | `0x140001243–0x140001276` | immediate success, no data |
| `0x000B0027` | `0x0B`/`0x09`/METHOD_NEITHER/0 (ANY) | `0x140001124` (`0x140001353`) | Produces a fixed 32-byte capability block (zeroed, `0x20`, then copies ctx words `+4`, `+8` to `out+4`, `out+6`; the word IDs `0xC2A8/0xC2A9/0xC2AA` at ctx+8 select a third word from ctx+0xC, otherwise 1); requires caller length ≥ 0x20 (`0x140001135–0x14000113b`) else `0xC0000023` |
| `0x000B0191` | `0x0B`/`0x64`/METHOD_IN_DIRECT/access-bits `2` | `0x140001048` (`0x140001344`) | requires lower device (as above); forwards IRP via `0x140001090` with tag `0x2a2033` |
| `0x000B0192` | `0x0B`/`0x64`/METHOD_OUT_DIRECT/access-bits `2` | `0x140001000` (`0x140001335`) | forwards IRP via `0x140001090`, tag `0x2a202f` |
| `0x000B0195` | `0x0B`/`0x65`/METHOD_IN_DIRECT | `0x14000106c` (`0x140001326`) | forwards, tag `0x2a203b` |
| `0x000B01A2` | `0x0B`/`0x68`/METHOD_OUT_DIRECT | `0x140001024` (`0x140001310`) | forwards, tag `0x2a2037` |
| every other value | — | `0x14000131f` | `0xC00000BB` (`STATUS_NOT_SUPPORTED`) |

Handler exit logic `0x14000135d–0x14000137e`: adapters that completed the IRP themselves suppress the final completion (guard flag at stack, `0x14000121d` init `1`, passdown funnels set it to `0` at `0x1400012ba`); completion is `IofCompleteRequest` via IAT `0x140002020` at `0x14000136c`.

**Inbound-only supplementary codes** (sent **down** by this driver, never requested from it): `0x2a2014`/`0x2a2018` — device-type `0x2A`, functions `0x805/0x806`, METHOD_BUFFERED, FILE_ANY_ACCESS — used at `0x14000519c` to fetch ctx-resident descriptor data (4- & 16-byte holders at local `0x1400051c8–0x140005207`) and pooled buffer; `0x2a201c` (function `0x807`) — sent at `0x140005064–0x1400050b5` during STOP to cancel in-flight passdowns via synchronous helper `0x14000509c` (`IoBuildDeviceIoControlRequest` + `KeInitializeEvent` + block-on-completion, `0x1400050ec–0x140005113`).

No handler dereferences caller-supplied raw pointers outside the class-mediated `Irp+0x70` buffer; no handler performs writes other than the internal context updates and the buffers described above; every handler bounds its output by a caller-declared length before copying.

---

## 4 Access-control audit

- **Privilege/identity APIs:** zero. No `SeSinglePrivilegeCheck`, `SeAccessCheck`, token, audit or capability API appears in the import directory, and no call site in any of the 38 local code-bearing procedures touches one (complete `analyze_function` coverage listed in §2/§3). No caller-identity or process-context inspection (`PsGetCurrentProcess*` absent entirely).
- **Security-descriptor interaction:** the driver never builds, sets, or queries a security descriptor. `IRP_MJ_QUERY_SECURITY`/`IRP_MJ_SET_SECURITY` (majors 20/21) are forwarded verbatim to the lower device with `IoSkipCurrentIrpStackLocation` and `PoStartNextPowerIrp`/`IofCallDriver` (`0x1400013f0–0x14000142f`, `0x140001430–0x140001449`); no descriptor text (SDDL) exists anywhere in the string inventory.
- **Device/interface creation:** none — the binary creates no device object, no device interface, no symlink, no exclusive-flag device; there is nothing of its own to open from user mode. Its registration (`HidRegisterMinidriver` at `0x1400060b8`) defers the public HID device to HIDCLASS, which owns the exposure and its DACL.
- **Exposure surface actually reachable by an arbitrary user-mode caller through the HID class device:** the standard complete HID operations that HIDCLASS builds over this minidriver (read/write reports). None of the binary's internal control codes (`0x000B0003`–`0x000B01A2`) can be sent directly from user mode; internal-device-control IRPs are kernel-issued only. No `SeSinglePrivilegeCheck`-like gate exists or is needed inside this binary for them, because the only sender is the class driver above it.
- **Registry access:** one read of its **own** service-subkey value (`LGVirHid\Parameters\DebugLevel`). No other registry operation exists (no write-capable registry import).
- **Attacker-in-scope summary:** a user-mode process can, at most, issue standard HID requests on the device that HIDCLASS published; the binary contributes no additional access path, stores no credential-like data, and has no power of privilege escalation or system-state mutation beyond emulating a joystick and consuming its own debug cookies.

---

## 5 Most dangerous exposed capability

**None that grants user-mode privilege; the strongest local primitive is the forwarded-IRP pass-down plus the emulation state engine.** Concretely, and with no claim above its measured behavior:

1. The distribution of the binary's own functions to a user-mode caller is limited to what HIDCLASS publishes; there is no `IoCreateDevice`/interface/`SDDL`/`privilege` operation to widen that limit.
2. The strongest *kernel-local* behavior is `0x14000109c`'s forward (skip-location + `IofCallDriver`) toward the lower device — anyone who can already drive the HID stack (kernel components) can route typed IRPs (`0x000B000B`, `0x000B000F`, `0x000B019x`, `0x000B01Ax`) either down (passdown tags above) or into the fixed-size context copies (`0x000B0003`/`0x000B0007`/`0x000B0027`). All of those consumers are size-bounded and write only class-provided buffers, so the "most dangerous" capability is a forwarding primitive, not a privilege boundary.
3. If forced to name the narrowest user-mode-visible effect: an anonymous logged-on caller can interact with an **emulated joystick** (standard HID read/write of reports) — a benign input-emulation capability that HIDCLASS mediates and whose DACL belongs to HIDCLASS, not this driver.

No buffer-model abuse, no arbitrary write, no handle/kernel-pointer disclosure, no unsigned-code load, no APC/injection, no hard-error or key-protection trick, no activation of process-token change, was found at any address in this binary.

---

## 6 VERDICT

**NO MALICIOUS CAPABILITY / NOT EXPLOITABLE AS LOADED — benign WDM HID virtual-joystick minidriver.**

- The binary registers itself with HIDCLASS (`0x1400060b8`), creates **no** device of its own, exposes **no** device interface and **no** user-mode control code of its own; its entire reach is the four hooked majors (majors 15/27/20/21) consumed by the HIDCLASS-mediated stack.
- Complete import and §3 IOCTL coverage shows **no** SDDL/security/privilege API usage, **no** registry write, **no** process/thread/token interaction, **no** pool corruption by design, and consistent /GS+CFG hardening.
- The only unusual element is the address-mapped opaque data blob at `0xff00000000–0xff00001850` ("tdb") containing no code and no references; this is a provenance-unknown, capability-neutral addition and is recommended for byte-level comparison against an unquestioned copy of the same driver version if provenance is required.
- Operational close-out: **no mitigation or removal action is required for this artifact based on static evidence alone.**
