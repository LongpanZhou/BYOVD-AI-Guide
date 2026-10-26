# Audit: ThrottleStop `LowLevel_x86` + OCCT `ORingDrv` — kernel memory-write audit (static)

| Field | Value |
|---|---|
| File(s) | `drivers/ThrottleStop_LowLevel_x86_01C14C61.sys` (18,432 B)<br>`drivers/OCCT_ORingDrv_221D879A.sys` (76,976 B) |
| SHA-256(s) | `01C14C61303717F8EF2D9DBD2D003F6E7B70437AEB3690BC0151101B3D87A81F`<br>`221D879A2B4C7BBD80DFBA8F95A2CA388BFFD152AF7BC208025404B33C17EF41` |
| Analysis date | 2026-10-25 |
| Method | Static only. SHA-256 verified on disk. PE headers/imports/DACL constants read with a read-only PE parser; decompilation with local Ghidra 12.1.4 headless (56 functions for ThrottleStop x86, 309 for OCCT); dispatcher jump tables and call-site argument setup cross-checked with llvm-objdump 20.1.5. **REA was not used** — four REA audits were already active and the constraint was not to open a fifth session. Nothing was loaded, installed, executed, or written to the registry. |
| Reach tier | **R2 — local administrator** (both devices: DACL SYSTEM + Administrators, generic all) |
| Setup required | **service** (both). ThrottleStop additionally needs driver-signature enforcement off *and* a 32-bit Windows install. |
| Write quality | ThrottleStop x86: **W3P** (physical-address-only, arbitrary PA + arbitrary value)<br>OCCT: **W0** |
| Severity | ThrottleStop x86: **BLOCKED** (unsigned 32-bit image; static primitive **MW3**)<br>OCCT: **NO-MEMORY-WRITE (HW-ONLY)** |
| Verdict | **No loadable kernel memory-write primitive is added by either file.** ThrottleStop x86 is the 32-bit sibling of the already-`BLOCKED` x64 build and repeats its physical-memory window; OCCT ORingDrv exposes no kernel memory write at all — MSR, PCI-config read, and two device-MMIO windows only. |

> Static-only audit. No exploit code, no PoC, no operating steps. Both files were read from disk only.

## Per-file result

| File | Arch | Signature | Device / effective DACL | Write quality | Static severity | Status |
|---|---|---|---|---|---|---|
| `ThrottleStop_LowLevel_x86_01C14C61.sys` | i386 (0x14C) | **NotSigned** (cert dir RVA 0x4800 = EOF, declared 0x6C28) | `\Device\<service-name>` + `\??\<service-name>`; `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | W3P | **MW3** | **BLOCKED** — unsigned *and* 32-bit-only |
| `OCCT_ORingDrv_221D879A.sys` | x86-64 (0x8664) | **Signed** — Microsoft Windows Hardware Compatibility Publisher (WHQL), timestamp 2026-03-09 | `\Device\ORingDrv` + `\DosDevices\ORingDrv`; `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | W0 | **NO-MEMORY-WRITE (HW-ONLY)** | Live (admin-reachable) |

---

# 1. ThrottleStop `LowLevel_x86` (`01C14C61`)

## 1.1 Internals

- PE32, machine `0x14C`, image base `0x400000`, `SizeOfImage 0xC000`, timestamp 2020-10-06 20:34:27 UTC. Sections `.text`, `.rdata`, `.data`, `PAGE`, `INIT`, `.rsrc`, `.reloc`. Version resource: FileVersion `3.0.0.0`, ProductName `Low-Level Driver`, no CompanyName.
- **Signature: absent.** `IMAGE_DIRECTORY_ENTRY_SECURITY` = RVA `0x4800`, size `0x6C28`; the file is exactly `0x4800` bytes, so the WIN_CERTIFICATE starts at EOF and no certificate bytes exist. This is the same defect as the x64 baseline (there the pointer was `0xB000` in a `0x5800` file).
- Imports: `ntoskrnl.exe` (device/IRP, `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `IoAllocateMdl`, `MmBuildMdlForNonPagedPool`, `PsGetCurrentProcessId`, security APIs used by the statically linked `wdmsec` library), `HAL.dll` (`HalGetBusDataByOffset`, `HalSetBusDataByOffset`, `KeGetCurrentIrql`). No `memcpy`-style arbitrary copy sink is imported for the IOCTL path.

## 1.2 Entry / device / effective DACL

- Entry `0x00401370` → `DriverEntry` (`entry`). It derives the device name from the **service key basename**: `wcsrchr(RegistryPath->Buffer, L'\\')` (call at `0x004013A6`), formats `\Device\%ls` (`0x004014B6`, `_snwprintf` wrapper `0x00401300`), and calls the statically linked **`WdmlibIoCreateDeviceSecure`** at `0x004014EA`.
- Arguments at the call site: extension size `0x140C`, device type `0x22`, characteristics `0x100` (`FILE_DEVICE_SECURE_OPEN`), exclusive `0`, SDDL `PCUNICODE_STRING` at `0x004031D0`.
- SDDL structure at `0x004031D0`: `{Length=0x36, MaximumLength=0x38, Buffer=0x00403198}` → **`D:P(A;;GA;;;SY)(A;;GA;;;BA)`**. Decoded: protected DACL, `GENERIC_ALL` to `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`; no ACE for `Everyone`/`Authenticated Users`. The other SDDL fragments in `.rdata` (`0x0040316E`…`0x00403278`) are `wdmsec` library constants, not the descriptor passed by `DriverEntry`.
- `WdmlibInit` (`0x00407000`) resolves `IoCreateDeviceSecure` via `MmGetSystemRoutineAddress`; if that export is missing, `_IoDevObjCreateDeviceSecure_36` (`0x0040712B`) parses the same SDDL with `SeSddlSecurityDescriptorFromSDDL` and applies it with `ObOpenObjectByPointer` + `ZwSetSecurityObject` (`0x004070B1`). Either path yields the effective DACL above.
- Symbolic link `\??\%ls` created at `0x0040158C` (`IoCreateSymbolicLink`), then `IoRegisterShutdownNotification`.
- `DRIVER_OBJECT` dispatch installed in `DriverEntry`: `IRP_MJ_CREATE`=`0x00401610`, `IRP_MJ_CLOSE`=`0x00401640`, `IRP_MJ_DEVICE_CONTROL`=`0x00401BD0`, `IRP_MJ_SHUTDOWN`=`0x00401670`, `IRP_MJ_CLEANUP`=`0x00401750`, `DriverUnload`=`0x004016A0`. No `IRP_MJ_READ`/`WRITE`.

**Effective gate: the DACL only.** A standard user cannot open the device; a local administrator can, with generic-all rights. There is no privilege check, no caller-identity handshake, and no `IoValidateDeviceIoControlAccess` call in the dispatch path.

## 1.3 Dispatch and IOCTL table

`IRP_MJ_DEVICE_CONTROL` handler `0x00401BD0` switches on `Parameters.DeviceIoControl.IoControlCode` (stack-location `+0xC`). The switch is a two-level table: byte index table at `0x004022D4`, target table at `0x004022A4`; base `0x80006430`, span `0x74`. Decoded targets:

| IOCTL | Access / method | Input | Handler | Kernel action |
|---|---|---|---|---|
| `0x80006430` | FILE_READ_ACCESS / METHOD_BUFFERED | 2 (port) | `0x00401C14` | `in` 1/2/4 bytes from caller port — **HW-ONLY** |
| `0x80006434` | FILE_READ_ACCESS / METHOD_BUFFERED | 5/6/8 (port+value) | `0x00401C9F` | `out` 1/2/4 bytes to caller port — **HW-ONLY** |
| `0x80006448` | FILE_READ_ACCESS / METHOD_BUFFERED | 8 | `0x00401D30` → `0x004018C0` | `rdmsr`, no denylist — **HW-ONLY** |
| `0x8000644C` | FILE_READ_ACCESS / METHOD_BUFFERED | 12 | `0x00401D3E` → `0x00401780` | `wrmsr` with denylist — **HW-ONLY** |
| `0x8000645C` | FILE_READ_ACCESS / METHOD_BUFFERED | 12 (PA64, len32) | `0x00401D4C` → `0x004019B0` | map PA range RW into caller process, return VA |
| `0x80006460` | FILE_READ_ACCESS / METHOD_BUFFERED | 4/8 (VA) | `0x00401D5F` | unmap by VA + PID |
| `0x80006494` | FILE_READ_ACCESS / METHOD_BUFFERED | 0 | `0x00401E37` | no-op: returns DWORD 4 |
| `0x80006498` | FILE_READ_ACCESS / METHOD_BUFFERED | 8 (PA64) | `0x00401EA6` | **read 1/2/4/8 bytes from any PA** |
| `0x8000649C` | FILE_READ_ACCESS / METHOD_BUFFERED | 8+1/2/4/8 (PA64, value) | `0x00401FC3` | **write 1/2/4/8 bytes to any PA** |
| `0x800064A0` | FILE_READ_ACCESS / METHOD_BUFFERED | 8 | `0x004020E9` | PCI config read (`HalGetBusDataByOffset`) — **HW-ONLY** |
| `0x800064A4` | FILE_READ_ACCESS / METHOD_BUFFERED | 8+1/2/4 | `0x004021BA` | PCI config write (`HalSetBusDataByOffset`) — **HW-ONLY** |

All codes are METHOD_BUFFERED (`method = 0`) and carry `FILE_READ_ACCESS` in the CTL_CODE (bits 14–15 = `01` for the whole `0x6430`–`0x64A4` range); the admin's generic-all open satisfies that.

## 1.4 Memory-write trace

### 1.4.1 Arbitrary physical write — IOCTL `0x8000649C` (`0x00401FC3`)

- Validates `OutputBufferLength == 0` and `size = InputBufferLength - 8 ∈ {1,2,4,8}`; rejects anything else with `0xC0000206`.
- `MmMapIoSpace(*(PHYSICAL_ADDRESS*)SystemBuffer, size, MmNonCached)` at `0x00402042`. **No physical-range check of any kind.**
- Stores the caller's value from `SystemBuffer+8` into the mapping at width 1/2/4/8 (`0x0040207E` / `0x0040209B` / `0x004020B8` / `0x004020CF`), then `MmUnmapIoSpace`.
- Result: **any physical address, any value, sizes 1/2/4/8.** The only gate is the admin DACL.

### 1.4.2 Arbitrary physical read — IOCTL `0x80006498` (`0x00401EA6`)

- `OutputBufferLength` = 1/2/4/8 selects the width; `InputBufferLength == 8` supplies the physical address. Same unvalidated `MmMapIoSpace`; the mapped value is copied into the output buffer (which, for METHOD_BUFFERED, is the same `SystemBuffer`).
- This is a full physical read (a page-table walk is therefore possible from user mode), but it does **not** return any kernel virtual address.

### 1.4.3 Physical range mapped into the caller's process — IOCTL `0x8000645C` (`0x004019B0`)

- Input 12 bytes: physical base (8) + length (4). Output length 4 or 8.
- `MmMapIoSpace(base, length, MmNonCached)` → `IoAllocateMdl(va, length, FALSE, FALSE, NULL)` → `MmBuildMdlForNonPagedPool(mdl)` → **`MmMapLockedPagesSpecifyCache(mdl, 1 /*UserMode*/, MmNonCached, NULL, FALSE, 0x10)`** at `0x00401ADB`.
- Because `AccessMode = UserMode`, the returned pointer is a **user-mode address in the calling process**, not a kernel address. The IOCTL writes that value into the output buffer immediately after the call. The mapping is recorded in the device extension (`0x140C` bytes) as a 0x100-entry table of `{physical base, user VA, MDL, length, PID}`.
- IOCTL `0x80006460` (`0x00401D5F`) unmaps: it requires the caller to pass the VA (4/8 bytes), then matches the table entry's VA **and** `PsGetCurrentProcessId()` (`0x00401DD0`) before `MmUnmapLockedPages` + `MmUnmapIoSpace` + `IoFreeMdl`.
- Net effect: **read/write user-mode access to an arbitrary physical range**, of arbitrary length (32-bit), with no range check. Still PA-based, not a kernel-VA write.

### 1.4.4 Hardware-only paths (not memory writes)

- **MSR write** `0x8000644C` → `0x00401780`: `wrmsr(index, value)` with both from input. Denylist at `0x0040181D`–`0x0040184B`: `0x174`–`0x176` and `0xC0000081`–`0xC0000083`. **`IA32_EFER 0xC0000080` is writable.** MSR read `0x80006448` has no denylist.
- **Port I/O** `0x80006430`/`0x80006434`: `in`/`out` at any port, widths 1/2/4.
- **PCI config** `0x800064A0`/`0x800064A4`: `HalGetBusDataByOffset`/`HalSetBusDataByOffset` with caller bus/slot/function/offset and no device filter.
- These are `HW-ONLY`. They are recorded because they are the strongest hardware capabilities in the file, not because they write kernel memory.

## 1.5 Comparison with the x64 baseline (`70CCADF7`)

| Property | x64 baseline | x86 (`01C14C61`) | Material difference? |
|---|---|---|---|
| Device-creation call | `WdmlibIoCreateDeviceSecure`, ext `0x2818`, type `0x22`, chars `0x100` | same, ext `0x140C` | no (extension size only) |
| Effective SDDL | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` @ `0x1400032B0` | identical @ `0x00403198` | **no** |
| IRP dispatch set | CREATE/CLOSE/DEVICE_CONTROL/SHUTDOWN/CLEANUP/UNLOAD | identical | no |
| IOCTL set | `0x80006430`–`0x800064A4` (11 live codes) | identical 11 codes (jump table verified) | no |
| Physical write 0x…649C | arbitrary PA, value, 1/2/4/8 | identical logic (`0x00401FC3`) | **no** |
| Physical read 0x…6498 | arbitrary PA, 1/2/4/8 | identical logic (`0x00401EA6`) | **no** |
| Map/unmap 0x…645C/6460 | `MmMapIoSpace`+MDL+`MmMapLockedPagesSpecifyCache` | identical | no |
| Mapping access mode | **UserMode** (`movb $1,%dl` @ `0x140001E15`) | **UserMode** (`push 1` @ `0x00401AD8`) | no — but see note |
| MSR denylist | `0x174`–`0x176`, `0xC0000081`–`0xC0000083` (`0x140001C66`) | identical (`0x0040181D`) | **no** |
| Loadability | unsigned x64; needs DSE off | unsigned **i386**; needs DSE off *and* 32-bit Windows | **yes — strictly worse** |

Two corrections to the baseline's prose, both derived from the same code in **both** builds:

1. **The MSR denylist is `0xC0000081`–`0xC0000083`, not `0xC0000080`–`0xC0000082`.** The x64 baseline text lists `0xC0000080`–`0xC0000082`; the x64 instruction at `0x140001C66` (`lea 0x3fffff7f(%rcx); cmp $2; jbe deny`) rejects `0xC0000081`–`0xC0000083`, so `IA32_EFER (0xC0000080)` is writable in **both** builds. This is a wording/off-by-one error in the baseline, not an x86 difference (and EFER is MSR/HW-ONLY under the scope).
2. **The map IOCTL does not disclose a kernel VA.** `MmMapLockedPagesSpecifyCache` is called with `AccessMode = UserMode` in both builds, so the value returned to the caller is a user VA in the caller's process. The x64 report's `MW2` raise, which rests on "the kernel VA is returned (kernel address disclosure)", is not supported by the call site. The primitive is physical-address-only (`W3P`), which is `MW3` on the `SEVERITY.md` matrix — the same tier as `DirectIo64`. The practical capability is still severe (user-mode RW to any physical page, plus arbitrary-length mapping), but it is not a kernel-VA write-what-where.

The `x86` build therefore **does not differ materially in primitive** from the x64 build; it differs in *loadability*. A 32-bit kernel driver cannot be loaded by an x64 Windows kernel at all, so on this host the x86 file is unusable regardless of signing. On a 32-bit Windows install it would additionally need signature enforcement disabled.

## 1.6 Verdict — ThrottleStop x86

**BLOCKED.** Static primitive **MW3** — `reach=R2 setup=service write=W3P load=unsigned`.

- The device DACL is SYSTEM + Administrators generic-all (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`), so an administrator can open it (`R2`); a standard user cannot (`R1` is not reachable).
- The file contains a real, unconstrained physical-memory window: arbitrary PA read, arbitrary PA write (any value, 1/2/4/8), and an arbitrary-length PA mapping into the caller's process. There is **no** kernel-virtual-address write and **no** kernel-VA disclosure.
- MSR, port, and PCI paths are `HW-ONLY`.
- Load gate: unsigned **and** 32-bit-only (machine `0x14C`), so it is not loadable on this x64 host; on 32-bit Windows it needs signature enforcement off.

---

# 2. OCCT `ORingDrv` (`221D879A`)

New target; no prior report.

## 2.1 Internals

- PE32+ x64, machine `0x8664`, image base `0x140000000`, `SizeOfImage 0x15000`, timestamp 2026-03-09 16:25:46 UTC, sections `.text` (`0xD196`), `.rdata`, `.data`, `.pdata`, `PAGE`, `INIT`, `.reloc`.
- **Signed.** `IMAGE_DIRECTORY_ENTRY_SECURITY` = RVA `0x10400`, size `0x28B0`; certificate is present and the signer strings identify **Microsoft Windows Hardware Compatibility Publisher** with a 2026-03-09 timestamp (`Microsoft Time-Stamp Service`). Loadable on a default x64 system.
- KMDF driver (`WDFLDR.SYS`: `WdfVersionBind`/`WdfVersionBindClass`; no `ntoskrnl` IRP dispatch). Imports: `ExAllocatePool2`, `ExFreePoolWithTag`, `MmMapIoSpace`, `MmUnmapIoSpace`, `KeSetSystemGroupAffinityThread`, `KeRevertToUserGroupAffinityThread`, `KeQueryActiveGroupCount`, `KeQueryActiveProcessorCountEx`, `KeDelayExecutionThread`, `RtlCopyUnicodeString`, `DbgPrintEx`, `strncmp`, `HalGetBusDataByOffset`.
- Absent: `MmGetPhysicalAddress`, `MmProbeAndLockPages`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `HalSetBusDataByOffset`. No port I/O instructions anywhere in `.text` (verified by instruction scan: 0 `in`/`out`, 2 `rdmsr`, 2 `wrmsr`).

## 2.2 Entry / device / effective DACL

- `DriverEntry` = `0x140013000`. `WdfDriverCreate` (WDF table `+0x3A0`) then, at `0x1400130CC`, the table slot at `+0xC8` — **`WdfControlDeviceInitAllocate(Driver, &SDDL)`** — with the `UNICODE_STRING` at `0x14000F438` = `{Length=0x36, Max=0x38, Buffer=0x14000F400}`. The buffer at `0x14000F400` is **`D:P(A;;GA;;;SY)(A;;GA;;;BA)`**.
- The returned `PWDFDEVICE_INIT` is passed to the device-add routine `0x140012000`, which:
  - assigns the name `\Device\ORingDrv` (`0x140012420`) via WDF table `+0x218` (`WdfDeviceInitAssignName`);
  - creates the device (`WdfDeviceCreate`, table `+0x258`);
  - creates the symlink `\DosDevices\ORingDrv` (`0x140012450`) via `WdfDeviceCreateSymbolicLink` (table `+0x280`);
  - creates one I/O queue (`WdfIoQueueCreate`, table `+0x4C0`) whose `EvtIoDeviceControl` is `0x14000A660`; `WdfWaitLockCreate` follows.
- There is no `EvtIoRead`/`EvtIoWrite`; the only request surface is the IOCTL queue.
- **Effective DACL: `D:P(A;;GA;;;SY)(A;;GA;;;BA)`** — SYSTEM and Administrators generic-all, protected. Standard users are denied. This matches the `SDDL-ACTIVE-RESTRICTED` label in `STATUS.md`, and the string is genuinely the one passed to device creation (single xref at `0x1400130B3`).
- The device exists once the service is started (`Setup: service`); opening `\\.\ORingDrv` requires the admin DACL.

## 2.3 Dispatch and IOCTL table

`EvtIoDeviceControl` `0x14000A660` (6,341 bytes) is a binary-search dispatch on `IoControlCode`. All 79 live codes decode as **METHOD_BUFFERED** (`code & 3 == 0`); access is **FILE_READ_ACCESS** for `0x9C496xxx`–`0x9C497xxx` and **FILE_WRITE_ACCESS** for `0x9C49Bxxx`. The admin generic-all open satisfies both.

Each case first checks `DAT_140010148`; it is zero until IOCTL `0x9C496EE0` runs the context initialiser. (`DAT_140010138` / `DAT_140010140` belong to the separate first-time feature-initialiser set and do not gate IOCTLs.)

IOCTL `0x9C496EE0` allocates the 0x1C2920-byte non-paged context (`0x14000D5F8` → `ExAllocatePool2(0x40, 0x1C2920, 'tcco')` via `0x14000C154`) and the 0x1004-byte request table (`0x14000D580`), then runs ~45 per-feature initialisers (`0x14000A574`). There is no authentication token: any opener that can reach the device (i.e., an administrator) can perform the handshake.

Input, where an IOCTL takes any, is copied into a fixed stack structure with `WdfRequestRetrieveInputMemory` + `WdfMemoryCopyToBuffer` (`0x14000BFD4`, table `+0x858`/`+0x620`); the copy is bounds-checked by the WDF memory object. Output uses `WdfRequestRetrieveOutputMemory` + `WdfMemoryCopyFromBuffer` (`0x14000BF28`, table `+0x860`/`+0x628`). No raw user pointers, no METHOD_NEITHER.

| Code | Access | In (B) | Handler | Class / kernel action |
|---|---|---|---|---|
| 0x9C496EE0 | R | – | `0x14000D5F8`, `0x14000D580` | init: allocate 0x1C2920 context + 0x1004 table |
| 0x9C496EE4 | R | – | `0x14000A444` | CPU info block 0x1A0E4 |
| 0x9C496EE8 | R | – | `0x140009F20` | platform info block 0x1008 |
| 0x9C497098 | R | 0xc | `0x140004DB4` | platform info block 0x1008 |
| 0x9C497840 | R | 8 | `0x140009C28` | **BAR read 8 B** |
| 0x9C497848 | R | 0x10 | `0x140009AF4` | **BAR read 8 B** |
| 0x9C4976B0 | R | 0x30 | `0x1400014E4` | fixed-mailbox read + CPU info |
| 0x9C4979D0 | R | 0x30 | `0x140001988` | CPU info (mailbox read + WMI) |
| 0x9C49B844 | W | 8 | `0x140009CE4` | **BAR 8 B read-modify-write** |
| 0x9C49B9D4 | W | 0x30 | `0x140001CD8` | **fixed-mailbox 8 B MMIO write** |
| 0x9C49B6B4 | W | 0x30 | `0x140001698` | vendor-routed register write (MSR **or** fixed mailbox) |
| 0x9C49B53C | W | 0xc | `0x1400036D0` | MSR write (fixed index) |
| 0x9C49B544 | W | 0xc | `0x14000385C`, `0x1400034D0` | MSR write (fixed index) |
| 0x9C49B554 | W | 0xc | `0x140002EC8` | MSR write (fixed index) |
| 0x9C49B55C | W | – | `0x140002C00` | MSR write (fixed index) |
| 0x9C49B564 | W | – | `0x140003B80` | MSR write (fixed index) |
| 0x9C49B574 | W | 0xc | `0x140002130` | MSR write (fixed index) |
| 0x9C49B57C | W | 0xc | `0x1400023E0` | MSR write (fixed index) |
| 0x9C49B584 | W | 0x20 | `0x14000286C` | MSR write (fixed index) |
| 0x9C497520 | R | 0xc | `0x140003024` | MSR read |
| 0x9C497528 | R | 0x30 | `0x1400031C4` | MSR read |
| 0x9C497530 | R | – | `0x14000354C` | MSR read |
| 0x9C497538 | R | 0xc | `0x140003670` | MSR read |
| 0x9C497540 | R | 0xc | `0x1400037FC` | MSR read |
| 0x9C497550 | R | 0xc | `0x140002CCC` | MSR read |
| 0x9C497568 | R | – | `0x140003988` | MSR read |
| 0x9C497570 | R | 0xc | `0x140001FD8` | MSR read |
| 0x9C497578 | R | 0xc | `0x140002380` | MSR read |
| 0x9C497580 | R | 0x20 | `0x140002544` | MSR read |
| 0x9C497548 | R | – | `0x140003014` | no-op / version |
| 0x9C49B54C | W | – | `0x140003014` | no-op / version |
| 0x9C497560 | R | – | `0x140003ACC` | ACPI/WMI query |
| 0x9C497210 | R | – | `0x140006D60` | ACPI/WMI query |
| 0x9C4970A0 | R | – | shared branch | ACPI/WMI query |
| 0x9C497070 | R | – | `0x140003DF8` | ACPI/WMI query |
| 0x9C497078 | R | 0xc | `0x140004108` | ACPI/WMI query |
| 0x9C497080 | R | – | `0x1400044B8` | ACPI/WMI query |
| 0x9C497088 | R | 0xc | `0x140004824` | ACPI/WMI query |
| 0x9C497090 | R | – | `0x140004C3C` | ACPI/WMI query |
| 0x9C4970A8 | R | – | `0x1400054F0` | ACPI/WMI query |
| 0x9C4970B0 | R | – | `0x140005830` | ACPI/WMI query |
| 0x9C4970B8 | R | 0xc | `0x140005AD0` | ACPI/WMI query |
| 0x9C4970C0 | R | – | `0x140005E48` | ACPI/WMI query |
| 0x9C4970C8 | R | 0xc | `0x140005FDC` | ACPI/WMI query |
| 0x9C4970D0 | R | – | `0x140006538` | ACPI/WMI query |
| 0x9C4970D8 | R | 0x10 | `0x1400061F8` | ACPI/WMI query |
| 0x9C497200 | R | – | `0x1400068A0` | ACPI/WMI query |
| 0x9C497208 | R | 0xc | `0x140006B80` | ACPI/WMI query |
| 0x9C497218 | R | – | `0x14000707C` | ACPI/WMI query |
| 0x9C497220 | R | 0xc | `0x1400073B8` | ACPI/WMI query |
| 0x9C497228 | R | 0xc | `0x140007600` | ACPI/WMI query |
| 0x9C497230 | R | 0x10 | `0x14000799C` | ACPI/WMI query |
| 0x9C497238 | R | – | shared branch | ACPI/WMI query |
| 0x9C497240 | R | 0xc | `0x140008258` | ACPI/WMI query |
| 0x9C497390 | R | 0xc | `0x140008524` | ACPI/WMI query |
| 0x9C497398 | R | 0xc | `0x140008728` | ACPI/WMI query |
| 0x9C4973A0 | R | 0xc | `0x140008AE0` | ACPI/WMI query |
| 0x9C4973A8 | R | 0xc | `0x140008D0C` | ACPI/WMI query |
| 0x9C4973B0 | R | 0x10 | `0x140008EFC` | ACPI/WMI query |
| 0x9C497558 | R | – | `0x140002A40` | ACPI/WMI query |
| 0x9C49B074 | W | – | `0x140003F20` | ACPI/WMI set |
| 0x9C49B07C | W | 0xc | `0x1400041B8` | ACPI/WMI set |
| 0x9C49B084 | W | – | `0x140004650` | ACPI/WMI set |
| 0x9C49B08C | W | 0xc | `0x140004A30` | ACPI/WMI set |
| 0x9C49B09C | W | 0xc | `0x140005098` | ACPI/WMI set |
| 0x9C49B0A4 | W | 0xc | `0x140005420` | ACPI/WMI set |
| 0x9C49B0AC | W | – | `0x14000566C` | ACPI/WMI set |
| 0x9C49B0B4 | W | – | `0x140005A00` | ACPI/WMI set |
| 0x9C49B0D4 | W | – | `0x14000663C` | ACPI/WMI set |
| 0x9C49B204 | W | – | `0x1400069DC` | ACPI/WMI set |
| 0x9C49B214 | W | – | `0x140006EDC` | ACPI/WMI set |
| 0x9C49B21C | W | – | `0x140007284` | ACPI/WMI set |
| 0x9C49B22C | W | 0xc | `0x140007798` | ACPI/WMI set |
| 0x9C49B234 | W | 0x10 | `0x140007AA4` | ACPI/WMI set |
| 0x9C49B23C | W | 0x10 | `0x140007FA4` | ACPI/WMI set |
| 0x9C49B394 | W | 0xc | `0x1400085D0` | ACPI/WMI set |
| 0x9C49B39C | W | 0xc | `0x1400088A0` | ACPI/WMI set |
| 0x9C49B3B4 | W | 0x10 | `0x140008FB4` | ACPI/WMI set |

`In (B)` is the immediate passed to the input copy (`FUN_14000bfd4`); `–` means no input copy in that branch (or a shared branch). Output blocks are fixed-size copies into a WDF output memory object, whose length is enforced by the framework.

## 2.4 Access-control audit

- The only access gate is the device DACL (`SYSTEM` + `Administrators` generic all). There is no `SeAccessCheck`, no `SeSinglePrivilegeCheck`, no token/PID check, and no per-IOCTL access filter beyond the CTL_CODE read/write bits (satisfied by the generic-all open).
- `DAT_140010148` is an **initialisation** flag, not an authorisation token: IOCTL `0x9C496EE0` sets it, and any holder of the device handle can call that IOCTL.
- **Reach: R2 (local administrator).** Standard users cannot open `\\.\ORingDrv`.

## 2.5 Memory-write trace

### 2.5.1 What does *not* exist

- No kernel-VA write-what-where: no IOCTL takes a destination pointer; input is copied by value into stack structures and never reinterpreted as an address.
- No MDL mapping, no `MmProbeAndLockPages`, no `MmGetPhysicalAddress`, no `MmCopyMemory`, no `\Device\PhysicalMemory`, no `ZwMapViewOfSection`.
- No pool overflow sink found: the only variable-size-looking allocation is `ExAllocatePool2` in `0x14000C154`, and every call site passes a constant (`0x1A0E4`, `0x1008`, `0x1C2920`, `0x1004`).
- No PCI-config write: `HalSetBusDataByOffset` is not imported; only `HalGetBusDataByOffset` (`0x14000C500`) is used.
- No port I/O.

### 2.5.2 Device MMIO — PCI-derived window (IOCTLs `0x9C497840`, `0x9C497848`, `0x9C49B844`)

- Read helper `0x140009804` and write helper `0x1400098E8` compute a **physical** address from platform data, not from a raw user address:
  - `base = ctx[0x1C2108]` (32-bit) + `ctx[0x1C2110]` (64-bit), captured at init in `0x14000D310` from PCI configuration space via `HalGetBusDataByOffset` (`0x14000C500`, config offsets `0x14` and `0x170`).
  - `+ (u16[ctx+0x1C211E+idx*8] * index + u16[ctx+0x1C2120+idx*8] * 0x100) * 4 + offset`.
  - `index` is bounded by `u8[ctx+0x1C211D+idx*8]` (`0x140009930`); `offset < 0x1000` (`0x14000994D`).
- `FUN_14000C600` (`0x14000C600`) performs `MmMapIoSpace(pa, 8, MmNonCached)`, an 8-byte store, and `MmUnmapIoSpace`. `FUN_14000C3D8` is the matching 8-byte read.
- For `0x9C49B844` (`0x140009CE4`) the driver first reads the 8-byte register, replaces bits 8–14 and 15–21 from the 8-byte input, and writes it back — a device-register RMW at `device base + bounded offset`, not a kernel-memory write.
- `0x9C497840` / `0x9C497848` are pure reads of the same window.

**Classification: fixed-window device MMIO → `HW-ONLY`.**

### 2.5.3 Device MMIO — fixed mailbox (IOCTLs `0x9C49B9D4`, `0x9C49B6B4`)

- `FUN_140001CD8` (`0x140001CD8`) builds an 8-byte value from the input structure and calls `FUN_14000C600` with `pa = DAT_140010000 + ctx[0x1C20F0]` (`0x140001D34`–`0x140001D46`).
- `DAT_140010000` is a static 32-bit global (initial value `0x59A0`; no store to it anywhere in `.text`). `ctx[0x1C20F0]` is written once at init (`0x14000C7A8`: PCI config `0:0.0` offset `0x48`, bits 16–63, `<< 16`) — platform data, not IOCTL input.
- Target is therefore **fixed at init**, not caller-controlled; the caller supplies only the 8-byte value (composed from input fields by `0x140001D60`).
- `FUN_140001698` (`0x9C49B6B4`) routes to the same mailbox write (`FUN_140001CD8`) or to an MSR write (`FUN_1400034D0`) depending on the CPU signature.

**Classification: fixed-target 8-byte MMIO → `HW-ONLY`.**

### 2.5.4 MSR writes (IOCTLs `0x9C49B53C`, `B544`, `B554`, `B55C`, `B564`, `B574`, `B57C`, `B584`, and via `B6B4`)

- `FUN_14000C664` / `FUN_14000C654` execute `wrmsr` after pinning the target core with `KeSetSystemGroupAffinityThread`. The MSR index is a fixed per-feature global (`DAT_140010014`, `DAT_14001001C`, `DAT_140010020`), not caller-selected; the value is built from the input structure.
- `rdmsr` paths (`0x14000C434`, `0x14000C45C`) are the matching reads.

**Classification: MSR write → `HW-ONLY`.**

### 2.5.5 ACPI/WMI paths

- Most of the `0x9C497xxx` / `0x9C49Bxxx` families route through `FUN_140009300` / `FUN_140009774` (WMI/ACPI method evaluation, WMI index constants such as `0x14`, `0x1A`, `0x20`) and then store results into stack structures. These are firmware calls with fixed method IDs; no kernel memory destination.

## 2.6 Most dangerous exposed capability

An administrator who can open `\\.\ORingDrv` and complete the `0x9C496EE0` handshake gets:

1. `wrmsr` with a fixed per-feature MSR index and a caller-composed 64-bit value (the MSR index is selected per feature at init, not by the caller);
2. 8-byte writes to a fixed platform mailbox MMIO address; and
3. an 8-byte read-modify-write in a PCI-derived device window at a bounded offset (< 0x1000).

None of these writes kernel memory. The strongest *practical* effect is hardware state change (overclock/undervolt/power limit), which the scope classifies as `HW-ONLY`.

## 2.7 Verdict — OCCT

**NO-MEMORY-WRITE (HW-ONLY)** — `reach=R2 setup=service write=W0 load=signed`.

- Admin-only, signed KMDF control device with a real SDDL (`SYSTEM` + `Administrators`).
- 79 METHOD_BUFFERED IOCTLs; every write sink resolves to MSR, fixed-mailbox MMIO, or a bounded device-BAR RMW. No kernel-VA write, no arbitrary PA map, no MDL, no pool overflow.
- `STATUS.md` flagged this driver for `MmMapIoSpace`; the import is real, but both call sites use a fixed 8-byte device window, not a caller-supplied physical address.

---

# 3. Overall verdict

**No loadable kernel memory-write primitive is added by either file.**

| | ThrottleStop `LowLevel_x86` | OCCT `ORingDrv` |
|---|---|---|
| Real memory write? | Physical only (arbitrary PA R/W + arbitrary-length PA map into the caller) | **None** — MSR / fixed-mailbox MMIO / BAR RMW only |
| Kernel VA write? | No | No |
| Write quality | W3P | W0 |
| Static severity | MW3 | NO-MEMORY-WRITE (HW-ONLY) |
| Status | **BLOCKED** (unsigned + 32-bit-only) | Live, admin-only, signed |
| Net | Duplicate of the already-BLOCKED x64 primitive, with worse loadability | Hardware-access driver only |

- **ThrottleStop x86** is a functional clone of the x64 build: same SDDL, same 11 IOCTLs, same unvalidated physical read/write, same mapping design. It is not a new finding. Two baseline corrections are recorded in §1.5 (the MSR denylist is `0xC0000081`–`0xC0000083`, so EFER is writable; and the map IOCTL returns a **user** VA, so the `MW2` "kernel-VA leak" rationale does not hold — the correct static tier is `MW3`/`W3P`). The file is additionally a 32-bit image and cannot load on this x64 host.
- **OCCT ORingDrv** is `NO-MEMORY-WRITE (HW-ONLY)`. Its `MmMapIoSpace` usage is a fixed 8-byte device window addressed from platform data, not a caller-controlled physical address. The remaining writes are `wrmsr` and a fixed mailbox store.

No `MW1`/`MW2`/`MW4` finding results from this pair. Nothing was loaded or executed.

---

# 4. Limitations

- **REA was not used.** Four REA audits were already active and this task was explicitly offline; the analysis relies on Ghidra 12.1.4 headless plus llvm-objdump 20.1.5 and a read-only PE parser. No independent decompiler cross-check beyond those.
- **Static only.** No dynamic confirmation of the DACL, the IOCTL reachability, or the physical mappings. All conclusions are from the images.
- **OCCT breadth.** 309 functions and 79 IOCTL codes were triaged by decompiled call-graph and targeted reading of the dispatcher, the two `MmMapIoSpace` helpers, the mailbox helper, the MSR helpers, and the allocation sites. No symbolic taint analysis was run; a caller-controlled write into the 0x1C2920-byte context through a path not reached by those helpers cannot be excluded with certainty, though every context index seen is bounds-checked against a context-supplied count.
- **Ghidra rendering.** Some decompiled calls show a truncated argument list (e.g., `MmMapIoSpace(pa, 8)` without the cache type); argument order and values were confirmed from the corresponding `llvm-objdump` listings (`0x14000C600`, `0x4019B0`, `0x401ADB`, `0x140001D46`).
- **ThrottleStop identity.** The image is unsigned, has no CompanyName in its version resource, and is 32-bit; vendor identity rests on the file name, the PDB string `Driver.pdb`, and the `3.0.0.0` version block. It cannot be loaded on this x64 host for dynamic confirmation.
- **Baseline not re-audited.** The x64 `ThrottleStop` report was read as the comparison baseline only; the two corrections in §1.5 are backed by instruction-level evidence from the x64 image (`0x140001C66`, `0x140001E15`) and do not constitute a re-audit.
