# ThrottleStop LowLevel_x64 - admin-reachable kernel memory-write audit (static)

> **Correction (2026-10-25):** the x86 cross-check (`ThrottleStop_LowLevel_x86_and_OCCT_ORingDrv.md`)
> shows the `MmMapIoSpace` call uses `AccessMode=UserMode`, so the returned address is a user VA,
> not a kernel-address leak. The MW2 rationale is withdrawn. Both builds are **BLOCKED (static
> MW3/W3P)**: unvalidated physical read/write, no arbitrary kernel VA.

| Field | Value |
|---|---|
| File | `drivers/ThrottleStop_LowLevel_x64_70CCADF7.sys` (manifest batch: collected5; previously `_collected5\agentR4\new\ThrottleStop_LowLevel_x64_70CCADF7.sys`) |
| SHA-256 | `70CCADF79F0B4FAFED50640B77AA62E7DDF39840D8F1219E367CE0D2AA4BFBA9` |
| Architecture | PE32+ x64 (`machine 0x8664`), 22,528 bytes |
| Company / version | Company not present in version resource; FileVersion `3.0.0.0` |
| Signature status | **NotSigned.** Certificate directory points to file offset `0xB000`, beyond the 22,528-byte file. The embedded copy is the same. Known-bad hash list (`indexes/dedupe/known_bad_hashes.txt`): no match. |
| Method | Static only. Ghidra 12.1.4 headless decompile dump (`scratchpad\ghidra_dump\out\throttlestop_ll64.txt`, 2,761 lines, complete). Read-only PE parsing for the SDDL. Nothing loaded, installed, or executed. |
| Reach | **local administrator** (device DACL SYSTEM + Administrators only). |
| Setup required | **none** (driver load); the binary is unsigned, so driver-signature enforcement must be disabled. Load status is tracked separately as `load=unsigned`. |
| Verdict | **BLOCKED** (unsigned; loading needs signature enforcement off). Static primitive: **MW3** — reach=R2 setup=none write=W3P load=unsigned. Unvalidated physical read/write mapped into user mode; no arbitrary kernel VA and no kernel-address leak. MSR, port and PCI paths are HW-ONLY. |
| Write quality | W3P |
| Severity | BLOCKED (static MW3/W3P) |

> Static-only audit. This report records gates and primitives. It contains no test code and no operating steps. Nothing was loaded or run.

## 1. Entry surface (verified)

- `entry` (`0x140001730`): `FUN_1400016A0` builds `\Device\<name>`, then `WdmlibIoCreateDeviceSecure(DriverObject, 0x2818, name, 0x22, 0x100, 0, &DAT_1400032B0, 0, &DeviceObject)` (dump lines 577–585). The `0x100` flag is `FILE_DEVICE_SECURE_OPEN`.
- The SDDL argument is a `UNICODE_STRING` at `0x1400032B0` (Length 54, MaxLength 56). Its buffer (`0x140003278`) is `D:P(A;;GA;;;SY)(A;;GA;;;BA)`. **DACL: SYSTEM and Administrators, generic all. Standard users cannot open the device.** Read from the image; the decompile hides the third argument.
- Symbolic link `\??\<name>` created with `IoCreateSymbolicLink` (line 595).
- IRP_MJ_DEVICE_CONTROL dispatcher: `FUN_140001EF0` (line 841), switching on the IOCTL code at IO_STACK_LOCATION `+0x18`.

## 2. Memory-write analysis

### 2.1 Physical-memory write, unconstrained (IOCTL `0x8000649C`, line 1140)

- Input: 8-byte physical address, then the value (size 1, 2, 4 or 8 bytes, from `InputBufferLength - 8`, with the size checked against the set {1,2,4,8}).
- `MmMapIoSpace(physical address, size, MmNonCached)` is called with the caller's address. **No range check** on the address. The mapping is written with the caller's value, then unmapped.
- Consequence: any physical address can be written, with a caller-chosen value.

### 2.2 Physical-memory read, unconstrained (IOCTL `0x80006498`, line 1099)

- Same mapping step and the same missing range check. The mapped value is returned to the caller.

### 2.3 Physical-range map returned as kernel VA (IOCTL `0x8000645C`, line 1040 → `FUN_140001D30`, line 753)

- Input 12 bytes: physical base (8) and length (4). Output 4 or 8 bytes.
- `MmMapIoSpace` → `IoAllocateMdl` → `MmBuildMdlForNonPagedPool` → `MmMapLockedPagesSpecifyCache(mdl, KernelMode, …)`. The **kernel VA** is returned to the caller (kernel address disclosure), and the mapping is recorded in a table keyed by process ID.
- No range check on the physical base. Unmapped by IOCTL `0x80006460` (line 1044), which checks the caller's process ID against the record.

### 2.4 MSR write, partial denylist (IOCTL `0x8000644C`, line 1036 → `FUN_140001C10`, line 699)

- `wrmsr(index, value)`, both from input.
- Denied: `0x174–0x176` and `0xC0000080–0xC0000082` only (line 705–711).
- **Writable:** `IA32_CSTAR` `0xC0000083`, `IA32_FMASK` `0xC0000084`, `IA32_GS_BASE` `0xC0000101`, `IA32_KERNEL_GS_BASE` `0xC0000102`, MTRR and PAT ranges.

### 2.5 MSR read, no gate (IOCTL `0x80006448`, line 1032 → `FUN_140001CB0`, line 728)

- `rdmsr(index)` with no denylist. Read-only.

### 2.6 Port I/O (IOCTL `0x80006434`, line 1008)

- `in`/`out` at any port, widths 1, 2 and 4, from input. Not a memory write, but direct hardware access.

### 2.7 PCI configuration read and write (IOCTLs `0x800064A0` line 1181, `0x800064A4` line 1211)

- `HalGetBusDataByOffset` / `HalSetBusDataByOffset` with bus, slot, function and offset from input. No bus or device check.

### 2.8 Other

- `DbgPrint`-style logging only; no other memory writes found.
- No `ProbeForWrite`, `MmProbeAndLockPages` or user-address copies. Kernel addresses are never taken from input except as physical addresses for `MmMapIoSpace`.

## 3. Memory-touching IOCTL table

| IOCTL | Operation | Gate | Primitive | Reach |
|---|---|---|---|---|
| `0x8000649C` | physical write, 1/2/4/8 bytes | DACL only | **unconstrained physical write** | local administrator |
| `0x80006498` | physical read, 1/2/4/8 bytes | DACL only | **unconstrained physical read** | local administrator |
| `0x8000645C` / `0x80006460` | map / unmap physical range | DACL; process-ID check on unmap | kernel VA of arbitrary physical range (disclosed); mapping table | local administrator |
| `0x8000644C` | `wrmsr` | denylist (§2.4) | MSR write; GS base and KERNEL_GS base writable | local administrator |
| `0x80006448` | `rdmsr` | none | MSR read | local administrator |
| `0x80006434` | port `in` / `out` | none | arbitrary port I/O | local administrator |
| `0x800064A0` / `0x800064A4` | PCI config read / write | none | arbitrary bus/slot/function config write | local administrator |

## 4. Verdict and scale note

**BLOCKED; static primitive MW2** (reach=R2 setup=other write=W1 load=unsigned). The write primitive is unconstrained in address and value: any physical address, any value, sizes 1–8 bytes, through a device the administrator can open directly.

Caveats the reader needs:

1. **Scale (SEVERITY.md).** The write is physical-address-only, which is MW3 by definition. The physical read gives a kernel-address leak, which raises the rating one level to MW2. The file is unsigned and blocked on a default system, so the status is BLOCKED.
2. **Setup:** the file is unsigned. Windows will not load it on a default x64 system with driver-signature enforcement on. Loading it needs enforcement disabled. That precondition is larger than the driver itself, so the practical reach is lower than the primitive. The standard does not list this setup type.
3. **Known-bad:** the SHA-256 is not in `_collected5\known_bad_hashes.txt`. That list is the LOLDrivers set, so the driver's absence from it does not establish that it is safe. The primitive is the BYOVD class.

## 5. Confirmation plan (described only, not run; lab VM only, never the host)

1. Confirm that the driver cannot load on the test image without signature enforcement disabled. Record the load error. Do not disable enforcement on the host.
2. In an isolated VM with enforcement disabled, record the device DACL (`!sd`) and confirm that a standard-user token cannot open the device.
3. Confirm the physical read and write path with a harmless address on the VM only. Record the outcome. Do not run it against a live system address.

## 6. Limitations

- Static analysis of one build. Procedure names are Ghidra-recovered (`FUN_xxxxxxxx`). The decompile hides the third argument of the device-create call; the SDDL was read from the image directly.
- The version resource has no company name, and the file is unsigned, so vendor identity cannot be confirmed from the binary.
- Nothing run dynamically.
