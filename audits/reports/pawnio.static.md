# PawnIO `PawnIO_4383A699.sys` — static audit

Build: v2.2.0 (INF `DriverVer 03/11/2026`), SHA256 `4383a699eed9de0cf73eca3739b227dc07769e964381867dd482bf0760bf94cc`, x64.
PE TimeDateStamp `2006-08-15` (does not match the 2026 INF date; metadata anomaly, noted only).
Method: static only. Ghidra 12.1.4 headless, `DumpAllDecomp.java`. Image base `0x140000000`. Nothing loaded or installed.

## 1. Verdict

**NO-WRITE** (for attacker-chosen content). Every write-capable host function is reachable only through a module that passes an RSA signature check against keys embedded in the driver. No unsigned path was found.

Conditional capability (recorded, not a finding under the standard): a **signed** module can drive unchecked physical, PCI-config, and MSR writes with arguments taken from the user. The write surface exists. Its trust boundary is the signing key, and the device is admin-only and devnode-only (§3). If it were reachable, it would be `WRITE-PHYS-HIGH-BLOCKED` with `WRITE-PORT-HIGH-BLOCKED` for PCI and MSR. The verdict vocabulary has no slot for a signature-gated primitive, so this is flagged for your decision.

## 2. Gate analysis (why NO-WRITE)

The only route into the module loader is IOCTL `0xA1B22084`:
- `entry` (`0x140001e80`) → IOCTL `0xA1B22084` → `FUN_140010ea0` @ `0x140010ea0` (sole caller of the verifier: line 2154 of the dump, no other call sites).
- `FUN_140010ea0` → `FUN_140010fe0` @ `0x140010fe0` (sole caller: `FUN_140010ea0`, line 21336).
- `FUN_140010fe0`:
  1. Reads a 4-byte signature length from the input (`*param_2`), checks `sig_len <= total - 4`.
  2. SHA-256 over the module body: `FUN_140003320` @ `0x140003320` (sole caller: `FUN_140010fe0`, line 21410).
  3. Loops over embedded keys (`DAT_140012950` via `PTR_DAT_140012b70`) and calls `FUN_140003480` @ `0x140003480`: `BCryptImportKeyPair(RSAPUBLICBLOB)` + `BCryptVerifySignature(SHA256, ...)`, magic `0x31415352` ("RSA1").
  4. Any failed verify returns the error. Only success reaches `ExAllocatePoolWithTag` (module allocation, line 21428).
- Only a verified module is stored, in the per-handle context (`FileObject->FsContext`, `IO_STACK+0x30 → +0x18`), and later executed by IOCTL `0xA1B22104` (`FUN_140010ba0` @ `0x140010ba0`, the interpreter).

The verifier has no bypass path in the binary: no flag, no second loader, no unsigned-module branch. The key blobs are in the driver's own data, not in user-writable memory.

## 3. Precondition table

| Item | Result | Evidence |
|---|---|---|
| Device exists | Yes, created in `AddDevice` | `FUN_1400019c0` @ `0x1400019c0`: `IoCreateDevice(...)` with NULL device name (third argument `0`; trailing arguments dropped by the decompiler) |
| Device created in `DriverEntry`? | **No.** `entry` only sets dispatch and `AddDevice` | `entry` @ `0x140001e80` |
| Setup cost | **devnode** (`Root\PawnIO`, root-enumerated `SoftwareDevice`) | INF: `"PawnIO" = PawnIO_Device, Root\PawnIO`, `Class = SoftwareDevice`, `PnpLockdown = 1` |
| DACL | Admin-only, `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | INF `[Custom_Security] HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GA;;;BA)"` (INF only; the binary has no SDDL literal) |
| Symlinks | `\DosDevices\PawnIO` and `\Device\PawnIO`, both pointing at the PDO name | `FUN_1400019c0`: `IoCreateSymbolicLink` with literals `0x140012330` (`\Device\PawnIO`) and `0x140012350` (`\DosDevices\PawnIO`) |
| Alternate open path | None | No `IoRegisterDeviceInterface` import; one device object |
| Hardware | None needed for the module path | — |

Disqualifiers under the brief: **devnode** and **admin-only DACL**. Either alone is enough.

Note on the master table: `_collected2\master_drivers.csv` labels this build `DEFAULT-ADMIN`. That is slightly wrong. The DACL is declared by the INF `AddReg`, not inherited from the default. The effect is the same (admin-only), but the label should read `INF-SDDL-RESTRICTED`.

## 4. Dispatch and IOCTL table

Driver object offsets are x64 (`MajorFunction[i]` at `+0x70 + 8*i`).

| Slot | Routine | Address |
|---|---|---|
| `DriverUnload` (`+0x68`) | `LAB_140001e70` | `0x140001e70` |
| `AddDevice` (`DriverExtension+8`) | `FUN_1400019c0` | `0x1400019c0` |
| `IRP_MJ_CREATE` (`+0x70`) | `FUN_140001bd0` | `0x140001bd0` |
| `IRP_MJ_CLOSE` (`+0x80`) | `FUN_140001bd0` | `0x140001bd0` |
| `IRP_MJ_DEVICE_CONTROL` (`+0xE0`) | `FUN_140001bd0` | `0x140001bd0` |
| `IRP_MJ_PNP` (`+0x148`) | `FUN_140001d20` | `0x140001d20` |
| `IRP_MJ_POWER` (`+0x120`) | `FUN_140001e30` | `0x140001e30` |

| IOCTL | Meaning | Handler | Gate |
|---|---|---|---|
| `0xA1B22084` | load module | `FUN_140010ea0` | RSA signature (`FUN_140010fe0`) |
| `0xA1B22104` | execute loaded module | `FUN_140010ba0` | requires a loaded module |
| `0xA1B22184` | version | inline | output length must be 4; returns `0x20200` |

Host API exposed to modules (name table near `0x140013468`–`0x140013900`): `physical_read_*` / `physical_write_*` (1–8 bytes), `io_space_map`, `virtual_read_*` / `virtual_write_*`, `pci_config_read_*` / `pci_config_write_*`, `msr_read` / `msr_write`, `cr_*`, `dr_*`, `xcr_*`, `mxcsr_*`. Writes are reached through these host functions. Sinks below.

## 5. Sinks (for the conditional capability)

| Sink | Address | Check before the sink |
|---|---|---|
| Physical write: `*puVar1 = value` after `MmGetVirtualForPhysical` (byte) | `FUN_140002000` @ `0x140002000` | NULL return only |
| Physical write (qword) | `FUN_140002090` @ `0x140002090` | NULL return only |
| `io_space_map` → `MmMapIoSpace(phys, size, 0)` | `FUN_140002740` @ `0x140002740` | none |
| PCI config write `HalSetBusDataByOffset` | `FUN_140002bd0` @ `0x140002bd0` | reads vendor ID first (`0xFFFF` check) |
| MSR read / write | `FUN_140002840` @ `0x140002840` (`rdmsr`), `FUN_140002860` @ `0x140002860` (`wrmsr`) | none |

The byte and qword physical writers were traced. The other widths follow the same pattern but were not each traced.

## 6. Corruption, not write

- None found. The loader copies the module with a bounded `FUN_1400119c0(dst, src, len)` where `len` equals the allocation size.

## 7. Next dynamic test (described, not run)

- VM only, after a devnode install: a standard-user `CreateFile("\\\\.\\PawnIO")` should return `0xC0000022`. This confirms the admin-only DACL and is the only test needed for the BLOCKED label.
- Signature gate: load an unsigned module blob via `0xA1B22084` as admin. Expected `STATUS_INVALID_SIGNATURE`-class failure from `FUN_140010fe0`. A success would overturn §1.

## 8. Other notes

- `DRIVER_COLLECTION_PLAYBOOK.md` §2 lists PawnIO as **excluded by policy**. This audit was requested explicitly by the brief, so it was run. The exclusion is recorded here so it stays visible.
- The verdict depends on the RSA key table being immutable in the binary. It is in the driver's data section and not user-writable.
