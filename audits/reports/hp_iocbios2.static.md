# Audit: HP `iocbios2` (Intel Overclocking Device Driver) + HP custom-capture drivers

| Field | Value |
|---|---|
| Files | `drivers\HP\iocbios2_CD99AF27.sys`<br>`drivers\HP\iocbios2_248C12EE.sys`<br>`drivers\HP\hpcustomcapdriver_4185515E.sys`<br>`drivers\HP\hpomencustomcapdriver_31C1473B.sys`<br>`drivers\HP\hpomencustomcapdriver_6B1B8DC6.sys` |
| SHA-256 | `cd99af2797491c8937bf5977366e06fcca0bf4c46f0bb542ec46b3b9cf2f5e14`<br>`248c12ee260b1d73302ba4c465f4ca79cdb13e677231042a78bdb85827a18ebf` |
| Architecture | x86-64 (both) |
| Method | Static-only (REA / Ghidra 12.1.4). No driver loaded, no device opened, no IOCTL issued. |
| Verdict | **NO-WRITE** — every IOCTL path is gated by `SeSinglePrivilegeCheck` on an admin-only privilege |
| Setup required | **none** — `\Device\iocbios2` + `\DosDevices\iocbios2` are created in `DriverEntry` |

> Addresses are linked VAs at image base `0x140000000`.

## 1. Device surface and creation trigger

`DriverEntry` = `FUN_14000c000` @ `0x14000c000` (reached from `entry` @ `0x14000c260`). It creates the device **at load time**, not via PnP:

```
0x14000c045  RtlInitUnicodeString(&devName, L"\\Device\\iocbios2")
0x14000c057  RtlInitUnicodeString(&sddl,    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)(A;;GR;;;RC)")
0x14000c107  WdmlibIoCreateDeviceSecure(DriverObject, 0x110, &devName,
                                        DeviceType = 0x2a,          // FILE_DEVICE_UNKNOWN
                                        DeviceCharacteristics = 0,
                                        Exclusive = 0,
                                        &sddl, NULL, &DeviceObject)
0x14000c1xx  DeviceObject->Flags |= 0x04                    // DO_BUFFERED_IO
0x14000c1xx  DeviceObject->Characteristics = 0x100          // FILE_DEVICE_SECURE_OPEN
0x14000c209  IoCreateSymbolicLink(L"\\DosDevices\\iocbios2", L"\\Device\\iocbios2")
0x14000c218  FUN_140009000(...)                             // ExCreateCallback("\\Callback\\OcMailboxGTChangeCallback")
```

The `WdmlibIoCreateDeviceSecure` import is statically linked as `FUN_14000967c`; it is the routine that parses the SDDL and calls `ZwSetSecurityObject` (xref `0x140009947`). There is **no second security application** and no registry-read `Security` override.

Device object type `0x2a`; `DO_BUFFERED_IO` is set, so all IOCTL data goes through `Irp->AssociatedIrp.SystemBuffer`.

Major functions installed:

| Offset | IRP | Handler | Behaviour |
|---|---|---|---|
| `+0x70` | `IRP_MJ_CREATE` | `0x140009240` | status = 0, complete |
| `+0x80` | `IRP_MJ_CLOSE` | `0x140009240` | status = 0, complete |
| `+0xE0` | `IRP_MJ_DEVICE_CONTROL` | **`0x140001290`** | full IOCTL dispatcher |
| `+0xE8` | `IRP_MJ_INTERNAL_DEVICE_CONTROL` | `0x140009240` | status = 0 |
| `+0xF0` | `IRP_MJ_SHUTDOWN` | `0x140009240` | status = 0 |
| `+0x100` | `IRP_MJ_CLEANUP` | `0x140009240` | status = 0 |
| `+0x120` / `+0x128` | POWER / SYSTEM_CONTROL | `0x1400092e0` | status = 0 |

Opening `\\.\iocbios2` requires only `FILE_READ_ACCESS` under this DACL, and that is enough to submit `METHOD_BUFFERED` IOCTLs.

## 2. Effective DACL (cited from the binary, not the INF)

The descriptor string is embedded in `DriverEntry`:

```
D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)(A;;GR;;;RC)
```

Decoded: `SYSTEM` `GENERIC_ALL`; `BUILTIN\Administrators` `GENERIC_ALL`; **`Everyone` `GENERIC_READ` only**; `RESTRICTED` `GENERIC_READ` only. No `FILE_WRITE_ACCESS` for unprivileged users, no `FILE_ALL_ACCESS`, no `GENERIC_EXECUTE`.

Both builds contain the identical SDDL at `0x14000c057` and call `FUN_14000967c` at `0x14000c107`. The only `ZwSetSecurityObject` call site in the image is inside that wdmlib routine (`0x140009947`) — there is no second path that re-applies a DACL and no `IoCreateDeviceSecure` call with a different descriptor.

## 3. Handler table (IRP_MJ_DEVICE_CONTROL = `0x140001290`)

Parsing of the stack location (`lVar13 = Irp->Tail.Overlay.CurrentStackLocation`):

```
uVar14 = *(uint *)(lVar13 + 0x08);   // OutputBufferLength
uVar2  = *(uint *)(lVar13 + 0x10);   // InputBufferLength
uVar1  = *(uint *)(lVar13 + 0x18);   // IoControlCode
_Src   = *(ulonglong **)(Irp + 0x18); // AssociatedIrp.SystemBuffer
```

`Type3InputBuffer` (stack `+0x20`) is **never read**. Every code is `METHOD_BUFFERED` (`code & 3 == 0`), all with `RequiredAccess = 3` in the encoding (device type `0x89FF`, i.e. vendor-defined).

Every branch starts with the same gate before touching `SystemBuffer`:

```
cVar4 = FUN_140009598(Irp);
if (cVar4 == '\0') { Irp->IoStatus.Status = 0xC0000061; ... }   // STATUS_PRIVILEGE_NOT_HELD
```

| IOCTL | In / Out (min) | Handler | Operation (as decompiled) |
|---|---|---|---|
| `0x89FFE004` | 0 / 4 | inline | writes `0x070C0012` to `SystemBuffer` — version/capability |
| `0x89FFE420` | 12 / 8 | `FUN_1400093e4` | index validated against table @ `0x140005330` (0x28 dwords) |
| `0x89FFE424` | 20 / 4 | `FUN_14000943c` | 20-byte vendor op (input copied to locals) |
| `0x89FFE428` | 20 / 16 | `FUN_140009374` | 16-byte vendor op |
| `0x89FFE430` | 12 / 4 | `FUN_140009538` | **write path**; index + `FUN_1400090f0` range check |
| `0x89FFE434` | 24 / 16 | `FUN_140009300` | 16-byte vendor op |
| `0x89FFE440` | 36 / 4 | `FUN_1400026ec` | **write**, index validated |
| `0x89FFE444` | 20 / 0x420 | `FUN_1400024bc` | **write**, 0x420-byte payload |
| `0x89FFE448` | 24 / 0x810 | `FUN_140002374` | **write**, 0x810-byte payload |
| `0x89FFE44C` | 4 / 8 | `FUN_1400094a4` | SMBus/SPD read (sub-index 0..6, sizes 0x300/0x128) |
| `0x89FFE450` | 8 / =HiDword(in[0]) | `FUN_1400094f0` | 0x2A-entry mailbox table; base + index, dword write |
| `0x89FFE454` | 9 / ≥4 | alloc + `memcpy_s` + `FUN_14000956c` | variable-length vendor block write |
| `0x89FFE458` | 12 / 4 | `FUN_14000280c` | vendor register write |
| `0x89FFE45C` | 7 / 8 | inline | sets 8-byte reply; `ExNotifyCallback` if first word == 0x11 |
| `0x89FFE4C0` | 0 / 1 | `FUN_140002aa4` | writes `DAT_140007308` to the output byte |
| `0x89FFE4C4` | 1 / 0x800 | `FUN_140003a04` | per-slot 0x800-byte block |
| `0x89FFE4C8` | 0x42 / 4 | `FUN_140003adc` | writes 0x40 bytes at `(slot+0x0b)*0x40` |
| default | — | — | `0xC0000016` (STATUS_INVALID_DEVICE_REQUEST) |

`HalSetBusDataByOffset` call sites: `0x140002877`, `0x140002bd5`, `0x14000322a`. `MmMapIoSpace` is imported; its call sites are in the hardware-access helpers behind the same gate.

## 4. The privilege gate (the decisive control)

`FUN_140009598` @ `0x140009598`:

```
0x1400095c1  cVar1 = SeSinglePrivilegeCheck(0x15, *(undefined1 *)(Irp + 0x40));   // Irp->RequestorMode
0x1400095d3  cVar1 = SeSinglePrivilegeCheck(0x16, *(undefined1 *)(Irp + 0x40));
             return (cVar1 != 0);
```

- LUID low parts `0x15` (21) and `0x16` (22). With the standard `winnt.h` numbering these are `SeAuditPrivilege` (21) and **`SeSystemEnvironmentPrivilege`** (22) — the latter is exactly the privilege required for firmware/BIOS variable access and is Administrators-only. `SeAuditPrivilege` is held by system service accounts (`LocalSystem`/`LocalService`/`NetworkService`), not by a standard interactive user.
- The second argument is `Irp->RequestorMode`, so for a user handle the check is against the current thread's token; a kernel-mode caller is not automatically granted.
- Failure path (`LAB_1400013a9`) returns `0xC0000061` (`STATUS_PRIVILEGE_NOT_HELD`) and sets `Information = 0` before `IofCompleteRequest`.

**Answer to the DACL question:** the `Everyone:GR` ACE is *not* what stops write IOCTLs. Because every code is `METHOD_BUFFERED`, the I/O manager does not require `FILE_WRITE_ACCESS` on the handle, and the driver never calls `IoValidateDeviceIoControlAccess` (the name only appears as a wdmlib string, not as a call). A standard user can open the device for read and reach `0x140001290`. What stops the writes is the in-driver `SeSinglePrivilegeCheck` — a stronger check than the DACL, and one that is applied on **every** branch (the default branch performs no work).

Every code in the dispatch is structurally `METHOD_BUFFERED` (`code & 3 == 0`); a caller cannot change the method because it is encoded in the IOCTL number. There is therefore no `Type3InputBuffer` (METHOD_NEITHER) path in this driver to abuse — the only buffer the dispatcher ever reads is `Irp->AssociatedIrp.SystemBuffer`, and the I/O manager allocates and copies it.

## 5. Write sinks (for completeness — all behind the gate)

- `FUN_140002374` (IOCTL `0x89FFE448`): 0x810-byte vendor mailbox write.
- `FUN_1400024bc` (`0x89FFE444`): 0x420-byte vendor mailbox write.
- `FUN_1400026ec` (`0x89FFE440`): indexed register write.
- `FUN_140009538` (`0x89FFE430`): PCI-config style write via `HalSetBusDataByOffset`.
- `FUN_1400094f0` (`0x89FFE450`): dword write at `base[index] + offset`.
- `0x89FFE454`: `ExAllocatePoolWithTag` → `memcpy_s(pool, uVar18, SystemBuffer, uVar18)` → `FUN_14000956c`; length `uVar18 = (count-1)+9` is rejected unless `uVar18 <= InputBufferLength`, so the copy is bounded by the user buffer it came from.

`MmMapIoSpace` regions are driver-chosen physical addresses from the PCI/BIOS mailbox, not user-supplied.

## 6. Validation gaps

1. **The privilege gate is the only barrier.** If a future build dropped `FUN_140009598` from even one branch, the `GR` DACL would not prevent exploratory writes. `0x89FFE450` in particular indexes a static 0x2A-entry table and adds an offset — worth re-checking on every update.
2. **Two builds, same behaviour.** `CD99AF27` and `248C12EE` have different SHA-256 but identical `DriverEntry` (`0x14000c000`), identical SDDL literal, identical device/symbolic-link names, identical dispatch address (`0x140001290`) and identical privilege wrapper (`0x140009598`, calls at `0x1400095c1`/`0x1400095d3`). No behavioural difference was found in the reviewed paths; the difference is in build/signature data (not analysed further).
3. `0x89FFE45C` calls `ExNotifyCallback(ctx->Callback, 1)` with no user data — no sink.
4. `0x89FFE4C8` computes `(slot+0x0b)*0x40` and writes 0x40 bytes; `slot` is validated `< 8` and `(slot_hi-3) < 2` first (`0x140003834`/`0x140003adc`), so the target stays inside the driver's own table.

## 7. Setup required

**none.** The device and its `\DosDevices\iocbios2` link are created in `DriverEntry`; no INF, no devnode, no hardware ID. On an HP OEM image the service is already installed; a standard user can `CreateFile("\\\\.\\iocbios2", GENERIC_READ, ...)` and submit buffered IOCTLs immediately. This is the only driver in this batch that is genuinely "no-setup" — and it is also the only one with an explicit admin-privilege gate.

## 8. Next dynamic test

1. On the VM with the HP service loaded, as a **standard user**: `CreateFile("\\.\iocbios2", GENERIC_READ, FILE_SHARE_READ|WRITE, ...)` → expect success.
2. `DeviceIoControl(0x89FFE004, NULL,0, &out,4, ...)` → expect `FALSE`, `GetLastError() == ERROR_PRIVILEGE_NOT_HELD` (1314 / `0xC0000061`). This proves the DACL is not the control and the gate is.
3. Repeat with `0x89FFE450` (8-byte input) and `0x89FFE448` (0x810 output buffer) → same status. If any returns `0`, the privilege wrapper has been bypassed and the file must be re-rated.
4. Optional: run the same calls from a `LocalSystem` service to confirm the positive path and that the handler table matches the static decode. Do **not** issue the write codes from a privileged context on a production machine — they touch firmware mailboxes.

## Appendix: HP custom capture drivers (`hpcustomcapdriver`, `hpomencustomcapdriver`)

| File | Arch | SHA-256 |
|---|---|---|
| `hpcustomcapdriver_4185515E.sys` | x86-64 | `4185515ef51a3e6ad018e768cf3b077d3e8b1e884d85c3a2db31f43a086f2bdf` |
| `hpomencustomcapdriver_31C1473B.sys` | x86-64 | `31c1473b664119d84165a90f79fba6d95f5407ec1680518fd1bf434941b27f42` |
| `hpomencustomcapdriver_6B1B8DC6.sys` | x86 | `6b1b8dc6e9c730ed1fc55312b1eb9d7cc865d216ef0b97058e99d700625418b7` |

- Pure KMDF stub drivers (`WdfVersionBind`/`WdfVersionBindClass` only; `entry` → `FxDriverEntryWorker`). Imports: `DbgPrintEx`, `RtlCopyUnicodeString`, `WDFLDR.*`; no `IoCreateDevice`, no `IoCreateSymbolicLink`, no `Mm*`, no `ProbeFor*`.
- No INF was collected for them, so the DACL and hardware ID are unknown; by construction (KMDF `EvtDeviceAdd`, no control device) they require a **devnode**.
- Verdict: **NO-WRITE**, setup **devnode** (disqualified under no-setup). No further analysis warranted unless an INF surfaces.

*End of report.*
