# Audit: VBoxUSBMon.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\VBoxUSBMon.sys` |
| Recorded SHA-256 | `ADE2E8D684CB59BFEA99AD09E55BC5F2A808D824C2905DED1366B7D32E906529` (matches triage_index.csv row `VBoxUSBMon`; sha256 recomputed in-session) |
| Company/Version | Oracle and/or its affiliates (VirtualBox USB monitor; PDB `VBoxUSBMon.pdb`) |
| Method | Static-only audit via REA/Ghidra 12.1.4, memory-write scope only |
| Verdict | **NO-WRITE** (coverage ~55%) — no write through a caller-supplied kernel or user pointer found; handle-table lookups do not dereference inputs; writes stay in driver-owned records and the buffered output |
| Coverage | Not traced: `FUN_140005c50` (validation), `FUN_140005970` (field reset), `FUN_1400064a0` (release), `FUN_1400028d0` (IOCTL 0x229854), `RTMemContAlloc` caller (reached only through an indirect table; no resolved direct caller, two data references `0x1400335e4`, `0x1400341bc`) |

> **Static-only.** No load, no device open, no IOCTL execution. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- DriverEntry = `entry` @ `0x140002340`. Creates `\Device\VBoxUSBMon` via `IoCreateDevice` (device type `0x22`, **no SDDL**; default device SD applies, not established in-file) and `\DosDevices\VBoxUSBMon`.
- Dispatch: `DriverUnload`/`0x68` = `FUN_1400018e0`; `MJ_CREATE` = `FUN_140001280`; `MJ_CLOSE` = `FUN_1400010f0`; `MJ_DEVICE_CONTROL` = `FUN_1400013e0`; `MJ_INTERNAL_DEVICE_CONTROL` = `FUN_1400015b0`.
- Import surface for memory-write APIs: `MmAllocateContiguousMemory`, `MmFreeContiguousMemory`, `MmGetPhysicalAddress`. **No** `ProbeForRead`/`ProbeForWrite`, `MmProbeAndLockPages`, `MmMapLockedPages*`, `MmMapIoSpace`, `IoAllocateMdl`, `ZwMapViewOfSection`.

## IOCTL dispatch (`FUN_1400013e0`, buffered)

| Code | Handler | Input/output contract | Write behaviour |
|---|---|---|---|
| `0x229840` | inline | 8-byte out | writes constant `5` to the buffer (driver version) |
| `0x229844` | `FUN_1400025d0` | in 0x138, out 0xC | clears config fields, calls `FUN_140006020`, returns handle; writes only to the buffered output |
| `0x229848` | `FUN_140002fd0` | in 8, out 0 or 4 | reads user value, passes to `FUN_1400064a0` (not decompiled), clears matching list nodes; writes only driver-list nodes |
| `0x229854` | `FUN_1400028d0` | no input | not decompiled |
| `0x22985c` | `FUN_140002900` | in 8 (pointer-sized value), out 4 | **compares the user value against kernel list nodes; does not dereference it**; writes status into the buffered output |

## Memory-write analysis

| Pattern | Result | Evidence |
|---|---|---|
| User-supplied pointer dereference | None found. `FUN_140002900` and `FUN_140002fd0` use user-supplied 64-bit values only as list-node identities (pointer equality) | `ev_efbba536…`, `ev_d7f05947…` |
| Record copy from user input | `FUN_140006020` copies a fixed `0x150` bytes from the buffered input into a driver record (`RTMemAllocTag(0x150)`), links it into a driver list and a handle table | `ev_d9dbd0a3…` |
| Kernel address write from user input | None found | — |
| Contiguous allocation + physical address | `RTMemContAlloc` (`0x140015eb0`): `MmAllocateContiguousMemory(roundup(size), highest)`, `MmGetPhysicalAddress`, writes the 32-bit physical address through its first parameter `*param_1 = phys`. **No resolved direct caller**; incoming references are two data references (`0x1400335e4`, `0x1400341bc`) that look like table entries. If that output pointer ever comes from user input without probing, the write becomes an unprobed 4-byte kernel write of a fresh physical address. Not established | `ev_b153a513…`, `ev_b64eef79…`, `ev_5267507c…` |
| MDL / section mapping | Absent from import table | import sweep |
| Unchecked copy length | None in decompiled code; fixed sizes everywhere | the decompiles above |

## Findings

1. **No memory write from user input observed.** The DEVICE_CONTROL surface only writes to driver-owned records and to the buffered output.
2. **Open item: RTMemContAlloc output pointer.** The allocation helper writes the physical address through a pointer argument. The caller is not resolved (indirect table). If that caller passes a user-controlled pointer, it is a write-what-where of a 4-byte physical-address value. Verify the table caller before closing.
3. **Information disclosure, not write.** Physical addresses of contiguous allocations can reach a caller if the output is returned; not established in-file.

## Verdict rationale

NO-WRITE on the statically visible surface. Escalation needs the RTMemContAlloc caller to pass an unprobed user pointer (→ WRITE-MEDIUM at most, given the value is a physical address the attacker cannot choose).

## Next steps (for the write-only pass)

- Resolve the indirect caller of `RTMemContAlloc` (data references `0x1400335e4`, `0x1400341bc`: identify the table and the call site through it).
- Decompile `FUN_140006020`'s callers chain for the output pointer.
- Decompile `FUN_1400064a0` (release path) and `FUN_1400028d0`.

## VM confirmation plan (orchestrator-owned; non-destructive)

1. Unprivileged token: `CreateFile("\\\\.\\VBoxUSBMon", ...)`; record access.
2. If open: issue `0x229840` (version) and `0x22985c` with a bogus pointer-sized value, expecting a status-only reply and no fault.

## Evidence (REA, retained IDs)

`ev_5c6c0464a39a75ae67fa6f5e680410947151d99fdb048f8c05a634fdcf7eecfd` (`entry`), `ev_d1d6b6f64064b1224e412d528914dd3d7187f0a9692b52faef64d0d9787f681c` (DEVICE_CONTROL), `ev_efbba536bee8f54274f0bed3d3430b41fc36d23dc9716fb86dd4c9202aa09def` (`FUN_140002900`), `ev_d7f05947a369b2a8d273225007a56613a6330fea4dffc8fb6ad3db4f85cf6ae3` (`FUN_140002fd0`), `ev_a8b0e01fa1e97b15e077c9fae679528442ea7d8436aab19a0ca5ca1cee8146d3` (`FUN_1400025d0`), `ev_d9dbd0a3a5c0cc37d70d99b8b24aee791fd6d6f42b625dee300c3dd2c3f5cde2` (`FUN_140006020`), `ev_b153a513ac4e623ea4c1a28a3f92fd3c219f6b3823d8f9560dc2784ea4f67c27` (`RTMemContAlloc`), `ev_b64eef79581d9c141570191e87a793ae94beee03712c06839bc3b406e34e8704` (callers), `ev_5267507c67c9fd9b02670c9679ca4108632541b31d5c700ac923b5cb63abda93` (incoming references).
