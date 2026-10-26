# Audit: hcmon.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\hcmon.sys` |
| Recorded SHA-256 | `94938835F53B968665EDA2A7A082788DAC0A13EE486E3186387C0FF7ECECFE8A` (matches triage_index.csv) |
| Company/Version | VMware, Inc. / 8.11.14.0 (csv row `hcmon`, NotAfter 2023-12-15) |
| Method | Static-only audit via REA/Ghidra |
| Verdict | **NO-WRITE** — all IOCTL handlers are METHOD_BUFFERED with explicit length checks; the device is unreachable to unprivileged users because MJ_CREATE runs VMware's `SeAccessCheck` gate (Admins/System/registry SID) and returns `0xC0000022` |

> **Static-only.** No load, no device open, no IOCTL execution. All results digest-verified against SHA-256 `94938835…fe8a` on the shared REA bridge. Evidence IDs: `ev_0ab61d83…` (entry), `ev_d7fa1f4c…` (DriverEntry), `ev_16fdf490…` (IOCTL switch), `ev_e07c5c90…` (SD/check helper).

## Entry surface

- DriverEntry = `FUN_140011000` (INIT, entry `0x140011550` → `__security_init_cookie` → `FUN_140011000`).
- Creates **`\Device\hcmon`** (device type **0x22**, ext size 0x5F0) + `\DosDevices\hcmon`; cancel-safe queue (`IoCsqInitialize`, callbacks `FUN_140001af0`/`FUN_140001bc0`/`FUN_140001b50`); two `IoRegisterPlugPlayNotification` registrations; a system thread (`PsCreateSystemThread`).
- Dispatch: MJ_CREATE = `FUN_1400020a0`, MJ_CLOSE = `FUN_140001f10`, **MJ_DEVICE_CONTROL = `FUN_1400021e0`**.
- **No SDDL string, no SD-builder at device creation** — but the gate lives in the CREATE handler: `FUN_1400020a0` calls **`FUN_14000a350(security-context, DesiredAccess)`** (assembly-verified pattern `…JZ 0x140002185 / MOV dword [IoStatus], 0xC0000022`); failure ⇒ `STATUS_ACCESS_DENIED`, context never allocated.
- `FUN_14000a350` (Evidence `ev_e07c5c90…`) is the **same helper used by vmx86.sys** (byte-for-byte design): SD = `{SID from \Registry\Machine\SOFTWARE\Wow6432Node\VMware, Inc.\SID, S-1-5-32-544 (Admins), S-1-5-18 (System)}`, all ACEs mask `0x1F01FF`, then `SeAccessCheck(SD, subject, 0, DesiredAccess)`. Unprivileged open ⇒ denied ⇒ **no handle, no IOCTL plane**. (Caveat: a hostile/mis-issued value in that registry SID could change the picture; the value is written by VMware's installer, not by this driver.)

## Memory-write analysis

| Pattern | Result | Evidence |
|---|---|---|
| Copy-length confusion | None. `0x81012348`: `ExAllocatePoolWithTag(tag 'vcMc', InputBufferLength)` (capped < 0xFFFF) then memcpy(pool, SystemBuffer, InputBufferLength) — allocation equals copy length | `ev_16fdf490…` |
| Probe-less METHOD_NEITHER | No METHOD_NEITHER codes: all compared codes (0x81012334–0x81012378) have method bits `00` (buffered), access bits `00` | `ev_16fdf490…` |
| Caller-MDL mapping / PhysicalMemory / MmMapIoSpace | Absent — no `MmMap*`, `ZwOpenSection`, `PhysicalMemory`, `MSR/GDT/IDT` strings anywhere | strings sweep |
| Fixed-struct writes into SystemBuffer | `0x81012340` (4 B), `0x81012350` (4 B, needs `InLen > 3`), `0x81012378` (8 B, needs `InLen > 7`) — sizes match checks | `ev_16fdf490…` |
| User index × size | `0x8101234c` list walk: copy `min(InLen, stored_len)` — bounded; per-entry `memcmp` with stored length | `ev_16fdf490…` |
| MJ_WRITE / IRP_MJ_WRITE | No MJ_WRITE handler installed (only CREATE/CLOSE/DEVICE_CONTROL) | `ev_d7fa1f4c…` |
| USB request forwarding | `GET_DESCRIPTOR_FROM_DEVICE`/`SET_DESCRIPTOR_TO_DEVICE`/`VENDOR_DEVICE` name table = USBD-format request strings used to forward user-supplied control requests to real USB devices via the lower USB stack — device-integrity only, no kernel-buffer write primitive (round-2 out of scope) | strings sweep |

## Memory-touching IOCTL table

| Code | Method | Action |
|---|---|---|
| `0x81012348` | buffered | alloc(InputLen) + copy input into stored filter buffer |
| `0x8101234c` | buffered | list search + bounded copyback `min(InLen, len)` |
| `0x81012340/50/78` | buffered | 4/4/8-byte status writes into system buffer (checks match) |
| `0x81012360` | buffered | null-terminated wide-string device name → open target (`FUN_14000275c`) |
| `0x81012364` | buffered | resolve name → object, build IRP `0x22001F` (`FUN_140001e24`) |
| `0x81012368` | buffered | InLen > 0x2B gate → `FUN_140003cac` |
| `0x8101235c/38/6c/70/74` | buffered | queue-based USB device request plumbing (`FUN_140005cc8`, `FUN_14000611c`, `FUN_140005f4c`, `FUN_140006208`, `FUN_1400063d8`) — output is to caller buffers, all queued via IoCsq |
| all other codes | — | `0xC0000001/0xC000000D` invalid |

## Verdict + VM confirmation plan

**NO-WRITE.** Unprivileged reachability is structurally blocked at MJ_CREATE by VMware's standard `SeAccessCheck` helper (Admins/System/VMware registry SID, FILE_ALL); failure returns `STATUS_ACCESS_DENIED` and no per-file context is created. Even for authorized handles, the buffered IOCTL plane applies explicit length checks on every copy; no OOB, no unprobed pointers, no physical-memory or MDL machinery.

VM check (orchestrator-owned, non-destructive): unpriv token `CreateFile("\\\\.\\hcmon", GENERIC_READ|GENERIC_WRITE…)` → expect `ERROR_ACCESS_DENIED`; admin token → open + `0x81012340` (status read) as benign reachability proof.
