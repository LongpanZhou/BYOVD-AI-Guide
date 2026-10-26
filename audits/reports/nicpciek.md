# Audit: nicpciek.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\nicpciek.sys` |
| Recorded SHA-256 | `BE1255E7D8E4AA05C2CA22F9E8C60D79A0AD85D69B5167A9F0EAD0DA836D6F86` (matches triage_index.csv row `nicpciek`; verified before opening; REA reports the same digest) |
| Company/Version | National Instruments (NI-APAL 22.5.0f46 build paths; device identity strings `PCIe-8398`, `784179-01`, `National Instruments`). **Correction to ledger:** this is the NI cabled-PCIe device driver, not a NIC helper |
| Method | Static-only audit via REA/Ghidra 12.1.4, memory-write scope only |
| Verdict | **WRITE-MEDIUM (admin-gated)** — an out-of-bounds 24-byte write into the firmware-transfer object (table index 9 overlaps its count and owner fields) with caller-chosen count value. Reached only through IOCTL `0x807AE00C`, which requires an elevated admin token (`FUN_140008900`). Non-admin reachable paths: no kernel write found |
| Coverage | ~45%. Reviewed: IOCTL switch, all four custom IOCTL handlers, FW-table insert chain, property-get output path, `0x22FC00` user-VA write, allocator, admin-gate and error-logger helpers. Not traced: see Open items |

> **Static-only.** No load, no device open, no IOCTL execution. Addresses are linked VAs (image base `0x140000000`). Frame-layout claims come from Ghidra's stack-offset names, not from the compiler's frame map.

## Entry surface

- `FUN_140001ff0` creates an **unnamed** WDM device: `IoCreateDevice(DriverObject, DeviceExtensionSize 0x5e0, DeviceName 0, DeviceType 0x22, Characteristics 0x100 (FILE_DEVICE_SECURE_OPEN), Exclusive 0, …)`. No `\Device\` name, so the only open path is a device interface. `IoRegisterDeviceInterface` is imported; its call site was not traced, and the interface ACL comes from the INF, which is not in the file.
- No SDDL string in the image (search for `(A;` is empty). Device DACL is therefore not established in-file.
- Dispatch: `FUN_140006e50` handles `0x22FC00` and `0x22FC04` inline and forwards other IRPs. Custom IOCTLs `0x807AE004`/`08`/`0C`/`10` are switched in `FUN_140004f20`. Its callers are not resolvable (indirect or vtable call), so the route from MJ_DEVICE_CONTROL to `FUN_140004f20` is not established in-file.
- Imports: `ProbeForRead` (2 xrefs; in-procedure `FUN_140009950`, the other at `0x14000D1E8` unresolved), `ProbeForWrite` (3 xrefs; in-procedure `FUN_140006BB0` and `FUN_1400099D0`, the other at `0x14000D148` unresolved), `MmAllocateContiguousMemory`, `MmAllocatePagesForMdl`, `MmBuildMdlForNonPagedPool`, `MmGetSystemRoutineAddress`. **No** `MmProbeAndLockPages`, `MmMapIoSpace*`, or `MmMapLockedPagesSpecifyCache`. `MmGetSystemRoutineAddress` allows dynamic resolution of mapping routines that import xrefs cannot enumerate (coverage gap for BAR/MMIO).

## IOCTL surface

| Code | Route | Input → output | Gate | Memory effect |
|---|---|---|---|---|
| `0x22FC00` | `FUN_140006e50` → `FUN_140006bb0` | 0x18 → — | none | `ObReferenceObjectByHandle` on caller event handle; `ProbeForWrite(userVA, 8, 1)`; 8-byte object-derived value written to caller VA. No SEH around the write (F3) |
| `0x22FC04` | `FUN_140006e50` (inline) | 8 → — | none | `FUN_1400059f0` lookup by caller key; `ZwUnmapViewOfSection` / `ZwClose` on handles stored in the found object. Lookup not traced |
| `0x807AE004` | `FUN_140004f20` → `FUN_140005020` → `FUN_1400040d0` | 0x18 → 8 | none | Property get. Copies up to *out-length* bytes to caller VA (probed to the same length). Stack overruns (F2) |
| `0x807AE008` | `FUN_140004f20` → `FUN_140005150` → `FUN_1400046e0` | 0x18 → 4 | none | 4-byte caller read (probed, fixed length); writes a fixed config register via bus-interface vtable. Config-control (F4) |
| `0x807AE00C` | `FUN_140004f20` → `FUN_140005250` → `FUN_140004a00` | 0x18 → 4 | **`FUN_140008900` admin** | Pool allocation of caller length (input+0x10); probed copy from caller; firmware-table insert `FUN_140002710` → `FUN_140003060` (F1) |
| `0x807AE010` | `FUN_140004f20` → `FUN_140005350` → `FUN_140004c30` | 8 → 4 | **admin** | `FUN_140002840(caller u32)`, device operation, not traced |

## Findings

**F1 — admin-gated out-of-bounds write into the firmware-transfer object (WRITE-MEDIUM).**
- Object: `D = *(dispatch ctx + 8)`, the device context passed to `FUN_140004a00`. `FO = D+0x5b0` (`param_1[0xb6]` in `FUN_140004a00`). Layout from `FUN_140002710` / `FUN_140003060`: a table of 9 entries of 0x18 bytes at `FO+0x00..+0xD8`; count `u64` at `FO+0xD8`; owner key `u64` at `FO+0xE8`; busy flag at `FO+0xF8`.
- `FUN_140002710` checks `if (8 < count || …)` and logs error `0xfffa1121` via `FUN_14000b2c0`, but has **no `return`**. It then calls `FUN_140003060(FO, count, &entry, …)` unconditionally.
- At count = 9 (after nine admitted transfers; no reset in the traced paths), `FUN_140003060` writes entry index 9 at `FO+0xD8` (address = `FO + index·0x18`). The 24 bytes land on:
  - `FO+0xD8` ← IOCTL input+0 | (input+4 << 32). **Caller-chosen 64-bit value.** Count then becomes that value + 1;
  - `FO+0xE0` ← input+0x10 (length) with 4 bytes of uninitialised stack;
  - `FO+0xE8` ← kernel pool pointer `puVar5`. This is the owner slot.
- `FUN_140004a00` frees `puVar5` after the call (status < 0), leaving a dangling pointer in the owner slot. Later calls fail the owner check (`0xfffa1122`), so the insert cannot repeat. The corrupted count remains.
- **Gate:** `FUN_140004a00` calls `FUN_140008900(param_2)` (`SeTokenIsAdmin` on the impersonation token, else on the primary token). For a non-admin it sets `0xfffa111e` and skips `FUN_140002710`. The gate sits inside `FUN_140004a00`, after the caller's inputs are read but before any allocation or copy.
- **Not established:** any consumer of the count. The cleanup or commit routines that iterate the table were not found in the traced set. If they iterate `count` entries, the caller-chosen count reaches arbitrary offsets. That is the escalation path to WRITE-HIGH/CRITICAL.

**F2 — stack buffer overruns in property get (NO-WRITE; contained; non-admin reachable if the device opens).**
`FUN_1400040d0` writes into `local_158[9]`. The 32-byte local block spans frame offsets −0x158 to −0x138; the adjacent locals are zero-initialised dead fields.

| Request | Source | Bytes into 9-byte buffer | Overrun |
|---|---|---|---|
| `0x10000000` | constant `"National Instruments"` at `0x14000D7D1` | 21 | +12 |
| `0x10000100` | constant `"PCIe-8398"` (`'P'` + `CIe-8398`) at `0x14000D7B1` | 10 | +1 (NUL, value 0 into a zero byte) |
| `0x10000300` | constant `"784179-01"` (`'7'` + `84179-01`) at `0x14000D7C1` | 10 | +1 (NUL) |
| `0x10000400` | `FUN_140003820` decimal/hex string of a device-returned word | ≤ 16 | ≤ +7 (device-derived digits) |
| `0x10000500` (sub 2/3) | `vsprintf_s(buf, 0x20, "%02x.%02x.%02xf%02x", …)` | 12 | +3 (device-derived hex). The 0x20 bound is wrong for a 9-byte buffer |
| `0x10000200` | **unbounded** copy of the device-context string at `D+0x580` | strlen+1 | unbounded; origin not traced |

- All constant and device-derived overruns stay inside the 32-byte local block (per Ghidra's offsets). No return address or cookie is reached on that layout.
- `0x10000200` is the open item. Its source is a device-context field (appears to be the device identity string). If that field can be made long by a non-admin, the copy leaves the local block. The writer of `D+0x580` was not traced.
- Output copies use the caller's out-length for the probe (`FUN_1400099d0`), so user-side writes are bounded. The copy-out of an over-long `0x10000200` string also reads past the local block into the user buffer (information disclosure, out of scope).

**F3 — user-VA write, probed (NO-WRITE).** `FUN_140006bb0` probes 8 bytes at the caller VA and writes 8 bytes, with no SEH around the write. A concurrent unmap between probe and write causes a kernel-mode fault (DoS). `FUN_140009950` and `FUN_1400099d0` probe and copy the same length.

**F4 — config-control, out of round-2 scope.** `0x807AE008` writes a fixed config register (`0x54`) with a flag selected by the request code. The caller controls only the flag bit. Noted, not rated.

**F5 — status-code injection, out of scope.** Handlers pass caller input (`+0x14` for `0x807AE004`/`0C`, `+4` for `0x807AE010`) as the status code of `FUN_14000b2c0`. A caller can force an operation to abort or continue. No memory effect shown. Noted, not rated.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Write through a caller-controlled kernel address | None found in reviewed paths | `FUN_140006bb0`, `FUN_140009950`, `FUN_1400099d0` |
| Probe-length vs copy-length mismatch (user side) | None: probe and copy lengths match in all three | `ev_2637f546…`, `ev_2d7af758…`, `ev_93994fba…` |
| Kernel copy with caller length into a fixed buffer | Present: `FUN_1400040d0` (F2). Contained except `0x10000200` (open) | `ev_569294728…` |
| Object-table OOB write with caller-influenced index/value | **Present**, admin-gated (F1) | `ev_6e64c39b…` and `ev_750d1aa3…` (`FUN_140002710`, `FUN_1400056f0`; IDs returned in that order, confirm by address), `ev_d8fabd62…` (`FUN_140003060`), `ev_390b59e6…` (`FUN_140004a00`) |
| Pool allocation with caller length | Present: `FUN_140004a00` allocates caller length (input+0x10) + header; failure sets status; the allocation is admin-gated | `ev_390b59e6…`, `ev_750d1aa3…` / `ev_6e64c39b…` (`FUN_1400056f0`, see above) |
| MDL / `MmProbeAndLockPages` / `MmMapLockedPagesSpecifyCache` | None imported | `ev_281430e3…` (import sweep) |
| MMIO / physical mapping | Not enumerable: `MmGetSystemRoutineAddress` imported | `ev_281430e3…` |

## Verdict rationale

WRITE-MEDIUM. The only kernel-memory corruption found (F1) is reached solely through IOCTL `0x807AE00C`, behind `FUN_140008900`. Non-admin paths produce no kernel write: F2 overruns are contained, F3 is probed. Escalate to **WRITE-HIGH** if a count consumer (not traced) acts on the caller-set 64-bit count without a bound. Escalate to **WRITE-CRITICAL** if a non-admin route into the FW object or its count consumers is found. Drop to **NO-WRITE** if the device interface ACL excludes non-admins and no count consumer exists.

## Open items (not traced)

- `FUN_140002840` (behind `0x807AE010`, admin-gated) and `FUN_140004c30`'s other caller paths.
- `FUN_1400059f0` (lookup behind `0x22FC04`) and object lifetime.
- `FUN_140009a50` (object init for `0x22FC00`) and `FUN_140009240` / `FUN_140009390` (default vtable slots).
- **Count consumers and cleanup/commit routines for `FO`** (decisive for F1 escalation).
- Writer of `D+0x580` (decisive for F2 `0x10000200`).
- Callers of `MmAllocateContiguousMemory` (imported) and `MmAllocatePagesForMdl` (xref `0x140008C92`).
- Top-level route from MJ_DEVICE_CONTROL to `FUN_140004f20`, and any `MmGetSystemRoutineAddress` dynamic lookups.
- Device-interface ACL (INF/registration) — decides whether any of the non-admin surface is reachable.

## VM confirmation plan (orchestrator-owned)

1. Check whether the driver reaches device start without NI PCIe-8398 hardware. If it does not, the whole surface is hardware-gated and this stays a static finding.
2. Unprivileged token: open the device interface and record the result (decides the non-admin surface).
3. **F1 test is destructive** (writes object memory via the 10th transfer). Run only in the SOLO phase per the pool-corruption protocol, with a snapshot, and never paired with other drivers.

## Evidence (REA, retained IDs)

`ev_93994fba693a0d8f69f64a8b8de9192f1167bba19e4e172441b7b8cd34fea4f6` (`FUN_140006bb0`), `ev_2637f546937e36cb778766fb273f6d4f82f9d29de4f598cea6c66b219d4f6ca2` (`FUN_140009950`), `ev_2d7af758b3091dbd18efafd4bdbba095e52865286094fcfbd132cdffec94521e` (`FUN_1400099d0`), `ev_d00c12b8439c957913e3c05a605e0dd759b2f2f30faf8ddd3d30066a97f8e81f` (`FUN_140001ff0`), `ev_242950fdc2dd510b46b700981538479bcf4772427311bbe82a9ae598fd87bdcf` (`FUN_1400046e0`), `ev_390b59e67852b75ea808bc7158eafed18148a09c89889927367a56e5607f6ebe` (`FUN_140004a00`), `ev_569294728af7094aea4e99e4615286099fd938fdc524b2e8dd14350194d93fa3` (`FUN_1400040d0`), `ev_a5d9e91f1ed9ac4e4b4eeeb63769bd5bba0ef6d53e1e6f476686eb4f816120b6` (`FUN_140006e50`), `ev_cd7fffca6afbdd1b40d613d423108d7280676be4b9dddc43316ffa4283faa9fc` (`FUN_140005430`), `ev_2af7044dc149a951dca9cd3e19af9e622aee1a729c33b6254d0517cad074e57e` (`FUN_140003820`), `ev_750d1aa3297e936c7b15c757b294ad0fe5ea55e5a4cb7af58c335630c332633e` (`FUN_1400056f0`), `ev_6e64c39baf713415d6c3957246e1e594f94f4c0b39174eb80a49fb834ec0fe47` (`FUN_140002710`), `ev_d8fabd62a528ac320a07008617dfe40bf4c55206808db867ac6081c2a431542f` (`FUN_140003060`), `ev_e6c302ceb9a335b56adb9f980d285ea3be8284a663e8db7f04f899c6dcf412a5` (`FUN_140005250`), `ev_899d164bcaee92080c42404f7a40f02152d1a438b8d3ad310b610c792a113201` (`FUN_140005150`), `ev_92c340599a8d28efade42528640b3f77c77176b3b81102ba915b436c5404aea6` (`FUN_140005020`), `ev_69da0cf2faf839ca5534c667e694ba0d2bfb2c0792bb1e22dd65b6232ce30716` (`FUN_140004f20`), `ev_9e19f82d0c2b063cb0465930cfed89c1a2d115873481ebc6cd179c6343889a1b` (`FUN_140005350`), `ev_5bfad651faed08d0c2714deb9d0e9bf0398a218a858a1920c3d8901d258ed5b2` (`FUN_140004c30`), `ev_d7c54d00d6bfe0b617b195b19c57f8577280106da05d10c079d1c5845372c1a4` (`FUN_140008900`), `ev_ac5245fd4f1bfd7cb7556bc9f3cb865ea9fe60362a97cd361765b77398f7c8ef` (`FUN_14000b2c0`), `ev_ed7e443996843137fd5520c35499ba368144ce1e64f7653ba8b9b465094b5137` / `ev_ffabde79dd92a7e18e21b935b34bc1d58b44c7598a35242a68890ffd25099e04` / `ev_6b2fd401426b37c0e73141afea9449a215f168c6b957d5225bbbdad22c1aec3d` (constant strings), `ev_155fd4da3c5750df0d3494b6c9d83d9b24814f7b8f6bdd439f7958cedeb07d0a` (ProbeForWrite xrefs), `ev_42f645d6eb8fb5ca22bee512e97cb62c9ceedbd19b11cda3631299e3cbe5d764` (ProbeForRead xrefs), `ev_281430e3c0299ef6c56fc19efe0afd0dfb27f353ebef33590ddfb1e6c1ebf9f7` (`Mm` import sweep), `ev_67d8ef9da285ad7353a28043554a83952081e4ad73704393beb3f3db5c66d2ba` (MmAllocatePagesForMdl xrefs).
