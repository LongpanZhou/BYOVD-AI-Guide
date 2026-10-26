# Audit: vmusb.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\vmusb.sys` |
| Recorded SHA-256 | `8167B314EC353627F7FD635A300D817EEBEE80E4AA92D0510AA8CB8029E48CF6` (matches triage_index.csv row `vmusb`; sha256 recomputed in-session) |
| Company/Version | VMware, Inc. (VMware USB arbitrator; PDB `vmusb.pdb`) |
| Method | Static-only audit via REA/Ghidra 12.1.4, memory-write scope only |
| Verdict | **WRITE-MEDIUM (provisional)** — a header-driven write into a fixed-size request object on the MJ_WRITE path; overflow only if the pool stride is smaller than the device-capped table. Pool init not decompiled. Reachability (device DACL, pipe open) not established |
| Coverage | ~50%. Not traced: pool init that sets stride `*(pool+0x14)` and cap `*(dev+0x270)`, `FUN_140003a08` caller-side sizing, `FUN_140005418` (URB submit), `FUN_1400037dc`, `FUN_140008580` (copy routine), device SDDL and interface registration |

> **Static-only.** No load, no device open, no IOCTL execution. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- Device objects created with `IoCreateDevice` (no `IoCreateDeviceSecure` in the import list) plus `IoCreateSymbolicLink` and `IoRegisterDeviceInterface`. The device-object DACL depends on the default and on any interface SD; neither is established in-file.
- Memory-related imports: `MmMapLockedPagesSpecifyCache` (3 xrefs; 2 real call sites), `MmIsDriverVerifying`. **No** `ProbeForRead`, `ProbeForWrite`, `MmProbeAndLockPages`, `MmMapIoSpace`, `IoAllocateMdl` in the import table.
- `MmMapLockedPagesSpecifyCache` call sites: `FUN_140002490` (`0x140002524`) and `FUN_140003570` (`0x1400035ce`).

## Request path (write-relevant)

- `FUN_1400033e0` (IRP dispatch for transfers): device-state checks (`+0x28c`), pipe checks (`lVar5+0x10`), endpoint-type switch (`lVar6+0x24`). For any non-READ major (MJ_WRITE is 4) with the endpoint flag bit clear it passes `cVar9 = 0` (copy-in) into `FUN_140003570`; READ (major 3) passes `cVar9 = 1` when the bit is set.
- `FUN_140003570` (`0x140003570`, transfer header parser):
  1. Maps the IRP's MDL (`IRP+8`) with `MmMapLockedPagesSpecifyCache` if not already mapped (`mdl+0x0a & 5 == 0`), else uses `mdl+0x18`. The MDL is the I/O manager's locked user buffer for direct I/O.
  2. Reads header: `count = *(uint*)hdr`; requires `count != 0` and `count*12 + 0x10 <= param_4`; requires `count <= *(uint*)(dev+0x270)` (device cap).
  3. Allocates a request object `plVar5 = FUN_140003cec(dev+0x1d8)` from a fixed-stride free list, and a page-rounded data buffer `FUN_140003a08(dev+0x210, uVar9)` with `uVar9 = param_4 - hdr.offset0`.
  4. **Copy-in before validation:** when `param_5 == 0`, `FUN_140008580(dataBuf, hdr + offset0, uVar9)` runs **before** the per-entry bounds check.
  5. Writes fixed fields into the request object (offsets `+0x28`, `+0x60`, `+0x68`, `+0x6c`, `+0x70`, `+0xC8`, `+0xCC`), then the entry table in a loop: for each entry `i < count`, writes two dwords at `body + 0xC4 + 12·i` and `body + 0xC8 + 12·i` with values `(entry.offset - offset0)` and `entry.length`. Bounds check per entry (`offset + length <= param_4`; for non-kernel callers also `maxPacket >= length`) occurs **inside** the loop, after the copy.

## Memory-write analysis

| Pattern | Result | Evidence |
|---|---|---|
| Header-driven table write into request object | **PRESENT (conditional).** Writes at `body+0xC4+12i` / `+0xC8+12i`, `i < count`, `count <= dev+0x270`. Values attacker-chosen. Safe **iff** pool stride `S = *(pool+0x14)` satisfies `S >= 0xCC + 12*(cap-1)`. Pool init that sets `S` and `cap` is not decompiled | `ev_0634c577…`, `ev_1c8b5bdb…`, `ev_2298de12…` |
| Request-object stride | `FUN_140003bb0` refill: slot stride `*(pool+0x14) + 8`; block size `(stride)*n + 0x10`; slot count from pool `+0x28`/`+0x2c`/`+0x30`/`+0x34` | `ev_2298de12…` |
| Copy before validation | `FUN_140008580(dst, hdr+offset0, param_4 - offset0)` before entry check. If `offset0 > param_4`, the length wraps and the source read runs past the MDL mapping (read-side OOB; page-granular allocation limits the write side). Read-only issue; not a write | `ev_1c8b5bdb…` |
| Kernel address write from user input | None found. Only the header-chosen values are written, and only to the request object or the allocated data buffer | — |
| MJ_WRITE vs MJ_READ | Write-direction copy-in (`param_5 == 0`) is the path reachable by MJ_WRITE; read-direction (`param_5 == 1`) skips the copy | `ev_c53febce…` |
| Probe on user-mode data | None in-file. Relies on I/O manager direct I/O (locked MDL). The MDL map helper (`FUN_140002490`, `FUN_140003570`) uses `MmMapLockedPagesSpecifyCache` without a `ProbeFor*` call | import sweep |

## Entry/cap constants used

- Device cap `dev+0x270` (max table entries). Source not decompiled.
- Request pool `dev+0x1d8` (free list), data pool `dev+0x210`. Stride at `pool+0x14`.

## Findings

1. **Candidate heap write (WRITE-MEDIUM, provisional).** A user-controlled header can drive 8-byte writes to `body + 0xC4 + 12·i`. If the request-object stride is smaller than `0xCC + 12·(cap−1)`, these writes overflow the slot into neighbouring pool slots, with attacker-chosen values. Whether that happens is decided by the pool init, which is not yet decompiled.
2. **Copy-before-validate** on the copy-in path (read-side OOB via length wrap). Noted for completeness; not a write.
3. **Reachability unknown.** MJ_WRITE needs an open pipe with the expected endpoint type, plus device access. The device DACL and the pipe-open IOCTL are not traced.

## Verdict rationale

WRITE-MEDIUM (provisional). The write is real in the code path, but its bounds depend on a pool-stride/cap relationship that is not verified, and the path needs device access plus an open pipe. Escalate to **WRITE-HIGH** if (a) pool init sets `S < 0xCC + 12·(cap−1)`, and (b) the device is openable by an unprivileged caller and the pipe can be opened without privilege. Drop to **NO-WRITE** if pool init sets `S >= 0xCC + 12·cap`.

## Next steps (for the write-only pass)

- Decompile the pool init that writes `*(dev+0x1ec)` (the stride at `dev+0x1d8+0x14`) and `*(dev+0x270)` (the cap).
- Decompile `FUN_140008580` (copy routine) and `FUN_1400037dc` (sibling path).
- Trace the pipe-open IOCTL and the device SDDL / interface SD to settle reachability.

## VM confirmation plan (orchestrator-owned; non-destructive)

1. Unprivileged token: open the device and record whether access is denied (`ERROR_ACCESS_DENIED`).
2. If it opens: open a pipe with the expected endpoint type, then issue a write with a header whose `count` is at the cap and whose `offset0` leaves a small data window. Observe with a non-destructive pool-tag check (no bugcheck planned in this round).
3. Decisive overflow test (solo, snapshot-restore) is out of scope for this round.

## Evidence (REA, retained IDs)

`ev_0634c5771eb7340f0b7db7a7dd156f9ad1543399e3aba5c57bec6f803f9e8e81` (`FUN_140002490`), `ev_1c8b5bdb370e365fdc5805c54e3c8d9747479ef62b9697845b7cdecd73d3acfe` (`FUN_140003570`), `ev_c53febce9f74841ee57f41fdea7e523511ff809d21beedd3c6c17486b7786872` (`FUN_1400033e0`), `ev_f877e594cf33567e47ed82231444b47990b2e74d04a1e804eb9dd6140222d9d0` (`FUN_140003a08`), `ev_5927f1d335242d7e3c70630169d7ff95203be00bbadc6e93044224137b789009` (`FUN_140003cec`), `ev_2298de12569f55fec88b2e6458f95c59fade1bc8e1868403824c130d69129597` (`FUN_140003bb0`), `ev_d2131a8f453e28fc6dcb7afb1f9ff0cf609e2fd4c007187e87c9b7d9fef72d79` (callers of `FUN_140003570`).
