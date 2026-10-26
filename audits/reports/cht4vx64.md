# Audit: cht4vx64.sys (triage name `cht4vbd`)

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\cht4vx64.sys` |
| Recorded SHA-256 | `83E2C81274DDBE695EF845E541F7A2DB60EF5E195AE14FACDEEEBD30C0EF4E67` (matches triage_index.csv row 28; verified before opening; REA reports the same digest) |
| Company/Version | Chelsio Communications, 6.11.4.100 (triage row). KMDF driver (`WDFLDR.SYS` bind imports); PCIe adapter function with BAR mapping; PDB `cht4vx64.pdb` |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, short-form |
| Verdict | **NO-WRITE (coverage-limited, ~40%)** — the only MMIO mapping takes its address and length from the PnP resource list; no caller-controlled kernel write found in the traced set |
| Coverage | Import recon; the single `MmMapIoSpaceEx` site and its unmap; both dynamic lookups; the four WDF callbacks registered in device init; thunk xrefs for the three imported routines. Not traced: the WDF request-queue configuration (no `EvtIoDeviceControl` routine located), the device-interface creation, and the MMIO register accessors that use the mapped BAR |

> **Static-only.** No load, no device open, no IOCTL issued. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- No `IoCreateDevice`, `IoCreateDeviceSecure`, or `IoCreateSymbolicLink` in the import table. The device is created through the WDF function table, so the device name and interface are not visible by import.
- No SDDL string (search for `(A;` is empty). No `ProbeFor*`, no `MmProbeAndLockPages`, no `MmMapLockedPagesSpecifyCache`.
- Imports of note: `MmMapIoSpaceEx` (2 xrefs), `MmUnmapIoSpace` (3 xrefs), `MmGetSystemRoutineAddress` (3 xrefs), `IoAllocateErrorLogEntry` / `IoWriteErrorLogEntry`.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| MMIO mapping | One call site (`0x140066250`, in `FUN_140066140`); the import thunk at `0x140034248` has no other callers. Address and length come from the PnP resource list (`DAT_140061048+0x988` enumerator), not from caller input. At most two BARs are mapped (`uVar5 < 2`); stored at device context `+0x780` / `+0x798` | `ev_1f059b1b…` (resolve), `ev_f87fe50c…` (`FUN_140066140`), `ev_aa7dea4f…` (thunk xrefs), `ev_915bcebf…` (xrefs) |
| MMIO unmap | Two call sites in `FUN_1400663AC`, freeing the stored `+0x780` / `+0x798` mappings and their lengths; no caller input | `ev_097d7d16…`, `ev_169bcf01…`, `ev_dd5c6986…` |
| Pool allocation sized by a routine's output | `FUN_140002BE8` allocates the `KeQueryLogicalProcessorRelationship` output size (returned by the routine, not the caller) and frees it on all paths | `ev_4501d19b…` |
| Pool allocation with fixed size and bounded loop | `FUN_1400641B0` allocates `0xAA0` and writes eight-byte function pointers at a `0x10` stride up to `0xAA0`; the last write ends at `0xA98` | `ev_e5733e02…` |
| WDF callbacks | `FUN_14000F580`, `FUN_14000F4E0`, `FUN_14000F750`, `FUN_14000F650` operate on the device context with fixed offsets and constants. `FUN_14000F750` logs and zeroes five fixed `0xB0` records. None takes a caller-supplied address or length | `ev_b274d678…`, `ev_5a4ba079…`, `ev_83f1c5d4…`, `ev_faf1fb50…` |
| Dynamic routine resolution | `IoGetDeviceNumaNode` (in `FUN_1400641B0`) and `KeQueryLogicalProcessorRelationship` (in `FUN_140002BE8`). Both names are read from `UNICODE_STRING` literals. No mapping or probe routine is resolved | `ev_4501d19b…`, `ev_e5733e02…`, `ev_92771a2c…` (thunk `0x140034300`) |

## Verdict rationale

NO-WRITE. The mapping is driven entirely by PnP resources, so no caller can choose the physical address or length. The unmap path is symmetric. The four WDF callbacks found in device init do not take caller data. The overall verdict is coverage-limited because the WDF IOCTL queue (if any) and the register accessors that use the mapped BAR were not located.

Escalate to **WRITE-MEDIUM** if an `EvtIoDeviceControl` routine (not located) passes a caller-supplied offset or length to the mapped BAR region at `+0x780` / `+0x798`, or to a register-write helper. Escalate further if that routine is reachable from a non-admin handle.

## Open items

- Locate the WDF queue configuration (`WdfIoQueueCreate`) and any `EvtIoDeviceControl` routine. The WDF function-table index is not resolved in the traced set.
- Trace the MMIO accessors that take an index or offset and use the BAR VA at `+0x780` / `+0x798`.
- Device-interface creation and its ACL (not traced; the INF is not in the file).

## VM confirmation plan

Hardware-gated (Chelsio adapter). If available in the VM, record whether a non-admin handle can open the device interface and whether any IOCTL is accepted. Do not issue register writes outside the snapshot protocol.

## Evidence (REA, retained IDs)

`ev_915bcebfd576aa2483e7d3fa503ea8357df8075dd99bb546cb250e297f170a0a` (`MmMapIoSpaceEx` xrefs), `ev_dd5c6986e2d954eea4ff672e3082d1249756aecaa207cf9b3e3a3d2e96490514` (`MmUnmapIoSpace` xrefs), `ev_0f000c4bffdcf81bc8e3a2ba09f78331136e36cbda1124f8e7bdc06e45dc5b81` (`MmGetSystemRoutineAddress` xrefs), `ev_1f059b1bd2eba27ffdff5fcacd66cefe5b2a382d268bd839b9c424146d734107` (`FUN_140066140` resolve), `ev_f87fe50c304b6ab98692951e7c650d9bbec850fc37419b94bd105c2497b5bd81` (`FUN_140066140`), `ev_097d7d1613c1233e10e647dc7327dcb75cb1a858efa50b0a6682d8bd9a3ef4e9` (`FUN_1400663AC`), `ev_4501d19b6dbcf6c82fd8c9f3aba68125e00d2a250fa4391ee05fe64a34006216` (`FUN_140002BE8`), `ev_e5733e027ac912f7e0f996984dadc8102e502608a3954e155759060d05821d75` (`FUN_1400641B0`), `ev_aa7dea4f59191040e0e00993683fe6a862c10fcd2b3d2dc0b0e92f7e1b0a6c92` (xrefs of thunk `0x140034248`), `ev_169bcf0183012c8a83fb7c584514d2c9b0f7d78fe133abfa838b88f61d03bb49` (xrefs of thunk `0x140034250`), `ev_92771a2c8fa816d0cb8ca363a5c3fd803a309a167dc386f2c7f5999d06888262` (xrefs of thunk `0x140034300`), `ev_b274d6784d528a559ee85793a67601761d34cf4a867de1f699a111c25486dc93` (`FUN_14000F580`), `ev_5a4ba079ce5fbbd741d5ee4f21c261d41e660bafbf1638043fd7fc82ca5c2945` (`FUN_14000F4E0`), `ev_83f1c5d43ee50f4ad02bf41e7f38a4c9633638346cedfd359538ce228b042bb3` (`FUN_14000F750`), `ev_faf1fb50ab48b17fe78c961c1787328e4754c8fa05f86922ac67cb1b3eedb7de` (`FUN_14000F650`), `ev_782a7297e555fe0dd6f001a289d675cfe86bef93339b2c9e070b10addfdcf719` (`Mm` import sweep), `ev_fb3b91e28af286b6f1f61e23a7eac9525d77d48409d0c88f5db08188066bee88` (`Io` sweep), `ev_34ca8922bcbd5531aefc457f7aacedae7e9ce9dc80a7b1ef9ab4531e34bcb936` (`Wdf` sweep), `ev_a179c223003768951f0dd5257db14e047852784db4eca6f6e8fdc5c58b10e625` (`Probe` sweep, empty).
