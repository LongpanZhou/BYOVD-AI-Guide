# MSI RTCore32 `1E0A3CF8` - further static audit (admin-reachable vulnerabilities)

Addendum to `msi_rtcore.static.md`. Date: 2026-10-24. Scope: the whole RTCore32 image (70 functions, dump `scratchpad\dumps\rtcore32_1e0a_full.txt`), with the question "any unauthenticated read/write, and any vulnerability reachable with admin rights".

Method: static only. Ghidra 12.1.4 decompile (no decompile failures). Dispatcher `FUN_0001148e` read in full. Nothing loaded, installed, or executed. Descriptions are gate-level; no test code or operating steps.

## 1. Answer to the question

- **Unauthenticated (standard-user) read/write: none found.** The device DACL (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`, set at `FUN_0001192e` @ `0x1192e`) is the only access check. The create and close handlers are the same dispatcher, which completes the request as success for any major function other than DEVICE_CONTROL. No IOCTL does its own caller check. Result depends on the DACL being applied as written (see section 6, not traced).
- **Admin-reachable findings:** four confirmed gate defects, one unconditional kernel call that needs a follow-up test, and one bounds-check defect. Details below.

## 2. Verdicts (all `-BLOCKED`: the DACL is admin-only)

| # | Class | Finding | Verdict | Change from earlier report |
|---|---|---|---|---|
| F1 | PORT | Port-write BAR carve-out in `FUN_0001145a` @ `0x1145a` tests only port `0xCFC`. Ports `0xCFD`-`0xCFF` are not checked. | WRITE-PORT-HIGH-BLOCKED | Earlier report called the carve-out "narrow". It does not protect BAR registers against byte-lane port writes. |
| F2 | PORT (PCI config, HAL path) | `0x80002054` offset filter checks the start offset only; width 1, 2, or 4 is accepted. Start offsets `0x0D`-`0x0F` with width >= 2 span into BAR0. | WRITE-PORT-MEDIUM-BLOCKED, overlap NEEDS-DYNAMIC | New. |
| F3 | KVA (stale mapping) | `0x80002044` calls `MmUnmapIoSpace(input+8, input+0x10)` before the ownership check in `FUN_0001108a` @ `0x1108a`. The table slot is cleared only when slot index, VA, and size all match. A stale slot still validates in `FUN_000110d6`, so later read or write IOCTLs can reach an unmapped VA. | NEEDS-DYNAMIC (unconditional unmap confirmed statically; use-after-unmap write unproven) | New. |
| F4 | Corruption, not write | `FUN_000110d6` @ `0x110d6` adds `offset + width` in 32 bits and compares to size. Wrapped offsets near `0xFFFFFFFF` pass, so the access lands 1-3 bytes below the mapping VA. Fixed relative address, controlled value, unknown target. | Corruption, not write (target NEEDS-DYNAMIC) | New. |
| F5 | PORT (MSR) | MSR write denylist `FUN_00011120` @ `0x11120` denies `0x174-0x176` and `0xC0000080-0xC0000084` only. `IA32_FS_BASE` `0xC0000100`, `IA32_GS_BASE` `0xC0000101`, `IA32_KERNEL_GS_BASE` `0xC0000102`, MTRR, and PAT are not denied. | WRITE-PORT-MEDIUM-BLOCKED (per the brief's scale, a denylist is constrained) | Earlier report said the same MEDIUM. The per-CPU base MSRs are the reason the impact is high. |
| F6 | PHYS (window) | `FUN_00011190` @ `0x11190` BAR branch reads only the low dword of the BAR and does not check the 64-bit type bits (2:1). For a 64-bit memory BAR whose low dword is below `0x1000000`, the 16 MB window becomes physical `[0, 16 MB)`, which covers low system RAM. | WRITE-PHYS-MEDIUM-BLOCKED | Earlier report described the window as "a display BAR". For 64-bit BARs the window is not the device's BAR. |

Correction to the earlier report: the mapping check in `FUN_000110d6` is against the mapping VA the caller echoes back (`input+8`, `input+0xC`), not "the stored physical base". The table is keyed by VA, set in `FUN_000113de` @ `0x113de` before `FUN_0001103c` records the slot.

## 3. Evidence

**F1 - port write carve-out.** Dispatcher branches `0x80002014`, `0x80002018`, and `0x8000201C` call `FUN_0001145a(port)` and then `out(port, value)`. `FUN_0001145a` returns deny only when `port == 0xcfc` and CF8 bit 31 is set and the CF8 register is in `0x10-0x27`. Any other port returns allow. The check is on the port number, not the config-data lane.

**F2 - PCI config offset.** Dispatcher `0x80002054`: `width = puVar2[4]` must be 1, 2, or 4; `offset = puVar2[3]` must satisfy `offset < 0x10 || offset > 0x27`. The width is not added to the offset. `HalSetBusDataByOffset(4, bus, slot, value, offset, width)`. Whether the HAL honors an unaligned multi-byte write that spans into BAR0 is not verified (section 6).

**F3 - stale mapping.** Dispatcher `0x80002044`: when `input+8 | input+0xC != 0` and length is `0x30`, the code calls `MmUnmapIoSpace(input+8, input+0x10)` unconditionally. `FUN_0001108a` then clears table slot `input+0x2c` only if `table[slot].key == (input+8, input+0xC)` and `table[slot].size == input+0x10`. `FUN_000110d6` (used by `0x80002048` read and `0x8000204C` write) checks slot index `< 0x100`, key match, and `offset + width <= size`. It does not check that the mapping is still live. Result: an unmap call that does not clear the slot leaves a slot that later read and write calls accept.

**F4 - 32-bit bounds wrap.** `FUN_000110d6`: `(uint)(*(int*)(p+0x18) + *(int*)(p+0x14)) <= size`. For width 4 and offset `0xFFFFFFFC`-`0xFFFFFFFF`, the sum wraps to `0`-`3`, which is `<= size`. The access `VA + offset` lands `VA-4`-`VA-1`. Decompile is 32-bit (x86 build, DriverObject offsets confirm).

**F5 - MSR denylist.** `FUN_00011120`: `(p - 0x174) < 3` denies; `(p - 0xC0000080) <= 4` denies; otherwise allow. The MSR write branch `0x80002034` calls `wrmsr(index, value)` with the value from input. No other check.

**F6 - 64-bit BAR.** `FUN_00011190`: BAR branch reads `HalGetBusDataByOffset(4, bus, slot, &local_8, 0x10 + 4*BAR, 4)`. Checks: `local_8 != 0xFFFFFFFF`, `local_8 != 0`, `(local_8 & 1) == 0`. Window: `FUN_0001114c(base, len, local_8 & 0xFFFFFF00, 0x1000000)`. Bits 2:1 are not checked and the high dword is not read. Decompiler artifact noted: `HalGetBusDataByOffset` writes into the parameter's stack slot in the decompile, but the code keeps a copy in `puVar1` and uses that copy, so this is not a defect.

**F3 follow-on (section path, `0x80002000`).** Maps the same physical window into the caller's process (`ZwMapViewOfSection`, current process). Same gate `FUN_00011190`. No separate defect found.

## 4. Callback and IOCTL table (changes from the earlier table)

| IOCTL | Operation | Gate | Verdict |
|---|---|---|---|
| `0x80002000` | map section to caller process | `FUN_00011190` | (PHYS, F6) |
| `0x80002004` | unmap section view | none (process = current) | n/a |
| `0x80002008/200C/2010` | in byte/word/dword | none | READ-PORT |
| `0x80002014/2018/201C` | out byte/word/dword | `FUN_0001145a` (port == 0xCFC only) | WRITE-PORT-HIGH-BLOCKED (F1) |
| `0x80002028` | status | none | n/a |
| `0x8000202C` | accumulator | none | not a device write |
| `0x80002030` | rdmsr | `FUN_00011120` | READ-PORT (denylist) |
| `0x80002034` | wrmsr | `FUN_00011120` | WRITE-PORT-MEDIUM-BLOCKED (F5) |
| `0x80002040` | map physical range | `FUN_000113de` -> `FUN_00011190` | (PHYS, F6) |
| `0x80002044` | **unmap (unconditional `MmUnmapIoSpace`)** | slot clear only in `FUN_0001108a` | NEEDS-DYNAMIC (F3) |
| `0x80002048` | read through mapping | `FUN_000110d6` | READ (F4 bounds) |
| `0x8000204C` | write through mapping | `FUN_000110d6` | WRITE-PHYS-MEDIUM-BLOCKED; F4 bounds |
| `0x80002050` | PCI config read | none (any bus/slot) | READ-PORT |
| `0x80002054` | PCI config write | offset start-only filter | WRITE-PORT-MEDIUM-BLOCKED (F2) |

## 5. Corruption, not write

- F4: 1-3 bytes below the mapping VA, controlled value, target not named. Per the brief, reported here.
- F3 stale slot: a write through a stale mapping lands wherever the kernel has reused the VA. Target unknown until tested.

## 6. Not traced

- **DACL application.** `_WdmlibIoCreateDeviceSecure@36` (`0x14064`) and the `_SepSddl*` parser (`0x147b3`-`0x14ea5`) were not reviewed. The admin-only result assumes the literal is applied as written.
- **DriverUnload** at `LAB_00011006` (`+0x34`): not reviewed. Unknown whether tracked mappings are unmapped on unload.
- **HAL behavior** for unaligned multi-byte PCI config writes (F2).
- **OS behavior** of `MmMapIoSpace` on the low-16 MB range (F6) and of `MmUnmapIoSpace` on a VA not owned by the caller (F3).
- **Kernel VA reuse** after an unmap (F3 target).
- **CRT and SEH helpers** (`__except_handler4`, `_Rtl*`, `_Cm*`): not reviewed; not on the read/write path.
- Nothing run dynamically. RTCore32 is not installed on this host (`sc query RTCore32`: service does not exist).

## 7. Host exposure (read-only check)

- RTCore32 is not installed: `sc query RTCore32` returns "service does not exist".
- `Win32_DeviceMemoryAddress` lists no range at or above 4 GB. Display-class ranges here are 32-bit (`0xE0000000-0xF1FFFFFF`). F6's 64-bit condition is not visible in the resource list. Resizable BAR could still change this; not verified.

## 8. Next dynamic test (described, not run; lab VM only, never on the host)

1. **DACL (existing test):** `CreateFile("\\\\.\\RTCore32")` from a standard-user token should return `0xC0000022`. If it succeeds, every BLOCKED verdict above must be reopened.
2. **F3 stale slot:** with a kernel debugger attached, confirm whether `MmUnmapIoSpace` runs before the table check, and whether a slot whose size no longer matches the unmap call stays live. Observe the status returned and the page state. Do not write through the stale mapping outside the VM.
3. **F1 byte lanes:** breakpoint at `FUN_0001145a` and confirm the return value for port `0xCFD` with CF8 pointing at a BAR register. Observe only.
4. **F2 overlap:** on a lab device, confirm whether `HalSetBusDataByOffset` with start offset `0x0E` and width 4 modifies BAR0 bytes `0x10-0x11`.
5. **F6 window:** on a VM with a 64-bit memory BAR, read the BAR low dword (read-only) and compare with the window FUN_00011190 computes.
6. **F5 MSR:** not tested on any machine. A write to `IA32_GS_BASE` or `IA32_KERNEL_GS_BASE` is expected to crash the VM.

## 9. Updated NO-WRITE / unauth reason

No standard-user path found. The DACL is the only gate and is admin-only as written (not yet tested). All write-capable paths require admin.
