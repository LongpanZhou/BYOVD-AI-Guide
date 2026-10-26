# MSI RTCore32 `6F818DAF` — admin-reachable kernel memory-write audit (static)

| Field | Value |
|---|---|
| File | `drivers/RTCore32_6F818DAF.sys` (manifest batch: collected2; previously `_collected2\drivers\MSI\RTCore32_6F818DAF.sys` (21,664 bytes, file date 2020-06-18; PE timestamp not extracted this pass)) |
| SHA-256 | `6F818DAFE2012E8312331723C26EF7B1F566D4C3F5C043053F8B94F9298BCA2A` |
| Architecture | PE32 (x86). Not loadable on x64 by itself; see Entry surface. |
| Company / version | MSI (version resource not extracted this pass) |
| Method | Static only. REA/Ghidra 12.1.4, 115 procedures, all decompiles complete. Nothing loaded, installed, or executed. |
| Reachability tier | **R2 — local administrator** (ledger §17). Setup required: **none** (service create + start; DriverEntry creates the device). |
| Verdict | **MW2** (reach=R2 setup=none write=W2 load=signed). Physical-address write constrained to display-BAR and option-ROM windows (PA-based, MW3 base), raised one level by the mapping-VA disclosure from `0x80002040`. The use-after-unmap path (F3) could raise it to MW1 if confirmed (NEEDS-DYNAMIC). The GS-base MSR write (F5) is HW-ONLY unless chained. Labels in §3–§6 use the superseded WRITE-* scale; this row governs. |
| Write quality | W2 |
| Severity | MW2 (MW1 if F3 confirmed) |

> Static-only blockquote: this report documents primitives and gates. It contains no test code, no operating steps, and no exploit. VM validation is described in §7 but was not run.

## 1. Entry surface (verified)

- `entry` @ `0x1603E` → `FUN_0001192E`: `RtlInitUnicodeString` for `\Device\RTCore32` and `\DosDevices\RTCore32`, then `_WdmlibIoCreateDeviceSecure@36` with SDDL literal `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (decompile, `FUN_0001192E`, ev_acf2dc88…). **DACL: SYSTEM and Administrators only.** Standard users cannot open the device.
- MajorFunction (x86 offsets): CREATE `+0x38`, CLOSE `+0x40`, DEVICE_CONTROL `+0x70` → `FUN_0001148E`. Non-DEVICE_CONTROL requests complete with status 0.
- `IoCreateDevice`, `IoCreateSymbolicLink`, `ZwOpenSection`, `ZwMapViewOfSection`, `ZwUnmapViewOfSection`, `MmMapIoSpace`, `MmUnmapIoSpace`, `HalTranslateBusAddress`, `HalGet/SetBusDataByOffset`, `rdmsr`/`wrmsr`/`in`/`out` (inline) are the relevant surface.
- The imported `RtlAddAccessAllowedAce` / `ZwSetSecurityObject` are library helpers (`_SepSddl*`, `_IoDevObjCreateDeviceSecure`) and are not on the device-creation path above.

**Difference from the 2024 build:** this build's DACL is the same literal, traced here. The 2024 report (`msi_rtcore32_further.static.md`) listed the DACL as "not traced". That item is now traced for this build, with the same caveat that the `_WdmlibIoCreateDeviceSecure` internals were not walked.

## 2. Admin reachability

Under R2 the DACL is **not** a barrier. Every finding below is reachable by an administrator. The earlier "-BLOCKED" labels in the 2024 report mean "blocked for standard users" and do not apply at R2.

## 3. Memory-write analysis

### 3.1 Physical-target gate `FUN_00011190` (ev_71ec3caf…)

Used by `FUN_000113DE` (`0x80002040` map), `FUN_0001124A` (`0x80002000` section map). Allows only:

1. **Option-ROM window** `[0xC0000, 0xE0000)` via `FUN_0001114C` (ev_fcb5c062…). Non-RAM.
2. **16 MB window at a memory BAR** of a PCI function with base class `0x03` (display). Bus, slot, function, and BAR index (`< 6`) come from input. Class read at config offset `0x0B`. BAR low dword must not be `0`, `0xFFFFFFFF`, or have bit 0 set. Window = `[BAR_lo & 0xFFFFFF00, +0x1000000)`.

Window check (`FUN_0001114C`): requested `[base, base+len)` must lie inside the window. Verified.

**F6 — 64-bit BAR ignored (carried from the 2024 report; confirmed in this build).** The BAR branch reads only the low dword. Bits 2:1 (BAR type) and the high dword are not checked. For a 64-bit memory BAR whose low dword is non-zero and below `0x1000000`, the window becomes physical `[low, low+16 MB)`, which covers low system RAM. Requires a display device with such a BAR; the hardware layout is not visible statically.

### 3.2 Physical map and write

- `FUN_000113DE`: `FUN_00011190` gate → `HalTranslateBusAddress(1,0,…)` → `MmMapIoSpace(translated, len, MmNonCached)`. Records mapping VA (`input+8`) and size (`input+0x10`) in table via `FUN_0001103C`.
- `0x8000204C` write: `FUN_000110D6` check (slot index `< 0x100`, VA key match, `offset+width <= size`), then `*(VA+offset) = value` with width 1/2/4.

### 3.3 F4 — 32-bit bounds wrap (corruption before the mapping) (ev_966ccccea…)

`FUN_000110D6` computes `(uint)(offset + width) <= size`. For offset `0xFFFFFFFC`–`0xFFFFFFFF` with width 4 (and smaller offsets for narrower widths), the sum wraps to a small value and the check passes. The write lands 1–4 bytes **below the mapping VA**. Value is controlled; target is the kernel VA immediately before a mapping. The mapping VA is returned to the caller by `0x80002040`. Impact depends on what occupies that VA (unmapped page → kernel fault; another mapping → corruption). **Target NEEDS-DYNAMIC.**

### 3.4 F3 — unconditional unmap and stale slot (ev_1d66a1ed…, ev_eaac24dd…)

`0x80002044` (dispatcher `FUN_0001148E`) calls `MmUnmapIoSpace(input+8, input+0x10)` **before** the ownership check, using attacker-supplied VA and size. `FUN_0001103C` records the slot: the first empty entry, keyed by the caller's VA and size, with the index written back to the caller's struct at `+0x2C`. `FUN_0001108A` clears a slot **only** when the caller's index (`input+0x2C`), VA (`input+8`), and size (`input+0x10`) all match the recorded entry. All three are caller-supplied (ev_d893a72b…, ev_d89facfa…). So an unmap call whose size differs from the recorded size leaves the slot live. `FUN_000110D6` checks only the slot key and size, not whether the mapping still exists, so `0x80002048` read and `0x8000204C` write still pass on a stale slot.

**Path confirmed statically: use-after-unmap read and write through a live slot.** Outcome NEEDS-DYNAMIC: a write lands in whatever the kernel has since reused that VA for.

Consequences:
- Caller-chosen kernel VA and size passed to `MmUnmapIoSpace` (PTE invalidation of arbitrary system VA; crash or corruption).
- Use-after-unmap read and write through a stale slot.

### 3.5 F5 — MSR write denylist (ev_ba745388…)

`FUN_00011120` denies `0x174–0x176` and `0xC0000080–0xC0000084` only. Allowed (verified): `IA32_FS_BASE` `0xC0000100`, `IA32_GS_BASE` `0xC0000101`, `IA32_KERNEL_GS_BASE` `0xC0000102`, `IA32_PAT` `0x277`, MTRR range. `0x80002034` calls `wrmsr(index, value)` with the value from input.

Writing the GS-base MSRs changes kernel per-CPU base addressing. This is a **kernel-state control primitive**, not a direct write. Whether it yields controlled kernel memory access depends on SMAP and HVCI configuration and on kernel address knowledge (the mapping VA leak in §3.2 supplies one). **NEEDS-DYNAMIC; the crash outcome is expected for most values.**

### 3.6 Non-memory paths (for completeness)

- **Port I/O** `0x80002008`–`0x8000201C`: `FUN_0001145A` denies only port `0xCFC` when CF8 bit 31 is set and the register is in `0x10–0x27`. Ports `0xCFD`–`0xCFF` are not filtered (F1). Arbitrary port `in`/`out` reaches chipset and device state. `WRITE-PORT`, not memory.
- **PCI config** `0x80002054`: bus, slot, function unrestricted; offset filter tests the start offset only (F2). Width `1/2/4` from `0x0D–0x0F` can span into BAR0 (HAL behaviour not verified). `WRITE-PORT-MEDIUM`, overlap NEEDS-DYNAMIC.

## 4. IOCTL table (dispatcher `FUN_0001148E`, ev_eaac24dd…)

| IOCTL | Operation | Gate | Admin verdict |
|---|---|---|---|
| `0x80002000` | map `\Device\PhysicalMemory` section into the caller's process (`ZwMapViewOfSection`, protect `0x204` = PAGE_READWRITE + nocache) | `FUN_00011190` (same gate) | PHYS (§3.1); user-mode R/W view of the gated window |
| `0x80002004` | unmap section view | none | n/a |
| `0x80002008/200C/2010` | in byte/word/dword | none | READ-PORT |
| `0x80002014/2018/201C` | out byte/word/dword | `FUN_0001145A` (port `0xCFC` carve-out only) | WRITE-PORT-HIGH (§3.6) |
| `0x80002028` / `0x8000202C` | status / accumulator | — | n/a |
| `0x80002030` | rdmsr | `FUN_00011120` | READ |
| `0x80002034` | wrmsr | `FUN_00011120` (denylist) | **WRITE-MSR** (F5, NEEDS-DYNAMIC) |
| `0x80002040` | map physical range | `FUN_00011190` → `MmMapIoSpace` | PHYS; VA leaked to caller |
| `0x80002044` | unmap, unconditional `MmUnmapIoSpace` | slot clear only on exact match | **F3** (NEEDS-DYNAMIC) |
| `0x80002048` | read through mapping | `FUN_000110D6` | READ; F4 bounds |
| `0x8000204C` | **write through mapping** | `FUN_000110D6` | **PHYS-MEDIUM**; F4 corruption-before-mapping |
| `0x80002050` | PCI config read | none (any bus/slot/function) | READ-PORT |
| `0x80002054` | PCI config write | start-offset filter only | WRITE-PORT-MEDIUM (F2) |

## 5. Not traced

- `_WdmlibIoCreateDeviceSecure@36` internals (DACL application): literal assumed applied as written.
- `DriverUnload` (`0x11006`, decoded from bytes): deletes the symbolic link and the device. It does not unmap tracked mappings, so mappings from `0x80002040` survive an unload. A leak, not a write path.
- HAL behaviour for unaligned PCI config writes (F2), and the result of `MmUnmapIoSpace` on a VA the caller does not own (F3 outcome).

Traced in this pass: `FUN_0001103C` (slot record), `FUN_0001108A` (slot clear), `FUN_0001124A` (section map, §4).
- `HalGetBusDataByOffset` writes into the parameter slot (`param_4._3_1_`). Same decompiler artifact as the 2024 report; the copy `puVar1` is used for the BAR read. Not a defect.

## 6. Verdict (admin scope, R2)

Admin reachability is confirmed statically. Admin already holds the rights to load a driver, so the security relevance of this driver is that it hands an admin kernel-memory access through a signed, known-vulnerable driver. That is the basis for its blocklist status.

| Finding | Rating | Basis |
|---|---|---|
| Physical write, display BAR / option-ROM window | **WRITE-PHYS-MEDIUM** (statically confirmed) | §3.1, §3.2 |
| F6 widening to low RAM (64-bit BAR) | **Conditional HIGH** on qualifying hardware | §3.1 F6 |
| F4 write before a mapping | **WRITE-MEDIUM** (target NEEDS-DYNAMIC) | §3.3 |
| F3 unconditional unmap with live stale slot (use-after-unmap) | **Path confirmed statically; outcome NEEDS-DYNAMIC.** HIGH if the stale write lands in a reused kernel page | §3.4 |
| F5 GS-base MSR write | **NEEDS-DYNAMIC**; would be HIGH if confirmed as kernel access | §3.5 |
| Port / PCI config | WRITE-PORT-HIGH / MEDIUM (hardware) | §3.6 |

**Overall: MW2 under SEVERITY.md (reach=R2 setup=none write=W2 load=signed).** The F3 use-after-unmap path (NEEDS-DYNAMIC) would raise it to MW1 if confirmed. The F5 GS-base write is HW-ONLY unless chained. The WRITE-* labels elsewhere in this report are superseded. The 2024 build (`1E0A3CF8`) has the same gates per `msi_rtcore32_further.static.md`; its admin-reachable findings apply unchanged.

## 7. Confirmation plan (described only; not run; lab VM only, never the host)

1. **F3 and F4:** with a kernel debugger attached, observe whether a stale slot survives an unmap call that does not match the slot, and what the status and page state are afterwards. Do not write through a stale or unmapped VA outside the VM.
2. **F5:** observe the outcome of a `wrmsr` to `IA32_KERNEL_GS_BASE` with a value the lab controls. Expected: crash for most values. Record SMAP and HVCI state.
3. **F6:** on a VM with a display device that has a 64-bit memory BAR, read the BAR low dword (read-only) and compare with the window computed by `FUN_00011190`.
4. **DACL:** `CreateFile("\\\\.\\RTCore32")` from a standard-user token should return `0xC0000022`. This confirms the R1 result only; R2 is unaffected.

## 8. Limitations

- Static analysis of one build. Procedure names are Ghidra-recovered.
- Nothing run dynamically. RTCore32 is not installed on this host (`msi_rtcore32_further.static.md` §7).
- Blocklist status is taken from the ledger and the playbook; not re-checked against the Microsoft list in this pass.
