# Audit: bxvbda.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\bxvbda.sys` |
| Recorded SHA-256 | `FEB2771428706126FEA1CC9A50EBE3CF4F8E8FB6FCB3CA19996497CA44FDAC45` (verified vs triage_index.csv, service `b06bdrv`; Ghidra import digest matched) |
| Company/Version | QLogic Corporation 7.12.31.105 - "B06BDRV" client roles: DIAG/NDIS/iSCSI/WSD Client For QLogic 10 Gigabit Ethernet |
| Method | Static-only audit via LOCAL Ghidra 12.1.4 headless (Agent-D-validated fallback; REA shared bridge contended - 3 mis-served/timeout results discarded, digest-verified). Full 595-function decompile + complete 306-string inventory + complete import (71) inventory + byte-pattern sweep |
| Verdict | **WRITE-HIGH** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000`. Coverage: complete strings/imports/all 595 procs decompiled; per-path line-by-line review of the IOCTL dispatch (FUN_14000479c, ~800 src lines) + key helpers; sampled (not exhaustively line-read): FUN_140005c00/140005dac/140005ea8/140006b08/140006708/140006f78/140007194/1400072f0.

## Entry surface

- KMDF **virtual bus driver** for QLogic/BCM 10GbE (service `b06bdrv`): bootstrap `FUN_140001000` (WdfVersionBind -> WdfDriverCreate, `EvtDriverDeviceAdd = FUN_140001228`); EvtDeviceAdd creates an **unnamed FDO** (no name/SDDL string anywhere; context 0x9380, tag "FDOx"), registers a **device interface** (`+0x268` = WdfDeviceCreateDeviceInterface, GUID const at `.rdata 0x1400372e0`; separate GUID string `{2AF67184-48D3-4e8e-A3FF-969EFF740ED2}` at `0x140034e20`), and creates a **default sequential queue with EvtIoDeviceControl = `FUN_1400017a8` -> `FUN_14000479c`**.
- No `IoCreateDevice*` import; no `\Device\<name>`/`\DosDevices\` string of its own; **no SDDL string** -> interface reachability governed by the OS default device DACL (worst case per winmad.md convention: unprivileged open succeeds; FILE_ANY_ACCESS codes need no specific access right).
- File-create callback `FUN_1400019e4`: **no caller-identity/privilege check** (only per-file open-mode bookkeeping).
- Only user-openable command plane of its own = this IOCTL kit (device type `0x8000`, FILE_ANY_ACCESS, METHOD_BUFFERED); child PDOs (DIAG/L2ND/L4SC/L5WSD) belong to client drivers.

## Memory-write analysis

- **IOCTL `0x80002024` - uncapped MMIO write (kernel-VA OOB):** in-16 B `{u32 offset (4-aligned), u32 count, u32 data[]}`; guard = count!=0, `count*4 <= inLen-0xc` (caller's own buffer), `offset&3==0`; then `FUN_14000479c` loop (decomp `ALL 3095-3119`) writes `*(u32*)(BAR_base + offset) = value` per dword where `BAR_base = *(ctx+0x38)` is the MmMapIoSpaceEx-mapped register BAR (`FUN_14001e1f8`, mapping length = PCI BAR size clamped <= 0x400000). **Unlike sibling `0x8000201C` (which splits at offset < 0x8000 direct / >= 0x8000 into indirect window `FUN_140032854`), the 0x80002024 loop has NO window split and NO upper offset bound** -> any dword-aligned 32-bit offset (up to +0xFFFFFFFC from the BAR VA) with fully attacker-chosen value. Offsets beyond the BAR mapping write into adjacent/unmapped kernel VA => **controlled kernel OOB write (attacker location within ~4 GB window above a fixed kernel VA + attacker value)**. Attacker value+indexxsize pattern confirmed in decompile; no Se*/mode checks anywhere on the path.
- **`0x80002020`** - same read kit variant, loop (ALL 3051-3058) reads `*(u32*)(BAR_base + offset)` with the same **uncapped offset** (kernel OOB read; out-bounds check `outLen >= count*4` only bounds the return copy).
- **Bounded siblings (contrast, all METHOD_BUFFERED/ANY):** `0x80002018`/`0x8000201C` (window-split read/write kit: direct < 0x8000, else indirect reg-window `FUN_140032854` = offset->BAR+0x78, value->BAR+0x80 - device-space only), `0x80002014` (per-element `FUN_14002facc`, `start+count < 0x21` bound), `0x80002078` (`idx < 4`), `0x80002074/50/70` (exact fixed sizes), `0x80002060/64/68/6c` (in/out exact-checked), `0x80002054->FUN_14000650c` (max write 0x1c < min 0x1e), `0x80002094->FUN_14000681c` (exact 0x44 fit), `0x80002090->FUN_1400068f8` (memset(0,param_3) length-bounded; fixed writes <= 0xd5), `0x80002084/88->FUN_140006b08/140006708` (length-passed snapshots), `0x80002098` (1-byte write at `ctx+0x16be8 + b*0x1e8`, b byte-truncated; extension >= 0xe3200 => in-bounds).
- **`0x8000208C->FUN_140006ddc` (min out 0xd19):** fixed head <= 7, per-entry loop writes `entry_i x 0x150` (fields to +0x60) from a driver-internal port list + fixed tail at 0xa88..0xd19. Layout implies <= 7 entries (entry 7 slot would collide with the tail at 0xa88) - bounded **by adapter design margin**, OOB only if the hardware enumerates >= 8 ports; list length is not attacker-influenced. Residual design-margin note, not an unpriv primitive.
- **`\Device\PhysicalMemory` (string `0x1400367e0`):** `FUN_140033fc4` (parameterless, single caller `FUN_140001000` at DriverEntry -> cached `DAT_140081968`) opens `\Device\PhysicalMemory` with OBJ_KERNEL_HANDLE, maps **fixed physical address 0x80000, fixed length 0x80000** (BIOS/DMI region), scans for the iBFT/SMBIOS entry-point (`FUN_140033e34`), copies the table via right-sized `memcpy_s` into an `ExAllocatePoolWithTag` buffer (tag `iFBT`/`iBFT`), unmaps. **No attacker-influenced address or length; driver never writes the view; not reachable from any dispatch** - an init-time firmware-table read, not a primitive.
- **Mm\* imports:** MmMapIoSpaceEx only on PCI-BAR/boot-derived addresses (kernel-initiated; two sites above), MmUnmapIoSpace, MmGetSystemRoutineAddress (dynamic Ke*/IoGet/SetDevicePropertyData resolution - explains zero direct xrefs on dynamically resolved imports). No MmCopyMemory/MmMapLockedPages/MmProbe*/ZwMapViewOfSection-of-caller-MDL/Se* anywhere.
- **No MSR/GDT/IDT:** byte-pattern sweep = **WRMSR 0, RDMSR 0, SGDT 0, LGDT 0, LIDT 0** (in/out/doorbell port I/O n=0 in swept immediate form; device access is MMIO).
- Secondary (out of round-2 scope, noted): `0x80002050` returns the kernel adapter-context pointer (kernel-address disclosure); the register kit `0x8000201C`/`0x80002014` lets an unprivileged writer reprogram NIC device registers/DMA descriptors (device-integrity; escalation would require hardware-specific DMA-target knowledge).

## Memory-touching IOCTL table

| Code | Fn | Method | Path | Kernel write | Check |
|---|---|---|---|---|---|
| `0x80002024` | 0x809 | BUFFERED, ANY | `FUN_14000479c` ALL 3095-3119 | **BAR_base + attacker offset (any 4-aligned u32), attacker value** | offset **UNCAPPED** [ ] |
| `0x80002020` | 0x808 | BUFFERED, ANY | `FUN_14000479c` ALL 3051-3058 | (OOB read, same uncapped offset) | offset **UNCAPPED** [ ] |
| `0x8000201C` | 0x807 | BUFFERED, ANY | `FUN_14000479c` ALL 3062-3090 | BAR+offset < 0x8000 / indirect window | offset&3, inLen-bound [x] |
| `0x80002018` | 0x806 | BUFFERED, ANY | `FUN_14000479c` ALL 2986-3023 | (read kit, window-split) | `< 0x8000`, out>=n*4 [x] |
| `0x80002014` | 0x805 | BUFFERED, ANY | `FUN_14002facc` xn | table[idx] write | `start+count < 0x21` [x] |
| `0x80002010` | 0x804 | BUFFERED, ANY | `FUN_140006f78` | cmd-queue write (internal) | sampled [x] |
| `0x8000208C` | 0x823 | BUFFERED, ANY | `FUN_140006ddc` | port-list x 0x150 + fixed tail <= 0xd19 | design-margin (<=7 ports) |
| `0x80002094` | 0x825 | BUFFERED, ANY | `FUN_14000681c` | fixed 0x44 | exact fit [x] |
| `0x80002098` | 0x826 | BUFFERED, ANY | `FUN_14000479c` ALL 1393-1408 | 1 B @ ctx+0x16be8+b*0x1e8 | b <= 255, in-bounds [x] |
| `0x80002050/54/60/64/68/6c/70/74/78/84/88/90` | ... | BUFFERED, ANY | fixed-field getters + FUN_140005*/140006*/140007* helpers | bounded fixed writes / out-bound copies | min/exact checks [x] |

(`Fn = (code>>2)&0xFFF`; none of the sampled helpers passes caller length into an unchecked fill; `0x80002050` additionally leaks the kernel context pointer.)

## Verdict + VM confirmation plan

**WRITE-HIGH.** The device interface on the unnamed bus FDO is reachable worst-case by an unprivileged user (default DACL, FILE_ANY_ACCESS codes), and IOCTL **`0x80002024` performs a fully attacker-controlled DWORD write at any dword-aligned 32-bit offset from the mapped register-BAR kernel VA with no window/upper-bound check** (its sibling `0x8000201C` shows the intended 0x8000 window mechanism that this code path omits). Offsets inside the BAR stay in device MMIO (device-integrity abuse); offsets beyond the mapped BAR length are a controlled kernel-VA OOB write - an unprivileged local kernel memory-write primitive. `0x80002020` is the matching uncapped OOB read. No arbitrary absolute-64-bit write, no physmem/MDL/MSR/GDT primitive found.

VM plan (orchestrator-owned, describe only; hardware-conditional - runs only with a QLogic/BCM 10GbE adapter present): open the FDO's registered interface under a restricted token to record the actual DACL; probe `0x80002050` (pointer leak) to confirm dispatch reachability; then the decisive test for `0x80002024`: in = `offset 0x7F00, count 1, data 0x00000000` (in-window safe write) followed by `offset 0x00040000+` (beyond a plausible BAR size) watching for `PAGE_FAULT_IN_NONPAGED_AREA` naming bxvbda - pool-corruption-class test => run SOLO per the standing protocol.

*End of report.*
