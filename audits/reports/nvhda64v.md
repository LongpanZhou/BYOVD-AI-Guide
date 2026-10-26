# Audit: nvhda64v.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\nvhda64v.sys` |
| Recorded SHA-256 | `20c53e79ae686fdcabce253350345b7ef8e0b2eeb4c7b54c53dd9fd97f4c4f80` (matches triage_index.csv row "NVHDA") |
| Company/Version | NVIDIA Corporation — 1.4.0.1 ("NVIDIA HDMI Audio Driver") |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4, x86:LE:64) |
| Verdict | **WRITE-MEDIUM** (fixed ~6-byte non-paged-pool OOB write; single-open + endpoint-DACL conditional) |

> Static-only. No driver load, no device open, no IOCTL execution. Addresses at image base `0x140000000`. Results re-validated against the target SHA-256 (shared Ghidra session was observed switching programs across agents; flagged calls were re-run and re-checked).

---

## Entry surface

PortCls adapter driver, MSVAD-sample-derived (imports `PcInitializeAdapterDriver`/`PcAddAdapterDevice`/`PcRegisterSubdevice`/`PcNewPort`/`PcDispatchIrp` from portcls.sys). **No IoCreateDevice import** — driver creates no device object of its own; portcls instantiates the adapter + "Topology"/"Wave" KS subdevices (per-miniport `FUN_140010440` StartDevice; miniport created by FUN_140008190, codec type 2 → HDMI codec path).

- Custom dispatch = FUN_140010040 (`0x140010040`, installed by DriverEntry via MajorFunction override; PNP = FUN_140010310; unload present).
- **Two single-open control files**: CREATE/CLOSE compare the FileObject relative name against `\audioprotection` (global bool `DAT_14000e280`) and `\audioparameters` (`DAT_14000e284`) — compare sites `0x140010186/0x140010220` and `0x1400101d1/0x14001028b`. Each name admits exactly one handle; second open fails `0xC0000001`. The DACL comes from the portcls/KS device object (audio-endpoint security), not from this binary — no SDDL strings anywhere. NVIDIA's own audio server competes for the same single open.
- Everything else → `PcDispatchIrp` (KS-gated, out of scope).

## Memory-write analysis

The defect: **no OutputBufferLength gate on the buffered output copy**.

IOCTL `0x264800` (device type `0x26`, Fn `0x1200`, METHOD_BUFFERED, FILE_ANY_ACCESS):
1. Dispatcher FUN_140010040 reads only MajorFunction and IoControlCode — **neither InputBufferLength nor OutputBufferLength is ever checked**.
2. Resolves adapter object `*(ext+0x20)` and calls vtable fn `+0x40` = FUN_140012010 (`0x140012010`).
3. FUN_140012010 writes: `*(int*)SystemBuffer = channelConfig` and `*(uint16*)(SystemBuffer+4) = channels` — **6 bytes** into the METHOD_BUFFERED system buffer. The IO manager sizes that buffer as `max(InputBufferLength, OutputBufferLength)`; with `OutputBufferLength == 0` (and any small input) the allocation is 0..5 bytes and the write lands out-of-bounds in non-paged pool.
4. Dispatcher fallback path also writes 4 bytes directly (`*puVar4 = 0` / `= result`, `0x1400101a0` block) when the adapter object is absent.
5. `IRP->IoStatus.Information = 4` is reported regardless — completion then copies `min(0, 4) = 0` bytes back, so the corruption is invisible to the caller.

Overflow contents are adapter/registry state (channel config ∈ {0x107,0x33,0x3F,0x60F,0x63F,0xFF}; channels ∈ {2..8,4}) — **fixed extent (~6 bytes), low content control**, but attacker-triggered and repeatable while the single open is held.

Patterns checked with no findings:
- **METHOD_NEITHER**: none (all compared codes bits 1–0 = 00).
- **Caller MDL mapping**: no `MmProbeAndLockPages`/`MmMapLockedPagesSpecifyCache`/`MmMapIoSpace` imports or names; only `IoAllocateIrp`/`IoFreeIrp`.
- **Physical memory / sections**: no `ZwOpenSection`, no `\Device\PhysicalMemory`.
- **MSR/GDT/IDT**: none.
- **User length into fixed buffers**: `0x258810/0x258814`-style exact-header gates are absent here — but the remaining three custom codes (`0x26480c`, `0x26880c`, `0x8DE0004`) forward to vtable fns FUN_1400121E0/FUN_140013A50/FUN_140013930 whose bodies are **pure registry reads/writes of the adapter's own values** (PropertyEN/ST/RS/FT/CH/FL/UH, ChannelConfig) — they ignore the user buffer entirely.
- **Index × size**: none (no tables indexed by user values).

## Memory-touching IOCTL table

| Code | Method | Handler | Write action | Bound |
|---|---|---|---|---|
| `0x264800` | BUFFERED/ANY | FUN_140010040 → FUN_140012010 | writes 4+2 bytes into buffered system buffer | **none (defect)** |
| `0x264804/0x264808` | BUFFERED/ANY | FUN_140010040 | none (status `0xC0000002` path) | — |
| `0x26480C` | BUFFERED/ANY | FUN_140010040 → FUN_1400121E0 | none (registry-only; buffer ignored) | — |
| `0x268804/0x268808` | BUFFERED/ANY | FUN_140010040 | none | — |
| `0x26880C` | BUFFERED/ANY | FUN_140010040 → FUN_140013A50 | none (registry-only) | — |
| `0x8DE0004` | BUFFERED/ANY | FUN_140010040 → FUN_140013930 | none (registry-only) | — |

All other MJ_* → `PcDispatchIrp`.

## Verdict + VM confirmation plan

**WRITE-MEDIUM.** A genuine missing-bound defect exists (`0x264800` writes ~6 attacker-triggered bytes past a `max(in,out)`-sized buffered allocation), but it is: (a) fixed-size with negligible content control; (b) gated by a single-open control file and by the portcls/KS device DACL (audio-endpoint security — user-openable in typical deployments, admin-only otherwise); (c) too small to place shellcode, though repeated triggering can corrupt adjacent pool chunks.

VM confirmation (orchestrator-owned): (1) non-destructive: standard user opens the HDMI audio endpoint interface with name `\\audioprotection`, calls `DeviceIoControl(0x264800, in=12B, out=0)` → expect STATUS_SUCCESS with hidden 6-byte OOB (verify with pool tag auditing if available); (2) decisive (SOLO phase, snapshot-restore after): repeat the call in a loop against a pool-pinned allocation pattern to force an adjacent-chunk corruption bugcheck; driver expected in the bugcheck stack.

*End of report.*
