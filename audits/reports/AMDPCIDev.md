# Audit: AMDPCIDev.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\AMDPCIDev.sys` |
| Recorded SHA-256 | `E10768FEB8BB37FE8CD310F47C90EAF1EE6E520E792B67D65FD30ECB285A977F` (matches triage_index.csv row `AMDPCIDev`; sha256 recomputed in-session) |
| Company/Version | Advanced Micro Devices (PDB `AMDPCIDev.pdb`) |
| Method | Static-only audit via REA/Ghidra 12.1.4, memory-write scope only |
| Verdict | **NO-WRITE** - no memory-mapping or physical-memory APIs imported; device-control IRPs are forwarded to the lower stack; the only MSR writes take constant arguments at DriverEntry |
| Coverage | ~70%. Not traced: AddDevice `FUN_140006000`, PnP `FUN_140006120`, power `FUN_1400010f0`, unload `FUN_140006460`, process-notify callbacks `FUN_140001db0` / `FUN_140001a20`, init helpers `FUN_1400013a0`, `FUN_1400018c8`, `FUN_1400020dc`, `FUN_14000218c`, `FUN_14000181c`, `FUN_140001f2c`, `FUN_140001b9c` |

> **Static-only.** No load, no device open, no IOCTL execution. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- DriverEntry = `entry` (`FUN_14000835c` then `FUN_140008000`). Installs a default dispatch (`FUN_140001050`) on every major function. Overrides: PnP `0x148` = `FUN_140006120`; Power `0x120` = `FUN_1400010f0`; AddDevice (DriverExtension+8) = `FUN_140006000`; DriverUnload `0x68` = `FUN_140006460`.
- **No `IRP_MJ_DEVICE_CONTROL` handler of its own.** Default dispatch `FUN_140001050` acquires the remove lock and forwards the IRP to the lower device with `IofCallDriver`. This is a filter; device-control IRPs pass through.
- Imports (memory-relevant): **none** of `MmMapIoSpace`, `MmMapLockedPages*`, `MmProbeAndLockPages`, `IoAllocateMdl`, `ZwMapViewOfSection`, `MmCopyMemory`, `ProbeForRead`, `ProbeForWrite`, HAL bus access. Pool allocation (`ExAllocatePoolWithTag`) and registry-free process checks (`ZwOpenProcess`, `PsSetCreateProcessNotifyRoutineEx`) are present.

## MSR writes at DriverEntry (`FUN_14000222c`)

- Signature `FUN_14000222c(msr, bit, value)`: for each active processor group and each processor, sets `bit` of `msr` to `value` via `rdmsr`/`wrmsr` (read-modify-write, one core at a time under `KeSetSystemGroupAffinityThread`).
- Call sites in `FUN_140008000` pass **constant** arguments: `(0xc0011002, 0x12, 0)`, `(0xc0011004, 0x3e, 0)`, `(0xc0011023, 8, 1)`, `(0xc001102c, 0x33, 1)`, `(0x17b, 3, 0)`. No caller-controlled value reaches the MSR index, bit or value.
- Not a memory-write primitive. Noted as a load-time side effect (changes AMD CPU MSR bits on every core); see the findings section.

## Memory-write analysis

| Pattern | Result | Evidence |
|---|---|---|
| Physical / I/O space mapping | **Absent** from the import table | import sweep |
| User-buffer copy | **Absent**: no `ProbeFor*` imports and no IOCTL handler of its own | `FUN_140001050` |
| Kernel address write from IRP data | None: device-control IRPs are forwarded unchanged | `FUN_140001050` |
| MSR write with caller-controlled index/value | None: constants at DriverEntry | `FUN_140008000`, `FUN_14000222c` |
| Pool write | Allocations are driver-sized; no caller-supplied sizes found in decompiled paths | import sweep (`ExAllocatePoolWithTag`) |

## Findings

1. **No memory-write surface on this device.** It is a PCI filter whose device-control path is a pure forward.
2. **Load-time MSR changes on all cores.** `DriverEntry` sets a fixed set of AMD MSR bits (`0xC0011002`, `0xC0011004`, `0xC0011023`, `0xC001102C`, `0x17B`) on every processor. The values are constant and not caller-controlled; the effect is a system-wide CPU configuration change on load. Recorded for the orchestrator; out of memory-write scope.
3. Process-notify callbacks (`FUN_140001db0` / `FUN_140001a20`) and AddDevice (`FUN_140006000`) were not decompiled. They don't take caller input in the IRP path, but this is a coverage gap.

## Verdict rationale

NO-WRITE. The driver has no mapping API, no probe calls, and no device-control handler. The only writes to hardware state are constant MSR updates at load.

## Next steps (for the write-only pass)

- Decompile AddDevice `FUN_140006000` and the process-notify callbacks to confirm no caller-influenced writes.
- Confirm that `FUN_140001050` is the only path for device-control IRPs (no other attached-device handler).

## VM confirmation plan (orchestrator-owned; non-destructive)

1. Confirm that device-control IRPs are forwarded: issue an IOCTL to the stack's bottom device and observe pass-through. No write expected from this driver.
2. Note the MSR side effect on load for the orchestrator; do not load on the host.

## Evidence (REA, retained IDs)

`ev_28320c31a801cb94e9660b0db6ff281524bf7468260a6a9476ae475abe4b0a22` (`entry`), `ev_c687f2353c2c405aa3ff47fda89b25ee08bd5b15b89531b75af7118b4ca6ac74` (`FUN_140008000`), `ev_345a6c4d731c23bacbe735092cd9417486eb3d8b4742a73ca10885bdfd11825c` (`FUN_140001050`), `ev_52602d779008e463c323db9ece519122186a07e56455c4afac3e27cfe7aed6da` (`FUN_14000222c`).
