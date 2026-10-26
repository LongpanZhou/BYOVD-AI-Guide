# Audit: amdi2c.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\amdi2c.sys` |
| Recorded SHA-256 | `387811D57DEF06C9736D9F0BAB0DFB0F83DBAB19E5489BF9A6DCDCBD682DD8FE` (verified against triage_index.csv; recon.py hash re-verified) |
| Company/Version | Advanced Micro Devices, Inc. 1.2.0.99 (AMD I2C Controller Driver) |
| Method | Static-only audit via LOCAL Ghidra 12.1.4 headless + host PE/string/byte recon (incl. targeted check of the single `0F 20` hit); REA shared bridge contended (Agent D-validated fallback). No device opened, no IOCTL executed. |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000`. KPROCESSOR_MODE enum used correctly (KernelMode=0, UserMode=1; all mode args asm/byte-verified where relevant).

## Entry surface

KMDF **SpbCx client** driver (`SPBCx`/`KmdfLibrary` bind strings; `*AMD0010`/`*AMDI0010` ACPI HWIDs). Device SD explicitly assigned via SDDL `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;LS)` (UTF-16 @ `0x140008990` file-off `0x8990`) — System FULL, Administrators FULL, **LocalService** read/write; **no `WD`/Everyone ACE** → unprivileged open denied at the device object. The controller FDO is the SpbCx-owned device; all user-reachable control flows through SpbCx's validated SpbCtl interface (admin-gated by the SDDL above). No other device/interface/string surface in-file.

## Memory-write analysis

- **`MmMapIoSpaceEx` — one call site** (prepare-hardware path, near `0x140002bxx`): source = PnP **translated** `CmResourceTypeMemory` descriptor (`start@+4`, `len@+0xc` via WDF runtime table), protection `0x204` (READWRITE|WRITECOMBINE). Not attacker-influenced; BAR registers only (`KeStallExecutionProcessor` polling, HAL import).
- **`MmMapLockedPagesSpecifyCache` — two call sites** (`I2CReadData` @ line ~653 → priority `0x40000020`, `I2CXferData` @ ~920 → priority `0xc0000020` = NoExecute|NoWrite|High): both map the **SpbCx transfer MDL chain** (`param_1+0x21` list; per-MDL `MdlFlags&0x5` pre-check reuses `MDL->MappedSystemVa`) into a **KernelMode system-VA alias** — the standard SpbCx client pattern for CPU access to transfer buffers already locked by the I/O manager (caller-probed). The in-loop stores/loads are 1-byte-per-transferred-byte into the caller's own probed buffer, offset-walked within each MDL's `ByteCount` (`uVar3 < MDL->ByteCount`), bounded by the Spb-request transfer length. **No caller MDL is ever probed or mapped by this driver itself** (no `MmProbeAndLockPages`/`IoAllocateMdl`/`MmUnlockPages`/`MmUnmapLockedPages` imports — SpbCx owns the MDL lifecycle).
- All `memset` sites fixed-size (`0x38`, `0x28`, `0x24`, `0x20`, `0x90`, `0x48`, `0x68`, `0x178` context) on driver-owned buffers; no length-carrying fill.
- `IoBuildDeviceIoControlRequest`/`IoAllocateIrp`/`IofCallDriver` (internal Spb requests) — outbound only, kernel-controlled buffers.
- Privileged instructions: single `.text` byte-pair hit `44 0F 20 C0` (file off `0x63bd`) = **`MOV RAX, CR8`** (TPR/IRQL read — benign); **no** `wrmsr`/`rdmsr`/`lgdt`/`sgdt`/`mov cr*`-write in code (remaining scan hits are `.rdata`/`.rsrc` data false positives).
- No `ZwOpenSection`, `\Device\PhysicalMemory`, `MmCopyMemory`, `ProbeFor*` misuse, or METHOD_NEITHER plane attributable to this file (Spb owns the queue).

## Memory-touching IOCTL table

none (client registers no own dispatch; SpbCx owns the queue; SDDL above is admin-gated).

## Verdict + VM confirmation plan

**NO-WRITE.** Admin-gated SpbCx client; the only system-VA mapping work is the documented SpbCx transfer-buffer pattern over I/O-manager-locked MDLs; the only physical mapping is the PnP BAR; every fill is fixed-size; no privileged instructions beyond a benign CR8 read. Even under the worst-case-DACL convention, no kernel-memory-write path exists in-file (all buffer access is via SpbCx-validated, pre-locked transfer MDLs).

VM plan (orchestrator-owned, describe-only): none warranted. If ever dynamic: unpriv `CreateFile` on the SpbCtl interface GUID → expect denial (SDDL lacks WD); enumerate GPIO/I2C interfaces to confirm the controller publishes only SpbCtl.

*End of report.*
