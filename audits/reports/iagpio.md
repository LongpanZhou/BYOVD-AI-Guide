# Audit: iagpio.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iagpio.sys` |
| Recorded SHA-256 | `FAAA46F22944E043A90AE6E9F0F86AF187FC2819C563DA375B2A409347BB2C35` (verified against triage_index.csv; recon.py hash re-verified) |
| Company/Version | Intel(R) Corporation 1.1.1.0 (Intel(R) Serial IO GPIO Controller Driver) |
| Method | Static-only audit via LOCAL Ghidra 12.1.4 headless + host PE/string/byte recon (3 `.text` byte hits resolved); REA shared bridge contended (Agent D-validated fallback). No device opened, no IOCTL executed. |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000`.

## Entry surface

KMDF GpioClx **client** driver (`GPIOClx`/`KmdfLibrary` bind strings), sibling of Agent D's cleared iaLPSSi_GPIO.sys. Client creates **no** named device, interface, or SDDL of its own — no `\Device\`/`\DosDevices\`/GUID/SDDL string in the binary (25 UTF-16 strings checked). FDO is GpioClx-owned (unnamed, interface-less, admin-gated); also registers an ACPI **opregion handler** (`RegisterOpRegionHandler` @ decomp line ~2333, handler `FUN_140003ef0`) — invoked only by ACPI when AML accesses the region; no user-reachable path.

## Memory-write analysis

- **Single `MmMapIoSpaceEx`** (prepare-hardware, decomp line 2292): source = PnP **translated** `CmResourceTypeMemory` descriptor (`start@+4`, `len@+0xc` via WDF runtime table), protection `0x204` (READWRITE|WRITECOMBINE); `MmUnmapIoSpace` teardown. Not attacker-influenced; controller BAR registers only.
- `memset`/fill sites fixed-size (`0x200`, `0x310`, `0xd8`, `0x20`, `0x38`) on driver-owned buffers; no length-carrying fill.
- No `MmProbeAndLockPages`, `MmMapLockedPages*`, `IoAllocateMdl`, `ProbeFor*`, `ZwOpenSection`, `MmCopyMemory`, no `Se*` imports; import surface = mapping/WDF-bind/ACPI-opregion/WMI/ETW only.
- Privileged instructions: `.text` byte hits resolved at byte level — `0x14e3`/`0x15d5` = `MOV RBP,CR8`/`MOV RSI,CR8` (TPR/IRQL reads, benign); `0x3010` region = `JB rel32` (`0F 82 …`) whose displacement bytes coincidentally contain the scan pattern — mid-instruction false positive. **No** `wrmsr`/`rdmsr`/`lgdt`/`sgdt`/CR-writes in code (`.rdata`/`.rsrc` hits are data).

## Memory-touching IOCTL table

none (client registers no dispatch of its own; GpioClx owns the queue).

## Verdict + VM confirmation plan

**NO-WRITE.** GpioClx client with unnamed interface-less FDO; one PnP-translated BAR mapping; fixed-size fills; ACPI opregion handler is kernel-internal; no user-openable control surface in-file (worst-case-DACL convention moot — no own device object). Same template as iaLPSSi_GPIO.sys.

VM plan (orchestrator-owned, describe-only): none warranted. If ever dynamic: confirm devnode only with matching ACPI HWID, no named `\Device\` object, no GPIOCTL interface registered.

*End of report.*
