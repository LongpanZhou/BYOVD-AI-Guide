# Audit: amdgpio2.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\amdgpio2.sys` |
| Recorded SHA-256 | `7E514410F2D87B54AE8DF07002FBB154A28D2833495B4529B8D917E8DC28DFD0` (verified against triage_index.csv; recon.py hash re-verified) |
| Company/Version | Advanced Micro Devices, Inc. 2.2.0.130 (AMD GPIO Controller Driver) |
| Method | Static-only audit via LOCAL Ghidra 12.1.4 headless (80 fns dumped) + host PE/string recon; REA shared bridge contended (Agent D-validated fallback). No device opened, no IOCTL executed. |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000`.

## Entry surface

KMDF GpioClx **client** driver (AMDGPIO* callbacks registered via `GPIO_CONTROLLER_REGISTRATION`; `KmdfLibrary`/`GPIOClx` bind strings). Device/FDO is created by the GpioClx library: the client performs **no** `IoCreateDevice`/`WdfDeviceInitAssignName`/`WdfDeviceCreateDeviceInterface`/SDDL of its own - no device-name, interface-GUID, or SDDL string exists in the binary (36 UTF-16 strings checked: only HWID/registry/trace tokens). No user-openable surface attributable to this file; GPIOCTL IOCTLs would arrive on the GpioClx-owned FDO (unnamed, interface-less), which is admin-gated.

## Memory-write analysis

- **Single `MmMapIoSpace` call** (`FUN_1400026d0`-family prepare-hardware, call site near `0x1400027xx`): source = PnP **translated** `CmResourceTypeMemory` descriptor obtained via WDF runtime-table calls (WdfCmResourceListGetCount/GetDescriptor, table offsets `+0x980/+0x988`), length-gated to the GPIO controller BAR (`len == 0x300` or `0x400`). Not attacker-influenced. Unmapped via `MmUnmapIoSpace` on teardown. Same safe pattern as iaLPSSi_GPIO.
- Registers accessed through the mapped BAR only (`READ/WRITE_REGISTER_ULONG` trace strings at `0x1400051a0/0x1400051e0`); GPIO pin/bank writes (`AMDGpioWriteGpioPins`, `Mask/Unmask/ClearActive/Reconfigure/Connect/Disconnect`) land in the controller's hardware BAR, validated BankID/PinNumber by GpioClx - **hardware effect, not kernel-memory writes**.
- All `memset`/fill sites are fixed-size (`0x38`, `0x420`, `0xd8`) on driver-owned buffers.
- `ExGetFirmwareEnvironmentVariable`/`ExSetFirmwareEnvironmentVariable` (`L"AMD_MODS_RES"`, GUID var) - kernel-internal firmware-variable sync in the prepare-hardware path; no user-reachable call path; not a memory-write primitive.
- No `MmProbeAndLockPages`, `MmMapLockedPages*`, `IoAllocateMdl`, `ProbeFor*`, `ZwOpenSection`, `MmCopyMemory`, `MmMapIoSpace` with caller addresses, no METHOD_NEITHER surface (no own queue/dispatch), no `Se*` imports.
- Privileged-instruction byte scan: `wrmsr/rdmsr/cpuid` byte-pair hits all inside `.rdata`/`.rsrc` (import names, trace strings, Authenticode cert blob) - **none in code sections** (byte-verified against the section table).

## Memory-touching IOCTL table

none (client registers no dispatch of its own; GpioClx owns the queue).

## Verdict + VM confirmation plan

**NO-WRITE.** GpioClx client with an unnamed, interface-less FDO; the only mapping is a PnP-translated BAR; every fill is fixed-size; no user-openable control surface exists in-file (worst-case-DACL convention is moot - no device object of its own to open). Matches the iaLPSSi_GPIO.sys NO-WRITE template.

VM plan (orchestrator-owned, describe-only): none warranted by static evidence. If ever dynamic: confirm the GPIO controller PDO starts only with matching ACPI HWID (`*GPIO0010`/`*AMD0030`/`*AMDI0030`/`*AMDI0031`) and that no `\Device\` object is named; enumerate GPIOCTL interfaces to confirm none is registered for this controller.

*End of report.*
