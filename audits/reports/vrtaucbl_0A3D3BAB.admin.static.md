# Audit: vrtaucbl_0A3D3BAB.sys

| Field | Value |
|---|---|
| File | drivers\vrtaucbl_0A3D3BAB.sys |
| SHA-256 | 0A3D3BAB2EAE66FC17F9DCFA7336336B2F20C1B1C79AD00224554DA672E92551 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\vrtaucbl_0A3D3BAB.txt, 27,988 lines, arch AARCH64 decoded): MmMapLockedPagesSpecifyCache at dump 5188, 18359 (KernelMode, argument 0) and 20371; ProbeForWrite at dump 10933 guards a copy-out in FUN_14000cc38 (dump 10919-10935) only when the flag at struct+0x40 is set and the buffer is the direct (non-MDL) path |
| Company / version | Eugene (Evgenii) Muzychenko; file version 4.71.0.14195; "Virtual Audio Cable - kernel-mode WDM/KS driver" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US |
| Architecture | ARM64 (PE32+); machine 0xaa64; built 1781974258 |
| Reach | n/a (architecture). Device model: Virtual audio cable (vrtaucbl, AARCH64). IoCreateDevice, IoAttachDeviceToDeviceStack, IoAllocateIrp, and ProbeForWrite (imported). No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: HAL.dll, ntoskrnl.exe, ks.sys, portcls.sys.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePool, ExFreePool, ExFreePoolWithTag, KsProbeStreamIrp, MmAllocatePagesForMdl, MmCreateSection, MmFreePagesFromMdl, MmGetPhysicalAddress, MmMapLockedPagesSpecifyCache, MmMapViewInSystemSpace, MmMapViewOfSection, MmUnmapViewOfSection, PcRegisterPhysicalConnection, ProbeForRead, ProbeForWrite, RtlFillMemory, RtlMoveMemory, RtlZeroMemory, ZwCreateKey.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Candidate primitive (ARM64 build; not graded, architecture BLOCKED): FUN_14000cc38 copies driver data into a buffer of caller-supplied length (param_3, 32-bit) at dump 10935. The buffer is struct+0x70 (direct, user-supplied pointer) or struct+0x18 (MDL-mapped). ProbeForWrite (dump 10933) runs only when the flag at struct+0x40 is set and the direct path is taken; the place that sets that flag was not traced. Kernel MDL mappings are KernelMode. The IOCTL that reaches FUN_14000cc38 and its limits were not traced.

## 2 Verdict

**BLOCKED (architecture).** vrtaucbl_0A3D3BAB.sys is ARM64 (PE32+) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see §1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
