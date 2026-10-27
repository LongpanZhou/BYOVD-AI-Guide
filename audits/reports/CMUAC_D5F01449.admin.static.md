# Audit: CMUAC_D5F01449.sys

| Field | Value |
|---|---|
| File | drivers\CMUAC_D5F01449.sys |
| SHA-256 | D5F014496CA03289D3D72DD00939C632C08F9A76FB720D140244117287C2AE1D |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\CMUAC_D5F01449.txt): imports IoAllocateMdl, MmBuildMdlForNonPagedPool, MmMapLockedPagesSpecifyCache, MmUnmapLockedPages (dump 60-63); unmap call site at dump 65638; no direct map call site found in the decompile |
| Company / version | C-MEDIA; file version 8.1.0014.7337; "C-MEDIA USB Audio Class 1.0 and 2.0 Device Driver Driver" |
| Signature | Authenticode NotSigned; signer none |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1412835748 |
| Reach | n/a (architecture). Device model: Cooler Master UAC audio driver (PortCls, build D5F01449). PcNewPort at dump 56668, 56948, 62327. No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, portcls.sys, HAL.dll, USBD.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePool, ExAllocatePoolWithTag, ExFreePool, IoAllocateMdl, IoFreeMdl, MmBuildMdlForNonPagedPool, MmMapLockedPagesSpecifyCache, PcRegisterPhysicalConnection, RtlCompareMemory, ZwCreateFile, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Static primitive (not confirmed): the MDL mapping path is imported and its unmap call site exists (dump 65629-65641, buffers at object offset 0x124). The map call site was not resolved as a direct call in this dump (an indirect or thunked call is possible), so whether a user-mode mapping exists is not established. Architecture BLOCKED; write quality not assessed.

## 2 Verdict

**BLOCKED (architecture).** CMUAC_D5F01449.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
