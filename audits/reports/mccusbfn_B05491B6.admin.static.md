# Audit: mccusbfn_B05491B6.sys

| Field | Value |
|---|---|
| File | drivers\mccusbfn_B05491B6.sys |
| SHA-256 | B05491B66EA99FD59D0E51C05DED02CC498A92E5A773DA40A2A1088AD319BC9A |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\mccusbfn_B05491B6.txt, 7,029 lines, identical to mccusbfn_4ACB9302 except the program name): same MDL path at dump 3549-3555 and 6823-6829 (IoAllocateMdl, MmProbeAndLockPages with IoWriteAccess, KernelMode mapping) |
| Company / version | Measurement Computing Corporation.; file version 1.0.8.0; "MCCUSBFN" |
| Signature | Authenticode Valid; signer CN="Digilent, Inc.", O="Digilent, Inc.", L=Pullman, S=Washington, C=US, SERIALNUMBER=602 028 179, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Washington, OID.1.3.6.1.4.1.311.60.2.1.3=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1751560373 |
| Reach | n/a (architecture). Device model: MCC USB function-driver (mccusbfn, second build). No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, WDFLDR.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePoolWithTag, IoAllocateMdl, IoFreeMdl, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages, RtlCopyUnicodeString, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Static primitive (USB buffer MDL, arch x86), as in the sibling: the MDL is probed and locked for write (dump 3552) before the kernel-mode mapping (dump 3555); the length is from driver object fields. Whether the IOCTL path sets those fields from caller input was not traced. No user-mode mapping. Architecture BLOCKED; not graded for write quality.

## 2 Verdict

**BLOCKED (architecture).** mccusbfn_B05491B6.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see §1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
