# Audit: mcusb_2C269B0F.sys

| Field | Value |
|---|---|
| File | drivers\mcusb_2C269B0F.sys |
| SHA-256 | 2C269B0F1EA347BD02A0B656C9D5077AC5DEA3AD395631331EAA080ED63BD08C |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\mcusb_2C269B0F.txt, 5,764 lines, identical to mcusb_2BA82572 except the program name): same MDL probe-and-lock and kernel-mode mapping at dump 3122-3130 and 5430-5443 |
| Company / version | Measurement Computing Corporation.; file version 1.16.0.0; "MCUSB" |
| Signature | Authenticode Valid; signer CN="Digilent, Inc.", O="Digilent, Inc.", L=Pullman, S=Washington, C=US, SERIALNUMBER=602 028 179, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Washington, OID.1.3.6.1.4.1.311.60.2.1.3=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1751560363 |
| Reach | n/a (architecture). Device model: MCC USB DAQ driver (mcusb, second build). No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, WDFLDR.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePoolWithTag, IoAllocateMdl, IoFreeMdl, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages, RtlCopyUnicodeString, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Static primitive (USB buffer MDL, arch x86), as in the sibling: MDLs probed and locked for write (IoWriteAccess) before a KernelMode mapping; no user-mode mapping. Buffer sources and whether caller input sets their lengths were not traced. Architecture BLOCKED; not graded for write quality.

## 2 Verdict

**BLOCKED (architecture).** mcusb_2C269B0F.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
