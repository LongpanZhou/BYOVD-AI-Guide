# Audit: mcpci_CF877AAB.sys

| Field | Value |
|---|---|
| File | drivers\mcpci_CF877AAB.sys |
| SHA-256 | CF877AAB540798FB521CFFAE5587F7402F1A8C57584E3E77A4A2CDC822AA7D9F |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\mcpci_CF877AAB.txt, 5,202 lines, identical to mcpci_992CA233 except the program name): the same device-property/resource function at dump 340-388 maps the MDL table to UserMode (dump 375) and returns the addresses |
| Company / version | Measurement Computing; file version 1.3.4.0; "Driver for PCI Devices" |
| Signature | Authenticode Valid; signer CN="Digilent, Inc.", O="Digilent, Inc.", L=Pullman, S=Washington, C=US, SERIALNUMBER=602 028 179, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Washington, OID.1.3.6.1.4.1.311.60.2.1.3=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1751560342 |
| Reach | n/a (architecture). Device model: MCC PCI DAQ driver (mcpci, second build). No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, WDFLDR.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): IoAllocateMdl, IoFreeMdl, MmAllocateContiguousMemory, MmBuildMdlForNonPagedPool, MmFreeContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages, READ_PORT_BUFFER_USHORT, READ_PORT_UCHAR, READ_PORT_ULONG, READ_PORT_USHORT, READ_REGISTER_UCHAR, READ_REGISTER_ULONG, READ_REGISTER_USHORT, RtlCopyUnicodeString, WRITE_PORT_UCHAR, WRITE_PORT_ULONG, WRITE_PORT_USHORT, WRITE_REGISTER_UCHAR, WRITE_REGISTER_ULONG, WRITE_REGISTER_USHORT, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Static primitive (DAQ buffer exposed to user mode, arch x86), as in the sibling: the function at dump 340-388 maps flagged MDL entries with AccessMode UserMode (dump 373-375) and writes the user VAs into the caller output (dump 381). Caller, mapping protection and buffer contents not traced. Architecture BLOCKED; not graded for write quality.

## 2 Verdict

**BLOCKED (architecture).** mcpci_CF877AAB.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see §1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
