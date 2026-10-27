# Audit: mcpci_992CA233.sys

| Field | Value |
|---|---|
| File | drivers\mcpci_992CA233.sys |
| SHA-256 | 992CA23383E249D310E4CC5DCD132CE726542A2C9FF1F9E6EE197CBFC2AE0ACA |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\mcpci_992CA233.txt): imports MmAllocateContiguousMemory, IoAllocateMdl, MmProbeAndLockPages, MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmGetPhysicalAddress, MmUnmapIoSpace, HAL port I/O; the device-property/resource function at dump 340-388 maps MDLs from an object table to UserMode (AccessMode 1, dump 375) and returns the addresses in the output structure |
| Company / version | Measurement Computing; file version 1.3.4.0; "Driver for PCI Devices" |
| Signature | Authenticode Valid; signer CN=Measurement Computing Corporation, O=Measurement Computing Corporation, L=Norton, S=Massachusetts, C=US, SERIALNUMBER=3958376, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1684516324 |
| Reach | n/a (architecture). Device model: MCC PCI DAQ driver (mcpci). IoGetDeviceProperty for resource data; PCI BAR mapping through MmMapIoSpace. No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, WDFLDR.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): IoAllocateMdl, IoFreeMdl, MmAllocateContiguousMemory, MmBuildMdlForNonPagedPool, MmFreeContiguousMemory, MmGetPhysicalAddress, MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages, READ_PORT_BUFFER_USHORT, READ_PORT_UCHAR, READ_PORT_ULONG, READ_PORT_USHORT, READ_REGISTER_UCHAR, READ_REGISTER_ULONG, READ_REGISTER_USHORT, RtlCopyUnicodeString, WRITE_PORT_UCHAR, WRITE_PORT_ULONG, WRITE_PORT_USHORT, WRITE_REGISTER_UCHAR, WRITE_REGISTER_ULONG, WRITE_REGISTER_USHORT, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Static primitive (DAQ buffer exposed to user mode, arch x86): the function at dump 340-388 maps every MDL entry flagged in the object table (piVar5[6]==1, dump 373-375) with AccessMode UserMode and writes the resulting user VAs into the caller output (param_2[iVar7], dump 381). The MDLs are driver-allocated (contiguous/nonpaged memory, the table is driver state), so the exposure is a user-mode view of the driver DMA buffers; the caller, the mapping protection, and whether any kernel control data lies in those buffers were not traced. Physical-address and port I/O paths were not traced. Architecture BLOCKED; not graded for write quality.

## 2 Verdict

**BLOCKED (architecture).** mcpci_992CA233.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
