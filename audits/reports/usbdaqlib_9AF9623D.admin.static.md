# Audit: usbdaqlib_9AF9623D.sys

| Field | Value |
|---|---|
| File | drivers\usbdaqlib_9AF9623D.sys |
| SHA-256 | 9AF9623D0C495A733940F1ADD6F7FD11C5AA954C920E9B307B93FEDBB8589B1C |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\usbdaqlib_9AF9623D.txt, 15,580 lines, identical to usbdaqlib_1D53580B except the program name): same locking helpers and ADC/DAC callers (dump 2049-2057, 5694, 9798-9837, 15061-15090) |
| Company / version | Measurement Computing Corp.; file version 5.0.3 Build 1; "USB-2500 Device Driver" |
| Signature | Authenticode Valid; signer CN="Digilent, Inc.", O="Digilent, Inc.", L=Pullman, S=Washington, C=US, SERIALNUMBER=602 028 179, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Washington, OID.1.3.6.1.4.1.311.60.2.1.3=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1326992402 |
| Reach | n/a (architecture). Device model: MCC USB DAQ library driver (usbdaqlib, second build). No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, WMILIB.SYS, USBD.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePool, IoAllocateMdl, IoCreateDevice, IoFreeMdl, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages, memcpy, memmove, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Candidate primitive (x86 build, as in the sibling; not graded, architecture BLOCKED): the ADC and DAC start paths take a buffer VA from the request (param_2[3] / param_2[5]) and lock it for write with a KernelMode probe, then map it in kernel mode; the device writes samples into the locked pages with a length of count*2 bytes. Whether an unprivileged caller can reach it and whether earlier validation exists were not traced. Verify before sign-off.

## 2 Verdict

**BLOCKED (architecture).** usbdaqlib_9AF9623D.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
