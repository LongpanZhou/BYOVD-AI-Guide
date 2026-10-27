# Audit: mcusb_2BA82572.sys

| Field | Value |
|---|---|
| File | drivers\mcusb_2BA82572.sys |
| SHA-256 | 2BA82572F6927BD8107D375A90D3289FBAD8F4B9AEE5FF86EB284C396C4FEF40 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\mcusb_2BA82572.txt): IoAllocateMdl over a buffer at object+0x11 (dump 3122) and over a length (uint * uVar2) at dump 5430; MmProbeAndLockPages(MDL, KernelMode, IoWriteAccess) at 3126 and 5438; MmMapLockedPagesSpecifyCache with KernelMode at 3130 and 5443 |
| Company / version | Measurement Computing Corporation.; file version 1.16.0.0; "MCUSB" |
| Signature | Authenticode Valid; signer CN=Measurement Computing Corporation, O=Measurement Computing Corporation, L=Norton, S=Massachusetts, C=US, SERIALNUMBER=3958376, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1684516335 |
| Reach | n/a (architecture). Device model: MCC USB DAQ driver (mcusb). USBD/URB handling; no SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, WDFLDR.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePoolWithTag, IoAllocateMdl, IoFreeMdl, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages, RtlCopyUnicodeString, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Static primitive (USB buffer MDL, arch x86): the MDLs are probed and locked for write before a kernel-mode mapping (dump 3126-3130, 5438-5443). No user-mode mapping in this build. Buffer sources are driver object fields; whether caller IOCTL input sets their lengths was not traced. Architecture BLOCKED; not graded for write quality.

## 2 Verdict

**BLOCKED (architecture).** mcusb_2BA82572.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
