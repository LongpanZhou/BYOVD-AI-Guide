# Audit: mccusbfn_4ACB9302.sys

| Field | Value |
|---|---|
| File | drivers\mccusbfn_4ACB9302.sys |
| SHA-256 | 4ACB9302B3461DE476AFB871772E9D03DC67B6E1B60F1351FD88641724AFD2EC |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\mccusbfn_4ACB9302.txt): IoAllocateMdl (dump 3549) over a buffer whose length is (uint16 at object+0xEA) * (object+0xE2); MmProbeAndLockPages(MDL, KernelMode, IoWriteAccess) at 3552; MmMapLockedPagesSpecifyCache with KernelMode at 3555; second instance at dump 6823-6829 |
| Company / version | Measurement Computing Corporation.; file version 1.0.8.0; "MCCUSBFN" |
| Signature | Authenticode Valid; signer CN=Measurement Computing Corporation, O=Measurement Computing Corporation, L=Norton, S=Massachusetts, C=US, SERIALNUMBER=3958376, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1684516340 |
| Reach | n/a (architecture). Device model: MCC USB function-driver (mccusbfn, Measurement Computing). IoCreateDevice and pipe/URB handling via USBD. No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, WDFLDR.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePoolWithTag, IoAllocateMdl, IoFreeMdl, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages, RtlCopyUnicodeString, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Static primitive (USB buffer MDL, arch x86): the MDL is probed and locked for write (IoWriteAccess, dump 3552) before the kernel-mode mapping (dump 3555); the buffer and its length come from driver object fields (+0xE0-0xEA), not directly from the caller in this path. Whether the IOCTL path sets those fields from caller input was not traced. No user-mode mapping (AccessMode 0). Architecture BLOCKED; not graded for write quality.

## 2 Verdict

**BLOCKED (architecture).** mccusbfn_4ACB9302.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see §1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
