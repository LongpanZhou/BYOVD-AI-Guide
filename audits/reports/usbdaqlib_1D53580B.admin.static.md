# Audit: usbdaqlib_1D53580B.sys

| Field | Value |
|---|---|
| File | drivers\usbdaqlib_1D53580B.sys |
| SHA-256 | 1D53580BFB36CB70AC49C36525CC7B72BC64F0F6B54991BC3D4C5F2BB116925D |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\usbdaqlib_1D53580B.txt, 15,000+ lines): device created with IoCreateDevice(..., 0x180, 0, 0x22, 0x80) at dump 91 (no FILE_DEVICE_SECURE_OPEN); buffer locking helpers FUN_000124b6 (dump 2049-2057) and FUN_0002027e (utilLockBuffer, dump 15061-15090) call IoAllocateMdl + MmProbeAndLockPages(MDL, KernelMode, IoWriteAccess) + MmMapLockedPagesSpecifyCache(KernelMode); callers: ADC start FUN_0001659c (dump 5694; buffer param_2[3], count*2 bytes; reached from command 0x50002418 at dump 12660-12676), DAC start FUN_0001aba0 (dump 9798-9837; param_2[5]), FUN_00012550 (dump 2094) |
| Company / version | Measurement Computing Corp.; file version 5.0.3 Build 1; "USB-2500 Device Driver" |
| Signature | Authenticode Valid; signer CN=Measurement Computing Corporation, O=Measurement Computing Corporation, L=Norton, S=Massachusetts, C=US, SERIALNUMBER=3958376, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1326992402 |
| Reach | n/a (architecture). Device model: MCC USB DAQ library driver (usbdaqlib, first build). IoCreateDevice (0x180); USB DAQ transfer state machine (adcStartUsbTransfer / dacStartUsbTransfer). No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, WMILIB.SYS, USBD.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePool, IoAllocateMdl, IoCreateDevice, IoFreeMdl, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages, memcpy, memmove, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Candidate primitive (x86 build; not graded, architecture BLOCKED): the ADC and DAC start commands take a buffer VA from the request struct (param_2[3] / param_2[5], user-supplied in the command buffer) and lock it for write with a KernelMode probe (MmProbeAndLockPages, no user-range check and no exception guard in the visible code), then map it in kernel mode. The device writes acquired samples into the locked pages, so the destination would be caller-chosen with a length of count*2 bytes. Whether the request arrives as METHOD_NEITHER, whether any earlier validation rejects kernel addresses, and whether an unprivileged caller can reach command 0x50002418 were not traced. This needs checking before the driver family is signed off.

## 2 Verdict

**BLOCKED (architecture).** usbdaqlib_1D53580B.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
