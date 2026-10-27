# Audit: libusb0_AA7D75A4.sys

| Field | Value |
|---|---|
| File | drivers\libusb0_AA7D75A4.sys |
| SHA-256 | AA7D75A4D01B405AAB7C848674BBED392B64C6E374E20FD72ADC3C96294E2F00 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\libusb0_AA7D75A4.txt): large-transfer path builds sub-MDLs with IoAllocateMdl (dump 3711-3729) over a request buffer; MmMapLockedPagesSpecifyCache with KernelMode (argument 0) at dump 3530 (completion path); IOCTL switch 0x2220xx at dump 989-1244+; no MmProbeAndLockPages call found in the decompile |
| Company / version | http://libusb-win32.sourceforge.net; file version 1.2.6.0; "LibUSB-Win32 - Kernel Driver" |
| Signature | Authenticode Valid; signer CN=Travis Lee Robinson, C=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1326821962 |
| Reach | n/a (architecture). Device model: libusb-win32 filter driver (libusb0). Device stack filter using IoCreateDevice, IoAttachDeviceToDeviceStack and URB submission; the IOCTL dispatch covers 0x2220xx codes (METHOD_BUFFERED). No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, USBD.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePoolWithTag, IoAllocateMdl, IoBuildPartialMdl, IoCreateDevice, IoFreeMdl, MmMapLockedPagesSpecifyCache, memcpy, memmove, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Static primitive (USB transfer buffers, arch x86): IoAllocateMdl (dump 3723) takes the request buffer VA and length (local_1c, local_8); the source of local_1c and whether it is probed before the MDL is built were not traced in this pass (no direct MmProbeAndLockPages call found). The mapping at dump 3530 uses KernelMode, so it is a kernel view of the locked buffer. Writes from device data into the request buffer are a USB-device data path, not a caller-chosen kernel destination. Architecture BLOCKED; not graded for write quality.

## 2 Verdict

**BLOCKED (architecture).** libusb0_AA7D75A4.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
