# Audit: EL_Display_vhidbus_ECE1CE28.sys

| Field | Value |
|---|---|
| File | drivers\EL_Display_vhidbus_ECE1CE28.sys |
| SHA-256 | ECE1CE28A756E2B307AD54148BB070D930FD2C8007F028B6E58318C61061015A |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: not run (imports sufficient) |
| Company / version | DEVGURU Co., LTD.(www.devguru.co.kr); file version 2,9,2,0; "DGVHID Bus" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1624929360 |
| Reach | n/a (architecture). Device model: Device: IoCreateDevice (unnamed); ZwSetSecurityObject applies the only SDDL string in the image, D:P(A;;GA;;;SY)(A;;GA;;;BA) (SYSTEM and Administrators full access). Admin-only DACL: in scope (R2) if the device is reached through this descriptor. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | yes |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, WMILIB.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePoolWithTag, HalGetAdapter, HalGetBusDataByOffset, HalSetBusDataByOffset, IoCreateDevice, RtlCopyUnicodeString, RtlCreateSecurityDescriptor, RtlGetDaclSecurityDescriptor, RtlGetGroupSecurityDescriptor, RtlGetOwnerSecurityDescriptor, RtlGetSaclSecurityDescriptor, RtlLengthSecurityDescriptor, RtlSetDaclSecurityDescriptor, SeCaptureSecurityDescriptor, ZwCreateKey, ZwSetSecurityObject, memcpy, memset.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: HalSetBusDataByOffset writes PCI configuration space (HW-ONLY). No kernel memory mapping imported. Memory-write primitive: none visible in imports.

## 2 Verdict

**BLOCKED (architecture).** EL_Display_vhidbus_ECE1CE28.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
