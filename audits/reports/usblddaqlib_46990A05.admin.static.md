# Audit: usblddaqlib_46990A05.sys

| Field | Value |
|---|---|
| File | drivers\usblddaqlib_46990A05.sys |
| SHA-256 | 46990A0524557B0433231BBB9F9195C573A5762C3EFF0FA56ABBAEAB0B84BD58 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: not run (imports sufficient) |
| Company / version | Measurement Computing Corp.; file version 5.0.0 Build 11; "USB-2500 Loader Device Driver" |
| Signature | Authenticode Valid; signer CN="Digilent, Inc.", O="Digilent, Inc.", L=Pullman, S=Washington, C=US, SERIALNUMBER=602 028 179, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Washington, OID.1.3.6.1.4.1.311.60.2.1.3=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1262119374 |
| Reach | n/a (architecture). Device model: Devices created with IoCreateDevice; interfaces via IoRegisterDeviceInterface. No SDDL string. Effective DACL default. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, WMILIB.SYS, USBD.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePool, IoAllocateMdl, IoCreateDevice, IoFreeMdl, MmProbeAndLockPages, memcpy, memmove, memset.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: IoAllocateMdl, MmProbeAndLockPages and MmUnlockPages are present, but no kernel mapping of the locked MDL is imported. No kernel-VA write primitive visible in imports.

## 2 Verdict

**BLOCKED (architecture).** usblddaqlib_46990A05.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see §1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
