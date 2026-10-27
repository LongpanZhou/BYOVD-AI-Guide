# Audit: mxuwdrv2,3_96105CDC.sys

| Field | Value |
|---|---|
| File | drivers\mxuwdrv2,3_96105CDC.sys |
| SHA-256 | 96105CDCFC5D2027D74D17B04BC375F241B57B8A643409B68AA1834F46C6AAFE |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: not run (imports sufficient) |
| Company / version | Moxa Inc.; file version 4.3 Build 26010215; "UPort 1110/1130/1150 Device Driver" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US |
| Architecture | ARM64 (PE32+); machine 0xaa64; built 1767768125 |
| Reach | n/a (architecture). Device model: Devices: \Device\SerBus%0d, \Device\UMP%%d, \Device\UMPLDR%%d, \Device\mxuport%d; symlink \DosDevices\. No SDDL string. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, USBD.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePool, IoCreateDevice, RtlCopyUnicodeString, ZwCreateFile, ZwCreateKey.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: No mapping API imported (no MmMapIoSpace, MmMapLockedPagesSpecifyCache, ZwMapViewOfSection). Copy helpers RtlCopyUnicodeString, strncpy. No kernel-VA write primitive visible in imports.

## 2 Verdict

**BLOCKED (architecture).** mxuwdrv2,3_96105CDC.sys is ARM64 (PE32+) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
