# Audit: libusbK_6265AE9A.sys

| Field | Value |
|---|---|
| File | drivers\libusbK_6265AE9A.sys |
| SHA-256 | 6265AE9AE5C49F515613F0B749AD8390A1B34CA326203318BFFEB6C2C281D2D0 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: not run (imports sufficient) |
| Company / version | http://libusb-win32.sourceforge.net; file version 3.0.7.0 built by: WinDDK; "libusbK(lusbk) WDF USB Driver" |
| Signature | Authenticode Valid; signer CN=Travis Lee Robinson, O=Travis Lee Robinson, L=Meridian, S=Idaho, C=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1398615991 |
| Reach | n/a (architecture). Device model: Device symlink \DosDevices\libusb0-. No SDDL string. Effective DACL default. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, USBD.SYS, WDFLDR.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePoolWithTag, RtlCopyUnicodeString, memcpy, memmove, memset.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: No mapping API imported. memcpy and memmove present (internal copies, not traced). KMDF (WDFLDR). No kernel-VA write primitive visible in imports.

## 2 Verdict

**BLOCKED (architecture).** libusbK_6265AE9A.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
