# Audit: MOZAWindowsDriver_3331E368.sys

| Field | Value |
|---|---|
| File | drivers\MOZAWindowsDriver_3331E368.sys |
| SHA-256 | 3331E3685BDF45F4C8DD02569E7B537A23504BB1351970C97F655EA49ED16B46 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: not run (same source family as MOZAWindowsDriver_06676A68; in-object write not checked) |
| Company / version | MOZA Racing Team; file version v1.0.1.13 Commit: (x86); "MOZA WINDOWS DRIVER" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1705373323 |
| Reach | n/a (architecture). Device model: KMDF; device-interface notification path. No SDDL string in the image except the PDB path. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, WDFLDR.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePoolWithTag, RtlCompareMemory, RtlCopyUnicodeString, memcpy, memset.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: No mapping API imported. memcpy present. Imports cannot show in-object writes; the x64 sibling (MOZAWindowsDriver_06676A68) has a constrained in-object write through its SetKeysMap IOCTL. This x86 build was not decompiled and this report does not claim the write exists or not.

## 2 Verdict

**BLOCKED (architecture).** MOZAWindowsDriver_3331E368.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see §1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
