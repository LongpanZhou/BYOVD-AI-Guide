# Audit: DigiRlPt_8107C7F3.sys

| Field | Value |
|---|---|
| File | drivers\DigiRlPt_8107C7F3.sys |
| SHA-256 | 8107C7F3D71C50A93FF50AD24F932549FDCE819D8C7FAA60CDF7ED716718E35B |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: not run (imports sufficient) |
| Company / version | Digi International Inc.; file version 4.8.488.0; "Digi RealPort Driver" |
| Signature | Authenticode NotSigned; signer none |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1539386258 |
| Reach | n/a (architecture). Device model: Device created with IoCreateDevice; symbolic link via IoCreateSymbolicLink. Effective DACL not fixed in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, WMILIB.SYS, TDI.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePool, IoAllocateMdl, IoCreateDevice, IoFreeMdl, MmBuildMdlForNonPagedPool, RtlCompareMemory, RtlCopyUnicodeString, ZwCreateFile, memcpy, memmove, memset.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: IoAllocateMdl and MmBuildMdlForNonPagedPool are present, but no kernel mapping of an MDL (MmMapLockedPagesSpecifyCache, MmMapIoSpace, ZwMapViewOfSection) is imported, so no kernel-VA write through an MDL is visible in the imports. Device names in strings: \Device\PS_ / \Device\PSPDO_ / \Device\Tcp (TDI filter). No SDDL string.

## 2 Verdict

**BLOCKED (architecture).** DigiRlPt_8107C7F3.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
