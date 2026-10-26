# Audit: mccfwld_05370B16.sys

| Field | Value |
|---|---|
| File | drivers\mccfwld_05370B16.sys |
| SHA-256 | 05370B16E9EBF30AD0FEF6FE7249C039388026C9D96C63D63B78F076098A603B |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: not run (imports sufficient) |
| Company / version | Measurement Computing Corporation.; file version 1.0.6.0; "MCC Firmware Loader" |
| Signature | Authenticode Valid; signer CN="Digilent, Inc.", O="Digilent, Inc.", L=Pullman, S=Washington, C=US, SERIALNUMBER=602 028 179, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Washington, OID.1.3.6.1.4.1.311.60.2.1.3=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1751560369 |
| Reach | n/a (architecture). Device model: MCC firmware loader. No device name or SDDL string. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, WDFLDR.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): RtlCompareMemory, RtlCopyUnicodeString, memset.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: Imports: RtlCopyUnicodeString, memset, KeBugCheckEx, RtlCompareMemory only. No mapping API, no copy-to-user path visible. KMDF.

## 2 Verdict

**BLOCKED (architecture).** mccfwld_05370B16.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see §1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
