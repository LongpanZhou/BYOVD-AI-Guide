# Audit: mccfwld_B38AFACA.sys

| Field | Value |
|---|---|
| File | drivers\mccfwld_B38AFACA.sys |
| SHA-256 | B38AFACA3E72DB5E0DDE3B969509FE5F4D56FC983B821ED146003E4E42D2E182 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: not run (imports sufficient) |
| Company / version | Measurement Computing Corporation.; file version 1.0.6.0; "MCC Firmware Loader" |
| Signature | Authenticode Valid; signer CN=Measurement Computing Corporation, O=Measurement Computing Corporation, L=Norton, S=Massachusetts, C=US, SERIALNUMBER=3958376, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1684516338 |
| Reach | n/a (architecture). Device model: MCC firmware loader. No device name or SDDL string. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, WDFLDR.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): RtlCompareMemory, RtlCopyUnicodeString, memset.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: Imports: RtlCompareMemory, RtlCopyUnicodeString, KeBugCheckEx, KeTickCount, memset only. No mapping API. KMDF.

## 2 Verdict

**BLOCKED (architecture).** mccfwld_B38AFACA.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
