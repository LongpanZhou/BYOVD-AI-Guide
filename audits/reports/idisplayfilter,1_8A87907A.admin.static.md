# Audit: idisplayfilter,1_8A87907A.sys

| Field | Value |
|---|---|
| File | drivers\idisplayfilter,1_8A87907A.sys |
| SHA-256 | 8A87907A72837F014417B6545DFF61EFF4A079C65F51918D5064F8C66CD6C191 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: recommended (SDDL resolution; not run in this pass) |
| Company / version | None; file version None; "None" |
| Signature | Authenticode Valid; signer CN=SHAPE GmbH, O=SHAPE GmbH, L=Stuttgart, S=Baden-Wuerttemberg, C=DE |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1389963882 |
| Reach | n/a (architecture). Device model: Device \Device\idisplaywddm. SDDL candidates in the image: D:P(A;;GA;;;SY); D:P(A;;GA;;;SY)(A;;GA;;;BA); D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR;;;WD)(A;;GR;;;RC); D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC); D:P(A;;GA;;;SY)(A;;GRGX;;;BA). The one passed to ZwSetSecurityObject is not resolved (the x64 sibling idisplayfilter,2 is the same family). |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | unknown |

## 1 Triage

- Imports from: ntoskrnl.exe.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePool, ExAllocatePoolWithTag, ExFreePoolWithTag, IoCreateDevice, RtlCompareMemory, RtlCreateSecurityDescriptor, RtlGetDaclSecurityDescriptor, RtlGetGroupSecurityDescriptor, RtlGetOwnerSecurityDescriptor, RtlGetSaclSecurityDescriptor, RtlLengthSecurityDescriptor, RtlSetDaclSecurityDescriptor, SeCaptureSecurityDescriptor, ZwCreateKey, ZwSetSecurityObject, memcpy, memset.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: No mapping API imported. ZwSetSecurityObject and multiple SDDL strings present, so the effective descriptor depends on the call site (not resolved from triage alone).

## 2 Verdict

**BLOCKED (architecture).** idisplayfilter,1_8A87907A.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
