# Audit: AVerPL33_75F3DAE3.sys

| Field | Value |
|---|---|
| File | drivers\AVerPL33_75F3DAE3.sys |
| SHA-256 | 75F3DAE38505764340EF178BE4EA650EB98B6C8F4A5D5F8AFB4609C5177DD197 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\AVerPL33_75F3DAE3.txt, arch x86): PedDmaBufferAlloc (FUN_00096f20 region, dump 66130-66163): IoAllocateMdl over a request VA and length (*param_2, param_2[1]) then MmProbeAndLockPages(MDL, KernelMode, IoWriteAccess) at 66163; a helper at dump 162-172 uses UserMode for its probe (correct for user buffers); PnP resource mapping MmMapIoSpace at dump 66982 (PciStartDevice, CmResourceTypeMemory from the PnP list, not caller-controlled) |
| Company / version | AVerMedia TECHNOLOGIES, Inc.; file version 3.3.0.52; "AVerMedia H264 Codec Driver" |
| Signature | Authenticode NotSigned; signer none |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1405491630 |
| Reach | n/a (architecture). Device model: AVerMedia PL33 capture driver (x86). PnP resource handling (PciStartDevice), DMA buffer allocation (PedDmaBufferAlloc). No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.DLL, ks.sys, USBD.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePool, ExAllocatePoolWithTag, ExFreePool, ExFreePoolWithTag, IoAllocateMdl, IoFreeMdl, IoGetDmaAdapter, MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages, READ_PORT_BUFFER_UCHAR, READ_PORT_BUFFER_ULONG, READ_PORT_BUFFER_USHORT, READ_PORT_UCHAR, READ_PORT_ULONG, READ_PORT_USHORT, READ_REGISTER_BUFFER_UCHAR, READ_REGISTER_BUFFER_ULONG, READ_REGISTER_BUFFER_USHORT, READ_REGISTER_UCHAR, READ_REGISTER_ULONG, READ_REGISTER_USHORT, RtlCompareMemory, WRITE_PORT_BUFFER_UCHAR, WRITE_PORT_BUFFER_ULONG, WRITE_PORT_BUFFER_USHORT, WRITE_PORT_UCHAR, WRITE_PORT_ULONG, WRITE_PORT_USHORT, WRITE_REGISTER_BUFFER_UCHAR, WRITE_REGISTER_BUFFER_ULONG, WRITE_REGISTER_BUFFER_USHORT, WRITE_REGISTER_UCHAR, WRITE_REGISTER_ULONG, WRITE_REGISTER_USHORT, ZwCreateFile, ZwCreateKey, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Candidate primitive (x86 build; not graded, architecture BLOCKED): PedDmaBufferAlloc locks a request-supplied VA/length for write with a KernelMode probe (dump 66163), so a caller-chosen address would not be checked for user range. Whether the DMA buffer allocation IOCTL reaches this with an unprivileged caller, and whether the request is METHOD_NEITHER, were not traced. The PnP MmMapIoSpace call (66982) takes ranges from the PnP resource list, not the caller. Verify before sign-off.

## 2 Verdict

**BLOCKED (architecture).** AVerPL33_75F3DAE3.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see §1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
