# Audit: BbUBus51_4D52F9D9.sys

| Field | Value |
|---|---|
| File | drivers\BbUBus51_4D52F9D9.sys |
| SHA-256 | 4D52F9D901535C21434FC3AE1D5C35717FB72C86C0B351D85BFEA4064C44BAC8 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\BbUBus51_4D52F9D9.txt): MmMapIoSpace used on the PnP QueryResources path (dump 16495-16525) to map the device resource ranges from the PnP list; the mapped pointer is not traced to an IOCTL write |
| Company / version | Brainboxes Limited; file version Version 5.1.132.0; "Brainboxes Boost.Software Bus Driver" |
| Signature | Authenticode Valid; signer CN=Brainboxes Ltd, O=Brainboxes Ltd, L=Liverpool, C=GB, SERIALNUMBER=03245094, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.3=GB |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1604420185 |
| Reach | n/a (architecture). Device model: Bus enumeration for Brainboxes USB-serial bus; IoCreateDevice, IoCreateSymbolicLink, IoRegisterDeviceInterface. Device strings \DosDevices\ and \Device\. No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll, WMILIB.SYS, USBD.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePool, IoCreateDevice, MmMapIoSpace, RtlCompareMemory, ZwCreateKey, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: MmMapIoSpace (dump 16515) maps BAR/memory ranges taken from the PnP resource list (FUN_0001ff54 results, dump 16510-16516), not from a caller-supplied address. Brainboxes bus driver: memcpy sites at dump 6517-8398 copy device/USB buffers with lengths from device fields and IOCTL inputs; the 0x22xxxx IOCTL switch (dump 9339-9385) was not read in full. Static primitive: PnP-derived MmMapIoSpace mapping; a write through it would need an IOCTL path that was not traced (see Limitations).

## 2 Verdict

**BLOCKED (architecture).** BbUBus51_4D52F9D9.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
