# Audit: plser64_1_709ACAA8.sys

| Field | Value |
|---|---|
| File | drivers\plser64_1_709ACAA8.sys |
| SHA-256 | 709ACAA8F806EFA4DFDC0479B3761E5889880C05273901D0B0C7AC918509F7DD |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`scratchpad\ghidra_dump\out_c1\plser64_1_709ACAA8.txt`, complete, 326+ lines of header plus about 25,000 lines of decompile). Import triage; SDDL located in the image (VA 0x140047760, UNICODE_STRING header VA 0x140047750) and its use traced to dump 23038-23039; EvtIoDeviceControl-style switch (dump 500-2104+) located, first cases read. Get-FileHash and Get-AuthenticodeSignature. Nothing loaded or executed. |
| Company / version | Prolific Technology Inc.; file version 5.2.10.2; "USB-to-Serial Cable Driver" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher |
| Reach | R1 for opening the device, if the effective descriptor below is applied (WD = Everyone gets GR|GW). R3 (devnode / hardware: a Prolific USB-serial adapter must be attached) for the device to exist. |
| Setup required | devnode (hardware present) |
| Write quality | not finalized (PROVISIONAL, see §5 and §8) |
| Severity | NO-MEMORY-WRITE (PROVISIONAL) |
| HW-only | no |

Legend: "dump lines" are line numbers in the Ghidra dump. Image base 0x140000000.

## 1 Internals

- PE32+ x64 KMDF USB-to-serial driver (Prolific PL2303 family, WDF imports `WdfVersionBind`/`WdfVersionUnbind`/`WdfVersionBindClass`/`WdfVersionUnbindClass`). WDF calls go through `DAT_14004a458` and `PTR__guard_dispatch_icall_140047150`; WDF function indices are not named in the dump.
- Imports: `RtlQueryRegistryValues`, `RtlWriteRegistryValue`, `RtlDeleteRegistryValue`, `RtlGetVersion`, `RtlVerifyVersionInfo`, `RtlIsNtDdiVersionAvailable`, `MmGetSystemRoutineAddress` (resolves `RtlQueryRegistryValuesEx`, dump 97-98), `MmQuerySystemSize`, `IoGetConfigurationInformation`, `DbgPrint`, `KeQueryPerformanceCounter`.
- No MmMapIoSpace, MmMapLockedPagesSpecifyCache, MmCopyMemory, ZwMapViewOfSection, MmGetPhysicalAddress or ProbeForWrite import. `memcpy` and `memmove` are imported (CRT copies), and their call sites were not individually traced.

## 2 Entry / device / interface / effective DACL

- Device name strings in the image: `\Device\ProlificSerial`, `\DosDevices\`.
- **SDDL in the image:** `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)`, a UNICODE_STRING at VA 0x140047750 (Length 0x6E, MaximumLength 0x70, Buffer VA 0x140047760).
- Application: the descriptor is passed at dump 23038-23039 to a WDF function-table entry (`DAT_14004a458`) with the device handle and an output pointer. The WDF function is not named in the dump; this is the call that applies the descriptor under the assumption that it is the device's security descriptor (PROVISIONAL).
- Effective DACL (as applied, if that call is the security call): SYSTEM GA; Administrators GR|GW|GX; **Everyone (WD) GR|GW**; RESTRICTED CODE (RC) GR. Under this descriptor an unprivileged user can open the device for read and write, which makes the reach R1 for the open.

## 3 Dispatch and IOCTL table

- The WDF request dispatch (dump 500-2104+) uses WDF retrieve calls for request buffers with explicit minimum sizes (for example `(*(code*)PTR__guard_dispatch_icall_140047150)(DAT_14004a458, param_2, 1, &buf, &len)`, dump 517, 537). The switch is on the IOCTL code `param_5`.
- Codes with case labels found (first dump line): 0x222580 (514), 0x222090 (535), 0x222018 (1263), 0x222000 (1291), 0x222004 (1306), 0x222008 (1318), 0x22200C (1332), 0x222010 (1341), 0x222014 (1351), 0x22201C (1361), 0x222020 (1370), 0x222024 (1379), 0x222028 (1389), 0x22202C (1397), 0x222030 (1407), 0x22203C (1408), 0x222040 (1253), 0x222050 (1433), 0x222054 (1462), 0x222058 (1491), 0x22205C (1526), 0x222060 (1561), 0x222064 (1603), 0x222068 (1640), 0x22206C (1651), 0x222070 (1419), 0x222074 (1663), 0x222078 (1674), 0x22207C (1684), 0x222080 (1694), 0x222084 (1708), 0x222088 (1718), 0x22208C (1733), 0x2220A0 (1832), 0x2220A4 (1841), 0x2220B4 (1849), 0x2220B8 (1883), 0x2220BC (1917), 0x2220C0 (1966), 0x2220C4 (1768), 0x2220C8 (2015), 0x2220CC (2056), 0x2220D0 (2065), 0x2220D4 (2075), 0x2220D8 (2090), 0x2220DC (2104), 0x222094 (1809), 0x222098 (1819), 0x2224B4 (1756), 0x2224F8 (1746), and others not read.
- Method and access bits are not decoded per code in this pass; all codes are DeviceType 0x22 (see §8).
- Per-case bodies were not read beyond the first cases (0x222580 at 514-533, and 0x222090 at 535-539). Those cases use WDF-retrieved buffers with minimum sizes from the request.

## 4 Access-control audit

- No privilege check in the dispatch (no `SeAccessCheck`/`SeSinglePrivilegeCheck` found in the decompile by name). The gate is the device's security descriptor (§2).

## 5 Memory-write trace

- Writes to request buffers in the traced cases (0x222580: `*puVar14 = local_a0[0]`, `*local_a8 = bVar27`, dump 521, 530) are to WDF-retrieved buffers after a successful retrieve (`if (-1 < iVar9)`, dump 518). Their sizes are the WDF minimum-size argument (1 byte) — bounded.
- Writes into driver structures (`puVar12[...]`, `*(ushort*)((longlong)puVar12+0x3f6)`) are fixed-offset.
- memcpy/memmove sites were not enumerated. These are the open candidates: a user-length copy into a driver or request buffer would sit there.

## 6 Most dangerous exposed capability

- Not established. Under the R1 descriptor the vendor IOCTL family is openable by any user; the copy sites in the untraced cases decide the verdict.

## 7 Verdict

**NO-MEMORY-WRITE (PROVISIONAL).** The traced cases write only WDF-validated 1-byte buffers and fixed driver fields. The memcpy sites and the vendor cases are not traced, so the verdict is not final. Because the device descriptor grants Everyone read/write (R1 open), any write found in the untraced cases would be rated at R1 reach. Setup: devnode. HW-only: no. Signed (Valid).

## 8 Limitations

- Vendor IOCTL case bodies (dump 535-2104+) and memcpy/memmove call sites were not read; the verdict must be finalized after they are traced.
- The WDF function at `DAT_14004a458` used for the descriptor application (dump 23038-23039) and for request retrieval is not named. The descriptor application is taken from the call pattern and is PROVISIONAL.
- Method and access bits per IOCTL code were not decoded.
- No REA session used. No execution, no driver load, no registry writes.
