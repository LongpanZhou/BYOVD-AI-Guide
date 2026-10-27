# Audit: SmartSAMD.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\SmartSAMD.sys` |
| Recorded SHA-256 | `4EF7BE37F92557C8B0D30999541F284CC4A3E8FD98E0D78146F9F00D54E11BB9` (matches triage_index.csv row 60; verified before opening; REA reports the same digest) |
| Company/Version | Microsemi Corporation, 1.50.1.0 (triage row). StorPort miniport for Microsemi SmartRAID/SmartHBA controllers (driver string: "Storport Miniport Driver for SmartRAID/SmartHBA Controller"). Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope, **deep-form (partial)**: StorPort miniport, so the SRB_IO_CONTROL path reachable through IOCTL_SCSI_MINIPORT was reviewed in part (dispatch, CSMIALL dispatcher, CC1 and CC3 handlers, HwAdapterControl) |
| Verdict | **WRITE-MEDIUM (conditional, coverage-limited, ~35%)**. Two CSMI handlers store past the buffer bound implied by the caller-supplied `SRB_IO_CONTROL.Length`. The top-level check bounds `Length` against the real DataTransferLength, but the stores themselves are fixed-size. Worst case: a 28-byte zero or constant write past the end of the IOCTL buffer. Conditions: the IOCTL path is admin-gated (ACL not traced) and the device-level gate `FUN_14001bd10` passes (not reviewed) |
| Coverage | ~35%. Reviewed: DriverEntry `FUN_140021f34`, HwAdapterControl `FUN_140001010`, HwStartIo dispatch `FUN_140022610` (function-2 branch), SRB_IO_CONTROL dispatcher `FUN_140016a2c`, CSMIALL dispatcher `FUN_1400170f4`, CC3 handler `FUN_140018744`, CC1 handler `FUN_1400188b0`. Not reviewed: CC2 `FUN_1400185d8`, CSMIARY `FUN_140017638`, CSMISAS `FUN_140017a3c`, FIRMWARE `FUN_14001825c`, the inline CSMIPHY block, gate `FUN_14001bd10`, HwBuildIo `FUN_1400070a0`, HwInitialize `FUN_1400136d0`, HwFindAdapter `FUN_140010790`, HwInterrupt `FUN_14001bfd0`, HwResetBus `FUN_140026b30`, HwTracingEnabled `FUN_140021f10`, the rest of HwStartIo (SCSI execution paths), and the callers of the memset helper at `0x14002d940` |

> **Static-only.** No load, no device open, no IOCTL sent, no SRB issued. Addresses are REA default-space linked VAs (image base 0x140000000). The REA session was shared with another agent that switched targets repeatedly. Every result whose subject digest was not SmartSAMD was discarded; no fact below comes from a foreign-digest result.

## Entry surface

- **No device object of its own.** `Io` sweep empty (no `IoCreateDevice`), no `\Device\` string, no SDDL, no WDF. The port device is created by storport.sys.
- **DriverEntry** is `FUN_140021f34`. It memsets a 0xd0-byte HW_INITIALIZATION_DATA and calls `StorPortInitialize(DriverObject, RegistryPath, &hwInit, 0)`. The layout matches the WDK `storport.h` definition used for HpSAMD (local header `C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\km\storport.h`, line 10864; a local read, not REA evidence). Callbacks: HwInitialize `FUN_1400136d0` (+0x08), HwStartIo `FUN_140022610` (+0x10), HwInterrupt `FUN_14001bfd0` (+0x18), HwFindAdapter `FUN_140010790` (+0x20), HwResetBus `FUN_140026b30` (+0x28), **HwAdapterControl `FUN_140001010` (+0x78)**, **HwBuildIo `FUN_1400070a0` (+0x80)**, HwTracingEnabled `FUN_140021f10` (+0xb0). DeviceExtensionSize 0xabd0, SrbExtensionSize 0x1350, AdapterInterfaceType 5 (PCIBus).
- **StorPortInitialize** has a second reference, `0x14002f098`, that lies outside any recovered procedure (not decoded).
- **Admin gate.** IOCTL_SCSI_MINIPORT on the port device. The ACL is set by storport and was not traced in-file.
- **Imports.** 21 STORPORT functions. Registry imports (`StorPortRegistryRead`/`Write`) are configuration-control and out of scope. No `Mm*`, `Io*`, or `Probe*` imports. The only `mem` hit is a local `memset` at `0x14002d940`.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| Kernel mapping, MDL, or probe | None. `Mm` sweep empty, `Probe` sweep empty | `ev_c18d1f62...`, `ev_6c053aa7...` |
| HwAdapterControl (`FUN_140001010`) | Fixed-offset stores into the Parameters buffer (+4, +6, +8, +0xf). Flag read-modify-write on the device extension. No caller-supplied length is read | `ev_4247f2bf...` |
| HwStartIo SRB function 2 (`FUN_140022610` to `FUN_140016a2c`) | Top-level bounds check: DataTransferLength >= 0x1c and `Length` (+0x18) <= DataTransferLength - 0x1c. The claimed payload is bounded by the real buffer size. This check is correct | `ev_afb9fda7...`, `ev_4388436d...` |
| CSMIALL dispatcher (`FUN_1400170f4`) | ReturnCode stores at fixed +0x14 (inside the 0x1c header, which the caller guarantees). Routes by ControlCode to sub-handlers; gate `FUN_14001bd10(dev, 4, 0, CC)` not reviewed | `ev_424d0187...` |
| CC3 handler (`FUN_140018744`) | `if (Length < 8)` -> ReturnCode 3; otherwise `memset(buf+0x1c, 0, 0x24)`. The store extent reaches +0x40, but the gate only ensures Length >= 8, so the claim is 36 bytes. With DataTransferLength = 36 and Length = 8, the top-level check passes and the memset overruns the buffer by **28 bytes** (zero fill) | `ev_f74c286e...` |
| CC1 handler (`FUN_1400188b0`) | `if (Length < 0x92)` -> ReturnCode 3; otherwise driver strings at +0x1c..+0x2b and +0x6d..+0xa8, 8 bytes at +0x9d, 8 bytes at +0xbe, 4 bytes at +0xc6 (extent +0xca). The claim is Length >= 0x92 (end 0xae). With DataTransferLength = 174 and Length = 146, the top-level check passes and the stores overrun by **28 bytes** (driver constants and strings) | `ev_c1e438b8...` |
| CC2 (`FUN_1400185d8`), CSMIARY (`FUN_140017638`), CSMISAS (`FUN_140017a3c`), FIRMWARE (`FUN_14001825c`), inline CSMIPHY | Not reviewed | - |
| Gate `FUN_14001bd10(dev, 4, 0, CC)` | Not reviewed | - |
| memset helper `0x14002d940` callers | Not counted; not reviewed | `ev_567d552c...` (`mem`) |

## Verdict rationale

WRITE-MEDIUM, conditional. The top-level SRB_IO_CONTROL check in this driver is better than HpSAMD's: it binds the claimed `Length` to the real DataTransferLength. The sub-handlers still use fixed-size stores that are gated on `Length` alone. For CC3 the store extent (+0x40) exceeds the gate's claim (+0x24), and for CC1 the extent (+0xca) exceeds the claim (+0xae). When the attacker sets DataTransferLength to the claimed size, each store overruns the buffer by up to 28 bytes. The content is zeros (CC3) or driver constants and strings (CC1), and the overrun size is fixed. The IOCTL path is admin-gated by assumption (device ACL not traced), and the device-level gate `FUN_14001bd10` was not reviewed, so the verdict stays conditional. Coverage is about 35%.

Escalate to **WRITE-HIGH** if the port device ACL allows non-admin callers, or if the unreviewed CC2, CSMIARY, or CSMISAS sub-handlers also store beyond the claimed size with attacker-influenced offsets.

Drop to **NO-WRITE** if StorPort enforces an IOCTL_SCSI_MINIPORT buffer of at least 0x40 bytes (covers CC3) and 0xca bytes (covers CC1), or if `FUN_14001bd10` is false for ControlCodes 1 and 3 on all shipping hardware.

## Open items

1. Review CC2 `FUN_1400185d8`, CSMIARY `FUN_140017638`, CSMISAS `FUN_140017a3c`, FIRMWARE `FUN_14001825c`, and the inline CSMIPHY block for the same store-beyond-claim pattern.
2. Gate `FUN_14001bd10` for ControlCodes 1-4, and its device-level input.
3. Whether storport.sys enforces a minimum IOCTL_SCSI_MINIPORT buffer (drop condition), and whether DataTransferLength equals the IOCTL buffer size.
4. The second `StorPortInitialize` reference `0x14002f098` (not in a recovered procedure).
5. Not reviewed: HwBuildIo `FUN_1400070a0`, HwInitialize `FUN_1400136d0`, HwFindAdapter `FUN_140010790`, HwInterrupt `FUN_14001bfd0`, HwResetBus `FUN_140026b30`, HwTracingEnabled `FUN_140021f10`, and the callers of the memset helper `0x14002d940`.
6. Device ACL on the port device (the admin gate).

## VM confirmation plan (orchestrator-owned; VM only)

Hardware-gated (Microsemi SmartHBA). Not runnable on the host (stopped driver; admin-gated IOCTL). In a snapshot VM with Driver Verifier special pool enabled for `SmartSAMD.sys`, and an attached adapter or stub:
1. IOCTL_SCSI_MINIPORT with signature `CSMIALL`, ControlCode 3, Length 8, in a 36-byte buffer. A special-pool fault would show the 0x24-byte memset overrunning the buffer.
2. The same with ControlCode 1, Length 146, in a 174-byte buffer. This exercises the stores at +0xbe, +0xc2 (through +0xc6).
3. A 28-byte IOCTL buffer, to test whether StorPort rejects undersized buffers (the drop condition).

Run only in the VM, by the orchestrator. Nothing here is to be run on the host.

## Evidence (REA, retained IDs)

- `ev_c18d1f6288904b330fed95d96d346d757a5d001ba1ff1736d2ff072b61b4ae4a` (`Mm` sweep, empty)
- `ev_7b74eca3e907d8cce4aba3cf165aac578f1da8dc4aeeb673ae348935f899f617` (`Io` sweep, empty)
- `ev_0ece049321c806d3e35f2839b2355612f704b7d6fad08116c327bf2422167a5a` (`Wdf`, empty)
- `ev_508743a838d82f187147a6e9675266e885eefd4bfffd09dda46ca38271f2c666` (`StorPort` sweep, 21 imports)
- `ev_6c053aa71ec804adb55ab811d9acc6d27a878740eefb3578b586874839430232` (`Probe`, empty)
- `ev_567d552c20a7458090cb8456e6fa8cc1d34c075d3b5e5bcce6a02788e6f03f15` (`mem`, `memset` at 0x14002d940 only)
- `ev_83e3a341395d975e9cb674cd46d8b9e27284952ecf716cb1e5a0a72109f68006` (`copy`, empty)
- `ev_22569f9128c08554b8090dd50804d2a994b010e0b1261ed86cc154709aadf0a4` (`(A;`, empty)
- `ev_f807dba6f8f0336fb3d6325ff6792ba1c366578fd41ecd0a2189fed36d69cd6d` (`\Device\`, empty)
- `ev_68349e1c46df1d258cc3f3ca623e2bd10c4fbaac7a5c8f717ae2c1fced21b26b` (xrefs of StorPortInitialize: 0x140022051, 0x14002f098)
- `ev_e1fb4f6387134fa72b74fc99adb6928e396ecc7379c3abc8378df231387f0d28` (0x140022051 -> FUN_140021f34)
- `ev_281c69bbce4d004608cb6ab08833bc8c154524f8ad74676e10069eedcd6cac06` (0x14002f098 -> not in a procedure)
- `ev_49d5c96afe67d8f1d126f11bc5fc2cecbb889f437de142c87af434600471627a` (pseudocode FUN_140021f34, DriverEntry)
- `ev_4247f2bfa51f07f75c81443396dd4472f6d52b17e6d8e8438654485dce448680` (pseudocode FUN_140001010, HwAdapterControl)
- `ev_afb9fda7bada159b1147145091ccbc79462feeaf82bc8c69a0c278afdf52a23c` (pseudocode FUN_140022610, HwStartIo; large output, subject verified in the saved file as SmartSAMD)
- `ev_4388436d6fdb2fb8864450304d32f6e63a1bf482da0b6b9fec3d0c62336f1d11` (pseudocode FUN_140016a2c, SRB_IO_CONTROL dispatcher)
- `ev_424d0187b7ff5e186bdf15206626168662dcc0e4db63c41183cd409bd806dab4` (pseudocode FUN_1400170f4, CSMIALL dispatcher)
- `ev_f74c286e58e3120bd62e1126a1706ce81713c88fc66473a81f22a2ad4f81ce58` (pseudocode FUN_140018744, CC3 memset)
- `ev_c1e438b8be33b88a1304506a59f779baac16bde3e5dad4fe85620d978e14b15d` (pseudocode FUN_1400188b0, CC1 driver-info stores)
- Triage row check: Grep on the SHA returned triage_index.csv line 60.
