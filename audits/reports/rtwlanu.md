# Audit: rtwlanu.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\rtwlanu.sys` |
| Recorded SHA-256 | `d6bd2d1ac1251684856d2a6674499881ebd1139d4f1e2f6fb3bc41da40c8034e` (matches triage_index.csv row "RtlWlanu") |
| Company/Version | Realtek Semiconductor Corporation - 1030.52.1216.2025 |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4, x86:LE:64) |
| Verdict | **NO-WRITE** on the verified surface; **full OID/WDI plane unverified - Coverage ~ 55%** |

> Static-only. No driver load, no device open, no IOCTL execution. Addresses at image base `0x140000000`. Binary is large (11,932 procedures / 9,376 strings); recon + targeted decompilation under a time cap, not exhaustive.

---

## Entry surface

NDIS 6 WDI USB Wi-Fi miniport (`NdisMRegisterWdiMiniportDriver` name in the dynamically-resolved name table). Two control-device registrations exist:

1. **FUN_140008df4** (`0x140008df4`, global/early path, spinlock-guarded singleton `DAT_140b31f70`): `NdisRegisterDeviceEx(..., NDIS_DEVICE_OBJECT_ATTRIBUTES{type=0x380180, DeviceName="\Device\Realtek_Wifi_Device", SymbolicName="\DosDevices\Realtek_Wifi_Device"}, ...)` - **no SDDL field set** -> default (admin) SD.
2. **FUN_14047a064** (`0x14047a064`, per-adapter path, GUID-formatted): same names via `NdisRegisterDeviceEx` **with SDDL** `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)(A;;GA;;;AC)` (string `0x1404bcb70`) - decodes to System GA, Administrators GA, **Authenticated Users GENERIC_ALL**, All Application Packages GA. If this path registers the device, **any interactive local user holds a full-rights handle** to the control device.

IOCTLs on an NDIS-registered control device are translated by ndis.sys into OID requests (ndis-owned translation; no METHOD_NEITHER buffers handed directly to this binary's code).

Also present: a client of `\Device\XboxGIP` - FUN_14006e9b0 (`0x14006e9b0`) does `ZwCreateFile` (GENERIC_WRITE) + `ZwDeviceIoControlFile(0x40001C40, in=2 bytes)` against that device (Xbox wireless-controller interop). rtwlanu does **not** create the XboxGIP device; this is an outbound command, not a primitive.

## Memory-write analysis

- **Custom OID set plane** (funnel FUN_140019c60, `0x140019c60`, 3,464 bytes - reached by ndis OID translation, i.e. from the user-openable control device/network stack): custom OIDs `0xFF8190xx` write user bytes into adapter-structure fields at fixed offsets (e.g. `*(ushort*)(ctx+0x1296) = b`, `*(byte*)(pAdapter+0x6934c1) = b`), or delegate: 0xFF81904A -> FUN_1400d8e20 (`0x1400d8e20`), 0xFF819052 -> FUN_14011a2e0, 0xFF819056 -> FUN_14011a268, 0xFF819057 -> FUN_1400d8c20 (`0x1400d8c20`), 0xFF81908D -> FUN_1400d70a4.
- Spot-checked copy paths FUN_1400d8e20 and FUN_1400d8c20: **every branch reads a fixed count (1-4 bytes) and writes single bytes/words at fixed struct offsets** - bounded per-command by `param_3` length gates (`if (param_3 < 4) return 9;`, `if (1 < param_3)`-style preambles). No memcpy of a user-supplied length into a fixed kernel buffer; no indexxsize arithmetic on user values.
- **MmMapLockedPagesSpecifyCache**: name present in the INIT-section resolution table (`0x140b52532`) - dynamically resolved; caller sites not isolated in the audited window. No `MmProbeAndLockPages` on user MDLs, no `MmCopyMemory`, no `ZwOpenSection`, no `\Device\PhysicalMemory`, no MSR/segment-table names.
- **METHOD_NEITHER**: no custom METHOD_NEITHER dispatch found in the custom surface; buffer ownership is ndis.sys's.
- Unverified remainder (~45%): full OID_GEN/DOT11 set handlers, WDI task paths, USB transfer plumbing where the dynamically-resolved mapping API may be used (kernel-issued transfer buffers by NDIS convention).

## Memory-touching IOCTL table

Direct IOCTL handlers in this binary: none - the control device's MJ_DEVICE_CONTROL is ndis.sys-owned and becomes OID traffic. The only Zw IOCTL is outbound `0x40001C40` -> `\Device\XboxGIP` (2 bytes, FUN_14006e9b0).

## Verdict + VM confirmation plan

**NO-WRITE** (verified surface). The custom-OID control plane writes fixed-size, fixed-offset config values only; no unchecked copy/fill, no probe-less buffers, no physical-memory or mapping primitive found. The unverified remainder (full WDI OID/USB planes) is flagged in the verdict line; nothing observed suggests a write primitive there, and the SDDL-AU=GA control device is an input/config-control surface (out of scope this round).

VM plan (non-destructive): standard user opens `\\.\Realtek_Wifi_Device` (expect success when the AU=GA path registers it) and sends a custom OID via the ndis translation (e.g. `0xFF81903F` no-op) to confirm reachability; no corruption test warranted - no primitive to trigger.

*End of report.*
