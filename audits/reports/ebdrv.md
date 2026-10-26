# Audit: evbda.sys (triage name ebdrv)

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\evbda.sys` |
| Recorded SHA-256 | `48D9F61E943A7855562950FF26B866BD51A27D980757B065504FCD3F1A1D6F07` (matches triage_index.csv row 79; verified before opening; REA reports the same digest) |
| Company/Version | QLogic Corporation, 7.13.65.105 (triage row). KMDF PnP function driver (sibling of `bxvbda.sys` / `b06bdrv`, same 577xx code family). Triage state: **Stopped** (not running on this host) |
| Method | Static-only REA/Ghidra 12.1.4, memory-write scope. Partial deep-form: PnP start, the firmware-table read, and the BAR mapping were reviewed. The device-control (IOCTL) dispatch was **not located** |
| Verdict | **NO-WRITE (provisional, coverage-limited, ~25%)**. The writes reviewed are fixed-destination or sized to their allocation. The decisive path, the device-control dispatch, is not located |
| Coverage | ~25%. Reviewed: import, string, and byte sweeps; `FUN_1400EAC98` (firmware-table read, 345 bytes); `FUN_140003C8C` (PnP start, 1409 bytes); the xrefs of `\Device\PhysicalMemory` and `MmMapIoSpaceEx`; `FUN_14003B268` (59-byte `MmMapIoSpaceEx` wrapper), resolved but not read. Not reviewed: the device-control (`EvtIoDeviceControl`) dispatch and its IOCTL switch; the call sites of `memcpy_s` and of the internal `memset` at `0x1400EAFC0`; the callers of `FUN_14003B268` |

> **Static-only.** No load, no device open, no IOCTL issued. Addresses are linked VAs (image base `0x140000000`).

## Entry surface

- KMDF driver: the WDF loader imports (`WdfVersionBind`, `WdfVersionUnbind`, `WdfVersionBindClass`, `WdfVersionUnbindClass`) are present, and the device objects are created dynamically through the WDF function table. No `IoCreateDevice` import. The `\Device\` strings are `\Device\` (prefix, `0x1400EBF80`) and `\Device\PhysicalMemory` (`0x14011B900`). User openability of any device interface is **not established** in-file (WDF device creation and the default device ACL are not traced).
- The IRP-sending imports (`IoAllocateIrp`, `IofCallDriver`, `IoBuildDeviceIoControlRequest`) show the driver sends requests down its own stack. `IoConnectInterrupt`, `IoGetDmaAdapter`, and `IoGetDeviceProperty` show a hardware-facing PnP role.
- **Byte search:** `24 20 00 80` (little-endian `0x80002024`, the unbounded BAR-write IOCTL in the sibling `b06bdrv`) has **no match** in any initialized block of this binary (complete search). This rules out that specific code only. It does not rule out a similar write under another IOCTL code.
- Init-time firmware read: `FUN_1400EAC98` opens `\Device\PhysicalMemory`, maps the fixed physical range `0x80000`–`0xFFFFF`, scans for an SMBIOS/iBFT signature, copies the table into a pool buffer (tag `iFBT`), unmaps, and closes. No attacker-influenced address; not reachable from a dispatch.

## Memory-write analysis (reviewed scope)

| Pattern | Result | Evidence |
|---|---|---|
| `MmMapIoSpaceEx`, call site `0x1400040F3` (in `FUN_140003C8C`, PnP start) | One 4 KB mapping of the BAR physical address from `FUN_140058398`. Only read use: `FUN_1400EAEE8` reads one value, then `MmUnmapIoSpace`. No write through the mapping | `ev_d33a2999…` (resolve), `ev_3f734767…` (pseudocode) |
| `MmMapIoSpaceEx`, call site `0x14003B28B` (in `FUN_14003B268`, 59 bytes) | Wrapper, body not read; callers not traced | `ev_9986998b…` (resolve) |
| `MmMapIoSpaceEx` third reference `0x14011C070` | Presumably an import-table slot (not verified) | `ev_454d9070…` (xrefs) |
| `\Device\PhysicalMemory` (`FUN_1400EAC98`, init-time) | Read-only section view of the fixed range `0x80000`–`0xFFFFF`. The copy length is taken from the firmware table header and matches the pool allocation (no overflow). A bogus length over-reads the view: a denial-of-service class issue, firmware-controlled, not user reachable | `ev_ec75d30f…` (pseudocode), `ev_84e62d5e…` (resolve), `ev_59120…` see Evidence list |
| `MmGetPhysicalMemoryRanges` | One code reference at `0x140020AD8` (not reviewed); the other reference at `0x14011C250` is presumably an import-table slot | `ev_21812966…` (xrefs) |
| `memcpy_s` (import at `0x44`, thunk `0x14004AAB8`) | Call sites not counted; lengths not reviewed. Decisive | `ev_7f4500e3…` (mem sweep) |
| Internal `memset` at `0x1400EAFC0` | Call sites not counted; lengths not reviewed | `ev_7f4500e3…` (mem sweep) |
| `RtlCopyUnicodeString` (import) | Bounded by the destination's MaximumLength; call sites not reviewed | `ev_bf9e3353…` (copy sweep) |
| Probe and WDF-specific write APIs | None (`Probe` sweep empty; the WDF imports are loader-only) | `ev_59131cc8…` (Probe), `ev_1315b471…` (Wdf) |
| SDDL | None (`(A;` search empty) | `ev_685b6747…` |

## Verdict rationale

NO-WRITE, provisional. The reviewed writes are the init-time firmware copy (sized to its allocation), a read-only BAR mapping at PnP start, and the unreviewed `RtlCopyUnicodeString` (bounded). The decisive path is the device-control dispatch, which I did not locate. The byte search rules out the sibling's specific unbounded BAR write, but not a write of that shape under a different IOCTL code. Escalate to WRITE-* if the device-control handler passes a caller-supplied offset or length to an MMIO or copy sink. Move to deep-form on that handler before the verdict is final.

## Open items

1. **Locate and review the device-control dispatch** (decisive). Queue callbacks are registered during device init. `FUN_140003C8C` sets a set of FDO callback pointers at `+0x1E0`–`+0x248` (for example `FUN_140004FF0`, `FUN_140004EF0`, `FUN_1400050F0`, `FUN_140004C94`), so start with the function that calls `WdfIoQueueCreate`.
2. `memcpy_s` (thunk `0x14004AAB8`) and internal `memset` (`0x1400EAFC0`): count call sites and review their length arguments.
3. `FUN_14003B268` (`MmMapIoSpaceEx` wrapper): find its callers.
4. Firmware-table over-read in `FUN_1400EAC98` (denial-of-service class): recorded, not a write.

## VM confirmation plan (orchestrator-owned; VM only)

Hardware-gated (stopped driver; not run). In a snapshot VM with the adapter present, a read-only check of the device-interface default ACL, and whether any device-control request reaches the handler, without sending an IOCTL that writes.

## Evidence (REA, retained IDs)

- Mm sweep: `ev_9a5d2e1086aa409ebf5395b4e5b5e5b850856a3beabe498585f6521cb88807ef`
- Io sweep: `ev_db27b39376c925ad7fac443553bf218c5d343dbfa30a4b878be9927b27eb80d7`
- Probe sweep: `ev_59131cc8b09e55a0b64520877d619e7033ecf2574877176452c46727c361ef13`
- Wdf sweep: `ev_1315b471894feecdaf9dc40da53f481c65ed8863f259a44e3ecd35184614a022`
- StorPort sweep (none): `ev_3cf1180d345d931fc0d5e81a8b59a7daa248aab32e8f816eb05d92a1d844718d`
- Ndis sweep (none): `ev_42ac91d698d5a0501028548f11e1e1388954e744bbf2afe119188bd946328d0f`
- mem sweep: `ev_7f4500e3005330612e6d401efbaf09d9cc57d44cbb0ba8f6a76bb772a8279318`
- copy sweep: `ev_bf9e3353cb438a5ebbee521f8e8e3dcb02d8fc60755038ccb622d394a239ad7d`
- `(A;` SDDL search: `ev_685b67474bb18c924666872fc5e88251cbdfffd954ba6352d083833399ae1a28`
- `\Device\` strings: `ev_8b5c266832d3973dbb65b2ae2cc7986bacce8ba7d2a920ecc26bd2a1c8c3702a`
- xrefs of `\Device\PhysicalMemory` (`0x14011B900`): `ev_591201b676a0366cdd5fe9616d48a68f171c1575e86a68a48ae357c28e363fb9`
- xrefs of `MmMapIoSpaceEx`: `ev_454d90703c81d080167c6a2f9ccaf086c77e49a0979cfae3db306a5be235994f`
- xrefs of `MmGetPhysicalMemoryRanges`: `ev_218129664146dbac4719196233cd830bec6584fb4d85696f0d996519eb18f8ec`
- resolve `0x1400EACAA` (→ `FUN_1400EAC98`): `ev_84e62d5e5c06a4b188c509fed137e22027dd53e072d6cec4151f81d2f91123b4`
- resolve `0x1400040F3` (→ `FUN_140003C8C`): `ev_d33a2999b419806cd4891ebe9770619fe4fa93e7b29aa9ba67ee7d7b935dc862`
- resolve `0x14003B28B` (→ `FUN_14003B268`): `ev_9986998bc410f5226a5ae6755ba92dc6fdcb18ea1efdb77cdf8ab3f43de68457`
- pseudocode `FUN_1400EAC98`: `ev_ec75d30fc6be29b4d7247e5b605704d824c3b38c2e3185e0aae41fe39673363e`
- pseudocode `FUN_140003C8C`: `ev_3f734767314ca6d75ef648eb54a9b9c63ab9170a78f7870ca7961a987352742e`
- byte search `24 20 00 80` (no match): `ev_8f0de92ccf7c8aff55bb7a6c460215b1d5a6179a4f9af00e9da4697a1ec91cdc`
