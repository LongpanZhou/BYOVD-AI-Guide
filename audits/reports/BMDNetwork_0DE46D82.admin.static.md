# Audit: BMDNetwork_0DE46D82.sys

| Field | Value |
|---|---|
| File | drivers\BMDNetwork_0DE46D82.sys |
| SHA-256 | 0DE46D8290CEFBCAE012A06ACE5EB25E4010D628C6E0B3849AC25B3B261B5982 (verified with Get-FileHash) |
| Analysis date | 2026-10-25 |
| Method | Static, Ghidra 12.1.4 headless dump (`ghidra_dump\out_c1\BMDNetwork_0DE46D82.txt`, 204 functions, `=== DONE` at last line). REA not used. |
| Reach | R3 (NDIS miniport; loads only with the Blackmagic PCI network hardware enumerated) |
| Setup required | hardware |
| Write quality | W0 |
| Severity | NO-MEMORY-WRITE |
| HW-only | yes (BAR mapping and PCI config write only; no kernel memory write found) |

Identity (Get-AuthenticodeSignature / VersionInfo): Company Blackmagic Design; FileVersion 0.01.00.0000; signature Valid, Microsoft WHCP (`CN=Microsoft Windows Hardware Compatibility Publisher`).

## 1 Internals

- Driver type: NDIS miniport. Imports are NDIS.SYS and NTOSKRNL.EXE (EXT list, dump lines 3-~120). No `IoCreateDevice`, no `IoCreateSymbolicLink`, no `WdfDeviceCreate`, no `IoGetDeviceProperty`-based device object, and no `NdisMRegisterDevice` import.
- Registration: `NdisMRegisterMiniportDriver` at line 6815 in `FUN_14000e000 @ 14000e000` (header line 6754).
- Dangerous imports: `MmGetPhysicalAddress` (EXT, line 14), `NdisMMapIoSpace` (EXT), `NdisMUnmapIoSpace` (EXT), `NdisMSetBusData` (EXT), `NdisMAllocateSharedMemory` / `NdisMFreeSharedMemory` (EXT).

## 2 Entry / device / interface / effective DACL

- No driver-created device object. NDIS creates the miniport adapter; there is no named `\Device\` object or symbolic link in this image.
- Consequently there is no SDDL or DACL argument in the driver. The effective DACL question does not apply to an NDIS miniport with no device object. (The effective access control is the NDIS and network-stack path, section 4.)
- WMI registration: `IoWMIRegistrationControl(DAT_140008000, 0x80000002)` at line 6411 (`FUN_14000c810 @ 14000c810`, header 6394) and `IoWMIRegistrationControl(&DAT_140008100, 0x80010001)` at line 6442 (`FUN_14000c880 @ 14000c880`, header 6419). WMI data blocks are a possible administrator-reachable surface; not analysed further (section 8).

## 3 Dispatch and IOCTL table

- No IRP dispatch table and no IOCTL codes in this image. NDIS delivers OIDs and NetBuffer lists to the miniport. No `IRP_MJ_DEVICE_CONTROL` routine is present (no user-mode IOCTL surface).
- IOCTL table: none. Empty by design for an NDIS miniport.

## 4 Access-control audit

- No `SeSinglePrivilegeCheck`, `SeAccessCheck` or caller-identity check in the image.
- Packet and OID paths are reached through the NDIS stack. The adapter exists only with the PCI device present (`NdisMMapIoSpace` mapping from the NDIS resource list, section 5 item 1). Reach: R3 hardware.

## 5 Memory-write trace

1. **BAR mapping (fixed, PnP-assigned):** `NdisMMapIoSpace(plVar1, *param_1, *(lVar5 + 0xc + uVar7*0x14), *(lVar5 + 0x14 + uVar7*0x14))` at line 6693, inside `FUN_14000cd24 @ 14000cd24` (header 6644). The physical base and length come from the NDIS allocated-resource list `lVar5` (not from a caller). Fixed-window MMIO, so HW-only.
2. **PCI config write:** `NdisMSetBusData(**(param_1+8), 0, param_2, local_res18, 2)` at line 3663, inside `FUN_140006130 @ 140006130` (header 3655). It writes a 16-bit value from `param_3` (a register offset parameter, line 3655). This is PCI configuration space, which is HW-only per the scale.
3. **Packet data physical address:** `MmGetPhysicalAddress(uVar9)` at line 2778, inside `FUN_140004ef0 @ 140004ef0` (header 2725). `uVar9` is the packet data pointer returned by `NdisGetDataBuffer` (line 2760-2762). The address is passed to the DMA descriptor logic (`FUN_140004dd4` / `FUN_140004bd0` / `FUN_140004d04`). It is read-only use; no kernel write target is chosen by the caller.
4. **Shared memory allocation:** `NdisMAllocateSharedMemory(...)` at line 3571, inside `FUN_140005f50 @ 140005f50` (header 3561). Driver-owned DMA memory, not caller-controlled.

Write classification:

- Target control: none. No caller-chosen kernel address reaches a write (items 1-4).
- Value control: PCI config write value comes from the NDIS/driver path (item 2), not from a user-mode caller.
- Size control: fixed by NDIS (items 1, 4).
- Kernel write: none found.

## 6 Most dangerous exposed capability

PCI config space write via `NdisMSetBusData` (`FUN_140006130`, line 3663) and BAR MMIO through `NdisMMapIoSpace` (`FUN_14000cd24`, line 6693). Both are HW-only. Reaching the config-write helper requires the miniport's own internal call paths; no direct user-facing caller was traced.

## 7 Verdict

- Severity: **NO-MEMORY-WRITE** (HW-only). Reach R3 (Blackmagic NDIS miniport; needs the PCI device), setup `hardware`, write quality W0. Signed (WHCP).
- No kernel memory write from caller input in the analysed paths. The only `MmGetPhysicalAddress` call reads a packet buffer's PA. The mapped BARs and shared memory are fixed by PnP/NDIS.

## 8 Limitations

- NDIS OID handler table (`MiniportOidRequest`) was not traced; no OID path was checked for caller-controlled writes. A detailed OID-to-`NdisMSetBusData` path check remains.
- WMI data block handlers (`IoWMIRegistrationControl` at lines 6411/6442) were not decoded; WMI reachability from administrator context is unverified.
- Device-side DMA semantics not modelled.
- Hardware required: no dynamic analysis.
