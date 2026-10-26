# Elgato capture drivers — static audit

Folder: `_collected2\drivers\Elgato\` — **16 `.sys` files, 12 families**. The brief lists 10 families / 14 files. The two extra families, `kinonivad` and `kinonivd`, are in the same folder and are covered here as well.

Method: static only. Ghidra 12.1.4 headless, `AuditCls.java` (imports, device-creation and sink call sites, decompile of each sink-holding function, capped at 300 lines per function). Nothing loaded or installed.

**Limits of this pass:** each decompile has a 120-second timeout and a 300-line cap per function. The functions listed in §5 timed out and were not reviewed. Callback tables (KS properties and pin handlers) were enumerated only by their sink call sites, not one by one. Under the brief's rule, a hardware- or devnode-bound driver is disqualified in one line, so the per-callback audit was not done for these families.

## 1. Verdicts

**All 12 families: NO-WRITE.** Every family is disqualified by policy on setup cost. Each one needs either an attached capture device (USB `VID_0FD9` or PCI `VEN_12AB`) or an INF-installed devnode, and most need both.

| Family | Newest build | Date / version | Setup | Verdict |
|---|---|---|---|---|
| CamLinkPro.X64 | `63F81CE8` | 2021-09-17 / 1.1.0.194 | hardware (USB `0FD9:005C`) + devnode | NO-WRITE |
| CY3014.X64 | `A73163C8` | 2021-08-11 / 1.1.0.194 | hardware (USB `0FD9:004F`) + devnode | NO-WRITE |
| e60MZ0380.X64 | `99118E2D` | 2021-07-06 / 1.1.0.194 | hardware (USB `0FD9:005C`) + devnode | NO-WRITE |
| eMZ0380.X64 | `75F9A47D` | 2020-10-22 / 1.1.0.191 | hardware (USB `0FD9:005C`) + devnode | NO-WRITE |
| ElgatoGC656 | `042CAFD9` | 2015-11-05 / 2.1.1.5 | hardware (USB `0FD9:005C`) + devnode | NO-WRITE |
| ElgatoGC658 | `C4597A53` | 2015-11-05 / 2.1.1.5 | hardware (USB `0FD9:005C`) + devnode | NO-WRITE |
| elgatovirtualcamera | `D216849D` | 2024-04-17 / 1.3.4.97 | devnode (software device, Media class) | NO-WRITE |
| PP.SC0710.X64 | `5D0EDF91` | 2024-03-04 / 1.1.0.202 | hardware (USB `0FD9:005C`) + devnode | NO-WRITE |
| SC0710.X64 | `4CCFDEA2` | 2022-09-20 / 1.1.0.198 | hardware (PCI `12AB:0710`) + devnode | NO-WRITE |
| UB3400.X64 | `825332A7` | 2020-05-07 / 1.1.0.189 | hardware (USB `0FD9:005C`) + devnode | NO-WRITE |
| kinonivad (extra) | `AECF289A` | 2020-12-01 / 6.1.7600 | devnode (INF, Media class) | NO-WRITE |
| kinonivd (extra) | `844635B5` | 2020-11-20 / 10.0.10011 | devnode (INF, Media class) | NO-WRITE |

Other builds are listed in §2. They were not dumped separately.

## 2. Build dedupe

| Family | Other builds (not dumped) | Note |
|---|---|---|
| CamLinkPro.X64 | `D40EA12F` (2020-10-22, 1.1.0.191) | Product name in the older build reads "SC0710 Broadcast…", so the code base is shared. |
| CY3014.X64 | `C56A09B3` (2020-10-22, 1.1.0.191) | Same AVStream base. |
| e60MZ0380.X64 | `BF9A3116` (2020-10-22, 1.1.0.191) | Same file size as `eMZ0380 75F9A47D` (4263688 bytes); hashes differ, not diffed. |
| SC0710.X64 | `21A8968C` (2020-10-22, 1.1.0.191) | Older build. |
| ElgatoGC658 vs GC656 | GC656 is the dumped build for `trans700`/`UB658`. GC658 has the same size (43392) and the same import set, and was dumped separately. |

## 3. Shared findings (all families)

- **Setup:** each family's INF names a hardware ID or the Media class. The INF therefore installs a devnode. Corrections to the master table are in §6.
- **Surface:** KS / AVStream (`KsCreateFilterFactory`, `KsCreateDevice`) or PortCls (`PcInitializeAdapterDriver`). The user reaches the driver through the KS device interface that PnP creates, not through a named device object. None of these families imports `IoCreateDevice` or `IoCreateSymbolicLink`.
- **Sinks seen at import level** (see §4): `MmMapIoSpace` with `MmGetPhysicalAddress` (MMIO map), `IoAllocateMdl` with `MmProbeAndLockPages` and `MmMapLockedPagesSpecifyCache` (MDL user-buffer mapping), `ZwMapViewOfSection` (section mapping), and `ZwCreateFile` (file opens; the binaries reference `\??\C` and `\??\PCI` path strings, per the master table). The targets of the `ZwCreateFile` calls were not traced.

## 4. Per-family detail

### 4.1 CamLinkPro.X64 — `63F81CE8` (newest), `D40EA12F`
- INF: `USB\VID_0FD9&PID_005C`.
- Imports: `KsCreateFilterFactory`, `MmMapIoSpace`, `MmGetPhysicalAddress`, `ZwCreateFile`.
- Entry: `entry` @ `0x1402719d0` → `FxDriverEntryWorker` (KMDF stub).
- KS filter factory: `FUN_14022c6b0` @ `0x14022c6b0`, 9 call sites. **Decompile timed out.**
- MMIO map: `FUN_14024f07c` @ `0x14024f07c`. `MmMapIoSpace` at `0x14024f673`, `MmGetPhysicalAddress` at four sites. The address source is not visible within the 300-line cap.
- `ZwCreateFile`: 13 holder functions, starting `FUN_140253f18` @ `0x140253f18`.
- Verdict: **NO-WRITE** (hardware + devnode).

### 4.2 CY3014.X64 — `A73163C8` (newest), `C56A09B3`
- INF: `USB\VID_0FD9&PID_004F` (GameCapture HD60 S) and a `USB2\` variant.
- Imports: `IoAllocateMdl`, `KsCreateFilterFactory`, `USBD_*`, `ZwCreateFile`.
- MDL holders: `0x14025d7d4`, `0x14025fc24`. `ZwCreateFile` holder: `0x140246790`.
- KS filter factory: 9 call sites. **`FUN_14022f460` @ `0x14022f460` timed out.**
- Verdict: **NO-WRITE** (hardware + devnode).

### 4.3 e60MZ0380.X64 — `99118E2D` (newest), `BF9A3116`
- INF: `USB\VID_0FD9&PID_005C`.
- Imports: `KsCreateFilterFactory`, `MmMapIoSpace`, `MmGetPhysicalAddress`, `ZwCreateFile`.
- MMIO holder: `FUN_14028d254` @ `0x14028d254` (`MmGetPhysicalAddress`, `MmMapIoSpace`).
- `ZwCreateFile`: 7 holders, starting `0x140275f64`.
- **`FUN_14022eca0` @ `0x14022eca0` timed out.**
- Verdict: **NO-WRITE** (hardware + devnode).

### 4.4 eMZ0380.X64 — `75F9A47D`
- INF: `USB\VID_0FD9&PID_005C`.
- Imports: `IoAllocateMdl`, `MmProbeAndLockPages`, `MmMapLockedPagesSpecifyCache`, `ZwMapViewOfSection`, `MmMapIoSpace`, `MmGetPhysicalAddress`, `KsCreateFilterFactory`, `ZwCreateFile`.
- **This is the shape the brief flags most closely.** An MDL is built, locked, and mapped, and a section is mapped as well. Holders: MDL function `0x2b6a0`; `ZwMapViewOfSection` at `0x4dc80` and `0x4e180`; `ZwCreateFile` at `0x99e40`.
- **`FUN_00031b30` @ `0x31b30` timed out.** Its role is unknown and it is not one of the holders above. It was not reviewed.
- Verdict: **NO-WRITE** (hardware + devnode). Disqualified before the MDL path could be assessed.

### 4.5 ElgatoGC656 — `042CAFD9`
- INF: `USB\VID_0FD9&PID_005C`. Version resource: product "trans700", company "UB658".
- Imports: `IoRegisterDeviceInterface`, `KsCreateDevice`, `KsCreateFilterFactory`, `USBD_*`. No MMIO or MDL imports.
- `KsCreateDevice` holder: `0x114c4`. Device-interface registration: `0x139c8`.
- Verdict: **NO-WRITE** (USB hardware + devnode).

### 4.6 ElgatoGC658 — `C4597A53`
- Same size (43392 bytes), same import set, and same version resource as GC656. Hash differs. Verdict: **NO-WRITE** (same reasoning as 4.5).

### 4.7 elgatovirtualcamera — `D216849D`
- INF: `Class = Media`, no hardware ID. This is a software device installed through an INF. Setup cost: devnode.
- Imports: `KsCreateFilterFactory` only. 509 functions, no sink calls outside the KS filter factory.
- Verdict: **NO-WRITE** (devnode).

### 4.8 PP.SC0710.X64 — `5D0EDF91`
- INF: `USB\VID_0FD9&PID_005C`.
- Imports: `KsCreateFilterFactory`, `MmMapIoSpace`, `MmGetPhysicalAddress`, `ZwCreateFile`.
- MMIO holder: `0x14025c614`. `ZwCreateFile`: 15 holders, starting `0x140263c04`.
- **`FUN_1402420e0` @ `0x1402420e0` timed out.**
- Verdict: **NO-WRITE** (hardware + devnode).

### 4.9 SC0710.X64 — `4CCFDEA2` (newest), `21A8968C`
- INF: `PCI\VEN_12AB&DEV_0710&SUBSYS_000E1CFA` (Game Capture 4K60 Pro MK.2). This is a PCIe card, not USB.
- Imports: `KsCreateFilterFactory`, `MmMapIoSpace`, `MmGetPhysicalAddress`, `ZwCreateFile`.
- MMIO holder: `0x1402581cc`. `ZwCreateFile`: 14 holders, starting `0x14025d57c`.
- **`FUN_1402342d0` @ `0x1402342d0` timed out.**
- Verdict: **NO-WRITE** (PCI hardware + devnode).

### 4.10 UB3400.X64 — `825332A7`
- INF: `USB\VID_0FD9&PID_005C`.
- Imports: `IoAllocateMdl`, `MmMapLockedPagesSpecifyCache`, `MmProbeAndLockPages`, `ZwMapViewOfSection`, `KsCreateFilterFactory`, `ZwCreateFile`, `USBD_*`.
- MDL holders: `0x13250`, `0x14320`, `0x176b0`. `ZwMapViewOfSection`: `0x3c9b0`, `0x3ceb0`. `ZwCreateFile`: `0x60900`.
- **`FUN_00025200` @ `0x25200` timed out.**
- Verdict: **NO-WRITE** (USB hardware + devnode).

### 4.11 kinonivad (extra, not in the brief's list) — `AECF289A`
- INF: `Class=Media`. **The `HKR,,Security` line that sets the open ACL is commented out** (`;HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGWGX;;;WD)(A;;GRGX;;;RC)"`). The INF does not apply that DACL.
- Imports: `PcInitializeAdapterDriver` only (PortCls adapter init, not a sink). No MMIO, MDL, or section-mapping sinks. 133 functions.
- Verdict: **NO-WRITE** (devnode). The master table's `INF-SDDL-OPEN` label is wrong (§6).

### 4.12 kinonivd (extra, not in the brief's list) — `844635B5`
- INF: `Class=Media`, same commented-out ACL line as kinonivad.
- Imports: `KsCreateFilterFactory`. 758 functions.
- Verdict: **NO-WRITE** (devnode). The master label `INF-SDDL-OPEN` is wrong for the same reason.

## 5. Decompile timeouts (not reviewed)

| Build | Timed-out function | Address |
|---|---|---|
| CamLinkPro `63F81CE8` | KS filter factory | `0x14022c6b0` |
| CY3014 `A73163C8` | `FUN_14022f460` | `0x14022f460` |
| e60MZ0380 `99118E2D` | `FUN_14022eca0` | `0x14022eca0` |
| eMZ0380 `75F9A47D` | `FUN_00031b30` (MDL candidate) | `0x31b30` |
| PP.SC0710 `5D0EDF91` | `FUN_1402420e0` | `0x1402420e0` |
| SC0710 `4CCFDEA2` | `FUN_1402342d0` | `0x1402342d0` |
| UB3400 `825332A7` | `FUN_00025200` | `0x25200` |

None of these was reviewed. The verdicts above do not depend on them, because the disqualifier applies before any function is reviewed.

## 6. Corrections to `master_drivers.csv`

- **`INF-SDDL-OPEN` for kinonivad and kinonivd is wrong.** The INF line that sets the open ACL is commented out. The DACL that the INF would apply is not active.
- **`NO-DEVICE` is accurate** for all twelve, in the sense that none creates a named device. The real surface is the KS interface created by PnP.

## 7. Next dynamic test (described, not run)

None planned. Every family is disqualified by devnode or hardware. If the policy changed, the first step for `eMZ0380` and `UB3400` would be to review the MDL / section-mapping path (`FUN_00031b30` and the holders in §4.4 and §4.10), because those are the user-buffer shapes.

## 8. NO-WRITE reasons (one line each)

- **CamLinkPro, CY3014, e60MZ0380, eMZ0380, GC656, GC658, PP.SC0710, UB3400:** USB capture hardware with an INF devnode. The user path is the KS interface, which exists only with the device attached.
- **SC0710:** PCIe capture hardware with an INF devnode.
- **elgatovirtualcamera:** software KS device, but it needs an INF devnode.
- **kinonivad, kinonivd:** Media-class INF devnode, with the open ACL commented out.
