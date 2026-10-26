# Audit Status and Queue — canonical

**Last updated:** 2026-10-25
**Scope:** kernel memory-write only; `R2` local administrator is in scope; setup is a severity
field, not a disqualifier; hardware-only writes are `HW-ONLY`.

**This is the single live status source.** Other docs link here instead of copying the queue.

## Corpus

| Bucket | Count |
|---|---:|
| Original host corpus | 94 |
| `collected2` | 135 |
| `collected3` | 11 |
| `collected5` (R1–R4) | 41 |
| `collected1` (S1–S6) | 106 |
| **Total known** | **386** |

- Dedupe index: **932 hashes** - 925 tracked in `indexes\dedupe\existing_hashes.txt` + 7 exported-set hashes in a gitignored local gate file
- Canonical inventory: `indexes\drivers_manifest.csv` (386 unique `.sys`)
- **Exported 2026-10-25:** the verified set (7 files: 3 dynamically verified MW1 driver groups + their 32-bit/IA-64 sibling artifacts) left the repo; names, hashes, IOCTL mappings and logs are not in this repo.
- Known-bad: 5,833 LOLDrivers hashes (`indexes\dedupe\known_bad_hashes.txt`)
- All drivers are flat in `drivers/`; installers/extract trees were deleted 2026-10-24.
- Download URLs and batch metadata: `indexes/collections/`.
- Report names below are relative to `reports/`.

## Current results

| Driver | Verdict | Reach / setup | Report |
|---|---|---|---|
| AIDA64 `kerneld-x64` | **MW2** | R2 / none; signed | `AIDA64_kerneld.md` |
| HP `rtf64x64` | **MW2** | R1/R3; LWF composition required for usable context | `hp_rtf64x64.admin.static.md` |
| `silabser` | **MW2** | R1 / hardware (CP210x); W2 pool OOB | `silabser.admin.static.md` |
| `bxvbda` | **MW2** | R3 / hardware; W1 caller-VA + W2 BAR OOB | `bxvbda.admin.static.md` |
| Sandboxie `SbieDrv` | **MW2** (independent pass disputes; see appendix) | R2 / none; signed | `sbiedrv.admin.static.md`; appendix `sbiedrv.independent.static.md` |
| DirectIo64 | **MW3** | R2 / none; signed | `DirectIo64.md` |
| GPU-Z `nvflash_x64` (`79050454`) | **MW3** | R3 / hardware; signed | `GPUZ_nvflash_x64.md` |
| GPU-Z `nvflash_x64_variant2` + `nvflash_x86` | **MW3** | R3 / hardware; signed | `GPUZ_nvflash_variants.md` |
| ImDisk `imdisk.sys` (amd64) | **MW4** | R2 / none; signed | `imdisk.admin.static.md` |
| Spacedesk `spacedeskDriverBus` | **MW3** | R3 / composition; signed | `spacedesk_bus.admin.static.md` |
| CorsairGamingAudio64 (`64D31B6E`) | **MW3** | R3 / hardware; signed | `corsair_audio64.admin.static.md` |
| ThrottleStop `LowLevel_x64` | **BLOCKED** (static MW3/W3P; MW2 withdrawn) | R2 / none; unsigned | `throttlestop_ll64.admin.static.md` |
| ThrottleStop `LowLevel_x86` | **BLOCKED** (static MW3/W3P) | R2 / none; unsigned; x86-only | `ThrottleStop_LowLevel_x86_and_OCCT_ORingDrv.md` |
| OCCT `ORingDrv` | **NO-MEMORY-WRITE (HW-ONLY)** | R2 / none; signed | `ThrottleStop_LowLevel_x86_and_OCCT_ORingDrv.md` |
| SIVI64 | **BLOCKED** | n/a; IA-64 image | `sivi64.admin.static.md` |
| SIVX64 | **MW3** | R2 / service; signed; W3P | `SIV_variants.md` |
| SIVX32, SIVNT3, SIVNT4, SIVA32, SIVP32 | **BLOCKED** (architecture) | i386 / Alpha AXP / PowerPC | `SIV_variants.md` |
| MSI RTCore32 (`6F818DAF`) | **BLOCKED** (known-bad family; static MW2 reference; not hash-indexed) | R2 / none; signed | `msi_rtcore32_6F818DAF.admin.static.md` |
| ArgusMonitor | **NO-MEMORY-WRITE (HW-ONLY)** | R1 / none | `ArgusMonitor.md` |
| Spacedesk `spacedeskDriverAudio` | **NO-MEMORY-WRITE** | R3 / devnode | `spacedesk_audio.admin.static.md` |
| CorsairVBusDriver64 | **NO-MEMORY-WRITE** (admin-gated UAF residual) | R2 / none; signed | `CorsairVBusDriver64.md` |
| CorsairVHidDriver64 x64 | **NO-MEMORY-WRITE** | R3/composition; signed | `Corsair_VBus32_VHID32_64.md` |
| CorsairVBusDriver32 + VHidDriver32 i386 | **BLOCKED** (i386) | not loadable on x64 | `Corsair_VBus32_VHID32_64.md` |
| CorsairLLAccess64 (1.0.82) | **NO-MEMORY-WRITE (HW-ONLY)** | R2 / none; signed | `CorsairLLAccess64.md` |
| CorsairLLAccess64 (1.0.74) x64 | **NO-MEMORY-WRITE (HW-ONLY)** | R2 / none; signed | `Corsair_LLAccess32_LLAccess64_old_GamingAudio32.md` |
| CorsairLLAccess32 (1.0.82) i386 | **BLOCKED** (i386; static NO-MEMORY-WRITE) | not loadable on x64 | `Corsair_LLAccess32_LLAccess64_old_GamingAudio32.md` |
| CorsairGamingAudio32 i386 | **BLOCKED** (i386; static MW3) | not loadable on x64 | `Corsair_LLAccess32_LLAccess64_old_GamingAudio32.md` |
| CoreTemp `ALSysIO64Legacy` x64 | **BLOCKED** (static MW2) | R2 / none; unsigned | `CoreTemp_ALSysIO64Legacy.md` |
| CoreTemp `ALSysIO64` x64 + Legacy x86 | **BLOCKED** (static MW2) | R2 / none; unsigned | `CoreTemp_ALSysIO64_x64_and_Legacy_x86.md` |
| pcidaqlib ×4 (`4BEC3036`, `4D67C576`, `7519DAC6`, `7CBCD6B0`) | **MW3** (W2 kernel-VA write, R3 hardware cap) | R3 / hardware; signed | `pcidaqlib.md` |
| FPGATEST x64 + x86 | **BLOCKED** (static MW3, W2) | R3 / hardware; unsigned | `FPGATEST_x64_x86.md` |
| Scufdriver5/6 | **NO-MEMORY-WRITE** (W0) | R2 / none; signed | `Scuf_SiUSBXp.md` |
| CBUL32 + CBULWDM | **MW3** | R2 / service or devnode; signed; W3P | `CBUL32_CBULWDM.md` |
| usbdaqlib x64 ×2 (`58D0669F`, `E4056475`) | **MW3** (provisional) | R3/hardware; W2 fixed-pattern write | `usbdaqlib_58D0669F.admin.static.md`, `usbdaqlib_E4056475.admin.static.md` |
| usbdaqlib i386 ×2 (`1D53580B`, `9AF9623D`) | **BLOCKED** (i386) | not loadable on x64 | `usbdaqlib_1D53580B.admin.static.md`, `usbdaqlib_9AF9623D.admin.static.md` |
| usblddaqlib i386 ×2 (`2F015011`, `46990A05`) | **BLOCKED** (i386) | not loadable on x64 | `usblddaqlib_2F015011.admin.static.md`, `usblddaqlib_46990A05.admin.static.md` |
| usblddaqlib x64 ×2 (`9E26A72E`, `CDEC967D`) | **NO-MEMORY-WRITE** (W0) | signed; no mapping APIs | `Collected1_tail.md` |
| Virtual audio group x64 (`VirtualAudioDriver`, `vrtaucbl` x64, `usbaapl64`, `netaapl64`) | **NO-MEMORY-WRITE** (W0) | R2/R3; see report | `Virtual_audio_group.md` |
| Virtual audio i386/ARM64 (`vrtaucbl` x86/arm64) | **BLOCKED** (architecture) | not loadable on x64 | `Virtual_audio_group.md` |
| CoolerMaster `CMUAC` x4 | **BLOCKED** (unsigned; static W0) | R3 / hardware | `CoolerMaster_audio_CPUZ_remaining.md` |
| CoolerMaster `CMTAC_83986D97` x64 | **NO-MEMORY-WRITE** (W0) | R3 / hardware; signed | `CoolerMaster_audio_CPUZ_remaining.md` |
| CoolerMaster `CMTAC_F6772F57` i386 | **BLOCKED** (i386) | not loadable on x64 | `CMTAC_F6772F57.admin.static.md` |
| AVerPL33 x64 | **MW3** | R2 / hardware; W2 pool overflow | `AVerMedia_capture.md` |
| AVerPL33 i386 | **BLOCKED** (i386) | not loadable on x64 | `AVerMedia_capture.md` |
| Moxa `mxusbd` x2 | **MW3** | R3/hardware; signed; W2 pool OOB | `mxusbd,1_477EA31C.admin.static.md`; `mxusbd,2_4DD6AB6A.admin.static.md` |
| MCC I/O family x64 (`mcpci`/`mccusbfn`/`mcusb`) | **MW3** | R2 / hardware; W2 kernel VA + length | `MCC_group.md` |
| MCC I/O family i386 | **BLOCKED** (i386) | not loadable on x64 | `MCC_group.md` |
| MCC `mccfwld` x64 | **NO-MEMORY-WRITE** | no queue/interface/symlink | `MCC_group.md` |
| MCC `mccfwld` i386 | **BLOCKED** (i386) | not loadable on x64 | `MCC_group.md` |
| Brainboxes `BbUBus`/`BbUSer` x64 x4 | **NO-MEMORY-WRITE (HW-ONLY)** | R3 / hardware; signed | `Brainboxes_BbUBus_BbUSer.md` |
| Brainboxes `BbUBus`/`BbUSer` i386 x4 | **BLOCKED** (i386) | not loadable on x64 | `Brainboxes_BbUBus_BbUSer.md` |
| SteelSeries `ssps2` + `ssbthid` | **NO-MEMORY-WRITE** (W0); 5 i386 BLOCKED | R3 / hardware | `SteelSeries_SSPS2_SSBTHID.md` |
| SteelSeries `sshid` + `hidkmdf` | **NO-MEMORY-WRITE** (W0); 6 i386 BLOCKED | R1 `\Device\SSengine` (sshid); R3 HID (hidkmdf) | `SteelSeries_HID_core.md` |
| SteelSeries `msihid` + `sssmbus` | **NO-MEMORY-WRITE** (W0); i386 BLOCKED | R1 open GRGW/GRGWGX | `SteelSeries_MSIHID_SMBUS.md` |
| SteelSeries `STTub30` x64 (9E1CF7F9, 4D7F2B9D) | **MW3** | R3/hardware; W2 pool zero-fill overflow | `SteelSeries_STTub30_VAD.md` |
| SteelSeries `ssdevfactory` x64 ×3 | **MW2** | R1 / composition; W2 caller-address store | `SteelSeries_DevFactory_Xusb21.md` |
| SteelSeries `ssdevfactory` i386 ×2 + `xusb21` i386 ×2 | **BLOCKED** (i386) | not loadable on x64 | `SteelSeries_DevFactory_Xusb21.md` |
| SteelSeries `xusb21` x64 | **NO-MEMORY-WRITE** (W0) | hardware-gated; default DACL | `SteelSeries_DevFactory_Xusb21.md` |
| Netac `SMI_IO` 32/64 | **MW2** | R2 / none; W2 stack overflow + W3P PA map | `NZXT_Netac_HyperX_PawnIO.md` |
| SignalRGB FTDI `ftdibus` x64 (`8C494A63`) | **MW2** | R1/hardware; W2 URB-length pool OOB | `SignalRGB_ROCCAT.md` |
| TeamGroup `nvme` x64 ×3 (`45635E0B`, `A9B48787`, `E4AB6E36`) | **MW2** | R2/hardware; W2 PRP-builder OOB | `TeamGroup_nvme.md` |
| TeamGroup `nvme` i386 ×3 (`35B2D3D4`, `77C8809A`, `FFD83A43`) | **BLOCKED** (i386) | not loadable on x64 | `TeamGroup_nvme.md` |
| LSI SAS (`lsi_sas`, `lsi_sas2i`, `lsi_sas3i`, `lsi_sss`) | **MW3** | R3/hardware; W2 pool overflow | `LSI_Perc_SAS.md` |
| `percsas2i` + `percsas3i` | **NO-MEMORY-WRITE** (W0) | R3/hardware; bounded mailbox path | `LSI_Perc_SAS.md` |
| `megasr` | **MW4** (W3 fixed zero-fill OOB; DCMD resolved W3) | R3/hardware; signed | `megasr.current.md`; appendix `megasr.dcmd.appendix.md` |
| `nvlddmkm` (focused + IOCTL appendix) | **NO-MEMORY-WRITE** (scoped; all 35 IOCTL codes reviewed) | R1 devices; no user-controlled write | `nvlddmkm.focused.md`; appendix `nvlddmkm.ioctl.appendix.md` |
| ROCCAT `ScpVBus` x64 (`B1B85035`) | **NO-MEMORY-WRITE** | child PDO only; user path is internal IOCTL | `SignalRGB_ROCCAT.md` |
| `ftdibus_731AA4E6` + `ScpVBus_A12F3C7C` | **BLOCKED** (i386) | not loadable on x64 | `SignalRGB_ROCCAT.md` |
| HyperX `vachpxkd` x64 | **MW3** | R3 / devnode; W2 METHOD_NEITHER 8-byte write | `NZXT_Netac_HyperX_PawnIO.md` |
| NZXT `SiUSBXp` | **MW3** | R3 / hardware; W2 URB length OOB | `NZXT_Netac_HyperX_PawnIO.md` |
| ElgatoGC656/GC658 | **MW3** | R3 / hardware; W2 KS output-length pool overflow | `Elgato_capture.admin.static.md` |
| Elgato BDA x64 ×11 | **NO-MEMORY-WRITE (HW-ONLY)** | R3 / hardware | `Elgato_capture.admin.static.md` |
| Elgato virtual camera | **NO-MEMORY-WRITE** | length-checked handlers | `Elgato_capture.admin.static.md` |
| Elgato `kinonivad`/`kinonivd` | **BLOCKED** (i386) | not loadable on x64 | `Elgato_capture.admin.static.md` |
| MCHOSE x64 ×14 | **MW3** | R2/hardware; W2 pool OOB + pointer leak | `MCHOSE_audio.md` |
| MCHOSE i386 ×2 | **BLOCKED** (i386) | not loadable on x64 | `MCHOSE_audio.md` |
| NZXT `SiLib` / `cam_driver_mb`; PawnIO | **NO-MEMORY-WRITE** (HW-ONLY for cam) | see report | `NZXT_Netac_HyperX_PawnIO.md` |
| SteelSeries `STTub30` i386 ×2 | **BLOCKED** (i386) | not loadable on x64 | `SteelSeries_STTub30_VAD.md` |
| SteelSeries Engine/Sonar VADs | **NO-MEMORY-WRITE** | R3/PortCls; see report | `SteelSeries_STTub30_VAD.md` |
| `ftser2k_6AD3DC79` + `VirtualHID_43774DE0` | **BLOCKED** (i386) | static W0; not loadable on x64 | `collected2_gaps_ftser2k_VirtualHID.md` |
| Collected3 gaps (5 x64) | **NO-MEMORY-WRITE** (W0) | R2/R3; see report | `collected3_gaps.md` |
| `dlcdcncm660_0FFDDEF9` + `imdisk_arm64` | **BLOCKED** (ARM64) | not loadable on x64 | `collected3_gaps.md` |
| DesktopVideoUpdate ×2 | **NO-MEMORY-WRITE** (W0) | R2; legacy build test-signed | `Collected1_tail.md` |
| EL_Display_vhidbus_3242D1DC | **NO-MEMORY-WRITE** (W0) | R2; OOB read only | `Collected1_tail.md` |
| EL_Display_vhidbus_ECE1CE28 | **BLOCKED** (i386) | not loadable on x64 | `Collected1_tail.md` |
| usblddaqlib ×2 (x64) | **NO-MEMORY-WRITE** (W0) | signed; no mapping APIs | `Collected1_tail.md` |
| Moxa `mxuport` ×2, `mxuwdrv2` ×2, Perle `TruePort` | **NO-MEMORY-WRITE** | signed x64; see report | `S3_Moxa_Digi_Perle.md` |
| Digi/Moxa arch/signing blocked ×7 | **BLOCKED** | ARM64/i386 or signing | `S3_Moxa_Digi_Perle.md` |
| Blackmagic capture group | **MW4** (fixed-target W3 only) | R2/hardware; signed primaries | `Blackmagic_capture.md` |
| iDisplay + Prolific x64 | **NO-MEMORY-WRITE** (W0) | R1/R2; signed | `iDisplay_Prolific.md` |
| iDisplay + Prolific i386 | **BLOCKED** (i386) | not loadable on x64 | `iDisplay_Prolific.md` |
| RtUsbA64, libusb0_8058, libusbK_1DF6, MOZAUSBDriver | **NO-MEMORY-WRITE** (W0) | signed; device-presence gate | `S1_S2_remaining.md` |
| libusb0_AA7D, libusbK_6265, MOZAWindowsDriver_3331 | **BLOCKED** (i386) | not loadable on x64 | `S1_S2_remaining.md` |
| MOZAWindowsDriver_06676A68 | **MW4** (W3) | R3 / hardware | `S1_S2_remaining.md` |
| avmu3 / avmu364 / avmu3gc550 x64 | **NO-MEMORY-WRITE (HW-ONLY)** | R2 / hardware | `AVerMedia_capture.md` |
| avmu3 / avmu3gc550 i386 | **BLOCKED** (i386) | not loadable on x64 | `AVerMedia_capture.md` |
| SiUSBXp32/64 | **BLOCKED** (static MW2) | R2 / none; unsigned; pool OOB write | `Scuf_SiUSBXp.md` |

## Collected1 subagent batch — 2026-10-25

**Resolved conflicts:**

1. `MOZAWindowsDriver_06676A68` — **MW4**; `S1_S2_remaining.md` supersedes the earlier per-file MW3.
2. `mxusbd` x2 — **MW3**; the per-file reports and the R3/hardware W2 matrix are authoritative.
3. `CMUAC` x4 — **BLOCKED** (unsigned; static W0). `CMTAC_83986D97` x64 — **NO-MEMORY-WRITE**;
   `CMTAC_F6772F57` — **BLOCKED** (i386).
4. One CPU-Z x64 build - audit and driver **exported 2026-10-25** with the verified set.
5. **Known-bad policy:** the six hashes in `known_bad_hashes.txt` are hash-backed. RTCore32
   `1E0A3CF8`/`6F818DAF`, RTCore64 `A4F44E26`, RTCoreMini32/64, and both OHM WinRing0 builds are
   **family-blocked by policy** but are not in the LOLDrivers index; do not cite them as hash matches.

**Report header gaps:** some historical reports use reduced headers; all current reports carry
Reach and Setup, with Write quality/Severity inside the Verdict where not a separate row.

### Historical findings retained (pre-2026-10-24)

No unresolved historical findings. HP `rtf64x64`, `silabser`, and `bxvbda` have current reports;
the old copies are in `audits/legacy/`.

## In flight

None. Coverage reconciliation v3 is complete: **386/386 accounted (verified sets exported 2026-10-25), 0 unexplained missing**

## Completed queues

- `collected5` - 41/41 (2 exported; HWiNFO/OCCT a separate row).
- `collected1` - 106/106 (6 exported).
- `collected2` — 135/135 (current re-audit subset plus historical/blocked dispositions).
- `collected3` — 11/11.
- Original corpus — 94/94 (2 user-excluded: `NvModuleTracker`, `vgk`).
- High-value original re-audits — `silabser`, `bxvbda`, LSI/Perc, `megasr`, and scoped `nvlddmkm`.

There is no unassigned audit target. New work should be a re-audit only if a report is challenged
or a build changes.

## Known-bad / blocked references

**Hash-backed** (present in `indexes/dedupe/known_bad_hashes.txt`):
EVGA `driver-x64_33DA2CE2.sys`; MSI `MSIO32_C7D4943D.SYS`, `MSIO64_525D9B51.SYS`,
`amifldrv64_5F487829.sys`; ASRock `MsIo64_CFCF32F5.sys`; MSI `RTCore64_40061B30.sys`.

**Family-blocked by policy** (not in the LOLDrivers/known-bad hash index):
MSI `RTCore32_1E0A3CF8`, `RTCore32_6F818DAF`, `RTCore64_A4F44E26`, `RTCoreMini32_8EDBEAD1`,
`RTCoreMini64_014599A7`, and OHM `WinRing0_x64/x86`. They remain `BLOCKED` by family policy; do
not cite them as hash matches.

## Rules

- Only kernel memory writes count; MSR/port/PCI/SMBus/EC/MMIO are `HW-ONLY`.
- `R2` admin paths are in scope; a DACL is not a dead end.
- Setup (`none|service|devnode|hardware|composition`) is a severity field.
- `BLOCKED` is for known-bad/blocklisted, unsigned-HVCI-blocked, or unobtainable images; the static
  primitive can still be recorded as a reference.
- One canonical report per driver; appendices must name it.
- Check this file before auditing to avoid duplicate work.
