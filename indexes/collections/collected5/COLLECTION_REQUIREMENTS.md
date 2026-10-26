# Driver Collection Requirements — Utility / RGB / Fan / Monitoring Batch

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

## 1. Mission

Find **new** third-party Windows kernel drivers that are plausible sources of a **kernel memory-write primitive reachable by an unprivileged local user or a local administrator**. Admin-only DACLs are **in scope**; record the reach tier (`unprivileged` / `authenticated user` / `local administrator`). Focus on software-only utility drivers — RGB/lighting control, fan/thermal control, hardware monitoring, CPU-Z replacements, virtual devices, and similar — **not** OEM hardware driver packs.

**Goal:** kernel memory write only. See `..\..\..\PROJECT_GOAL.md`. Hardware-only writes are `HW-ONLY` and do not count unless they chain into a memory write.

## 2. What counts as a memory-write candidate

A driver is worth collecting when it shows one or more of:

- Creates a control device at `DriverEntry` (or an auto-installed PnP device) that a standard user **or local administrator** can open.
- IOCTL path accepts caller-controlled data and writes to kernel memory, maps physical memory, or copies to a caller-influenced kernel address.
- Permissive security descriptor: `IoCreateDeviceSecure` / `WdmlibIoCreateDeviceSecure` with `Everyone` / `WD` / `GRGWGX`, or a programmatic DACL set via `RtlSetDaclSecurityDescriptor` / `ZwSetSecurityObject` / `ObSetSecurityObjectByPointer`.
- Dangerous primitives: `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, arbitrary `memcpy`/write loops. MSR (`wrmsr`), port I/O (`IN`/`OUT`), PCI config, SMBus/EC, and fixed-window MMIO are **collection signals only** — flag them `HW-ONLY` unless they chain into a memory write.
- `METHOD_NEITHER` IOCTLs, missing `ProbeForWrite`, missing output-length checks, or caller-supplied pointers/sizes.
- No hardware dongle or special staging if possible. Devnode-only devices are still collected but ranked lower.

## 3. Target classes (priority order)

1. **RGB / lighting control** — motherboard, RAM, fan, keyboard, mouse, GPU, case lighting.
2. **Fan / thermal / watercooling control** — fan curves, pumps, sensors, Aqua Computer/EK/Bitspower/Alphacool-class utilities.
3. **Hardware monitoring / CPU-Z replacements** — CPU-Z, HWiNFO, HWMonitor, GPU-Z, AIDA64, Core Temp, SIV, Argus, OCCT, PassMark, LibreHardwareMonitor, Open Hardware Monitor, OpenRGB, FanControl.
4. **Virtual display / virtual audio** — Spacedesk-class, virtual audio cables.
5. **Security / telemetry / anti-cheat / DRM** — only small vendors; no big-corp agents.
6. **Other software-only control-device utilities** — docking, USB sharing, phone-link, remote-support, backup/imaging.

## 4. Vendor priority

### Tier A — small/indie, collect first
Cooler Master, Lian Li, Thermaltake, Kingston FURY, ADATA/XPG, Sabrent, DeepCool, Phanteks, Montech, Aquacomputer, EK Water Blocks, Bitspower, Alphacool, Argus Monitor, SIV, Core Temp, ThrottleStop, OCCT, PassMark, LibreHardwareMonitor, Open Hardware Monitor, OpenRGB, FanControl.

### Tier B — mid-size utility, collect if not already present
Corsair iCUE, Razer Synapse, Logitech G HUB, NZXT CAM (already collected), SteelSeries GG (already collected).

### Tier C — do NOT collect
Dell, HP, Lenovo, Microsoft Surface, Intel, AMD, NVIDIA, Broadcom, Realtek, Qualcomm OEM driver packs; Microsoft inbox drivers. No multi-GB OEM driver packs.

## 5. Hard exclusions

- **No big OEM driver packs** (Dell/HP/Lenovo/Surface/Intel/AMD/NVIDIA).
- **No Microsoft inbox drivers.**
- **No hash in `known_bad_hashes.txt`** (5,833 LOLDrivers hashes).
- **No hash in `existing_hashes.txt`** (932 already-collected hashes from the original 94, `collected1`–`collected5`, DriverStore scan, host scan).
- **No duplicate within the batch.**
- **No third-party driver download sites, torrents, repacks, or “driver packs.”**
- **No installers > 500 MiB (~524 MB).** If the only official package for a vendor is larger than 500 MiB, skip it and record `SKIPPED-OVER-500MB`.

## 6. Dedupe gate (mandatory)

Every extracted `.sys` must pass:

`C:\Users\<scrubbed>\Desktop\driver_candidates\tools\filter_new_drivers.ps1`

Inputs:

- `indexes\dedupe\existing_hashes.txt` — 932 existing hashes.
- `indexes\dedupe\known_bad_hashes.txt` — 5,833 LOLDrivers hashes.

The filter copies **only NEW unique** drivers into `drivers/` and records `NEW` / `EXISTING` / `KNOWNBAD` / `DUPLICATE` per file.

## 7. Extraction rules

- Download the official installer only. **Never execute it.**
- Treat installers as archives:
  - `7z x` for ZIP/CAB/MSI/NSIS/self-extracting EXE.
  - WiX Burn: `dark.exe -x`.
  - Inno Setup ≤ 6.0.5: `innoextract`.
  - Newer Inno Setup: `innounp 2.70.1`.
- Recursively expand `.zip` / `.cab` / `.msi` / `.exe` / `.7z` up to 5 levels.
- Collect `.sys` files ≥ 4 KB only. Do not keep `.inf`/`.cat`.
- Never load a driver, create a service, or write to HKLM.

## 7.1 Download hygiene (mandatory)

`drivers/` contains **only `.sys` files**. Everything else is temporary.

1. Download the installer into `downloads/` (gitignored). Never download it into `drivers/`.
2. Extract into the same temporary directory.
3. Run `tools\filter_new_drivers.ps1 -OutDir drivers -UpdateExisting`; it copies only deduped
   `.sys` into `drivers/` (flat) and updates the gate.
4. Record SHA-256, signature, version, original URL, and original path in
   `indexes/collections/collected<N>/manifest.csv` (and `urls.txt`).
5. Delete the installer, extract tree, and every non-driver payload (`.exe`, `.dll`, `.inf`,
   `.cat`, `.asar`, `.pak`, `.png`, `node_modules`, caches, screenshots, `$PLUGINSDIR`, `$TEMP`).
6. Verify `drivers/` contains only `.sys` + `README.md`, and `downloads/` is empty.
7. Do not keep `packages/`, `extract/`, `work/`, `manual/`, or `staging/` anywhere.

If the driver was not copied before deletion, re-download it. Do not keep the installer "just in
case". Installer cap still applies: **500 MiB**.

## 8. Manifest fields

`Pack, Vendor, Product, DownloadURL, Driver, SHA256, SizeKB, Company, FileVersion, SignatureStatus, Signer, OriginalPath, CopiedPath, Status, Reach, Notes`

## 9. Output layout

```
drivers\                         NEW unique .sys only (flat, one copy each)
indexes\collections\collected<N>\
  <agent>\manifest.csv           URL, original path, hash, signer, version
  <agent>\summary.txt
  <agent>\urls.txt               official download URLs
downloads\                       temporary installer/extract tree; emptied after step 7.1
```

The installer and extract tree live in `downloads\` and are deleted after step 7.1. They are
never part of the corpus.

## 10. Acceptance checks

- At least one official URL recorded per vendor.
- Every `.sys` has SHA-256 + signature status.
- **Zero** hashes from `existing_hashes.txt` or `known_bad_hashes.txt` inside `drivers/`.
- Summary counts: downloaded, extracted, `.sys` found, unique, NEW, EXISTING, KNOWNBAD, failures.
- No big-OEM pack downloaded.
- No installer or extract tree remains in `downloads/` (step 7.1).
- Every failure (403, login wall, unsupported installer) named explicitly.
