# Driver Collection Playbook

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

Reference for building **your own** driver corpus from vendor utility packages - **without
installing anything** and **without executing vendor binaries**. On this branch every count starts
at zero; the worked example this playbook was distilled from lives on
[`example`](https://github.com/LongpanZhou/BYOVD-AI-Guide/tree/example).

**Goal:** find kernel memory-write vulnerabilities. Only memory writes count; hardware-only writes are `HW-ONLY`. Admin-only DACLs are in scope (`R2`). See [`PROJECT_GOAL.md`](PROJECT_GOAL.md).

---

## 1. Why this document exists

Two ways to stock `drivers/`:

1. **Your own host** - copy candidates out of `C:\Windows\System32\drivers` (record their hashes
   so the dedupe gate knows them).
2. **Vendor utility installers** - treat every installer as an archive and pull the `.sys` files
   out without running anything.

This document records the second method: the extraction logic, the vendor yield rates, and the
dead ends, so your first collection run does not have to re-derive them.

---

## 2. Ground rules

| Rule | Reason |
|---|---|
| Never execute a vendor `.exe`/`.msi` | Running it is installation; it writes services, registry, and driver store |
| Only `7z`, `expand`, `dark.exe`, `innoextract`, `innounp` may run | These are decompressors, not installers |
| Delete the installer and extract tree immediately after harvesting | The project keeps only the driver payload, never installers or app trees |
| Skip installers > 500 MB | Time/bandwidth; almost always Electron app blobs |
| Do not re-collect known-bad/blocklisted drivers | They are `BLOCKED` references, not audit targets |
| Never load a driver on the host | Dynamic testing happens only in the VMware guest |

**Known-bad/blocklisted only:** `RTCore64`/`RTCore32`/`RTCoreMini*` (MSI Afterburner),
`AsIO3`/`AsUpIO` (ASUS), `gdrv2` (Gigabyte), and anything on the Microsoft vulnerable-driver
blocklist / LOLDrivers. These are `BLOCKED` references.

**User-excluded (never audit/open):** `vgk.sys` and `NvModuleTracker.sys` (anti-cheat category).
They are not blocklisted by hash and are not audit targets.

Everything else is in scope, including CPU-Z, HWiNFO, AIDA64, GPU-Z, ThrottleStop, and PawnIO.
Admin-only drivers are `R2` audit targets. Hardware-only writes (MSR/port/PCI/SMBus/EC/MMIO) are
`HW-ONLY` and do not count unless they chain into a memory write.

Rationale: the point is a memory-write primitive, not notoriety. A blocklisted driver is already
known and is usually blocked from loading; an unstudied utility driver is a better target.

### 2.1 Download hygiene (mandatory)

`drivers/` contains **only new `.sys` files**. Everything else is temporary.

1. Download and extract in `downloads/` (gitignored) - never in `drivers/`.
2. Harvest to `downloads\_harvest`, then run
   `tools\filter_new_drivers.ps1 -SourceDir downloads\_harvest -OutDir drivers -Manifest indexes\collections\collected<N>\manifest.csv -UpdateExisting`
   to copy only the deduped `.sys` into `drivers/` (flat) and update the dedupe gate.
3. Record the URL, original path, SHA-256, signer, and version in
   `indexes/collections/collected<N>/manifest.csv` (and `urls.txt`).
4. Delete the installer, the extract tree, and every non-driver payload: `.exe`, `.dll`, `.msi`,
   `.zip`, `.7z`, `.cab`, `.inf`, `.cat`, `.asar`, `.pak`, `node_modules`, `$PLUGINSDIR`,
   `$TEMP`, screenshots, logs, and caches.
5. Verify `drivers/` contains only `.sys` + `README.md`, and `downloads/` is empty:
   `Get-ChildItem drivers -File | Where-Object Extension -ne '.sys'` should show only `README.md`.
6. If a driver you expected is missing from `drivers/`, read the filter output before
   re-downloading. Do not keep the installer "just in case".

Wipe the scratch after every batch: `downloads/` back to just `README.md`, `drivers/` holding
only `.sys` files plus its `README.md`. Never keep an installer "just in case".

After accepting a batch, keep counts in **one** place: `audits/STATUS.md`, the single live
status source. `tools/rebuild_manifest.ps1` updates the manifest; `filter_new_drivers.ps1
-UpdateExisting` updates the dedupe index and summary.

---

## 3. Toolchain

Everything lives under `tools/`. Prerequisite: **7-Zip** at
`C:\Program Files\7-Zip\7z.exe` (hardcoded in `harvest.ps1`).

| Tool | Purpose |
|---|---|
| `harvest.ps1` | Recursive extract -> collect `*.sys` -> fingerprint -> append JSONL |
| `triage_scan.ps1` | Prints devices, symlinks, SDDL strings, imports for a `.sys` |
| `filter_new_drivers.ps1` | Mandatory dedupe gate; copies only NEW `.sys` |
| `innoextract\innoextract.exe` | Inno Setup 1.2.10 - **6.0.5 only** |
| `innounp` (on `PATH`) | Inno Setup **6.1+** - `winget install JurgenRathlev.innounp` |

WiX `dark.exe` (116 MB) is not retained; re-install WiX 3.14 into `tools\wix\` when a new
Burn/MSI package must be unpacked, then delete it again after the batch is accepted.

`harvest.ps1` delegates to `7z`/`innoextract`/`dark.exe` only - it **cannot unpack Inno >= 6.1
packages**. Run `innounp -x <file> -d <dir>` on those, then re-run `harvest.ps1` against the
extracted folder with `-NoExpand`.

`harvest.ps1` resolves `dark.exe`, `innoextract.exe` and `triage_scan.ps1` relative to its own
folder, so the `tools\` directory is self-contained and can be copied to another machine.

### Invocation

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "tools\harvest.ps1" `
  -Path   "downloads\<installer-or-directory>" `
  -Vendor "<Vendor>" `
  -PackageId "<package-id>" `
  -Out    "downloads\_harvest" `
  -Index  "indexes\collections\collected<N>\_index.jsonl"
```

Add `-NoExpand` when `-Path` is an already-extracted directory (otherwise it will try to
re-extract every `.exe` inside, which is slow and pointless).

Each driver is copied as `<name>_<sha256[0..8]>.sys` so hash collisions are visible and
re-runs do not overwrite silently. Then run `tools\filter_new_drivers.ps1` to copy only the new,
deduped files into `drivers/`. The filter preserves an existing hash suffix; it does not add a
second one.

---

## 4. Extraction decision tree

```
downloaded file
|-- .zip / .7z / .msi
|     \-- 7z x <file> -o<dir> -y
|           \-- recurse (max depth 4) over any archives found inside
|-- .exe
|     |-- 7z x <file> -o<dir> -y
|     |     |-- produced wixstdba.dll or BootstrapperApplicationData.xml  -> WiX Burn
|     |     |     \-- dark.exe -x <dir2> <file>   (attached container holds the .msi)
|     |     \-- produced >= 10 files  -> NSIS or similar, done
|     \-- produced < 10 files (PE stub only)  -> Inno Setup
|           \-- innoextract.exe -e -d <dir3> -- <file>
|                 |-- ok                                  -> harvest
|                 \-- "Unexpected setup data version: 6.x" -> innounp -x <file> -d <dir3>
|                       -> re-run harvest against <dir3> with -NoExpand
\-- .cab
      \-- expand.exe <file> -F:* <dir>
```

### Known extractor limits (learned the hard way)

1. **7-Zip cannot open Inno Setup at all.** It reports success and emits the PE sections
   (`.text`, `.rsrc`, `[0]`, `PACKAGEINFO`). If a driver harvest returns 0 files from an `.exe`
   but the listing contains `[0]` or `DVCLAL`, that is an Inno installer that was not extracted.
2. **`innoextract 1.9` stops at Inno 6.0.5.** Anything built with Inno 6.1+ fails with
   `Unexpected setup data version: 6.x`. Use **`innounp`** for those
   (`winget install JurgenRathlev.innounp`); it handles newer Inno Setup bundles such as
   CPU-Z 3.01 (Inno **6.3.0**).
3. **`Copy-Item -Recurse` silently truncates at MAX_PATH.** Electron apps keep drivers under
   `resources\app.asar.unpacked\node_modules\...\drivers\x64\`, which blows past 260 chars.
   NZXT CAM went from 3 drivers to 0 because of this. **Always scan directories in place** -
   `harvest.ps1` does this automatically.
4. **`.sys` extension case varies.** `kinonivd.Sys`, `PP.SC0710.X64.SYS`. Match
   case-insensitively (`-Filter *.sys` is case-insensitive in PowerShell; raw string matching is not).
5. **Signed != safe to run.** In the original worked example every binary verified `Valid`;
   signature status says nothing about the DACL or the IOCTL surface.

---

## 5. How to find packages

### winget (hash-verified, never installs)

```powershell
winget search --source winget "NZXT"
winget show   -e --id NZXT.CAM          # Installer Type / Url / Sha256
winget download -e --id NZXT.CAM --download-directory downloads `
  --accept-package-agreements --accept-source-agreements --disable-interactivity
```

`winget download` verifies the installer hash against the manifest before writing it. It does
**not** execute anything.

Version pinning (`--version`) works, but list available versions first:

```
https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/n/NZXT/CAM
```

A 429/404 there means the publisher path differs (e.g. `Asus/GpuTweak3/Stable/2.1.8.0`).

### Vendor direct

For vendors with no winget package, use the support/download page and prefer a portable `.zip`
over an `.exe`. Direct downloads skip the manifest hash check, so record the SHA256 of the
installer before extracting if provenance matters.

### Package search notes

- `winget search` with multi-word queries often returns **"No package found"**
  (e.g. "Armoury Crate"). Use a single token.
- Winget's column parser is fragile - narrow tables collapse to one space and `-split '\s{2,}'`
  silently drops rows. Do not trust an automated parser against `winget search`; resolve IDs
  by eye or via `winget show -e --id`.

---

## 6. What actually paid off

Yield is measured in **distinct driver families**, not files. Six version bundles of the same
six SteelSeries drivers are 52 files but only 6 families - counting files instead of families
inflates the corpus several-fold.

| Package | Files | Families | Verdict |
|---|---|---|---|
| `SteelSeries.SteelSeriesEngine` 3.22.1 | 44 | 9 | **best single source** |
| `SteelSeries.GG` 122.0.0 | 10 | 9 | best current source |
| `Elgato.4KCaptureUtility` 1.7.16 | 9 | 9 | capture cards (hardware) |
| `Elgato.GameCapture.HD` 3.70 | 8 | 8 | capture cards (hardware) |
| `MSI.Afterburner` 4.6.6 | 6 | 4 | excluded (blocklisted) |
| `NZXT.CAM` 4.76.5 | 3 | 3 | 1 open DACL |
| `Elgato.EpocCam` 3.4.0 | 2 | 2 | **software-only, permissive** |
| `WhirlwindFX.SignalRgb` 2.5.80 | 4 | 2 | FTDI stock DACL |
| `Elgato.CameraHub` 2.3.0 | 1 | 1 | virtual camera |
| `PawnIO` | 1 | 1 | admin-only |

### Zero-yield (do not retry)

`GIGABYTE.RGBFusion`, `Gigabyte atBIOS`, `GIGABYTE DRM Fix Tool`, `Kingston SSD Manager`,
`Crucial Storage Executive`, `OpenRGB`, `Elgato.ControlCenter`, `Dell.DisplayAndPeripheralManager`,
`Lenovo.DockManager`, `Acer.AutoDetectSerialNumber`.

These ship no kernel driver at all - the utility talks to the device over HID/WMI/SMBus from
user mode. That is the common case for modern RGB/fan software.

### Failed downloads

`Asus.BIOSConfigTool` (404 at CDN), `Asus.DisplayWidgetCenter` (manifest hash mismatch).
Both are manifest rot, not a tooling problem.

### Inno 6.3 - use `innounp`

`CPUID.CPU-Z` (and the ROG/AORUS/MSI/GBT/ASPHANTOM/TAICHI rebrands - all identical payload),
`REALiX.HWiNFO`, `FinalWire.AIDA64.*`, `TechPowerUp.GPU-Z`. `innoextract` cannot open these;
use `innounp` instead. They are **in scope** under the current goal.

---

## 7. Reading the result

### The only signal that matters for reachability

```
IoCreateDeviceSecure(..., L"<SDDL>", ...)      <- permissive SDDL = user-reachable
WdfDeviceInitAssignSDDLString(..., L"<SDDL>")  <- same, KMDF
INF [Security] / AddReg Security               <- same, class-installed devices
IoCreateDevice(...) with no SD                <- default SYSTEM+Administrators = NOT reachable
```

A permissive SDDL is `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)` - `;;;WD` is **Everyone**.
Also qualifying: `;;;BU` (BUILTIN\Users) and `;;;AU` (Authenticated Users).

`D:P(...)` is a **protected** DACL: no inherited ACEs. That does not make it restrictive -
it depends entirely on the explicit ACEs.

### Three-tier triage

| Tier | Meaning |
|---|---|
| **Reachable + software-only** | Audit first. No hardware, no devnode, no install. |
| **Reachable + hardware-gated** | Device only exists with the physical hardware. Still audited; setup=`hardware`, likely MW2/MW3. |
| **Admin-only** | `R2` in scope. Audit for a memory write; **do not mark dead** just because a standard user cannot open it. |

A driver can be "reachable" and still be worthless: if it only implements HID filter callbacks
there is no control device to open, and the SDDL is decoration. Check the `Device` column in
`indexes/collections/collected<N>/master_drivers.csv` before spending time.

### 7.1 Why string-matching SDDLs is wrong (learned the hard way)

The first version of `triage_scan.ps1` flagged a driver as reachable if *any* `D:P(...)` literal
in the file contained `;;;WD`. That is unsound and, in the original run this playbook was
distilled from, produced roughly a **50% false-positive rate**.

The failure mode: vendors ship a **table of descriptors** (one per OS version, SKU, or code path).
Most entries are never passed to the create call. ASRock `MsIo64.sys` contains seven SDDLs,
including `...GRGWGX;;;WD...`, and calls plain `IoCreateDevice` with **no** descriptor at all -
all seven strings are dead data. Same for EVGA `driver-x64` (7 dead) and ROCCAT `ScpVBus`
(1 dead). Ghidra confirmed `refs=0` for every one.

**`triage_scan.ps1` (the version shipped on `example`) does three things the first version did not:**

1. **Parses the PE import table** and reports which device-creation API is genuinely imported:
   `IoCreateDevice`, `IoCreateDeviceSecure`, `WdmlibIoCreateDeviceSecure`,
   `WdfDeviceInitAssignSDDLString`, `NdisRegisterDeviceEx`, or `KMDF-dynamic`
   (KMDF drivers only import `WdfVersionBind`, because the WDF API is a statically linked stub).
2. **Resolves each SDDL literal to a VA** and looks for a real reference. The scan is
   opcode-agnostic: any `disp32` in an executable section whose *next-instruction address + disp*
   lands exactly on the SDDL VA counts. This catches `lea`, `mov`, and `movups` - the last one
   matters because MSVC copies descriptors with SSE, so an `lea`-only scan misses them.
3. **Reads the sibling `.inf`**, because class-installed devices carry their DACL in
   `[Security]`/`AddReg`, not in the binary.

**Third failure mode, found during the audits (v3):** checking for a code reference *to the
string text* misses every driver that passes the descriptor indirectly. Vendors build a
`UNICODE_STRING` whose `Buffer` points at the text and `lea` **the descriptor** - and the
descriptor may sit before or after the string. Ghidra's `getReferencesTo(text)` has the same
blind spot. This produced false negatives on ASRock `MsIo` v1.3, ROCCAT `ScpVBus`, NZXT
`cam_driver_mb` and the whole SteelSeries WDF set.

The fix is to resolve the pointer in `.data` back to the literal, then validate a real
`UNICODE_STRING` header at `ptr-8` (x64) or `ptr-4` (x86): `Length == string size`,
`MaximumLength == Length or Length+2`, `Buffer == literal VA`.

A looser "any nearby code reference" window was tried first and produced the same 46 hits, so
the two methods did not disagree; header validation is simply the defensible one. The resulting
set was then cross-checked family by family against two independent manual audits (A2 on the
port-I/O cluster, A3 on the HID/SMBus cluster), and all 13 families agree. `SDDL-UNPROVEN`
went 48 -> 0 and `SDDL-ACTIVE-OPEN` 3 -> 46; the 48 previously "unproven" files were not dead,
they were live descriptors that the text-address scan could not see.

Xref markers bumped accordingly: `CODE-XREF` (direct), `DESC-XREF` (via descriptor),
`DATA-XREF` (pointer with no code reference), `DEAD`.

**Verdict vocabulary** (`Reach` column):

| Verdict | Meaning |
|---|---|
| `SDDL-ACTIVE-OPEN` | Literal is code-referenced **and** grants Everyone/Users. Real. |
| `SDDL-ACTIVE-RESTRICTED` | Code-referenced but admin-only. Real, but not reachable. |
| `INF-SDDL-OPEN` | Binary silent; INF declares an open DACL. Requires devnode install. |
| `INF-SDDL-RESTRICTED` | INF declares a DACL, but admin-only. Requires devnode install. |
| `SDDL-UNPROVEN` | Literal has a data pointer but no code reference. **Needs decompile-time reference resolution (REA).** |
| `SDDL-DEAD` | Literal present, nothing points at it. Ignore. |
| `DEFAULT-ADMIN` | Creates a device with no descriptor. Admin-only by construction. |
| `NO-DEVICE` | No control device at all (miniport / filter / class driver). |

Do not treat `SDDL-UNPROVEN` as a finding. `INF-SDDL-OPEN` means the device comes from an INF
devnode: setup=`devnode`, still auditable. Setup is a severity field, not a disqualifier.

### 7.2 Setup cost vs. reachability

These are independent axes and both matter:

- **Reachable** = the DACL lets a standard user **or local administrator** open the device.
- **Setup** = `none | service | devnode | hardware | composition` - a severity field, not a
  disqualifier.

A driver that creates its device in `DriverEntry` (`IoCreateDevice*`, `NdisRegisterDeviceEx`)
can be started with `sc create` + `sc start` (`service`/`none`). A driver whose device comes from
PnP enumeration (`INF-SDDL-OPEN`) needs a devnode. A hardware-attached driver needs the device.
All are audited; the gate is reflected in the MW severity, not used to discard the driver.

---

## 8. Your corpus

Live counts live in **one** place, generated per batch - do not copy them into other docs:

- `audits/STATUS.md` - your queue and totals
- `indexes\drivers_manifest.csv` - your inventory, regenerated by `tools/rebuild_manifest.ps1`
  from `drivers/` on disk after every accepted batch
- `indexes\dedupe\existing_hashes.txt` — your dedupe gate, updated by
  `filter_new_drivers.ps1` (run with its mandatory `-SourceDir`/`-OutDir`/`-Manifest` args
  plus `-UpdateExisting`)

The live audit queue is `audits/STATUS.md`. Do not duplicate it here; it changes as audits land.

---

## 9. Adding more drivers - start here

Vendors that fit the "obscure" profile and are rarely mined:

- **Cooling / water**: Aquacomputer `aquasuite`, EK `Loop Connect`, Alphacool, Phanteks,
  be quiet!, ARCTIC, Montech, InWin `iWizard`, DeepCool, SilverStone
- **Niche peripherals**: Wooting `Wootility`, Lamzu, VAXEE, Endgame Gear, Pulsar `Fusion`,
  Keychron `Launcher`, Ducky, MCHOSE, Ajazz, Attack Shark
- **Second-tier storage**: ADATA `SSD Toolbox`, SK hynix `Drive Manager`, Kioxia `SSD Utility`,
  TEAMGROUP, PNY, Sabrent `Rocket Control Panel`, Lexar, Netac
- **Second-tier boards**: ASRock `Polychrome` / `A-Tuning`, EVGA `Precision X1`,
  Palit `ThunderMaster`, Gainward, Inno3D `TuneIT`, Colorful `iGame Center`, Biostar
- **Virtual-device / remote-access** (highest no-setup yield): Parsec VDD, `spacedesk`,
  Duet Display, Splashtop, RustDesk, Eltima `USB Network Gate`
- **Enterprise OEM**: Dell `Optimizer`, Lenovo `Legion`, HP `OMEN Gaming Hub`,
  Alienware Command Center

The last two groups are the most promising for the actual goal: virtual devices are software-only
by definition, and enterprise utilities are rarely audited.

### Fast loop

```powershell
# 1. resolve
winget search --source winget "AQUACOMPUTER"

# 2. download (hash-verified) into the project's disposable downloads folder
winget download -e --id <ID> --download-directory downloads `
  --accept-package-agreements --accept-source-agreements --disable-interactivity

# 3. harvest  (handles zip/7z/cab/msi/NSIS/Burn; Inno >=6.1 needs innounp first; flat .sys output)
powershell -NoProfile -ExecutionPolicy Bypass -File "tools\harvest.ps1" -Path "downloads\<file>" `
  -Vendor <Vendor> -PackageId <ID> -Out "downloads\_harvest" -Index "indexes\collections\collected<N>\_index.jsonl"

# 4. dedupe (copies only NEW .sys into drivers/)
powershell -NoProfile -ExecutionPolicy Bypass -File "tools\filter_new_drivers.ps1" -SourceDir "downloads\_harvest" -OutDir "drivers" `
  -Manifest "indexes\collections\collected<N>\manifest.csv" -UpdateExisting

# 5. rebuild the inventory and delete the scratch
powershell -NoProfile -ExecutionPolicy Bypass -File "tools\rebuild_manifest.ps1" -NewBatch collected<N>
Get-ChildItem downloads -Force |
  Where-Object { $_.Name -notin @('README.md','.gitkeep') } |
  Remove-Item -Recurse -Force
```

Budget roughly 2-4 minutes per NSIS/MSI package, 1-2 minutes per zip, and 1-2 minutes per
Inno >= 6.0.5 package (innoextract or innounp).

---

## 10. Rebuilding `master_drivers.csv` (per-batch collection metadata)

`_index.jsonl` is append-only, one JSON object per harvested binary, and accumulates across runs.

```powershell
$base = 'indexes\collections\collected<N>'
$rows = Get-Content "$base\_index.jsonl" | ForEach-Object { $_ | ConvertFrom-Json }
$u    = $rows | Group-Object SHA256 | ForEach-Object { $_.Group[0] }   # dedupe by hash
$u | ForEach-Object {
  [pscustomobject]@{
    Family  = ($_.Driver -replace '_[0-9A-F]{8}\.(sys|SYS)$','')
    Vendor = $_.Vendor; Driver = $_.Driver; KB = [math]::Round($_.Bytes/1KB)
    Version = $_.Version; Sig = $_.Sig; SDDL = $_.SDDL
    Devices = $_.Devices; Symlinks = $_.Symlinks; Apis = $_.Apis
    SHA256 = $_.SHA256
    Reach  = 'SDDL-UNPROVEN'   # never judge reach by the raw SDDL string; run tools\triage_scan.ps1
  }
} | Export-Csv "$base\master_drivers.csv" -NoTypeInformation -Encoding UTF8
```

---

## 11. Folder layout

```
driver_lab\
|-- AGENTS.md
|-- PROJECT_GOAL.md
|-- PROJECT_MAP.md
|-- README.md
|-- WANTED_LEDGER.md
|-- DRIVER_COLLECTION_PLAYBOOK.md   this file
|-- guides\                        the five step-by-step guides
|-- drivers\                        your flat .sys corpus (empty at start)
|-- downloads\                      disposable download/extract scratch
|-- audits\
|   |-- README.md
|   |-- STATUS.md                   your single status/queue
|   |-- scope\                      AUDIT_SCOPE, SEVERITY, agent prompt
|   |-- reports\                    your per-driver reports
|   |-- evidence\                   your evidence logs
|   \-- projects\                   analysis projects
|-- poc\
|   |-- dynamic\                    VM-only PoC logs and helpers
|   \-- reference\                  reference PoC material
|-- indexes\
|   |-- drivers_manifest.csv        your inventory (generated)
|   |-- dedupe\                     existing/known-bad hashes
|   |-- collections\                manifests, summaries, URLs
|   \-- driverstore\                DriverStore scan outputs
\-- tools\                          harvest, triage, filter (fetched from example)
```

No `packages\`, `extract\`, `work\`, `manual\`, or `staging\` directories. The installer
and extract tree live in `downloads\` and are deleted immediately after harvest (section 2.1).
