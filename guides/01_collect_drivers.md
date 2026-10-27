# Collecting drivers — the hunt

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

Never run an installer. The entire collection is "treat the installer as an archive, extract
the payload, hash it, move on."

## 1. Where vulnerable drivers live

Signed, exploitable kernel drivers ship with the software people actually install:

| Category | Vendors/packages worth mining |
|---|---|
| Motherboard/perf tuning | MSI `Afterburner`, ASUS AI Suite, Gigabyte, Intel XTU |
| Hardware monitors | CPU-Z, HWiNFO, GPU-Z, AIDA64, HWMonitor, ThrottleStop |
| Gaming peripherals | Logitech, SteelSeries, Corsair iCUE, Razer, ROCCAT |
| RGB/fan/AIO control | NZXT CAM, Cooler Master MasterPlus, SignalRGB |
| Capture/USB/serial | ElGato, Blackmagic, AVerMedia, Moxa/Digi/Perle vendors |
| Virtualization | VMware, VirtualBox (their host tools ship host drivers) |
| SDKs / redistributables | Windows driver SDK samples, vendor SDKs, "driver only" cab |

Windows also keeps every driver it has loaded in `C:\Windows\System32\drivers` (and per-machine
`DriverStore\FileRepository`) — a good first batch is harvesting candidates from there before the
vendor sweep.

## 2. The rules

- Only `7-Zip`/`expand`/`dark.exe`/`innoextract`/`innounp` may touch an installer — those are unpackers.
  `innoextract` is not tracked in the repo; download it separately.
- Skip installers > 500 MB (Electron/launcher blobs).
- Delete the installer and the extract tree immediately after harvesting; keep only `.sys`.
- Never collect a driver you already hashed — dedupe against `indexes/dedupe/existing_hashes.txt`.
- Never load anything you collected on your daily host. Dynamic testing happens only in a
  disposable VM snapshot.

## 3. The concrete loop (this repo's commands)

```powershell
# 1. download the vendor package into downloads/ (no install, no execution)
cd downloads
winget download -e --id Elgato.EpocCam --download-directory . `
  --accept-package-agreements --accept-source-agreements --disable-interactivity

# 2. extract every .sys from the downloaded archive without executing it
..\tools\harvest.ps1 -Path .\<downloaded-file> -Vendor Elgato -PackageId Elgato.EpocCam `
  -Out .\_harvest -Index ..\indexes\collections\collected1\_index.jsonl

# 3. dedupe into the corpus (next block)
```

> [!NOTE]
> The example is Elgato EpocCam: a small package whose two drivers are **not** on the blocklist.
> MSI Afterburner also yields drivers, but they are the blocklisted RTCore family — a good
> negative test for the gate, not a first batch.

> [!TIP]
> On a default Windows install, PowerShell may block local scripts. If you see
> "running scripts is disabled on this system", run scripts as
> `powershell -NoProfile -ExecutionPolicy Bypass -File <script> ...`, or for the current window:
> `Set-ExecutionPolicy -Scope Process Bypass`.

`harvest.ps1` handles `.zip/.7z/.cab/.msi` and the installer-specific Inno Setup/Burn/NSIS
extractors, checks every extracted `.sys` against the dedupe index, and writes an `_index.jsonl`
line per accepted driver. Expected output is one `DRIVER ...` line per accepted `.sys`, then
`RESULT Elgato.EpocCam drivers=2`.

Dedupe into the corpus with the mandatory gate — never copy by hand:

```powershell
cd ..   # back to the repo root
tools\filter_new_drivers.ps1 -SourceDir downloads\_harvest -OutDir drivers `
  -Manifest indexes\collections\collected1\manifest.csv -UpdateExisting
tools\rebuild_manifest.ps1 -NewBatch collected1
```

Expected: `New: <N>` from the filter, then `manifest: <N> rows, <N> unique hashes` from the
rebuild. Drivers land in `drivers\` as `<name>_<hash8>.sys`.

## 4. Before your first sweep

Open [`WANTED_LEDGER.md`](../WANTED_LEDGER.md) and lock in your target class: the example repo is
tuned for **kernel memory writes only** (`mem W`), MW1 preferred. This is also where you declare
what is out of scope, like `HW-ONLY` writes. Everything downstream (the severity scale, the audit
prompt, the verdicts in `STATUS.md`) keys off that file.

## 5. Customizing the hunt for YOUR targets

Everything about *which* drivers you chase is data in `indexes/`, never code:

- **Vendor list** — edit `downloads/README.md` (the quickstart) plus one
  `indexes/collections/collected<NEW_N>/README.md` with the URLs and download commands you used.
- **Corpus manifest** — `indexes/drivers_manifest.csv` is regenerated from `drivers/`; the
  `Batch` column is how you slice the corpus later.
- **Known-bad list** — `indexes/dedupe/known_bad_hashes.txt` is a plain SHA-256-per-line
  text file. Fill it from LOLDrivers + the Microsoft blocklist so your own collection loop
  auto-skips hashes already known/exploited.
- **Severity/scope rules** — `audits/scope/SEVERITY.md` and `AUDIT_SCOPE.md` define what counts
  as a memory write; copy then customize them to your own hunt focus (e.g. include EVTs for
  physical drive writes).
- **STATUS** — `audits/STATUS.md`, one row per driver/battery. This is the file the agent
  reads before every audit so nothing is duplicated.
