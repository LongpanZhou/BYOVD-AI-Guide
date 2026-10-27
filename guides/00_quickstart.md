# Quickstart — from clone to first audit

This is the 10-minute walkthrough for this repo's default branch. It assumes you already cloned
the repo (see the README). Run every command from the repo root unless a step says otherwise.

## 1. The tree you start with

```text
driver_lab/
├── AGENTS.md                     # AI operating instructions
├── PROJECT_GOAL.md               # the hunt goal — edit to re-target
├── WANTED_LEDGER.md              # what counts as a find
├── audits/
│   ├── STATUS.md                 # empty verdict queue
│   ├── reports/                  # one canonical report per driver
│   ├── scope/                    # scope, severity, default audit prompt
│   ├── evidence/                 # dated proof (blocklist checks, logs)
│   └── projects/                 # analysis state (decomp)
├── drivers/                      # flat .sys corpus
├── indexes/
│   ├── drivers_manifest.csv      # generated inventory
│   ├── dedupe/                   # hash gate + known-bad list
│   ├── collections/              # per-batch provenance
│   └── driverstore/              # discovery output
├── poc/
│   ├── dynamic/                  # harness + results/<date>/
│   └── reference/               # calibration drivers only
├── tools/                        # fetched from example
└── downloads/                    # gitignored scratch
```

Two rules keep the tree clean:

- **`audits/STATUS.md` is the only live queue.** Every other document links to it.
- **Everything flat.** Drivers never get subfolders; the manifest's `Batch` column carries
  provenance.

## 2. Add the tools and the blocklist gate

Collection needs three extractors on the host (details in `DRIVER_COLLECTION_PLAYBOOK.md` §3):
**7-Zip** at `C:\Program Files\7-Zip\7z.exe`, **innoextract**
([constexpr.org/innoextract](https://constexpr.org/innoextract/) → `tools\innoextract\innoextract.exe`,
Inno Setup ≤ 6.0.5), and **innounp** for Inno Setup > 6.0.5
(`winget install JurgenRathlev.innounp`).

The scripts and the known-bad hash list are not stored on this branch. Fetch both from `example`:

```powershell
$raw  = 'https://raw.githubusercontent.com/LongpanZhou/BYOVD-AI-Guide/example'
$base = "$raw/tools"
'harvest.ps1','filter_new_drivers.ps1','rebuild_manifest.ps1','triage_scan.ps1' |
  ForEach-Object { Invoke-WebRequest "$base/$_" -OutFile "tools\$_" -UseBasicParsing }
Invoke-WebRequest "$raw/indexes/dedupe/known_bad_hashes.txt" `
  -OutFile "indexes\dedupe\known_bad_hashes.txt" -UseBasicParsing
Get-ChildItem tools\*.ps1, indexes\dedupe\known_bad_hashes.txt | Select-Object Name,Length
```

Expected: four `.ps1` files and `known_bad_hashes.txt` (~380 KB, 5,833 hashes). The filter refuses
to run without the list, because otherwise it cannot block known-bad drivers.

Verify the toolchain:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\rebuild_manifest.ps1
```

Expected: `manifest: 0 rows, 0 unique hashes`, and `indexes\drivers_manifest.csv` now exists.

> [!TIP]
> If PowerShell says **"running scripts is disabled on this system"**, use the
> `powershell -NoProfile -ExecutionPolicy Bypass -File <script> ...` form for every tool call, or
> run `Set-ExecutionPolicy -Scope Process Bypass` once in that window.

## 3. Collect the first batch

From the repo root:

```powershell
cd downloads
winget download -e --id Elgato.EpocCam --download-directory . `
  --accept-package-agreements --accept-source-agreements --disable-interactivity
```

`winget download` fetches the vendor package **without installing or executing it**. The file it
writes is an archive or installer — harvest it, never run it:

```powershell
..\tools\harvest.ps1 -Path .\<downloaded-file> -Vendor Elgato -PackageId Elgato.EpocCam `
  -Out .\_harvest -Index ..\indexes\collections\collected1\_index.jsonl
```

Expected output: one `DRIVER <name> <bytes> <sig> <reach>` line per accepted `.sys`, then
`RESULT Elgato.EpocCam drivers=2`. The `_index.jsonl` file is created automatically.

Dedupe into the corpus — never copy by hand:

```powershell
..\tools\filter_new_drivers.ps1 -SourceDir .\_harvest -OutDir ..\drivers `
  -Manifest ..\indexes\collections\collected1\manifest.csv -UpdateExisting
```

Expected: `New: <N>` and files named `<name>_<hash8>.sys` in `..\drivers\`.

Rebuild the inventory and clear the scratch:

```powershell
..\tools\rebuild_manifest.ps1 -NewBatch collected1
cd ..
Get-ChildItem downloads -Force |
  Where-Object { $_.Name -notin @('README.md','.gitkeep') } |
  Remove-Item -Recurse -Force
```

Expected: `manifest: <N> rows, <N> unique hashes`, and `downloads\` back to just `README.md`.

## 4. Check the blocklists

Run [guide 02](02_blocklist_check.md) **before** auditing. It downloads LOLDrivers and the
Microsoft blocklist and shows how to compare a candidate's hashes. Results go in
`audits\evidence\known_vulnerable_check_<yyyy-mm-dd>.md`.

## 5. Audit, verify, record

1. [Guide 03](03_audit.md) — static audit; write `audits\reports\<driver>.md`.
2. [Guide 04](04_dynamic_vm.md) — prove the primitive in a disposable VM; log under
   `poc\dynamic\results\<date>\`.
3. [`audits/STATUS.md`](../audits/STATUS.md) — add or update one verdict row.

## 6. What "done" looks like

- `drivers\` contains `<name>_<hash8>.sys` files, flat.
- `indexes\collections\collected1\manifest.csv` lists every accepted file with its SHA-256.
- `audits\reports\` has one canonical report for the driver.
- `audits\STATUS.md` has one row for that report.
- `downloads\` is empty except `README.md`.
