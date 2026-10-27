# BYOVD AI Guide

An AI-driven Windows-driver (BYOVD) research lab in a box: goal/ledger files, the method, and
empty data folders to fill with your own hunt. The worked example (386 drivers, 257 reports)
lives on the [`example`](https://github.com/LongpanZhou/BYOVD-AI-Guide/tree/example) branch -
the original run's snapshot, so its wording may not match the current docs.

## Setup

```powershell
git clone https://github.com/LongpanZhou/BYOVD-AI-Guide.git driver_lab
cd driver_lab
```

Fetch the four tools and the blocklist gate from `example`:

```powershell
$raw = 'https://raw.githubusercontent.com/LongpanZhou/BYOVD-AI-Guide/example'
'harvest.ps1','filter_new_drivers.ps1','rebuild_manifest.ps1','triage_scan.ps1' |
  ForEach-Object { Invoke-WebRequest "$raw/tools/$_" -OutFile "tools\$_" -UseBasicParsing }
Invoke-WebRequest "$raw/indexes/dedupe/known_bad_hashes.txt" `
  -OutFile "indexes\dedupe\known_bad_hashes.txt" -UseBasicParsing
```

Install the extractors the tools need (7-Zip, innoextract, and for Inno > 6.0.5 `innounp`) -
path details in `DRIVER_COLLECTION_PLAYBOOK.md` section 3. Then verify:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\rebuild_manifest.ps1
(Get-Content indexes\dedupe\known_bad_hashes.txt | Measure-Object -Line).Lines
```

Expected: `manifest: 0 rows, 0 unique hashes` and a gate count of `5833`.

If PowerShell blocks scripts, run them as `powershell -NoProfile -ExecutionPolicy Bypass -File <script>`.

## Start

Open the folder in your AI agent and say:

> Read `AGENTS.md`, then `guides/00_quickstart.md`. Set up the lab and wait for my target.

After that, you only name targets - for example "harvest as many RGB vendor drivers as you can
this batch" - and the agent runs: hash-verified `winget download` (never installs), harvest
(extract only), the dedupe gate, provenance in `indexes/collections/collected1/`, reports, and
verdict rows in `audits/STATUS.md`.

## The loop

| Step | Guide | You produce |
|:---:|---|---|
| 1 | [`guides/01_collect_drivers.md`](guides/01_collect_drivers.md) | flat `drivers\` + batch provenance |
| 2 | [`guides/02_blocklist_check.md`](guides/02_blocklist_check.md) | dated check in `audits\evidence\` |
| 3 | [`guides/03_audit.md`](guides/03_audit.md) | report in `audits\reports\` |
| 4 | [`guides/04_dynamic_vm.md`](guides/04_dynamic_vm.md) | proof logs (VM only) |
| 5 | [`audits/STATUS.md`](audits/STATUS.md) | one verdict row per driver |

## Rules

- Kernel memory writes only; hardware-only writes (MSR / port / PCI / SMBus / EC / MMIO) are
  `HW-ONLY`. Severity scale: `audits/scope/`.
- Never execute an installer or load a driver on the host; dynamic work is VM-only.
- `drivers\` stays flat (`.sys` + `README.md`), written only by the gate; one report per driver,
  verdict row into `audits/STATUS.md` after the report.
