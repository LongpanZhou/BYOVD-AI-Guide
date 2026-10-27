# BYOVD AI Guide

Setup and instructions for an AI-driven Windows-driver (BYOVD) research lab: the goal/ledger
files, the method, and empty data folders - everything a fresh lab starts with. No drivers,
reports, or tool binaries here. The worked example (386 `.sys` files, 257 reports, tools) lives
on the [`example`](https://github.com/LongpanZhou/BYOVD-AI-Guide/tree/example) branch - a
snapshot of the **original run's** setup, so some files there may not match the current docs;
treat it as a reference, not the manual.

## What you get

| Path | Purpose |
|---|---|
| `AGENTS.md` | operating instructions for an AI agent |
| `PROJECT_GOAL.md` | the goal - edit this to re-target the hunt |
| `WANTED_LEDGER.md` | what counts as a find |
| `audits/STATUS.md` | empty verdict queue (template) |
| `audits/scope/` | reach tiers, severity scale, default audit prompt |
| `guides/` | the five step-by-step guides |
| every data folder | empty, with a `README.md` saying what belongs there |

Folder map: `PROJECT_MAP.md`; collection reference: `DRIVER_COLLECTION_PLAYBOOK.md`.

## Setup

```powershell
git clone https://github.com/LongpanZhou/BYOVD-AI-Guide.git driver_lab
cd driver_lab
```

Fetch the four tools and the blocklist gate from `example`:

```powershell
$raw  = 'https://raw.githubusercontent.com/LongpanZhou/BYOVD-AI-Guide/example'
$base = "$raw/tools"
'harvest.ps1','filter_new_drivers.ps1','rebuild_manifest.ps1','triage_scan.ps1' |
  ForEach-Object { Invoke-WebRequest "$base/$_" -OutFile "tools\$_" -UseBasicParsing }
Invoke-WebRequest "$raw/indexes/dedupe/known_bad_hashes.txt" `
  -OutFile "indexes\dedupe\known_bad_hashes.txt" -UseBasicParsing
```

Three extractors are also needed on the host (details in `DRIVER_COLLECTION_PLAYBOOK.md`):

- **7-Zip** at `C:\Program Files\7-Zip\7z.exe` - the primary extractor, path hardcoded in
  `harvest.ps1`
- **innoextract** (Inno Setup <= 6.0.5) from
  [constexpr.org/innoextract](https://constexpr.org/innoextract/), drop at
  `tools\innoextract\innoextract.exe`
- **innounp** (Inno Setup > 6.0.5) - `winget install JurgenRathlev.innounp`
- Optional: **WiX 3.14** `dark.exe` at `tools\wix\`, only for Burn/MSI packages

Verify:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\rebuild_manifest.ps1
(Get-Content indexes\dedupe\known_bad_hashes.txt | Measure-Object -Line).Lines
```

Expected: `manifest: 0 rows, 0 unique hashes` and a gate count of `5833`. The filter refuses to
run without the gate - a lab with no blocklist would happily accept known-bad drivers.

> [!TIP]
> If PowerShell says "running scripts is disabled on this system", run scripts as
> `powershell -NoProfile -ExecutionPolicy Bypass -File <script> ...`, or run
> `Set-ExecutionPolicy -Scope Process Bypass` once in that window.

## Point your AI at the lab

Open the folder in your agent and start with:

> Read `AGENTS.md`, then `guides/00_quickstart.md`. Set up the lab and wait for my target.

### Example session

You name the target; the agent runs the machinery:

> **You:** Harvest as many RGB vendor drivers as you can this batch.
> **Agent:** proposes the package list (from `guides/01_collect_drivers.md` + the playbook), then
> per package: hash-verified `winget download`, `tools\harvest.ps1` (extract only), the one gate
> pass, provenance in `indexes\collections\collected1\`, and the `downloads\` wipe. Reports
> `DRIVER <name>` lines, `RESULT <id> drivers=N`, and updates `audits/STATUS.md`.
> **You:** audit `nzxt_cam` statically next.
> **Agent:** blocklist check, REA audit, canonical report, verdict row in `audits/STATUS.md`.

## The loop

| Step | Guide | You produce |
|:---:|---|---|
| 1 | [`guides/01_collect_drivers.md`](guides/01_collect_drivers.md) | `drivers\<name>_<hash8>.sys` + batch provenance |
| 2 | [`guides/02_blocklist_check.md`](guides/02_blocklist_check.md) | dated check in `audits\evidence\` |
| 3 | [`guides/03_audit.md`](guides/03_audit.md) | canonical report in `audits\reports\` |
| 4 | [`guides/04_dynamic_vm.md`](guides/04_dynamic_vm.md) | proof logs in `poc\dynamic\results\` |
| 5 | [`audits/STATUS.md`](audits/STATUS.md) | one verdict row per driver |

## Hard rules

- Only kernel memory writes count; hardware-only writes (MSR / port / PCI / SMBus / EC / MMIO)
  are `HW-ONLY`. Vocabulary: `R1`-`R3`, `W0`-`W3P`, `MW1`-`MW4` - full definitions in
  [`audits/scope/`](audits/scope/).
- Never execute an installer or load a driver on the host. Dynamic work is VM-only, snapshot
  first.
- `drivers\` stays flat: `.sys` plus `README.md` only, written only by the dedupe gate - never
  copy by hand.
- One canonical report per driver; update `audits/STATUS.md` **after** writing the report.
- No exploit code in reports; PoCs live in `poc\` and run only in the VM.

Missing a file the docs reference? Open the same path on the `example` branch (original run
snapshot), or fetch it with the block above. Nothing in this repo is a binary.
