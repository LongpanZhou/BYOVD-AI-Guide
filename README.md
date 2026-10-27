# BYOVD AI Guide

This repo is the **setup and instruction set** for an AI-driven Windows driver research lab.
It contains the folder skeleton, the goal/ledger files, and the method. It contains **no drivers,
no audit reports, no corpus, and no tool binaries** - the worked example (386 `.sys` files, 257
reports, scripts) lives on the [`example`](https://github.com/LongpanZhou/BYOVD-AI-Guide/tree/example)
branch. Note that `example` is a snapshot of the **original run's** setup: counts, wording, and
some file names there may not match the current docs on `main` - treat it as a reference, not the
manual.

## What you get

| Path | Purpose |
|---|---|
| `AGENTS.md` | operating instructions for an AI agent - start here if an AI is doing the work |
| `PROJECT_GOAL.md` | the canonical goal; edit this to re-target the hunt |
| `WANTED_LEDGER.md` | what counts as a find |
| `PROJECT_MAP.md` | folder map for this branch |
| `audits/STATUS.md` | empty verdict queue (template) |
| `audits/scope/` | reach tiers, severity scale, default audit prompt |
| `guides/` | the five step-by-step guides |
| every data folder | empty, with a `README.md` saying what belongs there |

## 1. Clone the lab

```powershell
git clone https://github.com/LongpanZhou/BYOVD-AI-Guide.git driver_lab
cd driver_lab
```

The clone already contains the full folder tree. You do **not** need to create directories, and
there is nothing to commit yet.

## 2. Verify the structure

```powershell
Get-ChildItem -Directory | Select-Object -ExpandProperty Name
```

Expected, one per line:

```text
audits
downloads
drivers
guides
indexes
poc
tools
```

Check that the ledgers are present:

```powershell
Get-ChildItem PROJECT_GOAL.md, WANTED_LEDGER.md, audits\STATUS.md, AGENTS.md
```

## 3. Fetch the tools and the blocklist gate

Collection also needs three extractors on the host (details in `DRIVER_COLLECTION_PLAYBOOK.md` section 3):

- **7-Zip** at `C:\Program Files\7-Zip\7z.exe` - the primary extractor; its path is hardcoded
  in `harvest.ps1`
- **innoextract** (Inno Setup <= 6.0.5) - download from
  [constexpr.org/innoextract](https://constexpr.org/innoextract/), drop at
  `tools\innoextract\innoextract.exe`
- **innounp** (Inno Setup > 6.0.5) - `winget install JurgenRathlev.innounp`
- Optional: **WiX 3.14** -> install `dark.exe` at `tools\wix\` only if a package needs
  Burn/MSI decompilation.

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

Expected: four `.ps1` files, plus `known_bad_hashes.txt` at roughly 380 KB (5,833 hashes). The
filter **refuses to run without it** - a lab with no blocklist would happily accept known-bad
drivers.

## 4. Verify the tools

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\rebuild_manifest.ps1
```

Expected output:

```text
manifest: 0 rows, 0 unique hashes
```

That also creates `indexes\drivers_manifest.csv`. Confirm the gate is populated:

```powershell
(Get-Content indexes\dedupe\known_bad_hashes.txt | Measure-Object -Line).Lines
```

Expected: `5833`.

> [!TIP]
> If PowerShell says **"running scripts is disabled on this system"**, use the
> `powershell -NoProfile -ExecutionPolicy Bypass -File ...` form above for every script, or run
> `Set-ExecutionPolicy -Scope Process Bypass` once in that window.

## 5. Point your AI at the lab

Open the folder in OpenCode (or another agent) and start with:

> Read `AGENTS.md`, then `guides/00_quickstart.md`. Set up the lab and wait for my target.

`AGENTS.md` carries the hard rules: scope, where to write, what never to run on the host, and how
to keep `audits/STATUS.md` current. Edit `PROJECT_GOAL.md` and `WANTED_LEDGER.md` first if you
want a different target class - the rest of the loop keys off those two files.

### Example session

You name the target; the agent runs the machinery. A first harvest looks like:

> **You:** Harvest as many RGB vendor drivers as you can this batch.
> **Agent:** proposes the package list from `guides/01_collect_drivers.md` and the playbook, then
> for each package: hash-verified `winget download`, `tools\harvest.ps1` (extract only), the one
> gate pass (`tools\filter_new_drivers.ps1 ... -UpdateExisting`), provenance in
> `indexes\collections\collected1\`, and the `downloads\` wipe.
> **Agent reports back:** one `DRIVER <name> <bytes> <sig> <reach>` line per accepted `.sys`,
> `RESULT <id> drivers=N`, and an updated corpus table in `audits/STATUS.md`.
> **You:** audit `nzxt_cam` statically next.
> **Agent:** blocklist check, REA audit, canonical report in `audits/reports/`, verdict row in
> `audits/STATUS.md`.

## 6. The loop

| Step | Read | You produce |
|:---:|---|---|
| 1 | [`guides/01_collect_drivers.md`](guides/01_collect_drivers.md) | `drivers\<name>_<hash8>.sys` + `indexes\collections\collected<N>\manifest.csv` |
| 2 | [`guides/02_blocklist_check.md`](guides/02_blocklist_check.md) | `audits\evidence\known_vulnerable_check_<date>.md` |
| 3 | [`guides/03_audit.md`](guides/03_audit.md) | `audits\reports\<driver>.md` |
| 4 | [`guides/04_dynamic_vm.md`](guides/04_dynamic_vm.md) | `poc\dynamic\results\<date>\<driver>_<harness>.log` |
| 5 | [`audits/STATUS.md`](audits/STATUS.md) | one verdict row |

## 7. Vocabulary

| Term | Meaning |
|---|---|
| `R1` | unprivileged / authenticated user |
| `R2` | local administrator - **in scope** |
| `R3` | devnode / hardware / composition |
| `W0`-`W3P` | write quality (`W3P` = physical-memory only) |
| `MW1`-`MW4` | severity, highest to lowest |
| `HW-ONLY` | MSR / port / PCI / SMBus / EC / MMIO - does not count as a memory write |

Full definitions: [`audits/scope/`](audits/scope/).

## 8. Hard rules

- Only kernel memory writes count. Hardware-only writes are `HW-ONLY`.
- Never execute an installer or load a driver on the host. Dynamic work is VM-only.
- `drivers\` is flat and holds only `.sys` plus `README.md`; add files only through
  `tools\filter_new_drivers.ps1`.
- One canonical report per driver; update `audits\STATUS.md` after writing it.
- No exploit code in reports; PoCs live in `poc\`.

## 9. If a link points at a file you don't have

Some guides mention reports, drivers, or helpers that are not on this branch. Open the same path
on [`example`](https://github.com/LongpanZhou/BYOVD-AI-Guide/tree/example), or fetch the four scripts in
step 3. Nothing in this branch is a binary.
