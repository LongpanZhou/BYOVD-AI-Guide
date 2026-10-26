# BYOVD AI Guide

**A beginner's guide to finding vulnerable Windows drivers.**

> [!CAUTION]
> **AI-written docs.** Every README and guide here was written by an AI agent, so expect
> mistakes. Verify commands, paths, versions, and hashes before relying on them.

> [!IMPORTANT]
> **The goals are a starting point — change them.** Ask AI to change the goals of this project
> into whatever you need: a different driver class, a different vulnerability primitive, a
> different target set, or a different lab shape. Edit [`PROJECT_GOAL.md`](PROJECT_GOAL.md), or
> simply prompt the agent.

> [!TIP]
> **AI spend:** a full run (collection + static audits of all 386 drivers + verification) costs
> about **$20 USD**. Models used: **GLM-5.3-Flash**, **DeepSeek-V4.1-Flash**, and **Haiku-5.5**
> through OpenCode Go (`opencode-go`, variant `max`).

> [!NOTE]
> **The verified drivers are deliberately absent.** Their binaries, hashes, IOCTL numbers, and
> logs live offline, not in git. If you fork this, do the same.

<details>
<summary><b>Contents</b></summary>

&nbsp;

- [What this repo is](#what-this-repo-is)
- [Setup](#setup)
- [Run the loop](#run-the-loop)
- [What's inside](#whats-inside)

</details>

## What this repo is

An AI-driven Windows driver vulnerability research guide: a repeatable method for finding drivers
that expose an arbitrary kernel memory-write primitive, plus a worked example corpus.

| | |
|---|---|
| **Goal** | [`PROJECT_GOAL.md`](PROJECT_GOAL.md) — edit it to re-target the hunt |
| **Reading order** | [`START_HERE.md`](START_HERE.md) |
| **Live status and queue** | [`audits/STATUS.md`](audits/STATUS.md) |
| **Target wishlist** | [`WANTED_LEDGER.md`](WANTED_LEDGER.md) |
| **Canonical counts** | [`indexes/README.md`](indexes/README.md) |

## Setup

This repo has **two branches**. Clone the one that fits what you're doing.

<details open>
<summary><b>Route A — instructions only (<code>guide</code> branch)</b></summary>

&nbsp;

No drivers, no audit data, no corpus — just the instruction set, the goal/ledger files, and the
empty folder skeleton. Clone this if you want to build your own lab from nothing:

```powershell
git clone -b guide https://github.com/LongpanZhou/BYOVD-AI-Guide.git driver_lab
cd driver_lab
Get-ChildItem -Directory | Select-Object -ExpandProperty Name
```

Expected: `audits`, `downloads`, `drivers`, `guides`, `indexes`, `poc`, `tools`. The clone already
contains the full tree, the ledgers, and an empty `audits/STATUS.md`; there is nothing to create or
commit.

> [!TIP]
> If PowerShell blocks local scripts, run them as
> `powershell -NoProfile -ExecutionPolicy Bypass -File <script> ...`, or run
> `Set-ExecutionPolicy -Scope Process Bypass` once in that window.

Then read [`guides/00_quickstart.md`](guides/00_quickstart.md); its step 3 fetches the four
tools from `main`.

</details>

<details open>
<summary><b>Route B — full working example (<code>main</code> branch)</b></summary>

&nbsp;

The full data set: corpus, audit reports, evidence, `tools/`, everything. Clone this to see the
methodology executed against real drivers:

```shell
git clone https://github.com/LongpanZhou/BYOVD-AI-Guide.git driver_candidates
cd driver_candidates
```

</details>

### Prerequisites

| Tool | Required | Notes |
|---|---|---|
| **OpenCode** | **yes** | the AI agent harness — it drives collection, subagent audits, and dynamic verification |
| 7-Zip | yes | `C:\Program Files\7-Zip\7z.exe` — the only extractor that touches installers |
| **innoextract** | yes (Inno Setup ≤ 6.0.5 only) | drop the exe at `tools/innoextract/innoextract.exe` — **not tracked in this repo**, download separately ([constexpr.org/innoextract](https://constexpr.org/innoextract/)) |
| **innounp** | yes (Inno Setup > 6.0.5) | `winget install JurgenRathlev.innounp` — `innoextract` chokes on newer Inno Setup bundles (e.g. CPU-Z 3.01 ships Inno 6.3.0) |
| WiX `dark.exe` | optional (WiX/Burn `.msi` unpacking) | install WiX into `tools/wix/` if a package needs Burn decompilation |
| Ghidra + JDK 21 (or IDA) | yes for static audits | headless decompilation is the validated primary engine; the debugger rarely keeps up with a freakout over 1 agent session |
| Disposable Windows VM (VMware) | yes for dynamic testing | snapshot `pre-driver-tests`, revert before every session; never the host |
| `mcp-windbg` server | yes for crash-dump triage | `!analyze -v` on guest `MEMORY.DMP` |
| `rea` MCP server | yes for in-session binary poking | has a 4-session capacity — digest-verify long sessions; use local Ghidra as fallback |

## Run the loop

Once the setup is in place, run these steps per batch; each has a detailed guide:

| Step | Guide | What you do |
|:---:|---|---|
| 1 | [`guides/00_quickstart`](guides/00_quickstart.md) | folder layout, command list |
| 2 | [`guides/01_collect_drivers`](guides/01_collect_drivers.md) | download → extract → dedupe into `drivers/` |
| 3 | [`guides/03_blocklist_check`](guides/03_blocklist_check.md) | check LOLDrivers + Microsoft blocklist per hash |
| 4 | [`guides/02_audit`](guides/02_audit.md) | static audit: dispatch/IOCTL/memory-write analysis |
| 5 | [`guides/04_dynamic_vm`](guides/04_dynamic_vm.md) | prove the primitive in a snapshotted VM |
| 6 | [`audits/STATUS.md`](audits/STATUS.md) | record the verdict |

> [!NOTE]
> Steps 3 and 4 are separate because the blocklist check runs *before* the audit. The file
> numbers follow content type, not execution order.

## What's inside

| Folder | Contents |
|---|---|
| [`drivers/`](drivers/) | 386 `.sys` binaries, flat |
| [`audits/`](audits/) | `STATUS.md` (verdict queue), `reports/` (257 reports), `evidence/` (blocklist checks + dump triage), `scope/` (severity scale) |
| [`poc/dynamic/`](poc/dynamic/) | privilege, lock-memory, and dump-listing helpers (no self-test harness) |
| [`indexes/`](indexes/) | manifest, dedupe hashes, known-bad hash list, batch metadata |
| [`tools/`](tools/) | `harvest.ps1`, `filter_new_drivers.ps1`, `rebuild_manifest.ps1`, `triage_scan.ps1` |
| [`downloads/`](downloads/) | (gitignored) installer scratch, wiped after each batch |
| [`guides/`](guides/) | the five step-by-step guides |

<details>
<summary><b>Not in the repo</b></summary>

&nbsp;

- `VM_ACCESS.md` — VM credentials (local, gitignored)
- `drivers/vgk.sys` — 104 MB, over the push limit
- the verified drivers — binaries, hashes, IOCTL numbers, and logs are kept offline

If you fork, do the same: export verified finds offline and keep them out of the repo.

</details>
