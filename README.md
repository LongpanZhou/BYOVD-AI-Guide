# BYOVD AI Guide - worked example

**Guide to finding vulnerable Windows drivers using AI**

This is the `example` branch: the worked example - full corpus, audit reports, and evidence. The method itself, and the clean lab skeleton for running your own hunt, lives on [`main`](https://github.com/LongpanZhou/BYOVD-AI-Guide/tree/main).

> [!TIP]
> API cost for a full run is roughly **$20 USD** - pay-per-token usage, not a plan/subscription price.

## Start here

| | |
|---|---|
| Goal - edit to re-target the hunt | [`PROJECT_GOAL.md`](PROJECT_GOAL.md) |
| Reading order | [`START_HERE.md`](START_HERE.md) |
| Live status and queue | [`audits/STATUS.md`](audits/STATUS.md) |
| Target wishlist | [`WANTED_LEDGER.md`](WANTED_LEDGER.md) |
| Canonical counts | [`indexes/README.md`](indexes/README.md) |

## Setup

Two branches - clone the one that fits:

- **`main`** - instructions only: the guides, ledgers, and empty folder skeleton, for building your own lab from nothing:

  ```shell
  git clone https://github.com/LongpanZhou/BYOVD-AI-Guide.git driver_lab
  ```

  Then follow [`guides/00_quickstart.md`](guides/00_quickstart.md); its step 2 fetches the four tools from this branch.

- **`example`** (this branch) - the full worked example: corpus, audit reports, evidence, `tools/`:

  ```shell
  git clone -b example https://github.com/LongpanZhou/BYOVD-AI-Guide.git driver_candidates
  ```

## Run the loop

Run these steps per batch; each has a detailed guide:

| Step | Guide | What you do |
|:---:|---|---|
| 1 | [`guides/00_quickstart`](guides/00_quickstart.md) | folder layout, command list |
| 2 | [`guides/01_collect_drivers`](guides/01_collect_drivers.md) | download -> extract -> dedupe into `drivers/` |
| 3 | [`guides/02_blocklist_check`](guides/02_blocklist_check.md) | LOLDrivers + Microsoft blocklist per hash (runs **before** the audit) |
| 4 | [`guides/03_audit`](guides/03_audit.md) | static audit: dispatch/IOCTL/memory-write analysis |
| 5 | [`guides/04_dynamic_vm`](guides/04_dynamic_vm.md) | prove the primitive in a snapshotted VM |
| 6 | [`audits/STATUS.md`](audits/STATUS.md) - example | record the verdict |

## What's inside

| Folder | Contents |
|---|---|
| [`drivers/`](drivers/) | 386 `.sys` binaries, flat |
| [`audits/`](audits/) | `STATUS.md` (verdict queue), `reports/` (257), `evidence/` (blocklist checks + dump triage), `scope/` (severity scale) |
| [`guides/`](guides/) | the five step-by-step guides |
| [`indexes/`](indexes/) | manifest, dedupe hashes, known-bad hash list, batch metadata |
| [`poc/dynamic/`](poc/dynamic/) | privilege, lock-memory, and dump-listing helpers |
| [`tools/`](tools/) | `harvest.ps1`, `filter_new_drivers.ps1`, `rebuild_manifest.ps1`, `triage_scan.ps1` |
| [`downloads/`](downloads/) | (gitignored) installer scratch, wiped after each batch |
