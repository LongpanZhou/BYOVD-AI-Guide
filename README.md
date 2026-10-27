# BYOVD AI Guide

Start your own AI-driven Windows-driver (BYOVD) hunt here. The original run (outdated setup)
lives on the [`example`](https://github.com/LongpanZhou/BYOVD-AI-Guide/tree/example) branch.

> [!IMPORTANT]
> **Total API cost for a full run is around $20 USD** - pay-per-token usage, not a subscription.
> Small targets and short batches cost proportionally less.

## Setup

```powershell
git clone https://github.com/LongpanZhou/BYOVD-AI-Guide.git driver_lab
cd driver_lab
```

Open the folder in your AI agent (OpenCode, Claude, Copilot, ...) and use this conversation -

| # | You say | The agent does |
|---|---|---|
| 1 | "Set up my lab: refresh the blocklist gate from the live LOLDrivers feed, tell me which extractors I still need, run all verification, and wait for my target." | Refreshes the gate from the live feed, verifies the four shipped tools (`manifest: 0 rows, 0 unique hashes`), then waits. |
| 2 | "Harvest as many RGB vendor drivers as you can this batch." | Proposes the package list, then per package: hash-verified `winget download`, `tools\harvest.ps1` (extract only), one dedupe-gate pass, provenance in `indexes/collections/collected1/`, wipes `downloads\`. |
| 3 | "Audit them statically and give verdicts." | Blocklist check per driver, REA audit, one canonical report each in `audits/reports/`, verdict rows in `audits/STATUS.md`. |
| 4 | "Fuzz the candidates on my VM." | Snapshot, then load and exercise each candidate in the disposable VM only (`guides/04_dynamic_vm.md`), proof logs in `poc/dynamic/results/<date>/`, verdicts finalized. |

**Turn 1 runs once, then you keep naming targets** - turns 2-4 are examples: each new target
sends the agent around the loop again (the arrow back to `collect`):

```text
setup  ->  collect  ->  blocklist check  ->  audit  ->  VM proof  ->  verdict
               ^                                                     |
               +-----------------------------------------------------+
```

Every step is documented in `AGENTS.md` and the five [guides/](guides/). The only things you
bring: three extractors (see `DRIVER_COLLECTION_PLAYBOOK.md` section 3), a disposable Windows VM
for step 4, and your REA MCP server for step 3.
