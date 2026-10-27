# BYOVD AI Guide

Start your own AI-driven Windows-driver (BYOVD) hunt here. The worked example (386 drivers,
257 reports) lives on the [`example`](https://github.com/LongpanZhou/BYOVD-AI-Guide/tree/example)
branch - the original run's snapshot, so its wording may not match the current docs.

## Setup

```powershell
git clone https://github.com/LongpanZhou/BYOVD-AI-Guide.git driver_lab
cd driver_lab
```

Open the folder in your AI agent (OpenCode, Claude, ...) and run this chat:

> **You:** Read `AGENTS.md`, then `guides/00_quickstart.md`. Set up my lab: refresh the blocklist
> gate from the live LOLDrivers feed, tell me which extractors I still need, run all
> verification, and wait for my target.
>
> **Agent:** Done - gate refreshed from today's feed, tools verified, `manifest: 0 rows, 0
> unique hashes`. Extractors you still need: none right now. Waiting for target.
>
> **You:** Harvest as many RGB vendor drivers as you can this batch.
>
> **Agent:** Proposing the package list... for each: hash-verified `winget download`,
> `tools\harvest.ps1` extract-only, one dedupe-gate pass, provenance in
> `indexes/collections/collected1/`, scratch wiped. `RESULT ... drivers=17`,
> `audits/STATUS.md` updated.
>
> **You:** Audit them statically and give verdicts.
>
> **Agent:** Blocklist check per driver, REA audit, one canonical report each in
> `audits/reports/`, verdict rows in `audits/STATUS.md`.

After that, keep naming targets; the agent runs the loop (collect -> blocklist check -> audit ->
dynamic proof in a VM -> verdict). Every detail of each step is in the five `guides/`.
