# Quickstart — build your own bad-driver research repo

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

This repo is a working example. You can copy its structure in about ten minutes and start
hunting for vulnerable Windows drivers in your own environment.

## 1. Create the structure

```
driver_lab/
├── drivers/                  # ALL .sys binaries, flat — one folder, no subfolders
├── audits/
│   ├── STATUS.md             # single source of truth for every verdict
│   ├── reports/              # one .md report per driver
│   ├── scope/                # your rules: scope, severity, agent prompt
│   └── evidence/             # logs/prove-you-did-it outputs
├── poc/                      # test harnesses (VM-only!)
├── downloads/                # gitignored scratch for installers/extract trees
├── indexes/
│   ├── drivers_manifest.csv  # name, batch, path, size, SHA-256 of every driver
│   ├── dedupe/               # existing_hashes.txt + known_bad_hashes.txt
│   └── collections/          # per-batch provenance (URLs, agent notes)
├── WANTED_LEDGER.md          # the wishlist — which vulnerability classes this hunt is after
├── tools/                    # harvest.ps1, triage_scan.ps1, rebuild_manifest.ps1
└── README.md                 # your guide
```

Two rules that make the loop work:

- **`STATUS.md` is the only live queue.** Every other document links to it instead of copying.
- **Everything flat.** Drivers never get subfolders; the manifest's `Batch` column carries provenance.

The scripts are in `tools/` on this branch. The `main` branch ships instructions only and
fetches them from here — copy them into your `tools/` folder instead of reinventing them:

- [`tools/harvest.ps1`](https://github.com/LongpanZhou/BYOVD-AI-Guide/blob/example/tools/harvest.ps1) — archive extraction
- [`tools/triage_scan.ps1`](https://github.com/LongpanZhou/BYOVD-AI-Guide/blob/example/tools/triage_scan.ps1) — peeks inside a driver
- [`tools/rebuild_manifest.ps1`](https://github.com/LongpanZhou/BYOVD-AI-Guide/blob/example/tools/rebuild_manifest.ps1) — regenerates the manifest
- [`tools/filter_new_drivers.ps1`](https://github.com/LongpanZhou/BYOVD-AI-Guide/blob/example/tools/filter_new_drivers.ps1) — the mandatory dedupe gate

Download 7-Zip. WiX `dark.exe` and `innoextract` are optional and go in `tools/`.

## 2. Clone this repo to start

```shell
git clone https://github.com/<owner>/<repo>.git driver_lab
cd driver_lab
# delete everything under drivers/ and audits/reports/, keep the empty folders and docs
# — the content here is the example, the structure is what you reuse
```

## 3. First commands once you've collected something

```shell
# after harvesting a vendor package
tools/harvest.ps1 -Path downloads\<installer>.exe -Vendor <Vendor> -PackageId <Id> -Out downloads\_harvest
# after dropping the .sys into drivers/
tools/rebuild_manifest.ps1
```

Then cross-check every hash in `indexes/dedupe/known_bad_hashes.txt` (see
[`02_blocklist_check.md`](02_blocklist_check.md)).
