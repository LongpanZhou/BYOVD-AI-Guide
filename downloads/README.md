# downloads/ — disposable scratch

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

Installers live here **only during a batch**. Gitignored — only `README.md` + `.gitkeep` are committed.

## Prerequisites

- **7-Zip** at `C:\Program Files\7-Zip\7z.exe` (core extractor; used by `harvest.ps1`).
- Optional: WiX `dark.exe` and `innoextract.exe` (extract more installer types).

## The loop (per batch)

```powershell
# 1. download a vendor installer into this folder
winget download --id <PackageId> --download-directory .

# 2. harvest every .sys out of it (never executing the installer)
..\tools\harvest.ps1 -Path .\<installer> -Vendor <Vendor> -PackageId <Id> `
  -Out .\_harvest -Index ..\indexes\collections\collected6\_index.jsonl

# 3. dedupe gate: only NEW .sys get into drivers/
..\tools\filter_new_drivers.ps1 -SourceDir .\_harvest -OutDir ..\drivers `
  -Manifest ..\indexes\collections\collected6\manifest.csv `
  -Existing ..\indexes\dedupe\existing_hashes.txt `
  -KnownBad ..\indexes\dedupe\known_bad_hashes.txt -UpdateExisting

# 4. rebuild the manifest
..\tools\rebuild_manifest.ps1 -NewBatch collected6

# 5. wipe the scratch (keep README.md + .gitkeep)
Get-ChildItem . -Force | Where-Object { $_.Name -notin @('README.md','.gitkeep') } | Remove-Item -Recurse -Force
```

The scripts create `indexes/collections/collected6/` and `downloads/_harvest` on first use;
`collected6` is just the next batch name — use `collected7`, `collected8`, etc. for later batches.

> [!TIP]
> On a default Windows install, PowerShell may block local scripts. If you see
> "running scripts is disabled on this system", run scripts as
> `powershell -NoProfile -ExecutionPolicy Bypass -File <script> ...`, or for the current window:
> `Set-ExecutionPolicy -Scope Process Bypass`.

## Hard rules

- Installer cap: **500 MiB**.
- **Never execute** an installer. Extraction only.
- Only `.sys` moves to `../drivers/`.
- Full method and vendor list: [`../DRIVER_COLLECTION_PLAYBOOK.md`](../DRIVER_COLLECTION_PLAYBOOK.md).
