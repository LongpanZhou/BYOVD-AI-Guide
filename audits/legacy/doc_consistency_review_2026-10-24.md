# Documentation Consistency Review — 2026-10-24

**Reviewer:** independent documentation/consistency pass (read-only)
**Scope:** all canonical Markdown, area READMEs, scope docs, index READMEs, and the three collection scripts
**Method:** file reads, `Select-String`, file counts, hash counts, and a relative-link check. No `.sys` file was opened with an analysis tool, no REA session was used, and nothing was executed.

**Only file written:** this review.

---

## Verdict summary

**Conditional pass.** The six-area structure is real and the numeric state is accurate:

- `drivers/` contains **394 `.sys` + `README.md` only**, with **394 unique SHA-256** values.
- `indexes/drivers_manifest.csv` has **394 rows and 394 unique hashes**; every manifest path exists and every size matches. All 394 hashes are in `indexes/dedupe/existing_hashes.txt`.
- Dedupe index is **932 unique hashes**; known-bad list is **5,833 unique hashes**.
- On-disk `.sys` total is **396** = 394 corpus + `poc/reference/dbk64.sys` + `audits/evidence/t7_guest_vsock.sys`, exactly as `indexes/README.md` says.
- `downloads/` contains only `README.md` and `.gitkeep`.
- No `_collected*`, `dynamic_evidence`, `_vm_batch*`, `_known_bad_control`, or root `README.txt` remains. `handover_agentH/` is a real retained folder under `audits/projects/`; `vm_batch2/` is correctly under `audits/legacy/`.
- All relative Markdown links in the 22 canonical/area docs resolve.

However, the project is **not ready for the next download batch** and the severity scale is not consistently applicable:

1. `SEVERITY.md` contradicts itself on `W3` / physical-memory-only writes; current reports already rate the same `W3` two different ways.
2. `SEVERITY.md` tells auditors to re-read known-bad/blocklisted drives that `STATUS.md` says must not be re-audited.
3. `drivers/README.md` gives an unrunnable `filter_new_drivers.ps1` command and tells the reader to copy files into `drivers/` by hand, bypassing the dedupe gate.
4. No download workflow updates `existing_hashes.txt` after a batch is accepted, so the mandatory dedupe gate goes stale immediately after every successful batch.

The reports tree is also a mixed current/legacy tree (P1), even though three canonical docs call it "all current".

---

## What passed

| Check | Result |
|---|---|
| Six top-level areas | `audits/`, `downloads/`, `drivers/`, `indexes/`, `poc/`, `tools/` only |
| `drivers/` payload | 394 `.sys` + `README.md`; no `.inf`, `.cat`, `.exe`, subfolder |
| `downloads/` payload | `README.md` + `.gitkeep` only |
| Manifest | 394 rows, 394 unique, no duplicate hashes, all paths/sizes valid |
| Batch totals | original 94 + collected2 135 + collected3 11 + collected5 43 + collected1 111 = 394 |
| Dedupe | 932 unique; all 394 corpus hashes present |
| Known-bad | 5,833 unique |
| On-disk `.sys` | 396 = 394 + 2 documented non-corpus references |
| Canonical links | all relative links resolve |
| Stale folders | none of `_collected*`, `dynamic_evidence`, `_vm_batch*`, `_known_bad_control` |
| Stale ledger | no active `_ledger.md`; only `audits/legacy/agent_ledgers_2026-10-24.zip` |
| Old counts | 389/106/776 only in `audits/legacy/structure_review_2026-10-24.md` (historical) |
| Goal wording | every canonical doc says memory-write-only, R2 in scope, setup is a severity field, hardware-only is `HW-ONLY` |

---

## P0 — must fix

### P0-1 — `SEVERITY.md` is internally inconsistent for `W3` and physical-memory writes

**Evidence**

- `audits/scope/SEVERITY.md:17` defines `W3` as **"fixed/narrow/PA-only"** — three different things in one value.
- `audits/scope/SEVERITY.md:27` says **MW3** is "Physical-memory mapping/write only" and lists required conditions **`W2`/`W3` + `R3` hardware; physmem map**.
- `audits/scope/SEVERITY.md:28` says **MW4** is "Narrow/fixed memory write" with required condition **`W3`**.
- The matrix at `audits/scope/SEVERITY.md:40-43` maps `W3` to **MW4** for every reach tier.
- The current DirectIo64 report rates **`W3` → MW3** (`audits/reports/DirectIo64.md:11-12`), and `audits/STATUS.md:35`, `PROJECT_GOAL.md:80`, and `README.md:51` all carry **MW3**.
- The current ImDisk report rates **`W3` → MW4** and explicitly cites the matrix (`audits/reports/imdisk.admin.static.md:12,135`).
- `audits/scope/SEVERITY.md:80-82` also calls physical-memory mapping an admin/R2 path, which the matrix sends to MW4.

**Why this blocks work:** two signed auditor outputs use the same `W3` input and produce different published levels (MW3 vs MW4). An auditor cannot apply the scale without guessing whether "PA-only" or "fixed/narrow" wins. This propagates into `STATUS.md`, `PROJECT_GOAL.md`, and `README.md`.

**Suggested edit (preferred): split the write-quality axis**

1. In `audits/scope/SEVERITY.md:17`, change the `Write quality` values to:
   `W1 arbitrary target + value · W2 constrained target or value · W3 fixed/narrow · W3P physical-memory (PA-only) mapping/write · W0 no memory write`
2. In `:27`, make MW3's required condition `W3P` (plus `R3` + `W2` where applicable), and remove `W3`.
3. In `:28`, keep MW4 for `W3` fixed/narrow/crash-first.
4. In `:38-44`, add a `W3P (PA-only)` column with **MW3** for R1/R2 and R3; keep `W3` → **MW4**.
5. In `:88`, change the report field grammar to `write=<W1|W2|W3|W3P|W0>`; make the same change in `audits/scope/AUDIT_SCOPE.md:66` and `audits/scope/STATIC_ANALYSIS_AGENT_PROMPT.md:119`.
6. Change `audits/reports/DirectIo64.md:11` from `W3` to `W3P`; leave ImDisk as `W3`.
7. Move the `CBULWDM` example out of MW2 at `:26` and into MW3/W3P.
8. Remove "read-only mapping" from the MW4 example at `:28`; a read-only mapping is `NO-MEMORY-WRITE`, not a write.

**Alternative if a new value is unacceptable:** change DirectIo64 to MW4 and remove "physical-memory mapping" from the MW3 definition. That would contradict `PROJECT_GOAL.md:29-32` and the existing MW3 examples, so the split is cleaner.

---

### P0-2 — `SEVERITY.md` orders re-audits of known-bad drivers that `STATUS.md` says are BLOCKED

**Evidence**

- `audits/scope/SEVERITY.md:62` says: "Blocklisted / known-bad | **BLOCKED** regardless of primitive."
- `audits/scope/SEVERITY.md:81` says these "must be re-read with R2":
  `EVGA driver-x64/x86, SMI_IO, MSIO64, amifldrv, RTCore, NTIOLib`.
- `audits/STATUS.md:114-115` says: "MSI `RTCore*` is known-bad/blocklisted: **BLOCKED** regardless of primitive. Do not re-audit for exploitability."
- `indexes/dedupe/known_bad_hashes.txt` contains the hashes of these corpus files:
  - `driver-x64_33DA2CE2.sys`
  - `MSIO32_C7D4943D.SYS`
  - `MSIO64_525D9B51.SYS`
  - `amifldrv64_5F487829.sys`
  - `MsIo64_CFCF32F5.sys`
  - `RTCore64_40061B30.sys`

**Why this blocks work:** an agent reading `SEVERITY.md` is told to re-read RTCore/MSIO/amifldrv/EVGA x64; an agent reading `STATUS.md` is told not to. The former violates the project's own known-bad rule and wastes audit time.

**Suggested edit**

Replace `audits/scope/SEVERITY.md:81` with a split bullet:

```markdown
- EVGA `driver-x86`, `SMI_IO`, `NTIOLib`, `iocbios2` — old “blocked by DACL”; admin can open.
  The x64 `driver-x64_33DA2CE2`, `MSIO32/64`, `amifldrv`, `MsIo64_CFCF32F5`, and `RTCore*`
  hashes are in `known_bad_hashes.txt` → **BLOCKED; do not re-audit**.
```

Also add the six filenames above to `audits/STATUS.md` as a short "Known-bad images retained in `drivers/`" list, so a future agent does not have to join the manifest to the hash list. Add the exception "unless known-bad/blocklisted" to the historical warning at `audits/README.md:57`.

---

### P0-3 — `drivers/README.md` gives an unrunnable filter command and tells the reader to copy by hand

**Evidence**

`drivers/README.md:30-33`:

```text
2. Run `../tools/filter_new_drivers.ps1` with
   `-Existing ../indexes/dedupe/existing_hashes.txt`
   `-KnownBad ../indexes/dedupe/known_bad_hashes.txt`.
3. Copy the new `.sys` here.
```

`tools/filter_new_drivers.ps1:1-8` declares **`-SourceDir`, `-OutDir`, and `-Manifest` as mandatory**:

```powershell
param(
  [Parameter(Mandatory=$true)][string]$SourceDir,
  [Parameter(Mandatory=$true)][string]$OutDir,
  [Parameter(Mandatory=$true)][string]$Manifest,
  [string]$Existing = '',
  ...
)
```

So the documented command prompts for three mandatory parameters (or fails in a non-interactive agent). Step 3 then tells the reader to copy files into `drivers/` manually, which can copy non-deduped `_harvest` output.

**Suggested edit**

Replace `drivers/README.md:29-35` with a complete, runnable block:

```powershell
..\tools\filter_new_drivers.ps1 `
  -SourceDir ..\downloads\_harvest `
  -OutDir . `
  -Manifest ..\indexes\collections\collected<N>\manifest.csv `
  -Existing ..\indexes\dedupe\existing_hashes.txt `
  -KnownBad ..\indexes\dedupe\known_bad_hashes.txt
```

Then say: "The filter copies only NEW `.sys` files into `drivers/`; **do not copy from `_harvest` by hand**." Add the dedupe-index update (P0-4) and keep the URL/rebuild steps.

The same "copy only the deduped `.sys` into `drivers/`" wording at `README.md:86`, `START_HERE.md:36`, and `PROJECT_GOAL.md:98` should be changed to "the filter's `-OutDir drivers` performs the copy" to avoid a manual-copy reading.

---

### P0-4 — the download workflow never updates `existing_hashes.txt`, so the dedupe gate goes stale after every batch

**Evidence**

- `tools/filter_new_drivers.ps1:40-53` checks `$existing` / `$knownBad` and copies `NEW` files; it never writes to `existing_hashes.txt`.
- `tools/rebuild_manifest.ps1:20-31` only rebuilds `indexes/drivers_manifest.csv`; it never writes to `existing_hashes.txt`.
- `indexes/dedupe/README.md:10-13` is the **only** document that says to append new hashes and regenerate `dedupe_summary.txt`.
- The workflows omit that step:
  - `DRIVER_COLLECTION_PLAYBOOK.md:49-59` (§2.1) and `:391-397` (§9 fast loop)
  - `downloads/README.md:14-26`
  - `README.md:82-89`
  - `tools/README.md:20-27`
  - `drivers/README.md:30-35`
  - `START_HERE.md:38-39`

**Why this blocks work:** after a batch is accepted, its hashes are absent from the gate. A later package containing the same driver under a different filename is classified `NEW` and copied again with a different basename, breaking the "one copy per SHA-256" invariant and the 932-hash gate.

**Suggested edit**

Add this step to every workflow, immediately after the filter and before/after `rebuild_manifest`:

```powershell
# 4b. update the dedupe gate with accepted hashes
$manifest = Import-Csv indexes\collections\collected6\manifest.csv
$manifest | Where-Object Status -eq 'NEW' |
  ForEach-Object { Add-Content indexes\dedupe\existing_hashes.txt $_.SHA256 }
# then regenerate indexes\dedupe\dedupe_summary.txt
```

Better: add `-UpdateExisting` to `tools/filter_new_drivers.ps1` so the gate is updated atomically with the copy, and document that switch. Until then, add the explicit step to `DRIVER_COLLECTION_PLAYBOOK.md` §2.1/§9, `downloads/README.md`, `tools/README.md`, `README.md`, `drivers/README.md`, and `START_HERE.md`.

**Canonical sequence to adopt** (replaces the variants in the current docs):

```powershell
# 1. download into the only scratch folder
winget download -e --id <ID> --download-directory downloads `
  --accept-package-agreements --accept-source-agreements --disable-interactivity

# 2. harvest
powershell -NoProfile -ExecutionPolicy Bypass -File tools\harvest.ps1 `
  -Path "downloads\<installer>" -Vendor "<Vendor>" -PackageId "<ID>" `
  -Out "downloads\_harvest" -Index "indexes\collections\collected6\_index.jsonl"

# 3. dedupe-copy into the corpus
powershell -NoProfile -ExecutionPolicy Bypass -File tools\filter_new_drivers.ps1 `
  -SourceDir "downloads\_harvest" -OutDir "drivers" `
  -Manifest "indexes\collections\collected6\manifest.csv" `
  -Existing "indexes\dedupe\existing_hashes.txt" `
  -KnownBad "indexes\dedupe\known_bad_hashes.txt"

# 4. update the gate
# append NEW SHA256s from manifest.csv to existing_hashes.txt; regenerate dedupe_summary.txt

# 5. rebuild inventory
powershell -NoProfile -ExecutionPolicy Bypass -File tools\rebuild_manifest.ps1 -NewBatch collected6

# 6. update every count copy (see P1-6)

# 7. delete scratch, keep the two markers
Get-ChildItem downloads -Force |
  Where-Object { $_.Name -notin @('README.md','.gitkeep') } |
  Remove-Item -Recurse -Force
```

---

## P1 — should fix

### P1-1 — `audits/reports/` is still a mixed current/legacy report tree

**Evidence**

- `audits/README.md:26` calls `reports/` "All current per-driver reports"; `audits/README.md:48` then says "Many reports in `reports/` and `legacy/` predate the 2026-10-24 scope update."
- `audits/reports/README.md:1` is headed "Current reports"; `PROJECT_MAP.md:34` says "All current per-driver reports"; `START_HERE.md:29` says "Current reports".
- `audits/reports/` has **141** Markdown files, but only **16** report names appear in `STATUS.md`. It contains **22 plain `*.static.md`** files and **38** files containing `WRITE-*` strings. Concrete old-policy conclusions:
  - `audits/reports/elgato_capture.static.md:11`: "All 12 families: NO-WRITE. Every family is disqualified by policy on setup cost." This directly contradicts the current goal.
  - `audits/reports/b06bdrv.md:9`: verdict `WRITE-HIGH`.
  - `audits/reports/hp_rtf64x64.static.md:15`: verdict `WRITE-HIGH`.
  - `audits/reports/silabser.md:307`: "VULNERABLE (static) - high-severity local privilege-escalation exposure."

**Suggested edit**

Either (preferred) move the pre-2026-10-24 reports to `audits/legacy/`, leaving `audits/reports/` only for current-scope reports, or add a one-line banner to every pre-scope report:

```markdown
> **HISTORICAL (pre-2026-10-24):** uses the old `WRITE-*` scale and may treat setup/hardware as disqualifying. Current scope: `audits/scope/AUDIT_SCOPE.md`; current verdicts: `audits/STATUS.md`.
```

At minimum, change the wording in `audits/README.md:26`, `audits/reports/README.md:1`, `PROJECT_MAP.md:3,34`, and `START_HERE.md:29` from "all current" to "current plus retained historical reports; `STATUS.md` is authoritative."

### P1-2 — `README.md` "Top findings" contains three drivers absent from `STATUS.md` / `PROJECT_GOAL.md`

**Evidence**

- `README.md:56` HP `rtf64x64` MW2, `:57` `silabser` MW2, `:58` `bxvbda` MW2.
- `audits/STATUS.md:27-45` does not list any of the three; `PROJECT_GOAL.md:73-90` does not either.
- Their reports still use old vocabulary: `audits/reports/hp_rtf64x64.static.md:15` `WRITE-HIGH`; `audits/reports/b06bdrv.md:9` `WRITE-HIGH`; `audits/reports/silabser.md:307` "VULNERABLE".

**Suggested edit**

Either add the three to `audits/STATUS.md` "Current results" with the reach/setup from their reports, or move them in `README.md` to a separate table:

```markdown
### Historical findings (pre-2026-10-24; re-audit before citing)
```

and add a note to `STATUS.md` that these are not current results. Do not leave them presented as equivalent to the current MW-rated rows.

### P1-3 — cleanup commands delete `downloads/README.md` and `.gitkeep` despite saying "keep"

**Evidence**

- `downloads/README.md:24`: `Remove-Item .\* -Recurse -Force` "(keep `README.md`)" — the command deletes it, and `.gitkeep` too.
- `DRIVER_COLLECTION_PLAYBOOK.md:397`: `Remove-Item downloads\* -Recurse -Force # keep downloads\README.md and .gitkeep` — same.
- `README.md:89`: "Delete everything in `downloads/`" — no exception.
- `PROJECT_MAP.md:15` and `downloads/README.md:4` say the folder is "empty" after harvest, while `.gitignore` explicitly unignores `README.md` and `.gitkeep`.

**Suggested edit**

Use the exclusion command from P0-4 step 7, or simply delete only the scratch trees:

```powershell
Remove-Item downloads\_harvest, downloads\_hx -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem downloads -File | Where-Object Name -notin @('README.md','.gitkeep') |
  Remove-Item -Force
```

Change "empty" to "contains only `README.md` and `.gitkeep`" in `PROJECT_MAP.md:15` and `downloads/README.md:4`.

### P1-4 — `downloads/README.md` quick-start has no runnable harvest command; 7-Zip prerequisite is undocumented

**Evidence**

- `downloads/README.md:12-13` says only "Extract with `../tools/harvest.ps1` ... It writes `.sys` files to `downloads/_harvest`." It does not show the required `-Path`, `-Vendor`, `-PackageId`, `-Out`, or `-Index`.
- `tools/harvest.ps1:13` hardcodes `C:\Program Files\7-Zip\7z.exe`. No doc lists 7-Zip as a prerequisite; `DRIVER_COLLECTION_PLAYBOOK.md:70-75` lists `harvest.ps1`, `triage_scan.ps1`, `filter_new_drivers.ps1`, and `innoextract` only.

**Suggested edit**

Add the full command from `DRIVER_COLLECTION_PLAYBOOK.md:86-92` to `downloads/README.md` (adjusting paths for the downloads directory), and add a "Prerequisites" line to the playbook §3 and `downloads/README.md`:

```text
7-Zip installed at C:\Program Files\7-Zip\7z.exe (harvest.ps1 hardcodes this path).
```

Also mention `downloads\_hx` as the work tree, since cleanup must remove it.

### P1-5 — `filter_new_drivers.ps1` adds a second hash suffix to harvested filenames

**Evidence**

- `tools/harvest.ps1:116-120` writes `<base>_<sha8>.sys`.
- `tools/filter_new_drivers.ps1:48-51` takes the harvested basename (already ending in `_<sha8>`), strips only the extension, and appends `_<sha8>` again:
  `foo_ABCD1234.sys` → `foo_ABCD1234_ABCD1234.sys`.
- Existing `drivers/` names have one suffix (for example `ArgusMonitor_E2875167.sys`); no current file has the double suffix, so this will appear only in the next batch.

**Suggested edit**

In `filter_new_drivers.ps1:48-50`, preserve an existing matching suffix:

```powershell
$base = [IO.Path]::GetFileNameWithoutExtension($f.Name)
$suffix = "_$($hash.Substring(0,8))"
if ($base.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) {
  $name = "$base.sys"
} else {
  $name = "$base$suffix.sys"
}
```

Add one sentence to the playbook §3: "`filter_new_drivers.ps1` preserves the harvest hash suffix; it does not add a second one."

### P1-6 — count-update instructions are incomplete and will leave six docs stale after a batch

**Evidence**

- `downloads/README.md:25-26` says update only `PROJECT_GOAL.md`, `START_HERE.md`, and `drivers/README.md`.
- `indexes/dedupe/README.md:11-13` says update only `PROJECT_GOAL.md`, `START_HERE.md`, `drivers/README.md`, and `indexes/drivers_manifest.csv`.
- Counts also live in:
  - `README.md:33-40`
  - `audits/STATUS.md:11-18`
  - `DRIVER_COLLECTION_PLAYBOOK.md:6,326-334`
  - `indexes/README.md:5,13`
- The dedupe index (`932`) is also quoted in `audits/STATUS.md:20`, `PROJECT_MAP.md:54`, `README.md:42`, `START_HERE.md:26`, `indexes/driverstore/README.md:10`, and `indexes/collections/collected5/COLLECTION_REQUIREMENTS.md:45,58`.

**Suggested edit**

Add one canonical maintenance line to `downloads/README.md` and `indexes/dedupe/README.md`:

```text
After rebuild_manifest.ps1, update every count copy: PROJECT_GOAL.md, START_HERE.md,
README.md, audits/STATUS.md, drivers/README.md, DRIVER_COLLECTION_PLAYBOOK.md (§6/§8),
indexes/README.md, and the dedupe summary. Prefer generating these from
indexes/drivers_manifest.csv instead of hand-editing.
```

### P1-7 — current report headers still cite deleted `_collected*`, root `*.sys`, `dynamic_evidence`, and `_vm_batch2` paths

**Evidence**

- `_collected*` paths in status-linked reports: `audits/reports/AIDA64_kerneld.md:5`, `DirectIo64.md:5`, `GPUZ_nvflash_x64.md:5`, `imdisk.admin.static.md:5`, `corsair_audio64.admin.static.md:5`, `sivi64.admin.static.md:5`, `cpuz_x64_cpuid.admin.static.md:5`, `cpuz_x64_ms.admin.static.md:5`, `ArgusMonitor.md:5`, `throttlestop_ll64.admin.static.md:5`, `spacedesk_audio.admin.static.md:5`, `spacedesk_bus.admin.static.md:5`, `msi_rtcore32_6F818DAF.admin.static.md:5`.
- Root paths: `audits/reports/b06bdrv.md:5` and `audits/reports/silabser.md:5` cite `C:\Users\<scrubbed>\Desktop\driver_candidates\*.sys`; those files are now in `drivers/`.
- `audits/README.md:62-64` warns only about `_collected1`/`_collected5`; it does not mention root paths, `_collected2`/`_collected3`, `audits\dynamic_evidence\`, or `_vm_batch2\`.
- `audits/reports/silabser.dynamic.md:204`, `logi_joy_bus_enum.dynamic.md:5`, `logi_joy_xlcore.dynamic.md:11`, `nvhda64v.dynamic.md:10`, `RzDev_051a.dynamic.md:16`, `t7_fuzz.md:11`, `VBoxNetAdp6.dynamic.md:12`, `VBoxNetLwf.dynamic.md:12`, and `vpnva.dynamic.md:13` still cite `audits\dynamic_evidence\`.

**Suggested edit**

Add a "Path aliases in historical report headers" paragraph to `audits/README.md` and `audits/reports/README.md`:

```text
Reports predating 2026-10-24 may cite the old root `driver_candidates\<name>.sys`,
`_collected2\`/`_collected3\` extras, `audits\dynamic_evidence\`, or `_vm_batch2\`.
Current equivalents: `drivers\<name>` (look up SHA-256 in
`indexes/drivers_manifest.csv`), `audits/evidence/`, and `audits/legacy/vm_batch2/`.
```

Optionally update the 16 reports linked from `STATUS.md` so the current-result headers are directly usable; the rest can rely on the banner.

### P1-8 — `audits/evidence/README.md` and the PoC READMEs overstate coverage as t1–t10

**Evidence**

- `audits/evidence/README.md:3`: "VM-phase evidence for the t1–t10 runs."
- Actual `audits/evidence/` has **t4–t10 only** (`t1`=0, `t2`=0, `t3`=0, `t4`=21, `t5`=45, `t6`=27, `t7`=32, `t8`=14, `t9`=34, `t10`=26).
- `audits/reports/logi_joy_bus_enum.dynamic.md:5` points to `audits\dynamic_evidence\t1_*.txt`; `logi_joy_xlcore.dynamic.md:11` points to `t3_*`. Neither set exists.
- `poc/README.md:8` and `poc/historical/README.md:3` say "t1–t10"; `PROJECT_MAP.md:44` says "t1–t10 PoC sources". Actual `poc/historical/` has t4–t7 PoC sources plus `host_probe.exe`; t8–t10 runbooks are in `audits/legacy/vm_batch2/`.

**Suggested edit**

- Change `audits/evidence/README.md:3` to: "VM-phase evidence for the t4–t10 runs (t1–t3 evidence was not migrated); reports that cite `t1_*`/`t3_*` are historical."
- Add: "Reports written before 2026-10-24 call this folder `audits\dynamic_evidence\`; that path is now `audits/evidence/`."
- Change `poc/README.md:8`, `poc/historical/README.md:3`, and `PROJECT_MAP.md:44` to: "t4–t7 PoC sources and harnesses; t8–t10 runbooks are in `audits/legacy/vm_batch2/`; t1–t3 are not retained."

### P1-9 — `DRIVER_COLLECTION_PLAYBOOK.md` §5 uses `.\dl`, which creates a second scratch folder

**Evidence**

`DRIVER_COLLECTION_PLAYBOOK.md:149`:

```powershell
winget download -e --id NZXT.CAM --download-directory .\dl `
```

The canonical scratch folder is `downloads/` (`PROJECT_MAP.md:15`, `downloads/README.md:3`, `README.md:82`, `DRIVER_COLLECTION_PLAYBOOK.md:49`). `.\dl` would create a root-level `dl/` that the cleanup step does not remove.

**Suggested edit**

Change `.\dl` to `downloads` and add `-e`/accept flags if the example is meant to be copy-pasteable.

### P1-10 — `DRIVER_COLLECTION_PLAYBOOK.md` §10 rebuilds over historical `collected2/master_drivers.csv` and reintroduces the known-wrong SDDL regex

**Evidence**

- `DRIVER_COLLECTION_PLAYBOOK.md:409-422` sets `$base = 'indexes\collections\collected2'` and exports to `$base\master_drivers.csv`, overwriting batch provenance.
- `:420` computes `Reach` as `$(if ($_.SDDL -match ';;;(WD|BU|AU)') { 'open' } else { 'restricted' })` — exactly the string-matching method §7.1 (`:249-292`) says is unsound and was replaced by descriptor validation.
- The canonical inventory is now `indexes/drivers_manifest.csv`; `DRIVER_COLLECTION_PLAYBOOK.md:334` says so.

**Suggested edit**

Either delete §10 or mark it clearly:

```markdown
> **HISTORICAL / DO NOT RUN.** This rebuilds the old `collected2` master table with the
> v1 SDDL string regex that §7.1 supersedes. The canonical inventory is
> `tools/rebuild_manifest.ps1` → `indexes/drivers_manifest.csv`.
```

If a batch-level summary is still wanted, read `Reach` from the harvest JSONL rather than re-deriving it, and write to a scratch path, never `collected2`.

### P1-11 — `indexes/dedupe/dedupe_summary.txt` is stale in both path and overlap count

**Evidence**

`indexes/dedupe/dedupe_summary.txt:1-4`:

```text
Existing unique hashes: 932
Known-bad hashes (LOLDrivers): 5833
Overlap existing/known-bad: 10
Index: C:\Users\<scrubbed>\Desktop\driver_candidates\_collected5\existing_hashes.txt
```

Actual intersection of the two files is **12** hashes, and `_collected5` no longer exists. The 12 include the six known-bad corpus images plus six other historical entries.

**Suggested edit**

Regenerate the file with:

```text
Existing unique hashes: 932
Known-bad hashes (LOLDrivers): 5833
Overlap existing/known-bad: 12
Index: indexes\dedupe\existing_hashes.txt
```

Add a line to `indexes/dedupe/README.md` saying `dedupe_summary.txt` is generated, not hand-edited.

### P1-12 — `AUDIT_SCOPE.md` uses a different `Reach` vocabulary from `SEVERITY.md` and the prompt

**Evidence**

- `audits/scope/AUDIT_SCOPE.md:64`: `Reach: unprivileged | authenticated user | local administrator | devnode/hardware`.
- `audits/scope/SEVERITY.md:15,88` and `audits/scope/STATIC_ANALYSIS_AGENT_PROMPT.md:117` use `R1 / R2 / R3`.
- `STATUS.md` and the current reports use `R2`, `R3`.

**Suggested edit**

Change `AUDIT_SCOPE.md:64` to `Reach: R1 | R2 | R3` (optionally with the textual expansion in parentheses). This removes an avoidable choice for new reports.

---

## P2 — nice-to-have

- **`drivers/README.md:3`:** "This is the only driver folder in the project" is true only for the corpus. Say "This is the only corpus folder; `poc/reference/` and `audits/evidence/` hold two non-corpus `.sys` references."
- **`downloads/README.md:10`:** the `winget download` example omits `-e` and the two `--accept-*` flags used in the playbook; a non-interactive run can fail.
- **`DRIVER_COLLECTION_PLAYBOOK.md:30` vs `downloads/README.md:29`:** "500 MB" vs "500 MiB". Align on MiB.
- **`DRIVER_COLLECTION_PLAYBOOK.md:29` vs `:45-59`:** "delete immediately after harvesting" vs "delete after the batch is accepted". Pick one and use it in both places.
- **`DRIVER_COLLECTION_PLAYBOOK.md:70-75` / `README.md:67-73`:** the tool tables omit `rebuild_manifest.ps1` (used in §9/README step 5) and `tools/vm/`. Add rows.
- **`DRIVER_COLLECTION_PLAYBOOK.md:247`:** "Check the `Device` column in `master_drivers.csv`" has no path and no such root file; point to `indexes\collections\collected2\master_drivers.csv` or say the manifest has no Device column.
- **`DRIVER_COLLECTION_PLAYBOOK.md:331-332`:** "`drivers/` — 43 drivers from collected5" and "`drivers/` — 111 from collected1" reads as if `drivers/` has 43/111; change to "collected5 contribution: 43; collected1 contribution: 111; `drivers/` total: 394."
- **`DRIVER_COLLECTION_PLAYBOOK.md:260` vs `tools/triage_scan.ps1:3`:** the playbook describes the v3 descriptor fix, but the script header still says `triage_scan.ps1 v2`. Update the header to v3 (the implementation already has `ViaDesc` / UNICODE_STRING validation).
- **`indexes/collections/README.md:14-15`:** "create `collected6/<agent>/`" conflicts with the top-level `collected6/manifest.csv` and `_index.jsonl` used by the playbook, `downloads/README.md`, and `tools/README.md`. Say "`collected6/<agent>/` when multiple agents contribute; otherwise `collected6/manifest.csv` + `_index.jsonl` at the batch root."
- **`indexes/collections/README.md` / `indexes/dedupe/README.md`:** the historical `manifest.csv` / `existing_drivers.csv` files still contain `_collected1` / `_collected5` paths. Add a one-line note that those are provenance, not live paths.
- **`indexes/collections/collected5/COLLECTION_REQUIREMENTS.md:70`:** recommends `innounp 2.70.1` for newer Inno Setup, but `tools/` has no `innounp` and `DRIVER_COLLECTION_PLAYBOOK.md:128-130` says Inno > 6.0.5 is unreachable. Mark the line historical or remove it.
- **`audits/evidence/README.md:12-14`:** the t7 guest image hash (`1205BD89…`) differs from `drivers/vsock.sys` (`CBF13689…`). Say explicitly "guest build, not byte-identical to the corpus copy; see `t7_fuzz.md`."
- **`audits/STATUS.md:57-68`:** the "Rolling queue" and "No full audit yet" table repeat the same targets. Consolidate or state that the table is a capability snapshot, not a second queue.
- **`DRIVER_COLLECTION_PLAYBOOK.md:214`:** says CPU-Z is "unreachable (Inno 6.3)" while the corpus already contains four CPU-Z images. Add "already obtained via carved resources; re-extraction not required."
- **`audits/reports/README.md`:** there is no report index. With 141 reports and only 16 named in `STATUS.md`, a generated `audits/reports/INDEX.md` (driver, severity, date, canonical/appendix) would prevent duplicate audits. Optional, but useful before the next audit wave.
- **`audits/README.md:57`:** add the known-bad exception to the "NO-WRITE because admin-only → re-audit" warning; otherwise RTCore/MSIO/amifldrv look like re-audit candidates.

---

## Stale-reference audit (detail)

| Token / old path | Found in canonical docs? | Status |
|---|---|---|
| `_collected*` | Only negative "do not recreate" text and the historical warning | Acceptable; no live instruction |
| `_ledger.md` | Only in `audits/legacy/structure_review_2026-10-24.md` | Historical; acceptable |
| `_admin_scope_backlog.md` | Only in the legacy structure review | Historical; acceptable |
| `dynamic_evidence` | 10+ current dynamic reports; not in canonical READMEs | **P1-7** (add alias) |
| `_vm_batch2` | Dynamic reports (`amdpsp`, `iaStorV`); actual folder is `audits/legacy/vm_batch2` | **P1-7** (add alias) |
| `_known_bad_control` | Only in the legacy structure review | Historical; acceptable |
| `README.txt` | Only `tools/innoextract/README.txt` (third-party) | Not a project stale reference |
| 389 / 106 / 776 | Only `audits/legacy/structure_review_2026-10-24.md` | Historical; acceptable |
| 295 | Incidental line/hash text in reports | Not a count |
| `handover_agentH` | `PROJECT_MAP.md:37`, `audits/projects/README.md:7` | Real folder, not stale |
| `vm_batch2` | `audits/legacy/README.md:12`, `audits/projects/README.md:9` | Real folder, correctly under legacy |

No old `_collected1..5` directories exist. No active `_ledger.md` exists. The only `README.txt` is the innoextract tool's own file.

---

## Counts actually verified

```text
drivers/*.sys                         394
drivers/ unique SHA-256               394
drivers_manifest.csv rows             394
drivers_manifest.csv unique SHA-256   394
existing_hashes.txt unique            932
known_bad_hashes.txt unique           5833
existing/known-bad overlap            12   (dedupe_summary says 10)
on-disk .sys under project            396  (394 + 2 documented references)
reports/*.md                          141
legacy/*.md                           8
reports with WRITE-* strings          38
plain *.static.md in reports          22
```

Batch distribution from `drivers_manifest.csv`: `original` 94, `collected1` 111, `collected2` 135, `collected3` 11, `collected5` 43. Sum = 394.

---

## Bottom line

The tree, counts, and links are in good shape. Fix the four P0 items before adding `collected6`; then do P1-1..P1-4 as a single pass so the next reader sees one current report folder, one cleanup command, one download sequence, and one count-update list.
