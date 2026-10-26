# Structure Review — driver_candidates

> **HISTORICAL (2026-10-24).** This review drove the cleanup that followed: scratch trees were
> deleted, `_collected1` was reconciled to 111 unique drivers, counts moved to 394, the ledger
> was migrated to MW, `_vm_batch1` duplicates were removed, and the status source is now
> `audits/STATUS.md`. Keep this file as history, not as a current to-do list.

> This is a **structure review**, not a driver audit. Do not add it to the driver/severity register.

**Date:** 2026-10-24 (late)
**Reviewer:** independent subagent
**Method:** read the requested canonical docs plus the root map/playbook; directory inventory; SHA-256 duplicate check of `.sys` files in the collection `new/` and `drivers/` folders (file-level only; no PE parsing, disassembly, loading, or execution); relative-link check over 173 Markdown files. No REA. No `.sys` was analyzed.

**Snapshot caveat:** The project is live. Reports landed during this review: `audits/DirectIo64.md` (22:14), `audits/sbiedrv.admin.static.md` (22:15), `audits/spacedesk_bus.admin.static.md` (22:17). Report totals and "in flight" lists are therefore moving targets; that drift is itself a finding (P0-3).

---

## Verdict

**The top-level goal is clear and consistent; the canonical register and the status/queue docs are not.** `START_HERE.md`, `PROJECT_GOAL.md`, `README.md`, `audits/README.md`, `audits/AUDIT_SCOPE.md`, `audits/SEVERITY.md`, and `audits/STATIC_ANALYSIS_AGENT_PROMPT.md` all state the same three rules: kernel memory-write only, local-administrator `R2` in scope, hardware-only writes are `HW-ONLY`. That is the strongest part of the project.

The weak point is `audits/_ledger.md`. It is the document `START_HERE.md` calls the "consolidated register", but §7 still contains the old no-setup disqualifier and §2/§18/§19 still use the retired `WRITE-*` scale. A new agent reading the ledger will receive two opposite instructions and will over-rate or drop drivers.

The file layout is generally good and the `_collected4`/`v2` removals are documented. The remaining structural problems are duplication (a second report tree in `_vm_batch1`, duplicate S5/S6 drivers), scratch-vs-corpus ambiguity (`_collected1` is 32 GB of installers/extracts around 106 counted drivers), and no generated status/report index. Those cause duplicate audits, which is the main practical waste.

| Review question | Verdict |
|---|---|
| 1. Goal clarity in canonical docs | **Partial.** Pass in six top-level docs; **fail** in `_ledger.md` §7 and §2. |
| 2. Contradictions / stale language | **Fail.** Ledger uses `WRITE-*` 20 times vs `MW[1-4]` 3 times; §19 rates a blocklisted driver outside `BLOCKED`. |
| 3. File structure | **Partial.** Numbering is explained and `_collected4` removal is documented; scratch trees, duplicate report trees, and S5/S6 duplication are not. |
| 4. AI-agent readability | **Partial.** Reading order is good; there is no status/report index, and "in flight" lists are already stale. |
| 5. Broken links / missing READMEs | **Mostly pass on links** (no genuine broken relative links); several working/evidence folders lack a README. |
| 6. Duplicate-work risk | **High.** Current reports exist for drivers still listed as queued/in-flight; S5/S6 contain the same six binaries. |

### What is already good

- The three core rules are repeated consistently in the top-level docs, including the "setup is a severity field, not a disqualifier" sentence.
- `PROJECT_MAP.md:46` explicitly records that `_collected4` was removed and must not be recreated; `PROJECT_MAP.md:48` explains that numbering is historical, not chronological.
- `audits/README.md` and `audits/legacy/README.md` correctly warn that old reports may use `WRITE-*` and "admin-only" disqualifiers.
- The dedupe gate is real and referenced from `START_HERE.md`, `PROJECT_MAP.md`, and `_collected5/COLLECTION_REQUIREMENTS.md`.
- `audits/sbiedrv.admin.static.md:12` is a good model for new reports: it gives the legacy label and the canonical equivalent (`MW2`, `reach=R2 setup=none write=W2 load=signed`) in one line.
- Relative links in canonical docs resolve. The only two "broken link" hits were false positives from code snippets in `audits/RzCommon.md` and `audits/RzDev_051a.md`.

### Structural inventory (at review time)

| Path | Contents | Observation |
|---|---|---|
| root | 94 `*.sys`, `triage_index.csv`, `triage_audit_joined.csv`, docs | Root corpus is clear; README says drivers are "not stored here" (P1-9). |
| `audits/` | 141 `.md` (6 canonical, 10 `*.dynamic.md`, ~125 reports/notes), `legacy/`, `_archive/`, `dynamic_evidence/`, `handover_agentH/`, `monitor/` | Flat report tree with no index; duplicate reports per driver; stale one-off `vm_readiness.md`. |
| `_collected1/` | S1-S6, 106 claimed / 117 `.sys` on disk, 32.2 GB | S5/S6 duplication; scratch trees dominate size. |
| `_collected2/` | 135 `.sys`, 72 families, 235 MB | `audits/` here is a Ghidra folder, not reports (confusing name). |
| `_collected3/` | 11 `.sys`, 124 MB, `_tools/` | Reports moved to `audits/legacy/`; `_tools` naming differs from `tools`. |
| `_collected5/` | 43 `.sys`, 2.59 GB, dedupe index | Good layout; `dedupe_summary.txt` and requirements still say 776 hashes. |
| `_vm_batch1/`, `_vm_batch2/` | VM transfer/fuzz artifacts | `_vm_batch1/reports/` duplicates 8 canonical reports and contains a second `_ledger.md`. |
| `indexes/`, `tools/`, `_known_bad_control/` | scan outputs, VM helper, calibration driver | Clear; mostly missing only small READMEs. |

---

## P0 blockers (must fix)

### P0-1 — `audits/_ledger.md` still carries the retired no-setup disqualifier

**Evidence:** `audits/_ledger.md:95`, under `## 7. Rules reminder`:

> "**No extra setup / no extra hardware:** if exploiting it needs a device you don't have or extra configuration (devnode, INF, composition), it is out of scope regardless of severity — record it as `Setup required: <type>` and move on."

This directly contradicts:

- `PROJECT_GOAL.md:16`: setup is "a severity field, **not** a disqualifier".
- `audits/AUDIT_SCOPE.md:25`: "This is a severity field, not a disqualifier."
- `_ledger.md:89` §6, which says the old rule is "superseded by §17".
- `_ledger.md:460-476` §17, which puts `R2` and devnode/hardware paths in scope.

An agent that reads `START_HERE.md` item 6 will read §7 and may drop exactly the drivers the project now wants (devnode, hardware-gated, composition).

**Suggested edit:** replace the bullet at `_ledger.md:95` with:

```markdown
- **Setup is a severity field, not a disqualifier.** Devnode/INF/hardware/composition
  paths are in scope; record `Setup required: <type>` and rate with `SEVERITY.md`.
  Only kernel memory writes count; hardware-only writes are `HW-ONLY`.
```

Keep the historical text only inside §10, which is already labeled "historical, superseded by §17".

---

### P0-2 — The canonical verdict register is still on the retired `WRITE-*` scale, and §19 violates the `BLOCKED` rule

**Evidence:**

- `audits/_ledger.md:24-41` (`## 2. Verdict register`) uses `WRITE-CRITICAL` (silabser), `WRITE-HIGH` (bxvbda), `WRITE-MEDIUM` (amdpsp), and `NO-WRITE` (VBoxNetAdp6/VBoxNetLwf). The whole ledger contains **20 `WRITE-` occurrences and only 3 `MW[1-4]` occurrences**.
- A one-to-one reading is wrong: `README.md:47` rates `silabser` **MW2** (CP210x-gated), while the ledger says `WRITE-CRITICAL`; `README.md:49` rates `bxvbda` **MW2**, while the ledger says `WRITE-HIGH`. `SEVERITY.md:53` explicitly says hardware-gated arbitrary writes become MW2.
- `audits/_ledger.md:509-521` rates MSI RTCore32 `WRITE-PHYS-MEDIUM`, `WRITE-MEDIUM`, and `WRITE-HIGH`. `SEVERITY.md:58` says "Blocklisted / known-bad | **BLOCKED** regardless of primitive", and `_ledger.md:523` admits "Blocklist status not re-checked in this pass".
- `audits/_ledger.md:509` and `:527` are both headed `## 19.` — the second should be §20.

**Suggested edit:**

- Migrate §2, §3, §8, §9, §18, and §19 to the `SEVERITY.md:84` format:
  `MW<n> — reach=<R1|R2|R3> setup=<none|service|devnode|hardware|composition> write=<W1|W2|W3|W0> load=<signed|unsigned|blocked>`.
- If the old labels must be preserved for history, put them in a separate `Legacy verdict` column, not in the primary verdict cell.
- Resolve MSI RTCore32 to `BLOCKED` (or add a one-line, explicit exception explaining why the project audits blocklisted drivers anyway). Do not leave a `WRITE-MEDIUM` verdict next to a "not re-checked" note.
- Renumber the §19 at `_ledger.md:527` to §20 and update any `§19` references.

---

### P0-3 — Status, queue, and corpus counts are duplicated and already stale, which causes duplicate audits

**Evidence:**

- Current reports exist for drivers still listed as in flight:
  - `audits/DirectIo64.md` (22:14) vs `START_HERE.md:31` and `PROJECT_GOAL.md:64` ("In flight: ... DirectIo64").
  - `audits/sbiedrv.admin.static.md` (22:15) vs `START_HERE.md:31` and `PROJECT_GOAL.md:64` ("Sandboxie SbieDrv").
  - `audits/spacedesk_bus.admin.static.md` (22:17) vs `START_HERE.md:32` and `PROJECT_GOAL.md:65` (queue: "Spacedesk Bus").
- `audits/_admin_scope_backlog.md:79` says "AIDA64 kerneld x64 — running", but `:128` says it is done.
- `audits/_admin_scope_backlog.md:74` says "ArgusMonitor — done, NO-WRITE", while the canonical result is `NO-MEMORY-WRITE (HW-ONLY)`.
- `audits/_admin_scope_backlog.md:140-156` says "No audit started yet" for ImDisk, Spacedesk, SIV, and HWMonitor `cpuz`; `audits/legacy/imdisk.static.md`, `audits/legacy/spacedesk_bus_audio_kbd.static.md`, `audits/sivi64.admin.static.md`, and `audits/cpuz_x64_*.admin.static.md` exist.
- `audits/_ledger.md:17` says 81 static reports and `:19` says 11 remaining; `audits/` has 141 `.md` at review time (6 canonical, 10 dynamic), and the backlog itself says 39 drivers have no full audit.
- `_collected1/README.md:6` says 106 new binaries; the folder contains 117 `.sys` (111 unique; see P1-1).

**Suggested edit:** create one machine-readable status source, for example `indexes/status.csv` or `audits/_status.md`, with one row per driver:

```text
driver,batch,path,sha256,reach,setup,severity,report,state,date
```

Then:

1. Generate the counts (total, new, audited, remaining, by severity) from that file.
2. Replace the hardcoded "Current status" / "In flight" / "Queue" blocks in `START_HERE.md`, `PROJECT_GOAL.md`, `README.md`, `_ledger.md`, and `_admin_scope_backlog.md` with a link plus a "last generated" stamp.
3. Add step 0 to `audits/STATIC_ANALYSIS_AGENT_PROMPT.md`: "Check `indexes/status.csv` / `audits/_index.md`. If a report exists, re-audit only with a stated reason."

This is a P0 because it is not a cosmetic count issue: it sends agents to re-audit drivers that already have reports.

---

## P1 improvements (should fix)

### P1-1 — `_collected1` has three different counts and six duplicate drivers in S5/S6

**Evidence:**

- `_collected1/README.md:6` says 106 total: S1 1 + S2 7 + S3 55 + S4 37 + S5 0 + S6 6.
- `_collected1/agentS5/new` contains 6 `.sys`; `_collected1/agentS6/new` contains 11 `.sys`.
- SHA-256 comparison shows six byte-identical pairs between S5 and S6:
  `CMTAC_83986D97`, `CMTAC_F6772F57`, `CMUAC_00D7F507`, `CMUAC_2F75117C`, `CMUAC_C2A3B919`, `CMUAC_D5F01449`.
- `_collected1/agentS5/reports/summary.txt` says `NEW 6`; `_collected1/agentS6/reports/summary.txt` says `NEW 11`; the README says `S5 0` / `S6 6`.
- S6 adds five `cpuz_*` images; if those count, the batch is 111 unique and the corpus total is 394, not 389. If they do not count, the rule excluding them is undocumented.

**Suggested edit:**

- Empty/remove `_collected1/agentS5/new` and add `_collected1/agentS5/reports/README.md`: "Superseded by S6; the six files here are duplicates. Do not audit."
- Decide explicitly whether carved CPU-Z resource images count as corpus. If yes, update the total to 111/394; if no, say "carved resources are evidence, not corpus" and keep the five files out of `new/`.
- Update the same number in `_collected1/README.md:6`, `START_HERE.md:24`, `PROJECT_GOAL.md:54`, `README.md:35`, `DRIVER_COLLECTION_PLAYBOOK.md:6`, and `_ledger.md:14`.

---

### P1-2 — Dedupe index is 932 in seven places and 776 in the collection requirements

**Evidence:**

- `_collected5/existing_hashes.txt` has **932** non-empty lines.
- `_collected5/COLLECTION_REQUIREMENTS.md:45` and `:58` say **776**.
- `_collected5/dedupe_summary.txt:1` says "Existing unique hashes: **776**".
- `START_HERE.md:26`, `PROJECT_GOAL.md:57`, `PROJECT_MAP.md:56`, `README.md:38`, `_collected5/README.md:15`, and `_collected1/README.md:8` say **932**.

**Suggested edit:** update the two 776 references and regenerate `dedupe_summary.txt`. Add the missing maintenance rule, because this drift will recur:

> After a batch is accepted, append the SHA-256 of every file in `new/` to `existing_hashes.txt`, regenerate `dedupe_summary.txt`, and update the count in `PROJECT_GOAL.md`, `START_HERE.md`, `PROJECT_MAP.md`, `README.md`, and the batch README. Do not hand-edit only one copy.

---

### P1-3 — `_vm_batch1/reports/` is a second report tree and a second ledger

**Evidence:**

- Eight reports are byte-identical to canonical copies in `audits/`:
  `AppleKmdfFilter.md`, `logi_joy_bus_enum.md`, `logi_joy_vir_hid.md`, `logi_joy_xlcore.md`, `NiSerP.md`, `RzCommon.md`, `RzDev_051a.md`, `vpnva.md`.
- `_vm_batch1/reports/_ledger.md:1` is headed "Driver Audit Ledger (static, blind, sequential)" and uses `HIGH`/`MEDIUM`/"Completed 8/94". It is not the consolidated ledger, but its name and location invite that reading.
- `_vm_batch1/README_VM.txt:5` says `reports\  matching static audit reports + _ledger.md` without a historical warning.

**Suggested edit:**

- Delete the eight duplicate report copies. Replace them with `_vm_batch1/reports/README.md` that points to `..\..\audits\<name>.md`.
- Rename `_vm_batch1/reports/_ledger.md` to `_vm_batch1/reports/_ledger.batch1.2026-10-23.md` and add a first-line banner: `HISTORICAL — not the consolidated register; see audits/_ledger.md`.
- Update `_vm_batch1/README_VM.txt` to say the reports live in `audits/`.

---

### P1-4 — Several current reports still use the retired scale and say the R2 question is unsettled

**Evidence:**

- `audits/cpuz_x64_cpuid.admin.static.md:13` and `:79-83`: `WRITE-CRITICAL ... Recorded this way until the R2 level question is settled.`
- `audits/cpuz_x64_ms.admin.static.md:13` and `:62`: same wording.
- `audits/throttlestop_ll64.admin.static.md:13` and `:77-83`: `WRITE-CRITICAL ... until the R2 level question is settled.`
- `audits/AIDA64_kerneld.md` header has no `Severity`, `Setup required`, or `Write quality` field.
- `audits/ArgusMonitor.md` header has no `Reach tier`, `Setup required`, or `Severity` field.
- `audits/DirectIo64.md:207` uses "High" and "not a privilege-boundary crossing", not MW.
- `audits/sivi64.admin.static.md:13` uses `NOT ASSESSED` where the scale has `BLOCKED`.

The R2 question was settled in `_ledger.md` §17 and `SEVERITY.md` before these reports were written (`SEVERITY.md` last modified 21:49; the reports 21:58-22:14). The sentence is factually stale.

**Suggested edit:** follow the `sbiedrv.admin.static.md:12` model. Rewrite the four header fields to the canonical values:

- AIDA64 -> `MW2`, `reach=R2 setup=none write=W2 load=signed`.
- ThrottleStop -> `MW2 if loaded`, `reach=R2 setup=none write=W1/W2 load=unsigned`.
- CPU-Z -> assign the MW level from `SEVERITY.md` based on the gate described in the report; do not keep `WRITE-CRITICAL`.
- SIVI64 (IA-64) -> `BLOCKED`, not `NOT ASSESSED`.
- DirectIo64 -> `MW<n>` plus the physical-write/port/MSR split.

Put the old label in a `Legacy verdict:` line if it helps continuity. Add a small checklist or lint script that fails a new report missing `Reach`, `Setup`, `Write quality`, or `Severity`.

---

### P1-5 — Report naming has no rule, so one driver has two or three reports

**Evidence:**

- `audits/README.md:55-57` says new reports should use `audits\<driver>.md` or `audits\<driver>_<variant>.md`, but the disk uses dotted names (`*.admin.static.md`, `*.static.md`, `*.dynamic.md`).
- Multiple reports for one driver:
  - `amdpsp.md` + `amdpsp_detailed.md` + `amdpsp.dynamic.md`
  - `b06bdrv.md` + `b06bdrv_detailed.md`
  - `msi_rtcore.static.md` + `msi_rtcore32_6F818DAF.admin.static.md` + `msi_rtcore32_further.static.md`
  - `megasas.md` + `megasas_rea.md`
- There is no index saying which one is the canonical verdict.

**Suggested edit:**

- Declare the existing dotted convention canonical rather than inventing a new one:
  - `<driver>.md` or `<driver>.admin.static.md` = canonical static report.
  - `<driver>.dynamic.md` = VM validation, must link the static report.
  - `<driver>.static.md` = legacy R1 static report.
  - `<driver>_detailed.md`, `_further`, `_rea` = appendices; first line must say "Appendix to `<canonical report>`".
- Add `audits/_index.md` with one row per driver: `driver`, `canonical report`, `aliases`, `severity`, `state`, `date`. This is also the human-readable companion to `indexes/status.csv` from P0-3.

---

### P1-6 — `audits/vm_readiness.md` is a stale blocker note presented as current

**Evidence:** `audits/vm_readiness.md:7` says **"STOPPED (BLOCKED)"**; `:9-10` cites live `opencode.exe` PIDs and a consent blocker; `:93` says "Do not run the PoC binaries left in earlier stage folders (t8_poc.exe, t9_poc.exe)". It is a one-off 06:46 status report, not a driver audit, and it is not listed in `audits/README.md` or `PROJECT_MAP.md`.

An agent that reads `audits/*.md` for context can conclude the VM is still blocked and stop.

**Suggested edit:** move it to `audits/_archive/vm_readiness_2026-10-24_0646.md` (or rename to `HISTORICAL_vm_readiness_2026-10-24.md`), and add a first line: "Historical one-off; current VM rules are `VM_ACCESS.md`." Remove it from the `audits/` root.

---

### P1-7 — `_admin_scope_backlog.md` contradicts itself and does not account for legacy reports

**Evidence:**

- `:74` "ArgusMonitor — **done, NO-WRITE**" (canonical: `NO-MEMORY-WRITE (HW-ONLY)`).
- `:79` "AIDA64 kerneld x64 — running" vs `:128` "AIDA64 kerneld-x64 — **MW2** ... done".
- `:140-156` "No audit started yet" includes ImDisk, Spacedesk Bus/Audio, SIV, and HWMonitor `cpuz`, but `audits/legacy/imdisk.static.md`, `audits/legacy/spacedesk_bus_audio_kbd.static.md`, `audits/sivi64.admin.static.md`, and `audits/cpuz_x64_*.admin.static.md` exist.
- `:70` says MSI `RTCore*` is blocklisted and "re-audit only if you want the admin path documented", but the ledger did that audit in §19.

**Suggested edit:** delete the duplicate "In flight / queued" block at `:72-80` and point to the status register. Add a `Legacy report` column to the P1/P2 tables with values `none` / `legacy, re-audit` / `current report`. Replace `NO-WRITE` with `NO-MEMORY-WRITE (HW-ONLY)`. Remove the "running" line or move the whole status block to the generated register.

---

### P1-8 — Scratch trees dominate the collections and are not marked disposable

**Evidence:**

- `_collected1` is **32.2 GB / 39,576 files**; `_collected5` is **2.59 GB / 1,987 files**.
- `_collected1/agentS6/work/DeepCool...` contains a full Electron `node_modules` tree and an `app.asar.unpacked` tree.
- `DRIVER_COLLECTION_PLAYBOOK.md:29` says "Delete the installer and extract tree after harvesting", but `packages/`, `extract/`, `work/`, `manual/`, and `staging/` are still on disk.
- `PROJECT_MAP.md:42-45` describes the batches as "106 binaries", "43 binaries", etc., without mentioning that the folders are tens of GB of scratch.

**Suggested edit:** add a `README.md` at each batch root with one clear sentence:

> Corpus = `drivers/` (or `new/`). `packages/`, `extract/`, `work/`, `manual/`, and `staging/` are disposable scratch; do not recurse them for audits.

Then either delete the scratch after harvest or move it under one root `_scratch/`. Add `.gitignore` entries for `_collected*/**/extract/`, `_collected*/**/work/`, `_collected*/**/manual/`, `_collected*/**/staging/`, and `_collected*/**/packages/`. This prevents an agent from grepping 32 GB of app code and makes "where is the corpus?" unambiguous.

---

### P1-9 — `README.md:69` says drivers are not stored here, but 94 root `.sys` and hundreds in collections are on disk

**Evidence:** `README.md:69`: "Drivers are not stored here. To rebuild a batch..." `PROJECT_MAP.md:16` correctly lists 94 root `*.sys`; `_collected2`, `_collected3`, and `_collected5` contain hundreds more. The `.gitignore` excludes `*.sys`, so the sentence is true only for git.

**Suggested edit:** replace with:

> Driver binaries are present on disk but excluded from git (`.gitignore`). To rebuild a batch, follow ...

This preserves the reproducibility point and stops an agent from concluding there are no local binaries.

---

### P1-10 — `Setup` vocabulary differs across canonical docs; `service` is only in PROJECT_GOAL

**Evidence:**

- `PROJECT_GOAL.md:16`: `none · service · devnode · hardware · composition`.
- `AUDIT_SCOPE.md:25`: `none | devnode | hardware | composition`.
- `SEVERITY.md:16`: `none · devnode · hardware · composition`.
- `STATIC_ANALYSIS_AGENT_PROMPT.md:111` and `:62`: `none | devnode | hardware | composition`.
- `audits/msi_rtcore32_6F818DAF.admin.static.md:10` works around the gap with "Setup required: none (service create + start)".

**Suggested edit:** choose one list and use it everywhere. Recommended: `none | service | devnode | hardware | composition`, with `service` defined as "create/start a kernel service, but no devnode/hardware". Update `SEVERITY.md`'s matrix rows if `service` changes the rating.

---

### P1-11 — Ledger opening, scoreboard, and §5 are stale or internally inconsistent

**Evidence:**

- `_ledger.md:3` says "94 non-Microsoft vendor drivers" as the project description; `:14-15` say 389 total. A reader can conclude the project is only the original 94.
- `_ledger.md:17` says 81 static reports; `audits/` has 141 `.md` at review time (6 canonical, 10 dynamic). `:19` says 11 remaining; the backlog says 39 no-audit.
- `_ledger.md:72-77` §5 points to `C:\Users\<scrubbed>\AppData\Local\Temp\opencode\agentH` (does not exist) and says "MOVE to audits\handover_agentH"; the folder already exists. It also repeats "Other session's standing claims."
- `_ledger.md:509` and `:527` are both `## 19.` (also see P0-2).
- The ledger is 545 lines and mixes current rules with campaign history; `START_HERE.md:18` sends every agent to it as item 6.

**Suggested edit:** rewrite line 3 as "Original corpus 94; total known 389 (or the current generated count)." Generate the report/remaining counts. Move §5 to a dated `HANDOVER` appendix or delete it; replace the Temp path with `audits/handover_agentH` and state it is already moved. Renumber the second §19 to §20. Add a 10-line "current state" header above §1 and move the campaign history below a `## History` divider.

---

### P1-12 — "Do not create `new`" conflicts with the required per-batch `new/`, and there is no next-batch rule

**Evidence:**

- `START_HERE.md:36`: "Do not create `v2`, `new`, or parallel project trees."
- Every batch requires `new/`: `_collected1/agentS1/new`, `_collected5/agentR1/new`, etc. `_collected5/COLLECTION_REQUIREMENTS.md:82-87` mandates it.
- `START_HERE.md:38` says "New drivers go to `_collectedN`", but `PROJECT_MAP.md:48` says numbering is historical and there is no statement of the next N, the required README/manifest, or the dedupe-index update.

**Suggested edit:** replace the rule with:

> Do not create a top-level `new/`, `v2/`, or parallel project tree. A per-batch `agentX/new/` is required and is the only place filter-approved drivers go.

Add a "new batch" section:

> Next new batch is `_collected6`. Copy the `_collected5` layout, add `README.md` and `reports/manifest.csv`, run `_collected5/tools/filter_new_drivers.ps1`, then append accepted SHA-256s to `_collected5/existing_hashes.txt` and update the counts (see P1-2).

This also answers "where do indexes go": discovery CSVs go in `indexes/<topic>/` with a generation date; audit-derived tables go in `audits/_index.md`.

---

### P1-13 — Tooling authority is split between local Ghidra and REA

**Evidence:**

- `_ledger.md:72` says "engine = local Ghidra headless primary"; `:59` says the REA bridge mis-serves under 4+-way load.
- `STATIC_ANALYSIS_AGENT_PROMPT.md:31` says "retain REA evidence IDs".
- `_admin_scope_backlog.md:91` says "Do not add more than ~4 concurrent REA audits".
- Reports mix both: `audits/AIDA64_kerneld.md:8` says "REA/Ghidra (Ghidra 12.1.4)"; `audits/sbiedrv.admin.static.md:8` says "Ghidra 12.1.4 headless" with a dump path.

An agent cannot tell whether REA is required, optional, or forbidden under load.

**Suggested edit:** add one paragraph to `STATIC_ANALYSIS_AGENT_PROMPT.md`:

> Primary engine: local Ghidra 12.1.4 headless. REA is optional for cross-checks and evidence IDs. If REA is unavailable or contended, continue with Ghidra and record the dump path and function addresses; do not block, and do not run more than 4 REA sessions at once.

---

### P1-14 — `BLOCKED` vs `MW2 if loaded` is ambiguous across canonical docs

**Evidence:**

- `PROJECT_GOAL.md:31` lists `BLOCKED (known-bad / unsigned-HVCI / component missing)`.
- `PROJECT_GOAL.md:63` rates ThrottleStop `MW2 if loaded` (unsigned/DSE-off).
- `STATIC_ANALYSIS_AGENT_PROMPT.md:70` also puts "unsigned" under `BLOCKED`.
- `SEVERITY.md:47` says unsigned/HVCI-blocked is `BLOCKED`, but the static primitive can still be MW1/MW2.
- `SEVERITY.md:58` says blocklisted/known-bad is `BLOCKED` regardless; `_ledger.md:515-521` rates RTCore32 `WRITE-MEDIUM`.

An agent can reasonably classify the same driver as `BLOCKED`, `MW2`, or `MW2 + BLOCKED`.

**Suggested edit:** separate the two axes explicitly:

- `Severity`: `MW1-MW4` / `NO-MEMORY-WRITE` — what the code can do.
- `Load status`: `signed | unsigned-DSE-off | blocklisted | unobtainable` — whether it can be loaded on the target.
- `BLOCKED` only when the driver cannot be loaded/obtained; if the team also wants to exclude blocklisted drivers by policy, say "BLOCKED by policy" and do not also assign MW.

Then update `PROJECT_GOAL.md:31`, `STATIC_ANALYSIS_AGENT_PROMPT.md:70`, and `SEVERITY.md:30/47/58` to the same rule.

---

## P2 nice-to-have

1. **`PROJECT_MAP.md` is incomplete.** Add rows for `_collected2/audits/` (Ghidra project, not reports), `_collected3/_tools/`, `_collected1/agentS6/{manual,work,staging}/`, `_collected5/{existing_drivers.csv,dedupe_summary.txt}`, `audits/_agent_monitor.log`, and `audits/vm_readiness.md` (or move the latter). Without these, an agent probing the map will find unexplained folders.

2. **Rename `_collected2/audits/` to `_collected2/ghidra/`.** It contains `ghidraproj` and a README saying "not reports", but the name still looks like the canonical `audits/` tree. Update `_collected2/README.md:12` and `PROJECT_MAP.md`.

3. **Rename `_collected3/_tools/` to `_collected3/tools/`.** `_collected2` and `_collected5` use `tools/`; the leading underscore is the only difference. Update `_collected3/README.md` to list it.

4. **Empty/generated folders should be marked or removed:** `_collected2/audits/ghidraproj`, `_collected3/ghidraproj`, `_collected5/agentR2/new`, `_collected1/agentS6/staging`, `_collected1/agentS6/manual/DeepCool/inno`. Add a `.gitkeep` plus "regenerable/empty" note, or delete. Docs currently imply they contain something.

5. **Missing READMEs:** `audits/dynamic_evidence/`, `audits/handover_agentH/`, `audits/_archive/`, `_known_bad_control/`, `tools/vm/`, `indexes/driverstore/`, `_collected3/_tools/`. `PROJECT_MAP.md` explains some, but a folder-local README is what an agent sees first.

6. **`_vm_batch2/README_VM.txt` uses the retired scale** (`WRITE-HIGH`, `WRITE-MEDIUM`, `NO-WRITE`) and says "Rules (unchanged)" even though the scope changed. Add a one-line banner: "Historical batch notes; current scale is `audits/SEVERITY.md`."

7. **`audits/README.md:49` cites `AIDA64 kerneld-x64.md`**, but the actual file is `audits/AIDA64_kerneld.md`. Fix the name (and make it a link). The "Current state" list is also only three rows while `audits/` has many reports; link `_index.md`/`status.csv` instead of duplicating.

8. **Stale cross-references:** `audits/AUDIT_SCOPE.md:5` says it supersedes "`_ledger.md` line 4", but line 4 now already includes admin scope. `_admin_scope_backlog.md:4` makes the same stale reference. Say "the pre-§17 wording" instead of "line 4".

9. **Root CSV placement:** `triage_index.csv` and `triage_audit_joined.csv` are original-94 metadata, but `README.md` does not mention them. Either add a sentence in `README.md` ("original 94 only") or move them to `indexes/original_corpus/`. `README.txt` is a legacy pointer; it is harmless but adds a second README at root. Consider deleting it after one release.

10. **`audits/dynamic_evidence/` has no index and contains `t4_poc.cs`, `t5_poc.cs`, `t6_poc.cs`, `host_probe.exe`.** The audit prompt says "No exploit code, no PoC." Add a README: "Historical harness artifacts; not templates; do not reuse." Consider moving the PoCs to `_archive/` so the evidence folder reads as evidence, not a toolkit.

11. **`audits/monitor/watchdog_v2.ps1`** uses a `v2` name even though `START_HERE.md:36` says no `v2` tree. It is a file, not a tree, but a simple rename to `watchdog.ps1` avoids the false signal.

12. **`PROJECT_GOAL.md:61-65` and `START_HERE.md:27-32` "Confirmed findings" list only AIDA64, ThrottleStop, and ArgusMonitor.** `README.md:43-50` also lists `rtf64x64`, `silabser`, and `bxvbda` as MW2. Either link the top findings table or add the missing rows so "confirmed" means the same thing everywhere.

13. **`_collected3/README.md:20` says "Reports for this batch were moved..."** but only five of the 11 binaries have legacy reports, and the backlog says six have no audit. Say "The five reports written for this batch..." so an agent does not assume full coverage.

14. **`indexes/driverstore/*.csv` have no generation date or hash-count stamp.** Add a header row or a `README.md`: "Generated <date> against existing_hashes.txt at <N> hashes; re-run before trusting `new_candidates.csv`." Otherwise an agent may treat a stale candidate list as current.

15. **`audits/_agent_monitor.log` and `audits/monitor/watchdog.log`** are raw logs in the audits tree with no explanation. Add a one-line README in `monitor/` or move logs to `_archive/`. Low risk, but they add noise to `audits/*` scans.

16. **`VM_ACCESS.md` contains the guest password in cleartext.** It is a lab VM, but the file is tracked. Consider moving the password to an untracked local note or adding "lab-only, no production credentials." Optional.

---

## Recommended fix order

1. **P0-1 and P0-2** — 30-60 minutes. Remove the old no-setup bullet, migrate the ledger register to MW, resolve RTCore32, renumber §19.
2. **P0-3** — 1-2 hours. Generate `indexes/status.csv` + `audits/_index.md`; replace the duplicated queues and counts with links.
3. **P1-1 and P1-2** — 1 hour. Fix the 106/111/117 and 776/932 splits; remove S5 duplicates; document the CPU-Z counting rule.
4. **P1-3, P1-6, P1-7** — delete the duplicate `_vm_batch1/reports` copies, archive `vm_readiness.md`, rewrite the backlog status block.
5. **P1-8 and P2-4/P2-5** — clean scratch trees, add batch/working-dir READMEs, add missing folder READMEs.
6. **P1-4/P1-5/P1-10/P1-14** — normalize current report headers, declare the naming convention, settle `service` and `BLOCKED`.

## Bottom line

The project is structurally sound: one folder, a clear top-level goal, an explicit dedupe gate, and a documented history. The danger is **canon drift**, not layout. The ledger is no longer a reliable register, and the status/queue has been copied into five docs that are now inconsistent. Fix P0-1/P0-2 first, then replace the duplicated status blocks with one generated source. After that, the folder structure is good enough to keep scaling the collection.
