# Reports

Flat folder: canonical reports, appendices, and retained historical reports. `../STATUS.md` is
the authoritative list of current verdicts; a report existing here does not by itself make it
current.

| Pattern | Meaning |
|---|---|
| `<driver>.md`, `<driver>.admin.static.md` | Canonical static report |
| `<driver>.dynamic.md` | VM validation; links the static report |
| `<driver>.static.md` | Legacy R1 static report |
| `<driver>_detailed.md`, `_further`, `_rea` | Appendix; names the canonical report |
| `<driver>.independent.static.md` | Independent cross-check; says which report is canonical |

Every new report must include `Reach`, `Setup`, `Write quality`, and `Severity` in the header and
cite code addresses/evidence IDs.

**Path aliases in historical report headers.** Reports predating 2026-10-24 may cite the old root
`driver_candidates\<name>.sys`, `_collected2\`/`_collected3\` extras, `audits\dynamic_evidence\`,
or `_vm_batch2\`. Current equivalents: `drivers\<name>` (look up SHA-256 in
`indexes/drivers_manifest.csv`), `audits/evidence/`, and `audits/legacy/vm_batch2/`.

Current status/queue: [`../STATUS.md`](../STATUS.md). Historical reports: [`../legacy/`](../legacy/).
