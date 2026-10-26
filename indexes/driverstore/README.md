# DriverStore scan — generated discovery output

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

| File | What it is |
|---|---|
| `driverstore_inventory.csv` | Full DriverStore `.sys` inventory with hashes/signatures/vendors |
| `driverstore_new_candidates.csv` | Candidates not in the existing corpus at scan time |
| `small_vendor_candidates.csv` | Small/mid-vendor shortlist |
| `driverstore_summary.txt` | Counts and tier breakdown |

**Generated 2026-10-24 against `indexes\dedupe\existing_hashes.txt` (925 tracked hashes + 7 exported hashes in a gitignored local gate file).** These are
discovery artifacts, not audit reports. Re-run the scan before trusting `new_candidates.csv`;
hashes and candidate lists drift.
