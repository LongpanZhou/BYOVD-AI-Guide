# indexes/dedupe/

| File | Purpose |
|---|---|
| `existing_hashes.txt` | SHA-256 gate: every driver already in the corpus |
| `known_bad_hashes.txt` | LOLDrivers / known-bad hashes |
| `dedupe_summary.txt` | counts and overlap |

`tools/filter_new_drivers.ps1 -UpdateExisting` writes the gate atomically. Do not edit by hand.
