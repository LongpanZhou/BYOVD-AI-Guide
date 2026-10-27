# indexes/dedupe/

| File | Purpose |
|---|---|
| `existing_hashes.txt` | SHA-256 gate: every driver already in the corpus |
| `known_bad_hashes.txt` | LOLDrivers / known-bad hashes |
| `dedupe_summary.txt` | counts and overlap |

`tools/filter_new_drivers.ps1 -UpdateExisting` writes `existing_hashes.txt` and
`dedupe_summary.txt` atomically - never edit those by hand. `known_bad_hashes.txt` is the seed
gate you refresh yourself from the live LOLDrivers feed (never hand-tweak it; see
`guides/00_quickstart.md` section 2).
