# indexes/collections/ - batch provenance

One folder per batch: `collected<N>/` holding `manifest.csv`, `urls.txt`, `summary.txt`,
`_index.jsonl` (harvest's running log, append-only) and `master_drivers.csv` (the playbook's
per-batch master list). Never recreate
batch folders at the project root. Look up a driver's batch in `../drivers_manifest.csv`.
