# Blocklist / known-vulnerable check (run before any dynamic test)

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

Two public datasets decide whether a candidate is worth auditing fresh:

1. **LOLDrivers** - community data about drivers used by real-world malware activity
   (https://www.loldrivers.io/, JSON endpoint `api/drivers.json`).
2. **Microsoft vulnerable driver blocklist** - the enforced XML that ships with
   Windows 11 / HVCI. `https://aka.ms/VulnerableDriverBlockList` -> ZIP containing
   `DriverPolicy_Enforced.xml`.

Both are *datasets*, not exploit material: they make your hunt faster and your audit honest.

## 1. The command line

```powershell
# LOLDrivers dataset (~33 MB JSON) into the gitignored scratch folder
Invoke-WebRequest https://www.loldrivers.io/api/drivers.json -OutFile downloads\loldrivers.json

# Microsoft blocklist
Invoke-WebRequest https://aka.ms/VulnerableDriverBlockList -OutFile downloads\blocklist.zip
Expand-Archive downloads\blocklist.zip downloads\blocklist_extract\
```

Run these from the repo root; everything lands in the gitignored `downloads\` scratch, which the
batch cleanup wipes - **after** copying the JSON/XML you want to keep as dated evidence into
`audits/evidence/` (section 4). The batch-cleanup whitelist lives in guides 00 and the playbook.

The XML is nested one level down:
`downloads\blocklist_extract\VulnerableDriverBlockList\DriverPolicy_Enforced.xml`.

Then, for each candidate driver, check:

- Flat **SHA-256** of the file.
- **Authentihash**: SHA-1 and SHA-256 over the PE headers *excluding* the `Checksum` field and
  the certificate-table data-directory entry, plus the section raw data. This is what Microsoft
  uses for Deny rules.
- `FriendlyName` text of blocklist rules.
- `FileAttrib` filename+`Minimum/MaximumFileVersion` rules - some blocks are name-based, not hash-based.

Quick hash lookup after downloading both lists:

```powershell
$hash = (Get-FileHash drivers\<file>.sys -Algorithm SHA256).Hash
Select-String -Path downloads\loldrivers.json -Pattern $hash -SimpleMatch
Select-String -Path downloads\blocklist_extract\*\DriverPolicy_Enforced.xml -Pattern $hash -SimpleMatch
```

## 2. What the results mean for your hunt

| List result | Audit implication |
|---|---|
| Family listed in LOLDrivers, **exact build not** | audit fresh, but expect EDR/tools to flag by name; treat as "known-bad family" |
| Exact build hash on either list | **BLOCKED (known-bad)** - record the finding and stop; do NOT dynamically test |
| Exact Authentihash on Microsoft blocklist | same - and note it won't load where that policy is on by default |
| Not listed at all | promising audit target |

Keep the raw comparison as a dated evidence file (see below).

## 3. What the lists do NOT tell you

- Absence from the blocklist does **not** mean a driver is safe, merely uncatalogued.
- Presence is a strong *signalling* problem, not a proof of damage.
- Both lists update constantly - an "exact-build not on list" result is only valid on the date you pulled the data. Date-stamp every check: `audits/evidence/known_vulnerable_check_<yyyy-mm-dd>.md`.

## 4. How to keep your own hunt current

Do the list check **on the day** you pull a new corpus, and keep the raw JSON/XML as dated
evidence in `audits/evidence/` (the gate file `indexes/dedupe/known_bad_hashes.txt` is
refreshed by re-deriving it - see guides/01 section 5). Re-derive from the live sources whenever a new
audit preview starts; stale lists are the most common cause of "nothing to do" hunts.
