# Auditing a driver - static review before (and instead of) dynamic testing

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

Static analysis answers *is there a kernel-write primitive, and who can reach it*; dynamic
testing only confirms it. Every driver in `drivers/` gets exactly one canonical report in
`audits/reports/`, in a fixed template. Appendices live in the same file or link back to it.

## 1. The canonical report skeleton

The same skeleton the default audit prompt (`audits/scope/STATIC_ANALYSIS_AGENT_PROMPT.md`,
"Report structure") mandates. Copy it verbatim:

```markdown
# Audit: <driver>

| Field | Value |
|---|---|
| File | `drivers/<filename>.sys` |
| SHA-256 | `<hash>` (matches manifest / index: yes) |
| Analysis date | `<yyyy-mm-dd>` |
| Method | Static-only via REA |
| Reach | R1 / R2 / R3 |
| Setup required | none / service / devnode / hardware / composition |
| Write quality | W1 / W2 / W3 / W3P / W0 |
| Severity | MW1 / MW2 / MW3 / MW4 / NO-MEMORY-WRITE / BLOCKED |
| HW-only | yes / no |

## 1 Internals
## 2 Entry / device / interface / effective DACL
## 3 Dispatch and IOCTL table
## 4 Access-control audit
## 5 Memory-write trace
## 6 Most dangerous exposed capability
## 7 Verdict
## 8 Limitations
```

> Static-only audit. No load, no execution.

## 2. What to look for, in order

1. **`DriverEntry`** -> `IoCreateDevice` / `IoCreateSymbolicLink` / WDF - the device someone opens.
2. **The dispatch table** -> `MajorFunction[IRP_MJ_DEVICE_CONTROL]` and every `case` in the IOCTL
   switch; the case table is where writes hide.
3. **`MmMapIoSpace` / `MmGetSystemAddressForMdlSafe` / `MapUserPhysicalPages`** -> arbitrary-PHYSICAL
   access from user input.
4. **`memcpy`/`RtlCopyMemory`/`strncpy`/`_vsnprintf` to a caller-supplied pointer.**
5. **Length fields taken from input** - pool overflows, `.sys` non-paged buffers with unchecked
   `InputBufferLength`/`OutputBufferLength`.
6. **`Zw*`/kernel API calls** taking user data (registry, files, connections).
7. **`MmCopyMemory`/`MmGetVirtualForPhysical`** - near-arbitrary reads.
8. **Pointers leaked into output** - `out` pointers passed to user mode, kernel VA leaks (KASLR).

Score each primitive with the scale in [`audits/scope/SEVERITY.md`](../audits/scope/SEVERITY.md),
then assemble the verdict row into `audits/STATUS.md`.

## 3. Automation available in this repo

- `tools/triage_scan.ps1` - quick pass for suspicious imports (`MmMapIoSpace`, `MmCopyMemory`,
  `PsGetVersion`, `ObReferenceObjectByHandle`) before you commit to a full audit.
- `guides/02_blocklist_check.md` - the two-list check that stops you re-auditing anything that
  LOLDrivers or the Microsoft blocklist has already catalogued.
- Copy the per-driver skeleton above into a new file per driver; one file per driver,
  always. Update `STATUS.md` *after* writing the report, not before.

Run the scanner on one file:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\triage_scan.ps1 drivers\<file>.sys
```

It prints one row per file with the imported device APIs, device/symlink names, SDDL reach, and a
`NO-DEVICE` marker for miniports and filter drivers. It is triage, not an audit - the report still
needs the manual trace.

## 4. When the verdict answers you leave

Keep `audits/reports/` flat and alphabetical so the manifest sorting is predictable. A driver
you have not audited still gets a stub report with `Verdict: PENDING` and the known entry
surface, so a later agent can pick it up without asking you.
