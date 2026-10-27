# Dynamic testing - only inside a disposable VM, only against your own pages

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

> Static analysis finds the primitive; you only need dynamic testing to *prove* it. This is where
> the discipline matters: one driver at a time, snapshot first, and never a live system address.

## 0. Build the VM first

Before any dynamic work, set up the guest the whole method depends on:

- Create a disposable Windows 10/11 VM (VMware Workstation or equivalent). It is a
  single-purpose target - nothing personal on it.
- Install the harness tooling: PowerShell 5+ and the .NET SDK (the harness pattern is C#),
  plus WinDbg for dump analysis.
- Take one baseline snapshot (e.g. `pre-driver-tests`) **before** any driver is loaded; revert
  to it before **and** after every test batch.

## 1. The VM rules of this repo

- One test VM, one snapshot baseline, revert **before and after** every test batch.
- One driver at a time: load it, exercise its IOCTL, unload it, *then* revert.
- Credentials for the guest live in a local file (`VM_ACCESS.md`) that is .gitignored and
  never leaves your machine.
- The harness only writes to pages **you** allocated (`AllocateUserPhysicalPages`); it never
  targets a live system address. Expected failure mode is a clean BSOD you can debug from the guest's dump.

## 2. The harness pattern (this repo's `poc/dynamic/`)

> [!NOTE]
> The self-test harness and the `run_<driver>.ps1` wrappers are **not shipped** in this repo.
> `poc/dynamic/` on `example` contains only that script set (`get_privs.ps1`,
> `grant_lockmem.ps1`, `list_minidumps.ps1`, `ObjList.cs`) - plus a `poc/README.md` one level up.
> Treat the block below as the shape to implement, not something you can run as-is.

```text
ControlledIoctlSelfTest.exe
|-- allocate 3 PFNs            (SeLockMemoryPrivilege needed)
|-- map two via the driver's own IOCTL  (or per-driver config)
|-- fill page A with a pattern, zero-fill page B -- the two pages are *yours*
|-- poke the driver:           "copy PA(A) -> mappedVA(B)"
\-- verify:  pattern seen in B?  write primitive confirmed -> finding recorded
```

Each driver gets a tiny `.ps1` wrapper (`run_<driver>.ps1`) that: create service -> start ->
harness -> stop -> delete service -> revert snapshot; the wrapper writes a log under
`poc/dynamic/results/` so every claim in `audits/evidence/` has a file backing it.

## 3. What can go wrong, and the countermeasure

| Failure | Try this |
|---|---|
| `MapUserPhysicalPages` not permitted | use the driver's own PA->user mapping IOCTL as the mapper (fewer assumptions) |
| Device open fails with error 2 (`ERROR_FILE_NOT_FOUND`) | the C# `CreateFileW` P/Invoke *must* set `CharSet.Unicode`, or the path is sent as garbage bytes |
| Harness bugcheck | do NOT assume the driver is malicious - check the dump; crashes are often the harness's own bug (e.g. a field-order mistake in the request struct) |
| Driver loads but no device | verify the object-manager namespace and the service actually reported RUNNING |

Pull the guest dump out (`C:\Windows\MEMORY.DMP`) and analyze it with WinDbg (`!analyze -v`).
The original run used the `mcp-windbg` MCP server for this; any WinDbg setup works.

## 4. Recording

`poc/dynamic/results/<yyyy-mm-dd>/<driver>_<harness>.log` contains the raw harness output;
`audits/evidence/` holds the "reproduction recipe" (down the syscall chain, exact IOCTLs).
Static or dynamic, every finding ends in the same format per driver before it is merged:

```
Verdict: MW1 | reach=R2 setup=none write=W1 load=signed
```

The one-line "why" lives in `audits/STATUS.md`.
