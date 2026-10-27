# AGENTS.md — instructions for AI agents

You are working in an instruction-only BYOVD research lab. This branch has no corpus, no reports,
and no tool binaries; your job is to build the lab and run the method.

## Read in this order

1. `PROJECT_GOAL.md`
2. `WANTED_LEDGER.md`
3. `audits/scope/AUDIT_SCOPE.md`
4. `audits/scope/SEVERITY.md`
5. `audits/scope/STATIC_ANALYSIS_AGENT_PROMPT.md`
6. `audits/STATUS.md`
7. `guides/00_quickstart.md` through `guides/04_dynamic_vm.md`

## Non-negotiable rules

- Only kernel memory writes count. MSR, port I/O, PCI config, SMBus/EC, and fixed-window MMIO are
  `HW-ONLY` unless they chain into a memory write.
- Reach tiers: `R1` unprivileged, `R2` local administrator (**in scope**), `R3`
  devnode/hardware/composition. Setup is a severity field, not a disqualifier.
- Never run a driver or an installer on the host. Dynamic work is VM-only, one snapshot per batch.
- `drivers/` is flat and contains only `.sys` plus `README.md`. Add files only through
  `tools/filter_new_drivers.ps1 -UpdateExisting`; never copy by hand.
- One canonical report per driver in `audits/reports/`; update `audits/STATUS.md` **after** writing
  the report.
- No exploit code in reports. PoCs live in `poc/` and are VM-only.
- Static analysis only on the host.

## Workflow

1. Read `audits/STATUS.md`; do not duplicate an existing verdict.
2. Collect with `tools/harvest.ps1`; dedupe with `tools/filter_new_drivers.ps1`.
3. Blocklist-check against LOLDrivers and the Microsoft list (`guides/02_blocklist_check.md`).
4. Audit statically with the default prompt; write `audits/reports/<driver>.md`.
5. Prove the primitive only in a snapshotted VM; raw logs go to `poc/dynamic/results/<date>/`,
   the reproduction recipe goes to `audits/evidence/`.
6. Record the verdict in `audits/STATUS.md`.

## Re-targeting

`PROJECT_GOAL.md` and `WANTED_LEDGER.md` are the control surface. Edit them first, then update the
`Scope:` line in `audits/STATUS.md`. Keep the shared vocabulary so reports stay comparable.

## Tools

Not shipped on this branch. Fetch the four scripts from `example` when you start collecting; see
`tools/README.md`.
