# Agent-H handover — historical analysis artifacts

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

This folder contains the Agent-H handover for the MegaRAID/SiS storage drivers:

- `ghidraProj/` — Ghidra project used for the decompilation head start (**local-only; the
  database is gitignored**, what's committed here is the scripts/output)
- `out/` — decompiled output / recon
- `*.ps1` — certificate, string, and section scanners
- `*.strings.txt` — per-driver string extracts

It is **analysis state**, not a corpus folder and not a report folder. Canonical reports live in
`../../reports/`; current severity/scope is in `../../scope/SEVERITY.md` and
`../../scope/AUDIT_SCOPE.md`.

The original handover was moved out of `%TEMP%` on 2026-10-24; this is the retained copy.
