# Audit: vmci.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\vmci.sys` |
| Recorded SHA-256 | `023EFB6166FC1291F4ADE77910A9F2C9C3BF38D807A33196639DA5E59BD8A2BC` (matches triage_index.csv) |
| Company/Version | Broadcom Inc. / 9.8.29.0 (csv row `vmci`, NotAfter 2025-05-14) |
| Method | Static-only audit via REA/Ghidra |
| Verdict | **NO-WRITE** (static) — no kernel memory-write primitive found in the audited surface; every copy is size-checked or allocation-matched; entry is access-gated. *Coverage: ~60% — IOCTL switch partially catalogued (see end).* |

> **Static-only.** No load, no device open, no IOCTL execution. All results digest-verified against SHA-256 `023efb61…a2bc` on the shared REA bridge (1-retry discipline). Evidence IDs: `ev_63cde94a…` (DriverEntry), `ev_cfa7f08e…` (AddDevice), `ev_caad80e1…` (MJ_CREATE), `ev_c4e47534…` (IOCTL switch), `ev_15f57837…` (WdmlibIoCreateDeviceSecure).

## Entry surface

- DriverEntry = `FUN_1400015b4` (INIT `0x14001a000` → `FUN_1400015b4`). WDM/PnP bus driver for "VMware PCI VMCI Bus Device"; `DriverExtension→AddDevice` = **`FUN_1400019b0`**.
- **AddDevice** creates the only user-reachable device, via **`WdmlibIoCreateDeviceSecure`** (`0x14001708c`, PAGE; forwards to dynamically resolved `IoCreateDeviceSecure` — assembly-verified call at `0x140001b00`, arg7 = `0x140012788`, arg8 GUID = NULL):
  - parent enumerates as `ROOT` → **`\Device\VMCIHostDev`** (host side), else → **`\Device\VMCIGuestDev`** (guest side); device type **4**, chars 0x100, ext 0xF0; one gets symlink **`\DosDevices\VMCIDev`**.
  - **The single SDDL string in the binary** (`0x140012710` in .rdata) is:
    `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)`
    → **Everyone (WD): GENERIC_READ + GENERIC_WRITE**; the 16 bytes at `0x140012788` form a `UNICODE_STRING{0x72,0x74,0x140012710}` wrapping exactly that text (57 chars = 114 bytes). Only two xrefs reference `0x140012788` — both inside the AddDevice `IoCreateDeviceSecure` call site — so both VMCI devices are intended to be **Everyone-openable read/write**. (Nuance: descriptor-as-PCWSTR plumbing could not be fully resolved statically; runtime confirmation listed below.)
- **MJ_CREATE = `FUN_140001ed0`** (Evidence `ev_caad80e1…`): rejects the request unless `(DesiredAccess & 0x3FEDFE60) == 0` (blocks requests for high-privilege bits such as DELETE/WRITE_DAC/WRITE_OWNER/MAXIMUM_ALLOWED/GENERIC_*); additionally, any open whose interface name contains **`\VMX`** must pass **`FUN_14000101c`** — the **third copy of VMware's SD-builder + `SeAccessCheck`** (ACEs: registry SID, `S-1-5-32-544` Admins, `S-1-5-18` System, all `0x1F01FF`); failure ⇒ `0xC0000022`. Other opens get a 0x20-byte FsContext (tag 'CTMM', flags from the access bits) — **no admin requirement for plain unpriv opens** of the non-`\VMX` name.

## Memory-write analysis

| Pattern | Result | Evidence |
|---|---|---|
| Copy-length confusion | Not found in audited branches. `0x81032004` (get device info): writes 4 bytes = `min(0xB0000, devext+0x14)` into ≥4-byte output | `ev_c4e47534…` |
| QueuePair VA list (user→kernel copy) | `0x81032018` (`IOCTL_VMCI_QUEUEPAIR_SETVA`, buffered): va-list pointer+count from system buffer; **count rejected if > 0x8000**; copy into an allocated buffer via "get va list from userlevel" helper (`FUN_140003104`) — size-matched, bounded; another branch allocates `*inPtr`-sized buffer without copy | `ev_c4e47534…` |
| Probe-less METHOD_NEITHER | Not observed in audited codes (all compared codes method-bits `00`) | `ev_c4e47534…` |
| MmProbeAndLockPages / MmMapLockedPagesSpecifyCache / MmMapIoSpace | Present (name-table strings at `0x14001ab3c/ab62/a7b0`); used for the VMCI notification bitmap and queue-pair page plumbing (kernel-managed buffers, PPN sets to hypervisor) — **no caller-controlled physical address or length found in audited paths**; caller pages used for queue pairs are locked via the normal IRP/MDL path after a successful context alloc | strings sweep |
| `\Device\PhysicalMemory` | **Absent** | strings sweep |
| MSR / GDT / IDT | Absent (VMCI queue-pair alloc uses hypervisor hypercalls, not MSR writes) | strings sweep |
| Datagrams / doorbells | Handlers gated on a per-file VMCI context ("Only valid for contexts"); datagram send copies the user datagram into a same-size allocation ("Failed allocating memory for datagram entry") | strings sweep |
| MJ_WRITE | No handler installed | `ev_63cde94a…` |

## Memory-touching IOCTL table (audited subset; device type 0x8103)

| Code | Method | Action |
|---|---|---|
| `0x81032004` | buffered | 4-byte device-info copyback (bounded by 0x8FFFF cap logic) |
| `0x81032008` | buffered | `IOCTL_VMCI_QUEUEPAIR_ALLOC`: `SeCaptureSubjectContext` → context create bound to caller SID (`FUN_14000dd7c`) → page allocation (`FUN_140005a38`) |
| `0x81032018` | buffered | `IOCTL_VMCI_QUEUEPAIR_SETVA`: va-list count ≤ 0x8000, size-matched user copy (`FUN_140003104`) → `FUN_14000c698` |
| remaining codes | buffered | queuepair alloc/attach/detach, doorbell create/destroy/ring, datagram send (context-gated; same-size allocations) — not individually decompiled in this pass |

## Verdict + VM confirmation plan

**NO-WRITE (static).** The audited IOCTL plane contains only bounded, size-matched copies; no METHOD_NEITHER derefs, no MDL→kernel-VA registration, no physical-memory mapping, no MSR/GDT/IDT writes. Reachability is *wide* (WD GRGW SDDL ⇒ any local user can open) but the handlers that copy user data do so with explicit count caps (≤ 0x8000 entries) and same-size allocations — a reachability surface without a found write defect.

VM confirmation (orchestrator-owned, non-destructive):
1. Unpriv open of `\DosDevices\VMCIDev`/`\Device\VMCIHostDev` → expect success (WD GRGW) — pins the SDDL finding.
2. Run `0x81032004` (4-byte read) as benign reachability proof.
3. If coverage should be raised: catalog remaining `0x8103xxxx` codes (doorbell ring/destroy, datagram send with `VMCIDatagram` copy, hibernate CPT restore "Couldn't copy cpt state from userlevel") — focus on any branch where an Information/length output is computed from a user field.

**Coverage: ~60%** — DriverEntry/AddDevice/MJ_CREATE fully audited; IOCTL switch audited through code `0x81032018` plus handler-name triage for the rest; switch tail (codes > `0x81032030`) and the four deep helpers (`FUN_140003104` probe semantics, datagram send, CPT restore, doorbell ring) not fully decompiled due to shared-bridge contention.
