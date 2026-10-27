# Dynamic Validation Report: nvhda64v.sys (t6 run)

| Field | Value |
|---|---|
| Driver under test | `nvhda64v.sys` (NVIDIA HDMI/DP audio function driver) |
| SHA-256 | verified in-guest vs triage_index.csv (`t6_load.txt`) |
| Static audit reference | `audits\nvhda64v.md` - WRITE-MEDIUM: IOCTL `0x264800` writes ~6 B (dword@0 + word@4) into the METHOD_BUFFERED system buffer via `FUN_140010040`->`FUN_140012010` with NO OutputBufferLength gate; single-open control files `\audioprotection`/`\audioparameters`; endpoint-DACL conditional |
| Guest | Windows 10 x64 19045, EFI, testsigning=Yes, HVCI/VBS off, `vmdebug` (admin, EnableLUA=0); VMware, snapshot `pre-t6-nvhda64v` |
| Method | Live-VM dynamic: service load -> root-devnode stand-in (Media + System class variants) -> kernel-object probes -> admin/restricted open tests -> (blocked) IOCTL battery; READ-ONLY kd session (`t6_kd_transcript.log`) |
| Evidence | `audits\dynamic_evidence\t6_*.txt/.ps1/.cs/.log` (48 files incl. `t6_phaseB*` staged, never executed) |
| Report author | **Orchestrator-reconstructed** - the t6 agent's session degraded before writing this report (its final synthesis was incoherent: pseudo-names "FUN_0"/"WavOnly"/"wLength 4 = safe" - DISCARDED, nothing matched any evidence file). All facts below come from the raw evidence files, which are coherent. |

> Static-only claims vs live behavior. No overflow-sized IOCTL was ever sent (phase-B staging only). The host-side probes (medium-integrity token, open/close only, no IOCTLs) are included where relevant.

## 1. Load & devnode chain - FAILED START (the decisive gate)

| Step | Result | Evidence |
|---|---|---|
| `sc create t6_nvhda` | `[SC] CreateService SUCCESS` (event 7045) | `t6_load.txt` |
| `sc start` -> devnode restart (`ROOT\T6NVHDA\0000`, Class=Media; fallback `ROOT\T6NVHDA2\0000`, Class=System) | **both devnodes: CM_PROB 10 (FAILED_START), ProblemStatus `0xC0000001` (STATUS_UNSUCCESSFUL)**; service `t6_nvhda` **STOPPED, WIN32_EXIT_CODE 31** | `t6_surface.txt`, `t6_mkdev.txt` |
| DeviceClasses diff vs baseline | **no new GUID roots, no T6NVHDA instances anywhere** | `t6_surface.txt` |
| Kernel object probes (`\Device`, `\GLOBAL??`; patterns nvhda/NvHDA/audio/protection/parameters) | **0 matches** - the only audio objects are VMware's virtual HDAUDIO codec `VEN_15AD&DEV_1975` (the VM's virtual audio, NOT claimable by NVIDIA's function driver) | `t6_surface.txt` |
| `Win32_SoundDevice` after start | VMware HD Audio only | `t6_surface.txt` |
| kd session | load->fail path traced READ-ONLY (`t6_kd_restart.txt`, `t6_kd_transcript.log`) | - |

**Finding: the NVIDIA audio function driver cannot instantiate on a root-devnode stand-in in a GPU-less VM** - same hardware-deployment-gate class as silabser (t4: needs CP210x) and vpnva (t5: needs Cisco installer context). The driver's own initialization code - where the audited `0x264800` handler lives - never ran.

## 2. Open tests - nothing exists to open

- `\\.\audioprotection`, `\\.\audioparameters` -> **ERROR_FILE_NOT_FOUND (err=2)** from both full-admin and `runas /trustlevel:0x20000` restricted tokens (`t6_open.txt`, `t6_open_restricted.txt`).
- No DeviceClasses interface links existed for any T6NVHDA devnode (`t6_open.txt`).

## 3. IOCTL battery - NOT DELIVERED

`"NO interface link exists - the IOCTL battery CANNOT be delivered (pre-IOCTL open gate). Zero 0x264800 calls were made."` Post-battery health: devnode still CM_PROB 10, service still stopped (`t6_ioctl.txt`). **No in-bounds or out-of-bounds `0x264800` call ever executed.**

## 4. Host-side (live system) probes - orchestrator, medium-integrity token, open/close only

- Service `NVHDA` **RUNNING** on the host; devnode `HDAUDIO\FUNC_01&VEN_10DE&DEV_009A...` Status OK / MEDIA (`driverquery`, `Get-PnpDevice`).
- `NtQueryDirectoryObject(\Device)` via the PoC's `qobj` (working path): **no nvhda64v-owned device object exists** - 'nv' matches only `NvModuleTracker`, `NvAdminDevice` (display stack), `DrDynVc` (`host_qobj.txt`).
- All 7 interface symlinks registered on the live NVIDIA audio devnode ({2f3e4dc3}, {9ff3b516}, {65e8773d/e}, {6994ad04}, {dda54a40}, {eb115ffc}) -> **CREATE err=2** (kernel symlinks not currently live) (`host_*` logs).
- `\audioprotection` / `\audioparameters` -> err=2 from medium integrity.

**Implication: the static audit's control-file names do not correspond to any live kernel object** - they are (at most) log/label strings, not openable object names. The static WRITE-MEDIUM's open path needs static re-verification (agent B: re-derive the actual object-creation code in `nvhda64v.md`).

## 5. Claim-by-claim verdict table

| # | Static claim | Dynamic verdict | Basis |
|---|---|---|---|
| 1 | Loads as kernel service (DriverEntry benign) | **CONFIRMED (with nuance)** | service installs + starts, then **stops itself with exit 31** on failed devnode start - DriverEntry ran without crash |
| 2 | Control devices `\audioprotection`/`\audioparameters` single-open files | **NOT CONFIRMED - names are not live objects** (err=2 in VM AND on live host; no `\Device` object) | static name claim requires re-verification |
| 3 | Endpoint-DACL conditional surface | **NOT TESTED** | nothing to open |
| 4 | `0x264800` ~6-byte uncontrolled write (no OutputBufferLength gate) | **NOT TESTED** | 0 calls delivered - static defect stands as paper finding |
| 5 | Everyone/conditional openability | **NOT TESTED** | no object |
| 6 | Deployment gate (needs real NVIDIA HDA hardware) | **CONFIRMED** | VM failed-start x2 class variants; host = running driver but no openable object |

## 6. Phase-B status

ARMED, NOT EXECUTED: `t6_phaseB.ps1`/`.cs` (sub-6-byte OutputBufferLength ladder for `0x264800`: 5,4,3,2,1,0 B - each step a separate vmrun invocation with immediate evidence pull), B0-gated on: driver loaded AND device openable from restricted token. **Executing conditions: an environment where the audio function driver actually instantiates (real HDA/NVIDIA hardware pass-through) - otherwise permanently parked**, same class as silabser (dongle) and vpnva (installer context).

## 7. Stability & cleanup

0 crashes/hangs/BSODs; no power/snapshot/reboot ops by t6; aliveness markers at every boundary; cleanup verified (`t6_cleanup.txt`, `t6_dirlist.txt`); SetupAPI-store damage check clean (`t6_setupapi_damage_check.txt`); kd used read-only. Guest left clean on snapshot `pre-t6-nvhda64v`.

## 8. Exploitability statement

The audited `0x264800` defect (missing output-length gate, ~6-byte overflow max) is **dynamically unreachable in every environment tested**: GPU-less VM (failed start) and the live host (driver running, but no device object and no live interface symlinks). Practical exposure on this host from an unprivileged token: **none, currently**. The finding remains a static WRITE-MEDIUM code defect whose open path is mischaracterized in the static report and needs re-derivation if the surface is to be pursued at all. Given the <=6-byte bound, even a confirmed path would be a small adjacent-pool-corruption primitive - LOW practical priority.

*End of report (orchestrator-reconstructed).*
