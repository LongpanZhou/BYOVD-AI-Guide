# Dynamic Exploitability Validation — `silabser.sys` (t4_* run, PHASE A)

| | |
|---|---|
| **Companion static audit** | `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\silabser.md` |
| **Binary SHA-256** | `9393781CF3FD66C9EA21380EC8EC1AFFA6D84EB27C7EAEB14064BD90D32F27B2` (verified host-side before push, guest-side after push, and again after copy to `System32\drivers` — all three identical) |
| **Validation date** | 2026-10-23 |
| **Phase** | **A — non-destructive reachability + acceptance only** (destructive pool-corruption test = separate orchestrator-gated Phase B; script staged, never executed) |
| **Method** | Live-VM dynamic testing: driver loaded as kernel service `t4_silabser`; ROOT devnodes fabricated via `CM_Create_DevNodeW` (t1/t3 proven recipe); surface observed via SetupAPI, kernel object-directory queries (`NtQueryDirectoryObject`), registry, DeviceMap and event logs; open probes from admin full token and `runas /trustlevel:0x20000` restricted token. Guest: Windows 10 x64 build 19045 (EFI), testsigning=Yes, HVCI/VBS off, user `vmdebug` (full admin, EnableLUA=0). |
| **Outcome** | **Load chain fully proven; AddDevice runs deep (both device interfaces registered) but FAILS on the offline root-devnode stand-in — the device object is torn down and no openable surface exists. The complete IOCTL plane, including the 0x222028 write primitive, is therefore UNREACHABLE in this configuration: not one IOCTL reached the kernel.** 5 CONFIRMED, 1 PARTIAL, 4 NOT TESTED (pre-IOCTL gate). No crash; clean teardown. |

Evidence files referenced below live in `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\dynamic_evidence\` (`t4_*.txt`, `t4_*.ps1`, `t4_poc.cs`, `t4_phaseB.*`). Guest-side artifacts retained under `C:\Users\vmdebug\Desktop\t4_work\`.

---

## 0. Environment / protocol notes (disclosures)

1. **Wait-gate satisfied.** The orchestrator update re-scoped the gate to `checkToolsState == running`; in fact BOTH conditions held before any guest mutation: `vmrun listSnapshots` showed **`pre-silabser-write` present** (alongside `pre-driver-tests`) and tools state was `running` (19:44:25 host time). The VM disk had already been reverted to the clean `pre-driver-tests` baseline by the orchestrator before this boot. No deviation to report.
2. **`cmd.exe` is broken under `runProgramInGuest` in this guest** (every `cmd /c …` invocation exits 1, including trivial ones like `whoami > file`; evidence: my bootstrap probes). All guest execution therefore used PowerShell scripts via `-File` (exit 0 throughout) — consistent with the t1/t3 harness precedent.
3. **Script defects found and disclosed** (both logged in evidence):
   - `t4_surface.ps1`'s `PocRun` helper dropped the second argument → the two-argument `qobj` probes crashed with `FATAL IndexOutOfRangeException` (visible in `t4_surface.txt`). Corrected and re-run in `t4_surface2.ps1` → `t4_surface2.txt`.
   - `t4_devnode.ps1`'s stale-enum-key check computed the wrong path (`Enum\ROOT\ROOT` instead of `Enum\ROOT\T4SILABSER*`). Harmless in this run (no stale keys existed) and cleanup uses correct literal paths.
   - Cosmetic: `FormatMessageW` output in the PoC log truncates to `(T)` — the Win32 **codes** are the decisive data and are unambiguous.
4. **Prohibitions honored:** no `vmrun` power/snapshot/reboot operations, no guest reboot, no `0x222024`/`0x222094`, and — as it turned out — **no `0x222028` call at all** (the phase-A plan allowed exactly one in-bounds `wLength=1` acceptance probe, but no openable device ever materialized, so the probe was never dispatched; see §3). No host-side execution of anything from the target.

---

## 1. Setup & load chain (exact commands + results)

All guest runs: `vmrun -T ws -gu vmdebug -gp 123456 runProgramInGuest <vmx> powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\vmdebug\Desktop\t4_work\<script>.ps1`, followed immediately by `CopyFileFromGuestToHost` of the evidence file. Guest aliveness confirmed at every phase boundary by marker writes to `t4_alive.txt` that were read back from the host (guest-local times below, UTC-07:00).

### Phase timeline (guest-local)

| Time | Phase |
|---|---|
| 16:45:33 | bootstrap: `t4_work` created + `t4_alive.txt` roundtrip OK |
| 16:51:01 | baseline (step 1) |
| 16:51:17 | copy + hash + service (steps 2–3) |
| 16:51:29 | devnode (step 4) |
| 16:52:01 | surface observation + USB-HWID fallback (step 5) |
| 16:54:13 | corrected object-directory probes (surface2) |
| 16:56:04 | open tests admin + restricted (step 6) |
| 16:57:01 | formal IOCTL-battery attempt (steps 7–8) |
| 16:57:19 | cleanup (step 9) |
| 16:58:22 | phase-B staging (step 10; compile-only) |

### 1.1 Baseline (step 1) — evidence `t4_baseline.txt`

- Full `Get-PnpDevice` list, `DeviceClasses` GUID key list, `Enum\ROOT` listing captured.
- **No pre-existing silabser service** (`driverquery` no rows; no `silab*`/`t4_*` service keys; `C:\Windows\System32\drivers\silabser.sys` absent; no T4 enum-key leftovers) → the planned service name `t4_silabser` was used; no adaptation needed.
- Baseline SERIALCOMM DeviceMap: `\Device\Serial0 = COM1` (only serial port). Baseline COM1 opens fine.
- DeviceClasses `{86e0d1e0-8089-11d0-9ce4-08003e301f73}` (GUID_DEVINTERFACE_COMPORT) **pre-exists** (owned by ACPI COM1) — my cleanup therefore removed only my T4 instance child under it; `{a2a39220-39f4-4b88-aecb-3d86a35dc748}` does **not** pre-exist.

### 1.2 Driver copy + hash (step 2) — evidence `t4_load.txt`

- Host `silabser.sys` pushed via `CopyFileFromHostToGuest` to `Desktop\t4_work\silabser.sys` → SHA-256 = expected digest ✓; `Copy-Item` to `C:\Windows\System32\drivers\silabser.sys` → re-hashed, identical ✓.

### 1.3 Service (step 3) — evidence `t4_load.txt` — **SUCCESS**

```
sc create t4_silabser type= kernel start= demand binPath= C:\Windows\System32\drivers\silabser.sys
  -> [SC] CreateService SUCCESS
sc start t4_silabser -> STATE : 4  RUNNING   (kernel driver, exit code 0, PID 0)
driverquery /v -> "t4_silabser" ... Running ... \??\C:\Windows\System32\drivers\silabser.sys
```

`DriverEntry` ran benignly (service running, no error events). Matches static audit §1 (KMDF bootstrap; no side effects at load time).

### 1.4 Devnode (step 4) — evidence `t4_mkdev.txt` — recipe reproduced exactly

| Sub-step | Command | Result |
|---|---|---|
| (a) clean keys | enum-key check | `T4SILABSER` absent (clean) |
| (b) devnode first | `CM_Create_DevNodeW(out dn, "ROOT\T4SILABSER\0000", parent=HTREE\ROOT\0, flags=0)` | **CR=0x0**, devnode=0x2, fresh status `0x1802001` problem=0 |
| (c) seed after | `ConfigFlags=0`, `Class=System`, `ClassGUID={4d36e97d-…}`, `DeviceDesc="t4 Silabser CP210x"`, `HardwareID=ROOT\T4SILABSER` (MULTI_SZ), `Service=t4_silabser` | seeded ✓ (key auto-created by CfgMgr) |
| (d) restart | `pnputil /restart-device "ROOT\T4SILABSER\0000"` | **"Device restarted successfully."** |
| outcome | `CM_Get_DevNode_Status` | **status `0x1802401`, problem=0xA (dec 10) = CM_PROB_FAILED_START** — `DN_DRIVER_LOADED`/`DN_STARTED` bits absent |

So the t1/t3 proven order (devnode FIRST, seed AFTER; flags=0 only) held, but unlike the Logitech drivers, **silabser's device did not come up**: `Get-PnpDevice` shows `Status=Error, Problem=CM_PROB_FAILED_START`, `DEVPKEY_Device_ProblemStatus` = **NTSTATUS 3221225488 = `0xC0000010` (`STATUS_INVALID_DEVICE_REQUEST`)**, service binding `t4_silabser` correct.

### 1.5 AddDevice outcome / device surface (step 5) — evidence `t4_surface.txt`, `t4_surface2.txt` — **THE KEY FINDING**

| Probe | Result |
|---|---|
| `DeviceClasses\{a2a39220-39f4-4b88-aecb-3d86a35dc748}` (SILABUSBSERIALBRIDGE) | **child EXISTS**: `##?#ROOT#T4SILABSER#0000#{a2a39220-…}`, `DeviceInstance=ROOT\T4SILABSER\0000` → the driver's `WdfDeviceCreateDeviceInterface` for the custom interface **ran** |
| `DeviceClasses\{86e0d1e0-8089-11d0-9ce4-08003e301f73}` (COMPORT) | **child EXISTS** for our instance (beside baseline ACPI COM1 child) → the COMPORT interface registration in `SerialCreateExternalNaming` **also ran** |
| SetupDi `DIGCF_PRESENT\|DIGCF_DEVICEINTERFACE` on bridge GUID | **count=0** → interface registered but **NOT ACTIVE** (device never started, so KMDF never enabled it) |
| SetupDi on COMPORT GUID | only baseline `acpi#pnp0501#1` is ACTIVE; our T4 interface not present/active |
| Kernel object dir `\Device` (335 entries) | **0 matches for "Silabser"** → the named device object `\Device\Silabser<N>` does **not exist** |
| Kernel object dir `\GLOBAL??` | only `COM1 [SymbolicLink]`; no Silabser link |
| SERIALCOMM DeviceMap | unchanged (`Serial0=COM1` only) → no `\DosDevices\COM<N>` published, no SERIALCOMM value written |
| Event logs (System + Kernel-PnP/Configuration) | only SCM event 7045 (service installed); **no** driver-logged error, **no** Kernel-PnP config/start events for the devnode |
| AddDevice-outcome gate | `DEVPKEY_Device_ProblemCode = 10` → per plan, the **one** fallback ran |

**Fallback (exactly one, per plan):** fresh devnode `ROOT\T4SILABSER2\0000` with `HardwareID=USB\VID_10C4&PID_EA60` (same recipe) → created (CR=0x0), seeded, `pnputil /restart-device` "Device restarted successfully" → **identical outcome: problem=0xA (CM_PROB_FAILED_START), bridge interface count=0 ACTIVE, no surface** (`t4_mkdev_fallback.txt` embedded in `t4_surface.txt`).

**Interpretation (grounded in the static audit):** both interface registrations sit at the END of `EvtDriverDeviceAdd` (§2.1–2.2: custom interface `0x1400111b5`; COMPORT interface inside `SerialCreateExternalNaming` `0x140010538–0x1400107c5`; the naming tail — `\DosDevices` symlink `0x1400106c0`, SERIALCOMM write `0x140010708` — comes after the COMPORT registration). Since both interface registry entries materialized but no DOS name/SERIALCOMM entry ever appeared, the failure occurred **inside the naming tail of AddDevice (or at its return), after both interface registrations — and the KMDF framework then deleted the (already-named) device object**, leaving the interface registry keys as orphans and the devnode at CM_PROB 10 with `STATUS_INVALID_DEVICE_REQUEST`. The device object's absence is directly observed (`\Device` has no Silabser entry), so this was an AddDevice failure with KMDF rollback, not merely a failed START of a live FDO. Exact failing statement cannot be determined from user mode.

**Consequence: the device surface does NOT materialize without USB hardware — and it fails EARLIER than the static audit's predicted file-create hardware gate (§2.4): the gate observed here is in AddDevice/start itself.**

---

## 2. Open tests (step 6) — evidence `t4_open.txt`, `t4_open_restricted.txt`

All opens with `CreateFileW` (share=0, OPEN_EXISTING), exact Win32 errors recorded:

| Path | Admin token | Restricted token (`runas /trustlevel:0x20000`) |
|---|---|---|
| `\\?\ROOT#T4SILABSER#0000#{a2a39220-…}` (bridge) | err **2** ×3 (RW/R/W) | err **2** (RW) |
| `\\?\ROOT#T4SILABSER#0000#{86e0d1e0-…}` (COMPORT) | err **2** ×3 | — |
| `\\.\Silabser0`, `\\.\Silabser1`, `\\.\Silabser2` | err **2** ×9 | — |
| `\\.\COM2`, `\\.\COM3` | err **2** | — |
| `\\.\COM1` (baseline negative control — OS serial driver) | **opens OK** RW/R/W | — |

- `lastErr=2` = `ERROR_FILE_NOT_FOUND`: the disabled interface has no object-manager symlink and the named device object is gone. **This is not an access-denial** (err 5) — the driver's Everyone-DACL (§4.1) was never even reached, because there is no device behind the name.
- One non-destructive re-start attempt per devnode was made (`pnputil /enable-device`) → *"Failed to enable device: … Device is already enabled."* — the devnode stays in failed-start state; no new AddDevice was triggered.
- The restricted-token mechanism itself works in this guest (output file written; same error). This establishes the `runas /trustlevel:0x20000` recipe as usable for Phase B's unprivileged-open test **once a surface exists**.

## 3. IOCTL battery (steps 7–8) — evidence `t4_ioctl.txt` — **NOT DISPATCHABLE**

The formal battery run attempted `session` (open RW → in-bounds probes → single 0x222028 `wLength=1` acceptance probe) on both interface paths:

```
SESSION OPEN \\?\ROOT#T4SILABSER#0000#{a2a39220-…}   -> FAIL lastErr=2  (exit=2; NO IOCTL sent)
SESSION OPEN \\?\ROOT#T4SILABSER#0000#{86e0d1e0-…}   -> FAIL lastErr=2  (exit=2; NO IOCTL sent)
```

- **In-bounds acceptance probes (`0x222008`, `0x222080`, `0x222098`, `0x22209C`, `0x22200C`): NOT TESTED** — pre-IOCTL open gate (same shape as the t3 report's finding).
- **`0x222028` acceptance probe (`wLength=1`, in-bounds): NOT DISPATCHED** — no handle ever obtained. Phase A therefore ends with **zero** `0x222028` calls ever sent (the permitted single probe was never deliverable) — the destructive-call prohibition is satisfied trivially.
- No kernel-memory state was touched by this run; no crash, hang, or BSOD occurred at any point; the guest was responsive at every boundary.

---

## 4. Claim-by-claim verdict vs static audit (§2.1–2.2, §4, §5.1)

| # | Static claim (audit §) | Verdict | Dynamic basis |
|---|---|---|---|
| 1 | Driver loads as a demand-start kernel service; `DriverEntry` benign (§1) | **CONFIRMED** | `t4_load.txt`: CreateService SUCCESS → STATE 4 RUNNING, exit 0; driverquery shows the image mapped from `System32\drivers\silabser.sys` |
| 2 | `EvtDriverDeviceAdd` creates the named device + registers BOTH interfaces unconditionally in the device-add path (§2.1–2.2) | **CONFIRMED (partial pipeline)** | `t4_surface.txt`: DeviceClasses children for BOTH GUIDs `{a2a39220-…}` and `{86e0d1e0-…}` created for our devnode during AddDevice — registry proof both `WdfDeviceCreateDeviceInterface` calls executed. (The device object itself was then rolled back by KMDF on the AddDevice failure — see #6.) |
| 3 | Interfaces enabled at PnP START (§2.2) | **NOT TESTED** | Start never succeeded (CM_PROB 10) — the enable step was never reached |
| 4 | Everyone-DACL (`D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)`) → any local user can open RW (§4.1) | **NOT TESTED** (cannot be evaluated without a live device object) | All opens fail with `ERROR_FILE_NOT_FOUND` **before DACL evaluation** (no symlink/device behind the path) — both admin and restricted token, identically |
| 5 | No caller-identity/privilege/access-mask checks on create or IOCTL paths (§4.2) | **NOT TESTED** | Pre-IOCTL gate: no handle obtainable, so no create/IOCTL dispatch occurred |
| 6 | Device surface exists for enumeration+CreateFile (§4.2 "Reachability") | **REFUTED for this configuration** | AddDevice **fails** on the offline root stand-in (CM_PROB 10 / NTSTATUS `0xC0000010`); KMDF tears down the named device (`\Device` has no Silabser object); no ACTIVE interface; no DOS name — **no openable surface exists at all** |
| 7 | `0x222028` handler reached with user-controlled `wLength` (§5.1 steps 1–4) | **NOT TESTED** | IOCTL plane unreachable in this configuration; zero IOCTLs dispatched |
| 8 | Missing bound check → `WdfMemoryCreatePreallocated(out+8, wLength)` OOB write into 9-B buffer (§5.1 core) | **PENDING — Phase B** (needs responding CP210x hardware) | Script staged (`t4_phaseB.ps1/.cs/.exe`); B0 responding-device gate mandatory; hardware pass-through or USB emulation required |
| 9 | Exclusive-open inferred (§4.2) | **NOT TESTED** | No open ever succeeded; exclusivity unobservable |
| 10 | Secondary capabilities `0x222024` / `0x222094` (§5.2) | **NOT TESTED (prohibited in Phase A)** | Not sent, per phase scope |

**Summary: the entire user-mode attack chain stops at AddDevice in the offline VM.** The static audit's defect analysis (§5.1) remains intact and uncontradicted by dynamic evidence — but its reachability premise ("device present → any user opens → IOCTL") was **not reproducible** without actual CP210x hardware, and the observed failure point (AddDevice/start, with device-object rollback) is EARLIER than the static audit's predicted gate (file-create hardware init). This is a new, dynamic-only finding.

---

## 5. AddDevice / hardware-gate finding (the load-chain lesson)

On Win10 19045 with the t1/t3-proven ROOT-devnode recipe:

1. `sc create/start` loads `silabser.sys` cleanly (DriverEntry benign).
2. A ROOT devnode bound via `Service=t4_silabser` triggers `EvtDriverDeviceAdd`, which runs deep enough to create registry entries for **both** device interfaces.
3. AddDevice then **fails** (`STATUS_INVALID_DEVICE_REQUEST`; devnode `CM_PROB_FAILED_START`), the KMDF device object (incl. `\Device\Silabser<N>`) is destroyed, interface registry entries are orphaned and stay DISABLED, and no DOS-name/SERIALCOMM publication occurs.
4. The failure is hardware-independent in its *form* (identical with `ROOT\T4SILABSER` and `USB\VID_10C4&PID_EA60` HWIDs), i.e. it is the offline root-stand-in configuration that cannot satisfy the driver's AddDevice expectations — but the exact failing statement inside the driver's naming tail could not be identified from user mode.
5. Practical consequence for this audit: **dynamic confirmation of the 0x222028 OOB write requires a responding CP210x device** — either USB hardware pass-through or USB-device emulation — so that AddDevice completes and a surface materializes. The Phase-B script's B0 gate encodes exactly this precondition and will abort with *"no responding device — hardware pass-through or USB emulation required"* if unmet.

---

## 6. Cleanup statement (evidence `t4_cleanup.txt`)

- `pnputil /remove-device` on both created devnodes → "Device removed successfully" ×2; **the driver auto-unloaded with the devnodes** (`sc stop` → 1062 "has not been started", matching t1's unload-on-remove behavior), then `sc delete t4_silabser` → `[SC] DeleteService SUCCESS`.
- `C:\Windows\System32\drivers\silabser.sys` copy deleted (verified gone).
- Enum keys `T4SILABSER`/`T4SILABSER2` already gone after remove-device (verified absent).
- DeviceClasses: `{a2a39220-…}` root removed after my T4 child (was empty then); `{86e0d1e0-…}` root **kept** with only the pre-existing baseline ACPI COM1 child (my T4 child removed) — baseline state preserved.
- Final verify: no silabser/t4 services (error 1060), no T4SILABSER PnP devices, SERIALCOMM back to baseline `\Device\Serial0 = COM1`.
- Guest alive at cleanup end and after phase-B staging (marker roundtrip `t4_alive.txt`, 16:58:22 guest-local). **No reboot, no power operation, no snapshot operation performed by this agent.** `t4_work\` retained per instructions.

---

## 7. PHASE B ARMED — awaiting orchestrator

Staged (compiled but **never executed** — evidence `t4_phaseB_staging.txt`):

| Guest file | Size | Purpose |
|---|---|---|
| `C:\Users\vmdebug\Desktop\t4_work\t4_phaseB.cs` | 8,636 B | destructive-probe source (host copy in `dynamic_evidence\`) |
| `C:\Users\vmdebug\Desktop\t4_work\t4_phaseB.exe` | 10,240 B | compile-verified build — **NOT RUN** |
| `C:\Users\vmdebug\Desktop\t4_work\t4_phaseB.ps1` | 4,442 B | per-step wrapper (evidence + aliveness marker per step) |

Design (each step = ONE separate `vmrun runProgramInGuest` invocation; per-step evidence `t4_phaseB_<step>.txt` must be pulled to the host **immediately after** the step so evidence survives a mid-sequence guest death; every log line is flushed to disk *before* the destructive call is issued):

- **B0 (safe gate, mandatory before any destructive step):** `0x222008` (18-B cached descriptor out of a 32-B buffer) must succeed, `0x222098` must return removed-flag 0, **and** `0x222028` with `wLength=1` GET_STATUS (in-bounds) must complete a live control-IN transfer. Gate strengthened beyond the plan's `0x222008`-only reading (a cached-descriptor copy can succeed with zero data even with no device); the live-transfer check is what actually proves a responding CP210x. On gate failure the script aborts: *"no responding device — hardware pass-through or USB emulation required"*.
- **B1 (17-B OOB):** `0x222028`, in `80 06 00 01 00 00 12 00` (GET_DESCRIPTOR DEVICE, wLength=18), out 9 B → expected 17-byte write past the 9-byte non-paged-pool system buffer (out+8 is its last valid byte). Expected effect: transient pool damage; may even "succeed" quietly; pool integrity thereafter suspect.
- **B2 (4-KB OOB):** `0x222028`, in `80 06 00 01 00 00 00 10` (wLength=0x1000), out 9 B → up to 4 KB of adjacent non-paged pool overwritten with descriptor bytes; bugcheck likely (`BAD_POOL_HEADER`/pool-corruption family), silabser.sys expected in the stack — the decisive evidence.
- **B3 (max):** `0x222028`, in `80 06 00 01 00 00 FF FF` (wLength=0xFFFF), out 9 B → up to 65,535-byte overflow; run only if B2 was somehow survivable.

**PHASE B IS ORCHESTRATOR-GATED: agent t4 executed NONE of B0–B3 and will not.**

---

## 8. Bottom line

- **What is proven:** the full user-mode load chain (service + root devnode + AddDevice entry) works from user mode with admin rights and is cleanly reversible; `DriverEntry` is benign; both interface registrations run unconditionally during AddDevice — exactly as the static audit describes (§2.1–2.2).
- **What is refuted for this configuration:** the practical reachability premise — on an offline machine (no CP210x hardware), **no device surface materializes** (AddDevice fails with `STATUS_INVALID_DEVICE_REQUEST` → CM_PROB 10; device object destroyed; interfaces registered-but-disabled; no COM link). Every open from admin and restricted tokens fails with `ERROR_FILE_NOT_FOUND` *before* the driver's Everyone-DACL could matter.
- **What is untouched:** the `0x222028` non-paged-pool OOB-write claim itself — **unconfirmed dynamically, but also uncontradicted**; it requires a responding device (hardware pass-through / USB emulation) and is armed for Phase B behind the mandatory B0 gate.
- **Stability:** zero crashes/hangs; no power/snapshot/reboot operations; guest left running and clean.

*All host-side evidence: `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\dynamic_evidence\t4_*.txt` + sources `t4_*.ps1`, `t4_poc.cs`, `t4_phaseB.*`. Guest-side artifacts retained under `C:\Users\vmdebug\Desktop\t4_work\`. No t1_*/t2_*/t3_* artifacts touched; `_ledger.md` untouched. No prompt-injection content was encountered in any target output during this run.*
