# Dynamic Validation — VBoxNetLwf.sys (t9_* run, guest phase; runs 1-2)

| | |
|---|---|
| **Date** | 2026-10-24 (guest runs ~01:05-01:45 UTC-07:00); host static prep same day |
| **Guest** | Windows 10 x64 19045 (EFI), testsigning=Yes, HVCI/VBS off, user vmdebug (admin token, EnableLUA=0); VMware Workstation; snapshot `pre-driver-tests` restored before run 1; NOT restored before run 2 (orchestrator decision: resume-without-revert) |
| **Method** | vmrun `runProgramInGuest` -> PowerShell -File scripts; host-compiled C# PoC (`t9_poc.cs`); netcfg/pnputil/sc deployment attempts with full setupapi.dev.log forensics; targeted Ghidra decompilation of the DriverEntry failure path (host-side, guest-identical binary) |
| **Outcome** | **The LWF never reached its device surface on the bare guest.** Store staging succeeds (WHQL), but the netcfg component install fails at driver matching (`0xE0000228` inside `0x800f0203`), and the direct service-recipe start fails at DriverEntry (`StartService FAILED 31`); two documented unblock levers (LoadOrderGroup=NDIS; INF Ndi template seeding) both fail identically. `\Device\VBoxNetLwf` never existed at any point -> the DACL/unpriv-open/sweep battery is unfulfillable in this composition. Zero BSODs, zero wedges. |
| **Verdict delta** | **WRITE-HIGH (candidate) -> NO-WRITE via shipped invariant**, PLUS the dynamic finding that the binding/start plane is gated in a bare guest (t5-class deployment gate at the binding layer) - the practical exposure is LOWER than static analysis alone suggested |
| **Coverage** | Dynamic: deployment layers 100% documented (store + netcfg + service + 2 levers + forensics); device-surface battery 0% (unreachable - the negative result IS the finding); combined with the static ~50% and the producer-invariant resolution, the decisive items are fully resolved |

Evidence: `audits\dynamic_evidence\t9_*`. Guest artifacts under `C:\Users\vmdebug\Desktop\t9_work\`.

---

## 0. Ground-truth drift disclosure

**None.** Guest-deployed copy (t9_work\VBoxNetLwf.sys, pushed + in-guest SHA-verified)
= `CD3AF3B853C27626FCFC85997FEEAD0A48E56D618E2129F62FE1B96A203A44C7` = audited binary
= host-install copy (drivers\network\netlwf\). The failure statuses below are
therefore the behavior of the EXACT audited binary.

## 1. Deployment ladder (every layer's exact result)

| Layer | Action | Result |
|---|---|---|
| L1 store staging | `netcfg -l VBoxNetLwf.inf -c s -i VBoxNetLwf` (and `pnputil`-equivalent internal flow) | **staging SUCCEEDS**: `{SetupCopyOEMInf}` -> `oem10.inf`; Signer Score `0x0D000005 (WHQL)`; Signer = Microsoft Windows Hardware Compatibility Publisher; Submission `30041490_13562717952827599_...`; "Indexed 2 device IDs" |
| L2 component install | netcfg "Install network driver - VBoxNetLwf" | **FAILED `0x800f0203`** (netcfg exit 515): `{Create Device - exit(0x00000000)}` -> `{Build Driver List - exit(0x00000000)}` -> **`Selecting driver failed(0xe0000228)`** -> `{Select Best Driver - exit(0xe0000228)}`. No service (SC 1060), no file copy (`drivers\VBoxNetLwf.sys` absent), device object absent (`\Device\VBoxNetLwf` -> `0xC0000034`). Cause: netcfg's created devnode HWID (component id `VBoxNetLwf`) does not match the INF's indexed model id (`oracle_VBoxNetLwf`) - no compatible driver -> install aborts before the service plane |
| L3 service recipe (t7 fallback) | `sc create VBoxNetLwf type= kernel start= demand binPath= t9_work\VBoxNetLwf.sys` + start | CreateService SUCCESS; **`StartService FAILED 31`** ("A device attached to the system is not functioning"; event 7000) = **DriverEntry returned failure**; STATE 1 STOPPED; device object still absent |
| L4 lever A | `sc config VBoxNetLwf group= NDIS` -> start | **FAILED 31** (same) |
| L4 lever B | seed INF Ndi template under `HKLM\...\Control\Network\{4d36e974-...}\{7af6b074-048d-4444-bfce-1ecc8bc5cb76}` (FilterClass=compression, FilterType=2, FilterRunType=2, CoServices, Interface ranges, FilterMediaTypes=ethernet) -> start | **FAILED 31** (same) |
| L5 | loop-breaker reached | **BLOCKED** after 3 techniques (netcfg; plain sc; group+Ndi) |

## 2. DriverEntry failure path (decisive static support for the 31)

Host Ghidra 12.1.4 on the guest-identical binary (project T9VMMR0, base 0x140000000):

- Real DriverEntry/`entry` @ `0x140003740`: `RTR0Init` -> state init
  (`FUN_1400012d0`, mutex + magic "VBoxNetflt" + filter-registry state) ->
  `PsCreateSystemThread` for `vboxNetLwfWinStartInitIdcThread` (**not**
  failure-gated - a failed IDC thread spawn does not stop registration) ->
  builds `NDIS_FILTER_DRIVER_CHARACTERISTICS` (header `0x00C8018B` = type 0x8B,
  revision 1, size 0xC8; Major=6; 11 handler pointers incl. the audited
  indicate/return/set functions) -> **`NdisFRegisterFilterDriver(DriverObject,
  &handle)`** -> non-zero -> `DbgPrint("vboxNetLwfWinRegister: failed to register
  filter driver, status=0x%x")` -> teardown (`vboxNetLwfWinTryFiniIdc` plane,
  `FUN_140002420`) -> return.
- The exact NDIS status is not observable without a kernel debugger (guest kd
  absent; DbgPrint requires an attached debugger; the SCM maps any DriverEntry
  failure to generic code 31). The audit-relevant conclusion: the driver refuses to
  register on this bare guest independent of the binding config seeded in lever B.

## 3. Device-surface battery status (the load-bearing items)

| Item | Status |
|---|---|
| `\Device\VBoxNetLwf` exists? | **NEVER** (ntopen/daclnt -> `0xC0000034` at every check across both runs) |
| DACL pull (resolves the NDIS-default-ACL open item) | **NOT REACHABLE dynamically** - the in-file static claim stands unmodified: `NdisRegisterDeviceEx` with SymbolicName EMPTY and DefaultSDDLString NULL (evidence `ev_e3718aca…`/`ev_ec103b28…`); the OS default device DACL would govern - UNRESOLVED dynamically |
| Unpriv open (runas /trustlevel:0x20000) | **NOT REACHABLE** (no object to open; staged script `t9_lwf_fuzz.ps1` never ran) |
| Structured sweep dev 0x12 fn 0x000-0xFFF (0x120000+fn*4, 8 chunks) + raw band fn*4 (2 chunks) + dev 0x22 spot band | **NOT REACHABLE** (no object; the expected universal `0xC00000BB` dead-dispatch result remains a static claim, evidence `ev_ec103b28…`) |

The non-fulfillment is itself the dynamic finding: **in a bare Win10 19045 guest the
LWF is uninstantiable at its binding/start plane** - the same class as t5's vpnva
3-layer gate (here: 2 of 3 layers blocked with exact codes) and t2's
package-signature-era expectations, but with a WHQL-signed production package: the
gate is compositional (bare guest), not signature-related.

## 4. The SG-producer invariant (headline, from Phase 1 - carried into the verdict)

Same shared-invariant conclusion as VBoxNetAdp6 (one merged analysis):
- Producer = VMMR0.r0 IntNetR0 (`SrvIntNetR0.cpp`), NOT in VBoxSup.sys; SGs delivered
  to the LWF's VBox entry (`FUN_140004020`) always satisfy
  **sum(seg.len) == SG.total** (single-segment equality or rebuilt per-GSO sums).
- The LWF conversion defect (`FUN_140003130`: bucket from total+0x2A,
  `NdisGetDataBuffer(total)`, then sum-of-lengths copy with no check) is
  **unreachable in the shipped composition**.
- The device IOCTL dispatch is dead by construction (`MJ_DEVICE_CONTROL` ->
  `0xC00000BB` for everything) - and in this guest the device object itself never
  materializes.

## 5. Halt / power events (full disclosure)

- **Run 1 halt:** external VIX soft power-off (`VMAutomationPowerOff`,
  cleanShutdown=TRUE, 08:30 UTC) between guest steps; agent did NO power ops; state
  written and handed back (t9_guest_phase_state.txt).
- **Run 2:** orchestrator resume WITHOUT revert (state survived); run completed to
  cleanup + verify.

## 6. Staged-but-not-executed (summary for the orchestrator)

| ID | Gate | Content |
|---|---|---|
| `t9_phaseB` (adp6/lwf) | B0: producer violating the equality invariant (requires in-guest VirtualBox VM + NIC-plane injection - EXPLICITLY out of scope per mission directive) | B1 trigger the unbounded copy (`FUN_1400202C0`) -> deliberate pool overflow, SOLO, orchestrator-only. NEVER EXECUTED; marker staged (`t9_phaseB_STAGED.txt`). |
| LWF surface battery | B0': the driver registers (`NdisFRegisterFilterDriver` succeeds) AND `\Device\VBoxNetLwf` materializes | full t9_lwf_fuzz.ps1 battery staged and parse-checked (DACL pull, unpriv opens, dev-0x12 full fn sweep + raw band + dev-0x22 band); would resolve the NDIS-default-ACL item dynamically. NOT EXECUTED. |

## 7. Cleanup verification

`audits\dynamic_evidence\t9_cleanup.txt`:
- `netcfg -u VBoxNetLwf` -> exit 0 (documents "component not installed" state).
- The stopped service + store package: `oem10.inf` "Driver package deleted
  successfully"; `sc delete VBoxNetLwf` SUCCESS; post-check 1060 (absent).
- The Ndi template seeded by lever B under `Control\Network\{4d36e974}\{7af6b074-...}`
  was **NOT explicitly removed** (documented for the orchestrator: benign 6-value
  Ndi config block; the final `pre-driver-tests` revert is the authoritative reset -
  light-cleanup deviation, orchestrator-directed).
- `drivers\VBoxNetLwf.sys` absent (never deployed).
- Pre-existing guest services untouched: vmci/vsock RUNNING, b06bdrv STOPPED.
- End state: pristine except `t9_work\` (scripts, logs, PoC, markers) per policy.

## 8. PoC bug disclosures (user-mode only, no guest impact)

- `qobj` mode BLOCKED (shared with the adp6 report; t9_qobj_blocked.txt) - not
  load-bearing for this target (name-based probes used).
- No other PoC/script issues encountered in this target's steps.

*End of report.*
