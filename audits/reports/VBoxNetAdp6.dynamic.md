# Dynamic Validation - VBoxNetAdp6.sys (t9_* run, guest phase; runs 1-2)

| | |
|---|---|
| **Date** | 2026-10-24 (guest runs ~01:05-01:45 UTC-07:00); host static prep same day |
| **Guest** | Windows 10 x64 19045 (EFI), testsigning=Yes, HVCI/VBS off, user vmdebug (admin token, EnableLUA=0); VMware Workstation; snapshot `pre-driver-tests` (orchestrator-owned) restored before run 1; **NOT restored before run 2** (orchestrator decision: resume-without-revert after an external clean power-off) |
| **Method** | vmrun `runProgramInGuest` -> PowerShell -File scripts (cmd.exe broken in-guest, t4 precedent); host-compiled C# PoC (`t9_poc.cs`, Framework64 v4.0.30319 csc) issuing raw-NTSTATUS probes via ntdll; DACL pulls (`GetKernelObjectSecurity` + SDDL convert); PnP devnode creation (`CM_Create_DevNodeW`) + registry seeding; pnputil/netcfg driver deployment; unpriv pattern `runas /trustlevel:0x20000` (staged; not needed on the no-device negative) |
| **Outcome** | **VBoxNetAdp6 installs and RUNS as an unmodified WHQL package on the bare guest (devnode started, miniport Running, adapter Up)** - its receive-conversion defect (unchecked sum-of-segment-lengths copy) is present in a LIVE driver but remains unreachable: the shipped SG producer (VMMR0.r0 IntNetR0) is equality-by-construction (Phase-1 static headline). No user-openable device object of its own exists (negative pack complete). Zero BSODs, zero wedges. |
| **Verdict delta** | **WRITE-HIGH (candidate) -> NO-WRITE via shipped invariant** (defect in-file, unreachable in the shipped 7.0.14 composition; static producer analysis + dynamic live-driver context) |
| **Coverage** | Dynamic: load layer 100% (deploy path + AddDevice/start + enumeration); negative-surface battery 100%; OID-plane/battery probing intentionally out of scope (no user surface); combined with the static ~50% the decisive items are fully resolved |

Evidence: `audits\dynamic_evidence\t9_*` (runbooks, logs, PoC, decomp). Guest artifacts under `C:\Users\vmdebug\Desktop\t9_work\` (t9 namespaced).

---

## 0. Ground-truth drift disclosure

**None.** All three binaries hash-identical between the audit corpus, the host install,
and the guest deployment:

| Copy | SHA-256 |
|---|---|
| Audited `VBoxNetAdp6.sys` (corpus + triage row) | `4E619BB6370F4BC4BE52F43D6C43F3A86E3E2CE7BB04BAADFF17D3B731F18F3F` |
| Host install `drivers\network\netadp6\VBoxNetAdp6.sys` | identical |
| Guest-deployed `C:\Windows\System32\drivers\VBoxNetAdp6.sys` | identical (in-guest hash check; sig Valid) |

Static claims from VBoxNetAdp6.md were therefore tested against the very binary the
guest executed. Version strings in-guest: Driver 7.0.14.11095 / NDIS 6.0 / build stamp
2024-01-15 (matches the INF DriverVer).

## 1. Support-driver layer (VBoxSup, t9_vboxsup) - context for the IDC client

- `sc create t9_vboxsup type= kernel start= demand binPath= t9_work\VBoxSup.sys` ->
  CreateService SUCCESS -> **STATE 4 RUNNING** (exit 0). [t9_stage.txt]
- Device surface (name-based, admin token):
  `\Device\VBoxDrv` open 0x12019F -> **st=0xE986F15C** (VBox-specific denial;
  reproducible across the two runs); `\Device\VBoxDrvStub` -> **st=0xE986E9F8**;
  `\Device\VBoxDrvU` -> **st=0x00000000 (opens)**, DACL
  `O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)`
  (**Everyone = 0x1201BF**, GR+GW); `\Device\VBoxDrvErrorInfo` -> opens, same
  Everyone-RW DACL. [t9_sup_names.txt, t9_adp_probe.txt]
- Confirms the audit's unpriv-openable class for VBoxDrvU (default-DACL item resolved
  dynamically; Everyone-GRGW in the DACL string is itself the token-independent proof).

## 2. Deployment ladder (documented layer by layer)

| Layer | Action | Result |
|---|---|---|
| L1 store staging | `pnputil /add-driver VBoxNetAdp6.inf /install` | **SUCCESS** -> `oem9.inf`; Signer Score `0x0D000005 (WHQL)`; Signer = Microsoft Windows Hardware Compatibility Publisher; Submission ID `30041490_13562717952827599_...`; "Unable to find any matching devices" (no devnode auto-created - expected for NCF_VIRTUAL) |
| L2 devnode | `CM_Create_DevNodeW("ROOT\SUN_VBOXNETADP\0000", parent "HTREE\ROOT\0", flags=0)` (t3 recipe) | **CR=0**, devnode dn=0x2, initial status `0x1802001` problem 0; hardware-initiated install section opened immediately |
| L3 driver matching (first attempt) | enum key auto-created by the hardware-initiated install (no HardwareID) | **FAILED: "No compatible drivers found" (0xE0000228)** -> devnode `CM_PROB_NOT_CONFIGURED (1)` |
| L3 fix | seed enum key `HardwareID=[sun_VBoxNetAdp, SUN_VBOXNETADP]` + Service=VBoxNetAdp + Class=Net + ClassGUID | matching completed; INF AddService created the `VBoxNetAdp` service (kernel, NDIS group, binary -> %12%\VBoxNetAdp6.sys); transient `CM_PROB_REGISTRY (19)` during processing |
| L4 AddDevice / start | PnP restart | **`{Core Device Install - exit(0x00000000)}` + `Device Status: 0x0180200b` (setupapi 01:23:31)** -> devnode `CM_PROB_NONE`, `status=0x180200B` (DRIVER_LOADED+STARTED), service **RUNNING** |
| L5 NetSetupSvc / ndi bindings | implicit (INF ndi AddReg during device install) | adapter fully materialized: interface GUID `{BDC167B6-57F0-4CBA-9574-740C75C2BEDC}`, ifIndex 24, MTU 1500, Endpoint=TRUE |

Net result: **the full production install path works on a bare guest** with only the
devnode-seeding nudge that any virtual-adapter INF needs.

## 3. Negative-surface pack (the in-file "no device object" claim, confirmed live)

- Name probes (admin, 0x12019F): `\\.\VBoxNetAdp6` -> **err=2**; `\\.\VBoxNetAdp` ->
  **err=2**; `\\.\VirtualBox\HostInterfaceNetworking-...` -> **err=3**.
  **No user-openable device object exists.** [t9_adp_probe.txt]
- The only kernel-object surface is the NDIS-managed interface
  `\Device\{BDC167B6-...}` (ndis-controlled, bound via the NDIS stack, not a
  driver-created control device; WdmInterface=TRUE is the NDIS miniport object).
- Adapter enumeration (live): "VirtualBox Host-Only Ethernet Adapter", MAC
  `0A-00-27-00-00-18`, Status Up, 1 Gbps, NDIS 6.0, ComponentID `sun_VBoxNetAdp`,
  PnPDeviceID `ROOT\SUN_VBOXNETADP\0000`.
- Consequence: the driver's user-mode attack surface is EMPTY by construction - all
  reachability runs through the VBox transport callback plane (kernel-side), exactly
  as the static audit concluded.

## 4. The SG-producer invariant (headline, from Phase 1 - carried into the verdict)

The receive-conversion defect (`FUN_140002450`: pool buffer sized `SG+0x20 total`,
copies `sum(seg.len)` via unbounded `FUN_14001EC40` memmove, no in-file check) is
**real but unreachable in the shipped composition**:

- The SG producer is NOT in VBoxSup.sys (no SUPR0IntNet* exports; `SRV_INTNET` is a
  CALL_SERVICE dispatch name into loaded modules). It ships as **VMMR0.r0**
  (source path string `\Devices\Network\SrvIntNetR0.cpp`), SHA
  `1133C74717583660A5208408961A2027FBD3932A7BA44AAD128222A807CBCAB0`.
- `IntNetR0IfSend` (VMMR0 +0x16c9f0) builds every SG delivered to the host trunk
  clients with `cbTotal(+0x20) = ring-header cbFrame` and
  `cSegs=cSegsUsed=1`, `aSegs[0].pv(+0x38)`/`aSegs[0].cb(+0x40)` from the SAME value;
  the GSO path rebuilds per-segment SGs with `cbTotal = seg0.cb + seg1.cb`.
  **Sum-of-lengths == total by construction** (t9_vmmr0_sgproducer.txt).
- Delivery into the client is singular (trunk vtable[+0x48], invoked once, from
  FUN_18016b930); no mutation window on length fields between build and delivery.
- Guest-controlled frame lengths scale both sides identically (device-emulation-
  bounded cbFrame). No clamp is needed and none exists because equality is structural.

**VM-confirmation plan status:** read-only SG descriptor observation (static plan
step 2) is superseded by the completed producer-side static analysis; the destructive
step (plan step 3) remains **STAGED, never executed** (see section 6).

## 5. Halt / power events (full disclosure)

- **Run 1 halt (~01:30 guest time):** the VM lost power between guest steps
  (agent-performed `vmrun list` -> 0 running VMs). Agent performed NO power ops;
  per halt discipline the run was stopped and the state written
  (t9_guest_phase_state.txt). Orchestrator post-mortem: external VIX soft power-off
  (`VMAutomationPowerOff`, cleanShutdown=TRUE, 08:30 UTC) - same anomaly class as t8.
- **Run 2 (resume):** orchestrator started the VM WITHOUT reverting (guest state
  survived the clean shutdown); agent resumed at the LWF levers step, verified all
  surviving state first (t9_resume_state.txt), and proceeded.
- **Run 2 second external power-off risk:** none materialized; the run completed
  through cleanup + verify.

## 6. Staged-but-not-executed (summary for the orchestrator)

| ID | Gate | Content |
|---|---|---|
| `t9_phaseB` (adp6/lwf) | B0: a producer delivering SG with cbTotal < sum(seg.len) - requires a genuine in-guest VirtualBox VM + frame injection through the emulated NIC plane (EXPLICITLY out of scope per mission directive) | B1 trigger the unbounded memmove copies (FUN_14001EC40) -> deliberate pool overflow, SOLO phase, orchestrator-only; B2 sentinel observation. NEVER EXECUTED; marker `t9_phaseB_STAGED.txt` staged in guest t9_work + host stage dir. |

## 7. Cleanup verification

`audits\dynamic_evidence\t9_cleanup.txt` (run 2):
- Services stopped (VBoxNetAdp stop-pending -> stopped; VBoxNetLwf already stopped;
  t9_vboxsup stopped) BEFORE file-bearing deletions (order-corrected for the
  resume-without-revert state).
- `netcfg -u VBoxNetLwf` -> exit 0 (documents the component was never installed).
- Devnode: `pnputil /remove-device ROOT\SUN_VBOXNETADP\0000` -> "Device removed
  successfully"; enum key gone.
- Store packages: `oem9.inf` + `oem10.inf` both "Driver package deleted successfully".
- Services deleted: t9_vboxsup / VBoxNetAdp / VBoxNetLwf -> 3x DeleteService SUCCESS;
  post-checks all 1060 (absent).
- Deployed files: `drivers\VBoxNetAdp6.sys` **absent** after delete-driver
  (uninstalled with the package), VBoxNetLwf.sys absent (never deployed), VBoxSup.sys
  absent (never INF-staged; demand service only).
- **Light-cleanup deviation (orchestrator-directed):** the final `pre-driver-tests`
  revert at campaign end is the authoritative reset; the documented end state here is
  "pristine except t9_work\ (scripts, logs, PoC, markers) per policy".
- Pre-existing guest services untouched throughout: vmci/vsock RUNNING,
  b06bdrv STOPPED - verified in discovery output.

## 8. PoC bug disclosures (user-mode only, no guest impact)

1. `qobj` mode BLOCKED 3/3 (t9_qobj_blocked.txt): `NtQueryDirectoryObject` returns a
   buffer that does not parse as a clean 32-byte-stride entry array under this .NET
   P/Invoke usage (string pointers land at low user VAs that AV on deref); an
   intermediate build's `ref uint` Context marshalling caused an infinite
   enumeration (539k iters, wedge-killed). All load-bearing work used name-based
   probes; the directory walk was never needed. Retro-explains t7's qobj AV class.
2. Script-logic fix during the run: the enum-key seeding guard skipped seeding when
   the hardware-initiated install had auto-created the key - corrected to seed id
   fields when HardwareID is absent (this was the L3 fix above).
3. One 180 s shell timeout on a direct-invocation qobj run (wedge rule); process
   killed in-guest, no guest impact.

*End of report.*
