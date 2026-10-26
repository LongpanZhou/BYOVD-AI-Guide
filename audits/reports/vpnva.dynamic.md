# Dynamic validation: vpnva64-6.sys

| | |
|---|---|
| **Companion static audit** | `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\vpnva.md` |
| **Binary SHA-256** | `506AB485FE0DA85C6DF6D0B7ABBAD412ACA6A8EB3F575DFC2C81662107054792` — verified on the **host source** (`certutil`), the **guest staging copy**, and the **guest `System32\drivers` copy** (all in-run, `t5_load.txt`); the DriverStore package copy (`vpnva-6.inf_amd64_b390894cbdbd8e01\vpnva64-6.sys`) also matched, and the package (`vpnva-6.cat`) is WHQL-signed "Valid" |
| **Validation date** | 2026-10-23 |
| **Agent** | t5 (dynamic validation agent, memory-write directive) |
| **Method** | Live-VM dynamic testing via vmrun guest ops (Win10 x64 19045, testsigning=Yes, HVCI/VBS off, user `vmdebug`, EnableLUA=0); NDIS miniport instantiated through devnode + genuine Cisco INF (`oem9.inf`) + `UpdateDriverForPlugAndPlayDevicesW`; **read-only kernel debugger** (kd / KDNET, pre-enabled in the guest) attached to observe the init chain |
| **Outcome** | **The NDIS miniport never instantiated in the test VM, so the control device `\Device\VPNVA` never existed and the entire IOCTL / MDL-map / no-authz surface was unreachable.** Load gate (service load) works; AddDevice fails inside ndis.sys before the driver's own init code runs (`STATUS_UNSUCCESSFUL`, CM_PROB 31 = `CM_PROB_FAILED_ADD`). Claim verdicts: 1 CONFIRMED, 1 PARTIAL, 6 NOT TESTED (§8). |
| **VM event** | Guest stopped responding to the kernel debugger during the pending-install retry loop, VMware Tools went down, and the VM exited host-side mid-Phase-A. No power/snapshot/reboot op was executed by this agent; full timeline in §7. |

All evidence files referenced below live in `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\dynamic_evidence\` (`t5_*`).

---

## 0. Prior-abort disclosure (preserved from the earlier stub)

The first dynamic attempt at this driver was **RUN ABORTED BY ORCHESTRATOR before completion** — validation reached the reconnaissance stage only (audit report + proven-load recipe read; REA handler decompile not yet run): no driver was loaded — `vpnva64-6.sys` was never copied to `C:\Windows\System32\drivers\`, service `t4_vpnva` was never created, no devnode was created, and no IOCTL/MDL/OID/parked-IRP phase was exercised. Residual guest state from that abort was limited to the `C:\Users\vmdebug\Desktop\t4_work\` directory (liveness marker + state-verification output, left for the record per abort instructions); no `t2_*` state was touched. This t5 run started fresh (`t5_*` namespace only, `t4_*` artifacts untouched).

## 1. Setup & load chain — CONFIRMED

### 1.1 Baseline (evidence `t5_baseline.txt`)

- `Get-PnpDevice`: **no Cisco/VPNVA devices** (only the Microsoft WAN miniports; the `SWD\MSRRAS\MS_AGILEVPNMINIPORT` IKEv2 WAN miniport is unrelated). Guest's real NIC (Intel 82574L, `Ethernet0`) is *Not Present*; network runs over `ROOT\KDNIC\0000` (kernel-debug adapter, Up).
- `DeviceClasses` GUID list snapshotted to `t5_work\t5_dc_before.txt` for the post-load diff.
- No `vpnva*`/`t5_*` service keys; no `C:\Windows\System32\drivers\vpnva64-6.sys`; no `ROOT\T5VPNVA*` leftovers; no `vpnva` rows in `driverquery /v`.
- `netsh i i show all` saved to guest (`t5_netsh_before.txt`, lost with the VM): 0 "Cisco AnyConnect" mentions.

### 1.2 Copy + hash (evidence `t5_load.txt`)

```
host  vpnva64-6.sys  --CopyFileFromHostToGuest-->  C:\Users\vmdebug\Desktop\t5_work\vpnva64-6.sys
guest staging SHA256: 506AB485...792  == audited digest  -> MATCH
System32\drivers\vpnva64-6.sys absent pre-copy; copy -> SHA256 re-verified MATCH
```

### 1.3 Service (evidence `t5_load.txt`) — SUCCESS

```
sc create t5_vpnva type= kernel start= demand binPath= C:\Windows\System32\drivers\vpnva64-6.sys   -> [SC] CreateService SUCCESS
sc start  t5_vpnva   -> STATE 4 RUNNING, WIN32_EXIT_CODE 0, SERVICE_EXIT_CODE 0, PID 0
driverquery /v: "t5_vpnva ... Running ... \??\C:\Windows\System32\drivers\vpnva64-6.sys"
```

`DriverEntry` (static `0x14000e000`) ran benignly — later also **directly observed in the kernel debugger** (§4, breakpoint at `vpnva64_6+0xe000` hit from `nt!PnpCallDriverEntry`).

## 2. Devnode & miniport instantiation — five attempts, all blocked

The control device `\Device\VPNVA` is registered by the driver **only from `MiniportInitializeEx`** (static §2: `MiniportInitializeEx` → `FUN_140004854` → `NdisRegisterDeviceEx`, exactly once, refcount-guarded), so instantiating the miniport is a hard prerequisite for every claim below. The proven t1/t3 root-devnode recipe was applied first and then escalated through a genuine-INF deployment. **All attempts failed to produce a miniport; the VM survived every attempt (no BSOD).**

| # | Attempt | Command path | Result | Evidence |
|---|---|---|---|---|
| 1 | Bare root devnode, Net class (t1/t3 recipe, order: create → seed → restart) | `CM_Create_DevNodeW("ROOT\T5VPNVA\0000", HTREE\ROOT\0, flags=0)` → `CR=0x0`; seed `ConfigFlags=0`, `Class=Net`, `{4d36e972-…}`, `DeviceDesc="t5 Cisco VPN VA"`, `HardwareID=ROOT\T5VPNVA`, `Service=t5_vpnva`; `pnputil /restart-device` → "Device restarted successfully" | devnode **problem=0x1F (31)** `CM_PROB_FAILED_ADD`, **ProblemStatus=0xC0000034** (`STATUS_OBJECT_NAME_NOT_FOUND`); no `\Device\VPNVA` (0/334 entries), `\\.\VPNVA` → ERROR_FILE_NOT_FOUND(2) | `t5_mkdev.txt`, `t5_diag.txt` |
| 2 | System-class variant | same recipe, `ROOT\T5VPNVA2\0000`, `Class=System`, `{4d36e97d-…}` | identical: problem=31, status=0xC0000034; no `\Device\VPNVA` | `t5_mkdev.txt` |
| 3 | Real Cisco INF package staged in guest; devnode matched to it | `pnputil /add-driver vpnva-6.inf /install` → published as **oem9.inf** (WHQL, Cisco Systems, class Net); devnode `ROOT\VPNVA\0000` created (`CR=0x0`), seeded `HardwareID=VPNVA`, `/restart-device` | devnode problem **1** (`NOT_CONFIGURED`), event 430 "requires further installation" — `/restart-device` on a hand-made devnode does not run a driver install | `t5_inf.txt` (incl. the seed-skip scripting bug, corrected in `t5_inf2.ps1`) |
| 4 | Full INF install of the matched devnode | `UpdateDriverForPlugAndPlayDevicesW("VPNVA", vpnva-6.inf, INSTALLFLAG_FORCE)` → **ok=True**, event 400 "was configured" (rank 0xFF0000); created service `vpnva` + full driver key | device stuck **pending start: problem 0x38 (56) `CM_PROB_NEED_CLASS_CONFIG`, status 0xC0000001** — the Net class-config (netcfg) pass never completed; drvinst waited 2×~3.75 min then gave up; no `\Device\VPNVA`, no `Control\Network` connection entry | `t5_inf4.txt`, `t5_setupapi_tail.txt` (authoritative install log) |
| 5 | Class-config enablers + cycles | started demand-start services **NetSetupSvc + netman**; `ConfigFlags` FAILEDINSTALL bit cleared; `/restart-device`, `/disable-device`+`/enable-device`, `/scan-devices` | class-config gate cleared → device attempts a real start → **problem=31 `CM_PROB_FAILED_ADD`, ProblemStatus=0xC0000001 (`STATUS_UNSUCCESSFUL`)**, reproduced across every cycle; service `vpnva` STOPPED (exit 1077 = never started) | `t5_inf7.txt`, `t5_inf8.txt` |

**Failure evolution decoded:** 0xC0000034 (attempt 1–2, no driver key — `NdisMAddDevice` opens the device's driver key) → `CM_PROB_NEED_CLASS_CONFIG` (attempt 4, netcfg pass missing/stalled) → **31 / STATUS_UNSUCCESSFUL** (attempt 5, the genuine driver-level AddDevice failure).

**Host-side context (for the deployment picture):** on the machine the binary was collected from, the real Cisco deployment exists as devnode `ROOT\NET\0000` (hardware ID `VPNVA`, INF `oem50.inf`, driver key `{4d36e972…}\0013` with `*IfType=6`, `*MediaType=0`, `*PhysicalMediaType=0`, `Ndi\Service=vpnva`, `Ndi\Interfaces{UpperRange=ndis5,LowerRange=ethernet}`, `ComponentId=VPNVA`, `NetCfgInstanceId={07C5177F-…}`, `NetLuidIndex=32773`) — currently **CM_PROB_DISABLED** on that host.

## 3. Surface observation (evidence `t5_mkdev.txt`, `t5_inf4.txt`, `t5_inf7.txt`, `t5_inf8.txt`)

Consistently at every attempt, across both deployment styles:

- `\Device` directory: **0 objects matching "VPNVA"** (334–335 entries enumerated); `\GLOBAL??`: 0 matches → no `\DosDevices\VPNVA` symlink either.
- `CreateFileW(\\.\VPNVA, GENERIC_READ|GENERIC_WRITE)` → **ERROR_FILE_NOT_FOUND (2)** every time.
- No new network adapter (`Get-NetAdapter -IncludeHidden` unchanged, 12–13 adapters, none Cisco/VPN); no `netsh` change.
- **No new DeviceClasses GUID** (delta vs `t5_dc_before.txt` = none) — consistent with the static audit: the driver registers a *named device object*, not a device *interface*; no interface GUID exists to enumerate.
- No NDIS/driver error events in the System log (only SCM service-install events id=7045/20003).
- The failed devnode persists with `DN_HAS_PROBLEM` + `CM_PROB_FAILED_ADD`; service `vpnva` created but never started.

## 4. Kernel-debugger observation (read-only; KDNET) — the decisive init-chain evidence

Because the AddDevice failure is ndis.sys-internal, a kernel debugger (guest pre-enabled: `debug=Yes`, `debugtype=NET`, hostip=192.168.121.1, port=50001) was attached read-only to watch the retry loop live (transcript preserved: `t5_kd_transcript.log`).

| Observation | Detail |
|---|---|
| Module name | **`vpnva64_6`** (underscore) — loaded at `fffff801`13ae0000` during observation; note `vpnva64-6+0x…` expressions fail to parse (dash = subtraction) |
| **PnP retry loop** | **7 prior load/unload cycles** of `vpnva64-6.sys` visible in the unloaded-module list — the pending-install worker retried the failing AddDevice repeatedly (load → DriverEntry → AddDevice fail → unload) |
| `DriverEntry` executed | Breakpoint `vpnva64_6+0xe000` **hit** at 21:14:50 UTC-4; stack `nt!PnpCallDriverEntry ← nt!IopLoadDriver ← nt!PipCallDriverAddDeviceQueryRoutine ← nt!PipCallDriverAddDevice ← nt!PiRestartDevice ← nt!PnpDeviceActionWorker` |
| `MiniportInitializeEx` (`+0xcc80`) | **NEVER hit** — for NDIS 6.x, init runs at device *START*; the start never proceeds past AddDevice, so the driver's own init code (and everything it contains, including the audit-documented `NdisRegisterDeviceEx` call at `+0x4a3d` and the uninitialized-attributes bug) **was never reached** |
| Conclusion | The AddDevice failure (`0xC0000001`) occurs **upstream of the driver's audited init path** — inside ndis.sys's `NdisMAddDevice` / the PnP start machinery. The static audit's init-bug claims were not dynamically exercised because init never ran. |

## 5. Open tests — NOT EXECUTABLE (no device object exists)

`\\.\VPNVA` returned `ERROR_FILE_NOT_FOUND` at every probe, from both the admin full token and (by extension of the same missing object) any restricted token. The planned access matrix (`GENERIC_READ|WRITE`, `R`, `W`, `MAXIMUM_ALLOWED`, `0`) and the security-descriptor dump (`NtQuerySecurityObject` → SDDL, to verify the static "no explicit SD, OS default DACL" claim) were fully built (`t5_poc.cs`: `open`, `sd`) but had **no target**. **The static no-authz claim therefore remains dynamically unverified — nothing in the run contradicts it, but no handle was ever obtained.**

## 6. IOCTL reachability — NOT EXECUTABLE (no handle)

The battery was fully built and staged (`t5_poc.cs` `session` subcommand, run through `t5_ioctl.ps1` with adapter-statistics snapshots before/after and restricted-token (`runas /trustlevel:0x20000`) repetition):

- Planned safe sequence: `0x22201C` (24-B query, incl. undersized-buffer failure probe) → `0x222004 {8,8}` + out-of-range failure probe → `0x222030` (8-B link-speed + media indication) → **`0x22200A` MDL-map with a 0x8000-B user ring** (≥ the `count*0x800` descriptor span for count=8; a pre-config gate probe first, expecting failure per audit) → `0x222027` pump trigger (METHOD_NEITHER, NULL buffers) → park resolution via bounded waits + targeted `CancelIoEx` (audit-documented cancel path) → `0x222010/18/80/84` state codes → `0x22200C` cleanup → post-state query.
- **Skipped deliberately** (documented, per the audit): `0x222023` (parks IRP; completion writes to a user pointer with unknown length enforcement), `0x22202B` (timer semantics undocumented), `0x22202F` (parks IRP with **no cancel routine** — static hang risk). No oversized buffers anywhere; every async call bounded-wait + cancel; nothing left pending.

**None of it executed: the MDL→system-VA mapping claim, the timer-pump→`NdisMIndicateReceiveNetBufferLists` behavior, and the FILE_ANY_ACCESS/no-authz acceptance remain statically-claimed, dynamically untested in this run.**

## 7. VM event disclosure (for the orchestrator record)

- **No power/snapshot/reboot op was executed by this agent.** No `vmrun stop/reset/suspend/snapshot/revertToSnapshot` calls were ever issued; no guest reboot was triggered.
- Timeline (kd transcript timestamps, UTC-4): kd attach 21:00:33 (clean `int3` break-in, system idle); several frozen-window inspections (each ≤ a few minutes, always resumed); `sxe ld` break-ins at 21:02/21:07/21:12/21:14; DriverEntry bp hit 21:14:50; resumed 21:14:51; idle-break inspections 21:15:28; disassembly reads 21:18:23–21:19:57; **last successful kd command ~21:20:10**; subsequently the target stopped responding to CTRL+BREAK (MCP: "may be wedged below the debugger's reach"), `vmrun checkToolsState` degraded to `installed` (tools service not running), and by ~21:29 `vmrun list` reported **0 running VMs** — the VM exited host-side during the pending-install retry loop with breakpoints armed.
- Root cause not determinable from the agent's side (guest-side kernel wedge with debugger unreachable → hypervisor-level exit, or an external/orchestrator-side action — indistinguishable from here). Per the standing instructions the VM was **not** powered back on by this agent. The kd transcript (hash `F774E91B4097EA9C2DC96CABB3E437F62AC8213A77D9C6DA53E582668E716D54`) preserves the full debugger-side record.

## 8. Claim-by-claim verdict table

| # | Static claim (vpnva.md §) | Verdict | Dynamic basis |
|---|---|---|---|
| 1 | Driver loads as a kernel service; `DriverEntry` benign (§2) | **CONFIRMED** | `t5_load.txt`: create+start OK (RUNNING, exit 0); kd: `DriverEntry` bp hit (§4) |
| 2 | Control device `\Device\VPNVA` + `\DosDevices\VPNVA` registered exactly once from `MiniportInitializeEx` → `NdisRegisterDeviceEx` (§2) | **NOT TESTED** | `MiniportInitializeEx` never ran: AddDevice failed upstream (CM_PROB 31 / 0xC0000001); no `\Device\VPNVA` at any point (§2–4) |
| 3 | Uninitialized attributes dword passed to `NdisRegisterDeviceEx` (§2 "Bug") | **NOT TESTED** | The call site (`vpnva64_6+0x4a3d`, inside init) was never reached; the observed init failure is upstream of it (§4) |
| 4 | No driver-enforced access control; all 14 IOCTLs `FILE_ANY_ACCESS` (§4) | **NOT TESTED** | No device object → no open → no IOCTL dispatchable (admin or restricted token) (§5–6) |
| 5 | `0x22200A` maps caller MDL into system VA (`MmMapLockedPagesSpecifyCache`, park at ctx+0x48) (§3.1) — **primary objective** | **NOT TESTED** | Same open gate; battery fully built, never dispatched (§6) |
| 6 | Receive-pump timer drains mapped user bytes into `NdisMIndicateReceiveNetBufferLists` (§3.1/§5.1) | **NOT TESTED** | Requires 0x22200A + 0x222027; unreachable (§6) |
| 7 | Exposure "high if `\Device\VPNVA` openable by any process"; gated only by OS default DACL (§6) | **PARTIAL** | The surface did not materialize in the test VM at all, so the OS-default-DACL gate could not be measured; the load itself is user-mode reproducible (service + devnode + INF install all succeed from an admin session) — the exposure statement's *premise* (an instantiated miniport) failed here (§2, §9) |
| 8 | Memory-write verdict scale context (round-2 directive): potential primitive = stale-mapping race (§5.1) | **NOT TESTED** | Requires the working miniport; phase-B ladder staged instead (§10) |

## 9. Deployment-gate findings (the decisive dynamic result)

1. **Three-layer instantiation gate**, each layer independently evidenced:
   - *Layer A — driver key:* a bare root devnode (the proven t1/t3 KMDF recipe) is **insufficient for an NDIS miniport**: `NdisMAddDevice` opens the device's driver key and fails with `0xC0000034` when it does not exist.
   - *Layer B — class config:* the Net class needs the network class-config (netcfg) pass; without `NetSetupSvc` (stopped in this VM) the device parks at `CM_PROB_NEED_CLASS_CONFIG` (56) and never starts, even with a complete INF install.
   - *Layer C — the miniport itself:* with the genuine Cisco INF installed, driver key present, services running, and the device healthy (problem=0), **every start attempt still fails at AddDevice with `STATUS_UNSUCCESSFUL`** — reproduced across restart/disable-enable/scan cycles, and observed live in the kernel debugger as a load→DriverEntry→fail→unload retry loop (7+ cycles).
2. **Consequence for every claim in the static report:** the entire user-mode surface (`\Device\VPNVA` open, `FILE_ANY_ACCESS` IOCTL plane, MDL→system-VA mapping, receive pump) is **gated behind a miniport instantiation that did not succeed on this Win10 19045 VM as tested**. This is a *reachability* result, not an access-control result: had the miniport instantiated, nothing in the run suggests any authz would have existed.
3. **Why this matters for the overall risk picture:** on this VM the driver is inert from user mode (service loads, no surface). The static HIGH-ish exposure claim remains conditional on an environment where the miniport instantiates — e.g., the genuine Cisco AnyConnect install path on a normal desktop session (the host's own deployment shows such an install existed, currently disabled), or whatever configuration satisfies `NdisMAddDevice`. Next-step recommendations: (a) run the genuine Cisco installer in the VM (interactive session, full network stack) and re-probe; (b) with ndis symbols available, kernel-debug the AddDevice failure to identify which internal step returns 0xC0000001.

## 10. Phase-B statement

`vpnva.md` documents one corruption-capable lifetime path (§5.1: parked IRP + **stale mapping lifetimes** between the `0x22200A` cancel teardown and the receive pump). Per the phase-A directive the ladder was **staged, never executed**:

- Staged: `t5_phaseB.ps1` (per-step runner, B0-safety-gate-first, one vmrun invocation per step, immediate evidence pull) + `t5_phaseB.cs` (race PoC, pre-flush logging; **host-compile-verified**, exit 0) + `t5_phaseB_staging.txt` (staging record with execution conditions).
- Steps: **B0** (safe gate: device present + open + `0x22201C` + `0x222004 {8,8}`) → **B1** (5× park→pump→immediate-cancel race) → **B2** (free-while-mapped: unpin + GC + 64 MB pressure → second pump) → **B3** (30-cycle soak).
- Execution is **orchestrator-gated and blocked on the same deployment gate as phase A**: without a working miniport, B0 aborts and the ladder is meaningless. It must also run SOLO (a successful race bugchecks the VM).

## 11. Cleanup statement

**Cleanup was NOT performed — the VM exited mid-Phase-A before the cleanup step.** Per the standing instructions this agent did not power the VM back on; the state below will be resolved by the orchestrator's snapshot restore. Orphaned guest state at VM exit (all under the t5 namespace; `t1_*`–`t4_*` untouched throughout):

- Service `vpnva` (created by the oem9.inf install; stopped) + service `t5_vpnva` (stopped) — both to delete.
- Devnode `ROOT\VPNVA\0000` (CM_PROB 31) + its enum key + driver key `Control\Class\{4d36e972…}\0010` (hand-built, then extended by the INF install) — to remove.
- Driver package `oem9.inf` in the guest DriverStore (`/delete-driver oem9.inf /uninstall`).
- `C:\Windows\System32\drivers\vpnva64-6.sys` (hash-verified audited copy) — to delete (no `.t5bak` was created; the file did not pre-exist).
- Demand-start services `NetSetupSvc`/`netman` were started by this agent (normally running on a real host) — harmless, self-managed by Windows.
- `C:\Users\vmdebug\Desktop\t5_work\` (scripts, PoC source/binary, evidence copies) — keep or delete per orchestrator policy.
- Host side: all evidence retained in `audits\dynamic_evidence\` (§12); `t5_poc.exe`/staging copies exist only there.

## 12. Evidence inventory (host, `audits\dynamic_evidence\`)

| File | Content |
|---|---|
| `t5_baseline.txt` | pre-load device/registry/service/network baseline (clean) |
| `t5_load.txt` | staging+deploy hash verification, `sc create/start`, driverquery, PoC compile |
| `t5_mkdev.txt` | attempts 1–2 (T5VPNVA Net / T5VPNVA2 System), CM_PROB 31/0xC0000034, no surface |
| `t5_diag.txt` | devnode properties (ProblemCode 31, ProblemStatus 0xC0000034), pnputil enum (`CM_PROB_FAILED_ADD`), service states |
| `t5_inf.txt` | attempt 3: package add (oem9.inf, WHQL), devnode NOT_CONFIGURED; includes the seed-skip scripting bug + fix |
| `t5_inf4.txt` | attempt 4: `UpdateDriverForPlugAndPlayDevicesW` ok=True, event 400 configured, CM_PROB 56 NEED_CLASS_CONFIG, `vpnva` service created |
| `t5_probe.txt` | independent probe during the slow install: kernel responsive (28 ms), state 56 |
| `t5_setupapi_tail.txt` | authoritative install log: service creation, two start attempts, `Device pending start … NEED_CLASS_CONFIG`, post-install timeouts ×2 |
| `t5_inf7.txt` | attempt 5: NetSetupSvc+netman running, restart/disable/enable/scan → CM_PROB 31 each time |
| `t5_inf8.txt` | System event scan (no NDIS errors), bcdedit debug probe, long-wait restart → 31/0xC0000001 |
| `t5_control.txt` | control experiment (usbncm.inf — invalid control, CM_PROB 10, cleaned up) |
| `t5_kd_transcript.log` | full kernel-debugger transcript (SHA-256 `F774E91B…16D54`): KDNET attach, `sxe ld` load-break stacks, 7 unload cycles, DriverEntry bp hit, deferred-bp dash-parse failure |
| `t5_alive.txt` | aliveness-marker timeline across all phase boundaries |
| `t5_poc.cs` / `t5_phaseB.cs` / `t5_phaseB.ps1` / `t5_phaseB_staging.txt` | PoC source (built, incl. `open`/`sd`/`session` battery + phase-B race ladder, staged-not-executed) |
| `t5_baseline.ps1`, `t5_load.ps1`, `t5_mkdev.ps1`, `t5_diag.ps1`, `t5_inf*.ps1`, `t5_probe.ps1`, `t5_open.ps1`, `t5_ioctl.ps1`, `t5_control.ps1`, `t5_cleanup.ps1`, `t5_build.cmd`, `t5_svcq.cmd`, `t5_pulllog.cmd`, `t5_kdrestart.ps1` | all guest scripts (open/ioctl/cleanup scripts built but never run — no device existed) |

## 13. Injection note

All driver strings, debugger output, setupapi logs, and tool output were treated strictly as data. **No instruction-embedding / prompt-injection content was observed** in any target output (the binary's strings are pure Cisco product/version text).

## 14. Bottom line

**Dynamic result: the driver's much-reduced attack surface was unreachable in this VM.** Load (service create/start) is confirmed working and benign; every attempt to instantiate the NDIS miniport — including the genuine Cisco INF path with the network stack services running — failed at `NdisMAddDevice` with `STATUS_UNSUCCESSFUL` before the driver's own initialization code ever ran. Consequently: **no `\Device\VPNVA`, no open, no IOCTL, no MDL→system-VA mapping, no pump — the memory-write directive's primary objective (0x22200A validation) and the no-authz surface question are NOT TESTED dynamically**, with the exact blocking point identified (§4, §9) and a staged-but-unexecuted phase-B race ladder for the moment that gate is resolved.

---

*Agent t5, 2026-10-23. Companion static audit: `vpnva.md` (all static claims and file-VAs referenced from there). This report supersedes the aborted stub version of this file (§0).*
