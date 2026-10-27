# Dynamic Validation - iaStorV.sys (t10_* run, batch 2)

| | |
|---|---|
| **Date** | 2026-10-24 (guest-local, UTC-07:00; host 2026-10-24) |
| **Guest** | Windows 10 x64 19045 (EFI), testsigning=Yes, HVCI/VBS off, user `vmdebug` (admin, EnableLUA=0), snapshot `pre-driver-tests` restored by orchestrator immediately before this session (guest pristine) |
| **Target file** | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaStorV.sys` - SHA-256 `30BEE94794953E2DBF0FC5AFCE0566F335AF022E89819DE145329E7C09C636BD`, Intel 8.6.2.1019, 412,176 B (audit record matches) |
| **Method** | `vmrun runProgramInGuest` -> PowerShell `-EncodedCommand`/`-File` scripts (cmd.exe broken in-guest); host-compiled C# PoC (`t10_poc.exe`, Framework64 v4.0.30319 csc) pushed + SHA-verified in-guest; raw-NTSTATUS probes via `ntdll!NtDeviceIoControlFile`; kernel object-directory walks (`NtQueryDirectoryObject` batch + raw-string extraction); CM devnode recipe (`CM_Create_DevNodeW` + enum-key seed + `pnputil /restart-device`); SCM ops via `sc.exe`; host-side kd attempt over NET |
| **Outcome** | **Load OK, surface UNDELIVERABLE.** Service `t10_iastrv` (isolated t10 namespace) created + STARTED successfully (STATE 4 RUNNING, Win32 exit 0, no 7000/7026 events). After DriverEntry-only load: **zero** target device objects/symlinks. The PnP AddDevice plane (the only device-creation path in the binary) is **not reachable in this guest**: a seeded `ROOT\T10IAST\0000` devnode restart is refused by the install pipeline with **CM_PROB_FAILED_INSTALL (28) / STATUS_PNP_NO_COMPAT_DRIVERS (0xC0000490)** (no INF; t2/t5 precedent: testsigning does not relax package-signature enforcement). Zero device objects => the shaped 0x4D014/0x4D004/0x4D008/0x41018 batteries and the structured sweeps had **no dispatch target and were not executed** (per runbook negative-finding path). kd dispatch watch: BLOCKED (target never connected). Zero BSODs; guest responsive throughout. One **orphaned running driver instance** remains (documented below) and is resolved by the orchestrator's canonical revert. |
| **Coverage gained** | Static audit open item #1 (MajorFunction table) **CLOSED statically** this session via local Ghidra headless (see section 1); open items #2 (MinorFunction-1 producers), #3 (`FUN_0005f908`), and the IO_STACK_LAYOUT field offsets re-confirmed in fresh decompilation. The `MinorFunction == 1` gate stands as the in-file answer; dynamic confirmation was **attempted and blocked by deliverability** (no device to open) - verdict remains conditional on exactly the static audit's terms, now with an empirical deliverability bound for this environment. |

Evidence files: `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\dynamic_evidence\t10_*` (this run's set: t10_static_assist.txt, t10_decomp_full.txt, t10_strings.txt, t10_T10Routing.java, t10_verify.txt, t10_hashcheck.txt, t10_load.txt, t10_discover.txt, t10_probe.txt, t10_devnode.txt [absent - see section 4], t10_dn_create.txt, t10_dn_seed.txt, t10_dn_status.txt, t10_dn2.txt [absent - see section 4], t10_dn2chk.txt, t10_dn3.txt, t10_restart2.txt, t10_state.txt, t10_poll1.txt, t10_setupapi_iastrv.txt, t10_nettest.txt, t10_ipconfig.txt, t10_dbgsettings.txt, t10_cleanup.txt, t10_cleanup2.txt, t10_cleanup3.txt, t10_alive_guest.txt, t10_host_smoke.txt). Guest artifacts: `C:\Users\vmdebug\Desktop\t10_work\` retained (logs + staged marker + scripts); Stage: `_vm_batch2\t10_iastorv\stage\` + `MISSION.md`.

---

## 0. Ground-truth drift disclosure (read before trusting anything)

1. **Binary drift: NONE (strongest ground truth of any run so far).** The guest's own inbox copy `C:\Windows\System32\drivers\iaStorV.sys` (412,176 B, Ver 8.6.2.1019, service `iaStorV` Stopped/Manual, never touched) hashes **identical** to the host-audited binary (`30BEE947...36BD`). The pushed copy was hash-verified in-guest before load. Every static claim transfers verbatim to the guest binary.
2. **Address-space drift (static tooling):** the static audit's "image base 0x140000000 / VA 0x14005c084" numbers are REA label-space. The file's true PE preferred ImageBase is **0x00010000**; the dispatch's **true file-RVA is 0x4c084** (Ghidra label `FUN_0005c084` @ 0005c084 = REA's number; file RVA = label - 0x10000). kd breakpoints must use `iaStorV+0x4c084` (module-relative), not the audit's derived RVA. All audit FUN addresses map as `trueRVA = label - 0x10000`.
3. **Harness drift:** this vmrun build has no `checkGuestState`; credentialed RPC only. `runProgramInGuest` waits for the **whole process tree** (job semantics) - a guest command whose child (e.g. `pnputil`) never returns wedges the channel (three launch-level hangs occurred, all attributable to this; guest stayed responsive).

## 1. Static assist (host, Ghidra 12.1.4 headless - closes static open item #1)

**MajorFunction routing (decisive):** init `FUN_00066228` (reached from PE entry file-RVA `0x11A008` -> `FUN_00012098` "Intel Storage Driver Ver" -> registry-config read `FUN_00011008` -> `FUN_00066228(DriverObject, RegistryPath, initData, &st)`) stamps:

| Slot | Major (wdm.h 26100.0) | Handler | Note |
|---|---|---|---|
| +0x70 / +0x80 | 0x00 IRP_MJ_CREATE / 0x02 IRP_MJ_CLOSE | `FUN_0006325c` | no in-file access-mask check; open policy = device DACL only |
| **+0xE0** | **0x0E IRP_MJ_DEVICE_CONTROL** | **`FUN_0005c084`** | **user IOCTL plane** (all audited codes) |
| +0xE8 | 0x0F IRP_MJ_INTERNAL_DEVICE_CONTROL (= IRP_MJ_SCSI) | `FUN_0005b848` | kernel SRB plane; never calls the pass-through handlers |
| +0x120 / +0x128 / +0x148 | 0x16 POWER / 0x17 SYSTEM_CONTROL / 0x1B PNP | `FUN_0005494c` / `FUN_000548f8` / `FUN_00058404` | |
| +0x68 Unload / DRExt+8 AddDevice | | `FUN_00062788` / `FUN_00057868` | AddDevice: `wcsstr` PCI\VEN_8086 -> Intel(`FUN_00057938`) / non-Intel(`FUN_00057c64`) |

- READ/WRITE/FLUSH etc. slots unset (NULL -> I/O-manager `STATUS_INVALID_DEVICE_REQUEST`). **User `DeviceIoControl` reaches `FUN_0005c084`** - the audit's conditional reach is real.
- **No MinorFunction re-stamp:** full-decomp grep (all ~1,300 functions, `t10_decomp_full.txt`) found no store of `0x01` to an IO_STACK_LOCATION MinorFunction; `FUN_0005e300`/`FUN_0005dcf0` gate the ORIGINAL user SL (`*(char*)(SL+1) != 1 -> 0xC000000D`). User-issued MJ_DEVICE_CONTROL IRPs carry MinorFunction 0.
- **x64 IO_STACK_LOCATION offsets re-confirmed** against WDK 10.0.26100 wdm.h (`POINTER_ALIGNMENT`): OutBufLen +0x08, InBufLen +0x10, IoControlCode +0x18, MinorFunction +0x01 - matches every dispatch/handler read.
- **0x4D014 sense zero-fill defect re-confirmed** in `FUN_0005e300` decomp: sense pointer = `SystemBuffer + SenseInfoOffset(ULONG @+0x20)`, lower bound only (>= 0x38), `memset(sensePtr, 0, SenseInfoLength(byte @+7))` - no upper bound; `IoStatus.Information = 0x38 + SenseInfoLength`. Prerequisites: struct Length >= 0x38 (native; 0x2C WOW64), InBufLen >= 0x38, OutBufLen >= 0x38+Sil, CdbLength != 0, DTL <= devext+0xecc.
- **0x4D004 data zero-fill defect re-confirmed** in `FUN_0005dcf0` decomp: `SRB.DataBuffer = SystemBuffer + DataBufferOffset(ULONG_PTR @+0x18)`; the wrap-capable check (`OutBufLen < DTL + DataBufferOffset`, 64-bit) applies ONLY when DataIn(byte @+8) == 1 && DTL != 0; the memset fires at build time when `devext+0xf48 == 2` && CDB[0] == 0x28.
- **`FUN_0005f908` (open item #3) partially resolved:** a CDB-opcode-driven response-size adjuster (opcodes 0x03/0x12/0x1A/0x35/0x4A paths; caps 0x18/0x10/0x12, returns 4 on length rejects) - a semantic helper, not a security gate; called only by `FUN_0005dcf0`.
- **0x4D008 (SCSI_MINIPORT, `FUN_0005d198`): NO MinorFunction gate.** Requires InLen >= 0x1C, SystemBuffer != NULL, OutBufLen >= HeaderLength+0x1C, signature at SystemBuffer+4: `IntelMpd` (any state) or `IntelATA`/`PIIXIDE` (FDO state 3); then switches on ControlCode (@+0x10).
- **Device/interface facts:** `\Device\Ide` directory object created via `ZwCreateDirectoryObject` on the Intel path only; devices via single `IoCreateDevice` call site (`0x5830e`, `FUN_000582a8`, Exclusive=FALSE, no SDDL; `IoCreateDeviceSecure` NOT imported - the audit's second xref `0x6a2e0` is the IAT, not a call site). Symlinks (`FUN_00057e34`): `\DosDevices\Scsi%d:` (collision-retried) + `\Device\ScsiPort%d` (single try - collides with the guest's pre-existing system ScsiPort0..3). `IoRegisterDeviceInterface` (single site `0x57c49`, Intel path only) = **DiskClassGuid `{2ACCFE60-C130-11D2-B082-00A0C91EFB8B}`**. AddDevice teardown path: forwarded request `0xC350200c` (`FUN_00058200`) decides persistence; on failure BOTH symlinks are deleted AND the device deleted.

## 2. Load (exact outcomes)

| Step | Result |
|---|---|
| Push + verify | All staged files SHA-verified in-guest (`t10_verify.txt`, `t10_hashcheck.txt`); PoC final build SHA `2CE09251EC5EC587BD4A797153911E94EB6B5B0DF9BC3149113E864336E52924`; inbox copy identical to audited binary (drift=none) |
| `sc create t10_iastrv type= kernel start= demand binPath= C:\Users\vmdebug\Desktop\t10_work\iaStorV.sys` | `[SC] CreateService SUCCESS` (exit 0) |
| `sc start t10_iastrv` | **STATE 4 RUNNING**, WIN32_EXIT_CODE 0, exit 0 - **DriverEntry SUCCEEDED** (init chain ran; table + system thread + `HKLM ...Scsi` key created) |
| driverquery | `t10_iastrv` Kernel Manual **Running** OK (binPath `\??\C:\Users\vmdebug\Desktop\t10_work\iaStorV.sys`); pre-existing guest rows `iaStorV` (Stopped, own inbox service) + `iaStorAVC` (Stopped) untouched |
| Events 7000/7026 (10 min window) | NONE (clean start) |

## 3. Discovery (surface found: NONE - negative finding complete)

`qobj \Device` (batch scan, `t10_discover.txt`): entries = `Video0..8`, **`Ide`** (directory - pre-existing), **`ScsiPort0`..`ScsiPort3`** (pre-existing system objects, present before/without my service's involvement; NOT target-created - the binary creates no devices outside AddDevice). **No `iaStorN`, no `IAAStorageDevice-N`.**
`\Device\Ide` directory query -> **0xC0000022** (DACL-denied even as admin - same class as t7's `\GLOBAL??` note). `\DosDevices` scan -> no iaStor/Scsi/IAA matches (3 scan attempts; first two crashed on a PoC parser bug - see section 5 - then fixed; final scan completed clean).
Open-probe corroboration (`t10_probe.txt`): uniform **0xC0000022** on zero-access opens for `\Device\Ide\iaStor0/1`, `\Device\ScsiPort4`, `\Device\Ide\IAAStorageDevice-0`, `\??\Scsi0:`/`Scsi1:` - uniform ACCESS_DENIED (policy-level, not name-level; not existence-informative), consistent with the DACL-locked `\Device\Ide` plane and admin-gated legacy SCSI ports.
**Conclusion: DriverEntry-only load produces no IOCTL surface. All IOCTL batteries/sweeps conditional steps skipped per runbook (negative-finding route).**

## 4. AddDevice attempt via devnode recipe (t6 recipe; per-step record)

| Step | Result |
|---|---|
| `CM_Create_DevNodeW('ROOT\T10IAST\0000', parent='HTREE\ROOT\0')` | CR=0, devnode status `0x1802001` problem=0 (`t10_dn_create.txt`) |
| Enum-key seed (atomic this time: mkdev->seed in one call, `t10_dn3.txt`) | Class=System `{4d36e97d-...}`, HardwareID `ROOT\T10IAST`, Service=`t10_iastrv`, ConfigFlags=0 |
| `pnputil /restart-device ROOT\T10IAST\0000` (service RUNNING at restart, verified) | **CM_PROB_FAILED_INSTALL (28), ProblemStatus 0xC0000490 = `STATUS_PNP_NO_COMPAT_DRIVERS`** (`t10_state.txt`, `t10_poll1.txt`) - PnP's INF-selection gate refuses a driverless devnode; **AddDevice never ran** (consistent with zero transient objects: post-restart `\Device` scan unchanged; `\DosDevices\ScsiN:` link absent) |
| `pnputil /remove-device` + enum-key removal (cleanup) | Device removed successfully; keys removed |
| setupapi.dev.log | No T10IAST/iaStor sections at all (same absence pattern as t7's bxvbda devnode) |
| **FUN_00058200 forwarded-0xC350200c outcome** | **NOT OBSERVED - the code path requires AddDevice, which never ran.** Static characterization stands (see section 1); the three launch-level hangs during devnode attempts were exec-tree waits, NOT observed kernel behavior - the actual 0xC350200c completion semantics remain unobserved |

Devnode-recipe attempts: 1 real execution (no-compat refusal) + 3 launch-hangs (infra). Loop-breaker: BLOCKED on this route; staged alternative below.

## 5. Batteries and sweeps (NOT DISPATCHED - no target)

Per runbook: batteries (0x4D014 sense shapes x4; 0x4D004 DataIn shapes x2; 0x4D008 x3 signatures; 0x41018; customs) and sweep bands (0x4D000-0x4D0FC, 0x41000-0x410FC, 0xC3512010-0xC351201C step 4, customs 0x2D1400/0x70000) were **conditional on an openable target device** (MISSION.md section 2 step 5-6 "If devices exist"). **Zero target device objects existed at any point -> not executed.** The decisive MinorFunction-gate dynamic confirmation therefore did NOT run; the static answer (section 1) remains the authority.

## 6. kd dispatch watch (optional step - BLOCKED, <=3 attempts honored)

| Attempt | Result |
|---|---|
| 1-2 | kd `-c` launch via Start-Process -> `E_INVALIDARG` (bad command-string handling) |
| 3 (direct, `net:port=50001,key=1.2.3.4`) | Listener established ("Using NET for debugging", UDP 50001 bound); guest `bcdedit /dbgsettings` = NET/hostip 192.168.121.1/port 50001/key 1.2.3.4/`debug Yes`; guest kdnet adapter up (`Ethernet (Kernel Debugger)`, 192.168.121.129) - **target never connected** ("no_debuggee, waiting to reconnect" >100 s) -> BLOCKED. A leftover kd.exe (pid 12936) holding UDP 50001 could not be terminated host-side (zombie); it is host-side only, no guest impact |

The MinorFunction seen at dispatch therefore remains **statically predicted only** (SL+1 == 1 required; user IRPs carry 0 -> 0xC000000D).

## 7. Safety incidents

**None.** Zero BSODs, zero guest wedges (guest process listing/IP/bcdedit all responsive throughout). No oversized inputs sent (nothing was dispatched at all). No host driver/service/device action taken. Pre-existing guest services (`vmci`, `vsock`, `b06bdrv`, `iaStorV`, `iaStorAVC`) untouched.

**PoC bug disclosures (user-mode only, no guest impact):** (1) `qobj` name parser dereferenced kernel-VA name buffers -> 0xC0000005 x2 and one unpaired-surrogate file-write failure -> fixed with pointer-range validation + ASCII sanitization + batch-mode raw-string extraction (the working final scan); (2) first load attempt failed because `iaStorV.sys` had not been staged (push-list omission, corrected); (3) three exec-channel hangs from the process-tree-wait semantics (attributed in section 0.3).

## 8. Cleanup (verified in `t10_cleanup.txt`, `t10_cleanup2.txt`, `t10_cleanup3.txt`)

- `pnputil /remove-device ROOT\T10IAST\0000` -> success; `Enum\ROOT\T10IAST` keys removed.
- `sc delete t10_iastrv` -> first `SUCCESS`, later attempts `1072` (already marked for deletion).
- `sc stop t10_iastrv` -> **BLOCKED**: 3 attempts all `1052` (`NOT_STOPPABLE`) after the PnP re-bind during the restart attempt - **ORPHANED RUNNING INSTANCE remains**: kernel image mapped from the (now deleted) `t10_work\iaStorV.sys`, **zero device objects** (driverquery shows "Disabled Running"), service record marked for deletion. **Harmless**: no IOCTL surface, no device, no dispatch path. Resolves on the orchestrator's canonical `pre-driver-tests` revert (t6 "orphaned state reverted" precedent). Disclosed, not hidden.
- Pushed files removed from t10_work: iaStorV.sys, t10_poc.exe/.cs, t10_*.ps1 (load/discover/dacl/open_unpriv/battery/sweep/cleanup/kd_dispatch) [x]; RETAINED per policy: t10_work dir, all *.txt logs, `t10_devnode.ps1`/`t10_dn2.ps1`/`t10_dn3.ps1`/`t10_probe.ps1`/`t10_trigger.ps1`/`t10_verify.ps1` (cleanup's keep-list missed the added scripts - retained intentionally, harmless ASCII scripts), `t10_phaseB_STAGED.txt` marker [x].
- Final aliveness marker written (cleanup-done).

## 9. Verdict delta vs static audit

Static: **WRITE-HIGH (conditional, ~30% coverage)** - two zero-fill sinks (0x4D014 sense 32-bit offset; 0x4D004 data 64-bit offset + wrap check), both behind the `MinorFunction == 1` gate; reach conditional on the unreviewed MajorFunction table + device ACL.

Dynamic result: **STAYS WRITE-HIGH (conditional), with the conditionals now sharpened and empirically bounded:**
- **Open item #1 (MajorFunction routing) - CLOSED (static):** `MajorFunction[0x0E] = FUN_0005c084` -> user DeviceIoControl reaches the dispatch; no re-stamping path exists in-file. The gate is the ONLY thing between a user request and the write sinks.
- **Open item #6 (device ACL/interface) - sharpened (static):** CREATE/CLOSE has NO in-file mask check; policy = device DACL alone; interface = DiskClassGuid on the Intel path only. **Dynamic resolution impossible here: no device object was ever created** (AddDevice unreachable: PnP INF-selection gate `STATUS_PNP_NO_COMPAT_DRIVERS` on driverless devnodes; no INF available; package-signature route blocked per t2/t5).
- **NEW empirical bound (this run):** the entire user-mode IOCTL plane is **undeliverable without Intel storage hardware or an INF-routed devnode** - in a hardware-less VMware guest the driver loads and idles with zero devices. The WRITE-HIGH conditional therefore hinges on a REAL Intel ATA/AHCI/RAID system (where AddDevice + the class enumeration create `iaStor%d`/`IAAStorageDevice-N` objects), OR a kernel-mode MinorFunction-1 sender (staged B0).
- Not dynamically tested (blocked): gate rejection status, DACL/unpriv-open, all shaped batteries, sweeps, kd dispatch watch.

## 10. Staged-but-not-executed escalations (summary for the orchestrator)

| ID | Gate | Content |
|---|---|---|
| `B0` KM MinorFunction-1 sender | KM build tooling (WDK + signing) - infeasible with guest csc | Build MJ_DEVICE_CONTROL + MinorFunction=1 IRP to `\Device\Ide\iaStorN`; with 0x48-byte SPTD (SenseInfoOffset 0x40, Sil 16) the sense memset writes 8 B past the buffer |
| `B1` Driver Verifier special-pool ladder | Verifier special pool on iaStorV.sys + reboot + SOLO session (orchestrator-owned) | L1 in-bounds sense fill -> L2 8-byte overrun -> L3 far-offset (0xF0) -> L4 0x4D004 in-bounds data fill -> L5 near-2^64 DataBufferOffset wrap fault |
| `B2` devext+0xf48 state forcing | KM-only (debugger state poke or hardware plane) | Arms the 0x4D004 CDB-0x28 inline zero-fill without hardware |
| INF-routed devnode | Valid INF package (driver store publish) - t2 precedent: package-signature enforcement blocks testsigning-only routes | Would make AddDevice deliverable in the guest (needs the original Intel INF + package validation) |

*End of report.*
