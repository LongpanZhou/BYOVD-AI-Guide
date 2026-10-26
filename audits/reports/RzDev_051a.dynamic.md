# DYNAMIC VALIDATION REPORT: RzDev_051a.sys (agent t2)

Date: 2026-10-23 (session started ~16:05 local, terminated 16:37 local by external VM power-off)
Guest: Windows 10 x64, EFI, testsigning=Yes, HVCI/VBS off, user `vmdebug` (admin, EnableLUA=0).
Driver under test: `RzDev_051a.sys` — SHA-256 verified at runtime:
`154902764B64D5CC08D8E37864B3B029709F7BA53A742CB4AE449417F02ECCAC` (matches static audit).
Static audit reference: `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\RzDev_051a.md`.

> **STATUS: INCOMPLETE — VALIDATION HALTED BY EXTERNAL VM POWER-OFF.**
> At 16:30:43 local (20:30:43Z) the VM was powered off by an external automation actor
> (`VMAutomationPowerOff` in `C:\Users\<scrubbed>\Downloads\Vmware\vmware.log`, `cleanShutdown="TRUE"`
> — a graceful guest shutdown, NOT a crash; no BSOD, no crash dump, no driver fault involved).
> This agent never issued any power-state command. All IOCTL/injection testing was still
> pending when the VM went down. See §7.

Evidence directory: `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\dynamic_evidence\`
Guest work dir: `C:\Users\vmdebug\Desktop\t2_work\` (prefix `t2_`, per coexistence rules; the
other agent's `t1_` namespace was never touched).

---

## 1. Setup & load chain — exact commands + results

All guest execution via `vmrun runProgramInGuest` with pushed PowerShell scripts
(`-NoProfile -ExecutionPolicy Bypass -File ...`); every result written by the guest to a file
and pulled to the host (runProgramInGuest does not capture stdout).

| Step | Command (guest side) | Result | Evidence |
|---|---|---|---|
| 1 | Pre-load snapshot: `Get-PnpDevice`, DeviceClasses GUID list, `Enum\ROOT` dump | Baseline recorded | `t2_devices_before.txt` |
| 2 | Copy `C:\Users\vmdebug\Desktop\driver_batch1\drivers\RzDev_051a.sys` → `C:\Windows\System32\drivers\RzDev_051a.sys` | Copied; src/dst hashes both `1549...CCAC` | `t2_load.txt` |
| 3 | `sc stop t2_rzdev` / `sc delete t2_rzdev` | FAILED 1060 (did not exist — clean slate confirmed) | `t2_load.txt` |
| 4 | `sc create t2_rzdev type= kernel start= demand binPath= C:\Windows\System32\drivers\RzDev_051a.sys` | `[SC] CreateService SUCCESS` | `t2_load.txt` |
| 5 | `sc start t2_rzdev` | **STATE: 4 RUNNING**, exit code 0 | `t2_load.txt` |
| 6 | `sc query` / `sc qc` / `driverquery /v /fo csv` | Service present, Running, binary path `\??\C:\Windows\System32\drivers\RzDev_051a.sys`, timestamp 3/22/2021 (authentic build) | `t2_load.txt` |
| 7 | Post-load device discovery: `Get-PnpDevice`, DeviceClasses diff, `Enum\ROOT` diff | **Nothing appeared** (see §2) | `t2_devices_after.txt` |

**Load-time finding (dynamic): the driver loads and stays resident under bare `sc start`
(DriverEntry + KMDF bind succeed), but it exposes ZERO user-reachable objects in this state.**

## 2. Device discovery after bare load — the PnP gate

Compared against the pre-load baseline (`t2_devices_before.txt`):

- `Get-PnpDevice`: no device with instance/class/name matching RAZER, RZCONTROL, RZVIRTUAL,
  RzDev, VID_1532 appeared (`t2_devices_after.txt` §1-§2 empty).
- `HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses`: **no new device-interface class keys**
  (diff shows no new GUID; no entry references RAZER/RZCONTROL/RZVIRTUAL/VID_1532).
- Kernel object-directory probe (C# via `NtQueryDirectoryObject` — `t2_probe1.cs/.exe/.txt`):
  - No object in `\Device` / `\??` matched `RZ|t2|RAZER|051A|virtual` filters (enumeration ran;
    probe's batch-loop had a residual single-entry-mode bug — the loop path is unreliable, but
    the direct-open probes below are independent and definitive).
  - Direct `CreateFile` on `\\.\RzDev_051a`, `\\.\RzDev_051a_control`, `\\.\RzControl`,
    `\\.\RZCONTROL`, `\\.\t2_rzdev` → **all ERROR 2 (not found)**.

This **dynamically confirms** the static claim that FDO/child creation lives behind
`EvtDriverDeviceAdd` (`FUN_14000c000` at WDF `+0x3a0` config), which requires a PnP devnode
bound to the service. The `FUN_1400041dc` "device bootstrap" called from vendor DriverEntry
(`FUN_14000d000`) did NOT leave any named/openable device object behind (either it did not run
its device-creation leg or it created only unnamed internals). With bare `sc start` there is
nothing for a user-mode caller to open — the attack surface is gated on driver binding to a
devnode (i.e., a real Razer device, or a synthetic devnode + driver package).

## 3. Attempts to satisfy the PnP gate (all documented)

| Attempt | Command | Result |
|---|---|---|
| A. Driver-package INF route | Pushed hand-written `t2_rzdev.inf` (Class=System {4D36E97D...}; model lines `ROOT\RZDEV051A\VID_1532&PID_0112&MI_02`, `USB\VID_1532&PID_0112&MI_02`, `ROOT\RZDEV051A`; `AddService = t2_rzdev 0x2`; capability value names `ControlDevice/DkmMouseDevice/DkmKeyDevice/MPosMouseDevice/DkmJsDevice/MouseExDevice/ConsumerControlDevice` + `Virtual_Kbd_1532`/`Virtual_Mou_1532`/`Virtual_Js_1532`/`Virtual_Con_1532` (+ `_0` fallbacks) AddReg'd into both the driver key and the HW key) → `pnputil /add-driver t2_rzdev.inf /install` | **BLOCKED by package-signature enforcement**: `Failed to add driver package: The third-party INF does not contain digital signature information.` — testsigning=Yes did NOT relax INF-package registration in this build. Evidence `t2_devnode.txt`. |
| B. Manual ROOT devnode | Created `HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\RZDEV051A\0000` with `HardwareID` (REG_MULTI_SZ, 3 IDs incl. VID_1532&PID_0112&MI_02), `Class`/`ClassGUID`, `Service=t2_rzdev`, `DeviceDesc`, `ConfigFlags=0` → `pnputil /scan-devices` | Key created, but **PnP did not ingest it live** ("Scan complete." with no device materialized; `Get-PnpDevice` still has no RZDEV051A node). Manual Enum keys are not converted into live devnodes by scan without driver-package install (attempt A failed) — consistent with known Win10 behavior. Evidence `t2_devnode.txt`. |
| C. Named control device probe | `CreateFile` sweep on candidate names (see §2) | No object exists (ERROR 2). |

**Conclusion for the gate:** with no INF/catalog path available (unsigned package refused) and
no reboot allowed by the coexistence rules (and boot-time ROOT re-enumeration being the
remaining mechanism to ingest a manual devnode), the PnP-gated device surface could not be
materialized in this session. The next viable step would have been a reboot after re-attempting
package registration with a signed catalog, or a `devcon`-style SetupDi install — **STOP: reboot
requires orchestrator approval; not performed.**

## 4. PoC design (prepared, partially run)

- `t2_probe1.exe` (host-compiled with `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`,
  pushed, executed in guest): kernel object-directory enumeration + named-device open probe.
  Executed successfully in guest; result: **no driver-created named device object exists**
  (evidence `t2_probe1.txt`).
- Full IOCTL PoC (`t2_ioctl_poc.cs` — planned, not run): open handles on RZCONTROL/RZVIRTUAL
  PDO interfaces (per static SDDL claim), exercise 0xB0003 (9-byte class descriptor),
  0xB0007 (report descriptor), 0xB0027 (0x20-byte struct), stubs 0xB000F/0xB0013/0xB001F/
  0xB0023/0xB002B/0xB0191/0xB002B (expect success when OutputBufferLength>3), default-code
  negative control (expect 0xC00001BB), then the inject chain: `0xF0203` (arm,
  `InputBufferLength > 0x10`, 32-byte well-formed input) followed by `0x220003` (completion-
  callback route), with `Cursor.Position` polling before/after to detect real synthetic input
  (the audit's `[ctx+0x580]` mouse-report pump claim). Restricted-token (non-admin) open test
  was planned to validate the `(A;;GRGWGX;;;WD)` Everyone ACE.
- **Never executed**: no device existed to open; the probe stops there.

## 5. Observed effects

- Driver load: OK, resident, no crash, no WER entries, guest stable for the ~20 minutes the
  driver was loaded (multiple script executions, one intentionally killed spinning user-mode
  probe process, no driver-related anomaly; the driver itself was never delivered any IOCTL).
- No device objects, no interfaces, no registry children, no event-log driver errors were
  produced by the loaded driver (device discovery results all empty).
- No IOCTL was ever issued to the driver (nothing to send them to).

## 6. Claim-by-claim verdict table (dynamic evidence vs static audit)

| # | Static claim (audit ref) | Verdict | Dynamic evidence / reasoning |
|---|---|---|---|
| 1 | Driver loads via `sc` (KMDF bind, WDFLDR shim, `FUN_14000d000` DriverEntry) | **CONFIRMED** | `sc start` → RUNNING, exit 0; hash-verified binary (`t2_load.txt`) |
| 2 | Device creation requires PnP devnode (AddDevice `FUN_14000c000`; FDO work `FUN_140002414`) | **CONFIRMED** | Bare load: zero devices/interfaces/named objects (`t2_devices_after.txt`, `t2_probe1.txt`) — load-time gate |
| 3 | SDDL `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)` — Everyone GR\|GW\|GX on child PDOs | **UNTESTED** | No PDO could be materialized (INF package signature block, §3) |
| 4 | Public descriptor IOCTLs 0xB0003/0xB0007/0xB0027 + stubs on PDO queues | **UNTESTED** | No PDO/device to open |
| 5 | `0xB000B` re-queue into internal queue (DEVICE ctx +0x10) | **UNTESTED** | No PDO/device to open |
| 6 | Inject chain: `0xF0203` arm (`FUN_140001f24`, `InputBufferLength>0x10`, ctx+0x448\|=2) → `0x220003` → `FUN_140003260` → `FUN_14000342c` (bit 0x8 gate) → `[ctx+0x580]` report pump | **UNTESTED** | No device to open; cursor-jump experiment never ran |
| 7 | No memory-corruption primitive; benign imports | **NOT CONTRADICTED** | No execution of IOCTL plane occurred |
| 8 | Capability registry names (ControlDevice etc.) gate children/timer/pump | **UNTESTED** | Value names were provisioned into the synthetic devnode key, but AddDevice never ran |

## 7. Incident & session state at power-off

- 16:26:11 local — last successful guest operation (probe run, evidence pulled).
- 16:30:43 local — external `VMAutomationPowerOff`, graceful (`cleanShutdown = "TRUE"`),
  `vmware.log` lines `Vix: VMAutomationPowerOff: Powering off` / `VMX exit (0)`.
- 16:31+ local — all `vmrun` calls from this agent fail with "VMware Tools are not running /
  not powered on". Polls at 16:33:39 and 16:37:05: still off, no reboot attempt logged.
- This agent issued **no** power-state, reboot, reset, suspend, or snapshot-restore command at
  any time; per the coexistence rules it did not attempt `vmrun start` either.
- Guest state at power-off (relevant if the VM is restarted WITHOUT snapshot rollback):
  - Service `t2_rzdev` exists, START_TYPE=DEMAND (will NOT auto-load at boot), was RUNNING.
  - `C:\Windows\System32\drivers\RzDev_051a.sys` copy exists.
  - Inert registry key `HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\RZDEV051A\0000` exists
    (no live CM devnode was ever created from it).
  - `C:\Users\vmdebug\Desktop\t2_work\` holds all scripts, probes, INF, and logs.
- Suggested resumption path for the orchestrator: power the VM back on, then either (a) register
  a signed driver package (self-signed cert + catalog in testsigning mode) or (b) approve ONE
  reboot so the manual `Enum\ROOT\RZDEV051A\0000` key is ingested by boot-time ROOT enumeration
  (with `Service=t2_rzdev` already set); after that, `t2_devs_after.ps1` + the prepared IOCTL
  PoC can run immediately.

## 8. Exploitability statement (current, honest state)

**What is proven so far:** the driver is loadable on demand by any local admin (standard `sc`),
stays resident, and — critically — **exposes nothing user-reachable until PnP binds it to a
devnode** (AddDevice gate dynamically confirmed). The Everyone-accessible synthetic-HID
injection surface and the `0xF0203`/`0x220003` arm/inject chain remain **statically asserted
but dynamically unverified**. In a production deployment the gate is normally satisfied by the
Razer driver package (device bound on real/dongle hardware), so the end-user exposure claimed
by the static audit remains plausible but is NOT dynamically proven by this session. The
provisioning blocker encountered in the lab (driver-package signature enforcement rejecting an
unsigned INF even with testsigning on) is itself a meaningful hardening datapoint: on this
VM the injection surface cannot be reached without either the vendor INF or a signed package.
