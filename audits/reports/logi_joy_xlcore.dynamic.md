# Dynamic Exploitability Validation - `logi_joy_xlcore.x64.sys` (t3_* run)

| | |
|---|---|
| **Companion static audit** | `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\logi_joy_xlcore.md` |
| **Binary SHA-256** | `38F5CF58E4B4B58E3C89428482A2B6570AA38D3F4ACE9CE5A1F964F3A753E488` (host source and guest `System32\drivers` copy both hash-verified in-run) |
| **Validation date** | 2026-10-23 |
| **Method** | Live-VM dynamic testing: driver loaded as kernel service + root-devnode stand-in; device interface enumerated via SetupAPI; `IRP_MJ_DEVICE_CONTROL` surface probed from user mode with bounded, audit-documented payloads. Guest: Windows 10 x64 (EFI), testsigning=Yes, HVCI/VBS off, user `vmdebug` (full admin token, EnableLUA=0). |
| **Outcome** | **Interface published and ACTIVE, but user-mode open is gated by the lower stack on the root-devnode stand-in - the IOCTL matrix could not be executed.** See section 5 verdict table: 3 CONFIRMED, 1 PARTIAL, 6 NOT TESTED (with reason), 1 static caveat resolved differently than predicted. |

Evidence files referenced below live in `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\dynamic_evidence\` (`t3_*.txt`, `t3_poc.cs`).

---

## 1. Setup & load chain (exact commands + results)

### 1.1 Service load (phase 1) - SUCCESS

Guest script `t3_step1.ps1` (evidence `t3_load.txt`):

```powershell
$src = 'C:\Users\vmdebug\Desktop\driver_batch1\drivers\logi_joy_xlcore.x64.sys'
$dst = 'C:\Windows\System32\drivers\logi_joy_xlcore.x64.sys'
Get-FileHash $src -Algorithm SHA256   # 38F5CF58... = audited digest [x]
Copy-Item -Force $src $dst            # dst hash re-verified [x]
sc.exe create t3_ljxlcore type= kernel start= demand binPath= 'C:\Windows\System32\drivers\logi_joy_xlcore.x64.sys'  # [SC] CreateService SUCCESS
sc.exe start  t3_ljxlcore             # STATE 4 RUNNING
```

- `DriverEntry` (`0x140011000`) ran without error: service `t3_ljxlcore` RUNNING, `PID 0`, exit code 0.
- Baseline: `DeviceClasses\{1abc05c0-c378-41b9-9cef-df1aba82b015}` **absent** (no devnode yet -> no `AddDevice`, matching the audit's PnP-driven interface model).

### 1.2 Devnode creation (phases 2-4) - needed three attempts; final recipe proven

Two load-chain findings worth recording (both evidence-logged):

- **Attempt A (failure):** seeding the enum key `HKLM\SYSTEM\CCS\Enum\ROOT\T3_LJXLCORE\0000` *before* `CM_Create_DevNodeW`, then calling `CM_Create_DevNodeW("ROOT\T3_LJXLCORE\0000", parent=HTREE\ROOT\0, flags=0)` -> **`CR=0x1E`** (evidence `t3_poc_mkdev.txt`, `t3_devnode2.txt`); `pnputil /restart-device` refused: *"The device instance does not exist in the hardware tree."* The t1-proven order (create devnode **first**, seed **after**) is mandatory; a pre-existing registered-but-uninstalled enum entry blocks the create.
- **Attempt B (success, evidence `t3_poc_sweep.txt` / `t3_sweep.txt`):** with no T3 enum keys present, the sweep created all three variants with `flags=0` and `CR=0`:
  - `ROOT\T3_LJXLCORE\0000` -> dn=0x2 [x]
  - `ROOT\T3_LJXLCORE\0001` -> dn=0x3 [x]
  - `ROOT\T3_LJXLCORE2\0000` -> dn=0x4 [x]
  - (`flags=4` -> `CR=0x1E`, `flags=8` -> `CR=0x10` - consistent failures; only `CM_CREATE_DEVNODE_NORMAL`+explicit instance works.)
- Enum keys auto-created by CfgMgr were then seeded (`ConfigFlags=0`, `Class=System`, `ClassGUID={4d36e97d-e325-11ce-bfc1-08002be10318}`, `DeviceDesc="t3 LogiJoy XLCore Filter"`, `HardwareID=ROOT\T3_LJXLCORE`, `Service=t3_ljxlcore`) and each devnode restarted via `pnputil /restart-device` -> *"Device restarted successfully"* x3.

### 1.3 External interruption (documented for the record)

Between run phases, the VM was cleanly powered off by external VIX automation at 22:26:20Z - `vmware.log`: `VMAutomationPowerOff: Powering off`, `cleanShutdown = "TRUE"` (evidence excerpt in `t3_state2.txt` timeline). **Not driver-related**: no IOCTL had been dispatched at that point; the driver had only run `DriverEntry`. The orchestrator restarted the VM; guest state (service, files, work dir) survived. This consumed no reboots from my side - the reboot was external, and the session was resumed after the orchestrator restored the VM.

---

## 2. PoC design

Single C# PoC (`t3_poc.cs`, host copy at `dynamic_evidence\t3_poc.cs`, compiled in-guest with `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`) with subcommands: `mkdev`, `sweep`, `devstat`, `iflist`, `ifenum`, `list`, `open`, `ioctl`.

### 2.1 Static ground truth used to build inputs

| Audit item | Value used |
|---|---|
| Interface GUID | `{1ABC05C0-C378-41B9-9CEF-DF1ABA82B015}` (bytes at `0x14000c9b8`) |
| IOCTL dispatcher | `0x1400021c0`; `key = (IoControlCode >> 2) & 0xFFF` at `0x14000221b`; `0x9xx` FUNCTION family -> case keys `0x8016-0x8020` |
| 0x916 | handler `FUN_1400011d4->FUN_140002c74`, input length checked by dispatcher (unknown constant - probed 0/4/16/40 B) |
| 0x917 | handler `FUN_1400011bc->FUN_140002608->FUN_140001230`, no input |
| 0x918 | handler `FUN_140005008`x2, `InputBufferLength >= 0x28`, audit example field `input[8]==2`, capacity checks `<100`/`<0x65` |
| 0x919 | handler `FUN_140003e3c`, `InputBufferLength >= 0x28`, static `.rdata` table `0x140007300` |
| 0x91A | handler `FUN_140001828`, `OutputBufferLength >= 0xe`, writes command+value into returned SystemBuffer |
| 0x91B | handler `FUN_140001ae0`, `InputBufferLength == 12`, command branches `0x1d`->`0x30` |
| 0x91C | handler `FUN_1400053b0->FUN_140005498`, `InputBufferLength >= 0x36`, string table: 41 entries x 16 B (ptr, id, type triples) - I statically dumped the table (`0x14000C330`) and its ASCII strings (`VID_046D&PID_C202` @ `0x14000C5C0`, `..._C209`, `..._C294&REV_2x`, ...); no match -> `0xC000000D` |
| 0x91D | handler `FUN_14000537c`, `InputBufferLength >= 8` |
| 0x920 | handler `FUN_140003fa8`, `InputBufferLength >= 0x14`, commands 1/2/3/7 only |
| Encode helper | `CTL(dev,f,method,acc) = (dev<<16)|(acc<<14)|(f<<2)|method`; core tests used `dev=0x22, method=0, acc=0` (-> e.g. F916 = `0x22002458` per audit's illustrative encoding) |

### 2.2 Bounded input matrix (all buffers <= 0x36 bytes, fixed shapes)

- F916 x4 (in=0/4/16/40 B zeros) - dispatcher length-gate probe
- F917 x1 (no input) + x1 with METHOD_NEITHER encoding (buffer-less handler -> method-bit probe that cannot NULL-deref)
- F918 x2 (0x28 B with `input[8]=2`; 0x28 B all-zero)
- F919 x2 (0x28 B zeros; 0x28 B with dword[0]=0x18)
- F91A x4 (out=0x0E pre-filled 0xEE with no input; out=0x20 with in-dword cmd 1/0/3)
- F91B x3 (12 B zeros; 12 B cmd=0x1d; 12 B cmd=0x30)
- F91C x2 (0x36 B: `"Logitech"` no-match; `0x36 B`: `"VID_046D&PID_C202"` table match)
- F91D x2 (8 B zeros; 8 B idx=2)
- F920 x5 (0x14 B, cmd dword 1/2/3/7/0)
- Decode probes on F91B: `dev=0x2A`, `dev=0xFFFF`, `acc=1`, `acc=2`, `acc=3` (all METHOD_BUFFERED)
- F921 (unhandled FUNCTION -> default forwarder to lower stack)
- Handle-open matrix: `GENERIC_READ|WRITE`, `GENERIC_READ`, `GENERIC_WRITE`, `0x00100000`, `0` (zero access)

---

## 3. Observed effects + evidence

### 3.1 Load and interface publication - CONFIRMED

| Observation | Evidence |
|---|---|
| Driver loads, `DriverEntry` OK | `t3_load.txt` (STATE 4 RUNNING) |
| `AddDevice` (`0x1400058f0`) fires on devnode restart | `t3_sweep.txt`: `DeviceClasses {1ABC05C0} present: True`, instance `##?#ROOT#T3_LJXLCORE#0000#{1abc05c0-...}` |
| Interface registered **once** despite 3 devnodes (flag `DAT_14000e248` guard) | `t3_sweep.txt` + `t3_poc_list.txt`: `instances=1` after three AddDevice invocations |
| Interface ENABLED at PnP START (`IoSetDeviceInterfaceState` TRUE in `FUN_140010200`) | `t3_poc_ifenum.txt`: `SetupDiGetClassDevs(DIGCF_PRESENT|DIGCF_DEVICEINTERFACE)` -> exactly 1 interface, `flags=0x1 -> ACTIVE=True`; authoritative device path `\\?\root#t3_ljxlcore#0000#{1abc05c0-c378-41b9-9cef-df1aba82b015}` |
| Devnodes healthy and bound to the driver | `t3_poc_devstat.txt`: status `0x180200B` (DN_ROOT_ENUMERATED\|DN_DRIVER_LOADED\|DN_STARTED), problem `0`, `Service=t3_ljxlcore` on all three |

### 3.2 User-mode open - GATED BY LOWER STACK (the key negative result)

Every `CreateFileW` on the published, ACTIVE interface fails - across **all** requested access modes (`RW`, `R`, `W`, `0x00100000`, `0`), before and after a full clean PnP cycle (remove-device -> implicit driver unload -> `sc start` -> re-create devnode -> seed -> restart -> fresh `AddDevice` + START):

```
CreateFileW(\\?\ROOT#T3_LJXLCORE#0000#{1abc05c0-c378-41b9-9cef-df1aba82b015}, acc=0xC0000000) -> INVALID_HANDLE_VALUE lastErr=1
```

(`t3_poc_open.txt`, `t3_enable2.txt`, `t3_ifenum.txt` - five open variants x three phases, all identical.)

- `lastErr=1` = `ERROR_INVALID_FUNCTION`, which per the in-guest `RtlNtStatusToDosError` mapping run (`t3_state2.txt`) corresponds to **`STATUS_INVALID_DEVICE_REQUEST` (`0xC0000010`)**.
- It is **not** a DACL/access denial: the access-denied gate in this driver maps to DOS 5 (`STATUS_...0xC0000056` -> DOS 5, also mapped in-run), and DACL failures would be DOS 5 as well. The failure occurs *after* symlink resolution (the interface is ACTIVE per SetupAPI), i.e. an `IRP_MJ_CREATE` reached the device stack and was completed with `STATUS_INVALID_DEVICE_REQUEST`.
- Mechanism (consistent with audit section 2.4): the driver's `IRP_MJ_CREATE` handler (`0x140005a50`) forwards to the lower device (`ext+0x18`). On the driver's real deployment the lower stack is HIDCLASS (which services `IRP_MJ_CREATE` for gamepad interfaces); on the root-devnode stand-in the lower device is the PnP root PDO, which does not service `IRP_MJ_CREATE` -> `STATUS_INVALID_DEVICE_REQUEST`.

### 3.3 IOCTL matrix - NOT EXECUTABLE in this configuration

Because no handle can be obtained (section 3.2), the full FUNCTION 0x916-0x920 matrix and the decode-looseness probes were **never dispatched to the kernel** (the PoC logs `FATAL: cannot open interface` and exits - `t3_poc_ioctl.txt`). The PoC and every payload remain fully built and were exercised up to the exact point of failure, so this is a documented gate, not an untested assumption.

---

## 4. Stability

- Guest responsiveness was confirmed **at every phase boundary** by a file write/read roundtrip through vmrun (marker `t3_alive.txt`): 15:15:23 (step1 start), 15:21:51, 15:23:05, 15:28:59, 15:30:42, 15:34:58, 15:37:47, 15:39:47, 15:41:58, 15:44:21, 15:45:09 (guest-local -07:00).
- No IOCTL ever reached the kernel, so no driver-execution crash risk was realized. The one VM outage was an external clean power-off (section 1.3), not a crash, and the guest resumed with full state.
- Cleanup (section 1 evidence `t3_cleanup.txt`): `pnputil /remove-device` OK -> 0 `T3_*` devices remain; service stopped+deleted; copied `.sys` deleted; phantom enum keys gone; empty `DeviceClasses\{1ABC05C0}` root deleted; `t2_rzdev` (other agent) untouched; final driverquery shows 0 t3 services; guest alive at cleanup end.

---

## 5. Claim-by-claim verdict table

| # | Static claim (audit section ) | Verdict | Dynamic basis |
|---|---|---|---|
| 1 | Driver loads as kernel service; DriverEntry `0x140011000` benign (section 1.3, section 2.1) | **CONFIRMED** | `t3_load.txt`: create+start OK, RUNNING, exit 0 |
| 2 | `AddDevice` registers device interface `{1ABC05C0-...}` (section 2.2) | **CONFIRMED** | `t3_sweep.txt`/`t3_poc_ifenum.txt`: interface appears after devnode restart, GUID bytes match |
| 3 | Once-only registration guard (`DAT_14000e248`) (section 2.2) | **CONFIRMED** | 3 devnodes -> exactly 1 interface instance (`t3_poc_list.txt`: `instances=1`) |
| 4 | Interface enables on PnP START via `IoSetDeviceInterfaceState` (section 2.3) | **CONFIRMED** | `t3_poc_ifenum.txt`: `SPINT_ACTIVE=True` on the sole interface |
| 5 | Unrestricted opens: unnamed non-exclusive device, no SD, no identity checks (section 4.3) | **PARTIAL** | Opens fail - but with `STATUS_INVALID_DEVICE_REQUEST` (stack-level), *not* access denial (DOS 5); DACL permitted the open attempt to proceed to the stack. On a stack that services CREATE the audit claim remains plausible, but it was not dynamically demonstrated (see #6-#8) |
| 6 | IOCTL FUNCTION 0x916-0x920 handlers behave per audit table (section 3.2) | **NOT TESTED** | No handle obtainable on the root-devnode stand-in (section 3.2) - pre-IOCTL gate |
| 7 | Dispatch decode ignores DeviceType/Access/Method bits (section 3.1) | **NOT TESTED** | Same open gate; encode variants built but undeliverable |
| 8 | "Most dangerous capability": unauthenticated per-collection config manipulation (section 5) | **NOT TESTED** | Requires open interface **and** attached input-device collections (hardware gate noted in audit); both absent in this VM |
| 9 | Audit caveat: "AddDevice may fail when attaching to a nonexistent lower stack" (orchestrator note) | **RESOLVED - DIFFERENT GATE** | `AddDevice` *succeeded* (interface published+ACTIVE, `t3_ifenum.txt`); the actual load-time gate sits one step later: the driver *forwards* `IRP_MJ_CREATE` to a lower stack that must service it - the root PDO does not -> `STATUS_INVALID_DEVICE_REQUEST` -> interface unopenable |

---

## 6. Exploitability statement

**End-to-end user-mode capability as measured in this VM: none, in this configuration.**

1. **What was achieved:** a user-mode caller (`vmdebug`, full admin token) can install and start the driver (`sc create/start`), plant a root devnode (`CM_Create_DevNodeW` flags=0), make `AddDevice` run, and observe a published, ACTIVE device interface `\\?\root#t3_ljxlcore#0000#{1ABC05C0-C378-41B9-9CEF-DF1ABA82B015}`. Everything up to and including interface publication is reproducible from user mode with admin rights.
2. **Where it stops:** the caller cannot open that interface on the stand-in stack. `IRP_MJ_CREATE` is forwarded by the driver to its lower device; the PnP root PDO completes it with `STATUS_INVALID_DEVICE_REQUEST`, so `CreateFile` fails with `ERROR_INVALID_FUNCTION` for *any* requested access - before any IOCTL can be sent. This is a deployment-shaped gate, not an access control: the audit's "no access control" claim (no SDDL, no privilege check, non-exclusive device) is statically intact, and nothing in the run contradicted it.
3. **Privilege assumptions:** all tested actions were performed with an already-admin token (`EnableLUA=0`); the load chain itself (service create, devnode creation) requires admin regardless. Whether a *non-admin* caller could open the interface was not measurable here (no open succeeded even for admin).
4. **Hardware/deployment gates:** the IOCTL control plane is per-collection (0x378-byte pool objects created when real input devices attach via the driver-to-driver handshake, audit section 1.5/section 1.7). Without a Logitech USB gamepad below the stack, most handlers would no-op even if the interface were openable - in this VM neither condition could be met simultaneously. The realistic dynamic threat surface therefore materializes only on a machine with the intended HID gamepad stack (HIDCLASS services CREATE; collections exist); there, the audit's exposure claim (any local user reaching write-semantics config codes) is the hypothesis to test, and this run neither confirms nor refutes it.
5. **Bottom line:** dynamic testing confirms the *exposure mechanics* through interface publication (admin-only, reversible, no crash) and identifies a previously undocumented lower-stack gate on the driver's forward-only `IRP_MJ_CREATE`. The audit's headline risk - unauthenticated local control plane over attached devices - remains **statically claimed, dynamically unproven** in this environment; the dynamic run found no path by which a user-mode caller reaches kernel IOCTL code in the tested configuration.

---

*All host-side evidence: `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\dynamic_evidence\t3_*.txt` + `t3_poc.cs`. Guest-side artifacts retained under `C:\Users\vmdebug\Desktop\t3_work\` (scripts, PoC source/binary, logs). No t1_*/t2_* state touched; no reboots, snapshots, or power-state changes performed by this agent; guest left running.*
