# Dynamic Fuzz Validation — VMware guest kernel surfaces (t7_* run)

| | |
|---|---|
| **Date** | 2026-10-23 (guest-local, UTC-07:00); host 2026-10-24 |
| **Guest** | Windows 10 x64 build 19045 (EFI), testsigning=Yes, HVCI/VBS off, user `vmdebug` (full admin token, EnableLUA=0), snapshot `pre-t7-fuzz` (orchestrator-owned, background) |
| **Method** | `vmrun runProgramInGuest` → PowerShell `-File` scripts (`cmd.exe` broken in-guest, t4 precedent); in-guest C# PoC (`t7_poc.cs`, compiled with Framework64 v4.0.30319 csc) issuing **raw-NTSTATUS** probes via `ntdll!NtDeviceIoControlFile`; kernel object-directory walks (`NtQueryDirectoryObject`); DACL pulls (`GetKernelObjectSecurity` + SDDL convert); unpriv probes via `runas /trustlevel:0x20000`; REA/Ghidra static assist on the **guest** `vsock.sys` copy |
| **Outcome** | **No write-relevant branch found on any reachable surface. vmci: 2048/2048 function codes swept — 3 success (fixed 4-byte getters, unpriv-confirmed), 12 context-gated (ACCESS_DENIED), rest invalid. vsock: 2048 codes swept twice — uniform exact-length/content rejection; only 0x810320C0 hits its kernel-only gate (0xC0000022) and 0x810320C7 returns STATUS_DEVICE_BUSY with no data; 3 exact-length getters confirmed matching static predictions. bxvbda: gate attempt failed as expected (devnode CM_PROB_FAILED_START, interface never materialized) — beyond-BAR escalation STAGED, never executed. nvhda64v: not installed in guest at all.** Zero BSODs, zero wedges, zero safety incidents. |
| **Coverage gained** | vmci.md's unverified ~40% is now empirically bounded for the unpriv-reachable plane (sweep of the full fn 0x800–0xFFF space); vsock.md's two open items (device SDDL; READ/WRITE vtable identity) **resolved** (SDDL = Everyone GRGW; vtable = driver-internal FUN_140006050/060/080/090/0b0/62a0 registered by kernel caller) |

Evidence files: `C:\Users\<scrubbed>\Desktop\driver_candidates\audits\dynamic_evidence\t7_*` (`.ps1` sources, `t7_poc.cs`, all result logs, `t7_guest_vsock.sys`). Guest artifacts retained under `C:\Users\vmdebug\Desktop\t7_work\` (kept per instruction).

---

## 0. Ground-truth drift disclosure (read before trusting the host-audit SHAs)

The guest's driver binaries **differ from the host-audited ones** for both VMware drivers:

| Driver | Guest SHA-256 (in-guest hash) | Host-audit SHA (triage_index.csv) |
|---|---|---|
| vmci.sys | `E9A45BDDB38925DED64B874644F58A6E8E87A10614ED7A34B9BDCCE6BD3D46C6` (106,536 B) | `023EFB61…A2BC` (9.8.29.0) |
| vsock.sys | `1205BD89A4C8AD4F9EF4FF0BC6E646285858EA7379CAF1F2AADB22115646460B` (91,176 B) | `CBF13689…CA68` (9.8.23.0) |
| bxvbda.sys | `FEB27714…DAC45` — **identical** to the audited binary | (same) |

Consequence: static claims from vmci.md/vsock.md (built on host copies) were treated as **hypotheses** and every load-bearing one was re-established empirically on the guest binaries. For vsock the guest copy was pulled to the host (`dynamic_evidence\t7_guest_vsock.sys`) and decompiled — it is **address-identical** to the host-audit's layout (FUN_140002c40 = MJ_DEVICE_CONTROL, FUN_140003738 = common dispatch), so the vsock.md function addresses remain valid for the guest build. vmci behavior (SDDL, naming, bounded getters) matched the audit's structural claims even though the file hash differs.

## 1. Target 1 — vmci.sys (PRIMARY)

### 1.1 Inventory

- Service `vmci` RUNNING (boot-start, group System Bus Extender); PnP devnode `PCI\VEN_15AD&DEV_0740&SUBSYS_074015AD&REV_10\3&61AAA01&0&3F` ("VMware VMCI Bus Device"), Service=vmci.
- Object directory: **`\Device\VMCIGuestDev`** exists (guest side, exactly as the audit's AddDevice split predicts — parent is PCI, not ROOT); **`\DosDevices\VMCIDev`** symlink present (`\\.\VMCIDev` opens). No `\Device\VMCIHostDev` in this guest (`ntopen` → `0xC0000034`), no host-side device.
- **DACL (dynamic, READ_CONTROL pull):**
  `\Device\VMCIGuestDev` = `O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1201bf;;;WD)(A;;0x1200a9;;;RC)`
  → Everyone (WD) = `0x1201BF` = FILE_GENERIC_READ | FILE_GENERIC_WRITE (read+write data, no DELETE, no WRITE_DAC). **Audit's `(A;;GRGW;;;WD)` SDDL claim confirmed dynamically** (guest DACL grants GA to SY/BA instead of the audit string's variants — same Everyone-RW essence; cosmetic drift between builds).
- Opens: `\\.\VMCIDev` **succeeds** from admin AND from a `runas /trustlevel:0x20000` basic-user token with `GENERIC_READ|GENERIC_WRITE`, `GENERIC_READ`, and even zero-access — the driver's MJ_CREATE mask check admits plain unpriv opens exactly as audited (`0x3FEDFE60` high-bit rejection not triggered by these masks). NT-path `\Device\VMCIGuestDev` open (0x12019F) also succeeds.

### 1.2 Documented-code reachability (well-formed inputs)

| Code | Input | Result |
|---|---|---|
| `0x81032004` (get device info) | in=0 or 16 B, out=0x40 | **st=0 ret=4**, value `0x000B0000` — matches audit's `min(0xB0000, devext+0x14)` |
| `0x81032008` (QUEUEPAIR_ALLOC) | 16 B / 64 B zeros | **0xC0000022** (ACCESS_DENIED) — context gate, not a length gate |
| `0x81032018` (QUEUEPAIR_SETVA) | 16 B zeros; shaped 0x18 (ptr=valid user sink, count=4) | **0xC0000022** both — unreachable without a VMCI context; user sink never touched |

### 1.3 Fuzz matrix — structured function-code sweep (the unaudited ~40%)

Scope per mission: device type `0x8103`, METHOD_BUFFERED, FILE_ANY_ACCESS, function codes **0x800–0xFFF** (2,048 codes) → `code = 0x81032000 + fn*4`. Input = 16 B zeros; output = 0x1000 sentinel-filled (0xEE) so any echo/data is detectable; per-code raw NTSTATUS + `IOSB.Information` logged, flushed per line (hang-attributable). Run in 8 chunks; **all chunks completed; zero hangs; zero crashes** (`t7_sweep.txt`, VMCIDev sections).

| Classification | Count | Codes |
|---|---|---|
| SUCCESS | 3 | fn 0x801 (`0x81032004`), fn 0x809 (`0x81032024`), fn 0x815 (`0x81032054`) |
| ACCESS_DENIED (`0xC0000022`) | 12 | fn 0x802 (`0x81032008`), 0x806–0x80D (`0x81032018`–`0x81032034`), 0x811–0x814 (`0x81032044`–`0x81032050`) |
| INVALID_PARAMETER (`0xC000000D`) | 2,033 | everything else (unimplemented / length-gated default) |

### 1.4 Deep-dive of the 3 success codes (bounded escalation; all ≤ 64 B in / ≤ 0x1000 out)

| Code | in=0 | in=16/64 zeros | in=16/64 × `0x41`-pattern | out=0x40 vs 0x1000 |
|---|---|---|---|---|
| `0x81032004` | st=0 ret=4 `0x0B0000` | identical | identical (no echo of input) | ret always 4 (bounded) |
| `0x81032024` | **0xC0000023** (BUFFER_TOO_SMALL — correct length gate) | st=0 ret=4 `0x0B0000` | identical | ret always 4 |
| `0x81032054` | st=0 ret=4 `0x7F11F56D` | identical | identical | ret always 4 |

- **New undocumented codes catalogued**: `0x81032024` = second fixed-value info getter (same `0x0B0000` device cap), `0x81032054` = version/time-token getter (constant `0x7F11F56D`). Both fixed 4-byte outputs, **not attacker-influenced**.
- **Unpriv confirmation**: all 3 re-issued under `runas /trustlevel:0x20000` → identical success (ret=4, same values) → unprivileged-reachable and benign. Two denied-band codes re-issued under restriction → same `0xC0000022` (denial is not an admin artifact).

### 1.5 vmci verdict

**NO-WRITE confirmed dynamically; audit's bounded-plane claim holds on the guest binary.** Of 2,048 function codes: only 3 dispatch to success, all fixed 4-byte constant getters; 12 more are gated behind a VMCI context that even admin user-mode cannot establish (`0xC0000022`); no code echoed input, none returned attacker-influenced `bytesReturned`, none returned more than 4 bytes. The context-gated band (the audit's count-capped QP/datagram/doorbell helpers) remains functionally unreached — **staged escalation**: context-creation bootstrap discovery (phase B; the audit's ≤0x8000-capped helpers are the only copy sites there and would need a context first).

## 2. Target 2 — vsock.sys

### 2.1 Inventory

- Service `vsock` RUNNING (boot-start); device **`\Device\vmci`** + `\DosDevices\vmci` symlink — both live (name is NOT vmci.sys's; VMCIGuestDev/VMCIDev are distinct names).
- **DACL (dynamic — resolves vsock.md's undecoded-SDDL open item):**
  `\Device\vmci` = `O:BAG:SYD:P(A;;FA;;;SY)(A;;0x1201bf;;;BA)(A;;0x12019f;;;WD)(A;;FR;;;RC)` → **Everyone = 0x12019F (GR+GW)**, same exposure class as vmci.sys.
- Opens succeed from admin AND restricted token (RW / R / zero-access).
- **Winsock AF_VSOCK plane unavailable**: `socket(AF_VSOCK=34, …)` → `WSAEAFNOSUPPORT (10047)` / `WSAEPROTONOSUPPORT (10043)` / `WSAEPROTOTYPE (10041)` — no provider installed (no VMware Tools service in guest). The "socket-plane" therefore reduces to the driver's own IOCTL plane.

### 2.2 Structured sweep + batteries (no blind undocumented fuzzing beyond the structured pattern)

- **Pass 1 & 2 (identical config, in=out=16 zeros): 2,048 codes → 2,047 × `0xC000000D`, 1 × `0xC0000022`** (fn 0x830 = `0x810320C0`). Zero hangs.
- Documented-code batteries: with `in=out=0x1000`, all documented codes → `0xC000000D` except `0x810320C0` → **`0xC0000022`** (consistent with the kernel-only `RequestorMode` gate; now also confirmed in code, §2.3).

### 2.3 Static assist on the guest binary (resolves vsock.md's open items)

Decompiled `t7_guest_vsock.sys` (SHA `1205BD89…`, REA/Ghidra):

- **MJ_DEVICE_CONTROL `FUN_140002c40`**: `FsContext == NULL` → `0xC000000D`; else common dispatch `FUN_140003738(Irp, FsContext, IoControlCode, SystemBuffer, InLen, OutLen, &Information)`.
- **`FUN_140003738` gates, in order**: (1) `InLen != OutLen` → `0xC000000D`; (2) per-code **exact-length** checks; (3) socket-plane codes additionally require a **socket-type file context** (`FsContext[0] != 0 && FsContext[1] == 0xC`).
- **Per-code exact lengths (user branch)**: `0x81032058`=4, `0x8103205C`=0x20, `0x81032064`=0x1C, `0x81032068`=4, `0x8103206C`=4, `0x81032070`=0x1C, `0x81032074`=0x2C, `0x8103207C`=0x48, `0x81032080`=0xC, `0x81032088`=0x38, `0x8103208C`=**0x624**, `0x81032094`=0x38, `0x81032098`=0x2C, `0x8103209C`=0xC, `0x810320C7`=0, `0x810320C0`=(out ≥ 0xB4; **kernel caller only** — `cVar5`-gated branch).
- **`0x810320C0`** = transport/provider registration: a **kernel-mode** caller's table of 24 driver-internal function pointers is consumed; the success path also writes a `0x1C+0x98 = 0xB4`-byte function-pointer block into the output SystemBuffer (kernel-address disclosure to the kernel caller — matches audit). **This resolves vsock.md finding #3's open item**: the READ/WRITE copy targets at `ctx+0x130/0x140` are the registered driver-internal callbacks — among them `FUN_140006050`, `FUN_140006060`, `FUN_140006080`, `FUN_140006090`, `FUN_1400060b0`, `FUN_1400062a0` (the same functions named in the audit as unresolved stubs). The registration requires kernel mode ⇒ a user IRP cannot populate it.
- FsContext-free getters (static): `0x81032058` returns constant `0x09080016`; `0x81032068` returns `0x1C`; `0x8103206C` returns `FUN_140002e40()`.

### 2.4 Corrected well-formed battery (exact lengths from §2.3)

| Code | in=out | Result |
|---|---|---|
| `0x81032058` | 4 | **st=0 ret=4 = `0x09080016`** — matches static prediction |
| `0x81032068` | 4 | **st=0 ret=4 = `0x1C`** — matches |
| `0x8103206C` | 4 | **st=0 ret=4 = `0x7F11F56D`** — matches (same constant as vmci's `0x81032054`) |
| `0x81032074` (prop-write, shaped 0x2C + own-user sink @+0x10) | 0x2C | `0xC000000D` (FsContext gate — 3rd and final attempt, BLOCKED → negative documented) |
| `0x8103207C` (shaped 0x48 + sink) | 0x48 | `0xC000000D` (FsContext gate) |
| `0x81032098` (shaped 0x2C + sink) | 0x2C | `0xC000000D` |
| `0x8103209C`/`80` | 0xC | `0xC000000D` |
| `0x81032088`/`94` | 0x38 | `0xC000000D` |
| `0x81032064`/`70` | 0x1C | `0xC000000D` |
| `0x8103205C` | 0x20 | `0xC000000D` |
| `0x810320C7` | 0 | **`0x80000011` (STATUS_DEVICE_BUSY)**, ret=0, no data — length gate passed (0 required); transport-state dependent |

### 2.5 vsock verdict

**NO-WRITE confirmed on the reachable plane.** Exact-length + FsContext-gating is airtight: a plain control-open (any privilege) can only reach the three fixed 4-byte getters and one transport-state code. Every copy-bearing handler (incl. the probed-user-pointer prop-write `0x81032074`) requires a **socket-type FsContext** obtainable only through the AF_VSOCK socket path, which this guest cannot service (no Winsock provider, VMware Tools absent) — an install-gate analogous to t6's hardware gate.

**Staged (not executed) — `t7_phaseB`-class items, vsock side:**
- **V-B0**: obtain a socket-type FsContext (requires AF_VSOCK provider = VMware Tools install, or kernel registration — the latter is kernel-only by gate). B0 is install-gated; no in-guest path found.
- **V-B1** (behind V-B0): `0x8103208C` registration with a real `0x624`-byte struct (static-derived field hints: `p4[2]` mode, `p4[3]`, `p4[4]`, `p4[5]` = pointer-carrying block, `p4[0x186]` flag) — would exercise `FUN_140002e68`/`FUN_140002f80` and the probed-copy helper `FUN_1400048bc`.
- **V-B2** (behind V-B1): `0x81032074` property-write with a socket context (writes fixed 4 bytes to the caller's own probed user pointer — expected benign; confirms probe presence).
- Raw MJ_READ/WRITE on a socket-context handle (the `ctx+0x130/0x140` vtable plane) — only meaningful after V-B1; targets now statically identified for the re-audit.

## 3. Target 3 — bxvbda.sys gate attempt (expected to fail — documented)

| Step | Result |
|---|---|
| Binary ground truth | guest `C:\Windows\System32\drivers\bxvbda.sys` = **`FEB27714…DAC45`** — identical to audited binary; **no push needed** (disclosed: the mission's "push bxvbda.sys" step was a no-op — file already present, hash verified in-guest) |
| Service | `sc create t7_bxv` (isolated t7 namespace; pre-existing `b06bdrv` service left untouched) → **RUNNING** (DriverEntry OK) |
| Devnode | `ROOT\T7BXV\0000` created **first** (`CM_Create_DevNodeW` flags=0, parent `HTREE\ROOT\0`, CR=0), enum key seeded **after** (Class=System `{4d36e97d-…}`, HardwareID=ROOT\T7BXV, Service=t7_bxv) — t1/t3 recipe reproduced exactly |
| Restart | `pnputil /restart-device` → "Device restarted successfully" |
| **AddDevice outcome** | **FAILED_START**: devnode `status=0x1802401 problem=10` (CM_PROB_FAILED_START); **interface `{2AF67184-48d3-4e8e-a3ff-969EFF740ED2}` ABSENT** from DeviceClasses → `WdfDeviceCreateDeviceInterface` never ran |
| Open probes | `\\?\ROOT#T7BXV#0000#{2AF67184-…}` err=2 ×3 (RW/R/0-access) — no object behind the name |
| Probes dispatched | **NONE** — the conditional logic correctly skipped the SAFE `0x80002024` in-window write and the `0x80002050` ctx-ptr leak because no openable surface exists |
| Forensics | SCM event 7045 only (service install); no T7BXV/bxvbda lines in setupapi.dev.log; service self-stopped (exit 31) after the devnode failed; `qobj \Device` (full ~340-entry dump) = **zero t7/bxv/qlogic/b06-named objects** |
| Escalation | **`t7_phaseB` STAGED, NOT EXECUTED** (both host `dynamic_evidence\t7_phaseB.ps1` and guest `t7_work\t7_phaseB.ps1` + `t7_phaseB_STAGED.txt` marker): B0 gate = interface materializes AND opens (needs a real QLogic VBD adapter — the WRITE-HIGH kit stays hardware-gated); then B1 `0x80002050` ctx-ptr leak → B2 SAFE in-window `{offset 0x7F00, count 1, data 0}` → B3 beyond-BAR single probes at 0x80000/0x100000/0x200000/0x400100, count=1, data=0, one probe per step with evidence pulls between steps. **I did NOT and will not execute beyond-window writes; solo-phase + orchestrator-gated per protocol.** |

## 4. Target 4 — nvhda64v64v object re-probe (time permitted)

- Guest: **`nvhda64v` service key ABSENT**, `driverquery` has no nvhda/nvvad/nvvhci rows, and the full `\Device` object dump (~340 entries) contains **no** `audioprotection`/`audioparameters`/NV-audio-named objects. `\GLOBAL??` enumeration is DACL-denied from user mode (`0xC0000022`, limitation noted).
- **Guest-side negative confirms and extends t6's host-side negative**: nvhda64v has no presence in this VM at all; the static `\audioprotection`/`\audioparameters` name claim remains B-gated (sub-6-byte ladder stays armed-but-parked from t6).

## 5. Safety incidents

**None.** Zero BSODs, zero guest wedges (longest single step ≈ 90 s, well under the 2-min wedge rule), zero unintended effects. All payloads within phase-A bounds (sweep inputs 16 B zeros; outputs ≤ 0x1000; the single 0x1000-length uses were OUTPUT-buffer sizing chosen precisely so fixed-size handler writes cannot pool-overflow — the oversized-INPUT direction was never used). Loop-breaker honored: qobj deep-walk branch (3 attempts → BLOCKED; negatives corroborated via registry/SCM/SetupAPI instead), `0x81032074` sink probe (3 attempts → BLOCKED with static-confirmed FsContext-gate explanation).

**PoC bug disclosures** (no guest impact, user-mode only):
1. `t7_poc` `qobj` over `\Device` can `0xC0000005` (user-mode AV) parsing returned name strings whose `Buffer` is a kernel VA (my parser deref bug; the initial successful scan confirmed the two VMware devices; later walks BLOCKED per loop-breaker).
2. First battery's `0x81032074` probes violated the `InLen==OutLen` dispatch rule (sent in=0x18/out=0x1000) — corrected after the static assist; the two invalid attempts are logged in `t7_battery.txt`.
3. Non-ASCII em dash in a script line broke PowerShell 5.1 ANSI parsing once (exit 1, nothing executed, nothing touched) — fixed, parse-checked thereafter.

## 6. Cleanup (verified in `t7_cleanup.txt`)

- `pnputil /remove-device ROOT\T7BXV\0000` → success; `Enum\ROOT\T7BXV` absent; `DeviceClasses\{2AF67184…}` absent.
- `sc stop` (already stopped) + `sc delete t7_bxv` → SUCCESS; post-check `sc query t7_bxv` → 1060 (absent); `driverquery` → **0 t7 services**.
- Pre-existing state untouched and verified: `b06bdrv` STOPPED, `vmci` RUNNING, `vsock` RUNNING; no t7/bxv/qlogic device objects; guest files: only `t7_work\` retained (PoC, scripts, logs) per instruction; `bxvbda.sys`/`vmci.sys`/`vsock.sys` in `drivers\` are the guest's own pre-existing files (never deleted/modified).
- Final aliveness marker written at cleanup end.

## 7. Staged-but-not-executed escalations (summary for the orchestrator)

| ID | Gate | Content |
|---|---|---|
| `t7_phaseB` (bxvbda) | B0: interface `{2AF67184}` openable (real QLogic VBD hardware required — absent) | B1 `0x80002050` leak → B2 in-window `0x80002024 {0x7F00,1,0}` → B3 beyond-BAR single probes 0x80000→0x400100; solo; per-step evidence pulls; never executed |
| vsock V-B0/B1/B2 | B0: AF_VSOCK socket-type FsContext (requires VMware Tools/provider install — absent) | B1 `0x8103208C` registration (0x624 struct, field map partially static-derived) → B2 `0x81032074` prop-write probe → B3 socket-context READ/WRITE vtable plane (targets now identified) |
| vmci context band | context-creation bootstrap (not found from user mode; admin and unpriv both `0xC0000022`) | the 12 context-gated codes (`0x81032008`–`0x81032050` family) whose internals are the audit's count-capped copy helpers |

*End of report.*
