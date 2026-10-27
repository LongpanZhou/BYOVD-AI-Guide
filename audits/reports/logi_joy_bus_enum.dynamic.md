# Dynamic Exploitability Validation: logi_joy_bus_enum.x64.sys

> **Agent scope:** t1_ (driver `logi_joy_bus_enum.x64.sys`, SHA-256 `79065269b2009dae18cdf5d9090fe8bab98dcfc1c52e66f91d62f47038192e9b` - verified in-guest before load).
> **Method:** live Windows 10 x64 VMware guest, user-mode PoC (`t1_poc.exe`, C#/.NET 4, compiled in-guest with `csc.exe v4.0.30319`), exercised exclusively the audit-documented IOCTLs with well-formed buffers.
> **Static baseline:** `audits\logi_joy_bus_enum.md`. **All guest outputs pulled to:** `audits\dynamic_evidence\t1_*.txt`.
>
> **Environment anomaly (disclosed):** shortly after the initial read-only reconnaissance (VM confirmed running, guest dirs listed), the VM was found **powered off** by an external party. After ~4 min of waiting I cold-started it with plain `vmrun start` (no reset / no snapshot restore / no other power operation). No guest state was lost; all subsequent work was done in the booted guest. The other agent's (`t2_*`) workspace was never touched.

---

## 1. Setup & load chain (exact commands + results)

| Step | Command (guest) | Result | Evidence |
|---|---|---|---|
| Copy | `Copy-Item driver_batch1\drivers\logi_joy_bus_enum.x64.sys C:\Windows\System32\drivers\` | SHA-256 both sides `79065269B200...92E9B` [x] | `t1_load.txt` |
| Create svc | `sc.exe create t1_ljbus type= kernel start= demand binPath= C:\Windows\System32\drivers\logi_joy_bus_enum.x64.sys` | `[SC] CreateService SUCCESS` | `t1_load.txt` |
| Start | `sc.exe start t1_ljbus` | `STATE : 4 RUNNING` (kernel driver, stoppable) | `t1_load.txt` |
| Verify | `driverquery /v /fo csv` | `t1_ljbus ... Running ... \??\C:\Windows\System32\drivers\logi_joy_bus_enum.x64.sys` | `t1_load.txt` |
| AddDevice check | registry `DeviceClasses\{DFBEDCDD-2148-416D-9E4D-CECC2424128C}` | **ABSENT** after plain `sc start` -> **AddDevice never fired without a PnP devnode** (load-time gate confirmed) | `t1_seed.txt` |
| Root devnode attempt A | manual `HKLM\SYSTEM\CCS\Enum\ROOT\t1_ljbusdev\0000` (ConfigFlags=0, Class=System {4d36e97d-...}, DeviceDesc, HardwareID=`ROOT\t1_ljbusdev`, **Service=t1_ljbus**) + `pnputil /scan-devices` + `pnputil /restart-device ROOT\T1_LJBUSDEV\0000` | "The device instance does not exist in the hardware tree" -> bare registry seeding does **not** materialize a devnode on Win10 | `t1_seed.txt` |
| Root devnode attempt B | `CM_Create_DevNodeW(out dn, "ROOT\t1_ljbusdev\0000", parent=HTREE\ROOT\0, flags=0)` | **cr=0x0 (SUCCESS), devnode ROOT\T1_LJBUSDEV\0000 appears (Status OK)**; flags 1/5 -> CR 0x4 (CR_INVALID_DEVNODE), flags 4 -> 0x1E; `SetupDiCreateDeviceInfo` w/ DICD_GENERATE_ID -> 0xE0000205 (all variants logged) | `t1_mkdev.txt` |
| Bind & start | `pnputil /restart-device 'ROOT\T1_LJBUSDEV\0000'` (Service value pre-seeded) | "Device restarted successfully" -> **AddDevice fired, `IoRegisterDeviceInterface`+`IoSetDeviceInterfaceState` ran**: `DeviceClasses\{DFBEDCDD-...}\##?#ROOT#T1_LJBUSDEV#0000#{dfbedcdd-2148-416d-9e4d-cecc2424128c}` present | `t1_iface.txt` |
| INF routes (fallbacks, both failed) | `pnputil /add-driver t1_bus.inf /install` -> "The third-party INF does not contain digital signature information"; `newdev!UpdateDriverForPlugAndPlayDevices` -> **caller process died natively mid-call** (but partially mutated child devnode state - used deliberately once per child as a state reset) | documented; not needed for final path | `t1_mkdev.txt`, `t1_bind2.txt` |

**Load-chain finding:** `sc` alone loads the image (DriverEntry + dispatch table registered) but the entire user-mode attack surface (device interface) requires a PnP devnode bound to the service. The service name is the binding key (`Service=` in the devnode's enum key). A standard-user cannot create root devnodes (CM_Create_DevNode requires admin), so the practical deployment gate is: **driver present + service bound to a devnode by the installer (G HUB), or an admin-created devnode**.

## 2. PoC design (IOCTLs exercised, buffers, addresses cited)

`t1_poc.cs` (modes: `open`, `snap`, `create <kb|ms|js>`, `inject <msx|msy|msw|kbd|js>`, `remove <kb|ms|js>`, `bind <hwid> <inf>`, `mkdev`, `mkcm`, `list`, `hidread <kind>`). Device path resolved from `DeviceClasses\{DFBEDCDD-...}`; opened `\\?\ROOT#T1_LJBUSDEV#0000#{dfbedcdd-2148-416d-9e4d-cecc2424128c}` with `GENERIC_READ|GENERIC_WRITE` (dispatcher gating `ext+0x08 != 0 / ext+0x0C != 6` per audit @ `0x1400070b6`).

| IOCTL (audit addr) | Buffer sent | Expected (audit) | Purpose |
|---|---|---|---|
| `0x2A2044` (`FUN_140001160` @ 0x140001160) | none (0 bytes) | appends `PsGetCurrentProcessId()` to `.data` array @ 0x140005090 (count @ 0x140005088) | unauthenticated self-registration |
| `0x2A2048` (`FUN_14000112c`) | in==out==132 B, buf[0]=132 | dumps <=16 tracked PIDs to buf+4, Information=0x84 | info disclosure / cross-channel proof |
| `0x2A2000` (`FUN_140007ad8`) | 200 B in==out, buf[0]=0xB7 | stub -> `0xC0000002` | table completeness |
| `0x2A2040` (`FUN_140007ae0`) | 8 B, buf[0]=8, buf[4]=`0x6B`/`0x6D`/`0x6A` | create child PDO (kb requires `ext+0x9C==0`; ms `ext+0xA0==0`); embedded HWIDs `LGHUBDevice\VID_046D&PID_C232/C231`; descriptors @ RVA 0x140004390 (kb, 63 B) / 0x1400043D0 (ms, 67 B) | device fabrication |
| `0x2A2004` (`FUN_140002744`) | 12 B, buf[0]=12, buf[4]=type, buf[8..12]=uniqueId | remove child + `IoInvalidateDeviceRelations` | device removal |
| `0x2A2010` (`FUN_140001a10`) | 8 B mouse report (16 button bits; X int16LE@2; Y int16LE@4; wheel@6; pan@7 - parsed from embedded descriptor): `00 00 FA 00 00 00 00 00` (X=+250), `00 00 00 00 96 00 00 00` (Y=+150), `00 00 00 00 00 00 01 00` (wheel +1) | overwrite parked HID read IRP | input injection |
| `0x2A200C` (`FUN_140001930`) | 8 B kb report (mod@0, reserved@1, 6 keycodes): `00 00 04 00 00 00 00 00` ('a') then all-zero (release) | input injection | keystroke injection |
| `0x2A203C` (`FUN_140001864`) | 8 B neutral joystick report | input injection | joystick path |

Injection pop/complete mechanics were additionally verified by decompiling `FUN_140001a10`/`FUN_140001930` (pop `FUN_1400015b0`, zero-fill `FUN_1400030c0`, copy `FUN_140002e00`, masking `FUN_14000118c` = `DAT_140005088 != 0` -> zeroes 4 B at popped-buffer+2 = X/Y region) and the internal dispatcher `FUN_1400012f0` (0x2A2023 -> park `FUN_140001620`, returns `STATUS_PENDING` 0x103) - pop of an empty queue returns **silently** and the user IOCTL still reports success (the audit's "success masks failures" - this also means `lpBytesReturned=0` is not by itself proof of an empty queue).

Objective measurements: `GetCursorPos` before/after each injection; `GetAsyncKeyState(VK_A)` 25 ms poller across keyboard injection; `Get-PnpDevice` snapshots; Enum/DeviceClasses registry scans; pool-tag census (`NtQuerySystemInformation(22)`); Microsoft-Windows-Kernel-PnP event log.

## 3. Observed effects (evidence in `dynamic_evidence\t1_*.txt`)

1. **Device interface up and openable** (`t1_iface.txt`, `t1_poc_snap.txt`): one instance; opened RW by vmdebug full-admin token, err=0.
2. **Unauthenticated PID facility works end-to-end** (`t1_poc_snap.txt`): `0x2A2044` -> ok; `0x2A2048` dump -> `tracked pid[0] = 4484` == caller's own PID. A later run in a different process reads back the list again (`t1_poc_open.txt` in-guest, mirrored in `t1_restricted.txt` run). **Process-exit callback confirmed live**: PID 4484 (registered 13:58) is gone from the 14:07 dump.
3. **Stub `0x2A2000`** (`t1_poc_snap.txt`): ok=False, lastErr=1 -> `ERROR_INVALID_FUNCTION` (matches audit `0xC0000002`).
4. **Virtual child PDO fabrication confirmed** (`t1_poc_create_kb/ms.txt`, `t1_dev_after_create.txt`):
   - keyboard: `0x2A2040` ok=True -> PnP devnode **`LGHUBDEVICE\VID_046D&PID_C232\1&17A214C2&0&01`**, FriendlyName **"Logitech_LGVirHid01"** (bus driver's QUERY_ID/device-text handlers visible in PnP).
   - mouse: -> **`LGHUBDEVICE\VID_046D&PID_C231\1&17A214C2&0&02`**, "Logitech_LGVirHid02".
   - joystick type `0x6A` -> ok=False err=87 (create handler supports only 0x6B/0x6D - matches audit).
   - create does **not** return the new uniqueId (out-buffer = echo of input) -> removal by `0x2A2004` requires guessing/scanning the id (see below).
   - children initially enumerate with **no function driver** (`CM_PROB_FAILED_INSTALL`) - pure PnP-surface manipulation by an unauthenticated caller.
5. **Full companion stack binding** (`t1_companion.txt`, `t1_bind3.txt`, `t1_bind4.txt`, `t1_pnplog.txt`): loaded `logi_joy_vir_hid.x64.sys` as `t1_ljvirhid` (benign per ledger; sanctioned by task plan), bound children by seeding `Service=t1_ljvirhid` + `ClassGUID={745A17A0-...}` (HIDClass) on the child enum keys + `pnputil /restart-device` (after one deliberate UpdateDriver state-reset per child). Kernel-PnP log confirms genuine Microsoft class binding on the collections: `HID\VID_046D&PID_C232\...` -> **keyboard.inf / kbdhid / "HID Keyboard Device"**, `HID\VID_046D&PID_C231\...` -> **msmouse.inf / mouhid / "HID-compliant mouse"**, parents = my virtual children. HID device interface `{4d1e55b2-f16f-11cf-88cb-001111000030}` + class interfaces `{884b96c3}`/`{378de44c}` enabled for both collections. Pool tags: `LJOY` = 2 paged allocs / 0 frees (both minidriver device contexts alive), `wmbe` present.
6. **Injection verdict** (`t1_poc_inject_*.txt`, `t1_poc_inject2_*.txt`, `t1_recreate.txt`): all injection IOCTLs return **ok=True, returned=0, no cursor movement, no VK_A hits** - with companion bound and PID-list empty (masking off). Attempts: mouse X/Y/wheel x9, keyboard x5 (down+release), joystick x2; also overlapped-`ReadFile` consumer probes - HID/class interfaces of the input collections are **ACCESS_DENIED (err 5) even as SYSTEM** (`t1_opens3.txt`, `t1_sys.txt`), i.e. no user-mode reader could be attached to force hidclass to park a read; no pending read IRP existed to overwrite, so the audited pop-and-complete path had nothing to complete. The driver-side code path (pop -> zero-fill -> copy attacker bytes -> complete) is decompilation-verified and gated only on a pending IRP.
7. **Removal behavior** (`t1_recreate.txt`, `t1_cleanup.txt`): `0x2A2004` validated our buffer shape; with children bound, every removal attempt (incl. bounded id scan 0..63) returned err=87 - removal of bound children by IOCTL was not achieved with guessed ids (create does not disclose the id). Removal was achieved via `pnputil /remove-device` (children + their HID stacks + collections torn down cleanly).
8. **Clean teardown** (`t1_cleanup.txt`, `t1_cleanup2.txt`): removing the bus devnode made the driver **unload itself** (both `sc stop` calls returned 1062 "has not been started" - already stopped by PnP); services deleted, copied .sys files deleted, phantom PnP entries removed, empty DeviceClasses GUID root deleted. **Final state: 0 LGHUB/t1 PnP devices, no services, no driver images, files gone.**

## 4. Stability

No crash, hang, or BSOD at any point across: load/unload, devnode creation/removal, child create/remove/inject cycles (including create-reject 87 paths), companion binding + HID stack build/teardown, restricted-token run. The guest remained fully interactive throughout. Only stability-relevant observation: the IOCTL success-masking (no error surfaced to callers) and one native crash inside `newdev.dll!UpdateDriverForPlugAndPlayDevices` in my *test harness process* (an OS API, not the audited driver).

## 5. Claim-by-claim verdict table

| # | Static claim (audit section ) | Verdict | Dynamic evidence |
|---|---|---|---|
| 1 | WDM bus filter; DriverEntry only registers dispatch; device/interface only via AddDevice on a PnP devnode (section 2) | **CONFIRMED** | `sc start` alone -> no DeviceClasses entry; devnode bind + restart -> interface appears (`t1_load.txt`, `t1_seed.txt`, `t1_iface.txt`) |
| 2 | Interface `{DFBEDCDD-...}` registered in AddDevice, enabled unconditionally on IRP_MN_START (section 2) | **CONFIRMED** | appeared exactly at devnode restart (`t1_iface.txt`) |
| 3 | MJ_CREATE: no caller checks; any caller can open (section 4) | **CONFIRMED** (tested from admin full token and from `runas /trustlevel:0x20000` restricted run - both opened RW; caveat: guest is single-user, EnableLUA=0, so the restricted run's true token contents were not independently verified) | `t1_poc_snap.txt`, `t1_restricted.txt` |
| 4 | No SDDL/`Se*` anywhere; driver adds zero access friction (section 4) | **CONFIRMED** for the bus interface it publishes (open+register+dump all succeeded; no ACL artifact observed). Note: the *children's* HID/class interfaces get OS-default input-device protection (err 5 even as SYSTEM) - that protection comes from the OS/HIDCLASS, not this driver | `t1_opens3.txt`, `t1_sys.txt` |
| 5 | `0x2A2044` unauthenticated PID self-registration, unsynchronized, no uniqueness check (section 3/section 4) | **CONFIRMED** (register + read-back of own PID in <=1 ms) | `t1_poc_snap.txt` |
| 6 | `0x2A2048` dumps tracked PIDs to any caller (section 3) | **CONFIRMED** | `t1_poc_snap.txt`, `t1_restricted.txt` |
| 7 | `0x2A2000` repudiated stub -> `0xC0000002` (section 3) | **CONFIRMED** | `t1_poc_snap.txt` |
| 8 | `0x2A2040` fabricates virtual keyboard/mouse child PDOs; joystick type unsupported in create (section 3) | **CONFIRMED** | `t1_poc_create_kb/ms/js.txt`, `t1_dev_after_create.txt` |
| 9 | Children picked up by PnP immediately (`IoInvalidateDeviceRelations` -> BusRelations) (section 3) | **CONFIRMED** | devnodes enumerated ~1 s after create; later bound by Microsoft HID INFs (`t1_pnplog.txt`) |
| 10 | Create does not return the assigned uniqueId (masked success) (section 3) | **CONFIRMED** | out-buffer = input echo (`t1_poc_create_kb.txt`) |
| 11 | `0x2A2004` removes a child by type+uniqueId | **PARTIAL** | buffer validation confirmed (shape accepted pre-bind; all calls err=87 once children existed - uniqueId never disclosed by create, so matching id could not be established from user mode; final removal done via PnP) |
| 12 | `0x2A200C/0x2A2010/0x2A203C` inject attacker bytes into parked HID read IRPs (section 3/section 5) | **PARTIAL** | driver accepts+processes the IOCTLs (success-masked, exactly as audited); full companion stack (vir_hid+hidclass+kbdhid/mouhid) bound; end-to-end input effect **not observed** because no HID read IRP was ever parked (offline testbed; input HID/class interfaces deny even SYSTEM open so no reader could be attached) |
| 13 | Mouse X/Y zeroing when PID list nonempty (`FUN_14000118c`, section 3/section 4) | **CONFIRMED (static decompile of the check: `return DAT_140005088 != 0`)**; dynamically unexercised (list was kept empty during injections) | decompile via REA |
| 14 | Process-exit callback removes registered PID (section 2) | **CONFIRMED** | `t1_poc_snap.txt` (4484) vs later dump |
| 15 | PnP churn DoS knob via repeated create/remove (section 5) | **PARTIAL** (single create/remove cycles proven; sustained churn deliberately not exercised for guest safety) | `t1_recreate.txt` |

## 6. Exploitability statement

**What a user-mode caller can actually achieve, end-to-end, confirmed on this system:**

1. With the driver's device interface existing (which requires the driver to be bound to a PnP devnode - an installer/admin action, not achievable from a standard-user session on Win10), **any caller able to open that interface - with no privilege, integrity, or identity check by the driver whatsoever - obtains:**
   - **Arbitrary virtual HID device fabrication and destruction at PnP level** (`0x2A2040`): new keyboard/mouse devnodes appear under the caller's control (~1 s latency, real HWIDs/descriptors), enumerable and bindable by real Microsoft INFs (proven: kbdhid/mouhid bound to the fabricated children). Combined with `0x2A2004` (whose id parameter could not be satisfied from user mode because create does not return it - a further defect, not a mitigation), this is a user-controllable device topology channel and a PnP-churn DoS vector.
   - **Unauthenticated kernel-facility read/write**: self-registration into a global tracked-PID array (`0x2A2044`, unsynchronized, unbounded uniqueness) and disclosure of the full tracked-PID list to any caller (`0x2A2048`).
2. **Synthetic input injection (`0x2A200C/0x2A2010/0x2A203C`)**: the driver-side mechanism is real and decompilation-verified (pop pending HID read IRP from the child's cancel-safe queue -> zero-fill -> copy attacker bytes -> complete). The IOCTLs are accepted from any caller with no buffer validation at all for these codes. **In this offline testbed the end-to-end effect was not observed** because the kernel HID read pipeline never parked a read IRP against the fabricated children (no session RIT/reader attached; HID interfaces deny even SYSTEM opens). In the real G HUB deployment - where the companion minidriver is properly INF-installed and the session's input stack actively reads the virtual devices - the parked-IRP precondition is routinely satisfied, which is precisely why the static HIGH rating stands. The dynamic evidence therefore confirms: (a) the injection door is open to any caller with no checks; (b) the effect depends on an environmental precondition (a pending HID read), not on any driver-side control.
3. **Privilege assumptions:** to exploit from a standard-user session, the attacker needs (a) the driver already installed+bound (G HUB present - the normal case for this product's user base) and (b) an openable interface handle - the driver contributes nothing to deny it; the OS default SD of the PDO the interface is registered against is the only gate, and this driver neither sets nor restricts it. Admin-created devnodes expand this to arbitrary root-devnode placement.
4. **Remaining gaps:** no user-mode proof of input reaching win32k in this environment; `0x2A2004`'s uniqueId sourcing unresolved (id never disclosed); the restricted-token probe ran under a guest without UAC so its evidentiary weight is limited.

**Overall: the static HIGH verdict's core claims are dynamically confirmed** (unauthenticated open/register/dump + device fabrication with real PnP effect + clean unload), with input injection verified at the driver boundary but its end-to-end environmental precondition not reproducible in the offline guest.

## 7. Cleanup statement

All t1_* artifacts removed from the guest (see section 3.8 + `t1_cleanup2.txt`): services `t1_ljbus`/`t1_ljvirhid` deleted, `System32\drivers\logi_joy_bus_enum.x64.sys` + `logi_joy_vir_hid.x64.sys` deleted, devnodes + phantom entries + seeded enum keys + DeviceClasses GUID root removed, `driverquery` shows no logi_joy images. The concurrent agent's (`t2_*`) artifacts were never touched. No reboot was required or performed.
