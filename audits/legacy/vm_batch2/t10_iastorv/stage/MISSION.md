# MISSION.md - t10 / iaStorV.sys dynamic phase (batch 2)

| | |
|---|---|
| Agent | agentT10 |
| Target | `C:\Users\<scrubbed>\Desktop\driver_candidates\iaStorV.sys` |
| SHA-256 | `30BEE94794953E2DBF0FC5AFCE0566F335AF022E89819DE145329E7C09C636BD` |
| Guest work dir | `C:\Users\vmdebug\Desktop\t10_work\` |
| Snapshot | `pre-driver-tests` (orchestrator owns restore/power) |
| Verdict being tested | WRITE-HIGH (conditional) - two zero-fill sinks behind a `MinorFunction == 1` gate |

## 0. Static ground truth (agentT10 Ghidra 12.1.4 headless, 2026-10-24)

Full decomp: `_vm_batch2\t10_iastorv\ghidra_scripts\decomp\iaStorV.sys.decomp.txt`
Targeted routing dump: `_vm_batch2\t10_iastorv\ghidra_scripts\t10_static_assist.txt`

**MajorFunction routing answer (decisive open item #1 - CLOSED statically):**
Init function `FUN_00066228` (called from the DriverEntry chain; PE entry file-RVA
`0x11A008`, in INIT section) stamps a 64-bit `_DRIVER_OBJECT`:

| Slot (offset) | Major (wdm.h 26100) | Handler | Note |
|---|---|---|---|
| +0x70 | 0x00 IRP_MJ_CREATE | `FUN_0006325c` | no in-file access check |
| +0x80 | 0x02 IRP_MJ_CLOSE | `FUN_0006325c` | same |
| +0xE0 | 0x0E IRP_MJ_DEVICE_CONTROL | **`FUN_0005c084`** | **user IOCTL plane** |
| +0xE8 | 0x0F IRP_MJ_INTERNAL_DEVICE_CONTROL (= IRP_MJ_SCSI) | `FUN_0005b848` | kernel SRB plane |
| +0x120 | 0x16 IRP_MJ_POWER | `FUN_0005494c` | |
| +0x128 | 0x17 IRP_MJ_SYSTEM_CONTROL | `FUN_000548f8` | |
| +0x148 | 0x1B IRP_MJ_PNP | `FUN_00058404` | PnP |
| +0x68 DriverUnload | | `FUN_00062788` | |
| DriverExtension+8 AddDevice | | `FUN_00057868` | wcsstr PCI\VEN_8086 -> Intel(57938) / non-Intel(57c64) |

- READ/WRITE/FLUSH etc. slots NOT set (NULL -> I/O manager default
  STATUS_INVALID_DEVICE_REQUEST). MJ_DEVICE_CONTROL IS set: **user DeviceIoControl
  reaches `FUN_0005c084`** - the audit's conditional reach is real.
- **No re-stamp path**: full-decomp grep for byte stores of `0x01` to an
  IO_STACK_LOCATION MinorFunction found none; the pass-through handlers
  (`FUN_0005e300` for 0x4D014, `FUN_0005dcf0` for 0x4D004) check `SL+1 == 1`
  with the ORIGINAL user SL. User-issued MJ_DEVICE_CONTROL IRPs carry
  MinorFunction 0 -> **expected 0xC000000D before any write**. The only
  MinorFunction==1 producers are kernel IRP_MJ_SCSI IRPs (class/port plane,
  kernel-owned buffers).
- **0x4D008 has NO MinorFunction gate** (FUN_0005d198): needs InLen >= 0x1C,
  SystemBuffer != NULL, OutLen >= HeaderLength + 0x1C, and signature at
  SystemBuffer+4: `IntelMpd` (any state) or `IntelATA`/`PIIXIDE` (FDO state 3);
  then switches on ControlCode (+0x10). Battery covers 3 signatures with zeros.
- **CREATE/CLOSE has no in-file mask check** - open policy = device DACL only
  (IoCreateDevice default security; IoCreateDeviceSecure NOT imported).
- **Device objects** (all via `FUN_000582a8`: IoCreateDevice, Exclusive=FALSE,
  no SDDL): `\Device\Ide\iaStor%d` (DeviceType 4, ext 0x1040 Intel / 0x940
  non-Intel path), `\Device\Ide\IAAStorageDevice-%d` (DeviceType 0x2D
  FILE_DEVICE_MASS_STORAGE, ext 0xFD0, chars 0x100/0x101 - only on unit
  enumeration, needs real controller).
- **Symlinks** (`FUN_00057e34`): `\DosDevices\Scsi%d:` AND `\Device\ScsiPort%d`,
  both -> the iaStor%d device. DOS-side open name: `\\.\ScsiN:`.
- **Interface**: `IoRegisterDeviceInterface(PDO, {2ACCFE60-C130-11D2-B082-00A0C91EFB8B}`
  = DiskClassGuid, ...)` - Intel path ONLY (after CC_ 0x0104/0x0106 check).
  Non-Intel (guest) path registers NO interface.
- **WOW64 paths exist** in both handlers (IoIs32bitProcess; 0x2C/32-bit layout) -
  native x64 PoC only; note the 32-bit variant exists but is not probed.
- **ZwCreateDirectoryObject("\Device\Ide")** runs on the Intel path only; the
  non-Intel path relies on the OS-provided `\Device\Ide` directory.

**ADDRESS-SPACE DRIFT DISCLOSURE**: the static audit's "VA 0x14005c084 /
image base 0x140000000" numbers are REA label-space. The file's true preferred
ImageBase is `0x10000` and the true file-RVA of the dispatch is **0x4c084**
(Ghidra label 0x5c084 = REA's 0x5c084 = function-start; file RVA = label-0x10000).
kd step: use `bp iaStorV+0x4c084` (module-relative), NOT +0x5c084.

## 1. Staged inventory (in `stage\`)

| File | Role |
|---|---|
| `t10_poc.cs` / `t10_poc.exe` | PoC: qobj/open/ntopen/dacl/daclnt/ioctl/stptd/stpt/srb/sweepc/mkdev/devstat |
| `t10_load.ps1` | SHA-verify + sc create/start + driverquery + events 7000/7026 |
| `t10_devnode.ps1` | t6 devnode recipe (mkdev FIRST, seed enum AFTER, pnputil restart) |
| `t10_discover.ps1` | qobj \Device, \Device\Ide, \DosDevices + setupapi.dev.log tail -> t10_devices.txt |
| `t10_dacl.ps1` | DACL pull per discovered device + \\.\ScsiN: |
| `t10_open_unpriv.ps1` | admin + restricted-token open/dacl probes (runas /trustlevel:0x20000) |
| `t10_battery.ps1` | shaped-struct batteries (see section 3) |
| `t10_sweep.ps1` | parameterized raw-code band runner |
| `t10_trigger.ps1` | one-shot 0x4D014 for the kd watch |
| `t10_cleanup.ps1` | sc stop/delete + file removal + verify + marker |
| `t10_kd_dispatch.ps1` | HOST-side kd attach/collect (t6 recipe) |
| `t10_phaseB_STAGED.txt` | staged-marker content (B0/B1/B2 - never execute) |

Push list (host -> guest t10_work): `iaStorV.sys`, `t10_poc.exe`, `t10_poc.cs`,
all `t10_*.ps1`, `t10_phaseB_STAGED.txt`.

## 2. Ordered runbook (PHASE 2 - only on orchestrator authorization)

0. Push + verify: CopyFileFromHostToGuest each file; `Get-FileHash` in-guest vs
   host SHA-256 (log `t10_verify.txt`); write aliveness marker `t10_alive.txt`.
   BEFORE push: vmrun fileExistsInGuest for t10_work\iaStorV.sys (never overwrite
   pre-existing files; t10_work is new). ALSO check whether the guest already has
   its own `C:\Windows\System32\drivers\iaStorV.sys` (possible Windows-shipped
   copy) and record its SHA-256 next to the pushed one - DRIFT DISCLOSURE both
   ways (t7 precedent). The sweep/batteries load the PUSHED binary via
   binPath= t10_work\iaStorV.sys.
1. `t10_load.ps1`. Record exact SCM status + Win32 exit code, driverquery rows,
   events 7000/7026. Expected: service RUNNING or FAILED (record exact).
   DriverEntry runs; no AddDevice without a devnode -> no device objects yet.
2. `t10_discover.ps1` -> expect zero iaStor objects (negative finding A).
3. `t10_devnode.ps1` (t6 recipe) -> AddDevice runs. Non-Intel path expected:
   device created -> `\DosDevices\Scsi%d:` + `\Device\ScsiPort%d` links;
   then FUN_00058200 (forwarded 0xC350200c) decides persistence: on failure the
   symlinks AND device are deleted (transient). Re-run `t10_discover.ps1`.
   Expected B: objects exist, or transient-creation negative (record which).
4. If devices persist: `t10_dacl.ps1` + `t10_open_unpriv.ps1`
   -> resolves ACL open item #6 dynamically (default-security + no in-file mask).
5. `t10_battery.ps1` -> decisive MinorFunction-gate answer (section 3).
6. `t10_sweep.ps1` bands (one invocation per band):
   `-start 4d000 -end 4d0fc`; `-start 41000 -end 410fc`; `-start c3512010 -end c351201c`;
   then single customs via battery-style ioctl: `2d1400`, `70000`.
7. kd (optional, <= 3 attempts): host `t10_kd_dispatch.ps1 -phase attach`;
   guest `t10_trigger.ps1`; host `-phase collect`. Record MinorFunction seen.
8. STAGED only: `t10_phaseB_STAGED.txt` (B0/B1/B2) - write the marker into
   t10_work, NEVER execute.
9. `t10_cleanup.ps1` + write `audits\iaStorV.dynamic.md` (t7_fuzz.md structure).

## 3. Battery expectations (record EXACT statuses)

| Battery | Shape | Expected |
|---|---|---|
| 0x4D014 sil=0 sioff=0x38 | SPTD 0x48, cdb 00 | 0xC000000D (gate) |
| 0x4D014 sil=16 sioff=0x38 | SPTD 0x48 | 0xC000000D (gate) |
| 0x4D014 sil=0 sioff=0x40 | SPTD 0x48 | 0xC000000D (gate) |
| 0x4D014 sil=16 sioff=0x40 | SPTD 0x48 | 0xC000000D (gate) |
| 0x4D004 datain=0 dboff=0x40 | SPT 0x48, cdb 2A | 0xC000000D (gate) |
| 0x4D004 datain=1 dboff=0x40 dtl=16 | SPT 0x48, cdb 28 | 0xC000000D (gate) |
| 0x4D008 sig=IntelMpd/IntelATA/PIIXIDE | SRB 0x50 zeros | signature-gated (NOT minor-gated); record |
| 0x41018 GET_ADDRESS out=8/0x1000 | in=0 | PDO-state-gated; expect 8-byte reply or 0xC0000010/0xC000000D |
| customs raw | 16/0x1000 | per static switch; record |

If ANY 0x4D014/0x4D004 battery returns SUCCESS with a buffer delta beyond the
0x48-byte shaped input: STOP that battery, record, mark phase-B trigger.

## 4. Abort points / wedge rule

- Any guest step > 2 min without output: kill (vmrun listProcessesInGuest ->
  killProcessInGuest on the script/poc pid), mark `wedge`, continue.
- Any BSOD/wedge of the guest: stop, report; orchestrator owns restore.
- Loop-breaker: <= 3 attempts per tool/technique -> BLOCKED, commit partial.
- Never: vmrun stop/reset/snapshot; host driver load; oversized inputs
  (shaped headers <= 0x100 B, raw in <= 64 B, out <= 0x1000); sense-offset
  exploitation; near-2^64 DataBufferOffset (B1 L5 only, staged).
- SHA drift of the pushed binary in-guest -> abort phase, report.
