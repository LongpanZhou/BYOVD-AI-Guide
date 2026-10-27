# SbieDrv.sys static audit

Scope: `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected3\drivers\Sandboxie\SbieDrv.sys` (only). The `_work` copy was not audited.
Method: Ghidra 12.1.4 headless, unique projects `sbiedrv_agent_cls1`, `sbiedrv_agent_dumpall`, `sbiedrv_agent_asm1` (all deleted after import). AuditCls.java (80 sink holders), DumpAllDecomp.java (730/730 functions decompiled, 0 failures), and a new read-only `SbieAgentAsm.java` (disassembly dump, written to the Ghidra scripts folder). Corpus file hash re-checked at the end: unchanged.

## 1. Verdict

| Driver | SHA256 (prefix) | PE timestamp (UTC) | Machine | Verdict | Setup required |
|---|---|---|---|---|---|
| SbieDrv.sys 5.73.2 (Sandboxie-Plus) | B2BFAC3C9FD4C378... | 2026-08-16 09:34:39 (TimeDateStamp 0x6A81842F) | x64 | **NO-WRITE** (for KVA / PHYS / PORT as defined in the brief; rests on untraced items, see section 6) | **none (provisional)** |

- Out-of-class observation (not a finding under the brief's three classes): **NEEDS-DYNAMIC**. Handler 0x12340031 rewrites the DACL of a caller-named registry key. Reachability depends on a registration table that was not fully traced (section 2, section 6).
- **DEFAULT-ADMIN: NOT CONFIRMED.** The driver never sets a DACL on its device object. The effective device DACL is the IoCreateDevice default, which this static pass cannot determine. The master-table verdict is the playbook assumption.
- The master-table device list is wrong. The driver creates exactly one device, `\Device\SandboxieDriverApi`. The other names in the CSV are path-matching or path-prefix strings (section 3).
- Corpus check: the file on disk still hashes to `b2bfac3c9fd4c378400ee4821a34773ccbaf71bb1e836c7a03acc9a9ab3cfe96`, size 272064.

## 2. Evidence block

No KVA, PHYS, or PORT finding was established (none met the four-part standard).

### Out-of-class observation: registry DACL rewrite via handler 0x12340031 (NEEDS-DYNAMIC)

Not counted under the brief's classes. It is a kernel-performed security write to an attacker-named object, not a write to an attacker-chosen address.

- Entry: user `DeviceIoControl` IOCTL 0x222007 (section 4) -> FastIo dispatcher `FUN_140001d50` (`0x140001d50`) -> ID `0x12340031` -> table slot -> `FUN_140015030` (`0x140015030`, registered in `FUN_14003e78c`).
- Input (kernel copy of user buffer `args`): `args+0x08` = byte length (even, <= 0x400); `args+0x10` = user pointer to UTF-16 key path (`ProbeForRead(*(args+0x10), len, 2)` at `0x140015030` line 29).
- Path copied to kernel pool (`FUN_14002cd40`); filter `FUN_140003d84` (`0x140003d84`) must return 0 (not traced).
- `ZwOpenKey(&h, 0xF003F /*KEY_ALL_ACCESS*/, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE, path)` at `0x140015030`, then `ZwSetSecurityObject(h, 0x14, DAT_140039830)`, then `ZwClose(h)`.
- The security descriptor `DAT_140039830` is built in `FUN_1400084f8` (`0x1400084f8`): three `RtlAddAccessAllowedAceEx(acl, 2, 0x13, 0x10000000 /*GENERIC_ALL*/)` ACEs, with SIDs read from the PE data:
  - RVA `0x391F0` = **S-1-5-11 (Authenticated Users)**
  - RVA `0x39200` = **S-1-1-0 (Everyone)**
  - RVA `0x39210` = **S-1-5-12 (Restricted Code)**
  - The DACL is set at `0x1400084f8` (`RtlSetDaclSecurityDescriptor(DAT_140039830, 1, lVar3, 0)`); a mandatory-label SACL is also set from `lVar2`.
- CONTROL: the key name (attacker chooses the registry path). Class: none of KVA / PHYS / PORT.
- Reachability gate: the handler returns `0xC0000002` when its `param_1` is 0 (`if ((param_1 == 0) || (DAT_140039830 == 0))`). `param_1` is the context returned by `FUN_1400182d0` (`0x1400182d0`) for the caller. That function returns 0 for PIDs absent from table `DAT_140039C80` and -1 for entries with a nonzero state byte. So the handler is reached only when the caller's PID has an entry in `DAT_140039C80`.
- Insertions into `DAT_140039C80` (`FUN_140011a94` / `FUN_14001211c` with `&DAT_140039c80`): `FUN_140017944` (`0x140017944`, reached from handler 0x24 via `FUN_14001a050`->`FUN_140018810`), `FUN_1400180f8` (same chain), and `FUN_140018d8c` (`0x140018d8c`, not reached from any handler). Whether a standard user can satisfy the 0x24 path's gate is NOT resolved (section 6).
- The handler 0x0c self-registration (`FUN_14001e640`, magic `0x123ABC0`, gated by `FUN_140026a5c`) inserts into table `DAT_140039C40`, which `FUN_1400182d0` does not consult. It does not, by itself, satisfy the 0x31 gate.
- If a standard user can reach an entry in `DAT_140039C80`, this is a standard-user primitive to grant Everyone GENERIC_ALL on any registry key the driver can open with KEY_ALL_ACCESS in kernel mode, which includes service keys. Whether kernel-mode `ZwOpenKey` bypasses the target key's DACL is expected behaviour but not verified here.

### Probe-type issues (corruption class, section 5)

Not findings: user-VA writes only, not kernel addresses.

## 3. Precondition table

**Device creation (Q1, Q2).** Every name in the CSV device list was checked against the binary.

| Name | Create / attach / path-string | Where | Evidence |
|---|---|---|---|
| `\Device\SandboxieDriverApi` | **CREATED** via `IoCreateDevice` | DriverEntry chain: `entry` (`0x14003D700`) -> `FUN_14003D000` (`0x14003D000`), call at `0x14003D10E` | Disassembly: `LEA RDX,[0x140040490]` at `0x14003D0AC`, `RtlInitUnicodeString` call at `0x14003D0DC`, `CALL [IoCreateDevice]` at `0x14003D10E` with DriverObject=`DAT_140039D08`, DeviceExtensionSize=0, DeviceType=`0x22` (R9D), DeviceCharacteristics=`0x100` (`FILE_DEVICE_SECURE_OPEN`, stack +0x20), Exclusive=BL (stack +0x28), DeviceObject->`DAT_1400396A8`. This is the only `IoCreateDevice` call site in the 730-function dump. |
| `\Device\SandboxieDriverApi` (second use) | Opened (not created) by kernel code | `FUN_1400241B8` (`0x1400241B8`, ZwCreateFile at `0x1400242BF`), `FUN_140024368` (`0x140024368`, ZwCreateFile at `0x140024467`) | String xrefs at `0x1400309D0` |
| `\Device\DeviceApi\CMApi` | String constant | `FUN_140020B80` (`0x140020B80`, LEA R8 at `0x140020D09`) | Not traced beyond the reference; no attach import |
| `\Device\Mup`, `\Device\Mup\DfsClient`, `\Device\Mup\;LanmanRedirector`, `\Device\Mup\;hgfs`, `\Device\LanmanRedirector`, `\Device\NamedPipe` | String constants (path-prefix tables) | `FUN_14000D0A4` (`0x14000D0A4`), `FUN_14000B4C8` (`0x14000B4C8`), `FUN_140009CD0` (`0x140009CD0`) | Xrefs to `0x140032CA0`-`0x140032DB8` are MOV from data globals, not device opens |
| `\Device\CdRom*\*`, `\Device\Floppy*\*`, `\Device\Harddisk*\*`, `\Device\HarddiskVolume*\*`, `\Device\` | Wildcard / prefix patterns | `0x14002E410`-`0x14002E580` (xref `FUN_14000B4C8`, `0x14000B612`) | Path matching, no device object is created |
| `\??\C:` | String constant (drive mapping) | `FUN_140015E7C` (`0x140015E7C`, LEA at `0x140015F5B`) | Not a symlink created by the driver |

- No `IoCreateSymbolicLink`, `IoCreateDeviceSecure`, `IoGetDeviceObjectPointer`, `IoAttachDevice*`, or `WdfDevice*` appears in the static import table, the dynamic-name strings, or the dump. Dynamic-name strings found (via `MmGetSystemRoutineAddress`): `MmCopyMemory`, `PsIsWin32KFilterEnabledForProcess`, `CmRegisterCallbackEx`, `KeAddSystemServiceTable`, `KeServiceDescriptorTable(Filter)`, `ObGetObjectType`, `ObQueryNameInfo`, `ObRegisterCallbacks`, `ObUnRegisterCallbacks`, `RtlQueryRegistryValuesEx`. None of these is a device-create or device-attach API.
- Symlink: **none found.** The driver creates no `\??\` or `\DosDevices\` link for its device. A standard user can reach `\Device\SandboxieDriverApi` only through a native-path open (`NtCreateFile`), not through Win32 `CreateFile`.

**Device precondition row:**

| Field | Value |
|---|---|
| Device created in | DriverEntry (`entry` -> `FUN_14003D000`) |
| Device name | `\Device\SandboxieDriverApi` |
| Symbolic link | none created by the driver |
| DACL | **not set by the driver** (no SDDL, no `IoCreateDeviceSecure`, no `ObSetSecurityObjectByPointer` on the device object). The only SD builder, `FUN_1400084F8` (`0x1400084F8`), sets DAT_140039820/DAT_140039830, not the device. The effective DACL is the IoCreateDevice default, which this pass did not determine. DEFAULT-ADMIN is the playbook assumption and is **unconfirmed**. |
| Setup cost | **none (provisional).** See section 6 for the DriverEntry gates not fully traced. No devnode, INF, or hardware. DriverEntry needs only: its own service key `RegistryPath` (`FUN_14003DAEC`, `ZwOpenKey` + `ImagePath`) and the directory containing the image to be openable (ZwCreateFile in `FUN_14003DAEC`). Build gate (`FUN_14003D984`, `0x14003D984`) passes for Windows 10 (build 19045 is in the base shadow table, see section 6). |
| Reachable by a standard user | **Unknown.** Depends on the device DACL. Open path: IRP_MJ_CREATE `FUN_140002600` (`0x140002600`) completes success whenever `DAT_140039028 != -1` (no further check). |

## 4. Callback and IOCTL table

### 4a. Dispatch (Q3)

Architecture: x64 (PE machine 0x8664). Offsets: MajorFunction at `DriverObject+0x70+8*i`, FastIoDispatch at `+0x50`, DriverUnload at `+0x68`.

| Slot | Handler | Set by | Evidence |
|---|---|---|---|
| MajorFunction[0] IRP_MJ_CREATE (`+0x70`) | `FUN_140002600` (`0x140002600`) | `FUN_14003D000` | `MOV [RAX+0x70],RCX` at `0x14003D0BE` |
| MajorFunction[18] IRP_MJ_CLEANUP (`+0x100`) | `FUN_140002590` (`0x140002590`) | `FUN_14003D000` | `MOV [RAX+0x100],RCX` at `0x14003D0D0` (index 18, not 14) |
| MajorFunction[14] IRP_MJ_DEVICE_CONTROL (`+0xE0`) | **not set by the driver** | - | No write to `+0xE0`; the only DriverObject writes in the dump are the five listed here (`DAT_140039D08 + 0x50/0x68/0x70/0x100`). IO-manager default for an unset slot is not verified here. |
| FastIoDispatch (`+0x50`) | struct allocated in `FUN_14003D000` (size 0xE0) | `FUN_14003D000` | `MOV [RAX+0x50],RDI` at `0x14003D0B3` |
| FastIoDeviceControl (FAST_IO_DISPATCH+0x50) | **`FUN_140001D50`** (`0x140001D50`) | `FUN_14003D000` | `MOV [RDI+0x50],RAX` (`LEA RAX,[0x140001d50]`) at `0x14003D09A`. The decompile shows 8 params; the 9th (DeviceObject) is dropped by the decompiler. |
| DriverUnload (`+0x68`) | `FUN_140008770` (`0x140008770`) | `FUN_1400083B0` (`0x1400083B0`, which is also registered as API 0x12340017), decompile line 7759 | `DriverEntry` clears it to 0 first (`entry`, `*(param_1+0x68)=0`). |

### 4b. IOCTL codes (Q3, Q4)

Decoding (CTL_CODE): DeviceType=0x22 (FILE_DEVICE_UNKNOWN) for all.

| IOCTL | Function | METHOD | Access | Input length check | Output | Handler | Reachable from user mode |
|---|---|---|---|---|---|---|---|
| **0x00222007** | 0x801 | **METHOD_NEITHER** (low bits = 3) | FILE_ANY_ACCESS | `args_len - 8 < 0x39` unsigned, i.e. **8 <= InputLen <= 0x40** (`0x140001D50`, checked at `ProbeForRead(puVar4,0x40,8)`) | not used | `FUN_140001D50` | **yes**, requires `ExGetPreviousMode()==UserMode` and `KeGetCurrentIrql()==0` (else `0xC0000148`) |
| 0x00222008 | 0x802 | METHOD_BUFFERED | FILE_ANY_ACCESS | must equal 0x38 (kernel path only) | - | `FUN_140001D50` (kernel branch -> SeFilterToken) | **no**: user-mode call returns `0xC0000010` |
| 0x0022200C | 0x803 | METHOD_BUFFERED | FILE_ANY_ACCESS | must equal 0x30 (kernel path only) | - | `FUN_140001D50` (kernel branch -> `thunk_FUN_1400010A9`) | **no**: user-mode call returns `0xC0000010` |

Sub-API dispatch behind IOCTL 0x222007 (`FUN_140001D50`):
- Input copied as 0x40 bytes to a kernel stack buffer (`FUN_14002CD40`, copy length = InputLen).
- Function ID = dword at `args+0` (copied `local_68[0]`).
- Index = `ID - 0x12340001`, valid when `< 0x4F` (79 slots). Table `DAT_1400396B0` (0x278 bytes, allocated in `FUN_14003D214`, `0x14003D214`).
- Handler call: `(*table[index])(context, args_kernel_copy, _guard_dispatch_icall)`.
- `context` (`lVar3`) is 0 when caller PID equals `DAT_1400396A0` or when `FUN_1400182D0` returns 0 (caller not in table `DAT_140039C80`). It is the entry pointer when the caller is present with state byte 0. It is -1 (rejected, `0xC000010A`) when the caller's entry state byte is nonzero (asm of `FUN_1400182D0`, `0x1400183BC`/`0x140018398`). Handlers themselves check `param_1` either way (some require 0, some require nonzero).
- 56 of 79 slots are registered (`FUN_14003D214` calls). 23 slots are unset (calls to an unset slot return `0xC0000010`).

Registered sub-API handlers (ID -> handler; registrar):

| ID | Handler | Registrar | ID | Handler | Registrar |
|---|---|---|---|---|---|
| 0x12340001 | FUN_140002500 | FUN_14003D000 | 0x12340031 | FUN_140015030 | FUN_14003E78C (**out-of-class, sec 2**) |
| 0x12340003 | FUN_140002690 | FUN_14003D000 | 0x12340033 | FUN_140002EB0 | FUN_14003D000 |
| 0x12340007 | FUN_140019310 | FUN_14003EB9C | 0x12340034 | FUN_14001C1E0 | FUN_14003ED50 |
| 0x12340008 | FUN_140019490 | FUN_14003EB9C | 0x12340035 | FUN_140020780 | FUN_14003F2EC |
| 0x12340009 | FUN_140019F80 | FUN_14003EB9C | 0x12340036 | FUN_14001FBC0 | FUN_14003F2EC |
| 0x1234000A | FUN_140019B90 | FUN_14003EB9C | 0x12340037 | FUN_14000D4A0 | FUN_14003E05C |
| 0x1234000B | FUN_140019060 | FUN_14003EB9C | 0x1234003A | FUN_14001EF10 | FUN_14001F750 |
| 0x1234000C | FUN_14001E640 (self-register, sec 2) | FUN_14001F750 | 0x1234003F | FUN_14001ECB0 | FUN_14001F750 |
| 0x1234000F | FUN_140004100 | FUN_14003D29C | 0x12340040 | FUN_140002010 | FUN_14003D000 |
| 0x12340010 | FUN_1400043F0 | FUN_14003D29C | 0x12340041 | FUN_1400028B0 | FUN_14003D000 |
| 0x12340011 | FUN_1400122A0 | FUN_14003E2BC | 0x12340042 | FUN_140013B40 | FUN_14003E2BC |
| 0x12340012 | FUN_1400125A0 | FUN_14003E2BC | 0x12340043 | FUN_140013EE0 | FUN_14003E2BC |
| 0x12340014 | FUN_14000A8D0 | FUN_14003DEB8 | 0x12340044 | FUN_140002A00 | FUN_14003D000 |
| 0x12340015 | FUN_140007820 | FUN_14003D374 | 0x12340045 | FUN_140024500 | FUN_140040258 |
| 0x12340016 | FUN_14000D570 | FUN_14003E05C | 0x12340046 | FUN_140002D20 | FUN_14003D000 |
| 0x12340017 | FUN_1400083B0 (also DriverUnload) | FUN_14003D000 | 0x12340047 | FUN_140002270 | FUN_14003D000 |
| 0x1234001B | FUN_14001E970 | FUN_14001F750 | 0x12340048 | FUN_14001EB20 | FUN_14001F750 |
| 0x1234001E | FUN_140014DA0 | FUN_14003E78C | 0x12340049 | FUN_14000A5D0 | FUN_14003DF58 |
| 0x1234001F | FUN_14000A050 | FUN_14003DEB8 | 0x1234004A | FUN_14000AD60 | FUN_14003DF58 |
| 0x12340020 | FUN_14000A700 | FUN_14003DEB8 | 0x1234004B | FUN_1400191D0 | FUN_14003EB9C |
| 0x12340022 | FUN_14000A310 | FUN_14003DEB8 | 0x1234004C | FUN_14001E740 | FUN_14001F750 |
| 0x12340024 | FUN_14001A050 (process registration path, sec 2) | FUN_14003EB9C | 0x1234004D | FUN_14001F410 | FUN_14001F750 |
| 0x12340025 | FUN_140009CD0 | FUN_14003DEB8 | 0x1234004E | FUN_1400045C0 | FUN_14003D29C |
| 0x12340026 | FUN_140001F70 | FUN_14003D000 | 0x1234004F | FUN_140003030 | FUN_14003D000 |
| 0x12340027 | FUN_140009F10 | FUN_14003DEB8 | 0x1234002A | FUN_140012940 (user-VA write, sec 5) | FUN_14003E2BC |
| 0x1234002B | FUN_140021DE0 | FUN_14004003C | 0x1234002F | FUN_1400129F0 (user-VA write, sec 5) | FUN_14003E2BC |
| 0x1234002C | FUN_140019570 | FUN_14003EB9C | 0x12340030 | FUN_140014F00 | FUN_14003E78C |
| 0x1234002D | FUN_140007750 | FUN_14003D374 | | | |
| 0x1234002E | FUN_14001E820 | FUN_14001F750 | | | |

Other callbacks / notify routines installed during init (not traced beyond registration):
- `FUN_14003EB9C` (`0x14003EB9C`): PsSetCreateProcessNotifyRoutineEx, PsSetLoadImageNotifyRoutine.
- `FUN_14004003C` (`0x14004003C`): PsSetCreateThreadNotifyRoutine.
- `FUN_14003EA14` (`0x14003EA14`): ObRegisterCallbacks.
- `FUN_14003E7FC` (`0x14003E7FC`): CmRegisterCallback.
- `FUN_14003DF58` (`0x14003DF58`): FltRegisterFilter (registration table `DAT_14003C000`, minifilter callbacks not traced).
- `FUN_140018F00` (`0x140018F00`): caller of PsSetCreateProcessNotifyRoutineEx (not traced).

Kernel-only paths: `FUN_140001D50` 0x222008 / 0x22200C branches are reachable only with `ExGetPreviousMode()==KernelMode` (no user-mode reach).

## 5. Corruption, not write

- `FUN_140012940` (`0x140012940`, handler 0x1234002A): `puVar1 = *(args+8)`; `ProbeForRead(puVar1, 8, 8)`; `*puVar1 = local_res8` (directory handle). A user-VA 8-byte store probed with the wrong probe type. Not a kernel address (ProbeForRead enforces user range).
- `FUN_1400129F0` (`0x1400129F0`, handler 0x1234002F): `puVar1 = *(args+8)`; then `ProbeForRead(puVar1, uVar2, 2)`; then `FUN_14002CD40(puVar1, puVar4, uVar2)` (copy into the probed user buffer). Copy into a user buffer probed only for read. User-VA only.
- `FUN_14001EB20` (`0x14001EB20`, handler 0x12340048): stores through `*(args+8)` and `*(args+0x10)` are correctly preceded by ProbeForWrite of the same pointers and lengths. Not a finding.
- `FUN_140014F00` (handler 0x12340030): `ProbeForWrite(puVar2, 8, 8)` before `*puVar2 = local_res8`. Not a finding.

## 6. Not traced

Items the verdict depends on, and what was not done:

1. **Device DACL (verdict-critical).** The effective DACL on `\Device\SandboxieDriverApi` is the IoCreateDevice default. Not determined statically. DEFAULT-ADMIN unconfirmed. Reachability by a standard user unknown.
2. **Handler coverage is triage-level.** All 56 registered handlers were checked with a heuristic (ProbeFor coverage, copy destinations, stores through input-derived pointers), and origins were traced for each flagged copy destination and store target. Not line-by-line for every store. Largest bodies not reviewed in full: `FUN_14001FBC0` (294 lines), `FUN_140019570` (219), `FUN_140019B90` (167), `FUN_14001EF10` (178, copy destinations checked only), `FUN_140013EE0` (279, partially: stores at +0xb2..+0xe2 go into kernel list node `DAT_140039CC8`), `FUN_140004100`, `FUN_14000A050`, `FUN_1400125A0` (remainder after line 90 not traced), `FUN_140008030`.
3. **Helpers not reviewed:** `FUN_14002CD40` (copy routine; direction `(dst, src, len)` inferred from call pattern, not verified), `FUN_14001F80C`, `FUN_14001F5FC`, `FUN_14000E438`, `FUN_14002277C`, `FUN_140013038`, `FUN_14001D1BC`, `FUN_140001D28` (called by CREATE/CLEANUP), `FUN_140003E34` (filter helper), `FUN_140004ACC` (config reader), `FUN_140026A5C` and `FUN_140028CF8` (caller admission check; gates handler 0x0C), `FUN_14001F56C`, `FUN_1400171F0`.
4. **Table DAT_140039C80 insertion (verdict-relevant to the out-of-class item).** Not traced to the end: handler 0x24 (`FUN_14001A050`) -> `FUN_140018810` -> `FUN_140017944`/`FUN_1400180F8`, including the gate that decides whether a standard caller is inserted. `FUN_140018D8C` (inserter, not reached from any handler) not traced.
5. **Table DAT_140039C40 vs DAT_140039C80.** The handler 0x0C self-registration writes DAT_140039C40. Whether that list is ever read as the gate for handler 0x31 (`FUN_1400182D0` reads DAT_140039C80) was not confirmed.
6. **Kernel-mode `ZwOpenKey` DACL behaviour** on the target key (relevant to the out-of-class item). Assumed, not verified.
7. **MajorFunction[14] default** (IRP_MJ_DEVICE_CONTROL unset): IO-manager default assumed, not verified. FastIo routing conditions in the IO manager assumed, not verified.
8. **DriverEntry gates not traced:** `FUN_140010124`, `FUN_14003D65C`, `FUN_14001F750`, `FUN_140040258`, `FUN_14003EB9C`, `FUN_14003DEB8`, `FUN_14003E78C`, `FUN_14003E2BC`, `FUN_14003E05C`, `FUN_140040420`, `FUN_14003F2EC` (partial: shadow table from built-in data, csrss.exe lookup, config via `FUN_140004ACC` with defaults). Setup "none" is provisional on these. `FUN_14003D29C` -> `FUN_1400058C0` (IniPath registry read, return ignored) and `FUN_140026B9C` -> `FUN_140027B54` -> `FUN_1400023D8` (signature-blob check on Sandboxie config, return ignored) were confirmed non-gating from the caller code.
9. **KeStackAttachProcess sites**: dump lines 22794 and 26422 (containing functions not identified), and `FUN_14003F86C` (init, csrss filter table; MmCopyMemory dest is a kernel buffer, src is csrss address from init config). Only the last is partly traced.
10. **MmCopyMemory** (resolved to `DAT_1400397D0` in `FUN_14003DE0C`) used only in `FUN_14003F86C` (init), not from any handler.
11. **ZwSetSecurityObject at `FUN_1400122A0` line 67** (handler 0x11): handle origin not traced.
12. **ObReferenceObjectByName in handler 0x3A** (`FUN_14001EF10` line 25184) uses a caller-supplied name. Not traced further; no write sink found in that path.
13. **Minifilter** (`FltRegisterFilter` registration `DAT_14003C000`) and **SSDT / notify callbacks** (`FUN_14003F86C`, process/thread/image notify routines): not traced for writes reachable from user IOCTL.
14. **`FUN_14000E6D8`** (only IoAllocateMdl / MmProbeAndLockPages / MmMapLockedPagesSpecifyCache site): maps a driver-allocated pool page only; not user-address mapping. Traced by its body, not by every caller.
15. **Win10 shadow/filter table:** build 19045 is above the 0x4512 threshold in `FUN_14003F1A8` (uses base table). Not traced in full.
16. **Dead code:** `FUN_14000DFA0` has no references (noted, not a sink).

No functions timed out (730/730 decompiled).

## 7. Next dynamic test (described, not run)

1. **Device DACL and reachability.** On an isolated Windows 10 build 19045 VM with the driver loaded as a service (admin), record the device object's security descriptor (WinDbg `!object \Device\SandboxieDriverApi` then `!sd`), and attempt `NtCreateFile("\Device\SandboxieDriverApi")` from a standard-user token. The result resolves DEFAULT-ADMIN and standard-user reachability.
2. **Out-of-class registry DACL rewrite.** On the same VM, from a standard-user token: (a) determine whether any call sequence inserts the caller into `DAT_140039C80` (handler 0x24 path, with `FUN_140026A5C`/`FUN_140028CF8` gate); (b) if inserted, call IOCTL 0x222007 with ID 0x12340031 against a throwaway HKCU key and compare its DACL before and after; (c) whether kernel-mode open bypasses the target DACL (test with a key the user cannot read). Do not target service keys on a non-test machine.
3. **FastIo routing.** Confirm that a user `DeviceIoControlFile(0x222007)` reaches `FUN_140001D50` through `FastIoDeviceControl` (not IRP_MJ_DEVICE_CONTROL).

## 8. NO-WRITE reason

Missing link: no KVA, PHYS, or PORT write was found with an attacker-controlled destination on the user-reachable path. Destinations derived from the IOCTL input are either ProbeForWrite-checked user addresses or kernel pool allocations. The only MDL site maps a driver-allocated pool page. There is no MmMapIoSpace, MmGetPhysicalAddress, HAL bus-data, MSR, or port-I/O reference, static or dynamic. This verdict still rests on the triage-level handler review (section 6, item 2) and on the device DACL being undetermined (item 1). The out-of-class registry DACL rewrite (section 2) is NEEDS-DYNAMIC and is not a KVA/PHYS/PORT finding.
