# SbieDrv.sys: admin-scope static audit (kernel memory write)

| Field | Value |
|---|---|
| File | `drivers/SbieDrv.sys` (manifest batch: collected3; previously `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected3\drivers\Sandboxie\SbieDrv.sys` (272064 bytes)) |
| SHA-256 | `B2BFAC3C9FD4C378400EE4821A34773CCBAF71BB1E836C7A03ACC9A9AB3CFE96` |
| Company and version | Sandboxie-Plus.com; FileVersion and ProductVersion 5.73.2 (ProductName "Sandboxie", FileDescription "Sandboxie Kernel Mode Driver") |
| Signature status and signer | Valid (`Get-AuthenticodeSignature`). Signer `CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation`; issuer `CN=Microsoft Windows Third Party Component CA 2014` |
| Method | static, Ghidra 12.1.4 headless decompile dump (730/730 functions; dump `ghidra_dump\out\sbiedrv.txt`, `=== DONE functions=730`). Analysis date 2026-10-24 |
| Reach tier | local administrator (indirect). Every memory-touching path found sits behind the trusted-caller gate in section 2. No such path is reachable from an ordinary device opener. |
| Setup required | none (driver load). The trusted-caller state is a runtime condition of the Sandboxie service, not a devnode or hardware gate. |
| Verdict | **MW2** - reach=R2 setup=none write=W2 load=signed (conditional; NEEDS-DYNAMIC). Legacy label: `WRITE-MEDIUM`. No write to a kernel address chosen by input was found; the overflows are constrained pool/stack writes. |
| Write quality | W2 |
| Severity | MW2 |

> Static analysis only. Nothing was loaded, installed, started or executed. The Ghidra dump and the binary were read, not run. Statements about runtime behaviour are predictions for section 7, not results.

Line numbers below refer to `ghidra_dump\out\sbiedrv.txt`.

---

## 1. Entry surface

### 1.1 Device, symbolic link, DACL

| Item | Finding | Source |
|---|---|---|
| Device | `\Device\SandboxieDriverApi`, created once in the DriverEntry chain | line 34921: `IoCreateDevice(DAT_140039d08, 0, name, 0x22, 0x100, 0, &DAT_1400396a8)`. Function FUN_14003D000 (line 34891). Called from `entry` at line 35321. |
| Device characteristics | `FILE_DEVICE_SECURE_OPEN` (0x100), device type 0x22, exclusive 0 | line 34921 |
| Symbolic link | none. Neither `IoCreateSymbolicLink` nor `IoCreateUnprotectedSymbolicLink` is imported or called. | EXT list (lines 2-218) |
| DACL set by the driver on the device | none. No `IoCreateDeviceSecure`, `ZwSetSecurityObject` on the device, `ObSetSecurityObjectByPointer`, or SDDL string targets it. | the only SD builders are on other objects: FUN_1400084F8 (lines 5764-5792, sets DAT_140039820/830), FUN_140013200 (14132-14133, NULL DACL on a directory object), FUN_1400169F0 (16743-16767), FUN_14002649C (27819-27821), FUN_140026C70 (28296-28317) |
| Effective device DACL | **not determined statically.** It is the kernel default for a named `IoCreateDevice` object with no SD, which this dump does not expose. The earlier "DEFAULT-ADMIN" label stays unconfirmed. |  |
| Effect on verdict | None on the memory-write verdict. The trusted-caller gate in section 2 applies independently of the device DACL. The device DACL decides only who can reach the dispatcher. The handlers reachable without the trusted gate contain no memory-write sink (section 3.2). |  |

### 1.2 IRP dispatch

| Slot | Routine | Source |
|---|---|---|
| IRP_MJ_CREATE (+0x70) | FUN_140002600 | line 34918 |
| IRP_MJ_CLEANUP (+0x100) | FUN_140002590 | line 34919 |
| IRP_MJ_DEVICE_CONTROL (+0xE0) | not set by the driver (IO-manager default) | no write to +0xE0 in the dump |
| FastIoDeviceControl (FAST_IO_DISPATCH+0x50) | **FUN_140001D50** (the IOCTL sub-API dispatcher) | line 34916: `plVar3[10] = FUN_140001d50` |
| DriverUnload (+0x68) | FUN_140008770 (via FUN_1400083B0) | assignment not re-verified in this pass |

Routing of the IOCTL that matters (`0x00222007`) is through FastIo. The IO manager's FastIo routing for `NtDeviceIoControlFile` is assumed here, not verified dynamically.

### 1.3 Sub-API dispatcher FUN_140001D50 (lines 1019-1114)

- Line 1040 and 1054: `ExGetPreviousMode()` must be UserMode for the 0x222007 path. Kernel-only branches for 0x222008 and 0x22200C (lines 1041, 1055) are unreachable from user mode.
- Lines 1067-1072: `KeGetCurrentIrql()` must be 0 and previous mode must be user, else `0xC0000148`.
- Lines 1074-1075: accepts only `IoControlCode == 0x222007` with `InputLength - 8 < 0x39`, i.e. 8 to 0x40 bytes.
- Lines 1083-1095: caller context. If `PsGetCurrentProcessId() == DAT_1400396A0`, context is 0. Otherwise `FUN_1400182D0` returns the caller's entry, 0 (absent from table) or -1 (rejected, `0xC000010A`). An absent PID and the trusted PID therefore both arrive with context 0. Handlers must test the PID themselves.
- Line 1097: `ProbeForRead(input, 0x40, 8)`. Line 1098-1099: zero then copy `InputLength` bytes to a kernel copy. The handler receives the kernel copy, so its pointer fields are still raw user addresses.
- Lines 1100-1102: `index = ID - 0x12340001`, accepted only when `< 0x4F` (79 slots, table at DAT_1400396B0, 0x278 bytes).
- Line 1107: indirect call to the handler with `(context, kernel_copy)`.

### 1.4 Sub-API handler table

- 56 handlers are registered from DriverEntry through `FUN_14003D214(id, handler)` (table function at line 34954, store at 34974). All registrars are called from `entry` (lines 35285-35321), so the table is live at load.
- The complete ID-to-handler list is reproduced by `grep "FUN_14003d214(0x"` on the dump. Section 4 lists every handler that contains a memory-touching path.

---

## 2. Trusted-caller gate (controls handlers 0x43, 0x49, 0x4A; also 0x15 and 0x35)

Several handlers test `param_1 == 0 && PsGetCurrentProcessId() == DAT_1400396A0`. The global `DAT_1400396A0` is set only by handler **0x12340033** (FUN_140002EB0, lines 1781-1831):

1. Line 1794: requires context 0 and `FUN_1400269B8()` true.
   - `FUN_1400269B8` (lines 28064-28107): the caller's token user SID must equal `S-1-5-18` (LocalSystem; `FUN_140026A98`, lines 28132-28150, compare at 28146). The caller's image path must begin with `DAT_140039810` (the directory the driver was loaded from; set at DriverEntry from the service ImagePath, line 35566). The image basename must equal `SbieSvc.exe` (line 28096).
2. Line 1795: requires `FUN_140026A5C()` true (lines 28110-28129). That function returns TRUE **without checking the caller image** when:
   - `DAT_1400397E8 != 0`. This is the test-signing bit, set at line 35372 from `FUN_140026B64` (lines 28181-28199, which reads `SystemCodeIntegrityInformation`, class 0x67, and returns bit 1 of CodeIntegrityOptions); or
   - the license-state word `_DAT_140039B00` matches a pattern set by the Certificate.dat parser `FUN_140027B54`.
   - Otherwise `FUN_140028CF8` (lines 29806-29863) must pass. It locates the caller image and verifies it through `FUN_1400279CC` and `FUN_140028E38` (signature verification in `FUN_140028EAC`, not traced in full).
3. Line 1814: `DAT_1400396A0 = PsGetCurrentProcessId()`. Cleared to 0 by `FUN_140002BCC` (line 1668); the call sites of that function were not traced.

**What this means for the reach tier.** The trusted caller must be a LocalSystem process running an image named `SbieSvc.exe` from the driver's own directory, and that image must pass the signature check. The check is skipped when test-signing is on. A local administrator therefore reaches the trusted handlers in one of two ways:
- with test-signing on, by creating a LocalSystem process that meets the name, path and SID conditions (the signature check is then skipped); or
- with test-signing off, only by executing code inside a process that passes the signature check, which in practice means the genuine signed SbieSvc.exe (for example through SeDebugPrivilege injection). This is not verified here.

No ordinary device opener reaches the trusted handlers.

---

## 3. Memory-write analysis

### 3.1 Import-level sinks (every dangerous call site)

| # | Sink | Site (line, function) | Reached from | Gate | Destination and value | Finding |
|---|---|---|---|---|---|---|
| 1 | `ZwMapViewOfSection` | 5611, FUN_140008030 (5514-5648) | init range only: callers at 35144, 35178, 36766, 36991, 37157 (their reach from `entry` not fully traced) | init only (no IOCTL caller found) | maps `\SystemRoot\System32\<name>` read-only into the current process (ZwCreateFile 5580, ZwCreateSection 5596). Not a write. | NO-WRITE |
| 2 | `IoAllocateMdl` 10088, `MmProbeAndLockPages(...,2)` 10094, `MmMapLockedPagesSpecifyCache(...,KernelMode)` 10095 | FUN_14000E6D8 (10046-10119) | single caller FUN_14000E064 at line 9680, size constant 0x60 | constant size | driver-owned 4 KiB pool page used as a bump allocator. The size argument is not from input. | NO-WRITE |
| 3 | `KeStackAttachProcess` | 20499, FUN_14001BE18 (20462-20530) | FUN_14001B248 (19966), FUN_14001B29C (19987), FUN_14001B348 (20032), FUN_14001BFA8 (20553); these are reached from FUN_140018810 (18276) and FUN_14001B4D0 (20199). FUN_140018810 is reached from handler 0x24 (FUN_14001A050, line 19191). | the handler 0x24 gate is not traced (open item in section 8) | attaches to a target process, reads its PEB and parameter block through `ProbeForRead` (lines 20500-20514), then copies at most `param_3*2` bytes into a pool block of `param_3*2 + 0x20` (copy at line 20516). | cross-process **read**. NO-WRITE. |
| 4 | `KeStackAttachProcess` | 24054, FUN_140020E74 (24020-24095) | FUN_140020D30 (24006) | not traced to a handler | attaches to a caller-named process only to resolve a handle with `ObReferenceObjectByHandle`. Not a memory write. | NO-WRITE |
| 5 | `MmCopyMemory` (resolved dynamically) | resolved at 35599-35600 (FUN_14003DE0C, 35587); used at 36966 (FUN_14003F86C, 36880) | DriverEntry only: FUN_14003F2EC (36681), called from `entry` (35291) | init only | copies from a csrss address held in an init-time filter table (the origin of that table was not fully traced) into a kernel buffer sized `count << 2` (lines 36963-36974). Read direction. | NO-WRITE (init-only read) |
| 6 | `KeStackAttachProcess` | 36972, FUN_14003F86C | same as row 5 | init only | pairs with row 5 | NO-WRITE |
| 7 | `MmMapIoSpace`, `MmMapIoSpaceEx`, `MmUnmapIoSpace`, `MmGetPhysicalAddress`, `ZwOpenSection(\Device\PhysicalMemory)`, `__readmsr`/`__writemsr`, `in`/`out`, `HalGetBusData`/`HalSetBusData` | none | none | n/a | not present. Checked in the EXT list and by a case-insensitive search of the dump. The dynamically resolved names are only MmCopyMemory, PsIsWin32KFilterEnabledForProcess, KeServiceDescriptorTable(Filter), KeAddSystemServiceTable and ZwCreateTokenEx (a log string). | not present |

### 3.2 memmove and memset sites inside the handler bodies

`memmove` is FUN_14002CD40 (line 34247; 105 call sites in the dump). `memset` is FUN_14002D000 (line 34542; 50 sites). This table covers every copy or fill located in a registered handler body (about 60 sites). Helpers called by handlers were traced where the handler passes a caller-derived destination. Non-handler sites are not individually audited (section 8).

| Handler (ID) | Function | Site lines | Destination | Length bound | Probe on user pointers | Result |
|---|---|---|---|---|---|---|
| 0x01 | FUN_140002500 | 1353 | user (`*(p+8)`) | constant string length | ProbeForWrite 1352 | user VA only. NO-WRITE |
| 0x03 | FUN_140002690 | 1474 | pool | `uVar7` | ProbeForRead 1456 (source) | NO-WRITE |
| 0x0A | FUN_140019B90 | 19031 | user | `ProbeForWrite(puVar10, uVar8)` at 19020 covers the total; loop writes list entries | ProbeForWrite 19020 | user VA only; NO-WRITE |
| 0x11 | FUN_1400122A0 | 13509, 13568 | pool (`uVar9+2`, `uVar10+2`) | exact | ProbeForRead 13503, 13565 | NO-WRITE |
| 0x12 | FUN_1400125A0 | none (only ProbeForWrite 13619) | n/a | n/a | n/a | NO-WRITE |
| 0x14 | FUN_14000A8D0 | 7200, 7201, 7205, 7264, 7268 | pool `uVar11 = uVar10+0x10+uVar9`; pool `iVar4+0x20` | terminators stay inside the pool; the wcslen-derived separator is inside the zeroed region | ProbeForRead 7187, 7194 | NO-WRITE |
| 0x15 | FUN_140007820 | 5189, 5196 | pool `len+0x40+len1` | each copy is followed by an explicit terminator; both stay inside the block | ProbeForRead 5173, 5181 | NO-WRITE (also trusted gate, section 2) |
| 0x1F | FUN_14000A050 | 6866, 6890, 6893 | user (`*(p+0x20)`) | `ProbeForWrite` lengths 6865 and 6888 cover the copy totals | ProbeForWrite 6865, 6883, 6888 | user VA only; NO-WRITE |
| 0x22 | FUN_14000A310 | 6954 | pool `uVar7+8` | `uVar7 < 0x401` (6951) | ProbeForRead 6952 | NO-WRITE |
| 0x27 | FUN_140009F10 | 6793 | user (`puVar1`) | `ProbeForWrite((uVar3+1)*2)` at 6792 covers `uVar3*2` | ProbeForWrite 6792 | user VA only; NO-WRITE |
| 0x2F | FUN_1400129F0 | 13810 (pool), 13833 (user) | pool; user | 13810: at most 0x1000 chars (line 13797). 13833: probed for READ only (13832). | ProbeForRead 13809, 13832 | user VA only (ProbeForRead rejects kernel addresses); NO-WRITE |
| 0x30 | FUN_140014F00 | 15605 | pool `uVar5+8` | `uVar5 < 0x401` (15602) | ProbeForWrite 15599, ProbeForRead 15603 | NO-WRITE |
| 0x31 | FUN_140015030 | 15660 | pool `uVar5+8` | `1 <= uVar5 <= 0x400` (15654) | ProbeForRead 15658 | NO-WRITE (gate: table entry, section 5) |
| 0x34 | FUN_14001C1E0 | 20672 | pool `RtlLengthSid(puVar1)` | SID length taken from user data | ProbeForRead 20668 covers 0x44 bytes only | read beyond the probed range is possible (information only). NO-WRITE |
| 0x35 | FUN_140020780 | 23763 | output buffer | total probed by ProbeForWrite 23727 (per-entry accumulation not re-verified) | ProbeForWrite 23727 | trusted gate (section 2); NO-WRITE within probe |
| 0x36 | FUN_14001FBC0 | 23372 | stack `local_288[80]` | `0x41 < uVar21` raises (23367), so at most 65 bytes plus NUL | ProbeForRead 23363, 23366 | NO-WRITE |
| 0x3A | FUN_14001EF10 | 22823, 22886 | pool 0x1008 | at most 0x800 chars, probed before clamp | ProbeForRead 22794 | NO-WRITE |
| 0x40 | FUN_140002010 | 1210 | user (`puVar2`) | capacity check `puVar1[1] < uVar8` (1204) | ProbeForWrite 1177-1182, 1209 | user VA only; NO-WRITE |
| **0x43** | **FUN_140013EE0** | **14999** | pool `int len + 0x178` (allocation 14938) | length `(uint)len` (14996, 14999); **no lower bound** | ProbeForRead(..., `int len`) at 14998 (negative value passes, see 3.3) | **heap overflow, trusted-only** |
| 0x46 | FUN_140002D20 | 1753, 1755 | pool | `<0x4000` and `<0x100001` (1749) | ProbeForRead 1750, 1751 | NO-WRITE (out-of-class, section 5) |
| 0x47 | FUN_140002270 | 1262 | pool | `uVar1 < 0x4000`, `uVar2 < 0x100001` (1253) | ProbeForRead 1256; ProbeForWrite 1257 (output buffer, same lengths) | NO-WRITE |
| **0x49** | **FUN_14000A5D0** | **7029, 7034** | pool `(int)len1*2 + 0x220` (7024) | second copy length `len2*2` where `len2 = wcslen(...)`, **no bound** | none (trusted-only) | **heap overflow, trusted-only** |
| **0x4A** | **FUN_14000AD60** | **7330** | stack `local_228[256]` | copy `wcslen*2` **before** the check `0x1FF < uVar2` at 7331 | none (trusted-only) | **stack overflow, then fast-fail (crash-first)** |
| 0x4E | FUN_1400045C0 -> FUN_140001B74 | 947-948 | pool `len+2` | copy `len+2` bytes; NUL at offset `(len+2) & ~1` (948) | ProbeForRead 937, 941 | 1-byte NUL past the requested size for odd `len`; pool granularity normally absorbs it. NO-WRITE (confirm, section 7). |
| 0x2A | FUN_140012940 | 13755 | user 8-byte store (`*puVar1`) | ProbeForRead (not ProbeForWrite) at 13755 | user VA only | NO-WRITE |

Store-only handlers (direct writes through input pointers, no memmove) were checked against their ProbeFor calls (lines in section 3.2 and the ProbeFor grep). Full coverage of every direct store was not completed (section 8).

### 3.3 The trusted-only overflows (detail)

**Handler 0x12340043, FUN_140013EE0 (lines 14757-15036).**
- Gate: line 14836 (`PsGetCurrentProcessId() == DAT_1400396A0`, inside `param_1 == 0`).
- Length: `iVar1 = *(int*)(param_2 + 0x20)` (14995), **signed**.
- Allocation: `ExAllocatePool(..., len + 0x178)` (14938). The sum is computed as `int` and passed as an unsigned size. A failed allocation returns an error and no copy follows.
- Copy: `FUN_14002CD40(plVar3 + 0x2F, src, (ulonglong)*(uint*)(plVar3 + 0x174))` (14999), where the stored value at +0x174 is `len` (14996). For negative `len` the copy length is `2^32 - |len|`, while the block is `len + 0x178` bytes.
- Probe: `ProbeForRead(*(param_2+0x28), iVar1, 1)` (14998) uses the same value as an unsigned length. It passes only when the user source address plus that length stays below the user boundary, so the source has to sit low in user space. This narrows the path but does not close it.
- Negative `len` values from -0x177 to -1 produce a block of 1 to 0x177 bytes and allow the copy. A value of -0x178 gives a zero-size request; whether that returns a block was not verified. More negative values make the allocation fail; the code logs the failure (`FUN_140016DE0`) and skips the copy.
- Primitive: a pool write that starts at the end of a small block and continues for up to about 4 GiB, with bytes from the caller's source buffer. The target is the pool memory that follows the block, not an address the caller chooses. Write quality W2. Pool metadata and neighbours can be corrupted.
- Positive `len` is consistent (allocation `len+0x178`, copy `len`, offset 0x178 + len fits).

**Handler 0x12340049, FUN_14000A5D0 (lines 7005-7055).**
- Gate: line 7020 (PID test).
- Allocation: `(int)len1*2 + 0x220` (7024), where `len1` is the wcslen of the first string.
- Copy 1: `len1*2` bytes at offset 0x21C (7029). Fits.
- Copy 2: `len2*2` bytes at offset 0x18 (7034), where `len2` is the wcslen of the second string (`*(param_2+8)`), **no bound**. The copy overruns when `len2 > len1 + 0x103`.
- Primitive: heap overflow of length set by the second string, bytes from the second string. W2.

**Handler 0x1234004A, FUN_14000AD60 (lines 7303-7363).**
- Gate: line 7326 (PID test).
- Copy: `wcslen*2` bytes into `local_228[256]` at 7330. The length check `if (0x1FF < uVar2)` is at 7331, after the copy.
- Then `FUN_14002CCB8` (lines 34160-34171) executes `int 0x29` (fast-fail) at 7333. The function never returns.
- Primitive: stack write past a 512-byte buffer, then fast-fail. There is no return and no controlled execution. Crash-first, capped at MW4.

---

## 4. Memory-touching IOCTL table

All user-reachable memory paths go through IOCTL `0x00222007` (method NEITHER, FILE_ANY_ACCESS, function 0x801) and the sub-API ID in the first input DWORD. Kernel-only codes `0x00222008` and `0x0022200C` are unreachable from user mode (lines 1041, 1055).

| Sub-API ID (IOCTL 0x222007) | Handler | Input checks | Memory primitive | Reach (gate) | Verdict |
|---|---|---|---|---|---|
| 0x12340043 | FUN_140013EE0 | input 8-0x40 bytes; name struct probed 0xC0 bytes (14841), second struct 0xA2 (14874); `len` unchecked below | pool heap overflow, `len` signed (negative passes), W2 | trusted only (section 2) | **WRITE-MEDIUM (conditional)** |
| 0x12340049 | FUN_14000A5D0 | input 8-0x40 bytes; strings via wcslen, no probe | pool heap overflow (second string), W2 | trusted only (section 2) | **WRITE-MEDIUM (conditional)** |
| 0x1234004A | FUN_14000AD60 | input 8-0x40 bytes; wcslen, no probe | stack overflow then fast-fail, crash-first | trusted only (section 2) | MW4 (crash-first). NO-WRITE for exploitation. |
| 0x12340015 | FUN_140007820 | probes on both strings | bounded (section 3.2) | trusted only | NO-WRITE |
| 0x12340035 | FUN_140020780 | output probed (total) | output loop not fully re-verified | trusted only | NO-WRITE (partially traced) |
| 0x1234004E | FUN_1400045C0 | input probed | 1-byte NUL past odd-length allocation (pool granularity) | trusted, or a PID with an entry in the sandbox list (FUN_14001F6DC, lines 23062-23088). The list is populated by FUN_14001F5FC from handler 0x0C and other handlers gated by FUN_140026A5C (section 2). | NO-WRITE (confirm, section 7) |
| 0x12340001 | FUN_140002500 | ProbeForWrite | constant write to user pointer | any context | NO-WRITE |
| 0x12340003 | FUN_140002690 | ProbeForRead on source | pool copy, bounded | any context | NO-WRITE |
| 0x12340014 | FUN_14000A8D0 | ProbeForRead, lengths 32000 bound | pool, bounded; file rename via ZwSetInformationFile | table entry required (param_1 != 0) | NO-WRITE |
| 0x1234001F | FUN_14000A050 | ProbeForWrite on output | user VA only | param_1 != 0 | NO-WRITE |
| 0x12340022 | FUN_14000A310 | ProbeForWrite 6948, ProbeForRead 6952 | pool, bounded | table entry required (param_1 != 0) | NO-WRITE |
| 0x12340027 | FUN_140009F10 | ProbeForWrite 6792 | user VA only | any context | NO-WRITE |
| 0x12340030 | FUN_140014F00 | ProbeForWrite 15599, ProbeForRead 15603 | pool, bounded | param_1 == 0 path | NO-WRITE |
| 0x12340031 | FUN_140015030 | ProbeForRead 15658 | pool, bounded; registry DACL write (out-of-class) | param_1 != 0 (table entry) | NO-WRITE (out-of-class, section 5) |
| 0x12340034 | FUN_14001C1E0 | ProbeForRead 20668 (0x44 bytes) | pool block and copy both use `RtlLengthSid(puVar1)`, so no write overrun. The SID can be longer than the 0x44-byte probe, so the read can run past it (information only). | trusted only (PID test at 20657) | NO-WRITE |
| 0x12340036 | FUN_14001FBC0 | ProbeForRead 23366; length cap 0x41 | stack copy, bounded | table entry required (param_1 != 0) | NO-WRITE |
| 0x1234003A | FUN_14001EF10 | ProbeForRead 22794 | pool, bounded | table entry required (param_1 != 0) | NO-WRITE |
| 0x12340040 | FUN_140002010 | ProbeForWrite 1177-1182, 1209; capacity 1204 | user VA only | any context (PID test 1168) | NO-WRITE |
| 0x12340046 | FUN_140002D20 | length caps; ProbeForRead | pool, bounded; registry DACL write (out-of-class) | FUN_140026A5C only | NO-WRITE (out-of-class) |
| 0x12340047 | FUN_140002270 | ProbeForRead 1256, ProbeForWrite 1257 | pool, bounded | param_1 == 0 path | NO-WRITE |
| 0x1234002A | FUN_140012940 | ProbeForRead 13755 | user 8-byte store only | param_1 == 0 | NO-WRITE |
| 0x1234002F | FUN_1400129F0 | ProbeForRead 13809, 13832 | pool; user copy probed for READ only | param_1 == 0 | NO-WRITE (user VA only) |
| 0x12340033 | FUN_140002EB0 | gates in section 2 | sets the trusted PID | LocalSystem + SbieSvc.exe + signature (or test-signing) | enabling step, not a write |
| 0x0C | FUN_14001E640 | param_1 == 0; FUN_140026A5C for every non-null request | adds PID to the sandbox list (DAT_140039A38) or to DAT_140039C40 | FUN_140026A5C (section 2) | enabling step, not a write |
| 0x00222008 / 0x0022200C | kernel-only | PreviousMode must be kernel | n/a | not user-reachable | n/a |

---

## 5. Out-of-class observations (security-descriptor writes, not memory writes)

These are not kernel memory writes under the scope. They are recorded for the owner.

- **0x12340031, FUN_140015030 (lines 15629-15688).** Writes `DAT_140039830` (Authenticated Users, Everyone and Restricted Code GENERIC_ALL, built at 5764-5792) as the DACL of a caller-named registry key, after the filter FUN_140003D84 returns 0. Gate: context must be non-zero (table entry, line 15648). The insertion path into `DAT_140039C80` (handler 0x24, FUN_140018810, FUN_140017944) is not fully traced.
- **0x12340046, FUN_140002D20 -> FUN_140026C70 (28296-28317).** Writes a caller-supplied DACL blob onto a caller-named key under `\REGISTRY\MACHINE\SECURITY\SBIE...` (fixed prefix, line 1756; `ZwSetSecurityObject` at 28317). Gate: `FUN_140026A5C` (line 1743). That gate returns TRUE for every caller while test-signing is on (section 2).
- **0x12340011, FUN_1400122A0 (13463-13583).** Creates an object directory from a caller-supplied name. The object attributes carry a security descriptor built from DAT_140039820, and a label is set through `ZwSetSecurityObject` (line 13530). The exact argument layout was not confirmed beyond the decompile. FUN_140013200 (14104-14133) creates a directory object with a NULL DACL (Everyone full access) from a config-derived name, called from FUN_1400184A0 (17959). The gate for that call chain is not traced.
- **FUN_1400169F0 (16743-16767)** sets a DACL and calls `ZwSetSecurityObject`. The only caller in the dump is itself, so it is unreached in this dump (callback registration not traced).
- **FUN_14002649C (27819-27821)** via FUN_140025530 (27160) and FUN_140025310 (27132). The handler chain is not traced.

---

## 6. Verdict

- **WRITE-MEDIUM (conditional, NEEDS-DYNAMIC).** SEVERITY.md equivalent **MW2**: `reach=R2 setup=none write=W2 load=signed`.
- Basis. The driver contains two controlled heap overflows (0x43, 0x49) and one stack overflow with immediate fast-fail (0x4A). All three are reachable only from the registered Sandboxie-service caller (section 2). No path writes to a kernel address chosen by input. No physical-memory, MSR or port write exists. No ordinary device opener reaches the overflow sites.
- Constraints, in plain words. For 0x43, the write starts at the end of a pool block sized `len + 0x178`, runs for up to about 4 GiB, and carries bytes chosen by the trusted caller. The target is whatever pool memory follows; the caller does not choose the address. For 0x49, the overflow starts past a block sized by the first string and carries the second string, which the trusted caller controls. For 0x4A, a 512-byte stack buffer is overrun and the function fast-fails; that gives a crash only.
- Change from the earlier NO-WRITE. The earlier pass counted only KVA, PHYS and PORT writes. The admin-scope definition also counts copies to caller-influenced kernel addresses and missing bounds. Under that definition 0x43 and 0x49 are memory writes.
- The device DACL is not determined. It does not change this verdict, because the gate in section 2 is independent of it.
- Under the legacy scale used in `_ledger.md` the same finding is WRITE-MEDIUM (gated). It is not WRITE-HIGH, because WRITE-HIGH requires an unprivileged reach.

---

## 7. Dynamic confirmation plan (described only, not run)

All steps are for an isolated Windows 10 build 19045 VM. Nothing below was executed in this pass.

1. **Device DACL.** Read the security descriptor of `\Device\SandboxieDriverApi` (`!object`, then `!sd`). Record which token classes can open it. This resolves the device-step reach tier.
2. **Admission outcome.** Record the return values of `FUN_1400269B8`, `FUN_140026A5C` and `FUN_140028CF8` for: (a) the genuine service; (b) a LocalSystem process outside the driver directory; (c) with test-signing off and on. Observation only.
3. **Sizing arithmetic.** On the trusted path, confirm that the pool block size and the copy length at 14938 and 14999 differ as section 3.3 describes. Confirm the same for 7024 and 7034. Use a test harness on the isolated VM only, and build no payload.
4. **Pool neighbourhood.** Use `!pool` to show which objects sit next to a block allocated at 14938 and at 7024. This decides what a W2 write can reach.
5. **0x4E odd length.** Use `!pool` to confirm that the usable size of the block from FUN_140001B74 absorbs the trailing NUL for odd lengths. If it does, 0x4E is NO-WRITE.
6. **Out-of-class effects.** On a disposable key only, observe the effect of 0x31 and 0x46 on the key's DACL and owner. Do not target service keys on a non-test machine.

---

## 8. Limitations

- Only the Ghidra decompile was read; the disassembly was not. Argument directions for FUN_14002CD40 (memmove) and FUN_14002D000 (memset) were inferred from their call pattern and from the ImDisk helpers FUN_140005A40 and FUN_140005D00, whose opening branches were read.
- All 730 functions decompiled. Only the 56 handler bodies, the named import sinks and the functions they call with caller-derived destinations were traced. The 105 memmove and 50 memset call sites in the whole dump were not individually audited.
- Direct stores through input pointers were checked against their ProbeFor calls only where those calls are visible. Full store coverage was not completed.
- Not traced in full: the body of signature verification (FUN_140028EAC); the licence word parser (FUN_140027B54); FUN_140026C70 internals; the context table FUN_1400182D0; the insertion path into DAT_140039C80 (handler 0x24 -> FUN_140018810 -> FUN_140017944 and its gate); the caller of FUN_140020E74 (FUN_140020D30); the chains FUN_140025530/FUN_140025310 and FUN_1400184A0; FUN_1400062B4 (the 0x4E sink).
- Init-only classification of ZwMapViewOfSection (row 1) and MmCopyMemory (row 5) rests on the caller listing. Not every init caller was traced back to `entry`.
- The effective device DACL is not determined.
- Time-of-check and time-of-use between ProbeFor and use was reasoned only for the sites listed.
- The FastIo routing assumption (section 1.2) is not verified.
- No dynamic testing. Every runtime statement is a prediction for section 7.
