# amdpsp.sys detailed memory-write audit

- Target: `C:\Users\<scrubbed>\Desktop\driver_candidates\amdpsp.sys` (135,184 bytes, PE, x86_64)
- SHA-256: `0A3AF18439B6BB4AF119C8020A3D0220ED6CC8AE04E20032F846E77777700A0A` (Get-FileHash). Matches the `amdpsp` row of `triage_index.csv` (SHA256 column). REA `open_binary` returned the same digest, `0a3af184...700a0a` (no evidence_id).
- Method: static analysis through REA (Ghidra 12.1.4). Nothing was loaded, opened, sent or executed on this host. REA was closed after analysis.
- Naming: Ghidra names (`FUN_xxxxxxxx`). WDF calls are indirect calls through unnamed slots. Where a WDF identity is given, it is inferred from argument shapes and marked "(inferred)".
- Evidence: IDs are listed in section 8. Facts are numbered F1 to F33.

---

## 1. Summary

**Ratings**

- (a) Unprivileged user can open the device and reach the IOCTLs: **WRITE-HIGH (candidate)**.
- (b) Only administrators can open the device: **WRITE-MEDIUM**.

**Why (a) is HIGH**

- The device DACL grants Everyone (WD) GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE (F2, F3). No privilege, token or requestor check was found on the traced paths (F27).
- IOCTL 0x9C422834 copies a caller-chosen number of bytes into a 0x9000-byte driver-owned contiguous buffer at offset 0x8000. Nothing bounds the length, so any length above 0x1000 writes past the end, with caller-chosen bytes (F19). This is an in-file memory-corruption primitive reachable without privileges.
- IOCTL 0x9C422002 maps a kernel-allocated contiguous buffer into the caller's address space. IOCTL 0x9C422003 frees the pages but never unmaps that mapping or releases its MDL (F15, F17). If the mapping survives the free, the caller keeps access to freed physical pages. Whether it survives is OS behaviour and needs VM verification.
- Not CRITICAL on the in-file evidence. No reached path lets the caller choose an arbitrary write address. The overflow's destination depends on adjacent kernel memory. The post-free mapping effect is OS-dependent. Caller words do reach PSP command fields (F23), but whether the PSP treats them as physical addresses cannot be shown in the file.

**Why (b) is MEDIUM**

- The same handlers are reachable by an administrator, who can already load kernel-mode code. No privilege boundary is crossed. The defects are still memory-safety bugs and should be fixed.

**Earlier WRITE-HIGH rating**

- **Keep** for (a), on different grounds. The claimed physical-address return and the claimed mailbox-write chain are wrong (section 3). The rating now rests on F19 and F17.
- **Lower** the administrator-only case to WRITE-MEDIUM.
- **Raise** (a) to WRITE-CRITICAL if any of these is confirmed: (i) KMDF returns the raw caller pointer for METHOD_NEITHER requests, so IOCTL 0x9C422003 writes a zero DWORD to a caller-chosen address (F18); (ii) the PSP writes to physical addresses carried in caller-supplied command fields (F23, F25); (iii) the overflow destination is shown to be an attacker-steerable kernel object.

**Answers to the questions**

- Q1: Yes. The device is `\Device\amdpsp` with symbolic link `\DosDevices\amdpsp` (Win32 name `\\.\amdpsp`). Its DACL includes `(A;;GRGWGX;;;WD)`, so any user may open it with generic read and write. The SDDL is attached before device creation (F2 to F6). Runtime effect still to be verified.
- Q2: 0x9C422002 is handled in the request callback FUN_1400017B0 and calls FUN_140003020. The size is a caller DWORD, nonzero and uncapped. Memory comes from MmAllocateContiguousMemorySpecifyCache (cached) and is mapped to user mode with MmMapLockedPagesSpecifyCache. The caller receives a status and a user VA. It receives no physical address and no size. The caller gets RW access to those physical pages through its mapping. The PSP gets them only through 0x9C422000, which sends the physical address of a caller-selected allocation (F14 to F16, F24).
- Q3: Mailbox writes go through FUN_140002EB0 at BAR0 + 0x10500 + reg (device IDs 0x1456, 0x15DF, 0x1486), otherwise BAR1 + reg (F20). The registers and command codes are constants. No caller-chosen register offset or value reaches the mailbox (F22). Caller-chosen physical memory reaches the PSP only as (i) the physical address of the caller's own allocation (0x9C422000) and (ii) the physical pages behind the caller's own pinned buffer (0x9C422824). Raw caller words are placed in command fields 2, 3, 4, 5 and 9 (F23). Their meaning is defined by PSP firmware, which is not in the file (F25).
- Q4: No privilege or identity check on the traced paths. The device DACL is the only gate (F27).
- Q5: (a) WRITE-HIGH (candidate). (b) WRITE-MEDIUM. Details in section 5.

---

## 2. Verified facts

### 2.1 Inventory of IOCTL paths (summary of F7 to F24)

| IOCTL | Method (low bits) | Path | Reachable under F9 | Caller controls | Effect |
|---|---|---|---|---|---|
| 0x9C422000 | BUFFERED (0) | probe in callback, then FUN_140004880 | yes | size a (<= own allocation size), user VA c (own 0x9C422002 allocation), 16-byte header at d | doorbell 0x20000; PA of caller-selected allocation and size sent (F26) |
| 0x9C422002 | OUT_DIRECT (2) | callback only, FUN_140003020 | yes | size (uint32, uncapped) | contiguous alloc, user mapping, table entry; no PA returned (F14 to F16) |
| 0x9C422003 | NEITHER (3) | callback only, FUN_140003810 | yes, if KMDF returns raw pointers (open item 1) | user VA key; output pointer | frees contiguous memory without unmapping (F17); writes 0 to output pointer (F18) |
| 0x9C422004 | BUFFERED | callback, then FUN_1400031F0 | yes | channel index 1 to 16 | doorbell 0x30000 (F26) |
| 0x9C42280C | BUFFERED | FUN_1400081A0 | yes | DWORD | command 2 with raw DWORD (F23) |
| 0x9C422810 | BUFFERED | FUN_140007F90 | yes | type map and four 16-byte entries | command 3; raw qwords possible (F23) |
| 0x9C422814 | BUFFERED | FUN_140007E70 | yes | two DWORDs | command 4 with raw DWORDs (F23) |
| 0x9C422818 | BUFFERED | FUN_1400071C0 | yes | DWORDs and type map | command 5 (F23) |
| 0x9C422820 | BUFFERED | preprocess FUN_140006920, then FUN_1400074B0 | yes | size (page-rounded) | RW NonCached user mapping; command 6 with driver PA (F24) |
| 0x9C422824 | BUFFERED | probe in callback, then FUN_1400077F0 | yes, page-multiple and page-aligned buffer | pins caller's pages | command 6 with PFN list (F24) |
| 0x9C422808 | BUFFERED | probe in callback, then FUN_140007340 | yes | length and bytes | command 1 with driver PA (F24) |
| 0x9C422834 | BUFFERED | probe in callback, then FUN_140007A90 | yes (input 0x20, output 0x158) | length (uncapped) and bytes | **contiguous overflow** (F19); command 9 with raw 16 bytes (F23) |
| 0x9C422828, 0x9C422830, 0x9C422838, 0x9C42283C, 0x9C422804, 0x9C422844 | BUFFERED | queue handlers in FUN_140001F90 | yes | not traced in full | not traced (section 6) |
| 0x9C422010 to 0x9C422034 (incl. 0x9C422018, 0x9C422028, 0x9C422030) | BUFFERED | FUN_1400022C0 handlers | no, under F9 (F13) | n/a | conditional facts in F30 |

### 2.2 Device exposure (Q1)

- **F1.** SHA-256 matches the triage row. REA reports the same digest, PE, x86_64. (Get-FileHash; triage_index.csv; open_binary, no evidence_id.) The triage row shows state "Running", so the driver is loaded on the analysis host. The device itself was not checked.
- **F2.** SDDL at 0x140009210: `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)`. It is the only match for `(A;` (case-sensitive). ev_5999fca3a5062e9e6d21e81d2c07f59f81f06f10d74df4044b44745e1c204f18
- **F3.** ACE meanings: SY GenericAll; BA, WD (Everyone) and RC each GR|GW|GX. The DACL is protected (`P`): no inherited ACEs, and no Authenticated Users or Interactive ACE. The WD ACE gives every token, including standard users, generic read and write. Same evidence as F2.
- **F4.** Device name `\Device\amdpsp` at 0x1400091F0. Symbolic link `\DosDevices\amdpsp` at 0x140009290. Typed-context name `DEVICE_CONTEXT` at 0x1400091A0. ev_4bfa2462d2fb7d7cbb3fc7d55f03d876b78cc12c84d1eab9ffc2c492cd436354
- **F5.** The SDDL is referenced at 0x14001D2CB inside FUN_14001D1E0 (0x14001D1E0 to 0x14001D582). In that function, in order: device name (decimal suffix for instances other than 0), buffered I/O type, SDDL assignment (WdfDeviceInitAssignSDDLString, inferred), WdfDeviceCreate, then for instance 0 the symbolic link and a device interface (GUID at 0x1400091E0), then the default queue (FUN_140002A40). The SDDL is attached before the device is created. The file does not show the framework step that applies it to the named object; that is runtime behaviour (section 6). ev_9dbc85c7d10852c4872230bdc4ae7c2ad2991a55caef1fdb7c204eab2b73682e (xref 0x14001D2CB); ev_9e9413d570b64260d0780fbba990ea48fac8aa457bcd191137478781a36e4487 (containing procedure); ev_128edec4fb9476d7d0f9679d605d0ee318fdabbd2d4d76644960d2763f4b8735 (pseudocode); ev_9f73ba495ba2524fe2be2204b90f5b833a94c4a55fef2b92d704fa1d21de4911 (xref 0x1400091F0); ev_95703b60da4c46efb42d0149a1283fd99abe12b2a5e1c634aaae495a3df04b38 (xref 0x140009290).
- **F6.** FUN_14001D1E0 is called from FUN_14001D010 at 0x14001D010, its only resolved caller. FUN_14001D010 creates the device from a driver and device-init argument (EvtDriverDeviceAdd shape, inferred). It is reached indirectly, so its caller is not traced. ev_d7e54d3446babb2437e80a4dee2503fc5b2736ef613f903de577588c990e48be; ev_ff66a39fd44a4a146abe5af52e72e4efebe3ddac50f1d0812f1fc2f9f1c57406.

### 2.3 Dispatch and gating (Q2)

- **F7.** Neither `02 20 42 9C` (0x9C422002) nor `00 20 42 9C` appears in any initialized segment (complete searches). The IOCTL cases are compiled into a jump table and are visible only in decompiled output. ev_46c644826214bbe5eb90e549c1662f415befb98e85ae0ef3434eb64365641bbb; ev_b1d9289b0f8ee81266b07f8948c78e05f96282dc0325d6d9fafb101e0812d909.
- **F8.** Range compares against 0x9C422800: `81 F9 00 28 42 9C` (cmp ecx) at 0x140001748 in FUN_140001670, and `81 7D C0 00 28 42 9C` (cmp [rbp-40h]) at 0x140001E3D in FUN_1400017B0. They split codes at or below 0x9C422800 from higher codes. ev_32ed281f0fc36ed380cacfa6b0ebc4eb47a060f91a8bc6d68a07679b1b7e9e05 (search "42 9C": hits 0x14000174C and 0x140001E42); ev_9751aec2a7f108b5b01495a486b96ce39f0cd1f70b3f6b95adaaba257cab0aa7 (bytes at 0x140001730); ev_dfe7b9a21003093e2f68695f4083a2736253c54ca4a9f614bdc14c31306c9a23 (bytes at 0x140001E20).
- **F9.** Callback registration. At 0x14001D05C to 0x14001D066, FUN_14001D010 calls the slot at 0x14001A410 with RDX = device-init and R8 = FUN_1400017B0. R9 is never set, so the call passes two explicit arguments. That matches a caller-context callback registration (inferred: WdfDeviceInitSetIoInCallerContextCallback), not the five-argument WDM preprocess registration. ev_b0599849041178bd4e533c4c07650b662d4caa914c0c1f83d6df5391d4816737 (assembly); ev_b0d50902c100780d393e222438bce901ffaec908fcaef629aefcc43d80e1e219 (xrefs to FUN_1400017B0: 0x14001D05C code, 0x14001C0C0 .pdata).
- **F10.** FUN_1400017B0 (the callback) reads the request parameters. For type 0x0E (IRP_MJ_DEVICE_CONTROL) it switches on the IOCTL. Handled codes: 0x9C422000 to 0x9C422009 (0x9C422001 is a no-op). Default: STATUS_INVALID_DEVICE_REQUEST (0xC0000010), completed in the tail. Codes above 0x9C422800 call FUN_1400026A0 first. Otherwise a zero result forwards the request through the slot at 0x14001A498 (inferred: WdfDeviceEnqueueRequest). ev_530c6617379cb964ed6cb38513b702cc1ddd497bc569cdd2356d05bab6ad16bb.
- **F11.** Default queue (FUN_140002A40): DefaultQueue TRUE, parallel dispatch, EvtIoDeviceControl and EvtIoInternalDeviceControl = FUN_140001670, EvtIoStop = FUN_140001F30 (field positions inferred from the queue-config layout). ev_68e2e5fbc2a8e3119f9877be859916fc4f0c2d94897e4fb5fc46bf97c2230384.
- **F12.** FUN_140001670 (EvtIoDeviceControl shape): codes at or below 0x9C422800 go to FUN_1400022C0, higher codes to FUN_140001F90. FUN_1400022C0 has cases 0x9C422000, 0x9C422004, 0x9C422008 and 0x9C42200C (no-op), and 0x9C422010, 0x9C422014, 0x9C422018, 0x9C42201C, 0x9C422020, 0x9C422024, 0x9C422028, 0x9C42202C, 0x9C422030, 0x9C422034. It has no case for 0x9C422002 or 0x9C422003. ev_604269c82977ab70cda42e82c48bdb01b8217a9bc43b999e97281721a16ccc1c (FUN_140001670); ev_28694b91b0a3dca8a36a5b5f9a5c9ec2e465a9d4bc2de304f2a5cc33d2d49f74 (FUN_1400022C0); ev_af951614939ec56cd1e00c02de0e32cfd655b4d3ca90793b2cfbd8be98d03b45 (FUN_140001F90).
- **F13.** Gate (conditional on F9). The callback has no case for 0x9C42200A through 0x9C4227FF other than 0x9C422000 to 0x9C422009. Under F9, IOCTLs 0x9C422010 to 0x9C422034 are completed with STATUS_INVALID_DEVICE_REQUEST before they reach the queue. Their handlers (FUN_1400046A0, FUN_140004140, FUN_140005DB0, FUN_140003AF0, FUN_140004C60, FUN_140005A00) are therefore unreachable from user mode in this build. ev_530c6617379cb964ed6cb38513b702cc1ddd497bc569cdd2356d05bab6ad16bb.

### 2.4 IOCTL 0x9C422002 and 0x9C422003 (Q2)

- **F14.** 0x9C422002 (OUT_DIRECT; input 8 bytes, output 0x38). The callback calls FUN_140003020 with the input DWORD as the size, the output buffer, and output+8 as the result slot. It then completes the request with information 0x38. It is never queued. ev_530c6617379cb964ed6cb38513b702cc1ddd497bc569cdd2356d05bab6ad16bb (case 0x9C422002); ev_5a67509474a8019d0f36c5cb4874d351bea8954a11897a51e32bf528630b199e (FUN_140003020).
- **F15.** FUN_140003020 steps. (1) Requires non-null driver state and a nonzero size. There is no upper bound; the size is a 32-bit value. (2) FUN_140002B50 calls `MmAllocateContiguousMemorySpecifyCache(size, 0, 0xFFFFFFFFF, 0x4000000, MmCached)` and zeroes the buffer. The physical address goes to a stack slot and is never returned. (3) `IoAllocateMdl(size)`, `MmBuildMdlForNonPagedPool`, then `MmMapLockedPagesSpecifyCache(MDL, UserMode, MmCached, NULL, 0, 0x40000000)` gives a user VA. (4) The triple (kernel VA, user VA, size) is recorded in a 100-entry table, with no MDL. (5) output+0 = status, output+8 = user VA. The caller gets no physical address and no size back. ev_5a67509474a8019d0f36c5cb4874d351bea8954a11897a51e32bf528630b199e; ev_97facc6dcaf808a27743a345c8e4b90cadab8b17799a583f238a50b8164c6468 (FUN_140002B50); ev_0826626fd42321266b0a2c03f4eb67207c420097c995b9d9dc7e541f3a6dff93 (callers of MmAllocateContiguousMemorySpecifyCache: FUN_140002B50 and FUN_140002C30); ev_b95bcab190fb9dfb2c7f6471021337daad785d295ff9f8747488f04d097f2581 (callers of MmMapLockedPagesSpecifyCache: FUN_140003020 and FUN_140006920).
- **F16.** FUN_140003020 has two leak paths. A full table returns 0x8000001A without unmapping or freeing. A failed table lock returns success without recording the entry, so the user VA is handed out but untracked. ev_5a67509474a8019d0f36c5cb4874d351bea8954a11897a51e32bf528630b199e.
- **F17.** 0x9C422003 (NEITHER). The callback calls FUN_140003810, which finds the entry by user VA, calls FUN_140002E20 and clears the entry. FUN_140002E20 contains only a call to MmFreeContiguousMemory (Ghidra printed no arguments). Neither function unmaps the user mapping or frees an MDL. The table holds no MDL, so the mapping from F15 is never removed. ev_df5127f6df89481add181d1d44e4e716d9d37e517b60c6fcd7952ffea3382238 (FUN_140003810); ev_5de8ad71f84ddf1b0aa520e53afcd823c189a3e169021326e1d971a709f494a9 (FUN_140002E20).
- **F18.** FUN_140003810 writes 0 (4 bytes) to its output parameter as its first action (`*param_3 = 0`). For a NEITHER request that parameter comes from WdfRequestRetrieveOutputBuffer. If KMDF returns the raw caller pointer for NEITHER requests, this is an unprobed 4-byte zero write to a caller-chosen address. The function also reads the first input qword through the input pointer. KMDF behaviour is not verified (open item 1). ev_df5127f6df89481add181d1d44e4e716d9d37e517b60c6fcd7952ffea3382238.

### 2.5 Contiguous-buffer overflow (Q2, Q5)

- **F19.** 0x9C422834 (BUFFERED; input 0x20, output 0x158). The preprocessor FUN_1400026A0 probe-locks the caller buffer at input+0x18 with length input+0x10, then replaces the pointer with a kernel VA. FUN_140007A90 allocates 0x9000 bytes (FUN_140002C30, MmNonCached) and calls `FUN_140008740(buffer + 0x8000, locked buffer, *(uint*)(input+0x10))`. Nothing bounds the length. For a length above 0x1000 the copy writes past the 0x9000-byte buffer, by length minus 0x1000 bytes, with caller-chosen bytes. The buffer is then sent to the PSP as command 9 with its physical address and size 0x9000 (F23). ev_7b1476e6658978b52048f1432008df2611001911ab9a9f39ce3f2e404ee44b25 (FUN_140007A90); ev_cd1ea4739a5031ae589f097e6e6c01ce9167cc323412dbff70d522b8bdddee11 (FUN_1400026A0, case 0x9c422834); ev_af951614939ec56cd1e00c02de0e32cfd655b4d3ca90793b2cfbd8be98d03b45 (FUN_140001F90: case 0x9c422834 requires input 0x20 and output 0x158); ev_8594f8ee5a478e1fe80272ff9d51065fed4a2a8c0cf3d7940379996acbd91402 (FUN_140002C30, non-cached allocator).
- Note: FUN_140008740 is treated as `memcpy(dst, src, n)` from its use in several functions. It was not read separately.

### 2.6 Mailbox and PSP paths (Q3)

- **F20.** FUN_140002E50 (read) and FUN_140002EB0 (write) take a register offset. The base comes from the device context: +0x18 holds the device ID, +0x30 the BAR-0 mapping, +0x48 the BAR-1 mapping. For device IDs 0x1456, 0x15DF and 0x1486 the address is BAR-0 + 0x10500 + offset. For other IDs it is BAR-1 + offset. A NULL base returns 0xFFFFFFFF on reads. ev_2209b7c8d12514f4957f1d810810b10ccf3d441f7a4e7f7093fc62b68d19fffb (read); ev_d8f2a6e08c50ea1dbfe0b91f934f41c9ae1e38d52f3fe06871d23b53c7b6e20f (write); ev_00349fddc29e1dce31f61e23a6c1be711dc9865e6fcdba439620993739802877 (search "?? 05 01 00": hits at 0x140002E65 and 0x140002EC5, the 0x10500 adds); ev_e262727b241604d7db9318c7d688a39c31c6edf1e86bb062272d2cfabd157140 (17 write callers); ev_94d5fabc6a6581b264b5a986d5b68c30bb32e52d31aa52554831d9a57182492e (18 read callers).
- **F21.** The BAR mappings come from FUN_14001D590 (MmMapIoSpace, MmNonCached) using the PnP translated resource list. No caller input reaches it. MmMapIoSpace has exactly one caller, FUN_14001D590. Its own caller (the prepare-hardware path, inferred from the callback table in FUN_14001D010) is not traced. ev_92e722279367301002ef29e8354e487959b1c066a92214e12e6905d5348770a3 (FUN_14001D590); ev_1b28bb3c32f07fb45147bfa35ce9918b40cd3e7dfd7462bf301e9d9cb18930bb (callers of MmMapIoSpace).
- **F22.** Register offsets used by all traced writers are constants. Doorbell 0x44 carries a command code in bits 16 to 19: 0x10000, 0x20000, 0x30000, 0x40000, 0x50000, 0x60000, 0x70000, and 0xFF0000 at init. Registers 0x48 and 0x4C carry the physical-address halves of the init ring. Register 0x50 is the ring write index. Registers 0x5C, 0x94, 0x114 and 0x194 are TEE queue indices and acknowledgements. No traced writer takes its offset or value from the caller. Writers: FUN_140003DC0 (init; ev_90ac6c5c7bb863b121543f447543a09c2acbdc637928ed1f5e220d4380cef67d); FUN_140006440 (second init, 0x10000; ev_afd45403bf8d0320b8eb114c497ef481644f33f142f3e1ff953a9754c8d9a662); FUN_140008540 (ring submit, reg 0x50; ev_78154e74f7d70bc9132ae05a4ae0a551775996a67b71d8a7ee9215ac200da62e); FUN_140006060 (0x60000; ev_f6620712b8e3a747c3ef40e07cba69878357c33e0a9d1de68d22a0ee329bade5); FUN_140006350 (teardown, 0x20000; ev_68951322e3c0975d103a143af610129fbd48f4eaabf6e3f99a282811cc695eba); FUN_140006660 (worker; 0x94/0x194; ev_a31a69417106a9053526590719fcd1a271f6330da10880204b88b97c9cf0008e); FUN_140005300 (TEE ISR worker; 0x5C/0x94/0x114; ev_918e2871d283e47cae9a0314e0fe18b1cba490c409cb545117da78d7c7e67182).
- **F23.** Command submission. FUN_140008540 writes a 0x400-byte command into a ring slot and writes the new ring offset to reg 0x50. Its twelve callers are high-range handlers: FUN_140006DC0, FUN_1400071C0, FUN_140007340, FUN_1400074B0, FUN_140007600, FUN_1400077F0, FUN_140007960, FUN_140007A90, FUN_140007CD0, FUN_140007E70, FUN_140007F90, FUN_1400081A0 (ev_4bb3e5e3d6ab9fe37ca9f206c6e6d5e8b96587170811768cf6496e2a6d9761d9; ev_78154e74f7d70bc9132ae05a4ae0a551775996a67b71d8a7ee9215ac200da62e). Command IDs are constants per handler. Caller-supplied words reach command fields as follows.
  - Command 2 (0x9C42280C, FUN_1400081A0): input DWORD at +0 (ev_0660cf16037cf4cf4f6eb12894745ffda346837be30a479d35a9fa1bf3b3d01d).
  - Command 3 (0x9C422810, FUN_140007F90): input DWORD at +0xC is a type map for four 16-byte entries at input+0x10 to +0x4F. Type 1 or 3 copies the entry's 8-byte value raw into the command. Types 5 to 7 treat the entry's qword as a user VA and copy the matched driver-buffer ID. Types C to F dereference the entry's qword as a pointer in kernel mode without a probe, and compare the value. ev_14a1ebdb5caf514a71451539c8c560810e78aa89d4652a8abbda5bd280cb6d72 (FUN_140007F90); ev_7b728f55cafd53c6bd3339c52e3f146b2f7c0e52b75be11c01f8af9a3850220f (helper FUN_1400082B0).
  - Command 4 (0x9C422814, FUN_140007E70): input DWORDs at +0 and +4 (ev_07bb06f926aa782185c1957cc24ee4e6d8d02896c4d54bd04fb037147cb55a33).
  - Command 5 (0x9C422818, FUN_1400071C0): input DWORDs at +0, +4 and +0x54, plus the cmd 3 type-map mechanism (ev_9f52ed22aa6a85da37638461469aa31d1a23683e4616529ee4e240f485299bd1).
  - Command 9 (0x9C422834, FUN_140007A90): first 16 input bytes copied raw, plus the physical address and size 0x9000 of the F19 buffer (ev_7b1476e6658978b52048f1432008df2611001911ab9a9f39ce3f2e404ee44b25).
  - Response: FUN_140006B00 polls for up to about 10 s until response dword +4 equals 2 (ev_29af0ee325f3aa8052025771e4aac67bcb1acb2551a263b6c6b2ce760339beec).
- **F24.** Physical addresses given to the PSP, by IOCTL.
  - 0x9C422000 (FUN_140004880, BUFFERED): the caller's user VA (input+8) must equal a live 0x9C422002 entry whose size is at least input+0. The command carries the physical address of that caller-owned allocation and the size a. Doorbell 0x20000 is written to reg 0x44, then the driver waits. The 16-byte header at input+0x10 selects one of six static entries (static size, copied into a temporary buffer). The header is read as 16 bytes; only a nonzero probed length is checked (F30). ev_5fbe812b089135d54f07aa237023560fcf234ab240274ede2c1d4eadc2483990 (FUN_140004880); ev_530c6617379cb964ed6cb38513b702cc1ddd497bc569cdd2356d05bab6ad16bb (preprocess case 0x9c422000).
  - 0x9C422004 (FUN_1400031F0): tears down a flagged channel and writes doorbell 0x30000. Only the channel index (1 to 16) is caller-controlled. ev_780a75b80aa4c89817f1e60aff54ca71e6cac5ee82efdd3168ef97b32dbed85f.
  - 0x9C422808 (FUN_140007340, BUFFERED, input 0x10): a page-rounded driver buffer receives the caller's data (probe-locked). Its physical address and size go to command 1 (ev_523100dcafcf56d5f39ae47fd4f9221f8ce4c5d8b46efaf7792bb73439c34c2a).
  - 0x9C422820 (BUFFERED, input 0x168, output 0x158): the preprocessor FUN_140006920 allocates a page-rounded NonCached buffer, maps it RW to the caller (MmMapLockedPagesSpecifyCache with UserMode and MmNonCached), stores the MDL and key in a table, and writes the physical address into the input at +0x160 and +0x164 (ev_8d6cf363cdbd288041de47ba995c4f1f6f60d99ed6b5f69daa380846de0ff704). FUN_1400026A0 calls it (ev_acf0c42462897b3bba0f63af983503393bb11d027c549604864d8cc0ffd52c51). FUN_1400074B0 sends command 6 with the physical address and size (ev_295e7ab7be5edb097ce12beca0acf82b3fef110aed32b47105f9494ab7dfe172). The copy-back window is 0x158 bytes, so as far as the file shows the physical address is not returned to the caller. The PSP's response could still echo it.
  - 0x9C422824 (BUFFERED, input 0x170, output 0x158): requires a page-multiple size and a page-aligned caller buffer. FUN_140006F70 builds a PFN list over the caller's locked pages (MmGetPhysicalAddress on the kernel alias) and sends command 6 (ev_0f7a97be04c6895cb7a6a44dd44a9646ea6a3dad8d9e4255c823d316b2fa2d4b; ev_56f11750cd1d722abd2eaa2b6b383fec666a3e24ae97022595bc0206046bff6a). It also writes a driver table slot (0 to 9) into input+0x15C, so the later indexed write is bounded and is not an arbitrary index. The PSP receives the physical pages behind a caller-selected virtual range; the caller already has access to those pages.
- **F25.** The PSP's meaning of raw words is not in the file. Under F23 and F24, the only physical ranges the driver gives the PSP are driver-owned allocations or the caller's own pinned pages. Raw caller words (commands 2, 3, 4, 5 and 9) are not resolved by the driver. Whether the PSP reads or writes any of them as an address is PSP firmware behaviour and cannot be shown in the file.

### 2.7 Other facts

- **F26.** 0x9C422002 and 0x9C422003 never reach the mailbox. FUN_140003020 and FUN_140003810 call no mailbox routine (F15, F17).
- **F27.** Privilege checks. The only `Se` import is KeSetEvent. The only `Ps` imports are PsCreateSystemThread and PsTerminateSystemThread. No PsGetCurrentProcess, SeAccessCheck, SeSinglePrivilegeCheck or token call is imported. No requestor-mode or token check was found in the traced functions. A WDF requestor-mode call, if present, is unnamed. ev_eef768653df64eae3a5ef43d470acbc30fd63794c3bc11fb5a0a7873cf520b7b (Se); ev_0a6455e0c6ad545b844f37a2b079c43078361db25d32b2c53fa6c1887515dc44 (Ps); ev_c8dbf112f9817e86655c9f55319b4b799ecee32794d8985e8c5a703d61156c8d (Mm imports).
- **F28.** The "DrIntegrationTest" strings (0x14000BEF0, 0x14000DAD0) have no xrefs in REA's output, and no analysed code references them. ev_992ecd17279772e1cd081984bae1df5929e6995ec99c1ec48a5f497809bb7e3b; ev_c641161cd0d958c3ab4d63a9e91c773d05c54195f83149d39baf09a68434baa1 (xrefs 0x14000BEF0, none); ev_df5f888192d123567a9bda0b5616a77acce32053b2a06f7ff9964393a876cded (xrefs 0x14000DAD0, none).
- **F29.** No event or audit logging on the traced IOCTL paths. DbgPrintEx appears only in TEE paths (FUN_140005300 and FUN_140004C60). ev_918e2871d283e47cae9a0314e0fe18b1cba490c409cb545117da78d7c7e67182 (FUN_140005300); ev_d74bd83b52810ebd9f54f68a05890c473b4be260adfcb419c825238ea02e758b (FUN_140004C60).
- **F30.** Handlers unreachable under F9, recorded for the case where F9 is wrong. 0x9C422028 (FUN_140004C60) uses the unprobed input pointer input+0x18 as the source of a kernel memcpy, with caller length input+8, into a PSP-bound buffer (ev_d74bd83b52810ebd9f54f68a05890c473b4be260adfcb419c825238ea02e758b). 0x9C422030 (FUN_140005A00) has no size cap and copies the result back to the caller (ev_a3a82b5c9eb1315fc76099ca2c0d0d26a3c7325d58b26a9024dc5b1296ff9a3b). 0x9C422018 (FUN_140004140) caps the size at 1 MiB (ev_89342c966e335a36e12d6d7652fb1e43b3e3b4159d02b2deaa8698816a872365). 0x9C422010 (FUN_1400046A0) and 0x9C42201C (FUN_140005DB0) work on channel buffers (ev_6144052e6108d9f0d735d243836eb71f5ef591d7c88debbe2bece63b51663230; ev_b3b4bb091dc8b9d1fb7f85c6acd153d58e33b8bc86d2c736a4668f78a09f628a). 0x9C422020 (FUN_140003AF0) rings doorbell 0x10000 (ev_88df091c2843d011c3c43602ae440cbdbc65159525504b6274e36d129102b842). Also: the 0x9C422000 header is read as 16 bytes when the probed length may be 1 to 15 (minor over-read).
- **F31.** Teardown helper FUN_140006350 frees driver state (ExFreePoolWithTag, tag 0x454554) and rings doorbell 0x20000 (ev_68951322e3c0975d103a143af610129fbd48f4eaabf6e3f99a282811cc695eba). Its callers are not traced.
- **F32.** 0x9C422002 output: the user VA is at output+8. The mapping is a UserMode MDL mapping with no protection argument; read-write is expected, not verified. Size and physical address are not returned.
- **F33.** 0x9C422828 (FUN_140007960) is gated by FUN_140006D20 (not traced) and sends command 7 (ev_7dce355835331458e987bd3359b3f4d37110922aab1c1a3b620457b6224e6b07).

---

## 3. Corrections to the earlier report

1. **"IOCTL 0x9C422002 returns the physical address."** Incorrect. It returns a status (output+0) and the user VA (output+8). The physical address is computed and discarded (F15). The physical address reaches the PSP only through commands (F24).
2. **"0x9C422002 maps read-write into the caller."** Partly correct. The mapping is a UserMode MDL mapping; read-write is expected but not verified in the file (F32).
3. **"Allocates contiguous memory of a caller-chosen size."** Correct. The size is a 32-bit value from input+0, checked only for zero (F15).
4. **"IOCTL 0x9C422002."** The case exists in the decompiled callback (F10, F14). The code is not a literal in the binary (F7), so it was found through the jump table, not a literal search.
5. **"A kernel write through the PSP mailbox is untraced."** Not supported as stated. No traced mailbox writer takes a caller-chosen offset or value (F22). 0x9C422002 never reaches the mailbox (F26). "Untraced" cannot be checked in the file, and the IOCTL paths contain no logging (F29).
6. **Import name.** The import is MmAllocateContiguousMemorySpecifyCache, used with MmCached (FUN_140002B50) and MmNonCached (FUN_140002C30). Not MmAllocateContiguousMemory (F15, F19).
7. **"Everyone-writable SDDL."** Correct as to ACE content (F2, F3). It applies to the named device `\Device\amdpsp` (F5). "Writable" means generic write on the device object.
8. **Most serious primitives.** The earlier report named the wrong ones. The in-file primitives of concern are the overflow in 0x9C422834 (F19), the live user mapping after free (F17), and the possible zero write in 0x9C422003 (F18).

---

## 4. Reachability

**Proven in the file**

- Device name, DosDevices link, SDDL and its DACL content (F2 to F5).
- Device creation through FUN_14001D010 and FUN_14001D1E0 (F5, F6).
- Dispatch chain for 0x9C422000 to 0x9C422009 and for codes above 0x9C422800, and the gate for the rest (F8 to F13).
- Input and output lengths each handler requires (F14, F19, F24).
- Access checks: none on the traced paths (F27).

**Needs VM verification**

- The device object exists on a running system, and the SDDL is applied to the named object (the triage state shows the driver loaded; device creation is PnP-driven; the SDDL-to-object step is KMDF runtime behaviour).
- Effective access for a standard token.
- That the slot at 0x14001A410 is the caller-context callback registration (F9). This decides the gate in F13.
- KMDF behaviour for NEITHER requests (F18).
- Whether MmFreeContiguousMemory with a live user mapping leaves the mapping valid (F17), and whether the mapping is writable (F32).
- What follows the 0x9000-byte contiguous buffer (F19).
- PSP interpretation of raw words and physical ranges (F25).

**Gating note.** Under F9, IOCTLs 0x9C422010 to 0x9C422034 are unreachable from user mode. If F9 is wrong, the handlers in F30 become live. 0x9C422028 is the one that dereferences an unprobed caller pointer as a copy source.

---

## 5. Severity rationale

**(a) Unprivileged user can open the device: WRITE-HIGH (candidate)**

- Reach: any token holding a handle (WD GRGWGX). No privilege check on the traced paths (F27). The overflow needs only a probe-able user buffer longer than 0x1000 bytes, so no special privilege is needed (F19).
- Strength: caller-chosen bytes written past a driver-owned contiguous buffer, with a caller-chosen length. Placement is not controlled in the file, so this is not an arbitrary-address write. That is why it stays HIGH and is not CRITICAL.
- Lifetime: a live user RW mapping of freed pages (F17). If the kernel reuses those pages, the caller can write kernel data. This depends on OS behaviour, so it is a HIGH candidate.
- Pending: F18. If KMDF passes raw pointers for NEITHER requests, IOCTL 0x9C422003 becomes a 4-byte zero write to any caller-chosen address. That is CRITICAL.

**(b) Only administrators can open the device: WRITE-MEDIUM**

- Reach: administrators only. An administrator can already load kernel-mode code, so no privilege boundary is crossed (F19, F17 apply unchanged).
- The defects remain memory-safety bugs and should be fixed. They are not elevation-of-privilege findings in this configuration.

**What would change the ratings**

- To WRITE-CRITICAL for (a): F18 confirmed (raw pointer); or the overflow destination shown to be an attacker-steerable kernel object; or PSP firmware shown to write to physical addresses from raw caller words (F25).
- To WRITE-MEDIUM for (a): the DACL shown not to apply to the device object at runtime (then the device is admin-only in practice); or the post-free mapping shown to be torn down by the OS and the overflow shown to hit only unmapped memory (crash only, no corruption).
- The overflow stays in the file as an unbounded copy regardless of these checks, so the rating cannot drop below HIGH for (a) unless the device is shown to be unreachable.

---

## 6. Open items

1. **KMDF NEITHER retrieval (F18). Highest impact.** Confirm whether WdfRequestRetrieveOutputBuffer and WdfRequestRetrieveInputBuffer return the raw caller pointer for METHOD_NEITHER. If they do, IOCTL 0x9C422003 is an arbitrary 4-byte zero write.
2. **Overflow in 0x9C422834 (F19).** Destination adjacency, whether an attacker can steer the placement, and the crash versus corruption outcome for lengths above 0x1000.
3. **Post-free mapping (F17, F32).** Whether the user mapping survives MmFreeContiguousMemory, and whether it is writable.
4. **Runtime DACL and effective access (F2 to F5).** Whether the WD ACE is applied to the device object, and what a standard token gets.
5. **Gate identity (F9, F13).** Confirm that the slot at 0x14001A410 is the caller-context callback. If it is not, the low-range handlers in F30 are live.
6. **PSP semantics (F23 to F25).** Whether command fields 2, 3, 4, 5 and 9 raw words, and the physical ranges in commands 1, 6 and 9, are read or written by the PSP as addresses.
7. **Untraced handlers and helpers.** IOCTLs 0x9C422014 (FUN_140006190), 0x9C422024, 0x9C42202C (FUN_140003910), 0x9C422034 (FUN_1400037C0), 0x9C422804 (FUN_140007600), 0x9C422830 (FUN_140006DC0), 0x9C422838 (FUN_140006B70), 0x9C42283C (FUN_140007CD0), 0x9C422844 (FUN_140007130). Helpers FUN_140006D20 (gate for 0x9C422828), FUN_1400080E0, FUN_140007310, FUN_140002DC0, FUN_140002D10, FUN_140002D30 and FUN_140001450 (interrupt callback, inferred; not traced).
8. **Requestor-mode check.** Scan the untraced handlers for an unnamed WDF requestor-mode call.
9. **Unresolved callers.** FUN_14001D590 (prepare-hardware path), FUN_140006350 (teardown), FUN_140001450 and FUN_140004500 (TEE trace) are not traced.
10. **Minor defects.** 0x9C422000 header over-read when the probed length is 1 to 15 (F30). FUN_140003020 leaks on a full table and hands out an untracked mapping on lock failure (F16). FUN_140008740 treated as memcpy (section 2.5 note).

---

## 7. VM verification plan (orchestrator-owned; not run)

Principle: static checks first, then read-only checks in an isolated VM, then benign IOCTLs, and only then anything that can crash the system. Nothing here has been run, and nothing is to be run on this host.

**Stage 0. Static (no execution)**
- Identify the KMDF version. Map the slots 0x14001A410, 0x14001A498 and 0x14001AA28/AA30/AA70/AA78 to KMDF function names using the matching headers. Confirm the caller-context callback and the retrieve semantics for NEITHER requests (open items 1 and 5).
- Read the KMDF documentation for WdfRequestRetrieveInputBuffer and WdfRequestRetrieveOutputBuffer on METHOD_NEITHER.

**Stage 1. VM, read-only (no IOCTLs)**
- Load the driver in a clean snapshot VM. From a host kernel debugger, read the device object's security descriptor and the symbolic link (object and security queries only). Expected result: an Everyone GR|GW|GX entry (open item 4).
- Log on as a standard user and confirm that CreateFile on `\\.\amdpsp` succeeds. Send no DeviceIoControl.

**Stage 2. VM, benign IOCTLs (user-owned buffers only)**
- Send 0x9C422003 with a user buffer owned by the test process. Break on FUN_140003810 and record whether it runs and what the output pointer equals. Do not use kernel addresses at this stage.
- Send 0x9C422002 with size 0x1000. Confirm that the output holds a user VA and no physical address. Then send 0x9C422003 with that VA, and inspect the VAD and PTE of the user VA (`!vad`, `!pte`) to see whether the mapping remains (open item 3).

**Stage 3. Sacrificial VM, debugger attached, orchestrator approval required**
- Overflow adjacency (open item 2): with a known memory layout and a sentinel pattern placed after the 0x9000-byte buffer, send 0x9C422834 with a length of 0x1100 and inspect the adjacent bytes. Escalate only with approval.
- Kernel-address zero write (open item 1), only if Stage 2 shows that raw pointers reach the handler: one 4-byte write to a sentinel kernel address, then revert the snapshot. Orchestrator decision.

**Stage 4. PSP behaviour**
- Whether the PSP reads or writes physical ranges or raw command words (open item 6) needs PSP-side tracing that a standard VM cannot provide. Mark as not verifiable with this setup.

---

## 8. Evidence list

Every ID below is the `evidence_id` returned by REA in this session for the query named. Procedures re-queried for this final pass (0x140002E50, 0x140002EB0, 0x140007E70, 0x140007A90, 0x140003810, 0x140003AF0, 0x140006350) were checked against their latest responses. Entries for `open_binary`, `Get-FileHash` and the triage Grep returned no evidence_id.

- ev_5999fca3a5062e9e6d21e81d2c07f59f81f06f10d74df4044b44745e1c204f18: search_strings "(A;" (SDDL at 0x140009210) (F2, F3)
- ev_992ecd17279772e1cd081984bae1df5929e6995ec99c1ec48a5f497809bb7e3b: search_strings "D:" (SDDL; DrIntegrationTest strings) (F2, F28)
- ev_4bfa2462d2fb7d7cbb3fc7d55f03d876b78cc12c84d1eab9ffc2c492cd436354: search_strings "Device" (device name, symlink, DEVICE_CONTEXT) (F4)
- ev_9dbc85c7d10852c4872230bdc4ae7c2ad2991a55caef1fdb7c204eab2b73682e: xrefs 0x140009210, to 0x14001D2CB (F5)
- ev_9f73ba495ba2524fe2be2204b90f5b833a94c4a55fef2b92d704fa1d21de4911: xrefs 0x1400091F0, to 0x14001D229 (F5)
- ev_95703b60da4c46efb42d0149a1283fd99abe12b2a5e1c634aaae495a3df04b38: xrefs 0x140009290, to 0x14001D397 (F5)
- ev_9e9413d570b64260d0780fbba990ea48fac8aa457bcd191137478781a36e4487: resolve 0x14001D2CB, gives FUN_14001D1E0 (F5)
- ev_9825108a2660357fb941720419ff9e5e7fcfd205d0419194401e5ec05dba7d64: resolve 0x14001D229 (F5)
- ev_98428ac6e4432439025bbd4b55a9da33a29b33b2bceb4b40346fd3b91e38be04: resolve 0x14001D397 (F5)
- ev_128edec4fb9476d7d0f9679d605d0ee318fdabbd2d4d76644960d2763f4b8735: pseudocode FUN_14001D1E0 (F5)
- ev_d7e54d3446babb2437e80a4dee2503fc5b2736ef613f903de577588c990e48be: callers of FUN_14001D1E0, gives 0x14001D010 (F6)
- ev_ff66a39fd44a4a146abe5af52e72e4efebe3ddac50f1d0812f1fc2f9f1c57406: pseudocode FUN_14001D010 (F6, F9)
- ev_b0599849041178bd4e533c4c07650b662d4caa914c0c1f83d6df5391d4816737: assembly FUN_14001D010 (F9)
- ev_68e2e5fbc2a8e3119f9877be859916fc4f0c2d94897e4fb5fc46bf97c2230384: pseudocode FUN_140002A40, default queue (F11)
- ev_eef768653df64eae3a5ef43d470acbc30fd63794c3bc11fb5a0a7873cf520b7b: search_procedures "Se" (case-sensitive): KeSetEvent only (F27)
- ev_0a6455e0c6ad545b844f37a2b079c43078361db25d32b2c53fa6c1887515dc44: search_procedures "Ps": PsCreateSystemThread, PsTerminateSystemThread (F27)
- ev_c8dbf112f9817e86655c9f55319b4b799ecee32794d8985e8c5a703d61156c8d: search_procedures "Mm": imports (F15, F27)
- ev_46c644826214bbe5eb90e549c1662f415befb98e85ae0ef3434eb64365641bbb: search_bytes "02 20 42 9C", no match (F7)
- ev_b1d9289b0f8ee81266b07f8948c78e05f96282dc0325d6d9fafb101e0812d909: search_bytes "00 20 42 9C", no match (F7)
- ev_32ed281f0fc36ed380cacfa6b0ebc4eb47a060f91a8bc6d68a07679b1b7e9e05: search_bytes "42 9C": hits 0x14000174C, 0x140001E42 (F8)
- ev_9751aec2a7f108b5b01495a486b96ce39f0cd1f70b3f6b95adaaba257cab0aa7: read_bytes 0x140001730, compare at 0x140001748 (F8)
- ev_dfe7b9a21003093e2f68695f4083a2736253c54ca4a9f614bdc14c31306c9a23: read_bytes 0x140001E20, compare at 0x140001E3D (F8)
- ev_604269c82977ab70cda42e82c48bdb01b8217a9bc43b999e97281721a16ccc1c: pseudocode FUN_140001670 (F12)
- ev_f995b1e596589e7a7bdc2b7db1ea9780e697056ed36c351aa938a5fb36569fde: callers of FUN_140001670, none resolved (F11, F12)
- ev_45ef3cfb07dbf4c0a3b6829c61a1b5255d07c44a3cb31074732816857c7b492c: xrefs 0x140001670 (FUN_140002A40 references) (F11)
- ev_530c6617379cb964ed6cb38513b702cc1ddd497bc569cdd2356d05bab6ad16bb: pseudocode FUN_1400017B0, callback (F10, F13, F14, F18, F19, F24)
- ev_b0d50902c100780d393e222438bce901ffaec908fcaef629aefcc43d80e1e219: xrefs 0x1400017B0 (F9)
- ev_cd2fb74274018cdd9e21aa0eb1253dcf256b409da1d0efe0536bfac6769f5389: callers of FUN_1400017B0, none resolved (F9)
- ev_28694b91b0a3dca8a36a5b5f9a5c9ec2e465a9d4bc2de304f2a5cc33d2d49f74: pseudocode FUN_1400022C0 (F12, F13)
- ev_af951614939ec56cd1e00c02de0e32cfd655b4d3ca90793b2cfbd8be98d03b45: pseudocode FUN_140001F90 (F12, F19, F24)
- ev_cd1ea4739a5031ae589f097e6e6c01ce9167cc323412dbff70d522b8bdddee11: pseudocode FUN_1400026A0, preprocess (F19, F24)
- ev_5a67509474a8019d0f36c5cb4874d351bea8954a11897a51e32bf528630b199e: pseudocode FUN_140003020 (F14, F15, F16)
- ev_97facc6dcaf808a27743a345c8e4b90cadab8b17799a583f238a50b8164c6468: pseudocode FUN_140002B50 (F15)
- ev_8594f8ee5a478e1fe80272ff9d51065fed4a2a8c0cf3d7940379996acbd91402: pseudocode FUN_140002C30 (F19)
- ev_0826626fd42321266b0a2c03f4eb67207c420097c995b9d9dc7e541f3a6dff93: callers of MmAllocateContiguousMemorySpecifyCache (F15)
- ev_b95bcab190fb9dfb2c7f6471021337daad785d295ff9f8747488f04d097f2581: callers of MmMapLockedPagesSpecifyCache (F15)
- ev_1b28bb3c32f07fb45147bfa35ce9918b40cd3e7dfd7462bf301e9d9cb18930bb: callers of MmMapIoSpace, gives FUN_14001D590 (F21)
- ev_92e722279367301002ef29e8354e487959b1c066a92214e12e6905d5348770a3: pseudocode FUN_14001D590 (F21)
- ev_df5127f6df89481add181d1d44e4e716d9d37e517b60c6fcd7952ffea3382238: pseudocode FUN_140003810 (F17, F18)
- ev_5de8ad71f84ddf1b0aa520e53afcd823c189a3e169021326e1d971a709f494a9: pseudocode FUN_140002E20 (F17)
- ev_8d6cf363cdbd288041de47ba995c4f1f6f60d99ed6b5f69daa380846de0ff704: pseudocode FUN_140006920 (F24)
- ev_acf0c42462897b3bba0f63af983503393bb11d027c549604864d8cc0ffd52c51: callers of FUN_140006920, gives FUN_1400026A0 (F24)
- ev_295e7ab7be5edb097ce12beca0acf82b3fef110aed32b47105f9494ab7dfe172: pseudocode FUN_1400074B0, command 6 (F24)
- ev_7b1476e6658978b52048f1432008df2611001911ab9a9f39ce3f2e404ee44b25: pseudocode FUN_140007A90, overflow (F19, F23)
- ev_0f7a97be04c6895cb7a6a44dd44a9646ea6a3dad8d9e4255c823d316b2fa2d4b: pseudocode FUN_1400077F0 (F24)
- ev_56f11750cd1d722abd2eaa2b6b383fec666a3e24ae97022595bc0206046bff6a: pseudocode FUN_140006F70, PFN list and slot (F24)
- ev_523100dcafcf56d5f39ae47fd4f9221f8ce4c5d8b46efaf7792bb73439c34c2a: pseudocode FUN_140007340 (F24)
- ev_7dce355835331458e987bd3359b3f4d37110922aab1c1a3b620457b6224e6b07: pseudocode FUN_140007960 (F33)
- ev_2209b7c8d12514f4957f1d810810b10ccf3d441f7a4e7f7093fc62b68d19fffb: pseudocode FUN_140002E50, mailbox read (F20)
- ev_d8f2a6e08c50ea1dbfe0b91f934f41c9ae1e38d52f3fe06871d23b53c7b6e20f: pseudocode FUN_140002EB0, mailbox write (F20)
- ev_00349fddc29e1dce31f61e23a6c1be711dc9865e6fcdba439620993739802877: search_bytes "?? 05 01 00", hits in FUN_140002E50 and FUN_140002EB0 (F20)
- ev_1f35f95d922320eadb7e63bc5452e0f10145efe3f1050c9c89c82a3021f3aa4f: search_bytes "00 05 B1 03", no match (F20)
- ev_e262727b241604d7db9318c7d688a39c31c6edf1e86bb062272d2cfabd157140: callers of FUN_140002EB0, 17 (F20)
- ev_94d5fabc6a6581b264b5a986d5b68c30bb32e52d31aa52554831d9a57182492e: callers of FUN_140002E50, 18 (F20)
- ev_ae562765216f8add79eea7e2b3c082278ba55b9a4fa64f7bf6e3bbfdcbd10f2f: callers of FUN_140002E20, 16
- ev_5fbe812b089135d54f07aa237023560fcf234ab240274ede2c1d4eadc2483990: pseudocode FUN_140004880, 0x9C422000 path (F24, F26)
- ev_780a75b80aa4c89817f1e60aff54ca71e6cac5ee82efdd3168ef97b32dbed85f: pseudocode FUN_1400031F0, 0x9C422004 path (F24)
- ev_90ac6c5c7bb863b121543f447543a09c2acbdc637928ed1f5e220d4380cef67d: pseudocode FUN_140003DC0, init ring (F22)
- ev_afd45403bf8d0320b8eb114c497ef481644f33f142f3e1ff953a9754c8d9a662: pseudocode FUN_140006440, second init (F22)
- ev_78154e74f7d70bc9132ae05a4ae0a551775996a67b71d8a7ee9215ac200da62e: pseudocode FUN_140008540, ring submit (F22, F23)
- ev_4bb3e5e3d6ab9fe37ca9f206c6e6d5e8b96587170811768cf6496e2a6d9761d9: callers of FUN_140008540, 12 (F23)
- ev_14a1ebdb5caf514a71451539c8c560810e78aa89d4652a8abbda5bd280cb6d72: pseudocode FUN_140007F90, command 3 (F23)
- ev_9f52ed22aa6a85da37638461469aa31d1a23683e4616529ee4e240f485299bd1: pseudocode FUN_1400071C0, command 5 (F23)
- ev_07bb06f926aa782185c1957cc24ee4e6d8d02896c4d54bd04fb037147cb55a33: pseudocode FUN_140007E70, command 4 (F23)
- ev_0660cf16037cf4cf4f6eb12894745ffda346837be30a479d35a9fa1bf3b3d01d: pseudocode FUN_1400081A0, command 2 (F23)
- ev_7b728f55cafd53c6bd3339c52e3f146b2f7c0e52b75be11c01f8af9a3850220f: pseudocode FUN_1400082B0, type-map helper (F23)
- ev_29af0ee325f3aa8052025771e4aac67bcb1acb2551a263b6c6b2ce760339beec: pseudocode FUN_140006B00, response poll (F23)
- ev_f6620712b8e3a747c3ef40e07cba69878357c33e0a9d1de68d22a0ee329bade5: pseudocode FUN_140006060, TEE log (F22)
- ev_a31a69417106a9053526590719fcd1a271f6330da10880204b88b97c9cf0008e: pseudocode FUN_140006660, worker (F22)
- ev_918e2871d283e47cae9a0314e0fe18b1cba490c409cb545117da78d7c7e67182: pseudocode FUN_140005300, TEE ISR worker (F22, F29)
- ev_68951322e3c0975d103a143af610129fbd48f4eaabf6e3f99a282811cc695eba: pseudocode FUN_140006350, teardown (F22, F31)
- ev_88df091c2843d011c3c43602ae440cbdbc65159525504b6274e36d129102b842: pseudocode FUN_140003AF0, unreachable under F9 (F30)
- ev_6144052e6108d9f0d735d243836eb71f5ef591d7c88debbe2bece63b51663230: pseudocode FUN_1400046A0, unreachable under F9 (F30)
- ev_89342c966e335a36e12d6d7652fb1e43b3e3b4159d02b2deaa8698816a872365: pseudocode FUN_140004140, unreachable under F9 (F30)
- ev_b3b4bb091dc8b9d1fb7f85c6acd153d58e33b8bc86d2c736a4668f78a09f628a: pseudocode FUN_140005DB0, unreachable under F9 (F30)
- ev_a3a82b5c9eb1315fc76099ca2c0d0d26a3c7325d58b26a9024dc5b1296ff9a3b: pseudocode FUN_140005A00, unreachable under F9 (F30)
- ev_d74bd83b52810ebd9f54f68a05890c473b4be260adfcb419c825238ea02e758b: pseudocode FUN_140004C60, unreachable under F9, DbgPrintEx (F29, F30)
- ev_c641161cd0d958c3ab4d63a9e91c773d05c54195f83149d39baf09a68434baa1: xrefs 0x14000BEF0, none (F28)
- ev_df5f888192d123567a9bda0b5616a77acce32053b2a06f7ff9964393a876cded: xrefs 0x14000DAD0, none (F28)
