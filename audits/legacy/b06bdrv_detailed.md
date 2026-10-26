# b06bdrv (bxvbda.sys): detailed memory-write audit

Scope: static analysis only. Nothing was loaded, no device was opened, no IOCTL was sent, and nothing was run on this host beyond reading REA results and the target bytes. Target SHA-256 was verified before analysis: REA reports feb2771428706126fea1cc9a50ebe3cf4f8e8fb6fcb3ca19996497ca44fdac45, which matches the expected digest, and a local Get-FileHash agrees.

Names: FUN_xxxxxxxx are Ghidra names. WDF calls are identified by table offset (for example 0x868). The WDF names used below are inferred from argument shape and are not confirmed against KMDF headers.

Structures used below:
- devctx: the WDF device context (0x9380 bytes, from the WdfDeviceCreate attributes).
- core: devctx+0x10, the first argument of FUN_14000479C.
- adapter: pool+0x10 of a 0x21E90-byte NonPagedPoolNx object. Its pointer is stored at core+0x30 (that is, devctx+0x40). BAR_base = adapter+0x38.

## 1. Summary

| Case | All verified write primitives (driver level) | Claimed 0x80002024 BAR write alone |
|---|---|---|
| (a) unprivileged user can open the device | WRITE-CRITICAL (conditional; reachability is not proven in-file) | WRITE-HIGH |
| (b) administrators only | WRITE-HIGH | WRITE-MEDIUM |

- Rating change: RAISE the earlier WRITE-HIGH at driver level. The claimed 0x80002024 primitive is confirmed exactly. The earlier report missed IOCTL 0x8000203C, which writes count dwords of attacker data to a 64-bit kernel address taken from the input buffer, with only count, length and 4-byte alignment checks (V20). The same unauthenticated dispatcher also has 0x80002038, a kernel read from a caller-supplied address (V21), and 0x80002050, which returns the adapter's kernel address (V22).
- Reachability is the open question. The binary has no identity check, no SDDL, and no security API on the IOCTL path (V8, V35-V38). The effective ACL of the device is set outside the binary, so case (a) versus case (b) needs the VM check in section 7.
- Every dispatched IOCTL goes through one queue and one function (FUN_14000479C), so reachability is the same for all of them.

## 2. Verified facts

- V1. Target identity: REA sha256 = FEB2771428706126FEA1CC9A50EBE3CF4F8E8FB6FCB3CA19996497CA44FDAC45 (matches); local Get-FileHash identical. open_binary returned no evidence_id; the subject digest is in ev_186a25a0db20ca168226e5e1074e67fa5fa7f0886629510e073f8d6da8b79805.
- V2. The 0x80002024 constant occurs once in initialized memory, as the imm32 of `MOV ECX,0x80002024` at 0x1400047DF (imm at 0x1400047E0), inside FUN_14000479C (0x14000479C). Evidence: ev_186a25a0db20ca168226e5e1074e67fa5fa7f0886629510e073f8d6da8b79805; ev_7a64cedd84dc352c37b6505ef9ffe2c017b8089d50899d03940e3718a338d45c.
- V3. Case dispatch for 0x80002024: `CMP EAX,ECX` at 0x1400047E4, `JZ 0x140004D29` at 0x1400047EC; case body 0x140004D29-0x140004DBC. Evidence: ev_7a64cedd84dc352c37b6505ef9ffe2c017b8089d50899d03940e3718a338d45c; ev_558e91326af00362ac961d4463cb48c7dc9176377a10dfb4cabfd93b816ce6ce (pseudo, lines 552-577).
- V4. FUN_14000479C has one direct caller: FUN_1400017A8 (0x1400017A8). Evidence: ev_327107db61feeb876b91e049dbe4b46b883e93de6b594f0f1e39e37a8567b5f5.
- V5. FUN_1400017A8 returns 0xC0000010 unless core[0] == 0, and 0xC000000E unless devctx+0x14 is 1, 2 or 4. It then calls FUN_14000479C(core, request, outLen, inLen, IoControlCode, &info) with the IoControlCode unchanged. No identity check. Evidence: ev_a26ba713067c768a9e250b68ed0103dab4782efeaa76c6dd69b7cc2364c36e56.
- V6. Queue setup in FUN_140001228: the queue config (0x60 bytes) is zeroed at 0x140001548-0x14000154E; FUN_1400017A8 is written at config+0x28 (`MOV [RBP+0x98],RAX`, 0x14000156A); config+0x00 = 0x60, +0x04 = 1, +0x08 = 2, +0x0D = 1; WdfIoQueueCreate (table 0x4C0) is called at 0x140001596. This is the only handler slot written. Naming config+0x28 as EvtIoDeviceControl relies on WDF_IO_QUEUE_CONFIG member order (inference; see section 6). Evidence: ev_51c2e4bd45eb91f46ea7827611281aa34db5842ca8c3ac16a9fa189df6cb1673; ev_5864987d8dd1a2e2c4403eed4fc7b569e3bf12a8ea0b7b5b0d37724efba7371b; ev_fed4368e87359748e60451bbc30933acb61cce2ad7acfbe9995c83486132df6d (refs at 0x140001558 and 0x14000156A; 0x140082024 is a .pdata entry, not a call).
- V7. Device interface: WdfDeviceCreateDeviceInterface (table 0x268) at 0x14000164D, with the GUID pointer `LEA R8,[0x1400372E0]` at 0x140001629 and a NULL reference string (`XOR R9D,R9D` at 0x140001637). Evidence: ev_51c2e4bd45eb91f46ea7827611281aa34db5842ca8c3ac16a9fa189df6cb1673; ev_5864987d8dd1a2e2c4403eed4fc7b569e3bf12a8ea0b7b5b0d37724efba7371b.
- V8. Device appears unnamed: WdfDeviceCreate (table 0x258, call at 0x1400014D8, ContextSizeOverride 0x9380). No call before it passes a 16-byte UNICODE_STRING-shaped argument (calls 0x210, 0x1F0, 0x1B8, 0x1C0, 0x400, 0x248, 0x410, 0x1E8). No symbolic-link call appears after it (calls 0x188 x3, 0x4C0, 0x650, 0xF8, 0x108, 0x268, 0x170). Evidence: ev_51c2e4bd45eb91f46ea7827611281aa34db5842ca8c3ac16a9fa189df6cb1673; ev_5864987d8dd1a2e2c4403eed4fc7b569e3bf12a8ea0b7b5b0d37724efba7371b.
- V9. FUN_1400019E4 is an IRP_MJ_POWER preprocess callback, not a file-create callback: `LEA R8,[0x1400019E4]` at 0x1400013E1, `MOV R9B,0x16` at 0x1400013EE, table call 0x248 at 0x140001404 (WdfDeviceInitAssignWdmIrpPreprocessCallback by shape). Its body tests MinorFunction == 2 (IRP_MN_SET_POWER) and the Parameters.Power fields (+0x10, +0x18, +0x20) and forwards through table 0x110. It makes no identity call. Evidence: ev_51c2e4bd45eb91f46ea7827611281aa34db5842ca8c3ac16a9fa189df6cb1673; ev_043d69742f19817ef3266028d5499c63cbdd8f4ee21f7b898146dff3307f92ce; ev_f4ebea9a9547414dd1157081581fa9ac3f9a4b23327bab40e66c2ea30d524535; ev_974f70a081af2d12da7699ee3ac3d65d3c3405aa0c6098476288be94facc9b42.
- V10. The 0x20-byte, three-callback struct registered via table 0x400 (0x14000139B-0x1400013D6) holds FUN_140002DB8 at +8, FUN_140003144 at +0x10, and LAB_140003078 at +0x18. FUN_140002DB8 works on IO resource requirement descriptors (interrupt-type filter, append via table 0x940), so it is not a create handler. Evidence: ev_51c2e4bd45eb91f46ea7827611281aa34db5842ca8c3ac16a9fa189df6cb1673; ev_a4e4b7f2a6c7d63271b17296a16cba25a14cd62ad55873c25e7ceba574e6c27f.
- V11. No IRP_MJ_CREATE handler is identified in-file (V9, V10). The only WDM preprocess registration is the MajorFunction 0x16 call at 0x140001404. Evidence: ev_51c2e4bd45eb91f46ea7827611281aa34db5842ca8c3ac16a9fa189df6cb1673.
- V12. Guards for 0x80002024, instruction level: input retrieved with minimum length 0x10 (`MOV R8D,0x10` at 0x140004D44; table 0x868 call at 0x140004D4A); count = [in+8] (0x140004D60); offset = [in+0] (0x140004D68). count == 0 fails (0x140004D6B-0x140004D6E). count*4 > inLen-0xC fails (`LEA ECX,[RDX-0xC]` at 0x140004D77, `CMP RAX,RCX` at 0x140004D81, `JA` at 0x140004D84). offset & 3 fails (`TEST R8B,3` at 0x140004D8A, `JNZ` at 0x140004D8E). Evidence: ev_7a64cedd84dc352c37b6505ef9ffe2c017b8089d50899d03940e3718a338d45c.
- V13. The write, instruction level: loop 0x140004D9D-0x140004DBA. `MOV RAX,[R14+0x38]` loads BAR_base (R14 = adapter). Data is `MOV EDX,[R10]` (R10 = in+0xC+4i). The offset is zero-extended into RCX. `MOV dword ptr [RCX+RAX*1],EDX` at 0x140004DA7 is the store. `ADD R8D,4` at 0x140004DAE is 32-bit (offset wraps mod 2^32). Count is in R11, decremented at 0x140004DB6. Effective address = BAR_base + zext32(offset + 4i). Evidence: ev_7a64cedd84dc352c37b6505ef9ffe2c017b8089d50899d03940e3718a338d45c.
- V14. No comparison of offset against BAR size, mapping length, or any other adapter field exists on the 0x80002024 path. The case body contains only the V12 guards and the WDF call. Evidence: ev_7a64cedd84dc352c37b6505ef9ffe2c017b8089d50899d03940e3718a338d45c.
- V15. BAR_base origin: FUN_14001E1F8 calls MmMapIoSpaceEx (import EXTERNAL:0x32 = NTOSKRNL.EXE::MmMapIoSpaceEx) with base = (core+0x91B8) & ~0xF, length = min(core+0x91C0, 0x400000), protect 0x204 (PAGE_READWRITE | PAGE_NOCACHE, standard winnt.h values). The result is stored in a record and returned. Here core = *(adapter+0x18310). Evidence: ev_0dcda904a6d2e7c3b860c80e5103426603fc2cb95b062770dc9625d05ad96983; ev_1e3a6dbeb256d86ea97692ce6074ff708ffc064b6ba3b14a8c94d191f4389849.
- V16. FUN_140022E14 stores the mapping at adapter+0x38 (`*(param_1+0x38) = lVar6`). FUN_14001E1F8 has one caller, FUN_140022E14 (0x140022E14). FUN_140022E14 is called by FUN_14000DB50 on the adapter. Evidence: ev_8e87eb04593ce38cf4c1ca462ac9c1546a3629f42e1fcf1ebbb4cd58315fd9ee; ev_29a1e9b4c5d3cbc15790fceb3e02f01331b390f190a80bf661e3edc44b1a0fe7; ev_c6c343b1f4db09a731680f13b4839db5d59f6060aa172b94908a36eedcb0a8a6; ev_b449dd46d0037f9df90e417499f1d90b7e872384c45679f042b0544a7e770c44.
- V17. The mapping length is used only in the clamp; it is not stored in the adapter. FUN_140022E14 separately computes `1 << ((cfg & 0xF)+0xF)` into adapter+0x1078, and the write path never reads that field. Evidence: ev_8e87eb04593ce38cf4c1ca462ac9c1546a3629f42e1fcf1ebbb4cd58315fd9ee; ev_0dcda904a6d2e7c3b860c80e5103426603fc2cb95b062770dc9625d05ad96983.
- V18. Adapter allocation: FUN_14000DB50 calls ExAllocatePoolWithTag(0x200 (NonPagedPoolNx), 0x21E90, 'brcm') and returns pool+0x10 (the adapter). FUN_140003360 stores that pointer at its param_2+0x30. FUN_14000479C reads its adapter from core+0x30, so the chain holds if FUN_140003360's param_2 is core; that call site is not verified. Evidence: ev_b449dd46d0037f9df90e417499f1d90b7e872384c45679f042b0544a7e770c44; ev_e6477cacaface457dab15863aa5a3fc6bb1eab2379da41cb4e3fe2b156bab656; ev_4c977f56419be40a6a4b349a09587bc473786b3f9382a43e6a25c29b6256fc08; ev_083a7e5841b0960aa1721d602c9f4850399648355d20228182fc942cdd74e1af.
- V19. MmMapIoSpaceEx has two direct callers: FUN_14001E1F8 (V15) and FUN_14001AD4C (0x14001AD4C). FUN_14001AD4C maps one 0x1000-byte page of BAR physical space at an index-derived offset and increments reference counts. It has no resolved direct callers, so its use is open (section 6). Evidence: ev_34445e9fee183cbe82deae4f68f98c784e6d7efaf1a6d4fb43ad7944739b442a; ev_be3dd292262f7ca282ccb50cac5f489b2ae478494696553cdc1ab966b2e33582; ev_6f58fc620e4e3178548ab9b105924ee0d191628b3e15f7619a7ff9f3304cb0e8; ev_f6d2d95a25c0c185e5f85b6363fa601c49124eed3078819ed321ff1d1ce0f602.
- V20. IOCTL 0x8000203C, arbitrary kernel write: `CMP EAX,0x8000203C` at 0x140004DF8, `JZ 0x140004EF3` at 0x140004DFD. Destination = qword [in+0] (`MOV RDX,[RAX]` at 0x140004F32). Count = [in+8] (0x140004F2A). Guards: count == 0 (0x140004F35-0x140004F38); count*4 > inLen-0xC (0x140004F3D-0x140004F4B); destination & 3 only (`TEST DL,3` at 0x140004F4D-0x140004F50). There is no range check on the destination. Loop: data `MOV EAX,[R10]` (0x140004F57), store `MOV dword ptr [RDX],EAX` (0x140004F5E), `LEA RDX,[RDX+4]` (0x140004F60). Evidence: ev_7a64cedd84dc352c37b6505ef9ffe2c017b8089d50899d03940e3718a338d45c; ev_483c860ba8a081b68112f18701345cf64361441cba92a74c13a2376fd4caf01c; ev_558e91326af00362ac961d4463cb48c7dc9176377a10dfb4cabfd93b816ce6ce (pseudo, lines 731-754). The other constant hit, at 0x14006570F in .data, has no procedure and is not a dispatch entry: ev_d8cae38fca35eedff496d702a79edb28c889355c6b5a758dfe3c24dcc3ed1794.
- V21. IOCTL 0x80002038, arbitrary kernel read: `CMP EAX,0x80002038` at 0x140004DED, `JZ 0x140004F7E` at 0x140004DF2. Source = qword [in+0] (`MOV R8,[RAX]` at 0x140004FE6). Count = [in+8] (0x140004FE3). Guards: count == 0 (0x140004FE9-0x140004FEB); count*4 > outLen (0x140004FF1-0x140004FFD); source & 3 (0x140005006-0x14000500A). The loop (pseudo, lines 682-689) copies count dwords from the source into the output buffer. No range check. Evidence: ev_88518c2b5b80e0d6ae4812f9abf13097244f7a7ea4de4e192be9482e34e79ec5; ev_7a64cedd84dc352c37b6505ef9ffe2c017b8089d50899d03940e3718a338d45c; ev_558e91326af00362ac961d4463cb48c7dc9176377a10dfb4cabfd93b816ce6ce.
- V22. IOCTL 0x80002050 returns the adapter pointer as an 8-byte output (`*(longlong*)local_res8 = lVar2`, pseudo lines 213-222). Evidence: ev_558e91326af00362ac961d4463cb48c7dc9176377a10dfb4cabfd93b816ce6ce.
- V23. IOCTL 0x8000201C window split, instruction level: `CMP EDI,0x8000` and `JC` at 0x140004984-0x14000498A. Offsets below 0x8000 write BAR_base+offset directly (`MOV dword ptr [RCX+RAX*1],EDX` at 0x1400049A3). Offsets at or above 0x8000 call FUN_140032854 (`CALL 0x140032854` at 0x140004994). Evidence: ev_7a64cedd84dc352c37b6505ef9ffe2c017b8089d50899d03940e3718a338d45c.
- V24. FUN_140032854 writes BAR+0x78 (window address) and then BAR+0x80 (window data). FUN_1400326E8 writes BAR+0x78 and reads BAR+0x80. Both reach device-internal address space, not kernel memory. Evidence: ev_e9c69ffc4c28028e76f80772d9b2c279715cb28e5b09bfc0fa8d4ea0deb6e8ea; ev_4519fce14e0b0366ab688885faec86d3a9fd17c78644ad575c159d7837434308.
- V25. IOCTL 0x80002020 (read-kit): direct read of BAR_base+offset for every offset, no split. Guards: count != 0, 4*count <= outLen, offset & 3 (pseudo, lines 496-516; the read is at line 512; fall-through at 0x140004855 from the compare at 0x14000484A). Evidence: ev_558e91326af00362ac961d4463cb48c7dc9176377a10dfb4cabfd93b816ce6ce; ev_b00c3d00743062a23d841921d0d18682a40b3a124a109c01e4fdb349e38d3043 (search of the 0x80002020 constant; hit at 0x14000484B).
- V26. Other BAR-window cases (pseudo): 0x80002018 reads directly below 0x8000 and via FUN_1400326E8 at or above (lines 462-481). 0x80002028 reads via FUN_1400326E8 for all offsets (line 603). 0x8000202C writes via FUN_140032854 for all offsets (line 771). Evidence: ev_558e91326af00362ac961d4463cb48c7dc9176377a10dfb4cabfd93b816ce6ce.
- V27. IOCTL 0x80002014: bounded by `offset + count < 0x21` (line 426). Helper FUN_14002FACC writes the command register BAR+0x14AC and polls it. Device-internal. Evidence: ev_558e91326af00362ac961d4463cb48c7dc9176377a10dfb4cabfd93b816ce6ce; ev_485bef0d233bd25e1da317a31d31941ae6746de7bcb27fb4b912fd5fcff24a78.
- V28. IOCTL 0x80002010 (FUN_140006F78): bounded by `offset + count < 0x21` with count != 0. It performs a per-index device read into the output pointer. Evidence: ev_41507c27f5a273c6921fc224eafa192e375fb6a18e58f827587952587c616949.
- V29. IOCTL 0x80002030 (FUN_140030AA8) and 0x80002034 (FUN_140030BE0): both require 4-byte alignment and offset+len <= adapter+0x10C4, then do device NVRAM access through BAR+0x6424. Evidence: ev_e96500cf176014d4e46baa815d029efe0b9b78521c887439650199b43c8cb3fa; ev_71a9447f5a5463083fc40917ab3f96be9c8d869a4133de69762fc2ca9e94459b.
- V30. IOCTL 0x8000206C (FUN_1400072F0): requires the input to equal the token at adapter+0x499C, then writes a fixed 0xE0-byte block at fixed device offset 0x420. Evidence: ev_ed1cca66864ec02b0d742e60efa946549ac310eb663d5868ee21bfcfbe69e491.
- V31. IOCTL 0x8000207C and 0x80002080 (FUN_140005EA8): table adapter+0x1050 indexed by selector >> 7, with selector < 0x200000 (index < 0x4000). Read-only copy of 0x140 bytes to the output. Table size not established. Evidence: ev_ee2fb5ae99bdba9d0052f8d7e5d220b92a331112b48ef44602da7fb5d95784e3.
- V32. IOCTL 0x80002060 (FUN_140005C00: selector 0/1/2 to fixed device operations) and 0x80002064 (FUN_140005DAC: token, then a fixed 13-dword device read into the output). Neither takes an attacker address. Evidence: ev_57910cfbfe83902fd78efc1b05ea7cb9d9b647277cd0b0c60d0dcbd223200c2b; ev_cfc1b80d9949a0674356b62ee23acf0358c9675dc7e7aa0b31fc1fcc86121161.
- V33. IOCTL 0x80002000 calls FUN_140002634 (bit dispatch to FUN_1400025E4, not examined). IOCTL 0x80002004 calls FUN_1400046B8 (WDF calls keyed by a bit mask; no memory-address input). Evidence: ev_6edf28ed055ab7a960d65560412ff1e6a2bfeba0979a9843cb1fbc03cf0920a4; ev_1e28189ef0775a8006ac84b518b98fb4d78f8256881bc847b04dd847871c0c21.
- V34. IOCTL 0x80002098 (gated): index = byte [in+0] (0..255). It writes one byte at adapter+0x16BE8 + index*0x1E8 + 0x1E6 when adapter+0x1940 != 1 and two other state fields are non-zero (pseudo, lines 130-137). FUN_14000DB50 sets adapter+0x1940 = 1 during init. For index >= 93 the byte lies beyond the 0x21E90 allocation (usable 0x21E80 bytes). The callee FUN_140016E2C also reads and writes the entry at +0x1DE. Evidence: ev_558e91326af00362ac961d4463cb48c7dc9176377a10dfb4cabfd93b816ce6ce; ev_caddba590f792c8d1655592ea39cce4015afddfe66a21f45fa1e6f3652175036; ev_b449dd46d0037f9df90e417499f1d90b7e872384c45679f042b0544a7e770c44.
- V35. Identity APIs: the case-sensitive pattern "Se" matches only NTOSKRNL imports (KeSetEvent, ZwSetValueKey, KeSetImportanceDpc, KeSetTimer, ZwOpenSection, ZwMapViewOfSection, ZwUnmapViewOfSection, KeSetTargetProcessorDpc). "Requestor", "PsGetCurrentProcess", "SeTokenIsAdmin" and "IoCreateDevice" match nothing. "Security" matches only __security_check_cookie. Evidence: ev_03cf1370729c5642ef662d46938ee43edb759365d6faa75137989ea0bed60e1b; ev_4df367a81b426ff90a9ce567ded661a6b76d423cc7892b36f7678811998ea9ea; ev_6fb921e2deb81fd9c79c77fa25acc2adfffff28bdd23533a8e29904b3ddfc849; ev_6019704a2ae1976a9dade96e295ca000750713277ea11ae866b88a573a3dd4d0; ev_c70676471f5ff09d49094f4db14624e3f0748e2a4f8b7c333d02262eac715fea; ev_b828468aab499767b0ccc7efe1db56c1340bd6833be49bfafb1a92e7f0efc7dc.
- V36. No WDF request-identity call on the IOCTL path: the only table calls that take the request in FUN_14000479C are 0x868 and 0x870 (input and output buffer retrieval). Evidence: ev_558e91326af00362ac961d4463cb48c7dc9176377a10dfb4cabfd93b816ce6ce; ev_7a64cedd84dc352c37b6505ef9ffe2c017b8089d50899d03940e3718a338d45c.
- V37. SDDL-form text is absent from initialized memory: "D:P" (ASCII and UTF-16LE), "D:(" (ASCII and UTF-16LE) and "(A;" (ASCII and UTF-16LE) have no matches. "SDDL" is absent from the string inventory (the inventory has a completeness caveat). Evidence: ev_c3bba64ed7eb69b03cf2604c4fd7789defa3f4778ae79cf712e049715d65d748; ev_5b9a090cd73b7af18678f351cbf2f18df06b08f40cbabfa6abc2645b30929359; ev_92c82e4448a122176271c727f5182b5533a2188ab1be74d73591906ced771bbc; ev_0bf1b04fd0c138df71aa1ed3c274c9c97dfd001c353999a4709fdae8029399a5; ev_b003d1383427da5bd8e07e5f008b117ce2405d206f599149e29dd416b5e64d97; ev_6cf5ff203826cd071890eef4b640967a5ec1a0d4684c87bc00b0b8f04bbb2f9b; ev_7de9981817975e48d0df5a418c8052c6eb9cc1886c25ce782afcd8ef28c82967.
- V38. Access bits: every IOCTL value dispatched in FUN_14000479C (0x80002000-0x80002098) decodes to METHOD_BUFFERED and FILE_ANY_ACCESS (for example, 0x80002024 = CTL_CODE(0x8000, 0x809, BUFFERED, ANY)). The I/O manager therefore does not check the handle's granted access for these codes, so any handle that can be opened is enough. Derived from the code values (see V2).

## 3. Corrections to the earlier report

- C1. "File-create callback FUN_1400019E4" is wrong. It is the IRP_MJ_POWER preprocess callback (V9). The file-create question is therefore unanswered: no create handler is identified (V10, V11).
- C2. "BAR_base = *(ctx+0x38)" is imprecise. The chain is BAR_base = *(adapter+0x38), with adapter = *(core+0x30) = *(devctx+0x40) (V16, V18). This matches the claim if "ctx" means the adapter.
- C3. The clamp is min(core+0x91C0, 0x400000) (V15). The BAR size computed into adapter+0x1078 (V17) is not the clamp source.
- C4. All guards are as claimed (V12). Minor nuance: the length comparison uses the low 32 bits of (inLen-0xC), because the LEA is 32-bit. This is immaterial in practice.
- C5. "The offset has no upper bound" is confirmed (V14). The 32-bit offset wraps modulo 2^32 inside a 4 GiB window (V13).
- C6. The claimed primitive, taken alone, is WRITE-HIGH for case (a) and WRITE-MEDIUM for case (b) (section 5). The CRITICAL-grade primitive is a different IOCTL (V20).
- C7. Missing from the earlier report: the 0x8000203C arbitrary write (V20), the 0x80002038 arbitrary read (V21), the 0x80002050 pointer disclosure (V22), and the gated 0x80002098 out-of-bounds byte write (V34).
- C8. The window split is confirmed for 0x8000201C (V23). 0x80002024 has no split (V13, V14). The 0x80002020 read has no split (V25).
- C9. "No SDDL string" is confirmed at byte level (V37). Residual: other SDDL leading forms (for example "D:AI") were not searched.
- C10. "No Se* or caller-identity check" is confirmed and strengthened: no identity-related import (V35) and no request-identity call on the IOCTL path (V36).
- C11. EvtIoDeviceControl = FUN_1400017A8 is consistent with the code (V5, V6). The slot name is an inference (section 6, O3).
- C12. The earlier report labels FUN_1400019E4 as the file-create callback. Its registration shows it is the IRP_MJ_POWER preprocess callback (V9). The earlier report does not say how the label was derived, so this entry corrects the label only.

## 4. Reachability

Proven in-file:
- The IOCTL dispatcher is reachable through the device interface with GUID at 0x1400372E0 (V7) and a single parallel default queue whose only handler is FUN_1400017A8 (V6).
- The device is unnamed and has no symbolic link created by the driver; the device interface is its only in-file access path (V8).
- The driver performs no caller-identity or privilege check on the IOCTL path: no identity imports, no requestor query (V35, V36).
- The driver supplies no security descriptor: no SDDL-form text, no SD API (V37, V8).
- The I/O manager does not check the handle's access for these IOCTLs (FILE_ANY_ACCESS, V38), so the device's open ACL is the only gate.
- The only gates on the dispatch path are device-state checks (V5), not identity checks.

Requires VM verification (section 7):
- The effective security descriptor of the device object behind the interface, and therefore who can open it. The driver sets none in-file. The effective DACL comes from the OS/PnP defaults and any class-level or INF-supplied security. This must not be assumed from memory.
- Whether the device interface is enabled and its symbolic link exists after start.
- Whether any upper filter or class setting changes access.
- What IRP_MJ_CREATE does, since no create handler was identified (V11).
- Runtime values: the BAR length at core+0x91C0 (which decides whether the 0x8000-byte direct window is inside the mapping), adapter+0x1940 (gate for V34), the adapter+0x1050 table size (V31), and devctx+0x14 (state gate, V5).

## 5. Severity rationale

Case (a), unprivileged user can open the device (not proven in-file):
- 0x8000203C (V20) gives a 32-bit-granular write of attacker-chosen data to any 4-aligned kernel address, count dwords per call, with no address validation. Within the same unauthenticated handler, 0x80002038 gives an arbitrary read (V21) and 0x80002050 discloses the adapter's kernel address (V22). Together these supply a kernel corruption primitive from user mode with no in-file mitigation. Rating: WRITE-CRITICAL.
- The claimed 0x80002024 (V12-V14): contiguous 32-bit writes to BAR_base + [0, 4 GiB). Only the first min(BAR length, 4 MiB) bytes are the device mapping, and the writes there are device MMIO writes with side effects. Writes beyond the mapping hit ordinary system VA. An unmapped target causes a kernel bugcheck, so any opener can deny service this way. A mapped target corrupts whatever lives there; the mapped fraction of that window is not determinable in-file. The IOCTL gives no read and does not disclose BAR_base. Rating: WRITE-HIGH.
- Window cases (0x8000201C at or above 0x8000, 0x8000202C, 0x80002028, 0x80002018 at or above 0x8000) reach device-internal space only (V24, V23). They add device-state impact, not kernel-memory writes.
- 0x80002098 (V34) is a one-byte out-of-bounds write when its gate is open. The gate is closed by the init value of 1, so it is a conditional finding that needs a runtime check.

Case (b), administrators only:
- An administrator can already load kernel code. The concern is that an unchecked kernel write and read make the driver usable as a vulnerable-driver primitive. Rating: WRITE-HIGH for 0x8000203C.
- The 0x80002024 BAR write alone is bounded by its mapping and gives no read or base disclosure. Rating: WRITE-MEDIUM.

Why 0x80002024 alone is not CRITICAL: no read primitive comes with it, the base is not disclosed by that IOCTL, the mapped fraction of its window is unknown, and the target layout is not reliable. The CRITICAL grade depends on 0x8000203C, which has no such limits.

## 6. Open items

- O1. Reachability (decisive): effective security descriptor of the device object or interface (VM, section 7). Until then case (a) is conditional.
- O2. IRP_MJ_CREATE disposition: no EvtDeviceFileCreate identified (V10, V11). Confirm the table-0x400 and table-0x248 identities against KMDF headers, and confirm create behavior at runtime (VM).
- O3. WDF names are inferred from argument shape (tables 0x868, 0x870, 0x4C0, 0x248, 0x268, 0x258, 0x400, 0x410, 0x210, 0x1F0, 0x1E8). Confirm against the KMDF version the binary links to. The slot name config+0x28 = EvtIoDeviceControl relies on WDF_IO_QUEUE_CONFIG member order; if that slot were EvtIoInternalDeviceControl instead, the IOCTL path would not be reachable from user mode (V6). This is high-priority to confirm.
- O4. FUN_14001AD4C (V19) maps a 0x1000-byte BAR-physical page at an index-derived offset. It has no resolved direct callers (ev_6f58fc620e4e3178548ab9b105924ee0d191628b3e15f7619a7ff9f3304cb0e8). Find where its return value is stored and whether any dispatched IOCTL reaches it through a function pointer. It would add a kernel-VA window if it does.
- O5. Not decompiled: FUN_1400025E4 (0x80002000 path), FUN_14000D5A8 (0x80002008), FUN_140007034 (0x8000200C), the output-fill helpers FUN_140006B08, FUN_140006708, FUN_140006DDC, FUN_1400068F8, FUN_14000681C, FUN_14000650C, FUN_140006624, FUN_14000619C, FUN_140006C64, FUN_140006068, and the device-level helpers FUN_14002F9CC, FUN_140031064, FUN_1400311C0, FUN_1400327E4, FUN_140032914, FUN_140032600. Their call shapes show no attacker-chosen kernel address, but they were not read.
- O6. Writers of adapter+0x1940 (gate for V34). Static search for further stores is needed.
- O7. adapter+0x1050 table size (V31): the 0x8000207C/0x80002080 index reaches 0x3FFF. A read-side out-of-bounds candidate; unverified.
- O8. Writers of adapter+0x38 other than FUN_140022E14 were not enumerated. 0x8000203C already gives an unchecked write, so this does not change the rating.
- O9. The call site of FUN_140003360 was not verified (V18). Only the store at its param_2+0x30 was confirmed.
- O10. The runtime BAR length (core+0x91C0) and whether the 0x8000-byte direct window lies inside the mapping (VM).
- O11. Residual SDDL spellings (for example "D:AI" or "O:" prefixes) were not searched (V37).
- O12. The .data hit at 0x14006570F (ev_d8cae38fca35eedff496d702a79edb28c889355c6b5a758dfe3c24dcc3ed1794) is not an IOCTL table entry. It is data with no procedure, and the bytes look like embedded binary content. Low priority.
- O13. Tool note: find_xrefs_to_name returned name_not_found for MmMapIoSpaceEx (ev_8d0c8e842f16936e1173c2d77b6164f0cad0e660dbfe55a14b180fbf0c3d2a93), but search_procedures finds EXTERNAL:0x32 (V15). Import callers were enumerated through procedure_callers instead (V19).

## 7. VM verification plan (orchestrator-owned; NOT RUN)

Step 0 (static, no load; orchestrator decision): compare the WDF table offsets listed in O3 with the KMDF version the binary was linked against (wdffuncenum.h and WDF_IO_QUEUE_CONFIG member order). This settles the names used in V6, V9 and V10.

Step 1 (non-destructive; snapshot VM; do not open the device): with the driver installed on a snapshot (orchestrator decision), read-only:
- Enumerate the device instance (Get-PnpDevice). Read DEVPKEY_Device_SecuritySDS (device SDDL) and DEVPKEY_DeviceClass_SecuritySDS (class SDDL). List the interface symbolic link(s).
- Record which principals (Everyone, Authenticated Users, Users, Interactive) have any ACE granting access.
- If no device SD is stored, read the effective SD of the device object behind the link with a read-only tool (for example WinObj or accesschk on the device object), without opening the device.
- Outcome: no non-administrator ACE grants access means case (b) for this device; any non-administrator grant means case (a).

Step 2 (read-only runtime facts, same snapshot): BAR length from the PnP resource allocation (Win32_PnPAllocatedResource or Get-PnpDeviceProperty). The mapping length actually passed to MmMapIoSpaceEx. With kernel-debugger access approved by the orchestrator, read adapter+0x1940, devctx+0x14 and the adapter+0x1050 table size without issuing any IOCTL.

Step 3 (dynamic; not planned on this host; orchestrator decision only): only if Step 1 shows non-administrator access, a single open test with a standard-user account on an isolated snapshot, then revert. No IOCTL is sent in this plan.

## 8. Evidence list (full IDs)

Target identity and constants:
- ev_186a25a0db20ca168226e5e1074e67fa5fa7f0886629510e073f8d6da8b79805 (search "24 20 00 80"; subject digest)
- ev_b00c3d00743062a23d841921d0d18682a40b3a124a109c01e4fdb349e38d3043 (search "20 20 00 80")
- ev_b3fdb2d7b017365598631e2ac12b0219a4ba923495735b64966611d441c17750 (search "1C 20 00 80")
- ev_483c860ba8a081b68112f18701345cf64361441cba92a74c13a2376fd4caf01c (search "3C 20 00 80"; .data hit at 0x14006570F)
- ev_88518c2b5b80e0d6ae4812f9abf13097244f7a7ea4de4e192be9482e34e79ec5 (search "38 20 00 80")
- ev_d8cae38fca35eedff496d702a79edb28c889355c6b5a758dfe3c24dcc3ed1794 (read_bytes 0x14006570F)

Callers, xrefs and registration:
- ev_327107db61feeb876b91e049dbe4b46b883e93de6b594f0f1e39e37a8567b5f5 (callers of FUN_14000479C)
- ev_fed4368e87359748e60451bbc30933acb61cce2ad7acfbe9995c83486132df6d (xrefs 0x1400017A8)
- ev_f4ebea9a9547414dd1157081581fa9ac3f9a4b23327bab40e66c2ea30d524535 (xrefs 0x1400019E4)
- ev_4fa2a8bd7aed0b2d2f39ce776e58c2df735b131b23d55aa69df596b473fc4a91 (resolve 0x140001558)
- ev_d758e348e04fe5d0494ba29818459eb23c6730c5482b339a7af7273a9b104348 (resolve 0x14000156A)
- ev_974f70a081af2d12da7699ee3ac3d65d3c3405aa0c6098476288be94facc9b42 (resolve 0x1400013E1)
- ev_29a1e9b4c5d3cbc15790fceb3e02f01331b390f190a80bf661e3edc44b1a0fe7 (callers of FUN_14001E1F8)
- ev_c6c343b1f4db09a731680f13b4839db5d59f6060aa172b94908a36eedcb0a8a6 (callers of FUN_140022E14)
- ev_4c977f56419be40a6a4b349a09587bc473786b3f9382a43e6a25c29b6256fc08 (callers of FUN_14000DB50)
- ev_083a7e5841b0960aa1721d602c9f4850399648355d20228182fc942cdd74e1af (resolve 0x140003360)
- ev_bb82ef39e2a2effc72909e162f6ce4d2f5e151d70d1403d154c4fff9c2b4659a (resolve 0x14000DB50)
- ev_2551de02b3c2ea5706bf12ae71c9c9e7454bae99d76d14e9dfd018d29f560011 (resolve 0x140022E14)
- ev_34445e9fee183cbe82deae4f68f98c784e6d7efaf1a6d4fb43ad7944739b442a (callers of NTOSKRNL.EXE::MmMapIoSpaceEx)
- ev_6f58fc620e4e3178548ab9b105924ee0d191628b3e15f7619a7ff9f3304cb0e8 (callers of FUN_14001AD4C: none resolved)
- ev_f6d2d95a25c0c185e5f85b6363fa601c49124eed3078819ed321ff1d1ce0f602 (resolve 0x14001AD4C)

Procedure pseudo-code and assembly:
- ev_558e91326af00362ac961d4463cb48c7dc9176377a10dfb4cabfd93b816ce6ce (pseudo FUN_14000479C)
- ev_7a64cedd84dc352c37b6505ef9ffe2c017b8089d50899d03940e3718a338d45c (assembly FUN_14000479C)
- ev_a26ba713067c768a9e250b68ed0103dab4782efeaa76c6dd69b7cc2364c36e56 (pseudo FUN_1400017A8)
- ev_5864987d8dd1a2e2c4403eed4fc7b569e3bf12a8ea0b7b5b0d37724efba7371b (pseudo FUN_140001228)
- ev_51c2e4bd45eb91f46ea7827611281aa34db5842ca8c3ac16a9fa189df6cb1673 (assembly FUN_140001228)
- ev_043d69742f19817ef3266028d5499c63cbdd8f4ee21f7b898146dff3307f92ce (pseudo FUN_1400019E4)
- ev_a4e4b7f2a6c7d63271b17296a16cba25a14cd62ad55873c25e7ceba574e6c27f (pseudo FUN_140002DB8)
- ev_0dcda904a6d2e7c3b860c80e5103426603fc2cb95b062770dc9625d05ad96983 (pseudo FUN_14001E1F8)
- ev_8e87eb04593ce38cf4c1ca462ac9c1546a3629f42e1fcf1ebbb4cd58315fd9ee (pseudo FUN_140022E14)
- ev_b449dd46d0037f9df90e417499f1d90b7e872384c45679f042b0544a7e770c44 (pseudo FUN_14000DB50)
- ev_e6477cacaface457dab15863aa5a3fc6bb1eab2379da41cb4e3fe2b156bab656 (pseudo FUN_140003360)
- ev_be3dd292262f7ca282ccb50cac5f489b2ae478494696553cdc1ab966b2e33582 (pseudo FUN_14001AD4C)
- ev_e9c69ffc4c28028e76f80772d9b2c279715cb28e5b09bfc0fa8d4ea0deb6e8ea (pseudo FUN_140032854)
- ev_4519fce14e0b0366ab688885faec86d3a9fd17c78644ad575c159d7837434308 (pseudo FUN_1400326E8)
- ev_485bef0d233bd25e1da317a31d31941ae6746de7bcb27fb4b912fd5fcff24a78 (pseudo FUN_14002FACC)
- ev_41507c27f5a273c6921fc224eafa192e375fb6a18e58f827587952587c616949 (pseudo FUN_140006F78)
- ev_e96500cf176014d4e46baa815d029efe0b9b78521c887439650199b43c8cb3fa (pseudo FUN_140030AA8)
- ev_71a9447f5a5463083fc40917ab3f96be9c8d869a4133de69762fc2ca9e94459b (pseudo FUN_140030BE0)
- ev_ed1cca66864ec02b0d742e60efa946549ac310eb663d5868ee21bfcfbe69e491 (pseudo FUN_1400072F0)
- ev_ee2fb5ae99bdba9d0052f8d7e5d220b92a331112b48ef44602da7fb5d95784e3 (pseudo FUN_140005EA8)
- ev_57910cfbfe83902fd78efc1b05ea7cb9d9b647277cd0b0c60d0dcbd223200c2b (pseudo FUN_140005C00)
- ev_cfc1b80d9949a0674356b62ee23acf0358c9675dc7e7aa0b31fc1fcc86121161 (pseudo FUN_140005DAC)
- ev_6edf28ed055ab7a960d65560412ff1e6a2bfeba0979a9843cb1fbc03cf0920a4 (pseudo FUN_140002634)
- ev_1e28189ef0775a8006ac84b518b98fb4d78f8256881bc847b04dd847871c0c21 (pseudo FUN_1400046B8)
- ev_caddba590f792c8d1655592ea39cce4015afddfe66a21f45fa1e6f3652175036 (pseudo FUN_140016E2C)

Identity, security and string searches:
- ev_03cf1370729c5642ef662d46938ee43edb759365d6faa75137989ea0bed60e1b (search_procedures "Se", case-sensitive)
- ev_4df367a81b426ff90a9ce567ded661a6b76d423cc7892b36f7678811998ea9ea (search_procedures "Requestor")
- ev_6fb921e2deb81fd9c79c77fa25acc2adfffff28bdd23533a8e29904b3ddfc849 (search_procedures "PsGetCurrentProcess")
- ev_6019704a2ae1976a9dade96e295ca000750713277ea11ae866b88a573a3dd4d0 (search_procedures "SeTokenIsAdmin")
- ev_c70676471f5ff09d49094f4db14624e3f0748e2a4f8b7c333d02262eac715fea (search_procedures "IoCreateDevice")
- ev_b828468aab499767b0ccc7efe1db56c1340bd6833be49bfafb1a92e7f0efc7dc (search_procedures "Security", case-insensitive)
- ev_1e3a6dbeb256d86ea97692ce6074ff708ffc064b6ba3b14a8c94d191f4389849 (search_procedures "MmMapIoSpace"; EXTERNAL:0x32)
- ev_c3bba64ed7eb69b03cf2604c4fd7789defa3f4778ae79cf712e049715d65d748 (search_bytes "44 3A 50")
- ev_5b9a090cd73b7af18678f351cbf2f18df06b08f40cbabfa6abc2645b30929359 (search_bytes "44 00 3A 00 50 00")
- ev_92c82e4448a122176271c727f5182b5533a2188ab1be74d73591906ced771bbc (search_bytes "44 3A 28")
- ev_0bf1b04fd0c138df71aa1ed3c274c9c97dfd001c353999a4709fdae8029399a5 (search_bytes "44 00 3A 00 28 00")
- ev_b003d1383427da5bd8e07e5f008b117ce2405d206f599149e29dd416b5e64d97 (search_bytes "28 41 3B")
- ev_6cf5ff203826cd071890eef4b640967a5ec1a0d4684c87bc00b0b8f04bbb2f9b (search_bytes "28 00 41 00 3B 00")
- ev_7de9981817975e48d0df5a418c8052c6eb9cc1886c25ce782afcd8ef28c82967 (search_strings "SDDL", case-insensitive)
- ev_8d0c8e842f16936e1173c2d77b6164f0cad0e660dbfe55a14b180fbf0c3d2a93 (find_xrefs_to_name MmMapIoSpaceEx: name_not_found; tool limitation)

## 9. Session cross-check of V20 (added by the coordinating session)

The coordinating session reopened bxvbda.sys (digest feb2771428706126fea1cc9a50ebe3cf4f8e8fb6fcb3ca19996497ca44fdac45, matches) and read the decompile of FUN_14000479C, saved from procedure_pseudo_code (`raw_result.value`, lines 730-753, the `0x8000203C` branch):

- `iVar4 = WDF retrieve input (0x10)`; `uVar5 = local_40[2]` (input +8 = count); `puVar10 = local_40 + 3` (data at input +0xC).
- `local_40 = *(uint **)local_40`: the destination is the 8-byte value at input +0, used directly as a kernel pointer.
- Failure (`0xC0000001`) if count == 0, if `(inLen - 0xC) < count << 2`, or if `(destination & 3) != 0`. There is no range check on the destination.
- Loop: `*local_40 = *puVar10` for count dwords, advancing both pointers.

This matches V20. The write primitive is confirmed at the decompile level: arbitrary dword writes to an address supplied by the caller.
