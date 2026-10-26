# SteelSeries Engine VAD (SteelSeries-Engine-VAD_78C729CA.sys): static memory-write audit

Setup required: devnode (from audits\steelseries_nonrea_triage.md, setup_required row; ROOT\ hardware ID at INF line 29)

Scope: memory-write primitives only (copy, map, and memory paths in KS, property, and stream handlers). Static analysis only. The driver and its INF were not loaded, installed, or run, no device was opened, and no IOCTL was sent. No proof-of-concept material is included. INF facts, setup classification, import groups, and Authenticode belong to the non-REA triage report.

## 1. Summary

| Case | Rating | Qualifier |
|---|---|---|
| (a) standard user can reach the sink | NO-WRITE | coverage-limited, about 75% |
| (b) only an administrator can reach the sink | NO-WRITE | coverage-limited, about 75% |

- No memory-write sink is proven. Every direct copy call site in the image (8 callers of the internal memmove) is bounded. One copy (`FUN_14000a070`) is reached only through a function-pointer table, and its size source is unresolved. That is the decisive open item (section 6).
- Candidate tiers: not entered. Setup required is `devnode` (triage report), so these primitives do not enter the candidate tiers. They are rated for completeness only.
- Verdict scale: WRITE-CRITICAL / WRITE-HIGH / WRITE-MEDIUM / NO-WRITE. Input-injection and config-control findings are out of scope.

## 2. Header facts

- File: `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected2\drivers\SteelSeries\SteelSeries-Engine-VAD_78C729CA.sys` (82,608 bytes, x86_64 PE)
- SHA-256: `78C729CA45F8BA7EC66988E1B26574655766DD330EEB25A00E44D33E9E927821` (Get-FileHash). The REA open result digest is `78c729ca45f8ba7ec66988e1b26574655766dd330eeb25a00e44d33e9e927821`. The two agree.
- Version: INF `DriverVer = 09/09/2026,1.1.0.0`. The PE version resource was not read.
- Class: MEDIA (INF line 3; ClassGUID {4d36e96c-e325-11ce-bfc1-08002be10318}). Triage report is authoritative for INF facts.
- Hardware ID: `ROOT\VEN_SSGG&DEV_0002` ("SteelSeries Engine Virtual Chat"), INF line 29. Root-enumerated devnode.
- Device interfaces registered by the INF (INF lines 101-104): KSCATEGORY_AUDIO, KSCATEGORY_RENDER, KSCATEGORY_TOPOLOGY.
- INF Security ACE (AUDIOHW.AddReg, INF line 123), exact text: `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)`. The `WD` (Everyone) ACE grants GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE. The SDDL string does not appear in the .sys (search for `(A;` returned nothing).
- Setup required: devnode (triage report).

## 3. Verified facts

- Image layout: `.text` 0x140001000, `.rdata` 0x140005000, `.data` 0x140008000, `PAGE` 0x14000a000 (26 KB), `INIT` 0x140011000. Evidence: ev_5e84040fe674a6aa14c8636424fc117b00b577484072c09c70902ff54347a3ad.
- Entry 0x1400011f0 calls `FUN_1400113b8` (init) then DriverEntry `FUN_14000121c`. Evidence: ev_eaf4d8b9fdb4c653ead52487e47d3bf8394293ff020076e111d87cf67859661a.
- DriverEntry `FUN_14000121c` copies RegistryPath with `RtlCopyUnicodeString`, calls `WdfVersionBind` at 0x140001295, calls `FUN_14001129c`, and sets DriverUnload to `FUN_140001380` (DriverObject+0x68). Evidence: ev_ec4101fbea9ad5c2af7bc24f7c945b1b4025ae685c78a78887b02cc0ec878ddc; call-site resolution ev_42fd3027f82b4f5c52f04bb0e3a42e466069b91dd668509372a14f10a555837f.
- `FUN_14001129c` (INIT) calls `WdfDriverCreate` through the WDF function table (offset 0x3a0) with WDF_DRIVER_CONFIG (EvtDriverDeviceAdd = NULL, DriverInitFlags = 2 = WdfDriverInitNoDispatchOverride, pool tag 'SyAu'). It calls `PcInitializeAdapterDriver(DriverObject, RegistryPath, FUN_14000a220)` at 0x140011350 and hooks MajorFunction[IRP_MJ_PNP] (DriverObject+0x148) to `FUN_14000a5f0`. Evidence: ev_fc8b8779e9ef779c775fd48610a086819b968ee6e43cba97f07a88da027c615a; call-site resolution ev_6145d638c0823afaa940031fb8c8f3ad1e5c423f85fbb932a1f2badf983dc571; xrefs to the PORTCLS slot ev_78d5693b957a1de935bdd48b4bcd18e06bf365f24231a69bca6952fd1ede31fc.
- Device creation answer: DriverEntry does not reach IoCreateDevice. The driver has no IoCreateDevice import. The device is created on the PnP AddDevice path: `FUN_14000a220` = `PcAddAdapterDevice(DriverObject, PDO, FUN_14000a6b0 (StartDevice), 2, 0)`. Evidence: ev_9e5574e83675a8faea3f67509f49ac280a633a5d2d7e95aee1801c8c3173a4b3; import search ev_318943198343d047324a8140dfff63e095a47ea34ed7bd5e9a1febd1421bed7d.
- The WDF driver config has EvtDriverDeviceAdd = NULL, so WDF creates no device in DriverEntry (see the `FUN_14001129c` evidence above).
- Import set relevant to writes: NTOSKRNL has no memcpy, memmove, RtlCopyMemory, MmProbeAndLockPages, IoAllocateMdl, MmMapLockedPages, or IoCreateDevice import. The PORTCLS imports are PcInitializeAdapterDriver, PcAddAdapterDevice, PcNewPort, PcNewMiniport, PcRegisterSubdevice, PcRegisterPhysicalConnection, PcRegisterAdapterPowerManagement, and PcGetPhysicalDeviceObject. Evidence: ev_2f3ff6fb112338731956ad9b090a1efc74503bf2a8ad303cb6b1cf536e8c4906; name sweeps ev_c19fdd7371817b4defe0d47c69046cafa03d4d6624a8ae4012b96ef4f81d931a (Mm), ev_6c581229fbfa9e7334b786d6e1d0d0142579bbfe7cd30076c0333a608d4e18e3 (Probe strings), ev_9d30b24f14a0d01a0c667ef1c6b1f42d9ee984db35f53f4e5c85cdb098055966 (Mdl strings).
- No `rep movsb` (F3 A4) and no `rep movsq` (F3 48 A5) anywhere in the image. Evidence: ev_5e84040fe674a6aa14c8636424fc117b00b577484072c09c70902ff54347a3ad and ev_3587acb185f251c4dd7024e61d8aa642d24bf3191b7ef61606a39cc5865215b2.
- The driver's own memmove (overlap-aware, dst/src/size) is `FUN_140003fc0`. Its complete direct caller set (REA relationship coverage "complete") is 0x140003990, 0x14000a070, 0x14000ba5c, 0x14000bc00, 0x14000e748, 0x14000e85c, 0x14000ec00, 0x14000fba0. Evidence: ev_480b50ed5d1afc135067b7604892a448902d3c3821fe7571f6064b422fd0de09; callers ev_ad0984ffff47093f5fb29ff45c2b44ad985a518943db0f92c2b839111fa6c437.
- KS property dispatcher `FUN_14000be90` (PortCls PCPROPERTY handler) matches the property-set GUID and Id, then calls the sub-handler. Evidence: ev_43c4b6fc050e74863153e2048a13c11be07ffd8430896d41de59431d4d32a8ec.
- PCPROPERTY table at `.data` 0x1400084f0 (24-byte entries: Set pointer, Id, Flags, Handler). Pin-set entries are Id 14 (flags 0x203, SET-capable) and Id 15 (flags 0x201, GET only), all with Handler = `FUN_14000be90`. Evidence: ev_8e1b435875b4c1d0c3e5483facf6530d71085d6faf5e2f344ae1d4af73dec652.
- Pin-set GUID {8C134960-51AD-11CF-878A-94F801C10000} is at 0x140005840 and is referenced from `.data` 0x140008508 and code 0x14000bf04. Evidence: ev_2b20177c01e139840c715eb32e60251e7aded194965f432a91f95f64da3ad581; ev_2bf0a455082c88e2286b89aeaf6a765841ce8c67d2e6ccaa01c68498dd35178b.
- Pin Id 14 (PROPOSEDATAFORMAT) SET (`FUN_14000bc00` to `FUN_14000b500`) matches the user format against the driver's fixed format table and returns success only on a match. It does not store user bytes. Evidence: ev_508717372268cf375445340c1e7112c9eb51c1906a0ed6f2288fad019fbc22a1; ev_bc1158ad338ab4ffbe5dc08f26a1a99a1fcf455edbad006f73e038b8b6a77ed5.
- Pin Id 14 GET copies a driver-owned format block to the user output with `FUN_140003fc0`. The copy length is the block's own size dword. The code requires ValueSize >= 0x68 first. Driver-owned size values observed in `.data`: 0x58 and 0x68. Evidence: ev_bc1158ad338ab4ffbe5dc08f26a1a99a1fcf455edbad006f73e038b8b6a77ed5; ev_18d47cbd964f0a971ba1f3643cf7d2b501f540fe6d9b4c8b2cf021df61f08af0.
- Pin Id 15 (`FUN_14000ba5c`) is GET-only (SET returns 0xC0000010). It copies a driver block plus the user instance tail (InstanceSize - 8) to the output. It requires aligned(block size) + tail <= ValueSize. Evidence: ev_0d82507bb8ede425dc6d94b2f9791c748f7a05935bbee61520d7de43252b9e07.
- Audio-type set handlers `FUN_14000f32c` (Id 4), `FUN_14000f0ac` (Id 13), and `FUN_14000f1d0` (Id 55) read or write one 32-bit value. The channel index is bounded by the channel count, and the size is validated by `FUN_14000f4c0(..., 4, 4)`. Evidence: ev_93c470b229f71bab84772056d77c4b07579494a602191f813b6324329f230bc2; ev_7ebbadceaae950f0721ebada2cd5b220509dcd544c36b83947fc145aa05a7e92; ev_5501f8559bc40a93fbb2438b2ab8d0291b8636e9d06df5039381554152adfc30; size check ev_284dc4866c5c98821dcafa2c76775a7da1ad9241c1b6174bfcaa2a77e39609fc.
- BASICSUPPORT path `FUN_14000e85c`: output is bounded (`*param_3 >= total`) before the memmove. Evidence: ev_e4835be39cfee583d477d85f39e11bfafe00127890e753c1e3f7a6c75a2e3c75.
- Generic property helper `FUN_14000e748`: the SET path copies the fixed header size from user data only after `FUN_14000ec9c` requires user length >= that size. The GET path copies a fixed size bounded by the output size. Its only direct caller is `FUN_14000a100`. Evidence: ev_392ae1856109a6f9db4cea3c4a014c1703a4c02e8f49c1cc0bc1bbcc484d32f5; ev_a0e23e4c5337e1574abebe790b93774dba7907233424c21a915624ddc44b1f06; callers ev_b2824cfaa7c866f254ed2b55bcb069e9ee3638b50d3e2192e9d29d3b2ffe089a.
- Three-property dispatcher `FUN_14000a100`: headers at 0x140008220, 0x140008240, and 0x140008260 give fixed sizes 1 (SET), 8 (GET only), and 4 (SET). The SET targets are 8-byte object slots (param_1[0..2]), so no overflow. Evidence: ev_e882d10a0e1bc4ea2e43265d5612e9c1c67fe13cffb7ed03bbf8a6a754a946b0; header bytes ev_7a6af600539639e7fea4e54353ad391d4c291dd8c4bc72d6f572060b0e7a56f2.
- `FUN_14000ec00` copies a fixed 0x30 bytes (called only from `FUN_14000a100`). Evidence: ev_54fa3306a3fb2f2350f6f7f916daf552607c2a831d776688ca65a645200c9ab6; callers ev_8f546645b3ea904957895e12632ed541f10ff23e836c1b2fac67448c6a23f105.
- WaveRT buffer path: `FUN_14000f6f0` (AllocateAudioBuffer, DMA-backed, with a block-alignment check) and `FUN_14000f910` (FreeAudioBuffer). No caller data is copied into a driver ring. Evidence: ev_ba53bae606c8bf5d9b326326245b1848949b95a917439160004eef6c740eb164; ev_fc01425c6fc3f61052b1fb814411943f247b54ecea64ee531e5f36a688476757.
- The 72-pointer `.rdata` table at 0x140005bc0 holds WaveRT stream method pointers (including FUN_14000f6f0, FUN_14000f910, FUN_14000fa50, FUN_14000f9a0). Evidence: ev_6f2cf38b391e26f70414f80189504e7a2757b87590c1e4118bf01130ce26f4fc. `FUN_14000fa50` dispatches KSSTATE (stop, acquire, pause). Evidence: ev_8a50f78a74ff3937d610ef6b62fd4a17c1ff65f296207651d6b5584d7dcdd0d2.
- `FUN_140010050` inserts a 0x18-byte pool object into a notification list. It copies nothing from caller data. Evidence: ev_f5cc17ffb1ce0ce7daaab2376ee7679dd9d5041f8b2bd5d649f9ff0a073047e4.
- The stream/pin init `FUN_14000fba0` allocates `cbSize + 0x12` bytes and copies the same length from the block returned by `FUN_14000ed40`. The destination is bounded by the allocation. The source length is driven by cbSize, which is read-side and out of scope. Evidence: ev_0ec8927173442217d01b42a7633bcc69ed196272ca5389471ceda3c1e1176866; ev_a30524910435dc543f4b868fb09c7d4f91f31c4b6833becaff551c35a4c7bcf5 (`FUN_14000ed40` checks only type, subtype, and specifier).
- The GS failure stub `FUN_140003990` copies at most 15 qwords into its own stack frame. Evidence: ev_b532557cbd778f458612e21a922bffaa8db7afad0ad506848dbf420e92c016f1.
- `FUN_14000a070` is a memmove (dst = object, src, size = caller-supplied param_4) followed by field stores. It has no direct callers. Its only references are data slots at 0x14000544c, 0x1400086d0, and 0x1400093c0, and no code references those slots. Evidence: ev_80dc77b6bbab22a422ff2417ea0786ada98aa9c799629215d4c72251d746367e; callers ev_9e1db9df053eeb2d2675714c424091ae180a0c34014d0e95476d6e6c96dea882; references ev_5f1bfed49437f0d6da1761689b64418349797bf8f117d129c7edca31fd118e1f; slot xrefs ev_9ffb9d1c2bc69d50bd99a1ae1bdb841c2d8153cdb18aecd98388ce7c4d03fa94.

## 4. Reachability

Proven in-file:
- The PortCls property dispatcher `FUN_14000be90` is the registered handler for the Pin-set table at `.data` 0x1400084f0. Pin-set requests reach the sub-handlers listed in section 3.
- The driver registers no IRP_MJ_DEVICE_CONTROL handler of its own. The only MajorFunction change is IRP_MJ_PNP (`FUN_14001129c`).
- The WDF driver config has no EvtDriverDeviceAdd, so no WDF device exists.

Not proven in-file:
- That IOCTL_KS_PROPERTY is routed to these handlers by PortCls for a standard user. This depends on PortCls and ks.sys, which are outside the driver image.
- That a standard user can open the device object. This depends on whether PnP applies the INF Security ACE (line 123, which grants `WD` GRGWGX) to the device object. The driver does not embed or parse the SDDL.
- That the `.data` PCPROPERTY tables are complete. Only the Pin table at 0x1400084f0 and the sets covered by `FUN_14000be90` were decoded.

## 5. Severity rationale

- No write primitive is proven for either case. Every direct memmove call site is bounded or validated: `FUN_14000bc00`, `FUN_14000ba5c`, `FUN_14000e85c`, `FUN_14000e748`, `FUN_14000ec00`, and `FUN_14000fba0` (write side). The GS stub `FUN_140003990` is frame-bounded.
- The WaveRT stream path has no caller-data copy into a driver ring, so the "copy into a fixed-size ring buffer" pattern is absent in this image.
- The only unresolved copy, `FUN_14000a070`, would matter if its size were caller-controlled and its destination object field were smaller than that size. That is unproven, so the rating stays NO-WRITE with a coverage qualifier.
- Cases (a) and (b) get the same rating because no sink was found. The ACE affects reachability only.

## 6. Open items

1. `FUN_14000a070` (memmove with caller-supplied size into an object): find the dispatching table, the caller of the size argument, and the destination object size. This is the decisive item. If the size is attacker-controlled and the destination is smaller, the rating would move to WRITE-HIGH for case (a), conditional on the Security ACE applying.
2. Dispatch targets not decompiled: `FUN_14000eab4`, `FUN_14000e954`, `FUN_14000ea50` (set GUID {47c8ff75-...}, Ids 1-3); `FUN_14000b8cc` (set GUID {4a4d16b8-...}, Id 1); `FUN_14000b9d4` (General set, Id 0); `FUN_14000f048` (Audio set, Id 33). None calls the memmove helper directly (see the caller list above), but they could use another copy route.
3. Other PCPROPERTY tables (around `.data` 0x1400086c0-0x140008838) and the `.rdata` function table at 0x140005ed8-0x140006098 are not mapped.
4. Inline or SSE copies are not excluded. The absence of rep movs was verified; a complete census of inline moves was not performed.
5. Adjacent read-side observation (out of scope, not rated): `FUN_14000fba0` takes its source length from the cbSize field of a format block that only has its type checked (`FUN_14000ed40`). An over-length source read is possible.
6. Whether PnP applies the INF Security ACE to the device object cannot be verified from the driver binary alone.
7. Config-control paths (registry reads and writes, for example ZwEnumerateValueKey and ZwSetValueKey) are out of scope.
8. Code sharing with the Sonar driver: not yet compared. See the Sonar report for the result.

## 7. Evidence list

- ev_ee7eca28d3497d107610c206449041ec5d59a345dd4bd4b3db04f6f0d767344f (open result, Probe)
- ev_c19fdd7371817b4defe0d47c69046cafa03d4d6624a8ae4012b96ef4f81d931a (Mm)
- ev_318943198343d047324a8140dfff63e095a47ea34ed7bd5e9a1febd1421bed7d (Io)
- ev_345a73ab47c393644c65a63ec00e82675b4171640fbfc3bc82baca1e08360162 (Ks)
- ev_084e84534c7d71e841aa8a50b5144f690525bc84c3dfc3dfd2b4ffb0aa74c1bd (Ex)
- ev_d1be638754e00b4c4a802f398ae02c3f1d2571fdfcfde3dd2b6f4d36b68fcdde (copy)
- ev_a3639505bc7d8b7f3f3cfc14ad62bab09b6c22dee8b08ac03c2e7be46a415644 (mem)
- ev_be79ff867eabdbe44f5b0660c96e25b5a1599afb36ab9dcd6a05b13ba99d708a ("(A;" strings, none)
- ev_5d5e384645cbbfd6e83f23fa20b00a0e51b326e255ed2dad32eff48978646f26 ("\Device\" strings, none)
- ev_c1c2f1d11e5cb9eb4c9820775758df79a4a4532d0545b270ada0433695f93e84 (IOCTL_KS strings, none)
- ev_2f3ff6fb112338731956ad9b090a1efc74503bf2a8ad303cb6b1cf536e8c4906 (full import list)
- ev_6c581229fbfa9e7334b786d6e1d0d0142579bbfe7cd30076c0333a608d4e18e3 (Probe strings, none)
- ev_9d30b24f14a0d01a0c667ef1c6b1f42d9ee984db35f53f4e5c85cdb098055966 (Mdl strings, none)
- ev_5003b8823755b296295a9d2e28bfdf22b4bff666e261b267491dde0a3744644c (Stream strings, none)
- ev_00af734b3a0a835f88196c55fdadfa04e3906b36cb2624f99fbdd0fa9235c1e5 (Security strings, none)
- ev_14e4f04e4634bd5730ee31fbd25b1be9ae9293f409c0cbc880616cd6a9765c42 (Pc strings)
- ev_5e84040fe674a6aa14c8636424fc117b00b577484072c09c70902ff54347a3ad (rep movsb, none; block layout)
- ev_3587acb185f251c4dd7024e61d8aa642d24bf3191b7ef61606a39cc5865215b2 (rep movsq, none)
- ev_eaf4d8b9fdb4c653ead52487e47d3bf8394293ff020076e111d87cf67859661a (entry)
- ev_ec4101fbea9ad5c2af7bc24f7c945b1b4025ae685c78a78887b02cc0ec878ddc (DriverEntry)
- ev_fc8b8779e9ef779c775fd48610a086819b968ee6e43cba97f07a88da027c615a (FUN_14001129c)
- ev_9e5574e83675a8faea3f67509f49ac280a633a5d2d7e95aee1801c8c3173a4b3 (FUN_14000a220, AddDevice)
- ev_42fd3027f82b4f5c52f04bb0e3a42e466069b91dd668509372a14f10a555837f (DriverEntry call site)
- ev_6145d638c0823afaa940031fb8c8f3ad1e5c423f85fbb932a1f2badf983dc571 (PcInitializeAdapterDriver call site)
- ev_78d5693b957a1de935bdd48b4bcd18e06bf365f24231a69bca6952fd1ede31fc (PORTCLS slot xrefs)
- ev_480b50ed5d1afc135067b7604892a448902d3c3821fe7571f6064b422fd0de09 (FUN_140003fc0 memmove)
- ev_ad0984ffff47093f5fb29ff45c2b44ad985a518943db0f92c2b839111fa6c437 (memmove callers)
- ev_43c4b6fc050e74863153e2048a13c11be07ffd8430896d41de59431d4d32a8ec (FUN_14000be90 dispatcher)
- ev_8e1b435875b4c1d0c3e5483facf6530d71085d6faf5e2f344ae1d4af73dec652 (PCPROPERTY table at 0x1400084f0)
- ev_2b20177c01e139840c715eb32e60251e7aded194965f432a91f95f64da3ad581 (Pin GUID bytes at 0x140005840)
- ev_2bf0a455082c88e2286b89aeaf6a765841ce8c67d2e6ccaa01c68498dd35178b (Pin GUID references)
- ev_508717372268cf375445340c1e7112c9eb51c1906a0ed6f2288fad019fbc22a1 (FUN_14000b500)
- ev_bc1158ad338ab4ffbe5dc08f26a1a99a1fcf455edbad006f73e038b8b6a77ed5 (FUN_14000bc00)
- ev_18d47cbd964f0a971ba1f3643cf7d2b501f540fe6d9b4c8b2cf021df61f08af0 (.data dump 0x140008010)
- ev_0d82507bb8ede425dc6d94b2f9791c748f7a05935bbee61520d7de43252b9e07 (FUN_14000ba5c)
- ev_93c470b229f71bab84772056d77c4b07579494a602191f813b6324329f230bc2 (FUN_14000f32c)
- ev_7ebbadceaae950f0721ebada2cd5b220509dcd544c36b83947fc145aa05a7e92 (FUN_14000f0ac)
- ev_5501f8559bc40a93fbb2438b2ab8d0291b8636e9d06df5039381554152adfc30 (FUN_14000f1d0)
- ev_284dc4866c5c98821dcafa2c76775a7da1ad9241c1b6174bfcaa2a77e39609fc (FUN_14000f4c0)
- ev_e4835be39cfee583d477d85f39e11bfafe00127890e753c1e3f7a6c75a2e3c75 (FUN_14000e85c)
- ev_392ae1856109a6f9db4cea3c4a014c1703a4c02e8f49c1cc0bc1bbcc484d32f5 (FUN_14000e748)
- ev_b2824cfaa7c866f254ed2b55bcb069e9ee3638b50d3e2192e9d29d3b2ffe089a (FUN_14000e748 callers)
- ev_a0e23e4c5337e1574abebe790b93774dba7907233424c21a915624ddc44b1f06 (FUN_14000ec9c)
- ev_e882d10a0e1bc4ea2e43265d5612e9c1c67fe13cffb7ed03bbf8a6a754a946b0 (FUN_14000a100)
- ev_7a6af600539639e7fea4e54353ad391d4c291dd8c4bc72d6f572060b0e7a56f2 (headers 0x140008220)
- ev_0e4ab4c5070063c5f14b0b413fe76a77f33360ec10db8f612ec82ff9ac74a7ef (FUN_14000a100 xrefs)
- ev_54fa3306a3fb2f2350f6f7f916daf552607c2a831d776688ca65a645200c9ab6 (FUN_14000ec00)
- ev_8f546645b3ea904957895e12632ed541f10ff23e836c1b2fac67448c6a23f105 (FUN_14000ec00 callers)
- ev_80dc77b6bbab22a422ff2417ea0786ada98aa9c799629215d4c72251d746367e (FUN_14000a070)
- ev_9e1db9df053eeb2d2675714c424091ae180a0c34014d0e95476d6e6c96dea882 (FUN_14000a070 callers, none)
- ev_5f1bfed49437f0d6da1761689b64418349797bf8f117d129c7edca31fd118e1f (FUN_14000a070 references)
- ev_9ffb9d1c2bc69d50bd99a1ae1bdb841c2d8153cdb18aecd98388ce7c4d03fa94 (slot 0x1400086d0 xrefs, none)
- ev_ba53bae606c8bf5d9b326326245b1848949b95a917439160004eef6c740eb164 (FUN_14000f6f0)
- ev_fc01425c6fc3f61052b1fb814411943f247b54ecea64ee531e5f36a688476757 (FUN_14000f910)
- ev_c26f2183fae19aa2711c3e0d9fcf8ce2e82b4546d93ba61372151df22f781a6d (FUN_14000f9a0)
- ev_8a50f78a74ff3937d610ef6b62fd4a17c1ff65f296207651d6b5584d7dcdd0d2 (FUN_14000fa50)
- ev_f5cc17ffb1ce0ce7daaab2376ee7679dd9d5041f8b2bd5d649f9ff0a073047e4 (FUN_140010050)
- ev_6f2cf38b391e26f70414f80189504e7a2757b87590c1e4118bf01130ce26f4fc (72-pointer table at 0x140005bc0)
- ev_0ec8927173442217d01b42a7633bcc69ed196272ca5389471ceda3c1e1176866 (FUN_14000fba0)
- ev_a30524910435dc543f4b868fb09c7d4f91f31c4b6833becaff551c35a4c7bcf5 (FUN_14000ed40)
- ev_b532557cbd778f458612e21a922bffaa8db7afad0ad506848dbf420e92c016f1 (FUN_140003990)
- ev_b69d74ed44c4796540e02e93343c94b253bdd5e146b4ba486f79f376e8f2b3b4 (KSPROPSETID_Audio GUID search, none)
- ev_1c4b51e2711e0a63de83d714788e45fff1777b5d1eda38984fcefd292449934e (KSPROPSETID_Topology GUID search, none)
- ev_1317faf3242a96e974faad5e1e05703e355acce2930908b53a1210101c551bc0 (FUN_14000dac0 callers, none)
- ev_ffdd67b86ed66d1e049d6bfadadf69e8652ed05c237954b9a3086c431ab9b641 (pointer sweep, .rdata/.data)
- ev_8468dffb57d1604d35fea40cb26605fa98ac30749ba4e184f232f63b76ed929b (pointer sweep, 0x14001xxxx)
- ev_6a60525af613937a256a288fe607eba161eef2962132bec5ba06b1a36f123be9 (.rdata dump 0x140005ea0)
- ev_f6dc64650302f0b460e42a1c90cb4e4505c96445ae9e08584910c562fa8538c5 (GUID bytes 0x140005850)
