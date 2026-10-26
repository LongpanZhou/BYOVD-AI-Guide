# SteelSeries Sonar VAD (SteelSeries-Sonar-VAD_2685B48C.sys): static memory-write audit

Setup required: devnode (from audits\steelseries_nonrea_triage.md, setup_required row; ROOT\ hardware ID at INF line 29)

Scope: memory-write primitives only (copy, map, and memory paths in KS, property, and stream handlers). Static analysis only. The driver and its INF were not loaded, installed, or run, no device was opened, and no IOCTL was sent. No proof-of-concept material is included. INF facts, setup classification, import groups, and Authenticode belong to the non-REA triage report.

## 1. Summary

| Case | Rating | Qualifier |
|---|---|---|
| (a) standard user can reach the sink | WRITE-MEDIUM | provisional, conditional on the stream block size exceeding the ring capacity (provenance unresolved) |
| (b) only an administrator can reach the sink | WRITE-MEDIUM | provisional, conditional (same sink; same condition) |

- Candidate structural sink: the stream ring write `FUN_140003080` copies its wrap-around segment with a length that is not clamped to the ring capacity. The trigger (chunk length greater than capacity) is not proven. Chunk length is driven by the timer pump and bounded by the stream block size (`obj+0x88`). Capacity is probably the driver-owned table value `lVar3+0x120` (not directly traced). The provenance of `obj+0x88` decides standard-user reachability.
- No caller-controlled copy length was found in the KS property handlers. All property copies are bounded by fixed header sizes or by caller buffer sizes that are checked.
- Second unresolved sink: `FUN_14000c070` is a memmove into an object with a caller-supplied size. It has no direct caller (see section 6). It is the same function as Engine's `FUN_14000a070`.
- Candidate tiers: not entered. Setup required is `devnode` (triage report), so these primitives do not enter the candidate tiers. They are rated for completeness only.

## 2. Header facts

- File: `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected2\drivers\SteelSeries\SteelSeries-Sonar-VAD_2685B48C.sys` (95,912 bytes, x86_64 PE, KMDF stub present: `FxStubDriverUnloadCommon`)
- SHA-256: `2685B48C431FBECD4586F72335107A71A2A60C8747AA362979CF059DF8522527` (Get-FileHash). The REA open result digest is `2685b48c431fbecd4586f72335107a71a2a60c8747aa362979cf059df8522527`. The two agree.
- Version: INF `DriverVer = 04/14/2026,15.7.9.759`. The PE version resource was not read.
- Class: MEDIA (ClassGUID {4d36e96c-e325-11ce-bfc1-08002be10318}). Triage report is authoritative for INF facts.
- Hardware ID: `ROOT\VEN_SSGG&DEV_0001` ("SteelSeries Sonar Virtual Audio Device"), INF line 29. Root-enumerated devnode.
- Device interfaces registered by the INF: KSCATEGORY_AUDIO, KSCATEGORY_RENDER, KSCATEGORY_CAPTURE, KSCATEGORY_TOPOLOGY (INF lines 246-290).
- INF Security ACE (AUDIOHW.AddReg, INF line 309), exact text: `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)`. The `WD` (Everyone) ACE grants GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE. The SDDL string does not appear in the .sys (search for `(A;` returned nothing).
- PDB reference in the image: SteelSeries-Sonar-VAD.pdb (load state unknown).
- Setup required: devnode (triage report).

## 3. Verified facts

- Sweeps: no `rep movsb` (F3 A4) and no `rep movsq` (F3 48 A5) anywhere in the image. Evidence: ev_903a16e71713a503e76974487ff83e09eb1c6f402de431d7a4acbe69087a06a2; ev_c0730339b0a3f82c12639d7eb7b496ff1346133fa8575ee65ce0a2831ec7eefc.
- Name sweeps: no Probe; `Mm` gives only MmGetSystemRoutineAddress and KMDF stubs; `mem` gives only RtlCompareMemory; `copy` gives only RtlCopyUnicodeString. Evidence: ev_c58cf29db4c61dd5348a8cdb106c95a0fbbf050a9ba8994d6175245635f512a7; ev_66b5dc6c01f90897424ea7dbbe19439e0461603908753b7957e79bc54c3be608; ev_d5eb56b4f463914907d04a7a0b1ce6bf5544bf0b5efdec05844a27c100ce1a44; ev_a0ed5392cf4c919cf11b403194a961bd184d664f82bdbdd22055123ee5551719.
- Strings: no `(A;` and no `\Device\` string. Evidence: ev_dddfd005b8e7bd5dc0338dd56c3c2c97066a9dbcc176865131bdb3bbbfbf2ce3; ev_729e41c8a97d64429d8826184a0a568ee7f9175c3dcd26d118e61308ef1e1030.
- The driver's own memmove is `FUN_140004580` (overlap-aware dst, src, size; same shape as Engine's `FUN_140003fc0`). Its complete direct caller set (REA relationship coverage "complete") is 0x140002fa8, 0x140003080, 0x140004080, 0x14000c070, 0x14000de08, 0x14000dfc0, 0x140010c24, 0x140010d38, 0x1400110dc, 0x1400124c0. Evidence: ev_3af13c20e556cd5eb219e8cc88f9e7a7bab94e236dda7c15bb79a0258f6b4845; ev_4bda0ffb85a0ed59d2c565add80a4a3aa5a970efb272431c688dc9fa63e010d2.
- Pool allocation sites (ExAllocatePoolWithTag, EXTERNAL:0x2): 38 xrefs. Evidence: ev_29af443d5d91c3de9fb544fa4173b298af43d7f30b8eb2978e1068fb33c5bf8c; ev_10708f4b244534a82ba4a08bdb5d57b25485ebf7c078747350791f6f703843d0.
- PCPROPERTY dispatcher `FUN_14000e250` (set GUID and Id routing; Pin Id 14 to `FUN_14000dfc0`, Pin Id 15 to `FUN_14000de08`, General Id 0 to `FUN_14000dd80`, set {4a4d16b8} Id 1 to `FUN_14000dc54`, set {47c8ff75} Ids 1-3 to `FUN_140010f90`/`FUN_140010e30`/`FUN_140010f2c`, Audio-type Ids 4, 13, 33, 55 to `FUN_1400117fc`/`FUN_140011578`/`FUN_140011518`/`FUN_14001169c`). Evidence: ev_b25ead088b2edb36ae8fbd8417ae979a605c80dcad2ee2bcfb0c04f84f30b1c4.
- Pin-set GUID {8C134960-51AD-11CF-878A-94F801C10000} is at 0x1400057c8. It is referenced from two `.data` PCPROPERTY tables (0x140008b18, 0x1400096a8) and from code at 0x14000e2c4. Evidence: ev_0170a3478ac348ac2c166a944bcffd1499418bbe9d3c2ab9ffc3fc3d828aee2a; ev_8486f834c974a25ff9f4198fe5e57e5dfc90da70059a50d09a1f6c05d422c253; table bytes ev_3b3f520564492c903261a3002abeb47a103ef3740cd9f64844d822e7472acc69 and ev_359116868cf24145c82e7286a0fd472f20b6e16c6640618747a8c5a66a26275e.
- Pin Id 14 GET (`FUN_14000dfc0`) copies a driver-owned format block with `FUN_140004580`. The copy length is the block's size dword. The code requires ValueSize >= 0x68 first. SET matches the user format against a fixed table (`FUN_14000d8ac`) and does not store user bytes. Evidence: ev_ef3c3c5dc260ba2fe0703c47d60fda84dc0d0644b2a1c6da311173d53d42512d.
- Pin Id 15 (`FUN_14000de08`) is GET-only. It copies a driver block plus the user instance tail (InstanceSize - 8) to the output and requires aligned(block size) + tail <= ValueSize. Evidence: ev_afcf9676f725241dc214b3c69a48e690892444722e32379f3dfb48b2bbe42b79.
- Generic three-property dispatcher `FUN_14000c0f0` (headers DAT_140008600/620/640) calls the generic helper `FUN_140010c24` with user length = InstanceSize - 8, and calls `FUN_1400110dc(obj[9], obj+3, 0x30)` with a fixed 0x30. Evidence: ev_e7a17d19e9da29285a0ad8ae1f926e7449f5f09810242db3e78df148dcd9c184.
- `FUN_140010c24` (generic helper): SET copies a fixed header size only after `FUN_140011174` validates that the user length is >= that size; GET is bounded by the output size. Same design as Engine `FUN_14000e748`. Evidence: ev_2d1e57cf990fa9e8b95635c9d13050d5197b982b04bbaa2e7af1352bd14869e9.
- `FUN_140010d38` (BASICSUPPORT): output bounded by `*param_3 >= total`. Evidence: ev_21d26ebc505c1b66339c173448bbac0dd48b120f20f3cf93cbcce521e496e0b2.
- `FUN_1400110dc` allocates exactly `param_3` bytes and copies the same length into it (called only with 0x30 from `FUN_14000c0f0`). Evidence: ev_769d56b672e9c3a388c32713bddaedaf1633799a26a2ccbd856cd41c8f865d37; callers ev_a947598094a0bdc64209c2df212111e9de57948de2d8c926ff1f1d4bbf18eeb6.
- Stream/pin init `FUN_1400124c0`: allocates `cbSize + 0x12` bytes for the format copy (source from `FUN_140011218`, which checks only type, subtype, and specifier), then sets up arrays with memset. The destination is bounded by the allocation. The source length is cbSize-driven: read-side over-read possible, out of scope. Evidence: ev_885eec6e5a14db7fae76f416b5286e9935e14c942147bb5644da55b6e9275c81.
- GS failure stub `FUN_140004080` copies at most 15 qwords into its own frame. Evidence: ev_29b4921e27132c6970084f2b4d0be9882006fd6a8eb409c6925377a1f48d9445.
- Stream ring write `FUN_140003080(ring, len, src)`: the first copy is clamped to the room before the ring end. The second (wrap) copy has length `len - first`, which is not clamped to the ring capacity. Evidence: ev_d27b351150beedbd925e519333b7eedeb3ad195e875118a0b7f51a325921661e. Its only direct caller is `FUN_140003330` (ev_c3f81ce96271524399ccf1120031137a196c8a618fe452698d416cb69030883f).
- `FUN_140003330` (fill pump): chunk length = min(count, block - pos % block), where block = `obj+0x88`. Source = stream buffer `obj+0x90`, destination = ring. It has no direct callers and is reached from a table (slots 0x1400052c8 and 0x140006240). Evidence: ev_8fcdbb01a5f780fd8d8984dbcc267176eb5ea506ec4b518897040a57ea023672; ev_3ba338f2c8e4d2bf607ced3a60cf587154137af877102eeba2293e792a6af383; xrefs ev_c08d8ff345f83762eaf82a2d7f69aa9e30d51bee05231478b4091ddad58a1c61.
- Stream ring read `FUN_140002fa8` (called only from `FUN_140003440`): copies min(requested, available) bytes out of the ring, bounded by the caller length. Evidence: ev_0ed57d19a970a51e9ceab5ac2ae1c0ff4acedec3a8ce3344d5bfe267f197d883; caller ev_4c2497856af96abc455cc3ce3f441dd67dbe7a1206beec578668d8edeb2b9a1.
- `FUN_140003440` (drain pump): reads from the ring, or zero-fills when the ring is inactive. No direct callers; table slots 0x1400052d0 and 0x140006238. Evidence: ev_72229954c7d1a870aa9153071e461fa04f7ae9502e40f7051fb297cac9e741e6; ev_6e9d78cbf4c6d856d80ce1784e8c96bffa8d58c4ca65add861f1be53789fb2ab; xrefs ev_d162e1dee0339d770fc3fd9ca6f9e84a6ae9a2a1a141ec2cc984b01d6b7fa3bc.
- Timer callback `FUN_140002ab0` (ExAllocateTimer callback; `KeQueryPerformanceCounter` based). It gates the pump on elapsed time and calls the pump through the object vtable with count = `obj+0x88 / obj+0x98` (driver fields), not a user request. Evidence: ev_4aed13c71234a6a704aedcb84b85539d92873531deaedc7f07a17f4b279d5bd2.
- `FUN_14000ce84` allocates per-entry buffers sized by a driver table value (`lVar3+0x120`) and sets up callbacks; the sizes are driver-derived. Evidence: ev_fc6d6fdb09c7f9c6f2e4b7193dfd2fae92b453590d0dc3a36d8cbd03d3850897. `FUN_14000e61c` stores pointers into lists and copies nothing. Evidence: ev_c00ad2f88310f11aef23106e8034005447ac8721171a4bc5b25aece1a403b071.
- `FUN_14000c070` is a memmove (dst = object, src, size = caller-supplied) followed by field stores. It has no direct callers. Evidence: ev_10a2a6d9273c76ada6eaedd1fa093313972ea934fe4650794111b5d6ba44ab42; callers ev_7ba04aa8f061cd061efc085b69d5d17d60e9d862338c342ed943f826ea976bda.

## 4. Reachability

Proven in-file:
- The PortCls-style property dispatcher `FUN_14000e250` is the handler for the Pin-set table and for the other sets listed in section 3.
- The stream pumps are driven by a timer (`FUN_140002ab0`), so their copy counts are timer-driven, not caller-supplied.
- The driver registers no IRP_MJ_DEVICE_CONTROL handler of its own (no code writes to the MajorFunction table in the sections read).

Not proven in-file:
- Whether `obj+0x88` (stream block size) can be set from a standard-user request (for example RequestedBufferSize) and can exceed the ring capacity from `lVar3+0x120`. This decides whether the ring overflow is reachable.
- Whether IOCTL_KS_PROPERTY reaches these handlers for a standard user. That depends on PortCls and ks.sys, and on whether PnP applies the INF Security ACE to the device object.
- That the property tables are complete. The Pin table and the sets routed by `FUN_14000e250` were decoded. The `.data` tables at 0x1400096a8 and the GUIDs at 0x1400057d8 and 0x1400057e8 were not fully decoded.

## 5. Severity rationale

- The ring wrap copy in `FUN_140003080` is unclamped relative to ring capacity. That is a structural memory-write sink. Its trigger requires a chunk greater than the ring capacity, which is possible only if the stream block size is larger than the capacity. The block size is driver-derived, but its provenance was not traced.
- The copy source (the WaveRT buffer) is user-writable shared memory, but the length is not user-controlled. The user can change data, not size.
- Case (a) and case (b) get the same rating because the sink is the same and no caller path has been traced to a standard user.
- Because the trigger is unproven, both cases are provisional and conditional. Verdict: WRITE-MEDIUM (provisional, conditional), not higher.

## 6. Open items

1. Stream block size provenance: find every writer of `obj+0x88` (block size) and the ring capacity source (`lVar3+0x120`, `FUN_14000ce84`). If a standard-user request can set the block size above the capacity, rating (a) moves to WRITE-HIGH (conditional on device ACL). If not, rating drops to NO-WRITE.
2. `FUN_14000c070` (memmove with caller-supplied size into an object): find the dispatching table and the size source. It is the same function as Engine's `FUN_14000a070`, so resolving one resolves the other.
3. Dispatch targets not decompiled: `FUN_140010f90`, `FUN_140010e30`, `FUN_140010f2c`, `FUN_14000dc54`, `FUN_14000dd80`, `FUN_1400117fc`, `FUN_140011578`, `FUN_140011518`, `FUN_14001169c`. None of them is a direct caller of the memmove or of the generic helper (see the caller lists), so they do not copy through these routes.
4. Tables not decoded: the `.data` table at 0x1400096a8 beyond its first entry, and the GUIDs at 0x1400057d8 and 0x1400057e8.
5. Inline or SSE copies are not excluded. The absence of rep movs was verified; a complete census of inline moves was not performed.
6. Adjacent read-side issue (out of scope, not rated): `FUN_1400124c0` takes the source length from a format cbSize that is only type-checked. The same finding applies to Engine.
7. Whether PnP applies the INF Security ACE to the device object cannot be verified from the driver binary alone.
8. Setup (DriverEntry device creation for this driver) was not analyzed in this REA pass. That topic belongs to the triage report.

## Note: shared code with the Engine driver

- The two drivers share code at the library level. The memmove routine (`FUN_140004580` vs `FUN_140003fc0`), the GS failure stub (`FUN_140004080` vs `FUN_140003990`), the property dispatcher (`FUN_14000e250` vs `FUN_14000be90`), the generic three-property helper (`FUN_140010c24` vs `FUN_14000e748`), the BASICSUPPORT helper (`FUN_140010d38` vs `FUN_14000e85c`), the format copy (`FUN_14000dfc0` vs `FUN_14000bc00`), the stream init (`FUN_1400124c0` vs `FUN_14000fba0`), and the indirect memmove into an object (`FUN_14000c070` vs `FUN_14000a070`) have the same logic. Byte-level identity was not verified, because the Engine image was closed before this comparison.
- The Sonar driver adds the stream pump and ring (`FUN_140003080`, `FUN_140003330`, `FUN_140003440`, `FUN_140002fa8`), which the Engine driver does not have. That ring code is the source of the one structural sink above.

## 7. Evidence list

- ev_903a16e71713a503e76974487ff83e09eb1c6f402de431d7a4acbe69087a06a2 (rep movsb sweep, none; block layout)
- ev_c0730339b0a3f82c12639d7eb7b496ff1346133fa8575ee65ce0a2831ec7eefc (rep movsq sweep, none)
- ev_66b5dc6c01f90897424ea7dbbe19439e0461603908753b7957e79bc54c3be608 (Mm)
- ev_c58cf29db4c61dd5348a8cdb106c95a0fbbf050a9ba8994d6175245635f512a7 (Probe, none)
- ev_d5eb56b4f463914907d04a7a0b1ce6bf5544bf0b5efdec05844a27c100ce1a44 (mem)
- ev_a0ed5392cf4c919cf11b403194a961bd184d664f82bdbdd22055123ee5551719 (copy)
- ev_dddfd005b8e7bd5dc0338dd56c3c2c97066a9dbcc176865131bdb3bbbfbf2ce3 ("(A;" strings, none)
- ev_729e41c8a97d64429d8826184a0a568ee7f9175c3dcd26d118e61308ef1e1030 ("\Device\" strings, none)
- ev_0170a3478ac348ac2c166a944bcffd1499418bbe9d3c2ab9ffc3fc3d828aee2a (Pin GUID bytes 0x1400057c8)
- ev_8486f834c974a25ff9f4198fe5e57e5dfc90da70059a50d09a1f6c05d422c253 (Pin GUID xrefs)
- ev_3b3f520564492c903261a3002abeb47a103ef3740cd9f64844d822e7472acc69 (PCPROPERTY table 0x140008b18)
- ev_359116868cf24145c82e7286a0fd472f20b6e16c6640618747a8c5a66a26275e (table 0x1400096a8)
- ev_b25ead088b2edb36ae8fbd8417ae979a605c80dcad2ee2bcfb0c04f84f30b1c4 (FUN_14000e250 dispatcher)
- ev_ef3c3c5dc260ba2fe0703c47d60fda84dc0d0644b2a1c6da311173d53d42512d (FUN_14000dfc0)
- ev_afcf9676f725241dc214b3c69a48e690892444722e32379f3dfb48b2bbe42b79 (FUN_14000de08)
- ev_3af13c20e556cd5eb219e8cc88f9e7a7bab94e236dda7c15bb79a0258f6b4845 (FUN_140004580 memmove)
- ev_4bda0ffb85a0ed59d2c565add80a4a3aa5a970efb272431c688dc9fa63e010d2 (memmove callers)
- ev_29af443d5d91c3de9fb544fa4173b298af43d7f30b8eb2978e1068fb33c5bf8c (ExAllocatePool search)
- ev_10708f4b244534a82ba4a08bdb5d57b25485ebf7c078747350791f6f703843d0 (ExAllocatePoolWithTag xrefs)
- ev_e7a17d19e9da29285a0ad8ae1f926e7449f5f09810242db3e78df148dcd9c184 (FUN_14000c0f0 dispatcher)
- ev_2d1e57cf990fa9e8b95635c9d13050d5197b982b04bbaa2e7af1352bd14869e9 (FUN_140010c24 generic helper)
- ev_134a4638d67741eeb7e69ab8539c7803db8b349a2a50d8eb45efb6d0b03ab6ee (FUN_140010c24 callers)
- ev_21d26ebc505c1b66339c173448bbac0dd48b120f20f3cf93cbcce521e496e0b2 (FUN_140010d38)
- ev_769d56b672e9c3a388c32713bddaedaf1633799a26a2ccbd856cd41c8f865d37 (FUN_1400110dc)
- ev_a947598094a0bdc64209c2df212111e9de57948de2d8c926ff1f1d4bbf18eeb6 (FUN_1400110dc callers)
- ev_885eec6e5a14db7fae76f416b5286e9935e14c942147bb5644da55b6e9275c81 (FUN_1400124c0 stream init)
- ev_29b4921e27132c6970084f2b4d0be9882006fd6a8eb409c6925377a1f48d9445 (FUN_140004080 GS stub)
- ev_d27b351150beedbd925e519333b7eedeb3ad195e875118a0b7f51a325921661e (FUN_140003080 ring write)
- ev_c3f81ce96271524399ccf1120031137a196c8a618fe452698d416cb69030883f (FUN_140003080 callers)
- ev_8fcdbb01a5f780fd8d8984dbcc267176eb5ea506ec4b518897040a57ea023672 (FUN_140003330 fill pump)
- ev_3ba338f2c8e4d2bf607ced3a60cf587154137af877102eeba2293e792a6af383 (FUN_140003330 callers, none)
- ev_c08d8ff345f83762eaf82a2d7f69aa9e30d51bee05231478b4091ddad58a1c61 (FUN_140003330 xrefs)
- ev_0ed57d19a970a51e9ceab5ac2ae1c0ff4acedec3a8ce3344d5bfe267f197d883 (FUN_140002fa8 ring read)
- ev_4c2497856af96abc455cc3ce3f441dd67dbe7a1206beec578668d8edeb2b9a1 (FUN_140002fa8 callers)
- ev_72229954c7d1a870aa9153071e461fa04f7ae9502e40f7051fb297cac9e741e6 (FUN_140003440 drain pump)
- ev_6e9d78cbf4c6d856d80ce1784e8c96bffa8d58c4ca65add861f1be53789fb2ab (FUN_140003440 callers, none)
- ev_d162e1dee0339d770fc3fd9ca6f9e84a6ae9a2a1a141ec2cc984b01d6b7fa3bc (FUN_140003440 xrefs)
- ev_4aed13c71234a6a704aedcb84b85539d92873531deaedc7f07a17f4b279d5bd2 (FUN_140002ab0 timer callback)
- ev_fc6d6fdb09c7f9c6f2e4b7193dfd2fae92b453590d0dc3a36d8cbd03d3850897 (FUN_14000ce84)
- ev_c00ad2f88310f11aef23106e8034005447ac8721171a4bc5b25aece1a403b071 (FUN_14000e61c)
- ev_10a2a6d9273c76ada6eaedd1fa093313972ea934fe4650794111b5d6ba44ab42 (FUN_14000c070 memmove into object)
- ev_7ba04aa8f061cd061efc085b69d5d17d60e9d862338c342ed943f826ea976bda (FUN_14000c070 callers, none)
