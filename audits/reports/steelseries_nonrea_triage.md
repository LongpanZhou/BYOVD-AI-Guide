# SteelSeries non-REA static triage: Engine and Sonar VAD drivers

Date: 2026-10-24
Targets: `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected2\drivers\SteelSeries\` (SteelSeries-Engine-VAD_78C729CA and SteelSeries-Sonar-VAD_2685B48C; each with .sys, .inf and .cat)

**Constraints followed:** static only. No mcp__rea__ calls. Nothing was loaded, run, installed, or opened as a device. Files were read as bytes and text only.

**Labels:** [observed] = read from bytes, text, or tool output. [inferred] = my reading of observed facts. Offsets are hex file offsets. INF line numbers are 1-based.

**Method [observed]:** Imports were parsed with a read-only PowerShell reader (DataDirectory[1], section map, import descriptors, thunk arrays, IMAGE_IMPORT_BY_NAME). Cross-checks: each flagged name found by a raw byte search sits 2 bytes after the parser's entry offset (the hint word), and each DLL's import address table ends where the next DLL's begins (Engine: ntoskrnl FT 0x5040 + 33 slots = portcls FT 0x5148; Sonar: 0x5040 + 32 slots = 0x5140). Per-import dumps (name, DLL, entry offset) are in `C:\Users\<scrubbed>\AppData\Local\Temp\claude\C--Users-<scrubbed>\fa78ce70-0327-465b-ad3c-3048d39ce3cf\scratchpad\SteelSeries-Engine-VAD_78C729CA.sys.imports.csv` and `...\scratchpad\SteelSeries-Sonar-VAD_2685B48C.sys.imports.csv`.

**Naming [observed]:** Each collected file's suffix (78C729CA, 2685B48C) is the first 8 hex digits of its own SHA-256. The INFs name the files `SteelSeries-Engine-VAD` and `SteelSeries-Sonar-VAD` without a suffix (.sys at INF lines 14, 17, 38, 42 and 114 for Engine, and 14, 17, 38, 42 and 300 for Sonar; .cat at line 7 of each), so the collected names do not match what the INFs expect.

## Summary

| | Engine | Sonar |
|---|---|---|
| setup_required | devnode (INF line 29) | devnode (INF line 29) |
| Hardware ID | ROOT\VEN_SSGG&DEV_0002 | ROOT\VEN_SSGG&DEV_0001 |
| Imports | 47 in 4 DLLs | 46 in 4 DLLs |
| Group (a) hits | none | none |
| Group (b) hits | IoRegisterDeviceInterface, WdfVersionBind | IoRegisterDeviceInterface, WdfVersionBind |
| Device-creation path | AddDevice (PnP) [inferred] | AddDevice (PnP) [inferred] |
| Authenticode (.sys) | Valid | Valid |

## 1. SteelSeries-Engine-VAD_78C729CA.sys

### 1.1 File [observed]
- Path: `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected2\drivers\SteelSeries\SteelSeries-Engine-VAD_78C729CA.sys`
- SHA-256: `78C729CA45F8BA7EC66988E1B26574655766DD330EEB25A00E44D33E9E927821`
- Size: 82,608 bytes
- PE: x64 (Machine 0x8664), PE32+, 8 sections, e_lfanew 0xE8. TimeDateStamp 0x6AA16185 = 2026-09-09 13:39:17 UTC (file offset 0xF0).
- DataDirectory[1] (import): RVA 0x11468, size 0x64, file offset 0xDE68. Delay imports: none. Security directory (Authenticode blob): file offset 0xEE00, size 0x54B0.
- Companions: .inf 6,633 bytes, SHA-256 `4E2DA040A9B0EFBA8BBEAEE2C86B8B906A833CB6BA9BA64E3C1BA94B68FC99C5`; .cat 12,732 bytes, SHA-256 `5DCC034FDAB7C9FF21B856A9BFA7CFCF83515659457E54F2EAC958CE8F07CA42`.

### 1.2 INF facts [observed]
File: `SteelSeries-Engine-VAD_78C729CA.inf` (6,633 bytes; ASCII, CRLF).
- Class `MEDIA` (line 3). ClassGUID `{4d36e96c-e325-11ce-bfc1-08002be10318}` (line 5).
- DriverVer `09/09/2026,1.1.0.0` (line 6). CatalogFile `SteelSeries-Engine-VAD.cat` (line 7). PnpLockDown = 1 (line 8).
- ProviderName and MfgName: "SteelSeries ApS" (lines 171-172).
- Hardware ID (line 29): `ROOT\VEN_SSGG&DEV_0002`, DeviceDesc "SteelSeries Engine Virtual Chat" (line 174). It is the only hardware ID in the file.
- Install sections:
  - `[SteelSeries_Engine_VAD_SA.NT]` (lines 91-95): Include=ks.inf,wdmaudio.inf; Needs=KS.Registration, WDMAUDIO.Registration, MsApoFxProxy.Registration; CopyFiles (line 94); AddReg (line 95).
  - Service: `[SteelSeries_Engine_VAD_SA.NT.Services]` line 107 uses **AddService**: `AddService=SteelSeries_Engine_VAD,0x00000002,SteelSeries_Engine_VAD_Service_Inst`. Service section (lines 109-114): ServiceType=1, StartType=3, ErrorControl=1, ServiceBinary=%13%\SteelSeries-Engine-VAD.sys.
  - HW: `[SteelSeries_Engine_VAD_SA.NT.HW]` lines 116-117 uses **AddReg** = AUDIOHW.AddReg (lines 119-123).
  - WDF: `[SteelSeries_Engine_VAD_SA.NT.Wdf]` line 129: KmdfService = SteelSeries_Engine_VAD, SteelSeries_Engine_VAD_SA_WdfSect; KmdfLibraryVersion = 1.15 (line 131).
- Security line, quoted exactly (line 123; comment on line 122 reads `; SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RWX_RES_RWX`):
  `HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)"`
  SY is granted GA (full). BA, WD (Everyone) and RC (restricted code) are granted GRGWGX (read, write, execute). [observed text; ACE meaning per standard SDDL syntax]
- DeviceType (line 121): `0x0000001D` (FILE_DEVICE_SOUND).
- Device interface GUIDs (AddInterface, lines 101-104), KS category GUIDs: KSCATEGORY_AUDIO `{6994AD04-93EF-11D0-A3CC-00A0C9223196}` (line 144); KSCATEGORY_RENDER `{65E8773E-8F56-11D0-A3B9-00A0C9223196}` (line 145); KSCATEGORY_TOPOLOGY `{DDA54A40-1E4C-11D1-A050-405705C10000}` (line 146). Only chat-render endpoints are defined (KSNAME chat_wave_speaker and chat_topology_speaker, lines 140-141).
- AddReg and driver parameters: no `Parameters` subkey is written (case-insensitive grep, both INFs: no matches). Device-key writes: AssociatedFilters "wdmaud,redbook" (line 41); Driver "SteelSeries-Engine-VAD.sys" (line 42); wdmaud.drv entries (lines 44-50); DeviceType (line 121); Security (line 123). Chat-render endpoint values under EP\0 and FX\0 (lines 61-86): ROLE_CHAT 0x1 (line 77), repository "ChatRender" (line 79), EnableEndpointByDefault 0x100 (line 81), NeverSetAsDefaultEndpoint 0x103 (line 86).
- SignatureAttributes.DRM DRMLevel=1300 (line 20); PETrust=true (line 23).

### 1.3 setup_required: devnode [observed]
- Supporting line: INF line 29 (`ROOT\VEN_SSGG&DEV_0002`).
- Bus-prefix grep over both INFs (ROOT\, SWD\, SWC\, PCI\, USB\, ACPI\, HDAUDIO\, HID\): the only match in each file is line 29. No physical bus ID and no SWD\ or SWC\ ID. The `*_ID` lines (for example CHAT_SPEAKER_NAME_ID, line 163) are MediaCategories name GUIDs, not hardware IDs.

### 1.4 Import table [observed]
Import directory at file offset 0xDE68; 4 descriptors, 47 imports.
- ntoskrnl.exe (32), descriptor 0xDE68: ExFreePool 0xE0EA; ExAllocatePoolWithTag 0xE0D2; RtlAppendUnicodeToString 0xE0B6; MmGetSystemRoutineAddress 0xE09A; RtlRaiseException 0xE45E; RtlCopyUnicodeString 0xE194; DbgPrintEx 0xE1AC; KeInitializeSpinLock 0xE1BA; KeAcquireSpinLockRaiseToDpc 0xE1D2; KeReleaseSpinLock 0xE1F0; ExFreePoolWithTag 0xE204; RtlQueryRegistryValues 0xE080; **IoRegisterDeviceInterface 0xE230**; IoOpenDeviceInterfaceRegistryKey 0xE24C; IoSetDeviceInterfacePropertyData 0xE270; ZwClose 0xE294; ZwCreateKey 0xE29E; **ZwOpenKey 0xE2AC**; ZwEnumerateKey 0xE2B8; ZwEnumerateValueKey 0xE2CA; ZwSetValueKey 0xE2E0; wcscmp 0xE2F0; RtlCompareMemory 0xE2FA; KeFlushQueuedDpcs 0xE30E; KeSetEvent 0xE322; ExAllocateTimer 0xE330; ExSetTimer 0xE342; ExCancelTimer 0xE350; ExDeleteTimer 0xE360; RtlFreeUnicodeString 0xE218; RtlInitUnicodeString 0xE068; __C_specific_handler 0xE472.
- portcls.sys (9), descriptor 0xDE7C: PcRegisterAdapterPowerManagement 0xE148; PcAddAdapterDevice 0xE132; PcDispatchIrp 0xE122; PcGetPhysicalDeviceObject 0xE16C; PcRegisterSubdevice 0xE40C; PcRegisterPhysicalConnection 0xE422; PcNewPort 0xE442; PcNewMiniport 0xE44E; PcInitializeAdapterDriver 0xE106.
- HAL.dll (1), descriptor 0xDE90: KeQueryPerformanceCounter 0xE370.
- WDFLDR.SYS (5), descriptor 0xDEA4: WdfVersionBind 0xE394; WdfLdrQueryInterface 0xE3A6; WdfVersionUnbind 0xE3BE; WdfVersionBindClass 0xE3D2; WdfVersionUnbindClass 0xE3E8.

Offsets are for the IMAGE_IMPORT_BY_NAME entries; the name string starts 2 bytes later.

### 1.5 Flagged groups [observed]
- (a) memory mapping or copying: no hits. None of the eight names is in the table or in the byte search.
- (b) device creation: **IoRegisterDeviceInterface** (ntoskrnl.exe, 0xE230); **WdfVersionBind** (WDFLDR.SYS, 0xE394). Absent: IoCreateDevice, IoCreateSymbolicLink, IoAttachDeviceToDeviceStack, WdfDeviceCreate.
- (c) KS / PortCls: PcInitializeAdapterDriver (portcls.sys, 0xE106), PcAddAdapterDevice (0xE132), PcRegisterSubdevice (0xE40C), PcNewPort (0xE442). Absent: KsCreateDevice.
- (d) security: ZwOpenKey (ntoskrnl.exe, 0xE2AC). Absent: SeTokenIsAdmin, SeAccessCheck.

### 1.6 Device-creation path: AddDevice (PnP) [inferred]
- DriverEntry rule: it needs IoCreateDevice, which is absent, so this rule does not apply.
- AddDevice (PnP) rule: applies. The PnP import present is IoRegisterDeviceInterface. IoOpenDeviceInterfaceRegistryKey and IoSetDeviceInterfacePropertyData are also present. The label holds under any reasonable PnP set.
- Caveats:
  1. The imports show that the call exists, not which routine makes it. Disassembly must confirm.
  2. A KMDF driver (WdfVersionBind imported; KmdfService at line 129) dispatches WDF calls through a function table, so WdfDeviceCreate would not appear in the import table even if the driver uses it. [inferred from KMDF stub design] Its absence is not evidence that the driver does not create a WDF device.
  3. Both a PortCls entry set (PcInitializeAdapterDriver, PcAddAdapterDevice) and a KMDF bootstrap (WdfVersionBind) are imported. The imports do not show which framework owns the device object.

### 1.7 Signature [observed; Get-AuthenticodeSignature, read-only]
- Driver: Status Valid ("Signature verified."); SignatureType Authenticode; IsOSBinary False.
- Signer: CN=GN Hearing A/S, O=GN Hearing A/S, L=Ballerup, C=DK, SERIALNUMBER=55082715, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.3=DK. Thumbprint C540E47CE151E3301E14F5C54129920E5ECB60B3. Issuer CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1. Signer certificate valid 2026-07-29 to 2027-07-29.
- Timestamp: present. RFC 3161 token (TSTInfo content-type OID at file offset 0x10502). genTime 2026-09-09 13:41:55 UTC. TimeStamper: CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1. A signingTime attribute at file offset 0x11972 reads the same second. It sits after the TSTInfo anchor, so it is inside the timestamp token [inferred]; its owner was not decoded.
- Catalog `SteelSeries-Engine-VAD_78C729CA.cat`: Status Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation. Member hashes not checked in this pass.
- Name mismatch to resolve: INF ProviderName "SteelSeries ApS" (lines 171-172) vs signer organization "GN Hearing A/S". The relationship between them was not checked.

### 1.8 Trace-first list (groups a and b) [inferred from imports]
1. IoRegisterDeviceInterface (ntoskrnl.exe, entry 0xE230): find its callers and the routine that contains them. This settles the device-creation path in 1.6.
2. WdfVersionBind (WDFLDR.SYS, entry 0xE394): its call site and the WDF bootstrap. This shows whether WDF is in the device path at all.
- Group (a): no hits, so nothing to trace from it.
- Outside (a) and (b), if the trace goes further: PcInitializeAdapterDriver (0xE106) and the PcAddAdapterDevice reference (0xE132), which PortCls drivers usually pass to it as the AddDevice routine [inferred from documented PortCls usage]; ZwOpenKey (0xE2AC) call sites.

## 2. SteelSeries-Sonar-VAD_2685B48C.sys

### 2.1 File [observed]
- Path: `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected2\drivers\SteelSeries\SteelSeries-Sonar-VAD_2685B48C.sys`
- SHA-256: `2685B48C431FBECD4586F72335107A71A2A60C8747AA362979CF059DF8522527`
- Size: 95,912 bytes
- PE: x64, PE32+, 8 sections, e_lfanew 0xE0. TimeDateStamp 0x69DE5820 = 2026-04-14 15:07:12 UTC (file offset 0xE8).
- DataDirectory[1] (import): RVA 0x13448, size 0x64, file offset 0x11048. Delay imports: none. Security directory: file offset 0x12200, size 0x54A8.
- Companions: .inf 16,998 bytes, SHA-256 `AC0A1A5748EEE6F5B096A5C0EA7C3E77561A5BB2CD8B6668373556005E786B6F`; .cat 12,511 bytes, SHA-256 `D71C1CBE599DF40653D228EA666163F0763F9FECDE838A0A40031E636CB935F0`.

### 2.2 INF facts [observed]
File: `SteelSeries-Sonar-VAD_2685B48C.inf` (16,998 bytes; ASCII, CRLF).
- Class `MEDIA` (line 3); same ClassGUID as Engine (line 5). DriverVer `04/14/2026,15.7.9.759` (line 6). CatalogFile `SteelSeries-Sonar-VAD.cat` (line 7). PnpLockDown = 1 (line 8).
- ProviderName and MfgName: "SteelSeries ApS" (lines 393-394).
- Hardware ID (line 29): `ROOT\VEN_SSGG&DEV_0001`, DeviceDesc "SteelSeries Sonar Virtual Audio Device" (line 396). It is the only hardware ID in the file.
- Install sections:
  - `[SteelSeries_Sonar_VAD_SA.NT]` (lines 236-240): Include=ks.inf,wdmaudio.inf; Needs (same three as Engine); CopyFiles (line 239); AddReg (line 240).
  - Service: `[SteelSeries_Sonar_VAD_SA.NT.Services]` line 293 uses **AddService**: `AddService=SteelSeries_Sonar_VAD,0x00000002,SteelSeries_Sonar_VAD_Service_Inst`. Service section (lines 295-300): ServiceType=1, StartType=3, ErrorControl=1, ServiceBinary=%13%\SteelSeries-Sonar-VAD.sys. DisplayName "SteelSeries Sonar Driver" (line 397).
  - HW: `[SteelSeries_Sonar_VAD_SA.NT.HW]` lines 302-303 uses **AddReg** = AUDIOHW.AddReg (lines 305-309).
  - WDF: KmdfService line 315; KmdfLibraryVersion = 1.15 (line 317).
- Security line, quoted exactly (line 309; comment on line 308 reads `; SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RWX_RES_RWX`): `HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)"`. Identical to the Engine line.
- DeviceType (line 307): `0x0000001D`.
- Device interface GUIDs (AddInterface, lines 246-290; six endpoint groups), KS category GUIDs:
  - KSCATEGORY_AUDIO `{6994AD04-93EF-11D0-A3CC-00A0C9223196}` (line 345)
  - KSCATEGORY_RENDER `{65E8773E-8F56-11D0-A3B9-00A0C9223196}` (line 346)
  - KSCATEGORY_CAPTURE `{65E8773D-8F56-11D0-A3B9-00A0C9223196}` (line 347)
  - KSCATEGORY_TOPOLOGY `{DDA54A40-1E4C-11D1-A050-405705C10000}` (line 349)
  - KSCATEGORY_REALTIME `{EB115FFC-10C8-4964-831D-6DCB02E6F23F}` (line 348): defined, but no AddInterface line uses it (grep).
  - chat_capture_wave is registered under AUDIO, CAPTURE and RENDER (lines 262-264).
- Endpoint roles: PKEY_SS_VAD_ROLE is `{F141E7CC-921B-466D-802F-879D6D4AEC17},0` (line 360). The Engine uses a different GUID, `{DA86083D-8F92-42E0-982E-B72301E64FB2},0` (Engine line 157). Role values: CHAT 1, GAME 2, CHATCAPTURE 3, STREAM 4, MEDIA 5, AUX 6 (lines 372-377).
- AddReg and driver parameters: no `Parameters` subkey (grep, both INFs: no matches). Device-key writes: AssociatedFilters (line 41); Driver "SteelSeries-Sonar-VAD.sys" (line 42); wdmaud.drv entries (lines 44-50); MediaCategories names (lines 52-57); DeviceType (line 307); Security (line 309).
- Minor INF oddities: the Stream block sets PKEY_AudioEndpoint_Association twice (lines 219 and 223); KSCATEGORY_REALTIME is unused (line 348).

### 2.3 setup_required: devnode [observed]
- Supporting line: INF line 29 (`ROOT\VEN_SSGG&DEV_0001`). The bus-prefix grep found only line 29 in this INF. No SWD\, SWC\ or physical bus ID.

### 2.4 Import table [observed]
Import directory at file offset 0x11048; 4 descriptors, 46 imports.
- ntoskrnl.exe (31), descriptor 0x11048: ExFreePool 0x112C2; ExAllocatePoolWithTag 0x112AA; RtlAppendUnicodeToString 0x1128E; MmGetSystemRoutineAddress 0x11272; RtlRaiseException 0x1162C; RtlCopyUnicodeString 0x1136C; DbgPrintEx 0x11384; KeInitializeSpinLock 0x11392; KeAcquireSpinLockRaiseToDpc 0x113AA; KeReleaseSpinLock 0x113C8; RtlQueryRegistryValues 0x11258; RtlFreeUnicodeString 0x113F0; **IoRegisterDeviceInterface 0x11408**; IoOpenDeviceInterfaceRegistryKey 0x11424; IoSetDeviceInterfacePropertyData 0x11448; ZwClose 0x1146C; ZwCreateKey 0x11476; **ZwOpenKey 0x11484**; ZwEnumerateKey 0x11490; ZwEnumerateValueKey 0x114A2; ZwSetValueKey 0x114B8; RtlCompareMemory 0x114C8; KeFlushQueuedDpcs 0x114DC; KeSetEvent 0x114F0; ExAllocateTimer 0x114FE; ExSetTimer 0x11510; ExCancelTimer 0x1151E; ExDeleteTimer 0x1152E; ExFreePoolWithTag 0x113DC; RtlInitUnicodeString 0x11240; __C_specific_handler 0x11640.
- portcls.sys (9), descriptor 0x1105C: PcRegisterAdapterPowerManagement 0x11320; PcAddAdapterDevice 0x1130A; PcDispatchIrp 0x112FA; PcGetPhysicalDeviceObject 0x11344; PcRegisterSubdevice 0x115DA; PcRegisterPhysicalConnection 0x115F0; PcNewPort 0x11610; PcNewMiniport 0x1161C; PcInitializeAdapterDriver 0x112DE.
- HAL.dll (1), descriptor 0x11070: KeQueryPerformanceCounter 0x1153E.
- WDFLDR.SYS (5), descriptor 0x11084: WdfVersionBind 0x11562; WdfLdrQueryInterface 0x11574; WdfVersionUnbind 0x1158C; WdfVersionBindClass 0x115A0; WdfVersionUnbindClass 0x115B6.

### 2.5 Flagged groups [observed]
- (a) memory mapping or copying: no hits.
- (b) device creation: **IoRegisterDeviceInterface** (ntoskrnl.exe, 0x11408); **WdfVersionBind** (WDFLDR.SYS, 0x11562). Absent: IoCreateDevice, IoCreateSymbolicLink, IoAttachDeviceToDeviceStack, WdfDeviceCreate.
- (c) KS / PortCls: PcInitializeAdapterDriver (0x112DE), PcAddAdapterDevice (0x1130A), PcRegisterSubdevice (0x115DA), PcNewPort (0x11610). Absent: KsCreateDevice.
- (d) security: ZwOpenKey (ntoskrnl.exe, 0x11484). Absent: SeTokenIsAdmin, SeAccessCheck.

### 2.6 Device-creation path: AddDevice (PnP) [inferred]
Same rules and caveats as 1.6. IoCreateDevice is absent; IoRegisterDeviceInterface is present; both the PortCls and the KMDF bootstrap imports are present.

### 2.7 Signature [observed; Get-AuthenticodeSignature, read-only]
- Driver: Status Valid ("Signature verified."); Authenticode; IsOSBinary False.
- Signer: CN=GN Hearing A/S, O=GN Hearing A/S, L=Ballerup, C=DK, SERIALNUMBER=55082715, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.3=DK (same organization as Engine). Thumbprint 2D450F7FF0069547C0F6B6F19C22A6CACC48DA45. Issuer CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1. Signer certificate valid 2025-02-20 to 2028-02-20.
- Timestamp: present. RFC 3161 token (TSTInfo content-type OID at file offset 0x13902). genTime 2026-04-14 15:09:03 UTC. TimeStamper: CN=DigiCert SHA256 RSA4096 Timestamp Responder 2025 1. A signingTime attribute at file offset 0x14D71 reads the same second. It sits after the TSTInfo anchor, so it is inside the timestamp token [inferred]; its owner was not decoded.
- Catalog `SteelSeries-Sonar-VAD_2685B48C.cat`: Status Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation. Member hashes not checked in this pass.
- Name mismatch to resolve: INF ProviderName "SteelSeries ApS" (lines 393-394) vs signer organization "GN Hearing A/S".

### 2.8 Trace-first list (groups a and b) [inferred from imports]
1. IoRegisterDeviceInterface (ntoskrnl.exe, entry 0x11408): find its callers and the routine that contains them. This settles the device-creation path in 2.6.
2. WdfVersionBind (WDFLDR.SYS, entry 0x11562): its call site and the WDF bootstrap.
- Group (a): no hits, so nothing to trace from it.
- Outside (a) and (b), if the trace goes further: PcInitializeAdapterDriver (0x112DE) and the PcAddAdapterDevice reference (0x1130A); ZwOpenKey (0x11484) call sites.

## 3. Open items (not done in this pass)
- Disassembly confirmation of the device-creation path (other agent).
- Catalog member-hash check against each .sys.
- Reconciling the INF ProviderName "SteelSeries ApS" with the signer organization "GN Hearing A/S".
- No verdict on any capability is made in this report.
