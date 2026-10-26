# Audit: SteelSeries virtual audio devices (`SteelSeries-Engine-VAD`, `SteelSeries-Sonar-VAD`)

| Field | Value |
|---|---|
| Files | `drivers\SteelSeries\SteelSeries-Engine-VAD_78C729CA.sys`<br>`drivers\SteelSeries\SteelSeries-Sonar-VAD_2685B48C.sys` |
| SHA-256 | `78c729ca45f8ba7ec66988e1b26574655766dd330eeb25a00e44d33e9e927821`<br>`2685b48c431fbecd4586f72335107a71a2a60c8747aa362979cf059df8522527` |
| Architecture | x86-64 (both). INF target `NTamd64.10.0...17763`. |
| Method | Static-only (REA / Ghidra 12.1.4). No driver loaded, no device opened, no IOCTL issued. |
| Verdict | **NO-WRITE** (no kernel memory-write primitive found) |
| Setup required | **devnode** |

> Addresses are linked VAs at image base `0x140000000`.

## 1. Device surface and creation trigger

Both files are PortCls virtual-audio miniports built as KMDF "stub" drivers (the KMDF library is bound dynamically via `WdfVersionBind`; only `WDFLDR.SYS` appears in the import table).

`SteelSeries-Engine-VAD` DriverEntry = `FUN_14000121c` @ `0x14000121c`:

```
0x140001266  WdfVersionBind(DriverObject, &driverGlobals, &wdfGlobals, &bindInfo)
0x1400012xx  FUN_140001470(&wdfGlobals)              ; FxStubBindClasses (WdfVersionBindClass loop)
0x1400012xx  FUN_1400013ac()                         ; driver-object creation wrapper
0x1400012xx  FUN_14001129c(DriverObject, RegistryPath)
            └─ PcInitializeAdapterDriver(DriverObject, RegistryPath, FUN_14000a220)
            └─ DriverObject->DriverUnload = FUN_14000a7a0
```

`FUN_14001129c` is the PortCls registration path (it calls `PcInitializeAdapterDriver`, whose AddDevice callback performs `PcAddAdapterDevice`). The adapter FDO is therefore created by PortCls **when the PnP manager starts the devnode**, not at DriverEntry.

Evidence from the INFs:

- Engine: `[SteelSeries_Engine_VAD.NTamd64.10.0...17763]` → `ROOT\VEN_SSGG&DEV_0002` (`SteelSeries-Engine-VAD_78C729CA.inf:28-29`).
- Sonar: `ROOT\VEN_SSGG&DEV_0001` (`SteelSeries-Sonar-VAD_2685B48C.inf:29`).
- Registered interfaces (`SteelSeries-Engine-VAD_78C729CA.inf:101-104`): `KSCATEGORY_AUDIO`, `KSCATEGORY_RENDER`, `KSCATEGORY_TOPOLOGY` for the "chat" wave + topology subdevices.
- `AddService=SteelSeries_Engine_VAD,...,StartType=3` (`:106-114`) — demand-start, installed with the devnode.

Neither binary imports `IoCreateDevice` or `IoCreateSymbolicLink`, and neither contains a `\Device\...` / `\DosDevices\...` string. There is no legacy control device and no separate symbolic link: the only openable object is the PortCls KS device for the devnode.

## 2. Effective DACL

Active in both INFs:

```
SteelSeries-Engine-VAD_78C729CA.inf:121  HKR,,DeviceType,0x10001,0x0000001D      ; FILE_DEVICE_SOUND
SteelSeries-Engine-VAD_78C729CA.inf:123  HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)"

SteelSeries-Sonar-VAD_2685B48C.inf:307   HKR,,DeviceType,0x10001,0x0000001D
SteelSeries-Sonar-VAD_2685B48C.inf:309   HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)"
```

Decoded: `SYSTEM` `GENERIC_ALL`; `BUILTIN\Administrators` `GRGWGX`; **`Everyone` `GRGWGX`**; `RESTRICTED` `GRGWGX`. This is the normal audio-endpoint policy (user-mode audio needs read **and write** on the filter). The descriptor is applied by the PnP manager from the device hardware key; there is no `D:P` string in either binary and no `IoCreateDeviceSecure` import, so the INF value is the effective one.

Consequence: an unprivileged user can open the KS filter with `GENERIC_READ|GENERIC_WRITE`. The DACL provides no protection against write-type property requests.

## 3. Handler / property table

- `IRP_MJ_DEVICE_CONTROL` is owned by **portcls.sys** (`PcDispatchIrp`); the minidriver is reached only through its `PCAUTOMATION_TABLE` / `PCFILTER_DESCRIPTOR` returned by `IMiniport::GetDescription`.
- No custom IOCTL codes, no vendor device name, no filter-factory hook in the image. Imports are the standard PortCls set: `PcAddAdapterDevice`, `PcInitializeAdapterDriver`, `PcNewPort`, `PcNewMiniport`, `PcNewServiceGroup`, `PcRegisterSubdevice`, `PcRegisterPhysicalConnection`, `PcRegisterAdapterPowerManagement`.
- The INF registers the standard audio interfaces (Wave render + Topology) and the standard `wdmaud` subclasses (`wave`, `mixer`) — `SteelSeries-Engine-VAD_78C729CA.inf:44-50`.

**Not recovered statically:** the `PCAUTOMATION_TABLE` itself. The image contains no `PCFD` signature (`0x44434650`) in `.rdata`/`.data`, and a structured scan for `{PropertyItemSize ∈ {0x10,0x14,0x18,0x20,0x28}, Count 1..64, Properties→.rdata}` returned no candidate. The descriptor is either built at runtime or laid out differently in this PortCls version. This is the main residual unknown for this file.

## 4. Write sinks

None found. Specifically:

- No `MmMapIoSpace`, `MmGetPhysicalAddress`, `MmMapLockedPages*`, `MmAllocatePagesForMdl`, `MmCreateSection`, `MmMapViewOfSection`, `ZwMapViewOfSection`, `MmCopyMemory` imports.
- No `ProbeForRead` / `ProbeForWrite` imports. Buffer probing for KS requests is performed by portcls/ks before the miniport handler runs; the miniport therefore never dereferences a raw user pointer itself.
- No `memcpy`/`memmove` import. The only bulk routine imported is `RtlCopyUnicodeString` (device-interface / service-name construction) and `RtlCompareMemory` (GUID/name comparisons). Any compiler-inlined copies are of fixed-size descriptors, not of user-supplied lengths.
- Registry writes (`ZwCreateKey`, `ZwSetValueKey`, `ZwEnumerateKey`, `ZwEnumerateValueKey`, `IoOpenDeviceInterfaceRegistryKey`) are configuration persistence under the device's own key, not kernel memory writes.
- The wave data path is the PortCls-managed cyclic buffer (WaveRT/portcls maps it into the audio engine); the miniport does not program a DMA engine or a physical address.

The one KMDF-specific surface is the standard WDF device/queue set created in `EvtDeviceAdd` (KMDF is bound for library services, not for a second device). No `WdfIoQueueCreate`-style custom queue with `WdfRequestRetrieveInputBuffer` could be confirmed from the stub; the WDF function pointers are resolved through `WDF_DRIVER_GLOBALS` at runtime, so they are not visible as IAT entries.

## 5. Validation gaps / residual unknowns

1. **Automation table not enumerated** (see §3). A vendor `PCPROPERTY_ITEM` with a `PCPFNPROPERTY_HANDLER` that treats the KS-validated buffer as a structure could still exist. PortCls validates `MinProperty`/`MinData` from the same table, so the exposure would be a handler that trusts an *internal count* inside a correctly-sized buffer, not an out-of-bounds copy of an unchecked length.
2. The Engine and Sonar binaries differ (different SHAs, different INF device IDs) but both are ~272 internal procedures with the same import set; this audit reviewed Engine in depth and confirmed Sonar's imports/entry/INF match. Sonar's handler bodies were not individually decompiled.
3. KMDF queue dispatch is opaque in a stub-built driver; `WdfVersionBind` resolves all WDF entry points by index.

## 6. Setup required

**devnode.** Root-enumerated `ROOT\VEN_SSGG&DEV_0002` (Engine) / `ROOT\VEN_SSGG&DEV_0001` (Sonar), installed from the INF, service demand-start. No device exists before the devnode is created and started. This **disqualifies both under the no-setup rule**, regardless of the world-writable DACL.

## 7. Next dynamic test

1. On a disposable x64 VM, install the Engine VAD INF (`pnputil /add-driver ... /install`), confirm the `KSCATEGORY_RENDER` interface and the `\Device\...` KS filter appear.
2. As a standard user, `CreateFile` on the render interface with `GENERIC_READ|GENERIC_WRITE` — confirm the INF DACL really grants `WD` `GRGWGX` (this is the only access-control question that matters here).
3. Enumerate the property sets with `KSPROPERTY_TYPE_BASIC_SUPPORT`/`SET_SUPPORT`, then send `KSPROPERTY_TYPE_SET` for every settable id with `MinData-1`, `MinData`, and `MinData+0x100` byte buffers under Driver Verifier (Special Pool, Pool Tracking). No corruption test is warranted unless a set handler is discovered that accepts a variable-length payload.

*End of report.*
