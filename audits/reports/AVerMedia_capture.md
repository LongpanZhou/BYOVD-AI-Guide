# Audit: AVerMedia capture drivers (six-file group)

| Field | Value |
|---|---|
| File(s) | `AVerPL33_75F3DAE3.sys`, `AVerPL33_x64_93CBC0D8.sys`, `avmu3_F0EAC5C2.sys`, `avmu364_A266C94C.sys`, `avmu3gc550_B0E987CC.sys`, `avmu3gc550_x64_495B04F2.sys` |
| SHA-256(s) | `75F3DAE38505764340EF178BE4EA650EB98B6C8F4A5D5F8AFB4609C5177DD197` / `93CBC0D80BBB1742EBC94BCF20122C0CC4745ABC7A9DDDC9A5F0ABEDD1F6D433` / `F0EAC5C2455DFB4BBCA6B186BD664E3C89744B012BD7D81D57C4F214902B2E1E` / `A266C94C3D5E5AC179EB56F9715B307ADCEBE7B41A7D68B162FDD271B4F79E1F` / `B0E987CC23D0C591C57D2948AE422AE565BF070B99351A49C769E3F00EC11A40` / `495B04F2C0023D19A6997C2EBB7BC5BE7D41F2FE75E64CA95A111F06AAD641A1` |
| Analysis date | 2026-10-25 |
| Method | Static-only. Local Ghidra 12.1.4 headless (auto-analysis + decompiler) and llvm-objdump/PE parsing. REA was **not** used: four REA audits were already active (capacity limit). No load, service, registry, or execution. |
| Reach tier | **R3** (devnode + physical capture device); R2 local admin if the INF DACL grants write; R1 not established |
| Setup required | **hardware** (INF-installed function driver + the matching AVerMedia PCIe/USB capture device) |
| Write quality | **W2** for the AVerPL33 property-handler pool overflow; **W0** for every `MmMapIoSpace` / `MmMapLockedPagesSpecifyCache` path and for the four avmu3-family images |
| Verdict | **MW3** (both AVerPL33 builds) · **NO-MEMORY-WRITE (HW-ONLY)** (four avmu3-family builds) |
| HW-only | BAR/register MMIO and I2C register access: yes. The MW3 finding is a kernel pool write, not MMIO. |

## 0 Files verified

Hashes were computed with `Get-FileHash -Algorithm SHA256` and match both the file-name suffixes and `indexes/drivers_manifest.csv`. None of the six hashes is in `indexes/dedupe/known_bad_hashes.txt`.

| File | Arch | Size | PE timestamp | Embedded Authenticode |
|---|---|---:|---|---|
| `AVerPL33_75F3DAE3.sys` | i386 | 1,609,472 | 2014-07-16 02:20:30 | none (Security directory 0/0) |
| `AVerPL33_x64_93CBC0D8.sys` | amd64 | 1,781,504 | 2014-07-16 02:21:08 | none (0/0) |
| `avmu3_F0EAC5C2.sys` | i386 | 479,232 | 2014-05-21 00:55:30 | none (0/0) |
| `avmu364_A266C94C.sys` | amd64 | 519,168 | 2014-05-21 00:56:04 | none (0/0) |
| `avmu3gc550_B0E987CC.sys` | i386 | 627,840 | 2015-11-23 22:48:34 | none (0/0) |
| `avmu3gc550_x64_495B04F2.sys` | amd64 | 677,888 | 2015-11-23 22:48:18 | none (0/0) |

No embedded certificate means catalog-signing cannot be confirmed from the corpus (`.cat` was excluded). This is recorded as loadability-unverified, **not** as `BLOCKED`: there is no blocklist hit and no evidence the images are unsigned at install time.

## 1 Internals

All six are native WDM/AVStream kernel-streaming minidrivers (`Subsystem 1`, `DllCharacteristics 0x2000 / WDM_DRIVER`), with no WDF, no `IoCreateDevice`, no `IoCreateDeviceSecure`, no `IoCreateSymbolicLink`, no `IofCompleteRequest`, and no `IRP_MJ_DEVICE_CONTROL` handler installed by the driver. `DriverEntry` is a thin wrapper over `KsInitializeDriver`:

| Image | Entry VA | DriverEntry body |
|---|---|---|
| `AVerPL33_x64` | `0x1c0264` | `FUN_001c0208` (cookie init) → `FUN_00010f20` → `KsInitializeDriver(DriverObject, RegistryPath, &descriptor_0x1b9830)` |
| `AVerPL33` x86 | `0x18f5be` | cookie init → `FUN_00010d80` → `KsInitializeDriver` |
| `avmu3` | `0x818be` | cookie init → `FUN_00015560` → `KsInitializeDriver` |
| `avmu364` | `0x8cce4` | cookie init → `FUN_00015560` → `KsInitializeDriver` |
| `avmu3gc550` | `0xa54be` | cookie init → `FUN_0001665c` → `KsInitializeDriver` |
| `avmu3gc550_x64` | `0xb3464` | cookie init → `FUN_0001665c` → `KsInitializeDriver` |

Role, from version resources and embedded strings:

- **AVerPL33 pair** – service name `AVer330`; AVerMedia C353/C353E/C875/C985/C985E PCIe and USB capture/encoder family. Imports PCI BAR mapping (`MmMapIoSpace`), interrupt connect, DMA adapter, MDLs, and a USB bus interface. Contains a large custom KS property set (`AVer*Handler` functions).
- **avmu3 / avmu364 / avmu3gc550 pair** – service name `AVerMedia`; AVerMedia Hybrid TV / HD Capture USB3 tuners. Register access is through I2C device classes (`CLFE3`, `CPCA9539A`, `CVX8897`, `CVampVDecoderIT6603`) over the USB bus. No `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmGetPhysicalAddress`, `MmCopyMemory`, `ZwMapViewOfSection`, or `KeStackAttachProcess` import in any of the four.

## 2 Entry / device / interface / effective DACL

The device object is created by **ks.sys/AVStream**, not by these images. There is no device-name string, no `\Device\...` or `\??\...` hard-coded path, and no SDDL literal in any of the six binaries. Where a device interface is published, it is via `IoRegisterDeviceInterface` (AVerPL33 x64 `FUN_000164e0`, x86 `FUN_00015130`; avmu3gc550 x64 `FUN_00015d84`), derived from a GUID supplied by the descriptor.

GUIDs recovered from the AVerPL33 x64 `.rdata`:

| VA (base `0x10000`) | GUID | Meaning |
|---|---|---|
| `0x1139a0` | `6994AD05-93EF-11D0-A3CC-00A0C9223196` | `KSCATEGORY_VIDEO` |
| `0x1139b0` | `65E8773D-8F56-11D0-A3B9-00A0C9223196` | `KSCATEGORY_CAPTURE` |
| `0x111720` | `9A8B368A-F82C-477E-83E1-5E88FD2E1B2B` | vendor KS property set (GpioI2c) |
| `0x111778` | `A1DFC885-1DFB-4A70-8F99-A5CBAF52ACC4` | vendor KS property set (I2C/GPIO/Parameter) |
| `0x113900` | `FAE408DC-E1D4-472B-AC63-9A99A155410D` | vendor GPIO/I2C device-set GUID |

**Effective DACL: unresolved from the image.** Because the device is created inside ks.sys, the security descriptor comes from the INF/`Security` registry value supplied by the driver package, and that INF is not in the corpus. There is no `IoCreateDeviceSecure`, no `RtlSetDaclSecurityDescriptor`, and no SDDL string to resolve. Operating assumption for this report: the standard AVStream device ACL (SYSTEM/Administrators full, users read-only), i.e. **R2** for `KS_PROPERTY` *Set* requests; **R1 only if** the AVerMedia INF grants `FILE_WRITE_ACCESS` to `Everyone` (unverified). The `R3/hardware` gate is independent of the DACL and is what caps the finding.

## 3 Dispatch and IOCTL surface

The driver installs no `IRP_MJ_DEVICE_CONTROL` routine. User-visible control is the KS contract handled by ks.sys on the filter/pin file object:

| Code | Name | Method | Access | Kernel action |
|---|---|---|---|---|
| `0x2F0003` | `IOCTL_KS_PROPERTY` | `METHOD_NEITHER` | `FILE_ANY_ACCESS` (Set still needs a writable handle) | ks.sys validates set/id, then calls the minidriver property item's Get/Set handler |
| `0x2F000F` | `IOCTL_KS_METHOD` | `METHOD_NEITHER` | `FILE_ANY_ACCESS` | ks.sys → minidriver method handler (standard capture methods only here) |
| `0x2F0007` | `IOCTL_KS_ENABLE_EVENT` | `METHOD_NEITHER` | `FILE_ANY_ACCESS` | ks.sys → event handler |
| `0x2F000B` | `IOCTL_KS_DISABLE_EVENT` | `METHOD_NEITHER` | `FILE_ANY_ACCESS` | ks.sys → event handler |
| `0x2F0013` / `0x2F0017` | `IOCTL_KS_WRITE_STREAM` / `IOCTL_KS_READ_STREAM` | `METHOD_NEITHER` | `FILE_WRITE_ACCESS` / `FILE_READ_ACCESS` | AVStream pin streaming |
| `IRP_MJ_CREATE/CLOSE/CLEANUP` | — | — | handle rights | `CCaptureFilter::dispatchCreate` / `dispatchClose` (`0x187a0` / `0x18a50` in the x64 filter dispatch) |
| `IRP_MJ_READ/WRITE` | pin I/O | — | pin rights | AVStream pin processing / DMA |

### 3.1 AVerPL33 custom property sets (the only non-standard surface)

The x64 filter descriptor passed to `KsCreateFilterFactory` is at `0x1b9830` (`KSFILTER_DESCRIPTOR`, confirmed against the Windows SDK `ks.h` layout). Its `+0x00` field is the `KSFILTER_DISPATCH` at `0x10f7b8`; its `+0x08` field is `0x111c70`, a `KSAUTOMATION_TABLE`:

```
0x111c70  PropertySetsCount = 10
0x111c74  PropertyItemSize  = 0x48
0x111c78  PropertySets      = 0x111ae0
```

The descriptor's `Version` is `0xFFFFFFFF` (`KSFILTER_DESCRIPTOR_VERSION`), `Flags` is `0` (`KSFILTER_FLAG_DENY_USERMODE_ACCESS` **not** set), `ReferenceGuid` is `957BD672-7934-4B55-B81A-3E22B14C679A`, `PinDescriptorsCount=5` / `PinDescriptorSize=0x88`, and `Categories` = {`KSCATEGORY_VIDEO`, `KSCATEGORY_CAPTURE`}. The property sets are therefore filter-level: a handle to the filter (not necessarily a pin) reaches them.

The 10 `KSPROPERTY_SET` entries run `0x111ae0..0x111c70` (0x28 bytes each, matching `KSPROPERTY_SET` in the SDK). Six are vendor sets and four are standard KS sets; the relevant vendor items are:

| Set GUID | Set VA | Count | Item VA | Property id | MinProperty/MinData | Set handler (x64) | Set handler (x86) |
|---|---|---|---:|---|---:|---|---|
| `9A8B368A-F82C-477E-83E1-5E88FD2E1B2B` | `0x111ba8` | 1 | `0x111730` | 0 | `0x130` / `0x130` | `0x2e6d0` `AVerGpioI2cSetHandler` | `0x28af0` |
| `A1DFC885-1DFB-4A70-8F99-A5CBAF52ACC4` | `0x111bd0` | 6 | `0x111790` | 2 | `0x4c` / `0x4c` | `0x2f9b0` `AVerI2CSetHandler` | `0x299b0` |
| `A1DFC885-...` | `0x111bd0` | 6 | `0x1117d8` | 3 | `0x50` / `0x50` | `0x2ff90` `AVerGPIOSetHandler` | `0x29de0` |
| `A1DFC885-...` | `0x111bd0` | 6 | `0x111820` | 5 | `0x80` / `0x80` | `0x30230` `AVerParameterSetHandler` | `0x29fb0` |

Observed item layout (0x48 bytes, exactly `KSPROPERTY_ITEM` from the SDK): `+0x00` `PropertyId`, `+0x08` Get handler, `+0x10` `MinProperty`, `+0x14` `MinData`, `+0x18` Set handler, `+0x20` `Values`, `+0x28` `RelationsCount`, `+0x30` `Relations`, `+0x38` Support handler, `+0x40` `SerializedSize`. The handler addresses are only referenced from these tables and from their own `DbgPrint` calls, which is the expected AVStream registration pattern. The x86 column lists the same handler functions (identified by their own `DbgPrint` names); the x86 table itself was not re-parsed, but the build carries the identical handler set.

The avmu3-family images contain no `AVer*Handler` string and no comparable vendor handler set was found; their KS surface is the standard AVStream capture/tuner property sets. Their private code paths are I2C register writes to the tuner/decoder chips.

## 4 Access-control audit

- No `SeSinglePrivilegeCheck`, `SeAccessCheck`, privilege test, caller-image test, or authentication handshake in any handler reached here.
- The property handlers only null-check `Filter`, `Property`, and `Data` (e.g. `0x2f9b0`, `0x2e6d0`); they do not probe or capture the caller pointers and do not receive the IRP, so they cannot check `InputBufferLength` themselves.
- Gate 1: handle write access on the KS filter object (INF DACL, unresolved; R2 assumption).
- Gate 2: the physical capture device must be present and started, because the handlers resolve the device from the filter (`FUN_000279d0(param_1)`) and fail with `STATUS_UNSUCCESSFUL`/`0xC0000001` when it is absent. This is an `R3/hardware` gate.
- A local administrator can satisfy gate 1 if the INF is the normal vendor ACL; an unprivileged user can satisfy it only if the INF grants write to `Everyone` (not established).

## 5 Memory-write trace

### 5.1 `MmMapIoSpace` — fixed device BAR, not caller-controlled

Single call site in each AVerPL33 build:

- x64 `PciStartDevice` `FUN_000bc0d0`, call at `0xbc283`; unmap at `FUN_000bbe80`.
- x86 `PciStartDevice` `FUN_00098ce0`, call at `0x98e17`; unmap at `FUN_000998e0`.

The function walks the `IRP_MN_START_DEVICE` `CM_RESOURCE_LIST` and, for `CmResourceTypeMemory`, maps `TranslatedAddress` for the resource `Length` into the device context (`PciStartDevice() CmResourceTypeMemory Addr=... Len=...`). The physical address and length are the PnP-assigned BAR values; no IRP, IOCTL, or property field reaches them. There is exactly one cross-reference to the `MmMapIoSpace` import in each image, and it is this start-device path.

Register access on the resulting window is hardware-addressed: x86 uses `WRITE_REGISTER_ULONG/USHORT/UCHAR` (`0x95440`) and `WRITE_REGISTER_BUFFER_*` (`0x95b00`); x64 uses the same mapped base with direct volatile stores. Offsets and values are selected by the driver's GPIO/I2C/parameter code, not by a raw user pointer. **Classification: fixed-window MMIO, `HW-ONLY`, W0.**

### 5.2 `MmMapLockedPagesSpecifyCache` — user DMA buffer, no kernel target

Two call sites per AVerPL33 build:

| Purpose | x64 | x86 |
|---|---|---|
| `mapUserBuffer` | `FUN_00010390`, map call `0x104e6` | `FUN_00010490`, map call `0x105e9` |
| `PedDmaComplete` | `FUN_000ba7f0`, map call `0xbab2f` | `FUN_00097950`, map call `0x97be0` |

`mapUserBuffer` performs `IoAllocateMdl(Buffer, Length)` → `MmProbeAndLockPages(Mdl, UserMode, IoModifyAccess)` → `MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, ...)`, and unlocks/frees the MDL on teardown (`MmUnlockPages` / `IoFreeMdl`). The MDL describes the caller's own capture buffer; the kernel alias is handed to the DMA engine and written by the device. There is no caller-supplied physical address, no caller-supplied MDL, and no store to a kernel-selected destination. **Classification: user-memory DMA mapping, W0.**

### 5.3 True kernel-VA write: AVerGpioI2cSetHandler pool overflow (both AVerPL33 builds)

Item `9A8B368A-...`, property id 0, minimum input 0x130 bytes. Handler x64 `0x2e6d0`, x86 `0x28af0`. The property data begins at `Property+0x18`, immediately after the 0x18-byte `KSPROPERTY` header, per the `IOCTL_KS_PROPERTY` `METHOD_NEITHER` contract.

x64 logic at `0x2e6d0`:

```
len   = *(u32 *)(data + 0x120);          // no upper bound
buf   = operator new[](4);               // FUN_00027760(4) -> ExAllocatePoolWithTag(0, 4, 'Qpxl')
buf[0] = *(u8 *)(data + 0x118);
for (i = 1; i < len; i++)
    buf[i] = *(u8 *)((char *)&stack_local + (len - i));   // kernel stack read
if (*(u32 *)(data + 0x124) < 0x100)
    buf[len] = (u8)*(u32 *)(data + 0x124);                // one controlled byte
```

`operator new[]` is the same in x86 (`FUN_000227e0` → `ExAllocatePoolWithTag(0, size, 0x6c787051)` = `Qpxl`), and the x86 handler `0x28af0` has the identical `len = *(u32 *)(data + 0x120)` / 4-byte allocation / `buf[uVar1] = length` sequence. Consequences:

- A 4-byte non-paged-pool block is written from index 0 through `len`, i.e. up to `len + 1` bytes, with `len` taken directly from property input and never compared with 4.
- Bytes 1..`len-1` are read from the handler's kernel stack (not the user buffer), so the overflow is a stack-content/heap-metadata smash rather than a clean write-what-where; the last byte is attacker-chosen (0..0xFF) and lands at offset `len`.
- Large `len` also walks the stack read upward until it faults; moderate `len` (tens to hundreds) corrupts adjacent pool without an immediate fault. Pool grooming can position a victim object after the 4-byte block, so this is a genuine, constrained kernel memory write.
- The I2C transfer that follows does not undo the write.

### 5.4 Secondary: AVerI2CSetHandler stack overflow (both builds)

Item `A1DFC885-...`, id 2, minimum input 0x4c. Handler x64 `0x2f9b0`, x86 `0x299b0`.

x64: `u8 local_66[78]` (x86: `local_62[82]`); `len = *(u32 *)(data + 0x20)`; the loop copies `len` bytes from `data + 0x24` to `local_66[i]` (and `local_66[i+1]` in the non-ISP branch) with no bound. With `len` above 78 (x64) / 82 (x86) this is a kernel-stack buffer overflow with fully controlled bytes. The function ends with `__security_check_cookie` (`FUN_000d4350` x64 / `FUN_0005b797` x86), so overwriting the canary/return address normally bugchecks after the write. It is a crash-first stack corruption, useful as a secondary/DoS or with a canary leak, not the primary primitive.

### 5.5 Paths ruled out

No `MmGetPhysicalAddress`, `MmCopyMemory`, `ZwMapViewOfSection`, `\Device\PhysicalMemory`, `KeStackAttachProcess`, or raw `METHOD_NEITHER` output-pointer write to a caller-chosen kernel destination was found in any of the six. `AVerParameterSetHandler` (`0x30230`) dispatches per-index to device `setProperty` vtable calls and writes results to `Data+4`; no length-driven kernel copy was found in it. `AVerGPIOSetHandler` (`0x2ff90`) writes a fixed byte 6 into the property buffer (user memory) and issues fixed I2C register writes.

## 6 Most dangerous exposed capability

The GpioI2c property set on the two AVerPL33 builds: a hardware-gated non-paged-pool overflow of attacker-controlled length, with one attacker-chosen byte at a chosen offset and kernel-stack bytes filling the rest. It is not an arbitrary write and it is not what the triage flags pointed at — the `MmMapIoSpace`/`MmMapLockedPagesSpecifyCache` uses are benign fixed-BAR and user-DMA mappings — but it is a real kernel-VA memory write and therefore the reason these two files are not `NO-MEMORY-WRITE`.

Preconditions: AVerMedia C353/C353E/C875/C985/C985E class device installed and started, a handle to the KS filter with write access (admin by default; unprivileged only if the INF allows it), and a `KS_PROPERTY` Set with the vendor set GUID and a ≥0x130-byte input.

## 7 Verdict

| File | Flagged API | Gate | Write | Verdict |
|---|---|---|---|---|
| `AVerPL33_75F3DAE3.sys` | `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache` | hardware + INF ACL | W0 for mappings; **W2** for GpioI2c pool overflow; W2 crash-first for the I2C stack overflow | **MW3** — reach=R3 setup=hardware write=W2 load=catalog-signed (unverified) |
| `AVerPL33_x64_93CBC0D8.sys` | same | same | same | **MW3** — reach=R3 setup=hardware write=W2 load=catalog-signed (unverified) |
| `avmu3_F0EAC5C2.sys` | none imported | hardware + INF ACL | W0 | **NO-MEMORY-WRITE (HW-ONLY)** — reach=R3 setup=hardware write=W0 |
| `avmu364_A266C94C.sys` | none imported | hardware + INF ACL | W0 | **NO-MEMORY-WRITE (HW-ONLY)** — reach=R3 setup=hardware write=W0 |
| `avmu3gc550_B0E987CC.sys` | none imported | hardware + INF ACL | W0 | **NO-MEMORY-WRITE (HW-ONLY)** — reach=R3 setup=hardware write=W0 |
| `avmu3gc550_x64_495B04F2.sys` | none imported | hardware + INF ACL | W0 | **NO-MEMORY-WRITE (HW-ONLY)** — reach=R3 setup=hardware write=W0 |

**Overall: MW3 for the two AVerPL33 builds; NO-MEMORY-WRITE (HW-ONLY) for the four avmu3-family builds. No user-controlled physical-address mapping exists in any of the six.** The flagged `MmMapIoSpace` calls map PnP-assigned BARs at start-device; the flagged `MmMapLockedPagesSpecifyCache` calls map the caller's own DMA buffer. The primary kernel-VA write is the AVerPL33 GpioI2c property-handler pool overflow (secondary: the I2C handler stack overflow); it is hardware-gated and therefore MW3 rather than MW2.

## 8 Limitations

- **REA not used.** Four REA audits were already active; this audit is Ghidra 12.1.4 headless + llvm-objdump only. No REA evidence IDs exist for this report.
- **DACL unresolved.** The INF and `.cat` are not in the corpus; the KS device object is created by ks.sys, so the effective SDDL could not be read from the image. The R2 assumption is conservative, not proven. If the vendor INF grants write to `Everyone`, the PL33 finding would be R1 → MW2.
- **Loadability unverified.** No embedded certificate in any file; catalog signature was not available. Not `BLOCKED` because there is no blocklist hit or unsigned-at-install evidence.
- **Property-table layout confirmed; device binding inferred.** The 0x28-byte `KSPROPERTY_SET` and 0x48-byte `KSPROPERTY_ITEM` layouts match the Windows SDK `ks.h`, and the descriptor at `0x1b9830` points to the automation table at `0x111c70` (10 sets). The exact INF/device-model binding that loads this filter was not resolved.
- **No dynamic confirmation.** No driver was loaded and no IOCTL was sent. Crash behavior and pool layout are static inferences.
- **avmu3 family depth.** The four avmu3 images were audited for mapping primitives, dispatch, interfaces, and register-access paths, but their standard AVStream property/method handlers were not exhaustively reversed for non-mapping overflows. No mapping import, custom vendor handler table, or raw kernel destination was found in them.
- No exploit code, PoC, BYOVD instructions, or installation steps are included.
