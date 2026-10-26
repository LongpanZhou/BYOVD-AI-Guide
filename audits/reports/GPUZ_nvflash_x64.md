# Audit: GPU-Z nvflash_x64.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected5\agentR4\new\GPUZ_nvflash_x64_79050454.sys` |
| SHA-256 | `79050454D06AB7B6607BCA09386F704DF021C3C367CC0743DE6845301BB192AC` |
| Analysis date | 2026-10-24 |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4 headless decompiler, cross-checked with `llvm-objdump` linear disassembly and a hand-written PE parser) |
| Reach tier | **R3** — local administrator device DACL, but the mapping path needs NVIDIA/PLX/LSI PCI hardware |
| Setup required | **hardware** (a mapped GPU BAR; the device itself is admin-only) |
| Write quality | **W2** — constrained OOB kernel-VA write past a mapped BAR; no arbitrary target |
| Verdict | **MW3** — reach=R3 setup=hardware write=W2 load=signed (admin-only; not an arbitrary write) |
| Image base | `0x140000000` (all addresses below are image-relative RVAs unless prefixed with `0x1400`) |
| Signature | Authenticode **Valid** — `CN=Microsoft Windows Hardware Compatibility Publisher`, issued by `Microsoft Windows Third Party Component CA 2014`, timestamped (leaf notAfter 2025-01-10) |

---

## 1 Internals

**1.1 Binary shape**

* PE32+ (`0x20B`), AMD64, native kernel image, subsystem `IMAGE_SUBSYSTEM_NATIVE`, `DllCharacteristics = HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT`.
* Sections: `.text` RVA `0x1000`–`0x33C0`, `.rdata` `0x4000`–`0x49E4`, `.data` `0x5000`–`0x524C`, `.pdata` `0x6000`, `PAGE` `0x7000`–`0x8AD4` (executable, non-paged), `INIT` `0x9000`–`0x9698`, `.rsrc`, `.reloc`.
* `AddressOfEntryPoint = 0x2BC0` → `DriverEntry` at `0x140002BC0`.
* Linker 14.37 (VS 2019 toolchain), COFF timestamp `2024-10-15 02:26:14`. The statically-linked secure-device helper is identified by the decompiler as `IoDevObjCreateDeviceSecure` (Visual Studio 2019 Release library) — evidence `ev_88937e44964b4dea06676ab6d6ea9609c69a0cb4945402d483bc2ff70bd72ef7`.
* Version resource (`VS_VERSION_INFO`, RVA `0x5E66`): `NVIDIA Flash Driver, Version 1.21.0`, `OriginalFilename nvflash.sys`, `(C) 2017-2024 NVIDIA Corporation`.

**1.2 Imports (ntoskrnl.exe only)**

Memory/IO: `MmMapIoSpace` (IAT `0x4038`), `MmUnmapIoSpace` (`0x4040`), `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `MmGetSystemRoutineAddress`, `IoBuildSynchronousFsdRequest`, `IofCallDriver`, `IofCompleteRequest`, `KeInitializeEvent`, `KeWaitForSingleObject`, `KeBugCheckEx`.

Device/security: `IoCreateDevice`, `IoDeleteDevice`, `IoCreateSymbolicLink`, `IoDeleteSymbolicLink`, `ObOpenObjectByPointer`, `ZwSetSecurityObject`, `ZwClose`, `RtlCreateSecurityDescriptor`, `RtlSetDaclSecurityDescriptor`, `RtlAddAccessAllowedAce`, `RtlAbsoluteToSelfRelativeSD`, `RtlLengthSecurityDescriptor`, `RtlLengthSid`, `SeCaptureSecurityDescriptor`, `RtlGetDacl/Sacl/Owner/GroupSecurityDescriptor`, `IoDeviceObjectType`, `SeExports`, plus registry helpers used by the Wdmlib shim.

Device enumeration: `IoGetDeviceObjectPointer`, `IoGetDeviceAttachmentBaseRef`, `IoGetAttachedDeviceReference`, `IoEnumerateDeviceObjectList`, `IoGetDeviceProperty`.

**Not imported:** `ProbeForWrite`, `ProbeForRead`, `SeAccessCheck`, `SeSinglePrivilegeCheck`, `WRITE_PORT_*`/`READ_PORT_*`, `ZwWriteFile`, `HalGetBusDataByOffset`. There is no port-I/O and no direct user-pointer dereference.

**1.3 Driver-private runtime state**

| Address | Meaning |
|---|---|
| `0x140005000` | `__security_cookie` (set in `INIT:0x9000`) |
| `0x140005210` | resolved `IoValidateDeviceIoControlAccess` (stored, **never called**) |
| `0x140005218` | Wdmlib init flag |
| `0x140005220` | resolved `IoCreateDeviceSecure` (fallback `0x70C0`) |
| `0x140005230` / `0x140005238` | `LIST_ENTRY` head of mapped-GPU contexts |
| `0x140005240` | non-NULL one-byte sentinel pool allocation = "driver active" |
| `0x140005248` | number of live context entries |

Pool tag is `0x4E76544C` = `'LTVN'` (`ExAllocatePoolWithTag` at `0x1965`, `0x1992`, `0x1DC0`).

---

## 2 Entry / device / dispatch

**2.1 DriverEntry (`0x140002BC0`)**

1. `0x2BDE` calls `INIT:0x9000` (`__security_init_cookie`).
2. `0x2BE3`–`0x2C04`: if global `0x140005240` is non-NULL → `STATUS_INVALID_DEVICE_REQUEST` (`0xC0000001`); otherwise `ExAllocatePoolWithTag(NonPagedPool=1, 1, 'LTVN')` and store the pointer there. This is a single-load sentinel, not a per-open object.
3. `0x2C96` `RtlInitUnicodeString(&devname, L"\\Device\\NVFLASH")` — source string at RVA `0x33A0`.
4. `0x2CBE` loads `r9d = 0x81DE` (DeviceType) and `0x2CD7` calls `0x14000706C`, the Wdmlib `IoCreateDeviceSecure` wrapper, with stack arguments: `DeviceCharacteristics = 0`, `Exclusive = 1`, `DefaultSDDLString = 0x1400041A0`, `DeviceClassGuid = NULL`, `&DeviceObject`.
   * `0x1400041A0` is a `UNICODE_STRING { Length=0x36, MaximumLength=0x38, Buffer=0x1400041B0 }`; `0x1400041B0` holds `D:P(A;;GA;;;SY)(A;;GA;;;BA)`.
5. `0x2CE6`–`0x2D17` fills `DRIVER_OBJECT`:
   * `+0x68` (DriverUnload) = `0x140001710`
   * `+0x70` (IRP_MJ_CREATE) = `0x1400016D0`
   * `+0x80` (IRP_MJ_CLOSE) = `0x1400016D0`
   * `+0xE0` (IRP_MJ_DEVICE_CONTROL, index 14) = `0x1400016B0`
   * No IRP_MJ_READ / WRITE / INTERNAL_DEVICE_CONTROL / PNP / POWER / SYSTEM_CONTROL handlers are installed.
6. `0x2D1B`–`0x2D36`: `RtlInitUnicodeString(&link, L"\\DosDevices\\NVFLASH")` (source RVA `0x3340`), `IoDeleteSymbolicLink`, `IoCreateSymbolicLink`.
7. `0x2D58` / `0x2D66` call `0x140001BC0` (twice) to enumerate video devices and pre-map their BARs.

**2.2 Dispatch stubs**

* `0x1400016B0` (IRP_MJ_DEVICE_CONTROL): if `[0x140005240] == NULL` → `STATUS_INVALID_DEVICE_REQUEST`; else `jmp 0x1400010B0` with `r8 = Irp`.
* `0x1400016D0` (CREATE/CLOSE): sets `Irp->IoStatus.Status` to `0` or `0xC0000001` (same sentinel check), `Information = 0`, `IofCompleteRequest`.
* `0x140001710` (unload): rebuilds the symlink name, `IoDeleteSymbolicLink` (`0x1772`), `IoDeleteDevice` (`0x177C`), `ExFreePoolWithTag(0x178B)` on the sentinel, clears `0x140005240`.

**2.3 Device-object enumeration and BAR mapping (`0x140001BC0`, evidence `ev_af819ecbf1a6e6101d188acb39b55697626f9c81f7d949bc5f3332057d26c823`)**

* `0x1BFB` calls `0x140001AF0` — the teardown routine that walks the list, calls `iface->[+0x18]` (release), frees the interface object, `MmUnmapIoSpace(entry+0x28, entry+0x24)` (`0x1B6C`), and frees every 0x48-byte context.
* `0x1C00`–`0x1C13` re-initialise the `LIST_ENTRY` head and call `0x1400017B0`, which:
  * `0x1800` formats `\Device\Video%u` (`"%S%04u"` at `0x3390`, prefix `\Device\Video` in `.text`), `IoGetDeviceObjectPointer(..., 0x80000000, ...)` (`0x1830`), `IoGetDeviceAttachmentBaseRef` (`0x184E`), `IoEnumerateDeviceObjectList` (`0x1885`, `0x18D5`) into a `'LTVN'` pool array.
* For each `DEVICE_OBJECT`: skip if `Flags & 0x1000` is clear (`0x1C6B`); `0x140001930` sends a **vendor-private IRP** — `IoBuildSynchronousFsdRequest` with major `0x1B`, minor `0x08`, `Parameters = 0x10040` (`0x1A1B`, `0x1A7C`, `0x1A82`) to the attached device, output buffer 0x40 bytes, returns an interface block with function pointers at `+0x30` / `+0x38`.
* `0x1C97` calls `iface->fn38(ctx, 0, cfg, 0, 0x100)` to read **256 bytes of PCI configuration space**.
* Vendor filter (`0x1D4B`–`0x1D9B`): accepts vendor `0x10DE` (NVIDIA), `0x10B5` (PLX) with subsystem vendor `0x10DE`, or `0x1000` with subsystem vendor `0x10DE`.
* `0x1DB0` allocates the 0x48-byte context from non-paged pool (tag `'LTVN'`), zeroes it, increments `0x140005248`.
  * `+0x00` index, `+0x08` bus (`IoGetDeviceProperty(DevicePropertyBusNumber=0x0E)`), `+0x0C` device, `+0x10` function (from `DevicePropertyAddress=0x10`), `+0x14` vendor id, `+0x18` device id, `+0x1C` physical BAR (qword), `+0x24` mapped size, `+0x28` mapped VA, `+0x30` interface pointer, `+0x38` `LIST_ENTRY`.
* Map size selection (`0x1E81`–`0x1ED5`): NVIDIA `0x1000000` (16 MiB) or `0x2000000` if class `0x06`/subclass `0x80`; PLX `0x100000`; vendor `0x1000` `0x4000`.
* `0x1EFD` skips a zero BAR; `0x1F05` sets PCI command bits 1/2 (memory space + bus master) through the interface; `0x1F28`–`0x1F4D` clears BAR type bits and aligns the address.
* **`0x1F63` `MmMapIoSpace(BAR_phys, map_size, MmNonCached)`**; result stored in `+0x28`, physical base in `+0x1C`, size in `+0x24`; entry linked at `0x1F92`–`0x1FA6`.

The physical address is **never taken from an IOCTL**. It is read from the PCI config space of an enumerated NVIDIA/PLX/LSI video device.

---

## 3 IOCTL table

**3.1 Dispatch**

`0x1400010B0` is the single IOCTL handler (evidence `ev_4209c15eeec8026d32aa9272b3cc4fcebfa5729a2efec21a7dd806f882b620ee`):

* `0x10C8` `ioStack = Irp->Tail.Overlay.CurrentStackLocation` (`Irp+0xB8`).
* `0x10D2` `Irp->IoStatus.Information = 0`; `0x10DB` `Irp->IoStatus.Status = 0xC000000D`.
* `0x10E2` `InputBufferLength  = ioStack->Parameters.DeviceIoControl.InputBufferLength` (`+0x10`)
* `0x10E5` `OutputBufferLength = ioStack->Parameters.DeviceIoControl.OutputBufferLength` (`+0x8`)
* `0x10E9` `IoControlCode = [ioStack+0x18]`; `0x10EC` `add eax, 0x7E21FFFC`; `0x10F1` reject if `> 0x28`. This resolves to base code **`0x81DE0004`**.
* `0x10FA`–`0x1115` two-level jump table: byte selector at RVA `0x1678`, 32-bit RVA targets at `0x1650` (e.g. `[0x1650]=0x1117`).
* Every case enforces `InputBufferLength == OutputBufferLength == <exact size>` before touching `Irp->AssociatedIrp.SystemBuffer` (`Irp+0x18`, `0x112C`, `0x1200`, `0x12D8`, …). All IOCTLs are **METHOD_BUFFERED**, so the buffer is a kernel system buffer, not a user pointer; no `ProbeForWrite` is required or present.

Encoding: `CTL_CODE(DeviceType=0x81DE, Access=0, Function=F, Method=0)` → `FILE_ANY_ACCESS` + `METHOD_BUFFERED`.

**3.2 Table**

| IOCTL | F | In / Out | Handler | Kernel action |
|---|---|---|---|---|
| `0x81DE0004` | 1 | `0x218` / `0x218` | `0x1117` | Match context by BDF (`buf+4/8/0xC`), then copy `count` dwords (`buf+0x14`, 1–128 enforced at `0x11A3`) from `mapped_VA + buf[0x10]` into `buf+0x18` (`0x11DA`). **Block read of mapped BAR.** |
| `0x81DE0008` | 2 | `0x1C` / `0x1C` | `0x11EE` | Match by BDF, read 1/2/4 bytes (`buf+0x14` ∈ {1,2,4}) at `mapped_VA + buf[0x10]` into `buf+0x18` (`0x12B9`, `0x12A6`, `0x1294`). **Scalar read of mapped BAR.** |
| `0x81DE000C` | 3 | `0x1C` / `0x1C` | `0x12C6` | Match by BDF, write 1/2/4 bytes of `buf[0x18]` to `mapped_VA + buf[0x10]` (`0x138F`, `0x137B`, `0x1368`). **Scalar write to mapped BAR.** |
| `0x81DE0010` | 4 | `0x1C` / `0x1C` | `0x1398` | `iface->fn38(ctx, 0, buf+0x18, buf[0x10], buf[0x14])` (`0x1428`); success iff return == `buf[0x14]`. Length is caller-controlled and unchecked. |
| `0x81DE0014` | 5 | `0x1C` / `0x1C` | `0x143F` | `iface->fn30(ctx, 0, buf+0x14, buf[0x10], buf[0x18])` (`0x14D6`); success iff return == `buf[0x18]`. |
| `0x81DE0018` | 6 | any | `0x1613` | `STATUS_NOT_SUPPORTED` (`0xC00000BB`). |
| `0x81DE001C` | 7 | any | `0x1613` | `STATUS_NOT_SUPPORTED`. |
| `0x81DE0020` | 8 | `4` / `4` | `0x14ED` | Returns 4-byte version `{0x00,0x15,0x00,0x01}` (`0x150C`–`0x1519`). |
| `0x81DE0024` | 9 | `0x7E0` / `0x7E0` | `0x1521` | Copies one 0x24-byte record per context (index, BDF, vendor/device ID, **physical BAR**, map size) into the system buffer; **no entry-count bound** (`0x1570`–`0x15C0`). |
| `0x81DE0028` | 10 | `4` / `4` | `0x15C7` | Returns live-context count `[0x140005248]`. |
| `0x81DE002C` | 11 | `0x14` / `0x14` | `0x15FC` | Calls `0x140002470(buf)` — GPU locate/match helper (reads config space, compares BDF/vendor, no output write). |

**3.3 Input buffer layout for BDF-selected operations (0x1C bytes)**

```
+0x00 u32  ignored by the driver
+0x04 u32  bus        (compared with ctx+0x08)
+0x08 u32  device     (ctx+0x0C)
+0x0C u32  function   (ctx+0x10)
+0x10 u32  offset     (32-bit, zero-extended to 64-bit)
+0x14 u32  width {1,2,4} or block count {1..128}
+0x18 u32  value (write) / result (read)
```

The three flag IOCTLs (`0x81DE0018`, `0x81DE001C`, `0x81DE002C`…) are gated only by exact-length checks; there are no alignment checks on `offset` and no check that `offset + width <= ctx->map_size` (`ctx+0x24`).

---

## 4 Access-control audit

**Gate: device DACL only.**

* SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (RVA `0x41B0`, `UNICODE_STRING` at `0x41A0`) — a **protected** DACL with exactly two `GENERIC_ALL` ACEs: `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`. No `Everyone`, `Authenticated Users`, `Users`, or `INTERACTIVE` ACE.
* Applied through the statically-linked `IoCreateDeviceSecure` shim:
  * `0x7000`–`0x7021` resolve `IoCreateDeviceSecure` via `MmGetSystemRoutineAddress` (string at PAGE `0x8870`); `0x706C` tail-jumps to it.
  * Fallback `0x70C0` parses the SDDL (`SeSddlSecurityDescriptorFromSDDL`, evidence `ev_88937e44964b4dea06676ab6d6ea9609c69a0cb4945402d483bc2ff70bd72ef7`), calls `IoCreateDevice` (`0x71D1`), then `0x7228` opens the object with `ObOpenObjectByPointer` (`0x7295`) and applies the descriptor with `ZwSetSecurityObject` (`0x72AC`).
* `Exclusive = 1` (DriverEntry `0x2CCB`): only one open handle at a time.
* DeviceType `0x81DE`, all IOCTLs `FILE_ANY_ACCESS` — no additional per-function access mask to enforce.
* **No `SeAccessCheck` / `SeSinglePrivilegeCheck` / `Irp->RequestorMode` test anywhere.** The driver resolves `IoValidateDeviceIoControlAccess` at `0x7052` and stores it at `0x140005210`, but the pointer is **never referenced again** (no xref).
* Consequence: any process that can open `\\.\NVFLASH` reaches every IOCTL. With this DACL that means an **elevated administrator** (or SYSTEM); a filtered/standard user token is denied by the object manager. No further gate exists.

---

## 5 Most dangerous exposed capability

**5.1 Primary: unchecked-offset write into a kernel-mapped BAR (`IOCTL 0x81DE000C`)**

Path: `0x81DE000C` → case `0x12C6` → BDF lookup (`0x130D`–`0x1337`) → width dispatch (`0x1349`–`0x1359`) → store:

* byte: `0x138B` `movzx eax,[buf+0x18]`; `0x138F` `mov [rcx+r8], al`, `rcx = [buf+0x10]`
* word: `0x137B` `mov [rcx+r8], ax`
* dword: `0x1368` `mov [rcx+r8], eax`

`r8` is the MmMapIoSpace VA from `ctx+0x28` (set at `0x1F69`). `rcx` is a **zero-extended 32-bit offset** supplied by the caller. There is **no comparison against `ctx+0x24` (mapped size)** and no overflow check. The same applies to the read primitives `0x81DE0008` (case `0x11EE`) and `0x81DE0004` (case `0x1117`, up to 128 dwords).

Impact:

* In-range offsets (`< 16/32 MiB`) are ordinary GPU BAR/MMIO writes — the driver's intended nvflash register access; this permits GPU register and (via the miniport interface) potentially VBIOS/flash-side effects, but those are the product's purpose.
* Out-of-range offsets (up to `0xFFFFFFFC`) produce a **kernel virtual-address write past the mapping**: `mapped_VA + offset` can land in other system-space mappings or unmapped memory. This is a genuine kernel memory-corruption primitive, but it is *relative*: the base VA is chosen by `MmMapIoSpace` and is **not disclosed** to the caller (the enumeration record at `0x81DE0024` exposes physical BAR and size, not `ctx+0x28`). Reaching a chosen kernel object therefore requires guessing the mapping VA; a wrong guess bugchecks (`0x50`/`0x0A`).

**5.2 Secondary: unbounded record copy in `IOCTL 0x81DE0024`**

`0x1521` iterates the context list and writes 9 dwords (0x24 bytes) per entry starting at `SystemBuffer+0`, advancing `rdx += 0x24` with **no counter and no bound check** (`0x1570`–`0x15C0`). The buffer is exactly `0x7E0` bytes (`0x1521` length check), i.e. room for 56 records. With more than 56 accepted contexts (vendor 0x10DE/0x10B5/0x1000), the loop overflows the pool allocation with attacker-influenced-but-mostly-fixed data (BDF, IDs, physical addresses). Practical trigger requires >56 qualifying video devices; low likelihood, real defect.

**5.3 Secondary: unsynchronised list rebuild race**

Every case calls `0x140001BC0` when the list head is empty (`0x114C`, `0x1220`, `0x12F8`, `0x13CA`, `0x1471`, `0x1556`, `0x15EA`). `0x1BC0` first calls `0x1AF0`, which frees every context and unmaps its BAR (`0x1B69`/`0x1B6C`), then rebuilds. There is no lock, mutex, or critical section anywhere in the driver. Two concurrent IOCTLs on the (single, exclusive) handle while the list is empty can run `0x1BC0` simultaneously → double free / list corruption (`0x1BAC` even bugchecks via `int 0x29` if the list links are inconsistent). Requires a machine with no accepted GPU (empty list) or an unlucky window, plus racing DeviceIoControl calls.

**5.4 Secondary: unbounded length passed to the miniport interface**

`0x81DE0010` forwards `buf[0x14]` as a byte count to `iface->fn38(ctx, 0, buf+0x18, buf[0x10], count)` (`0x1428`) and only validates the return value. `0x81DE0014` forwards `buf[0x18]` to `iface->fn30(ctx, 0, buf+0x14, buf[0x10], count)` (`0x14D6`). Both counts are unchecked against the `0x1C`-byte system buffer; whether this overflows depends on the receiving nvlddmkm callback (outside this image).

**5.5 Information disclosure**

`0x81DE0024` returns, for each GPU: index, bus/device/function, vendor/device ID, **physical BAR base (qword)** and mapped size. `0x81DE0004`/`0x81DE0008` return raw dwords read from the mapping at arbitrary offsets. This is hardware/kernel-address information useful for follow-on attacks.

**5.6 What is NOT present**

* No caller-supplied physical address reaches `MmMapIoSpace`; the only call site is `0x1F63`, fed from PCI config space of an enumerated video device.
* No caller-supplied kernel pointer is dereferenced; all buffers are `METHOD_BUFFERED` system buffers with exact-length checks.
* No port I/O, no DMA programming, no `ZwWriteFile`, no registry write from the IOCTL path, no arbitrary call target (the only indirect calls use the driver's own interface block at `ctx+0x30`).
* `IoValidateDeviceIoControlAccess` is resolved but unused, so there is no per-IOCTL access check beyond the DACL.

---

## 6 VERDICT

**Access:** Administrator-only by construction. `D:P(A;;GA;;;SY)(A;;GA;;;BA)`, exclusive open, no `Se*` checks. A standard user cannot open `\\.\NVFLASH`; an elevated administrator can reach all 9 implemented IOCTLs.

**Is the top primitive a true kernel memory write?** **Not in the "arbitrary write" sense.** The strongest admin-reachable primitive is a **kernel-mode write to a pre-mapped PCI BAR at a caller-chosen 32-bit offset** (`0x81DE000C`, `0x1368`/`0x137B`/`0x138F`). Neither the physical base nor the kernel VA is caller-selectable, and the VA is not disclosed. Because the offset is completely unvalidated against the `0x24`-byte map-size field, offsets above the mapping turn it into a **constrained out-of-bounds kernel virtual-address write** (up to 4 GiB past a `MmMapIoSpace` region), plus matching OOB reads. That is a real kernel memory-safety defect, but it is a relative/OOB write, not a deterministic write-what-where.

**Additional admin-reachable defects:** pool overflow in `0x81DE0024` when >56 GPUs are present; unsynchronised teardown/rebuild race on the context list; unbounded lengths forwarded to the display miniport.

**Risk rating:** **Medium** for an admin-only driver. The design intent is privileged GPU register/flash access, the DACL is correct, and no unprivileged path exists. The missing bounds check on the MMIO offset and the missing enumeration cap are the items that elevate it above a pure "admin already owns the kernel" argument — they permit kernel memory corruption from a single DeviceIoControl without needing a vulnerable driver load of the attacker's own.

---

## 7 Limitations

* Static analysis only; the driver was never loaded, executed, or installed. No dynamic confirmation of mapping addresses, pool layout, or crash behavior.
* All function names are analyst-assigned (`FUN_*`); no PDB was available. Addresses are image-relative to `0x140000000`.
* REA/Ghidra decompilation was obtained for `0x1400010B0` (`ev_4209c15eeec8026d32aa9272b3cc4fcebfa5729a2efec21a7dd806f882b620ee`), `0x140001BC0` (`ev_af819ecbf1a6e6101d188acb39b55697626f9c81f7d949bc5f3332057d26c823`) and `0x1400070C0` (`ev_88937e44964b4dea06676ab6d6ea9609c69a0cb4945402d483bc2ff70bd72ef7`); byte-level reads at `0x140001000` are evidence `ev_86a64fdb4f6c479c19db3e8fb89f2fe1b0fa9eeb2cfff51a9038a36c07dde84d`. The remaining functions were reconstructed from `llvm-objdump` disassembly and a hand-written PE parser because the shared REA headless session was contended by concurrent analysts (repeated target rebinding); no claim above depends solely on an unverified decompiler name.
* The vendor-private IRP interface (major `0x1B`, minor `0x08`, `Parameters=0x10040`) and the callback block at `iface+0x30`/`+0x38` are implemented in the display miniport (`nvlddmkm`), which is outside this binary. The direction/validation semantics of those callbacks (and therefore the real impact of §5.4) could not be determined.
* BAR addresses, map sizes and device enumeration come from PCI configuration space and `IoGetDeviceProperty`; behavior on a malicious/emulated PCI device (arbitrary BAR) was not modelled.
* Authenticode status was checked statically with `Get-AuthenticodeSignature` (Valid, WHCP); revocation and catalog membership were not evaluated.
* No source, INF, or PDB was available; the SDDL path was verified from the embedded `UNICODE_STRING`/string bytes, not from build scripts.
