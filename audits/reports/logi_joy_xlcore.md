# Static Security Audit - `logi_joy_xlcore.sys`

| | |
|---|---|
| **File** | `C:\Users\<scrubbed>\Desktop\driver_candidates\logi_joy_xlcore.sys` |
| **SHA-256** | `38f5cf58e4b4b58e3c89428482a2b6570aa38d3f4ace9ce5a1f964f3a753e488` (matches REA on-open digest) |
| **Analysis date** | 2026-10-23 |
| **Method** | Static-only audit via REA/Ghidra. No execution, no dynamic instrumentation, no external/web lookups. Every claim cites a concrete code or data address of this file. |

Audit order follows the requested workflow: PE entry -> device creation/interface registration -> dispatch/IOCTL enumeration -> access-control audit -> single most dangerous exposed capability.

---

## 1. Internals

### 1.1 Basic layout
- PE32+ (64-bit), image base `0x140000000`. ~135 procedures, ~64 strings enumerated by REA.
- Sections of interest:
  - `PAGE` segment `0x140010000`-`0x140010400` - contains the PnP dispatch machinery (`FUN_140010000`, `FUN_1400100b0`, `FUN_140010200`).
  - `INIT` section at `0x140011000` - contains the PE entry stub and real `DriverEntry`.
- PE entry point `0x140011140` (`entry`) -> real DriverEntry is `FUN_140011000` at `0x140011000`.

### 1.2 What is *not* DriverEntry
- `0x140001000` looks like an early "core" routine but is in fact a **static-table initializer**: it fills a powers-of-two table at `DAT_14000e880`, zeroes `DAT_14000e2e0` (0x594 bytes), then calls `FUN_140002778`, and returns 1 (`thunk_FUN_140001000` @ `0x140001000`). It is invoked during DriverEntry *and* re-invoked on PnP-start re-init (`FUN_14000218c` -> `thunk_FUN_140001000`).
- The true DriverEntry is `FUN_140011000` (see section 2.1).

### 1.3 Runtime-resolved import
- `MmGetSystemRoutineAddress` is resolved at `0x14000588f` and is used to fetch **`RtlQueryRegistryValuesEx`** at runtime. This is the only runtime-resolved kernel routine in the binary (only non-IAT import call site).
- The caller is the registry helper `FUN_1400057d8`: builds a 32-byte query table, `RtlInitUnicodeString` + `RtlQueryRegistryValuesEx`, to read the service key `...\Parameters` value `DebugLevel`.
- Registry path strings in the binary: `L"LGJoyXLCore\\Parameters"` and value `L"DebugLevel"`; debug-print prefix `"LGJoyXLCore:"` stored at `0x14000e2b0` and installed in DriverEntry.

### 1.4 Device identity strings (verbatim from the binary)
- `VID_046D&PID_C202`, `VID_046D&PID_C209` (HID gamepad enumerations).
- Device description string `"LogitechWingManNewDevice"`.
- Registry key `LGJoyXLCore\Parameters`.

*Note on naming:* the description string is quoted verbatim because it is inside the audited file. Judgements below are based only on code/strings found in this image, not on external knowledge of the vendor.

### 1.5 Memory and locking model
- **Per-collection state object:** 0x378 bytes, allocated from NonPagedPoolNx with pool tag `0x594f4a4c` (`'LJoY'`) in `FUN_1400054fc`. Fields used by the control handlers:
  - `+0x00` next-pointer (singly linked list head at `DAT_14000e210`),
  - `+0x08` self-pointer,
  - `+0x18` lower-device / descriptor pointer,
  - `+0x2c` active flag (bit `0x2`),
  - `+0x358` additional descriptor field (0xd6 x 4 byte offset),
  - `+0x368` `KSPIN_LOCK`, with wrappers `FUN_140005b68` (~ `KeAcquireSpinLockRaiseToDpc`) and `FUN_140005b90` (~ `KeReleaseSpinLock`).
- **Global locks:** writer lock `DAT_14000e224` and reader lock `DAT_14000e220`, guarded by busy-wait loops that call `KeStallExecutionProcessor(1)` - exclusive-acquire `0x140002920`, shared-acquire `0x1400027e8`, shared-release `0x140002848`, exclusive-release `0x140002980`.
- **Collection removal:** `FUN_140002874` - acquire lock, unlink node from `DAT_14000e210`, `ExFreePool` both node and payload (payload leak if the list is in an unexpected state).
- **Integer-key collection lookup helpers:** `FUN_1400026e0` and `FUN_140002730` walk `DAT_14000e210`.

### 1.6 Upward (outbound) IRP traffic
The driver actively **sends internal control codes down to the lower device**:
- Synchronous: `FUN_14000557c` builds requests with `IoBuildDeviceIoControlRequest`.
- Asynchronous: `FUN_140005650` allocates an IRP with `IoAllocateIrp`; completion routine `FUN_140005550`; buffers pool-allocated with tag `0x6e696f69`.
- Target control codes observed: `0x2a2004` and `0x2a2028`, with input sizes 12 bytes / caller-specified, dispatched through `FUN_140001690` / `FUN_140001760` - i.e. reads of lower-layer force-feedback/poll configuration.
- Import (`IAT` thunk) xrefs enumerated for `IoBuildDeviceIoControlRequest`, `IoAllocateIrp`, `ExAllocatePoolWithTag`; entries in `.rdata` near `0x1400070xx`, in-procedure calls near `0x1400055xx`; the entries around `0x14000f0xx` are `.rdata` cross-reference data-table entries, not code.

### 1.7 Driver-to-driver registration handshake
- On `IRP_MJ_INTERNAL_DEVICE_CONTROL` code `0x222478`, handler `FUN_14000181c` hands back a function-pointer vector at `&PTR_FUN_14000c2b0` (`.rdata`, `0x14000c2b0`), whose slots point at local callbacks: add `FUN_140001240`, remove `FUN_1400013e0`, plus `0x140001570`, `0x1400015c0`, `0x140001690`, `0x140001760` (the latter two are the outbound/internal-IRP handlers of section 1.6).
- This is an **upper-layer kernel consumer registering callbacks** - it is not a user-mode reachability vector. Reaching `0x222478` requires a kernel-mode sender of `IRP_MJ_INTERNAL_DEVICE_CONTROL`; the driver's user-facing dispatch is `IRP_MJ_DEVICE_CONTROL` only (see section 3).
- `0x22247c` -> `FUN_140001800` / `FUN_1400025c8`: allocates a 0x10-byte node onto list `DAT_14000e218`.
- `0x223400` -> completed with success **without forwarding** (swallowed).
- Default -> forwarded to the lower stack.

---

## 2. Device & entry chain

### 2.1 DriverEntry (`FUN_140011000` @ `0x140011000`)
- Sets ANSI debug prefix `"LGJoyXLCore:"` (string at `0x14000e2b0`).
- Reads `DebugLevel` from `LGJoyXLCore\Parameters` via `FUN_1400057d8` (section 1.3).
- Fills all 28 `MajorFunction` slots with default forwarder `FUN_140005ac0`, then overrides (verified against the x64 `DRIVER_OBJECT` layout - MajorFunction base `+0x70`, DriverUnload `+0x68`):

| Index | IRP major | Handler |
|---|---|---|
| 0 | `IRP_MJ_CREATE` | `0x140005a50` |
| 2 | `IRP_MJ_CLOSE` | `0x140005a50` |
| 14 | `IRP_MJ_DEVICE_CONTROL` | `0x1400021c0` |
| 15 | `IRP_MJ_INTERNAL_DEVICE_CONTROL` | `0x1400029b0` |
| 22 | `IRP_MJ_POWER` | `0x140005250` |
| 27 | `IRP_MJ_PNP` | `0x1400100b0` |

- `DriverUnload` (`+0x68`) -> `0x140005b10`.
- `AddDevice` (DriverExtension `+8`) -> `0x1400058f0`.

### 2.2 AddDevice (`0x1400058f0`)
- Calls **`IoRegisterDeviceInterface`**(PDO, GUID at `0x14000c9b8`, reference string = 0, symbolic-link out-buffer `&DAT_14000e250`), guarded by flag `DAT_14000e248` so it registers once.
- GUID decoded from bytes at `0x14000c9b8`: **`{1ABC05C0-C378-41B9-9CEF-DF1ABA82B015}`**.
- Calls **`IoCreateDevice`**(DriverObject, extension size `0x20`, device name `NULL` -> **unnamed device object**, type `FILE_DEVICE_UNKNOWN` (0x22), characteristics 0, **`Exclusive = FALSE`**). No `SecurityDescriptor` argument is supplied.
- Attaches the new device to the driver stack; copies lower device-object flags/type; clears `DO_DEVICE_INITIALIZING` (bit 0x80 of flags at `DeviceObject+0x30`).

### 2.3 PnP dispatch (`0x1400100b0`)
- Minor 0x00 (`IRP_MN_START_DEVICE`): forward-and-wait through helper `FUN_140010000`, then completion path `FUN_140010200` calls **`IoSetDeviceInterfaceState(&DAT_14000e250, TRUE)`** (enabling the device interface) and sets ext+0 = 1.
- Minor 0x02 (`IRP_MN_REMOVE_DEVICE`): **disable** the interface, `IoDetachDevice`, `IoDeleteDevice`; raises the disabled-state byte (ext+1).
- Minor 0x04 (`IRP_MN_STOP_DEVICE`): disable interface, forward-and-wait, then complete with the inbound status.
- All other minors follow the default completion/forward path.
- Interface string registration is the only user-mode-visible handle: the driver exposes a **named device interface** on an **unnamed, non-exclusive device object**.

### 2.4 Unload (`0x140005b10`), Power (`0x140005250`), default forwarder (`0x140005ac0`)
- Unload: if the interface was registered, `IoSetDeviceInterfaceState(&DAT_14000e250, FALSE)`, `RtlFreeUnicodeString(&DAT_14000e250)`, clears flag `DAT_14000e248`. **No** device deletion, list teardown, or pool teardown happens here (WDM-filter style; relies on PnP REMOVE).
- Power: `PoStartNextPowerIrp` then forward via `PoCallDriver` (verified via import xrefs).
- Default forwarder: copies stack location and `IofCallDriver`s to the lower device (from ext+0x18). If the disabled-state byte (ext+1) is nonzero, IRPs are completed with `0xC0000056` - the same gate exists in CREATE/CLOSE and the internal-control path.

---

## 3. IOCTL table (`IRP_MJ_DEVICE_CONTROL` @ `0x1400021c0`)

### 3.1 Dispatch mechanics - the decode is deliberately loose
- `Windows` IOCTL bit layout: `[31:16] DeviceType | [15] Custom | [14:13] Access | [12:2] Function | [1:0] Method`.
- The dispatcher computes **`key = ((IoControlCode >> 2) & 0xFFF)`** - i.e. it extracts **only the 12-bit FUNCTION field**. Verified against raw instruction bytes at `0x14000221b`.
- For keys where `(key & 0xF00) == 0x900`, the key is repacked with a bit-set on the high bit (`BTS`-style packing, same raw bytes at `0x14000221b`), so the `0x9xx` FUNCTION family collapses onto consecutive case keys **`0x8016`-`0x8020`** (raw jump-table/case bytes verified).
- Consequences (all machine-verified in the dispatcher):
  - **DeviceType bits `[31:16]` are never checked** - any device-type encoding reaches every handler.
  - **Access bits `[14:13]` are never checked** - `FILE_ANY_ACCESS`-encoded CTL codes reach handlers that declare `FILE_WRITE_ACCESS` semantics, and vice-versa. This defeats handle-based access filtering that user-mode callers might set up via `CreateFile` access requests.
  - **Method bits `[1:0]` are never checked** - METHOD_BUFFERED vs. METHOD_IN/OUT_DIRECT is decided per-handler by which buffer pointer the handler reads, not by the encoding.
- Case keys `0x8400`/`0x8401` exist in the switch but are **unreachable** from the mask math (dead branches) -> `STATUS_NOT_SUPPORTED` (`0xC00000BB`).
- Default case: inlined `IoSetNextIrpStackLocation` (+0x48 stack-location stride; byte at `IRP+0x43` incremented) + `IofCallDriver` to the lower device (ext+0x18).

### 3.2 Handled FUNCTION codes (`0x916`-`0x920`)
All handlers operate on the pool-allocated 0x378-byte collection objects of section 1.5, keyed per-collection. Every case is bounded by either an explicit input-length check or static structure sizes - details in each row.

| FUNCTION | Case key | Input requirement | Output requirement | Handler chain | Kernel action | Bound evidence |
|---|---|---|---|---|---|---|
| 0x916 | 0x8016 | input length checked by dispatcher | - | `FUN_1400011d4` -> `FUN_140002c74` | per-collection trailing/refill refresh | writes confined to collection pool tables (`FUN_140002c74` layout) |
| 0x917 | 0x8017 | **none** (no length check; none needed) | - | `FUN_1400011bc` -> `FUN_140002608` -> `FUN_140001230` | walks **all** collections and refreshes each one's state | reads only from ext/inernal pool structures |
| 0x918 | 0x8018 | `InputBufferLength >= 0x28`, plus field check e.g. `input[8]==2` | - | `FUN_140005008` x2 | writes per-collection config tables | bounded by table capacity checks (`< 100`, `< 0x65`) |
| 0x919 | 0x8019 | `InputBufferLength >= 0x28` | - | `FUN_140003e3c` | channel assignment via static lookup | static `.rdata` table at `0x140007300`; indices bounded before use |
| 0x91A | 0x40C4 | - | `OutputBufferLength >= 0xe` | `FUN_140001828` | writes command+value into the pooled SystemBuffer (slots `param_1[1]`, `param_1[2]`); command clamped by switch | writes go back into the user's own buffer pool; no kernel-address write path |
| 0x91B | 0x801B (alias 0x40CC) | `InputBufferLength == 12` | - | `FUN_140001ae0` | fixed-offset writes into collection fields; command branches `0x1d`->`0x30` | every write at fixed offsets within the collection struct |
| 0x91C | 0x801C | `InputBufferLength >= 0x36`; NUL guaranteed by dispatcher-zeroed `input+0x32` | - | `FUN_1400053b0` -> `FUN_140005498` | vendor-string table walk; 41 entries x 16 B at `0x14000c338` w/ pointer table `0x14000c330`; reads only to first NUL | no OOB; no match -> `0xC000000D` |
| 0x91D | 0x801D | `InputBufferLength >= 8` | - | `FUN_14000537c` | static-table lookup (<=41 entries) | indices bounded |
| 0x920 | 0x8020 | `InputBufferLength >= 0x14` | - | `FUN_140003fa8` | fixed-offset writes into collection tables; only commands 1/2/3/7 accepted | bounded loops, fixed offsets |

Illustrative user-mode encodings (computed from the standard CTL bit layout, since the dispatcher ignores everything except FUNCTION): `FUNCTION 0x916` is reachable, among others, as `0x22002458` (`FILE_DEVICE_UNKNOWN|FILE_ANY_ACCESS|METHOD_BUFFERED`). **Any** encoding reaches the same handler.

### 3.3 Internal control codes (`IRP_MJ_INTERNAL_DEVICE_CONTROL` @ `0x1400029b0`)
- `0x222478` -> returns the callback vector `&PTR_FUN_14000c2b0` (section 1.7 - kernel-to-kernel registration, **not user-reachable**).
- `0x22247c` -> node allocation onto `DAT_14000e218` (section 1.7).
- `0x223400` -> completed success without forwarding.
- Default -> forwarded.

### 3.4 Bound-check verdict for section 3
No user-reachable handler writes to kernel addresses derived from user input without either (a) a length gate checked against a fixed constant, or (b) indices/clamps derived from static `.rdata` tables. **No arbitrary kernel write primitive was found in any user-reachable path.** The IOCTL surface's risk is *who may call these codes at all* - see section 4.

---

## 4. Access-control audit

Result: **no access control of any kind on the user-reachable IOCTL surface.**

1. **No security descriptor.** Searched the full string table for `SDDL`, `D:P`, `Everyone`, `SecurityDescriptor`, `Access`, `Privilege` - **0 matches**. The binary contains no SDDL string and no `RtlSetDaclSecurityDescriptor`-style logic.
2. **No privilege checks.** No import of `SeSinglePrivilegeCheck` (or any `Se*` access-check routine). No `ACCESS_DENIED` (`0xC0000022`) completion exists on the control path; the only denials are `0xC000000D` (no-match in 0x91C) and `0xC00000BB` (unreachable dead keys).
3. **Device opens are unrestricted.** `AddDevice` uses `IoCreateDevice` with **no `SecurityDescriptor`** argument, so the device object inherits the default DACL; combined with `Exclusive = FALSE`, any number of users/processes can open handles subject only to file-system-default conditions. **No caller identity check** exists in the `IRP_MJ_CREATE`/`IRP_MJ_CLOSE` path (`0x140005a50` - forward only, plus the ext+1 disabled-state gate to `0xC0000056`).
4. **Access bits ignored at dispatch.** Per section 3.1, the dispatcher keys on FUNCTION alone; **`FILE_ANY_ACCESS` primary-token callers reach write-semantics handlers** (`0x918`, `0x919`, `0x91B`, `0x920`) exactly as write-access callers would. There is no per-IOCTL access-mask enforcement anywhere between `IofCallDriver` and the handler body.
5. **Device interface is the handle surface.** `IoRegisterDeviceInterface` with GUID `{1ABC05C0-C378-41B9-9CEF-DF1ABA82B015}` (`AddDevice` @ `0x1400058f0`, GUID bytes at `0x14000c9b8`) publishes a user-mode-openable interface as soon as PnP START fires (`IoSetDeviceInterfaceState` call inside `FUN_140010200`).
6. **Only gating found:** the ext+1 disabled-state byte, raised on PnP REMOVE/STOP (`0x1400100b0` -> `FUN_140010200`/`0x140010100` region), which completes later IRPs with `0xC0000056`. This is a lifecycle guard, not a security boundary.

---

## 5. Most dangerous exposed capability

**Unauthenticated per-collection configuration/state manipulation of attached input-device instances.**

Concretely, any user-mode caller that can open the published device interface (GUID `{1ABC05C0-C378-41B9-9CEF-DF1ABA82B015}`) can, without any privilege check, identity check, or access-mask enforcement:

- **Rewrite the persistent configuration** of any connected collection instance via `FUNCTION 0x918` (needs input >= 0x28 bytes; writes into per-collection tables through `FUN_140005008` x2), `0x919` (>= 0x28 bytes; static-table-driven channel assignment via `FUN_140003e3c`), `0x91B` (12 bytes; fixed-offset field rewrites via `FUN_140001ae0`), and `0x920` (>= 0x14 bytes; command-1/2/3/7 table writes via `FUN_140003fa8`).
- **Query** state and vendor data via `0x91A` / `0x91C` / `0x91D` without output-side gating beyond minimum lengths.
- **Force a wholesale refresh/reset** of every attached collection in one call via `0x917` (no input at all - `FUN_1400011bc` walks the whole list `DAT_14000e210`), or per-instance reset via `0x916` (`FUN_1400011d4`).

Amplifier: the dispatcher ignores the Access bits (section 3.1), so a `FILE_ANY_ACCESS` handle - the access mode a caller obtains with the *least* access request - reaches all of the write-semantics codes above. Combined with `Exclusive = FALSE` and no SDDL on the device object, this is a full control plane over the filter's per-instance configuration, reachable by any local user able to open the interface. Realistic impact is device-misconfiguration (force-feedback/poll parameters, channel assignment, identity/ven strings), not code execution - no user-reachable handler was found that writes kernel memory outside the pool-allocated collection objects and the caller's own buffers (section 3.4).

---

## 6. VERDICT

- **Not a kernel backdoor / not an exploit primitive.** All user-reachable IOCTL handlers are bounded by explicit `InputBufferLength`/`OutputBufferLength` checks or by static table sizes (section 3.2/section 3.4). No arbitrary kernel read/write was found.
- **Dangerous exposure, not dangerous code.** The control plane is effectively an **unauthenticated per-collection configuration/query SDK**: no SDDL, no privilege check, non-exclusive unnamed device object, device-interface handle available to any caller (section 4).
- **Dispatch-layer access-control negligence.** The dispatcher decodes only the 12-bit FUNCTION field (`0x1400021c0`, raw bytes verified at `0x14000221b`); DeviceType/Access/Method bits are never tested, so `FILE_ANY_ACCESS` reachability of write-config codes is by construction, not accident of encoding.
- **Recommended posture for deployment review:** treat this driver as exposing an unauthenticated local configuration interface over input-device instances; if the threat model includes untrusted local users, the missing access control (section 4) is the finding to act on.
- **Suggestions for source-level fixes** (if source is available): enforce `Access` bits in the dispatch (`switch` on the full 24-bit CTL), complete with `STATUS_ACCESS_DENIED` per-handler when access does not match, restrict the device-object DACL/SDDL to admin-only SIDs for the configuration codes, and gate removal of state behind the disabled-state logic already present.

---

*Addresses in the form `0x1400NNNNN` are image-relative virtual addresses at preferred base `0x140000000`. Handler chains were verified statically (decompile + raw byte reads at the cited sites); no runtime evidence was collected. Analysis performed entirely offline with REA/Ghidra on the file whose SHA-256 appears in the header.*
