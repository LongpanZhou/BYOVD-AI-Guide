# Audit: AppleKmdfFilter.sys

**File:** `C:\Users\<scrubbed>\Desktop\driver_candidates\AppleKmdfFilter.sys`
**SHA-256:** `E044B74FF494725D56B292ACE8D558E315AE406085EE3695D859AD97254897FA`
**Analysis date:** 2026-10-23
**Method:** Static-only audit via REA/Ghidra (Ghidra decompiler + custom PE parsers; no execution, no network, no external references)

---

## 1 Internals

**PE facts (from optional/section headers, file offset `0xE0`):**

| Property | Value |
|---|---|
| Machine / Magic | `0x8664` / `0x020B` (x64) |
| Subsystem | `1` = Native (kernel driver) |
| `AddressOfEntryPoint` | `0x16D0` -> `entry` @ `0x1400016D0` |
| Sections | `.text` (RVA 0x1000, VSz 0xB69), `.rdata` (0x2000, 0x528), `.data` (0x3000, VSz 0x2F8, raw 0x200), `.pdata`, `PAGE` (0x5000, RWX 0x60000020), `INIT` (0x6000), `.rsrc`, `.reloc` |
| DllCharacteristics | `0x4160` - contains `IMAGE_DLLCHARACTERISTICS_GUARD_CF` (CFG on) |

**Import table (parsed at RVA `0x6094`, INIT - complete, only two modules):**

- `NTOSKRNL.EXE` -> `RtlCopyUnicodeString` (hint/name entries at RVA `0x6120`/`0x6108`-`0x610A`)
- `WDFLDR.SYS` -> `WdfVersionBind` (`0x6130`), `WdfVersionUnbind` (`0x6142`), `WdfVersionBindClass` (`0x6156`), `WdfVersionUnbindClass` (`0x616C`)

Notably absent (checked both the import table and the whole image): `IoCreateDevice`, `IoCreateDeviceSecure`, `IoCreateSymbolicLink`, any `Zw*`, any `Ex*`, any `Se*`, `Mm*`, `Ob*`. The only direct NT call in the entire binary is `RtlCopyUnicodeString`.

All other framework interaction goes through the **KMDF version-independent function table**: `WdfVersionBind` (called at `0x1400010B7` in `FUN_1400016FC`) delivers a table pointer stored at global `0x1400032D8`; every framework call is then `MOV RAX,[0x1400032D8] / MOV RAX,[RAX+slot] / CALL [0x140002040]` (the CFG `_guard_dispatch_icall` thunk at `0x140001A40`). The FxContext handle lives at `0x1400032E0` and is passed as first argument to every table call. In this report such calls are cited as *WDF-table slot +<offset>*; slot names are not resolvable statically (the table is populated at runtime by `WdfVersionBind`) - purposes below are inferred from argument shapes, not from vendor knowledge.

**Procedure inventory (29 entries from `binary_overview`, Evidence `ev_774868ffdfe5549fdedfd8fa4b51a1a7af5edcaafe250e722bbbc3cf7821854a`):**

| Address | Role |
|---|---|
| `0x140006064` | security-cookie init (`DAT_140003030` cookie base, `~cookie` folded into `0x140003038`) |
| `0x1400016D0` | PE `entry` (KMDF stub driver entry) |
| `0x1400016FC` | `FxStubDriverEntry`-equivalent: registry-path copy, `WdfVersionBind`, class/type binding, delegates to real `DriverEntry` work |
| `0x1400018D0` | `WdfVersionBindClass` loop over `.kmdfclassbind` records (`*rec == 0x50` check, callers of `WdfVersionBindClass`) |
| `0x14000186C` | type-init record loop over `&DAT_1400030A0` (`*rec == 0x28`, size-0x28 records, callback at `+0x20`) |
| `0x140001830`, `0x140001840`, `0x1400016A0` | `FxStubDriverUnloadCommon` / `FxStubDriverUnload` / `FxStubUnbindClasses` glue |
| `0x140006000` | real driver-registration: calls WDF-table slot `+0x3A0` with `(FxContext, DriverObject, RegistryPath, 0, {0x20-size config containing pointer to 0x140005000}, ...)` - passes `0x140005000` as `EvtDriverDeviceAdd` |
| `0x140005000` | `EvtDriverDeviceAdd` (PAGE section, `0x140005000-0x140005123`) - see section 2 |
| `0x140001000-0x140001512` | request-interception callback registered by `0x140005000` - see section 3 |
| `0x140001514-0x140001533` | request-finalization helper called from `0x1400014EF` (the only caller) |
| `0x140001610` | `__fastfail` helper (`MOV ECX,2; INT 29h`, called from `__security_check_cookie` fail path `0x1400015F9`) |
| `0x140001600` | `__security_check_cookie`; `0x1400015E0` cookie-compare stub |
| `0x140001620`, `0x140001640` | dead code - no caller anywhere (see below) |
| `0x1400019FB`, `0x140001A01`, `0x140001A10`, `0x140001A20` | import thunks for the four `WDFLDR` imports |
| `0x140001A40` | `_guard_dispatch_icall` (CFG thunk; literal target of **every** indirect call: `CALL qword ptr [0x140002040]`) |
| `0x140001A80` | `memset` |

**Hardening:** /GS cookie present and verified (`0x14000101B` XOR check in `FUN_140001000`, `0x1400014F8` epilogue check against `RBP+0x37`); CFG fids table at `0x140002048` (dword RVAs `0x1000, 0x1600, 0x1610, 0x16D0, 0x1830, 0x1840, 0x1A10, 0x1A20, 0x5000, ...`); all indirect framework calls route through `_guard_dispatch_icall`.

**Dead code:** `FUN_140001620` (wraps `FUN_140001640`; returns 1) and `FUN_140001640` (reads `u64 @obj+8`, `u32 @(*(obj+0x10)+8)`, then a byte at `+3+index`; `if (b & 0xF) return b & 0xF0; return u64val` - a descriptor/limit extractor shape). Verified by three independent methods: Ghidra xrefs (only hits are the guard-XFG table tuples `20 16 00 00 40 00 00 00` / `20 16 00 00 E0 00 00 00` at `0x140002488`/`0x1400024A8` and unwind `.pdata` entries at `0x140004024`/`0x140004030`), a whole-image qword scan (no pointer `0x140001620`/`0x140001640` exists in `.rdata`/`.data`), and a full `E8/E9` rel32 call-target scan across `.text`/`PAGE`/`INIT` (targets found: `0x140001514, 0x1400015E0, 0x140001610, 0x140001640(via 1620), 0x1400016A0, 0x1400016FC, 0x14000186C, 0x1400018D0, 0x140001980, 0x140006000, 0x140006064` - **nothing targets `0x140001620`**).

**Build provenance (embedded, shipped-artifact evidence):** debug directory at RVA `0x20A0` contains a CodeView record; PDB string at image `0x1400023F0...`: `D:\BWA\DF83B7D4-6CF2-0\AppleWinUSBDriver-486.40.9\srcroot\WindowsWinUSB\x64\Release\AppleKmdfFilter.pdb`, PDB GUID `0f1eb38f-b37f-41ab-1a07-5861b7dfed01`(? raw bytes `38 BF 0F 1E B3 7F 41 AB 1A 07 58 61 B7 DF ED 01`), link timestamp `0x5F77BCF1` (2020-10-03). Version resource (`.rsrc` string block at `0x14000714A...`): `CompanyName` = `Apple Inc.`, `FileDescription` = `Apple Mobile Device USB Device`, `OriginalFilename`/`InternalName` = `Generic.sys: ` (DDK filter-template artifact), `ProductVersion`/`FileVersion` = `486.0.0.0`, `ProductName` = `Windows (R) Win 7 DDK driver`.

**KMDF bind tables (`.data`, file `0x1600-0x1800` -> VA `0x140003000-0x140003200`):**

- `0x140003000`: type/context-info record `{ Size=0x28, NamePtr->0x140002070 ("FILTER_EXTENSION"), 8, self-ptr, ..., 0x00002B992DDFA232, 0xFFFFD466D2205DCD }` - the WDF context-type descriptor named `FILTER_EXTENSION`.
- `0x140003040`: `WDF_BIND_INFO` `{ Size=0x30, Component->"KmdfLibrary" (0x140002088), Maj=1, Min=15, 0x1BC, Functions->0x1400032D8 }` - binds **KMDF v1.15**.
- `0x140003080/0x140003088/0x140003090`: `.kmdfclassbind$a/$c/$d` records; `0x1400030A0/0x1400030B0`: `.kmdftypeinit$a/$c` (zero-filled at rest, filled during bind loop `FUN_1400018D0`/`FUN_14000186C`).
- `0x140003030`: /GS security cookie (also referenced from LoadConfig at VA `0x140002138`).

**Authenticode signature (static certificate-directory parse, `DD[4]` at file offset `0x2600`, length `0x2840`):** `WIN_CERTIFICATE { Length=0x2840, Revision=0x0200, CertificateType=0x0002 (PKCS_SIGNED_DATA) }`. Strings extractable from the PKCS#7 blob include the leaf subject **`$WDKTestCert build,1323032564032789080`** (a WDK-generated *test* signing certificate) and intermediate `Microsoft Windows Third Party Component CA 2012`. Static-only caveat: chain verification was not executed; but a `WDKTestCert`-named leaf is a build-machine test certificate, which under Windows code-integrity policy alone does not provide production trust (it is only loadable with kernel test-signing enabled). This is an observation about the file's own contents, not an external claim about any vendor.

---

## 2 Device & entry chain

Entry chain (all addresses verified in disassembly):

1. `entry` (`0x1400016D0`, = PE `AddressOfEntryPoint 0x16D0`): calls `FUN_140006064` (cookie init) then `FUN_1400016FC`.
2. `FUN_1400016FC` (`FxStubDriverEntry`-equivalent): `RtlCopyUnicodeString` copies the driver service-key registry path (buffer `0x1400032C8`, target buffer allocated at `0x1400030B0`/`0x140003250` region per `_DAT_1400032D0 = &DAT_1400030B0` at `0x14000170B`), then `WdfVersionBind(DriverObject, &unicodePath, &DAT_140003040, &FxContext)`; on failure `FxStubDriverUnloadCommon` (`0x1400017D6` -> `0x1400016A0` -> `WdfVersionUnbind`). Installs `FxStubDriverUnload` into `DRIVER_OBJECT->DriverUnload` (`*(param_1+0x68) = 0x140001840`).
3. `FUN_140006000`: calls **WDF-table slot `+0x3A0`** with `(FxContext, DriverObject, RegistryPath, 0, {0x20-size structure whose field holds `0x140005000`}, ...)` at `0x140001765` - i.e., **real driver registration with `EvtDriverDeviceAdd = 0x140005000`**. (Analogous slot `+0x648` read at `0x140001756` seeds the unload thunk.)
4. **`FUN_140005000` = `EvtDriverDeviceAdd` (PAGE `0x140005000-0x140005122`)** - the only device-creation code in the binary. Five WDF-table calls, in order:

   | Order | Slot | Args (beyond FxContext) | Evidence |
   |---|---|---|---|
   | 1 | `+0x238` | `DeviceInit`, `&{0x28,0,0,0,1,4}`, `0` | `0x140005012-0x140005051`; struct fields `1`@`+0x20`, `4`@`+0x24` (bool/DxState-ish pair; `4` = D3 in the DEVICE_POWER_STATE scale) |
   | 2 | `+0x1C8` | `DeviceInit`, `0` | `0x140005057-0x140005073` |
   | 3 | `+0x250` | `DeviceInit`, **`&FUN_140001000`** | `0x14000508F: LEA R8,[0x140001000]`; the request-interception callback is attached to the device init (`call @0x1400050C8`) |
   | 4 | `+0x1E8` | `DeviceInit`, `3` | `0x1400050D5` |
   | 5 | `+0x258` | `&DevInit`, `&WDF_OBJECT_ATTRIBUTES{Size=0x38, +0x18=1, +0x1C=1, +0x30=ContextTypeInfo->0x140003000}`, `&outDevice` | `0x1400050DB-0x140005114`; the attributes block references the `FILTER_EXTENSION` context-type record of section 1 |

   No other object is created: there is **no second device creation, no `WdfDeviceCreateDeviceInterface`-shaped call (no L"GUID:"-class constant and no 16-byte interface GUID anywhere in `.rdata`/`.data` - byte-checked), no symbolic link, no queue creation beyond the request-callback attachment**, and no `IoCreateDeviceSecure`/SDDL path (import table has no `Io*` at all).

**Strings relevant to exposure:** the complete REA string inventory (40 strings) contains exactly one module-identity string, `FILTER_EXTENSION`, and no device-object paths (`\Device\`, `DosDevices`), no interface GUID text, no SDDL/security-descriptor text, no "exclusive"/"Everyone"/"Users" markers. Combined with the import table (`RtlCopyUnicodeString` + 4 `WdfVersion*` only) this is conclusive static evidence that **the binary does not create or register any new user-facing device interface**; user-mode reachability, if any, is inherited from the device object of the stack this filter attaches to inside `EvtDriverDeviceAdd`, which the framework owns outside this image.

---

## 3 IOCTL table

The single request handler is `FUN_140001000` (`0x140001000-0x140001512`), attached in section 2 step 3. Locus of dispatch:

- `0x140001042-0x14000105B`: slot `+0x850(FxContext, request, &{0x28,0,...})` fills a 0x28-byte descriptor; field `+0x04` = request major (`ECX @0x140001061`), field `+0x18` = associated control code (`EDI @0x14000106D`).
- `0x140001064`: `CMP ECX, 0x0E` -> **IRP_MJ_DEVICE_CONTROL (14)** branch; `0x140001285: CMP ECX,3` -> **IRP_MJ_READ (3)**; `0x14000141C: CMP EAX,4` -> **IRP_MJ_WRITE (4)**. Any other major -> default path `0x1400014AD`.

### IRP_MJ_DEVICE_CONTROL (14) - control-code match table

All compared codes share device type `bit31-16 = 0x0022` (`FILE_DEVICE_USB`-namespace by raw arithmetic; reported here purely as observed numeric identities). The comparison tree is at `0x140001070-0x1400011F8`; each group computes a **rewritten control code** and stores it into field `+0x18` of a 0x48-byte block copied from `*(result_of_slot_+0x8E8 + 0xB8)` (copy via `MOVUPS/MOVSD` at `0x140001232-0x14000126D`, patch `MOV dword ptr [RBP-0x21], EAX` @`0x140001264`), then invokes slot `+0x7E0` with `(FxContext, request, &patchedBlock)` at `0x14000127A`, followed by the completion path of section 3.4.

| # | Accepted codes (exact step-4 ranges hit by the switch) | Method bits of accepted code | Rewrite formula (verbatim assembly) | Resulting code | Effect |
|---|---|---|---|---|---|
| 1 | `0x220021, 0x220025, 0x220029, 0x22002D, 0x220031, 0x220035, 0x220039, 0x22003D` (`checks @0x140001092-0x1400010BB`) | METHOD_IN_DIRECT (...21/...25: low2 bits = 1) | `((code-0x220021)&0xFFFFFFFC)+0x20` `|0x220002` (`0x1400010E6-0x1400010F2`) | `0x220022+4k` | method flipped 1->2, function (bits 13-2 = 8...15) unchanged |
| 2 | `0x220042, 0x220046, 0x22004A, 0x22004E, 0x220052, 0x220056, 0x22005A, 0x22005E` (`@0x1400010FC-0x140001121` + `EQ 0x220042 @0x14000108C`) | METHOD_OUT_DIRECT (low2 = 2; functions 16...23) | `((code-0x220042)&0xFFFFFFFC)+0x40` `|0x220001` (`0x14000114C-0x14000122D`) | `0x220041+4k` | method flipped 2->1 |
| 3 | `0x220191, 0x220195, 0x220199, 0x22019D, 0x2201A1, 0x2201A5, 0x2201A9, 0x2201AD` (`@0x14000116C-0x14000118F` + `EQ 0x220191 @0x14000107D`) | METHOD_IN_DIRECT (functions 100...107) | `((code-0x220191)&0xFFFFFFFC)+0x190` `|0x220002` (`0x1400011BC-0x1400011CA`) | `0x220192+4k` | method flipped 1->2 |
| 4 | `0x2201B2, 0x2201B6, 0x2201BA, 0x2201BE, 0x2201C2, 0x2201C6, 0x2201CA, 0x2201CE` (`@0x1400011CF-0x1400011F2` + `EQ 0x2201B2 @0x140001166`) | METHOD_OUT_DIRECT (functions 108...115) | `((code-0x2201B2)&0xFFFFFFFC)+0x1B0` `|0x220001` (`0x14000121F-0x14000122D`) | `0x2201B1+4k` | method flipped 2->1 |

Access mask: all accepted codes have `bits 15-14 == 0` (`FILE_ANY_ACCESS` on the numeric). Transfer method (bits 1-0): groups 1/3 = METHOD_IN_DIRECT (needs a kernel-side output MDL), groups 2/4 = METHOD_OUT_DIRECT. The four groups are therefore expected to be **kernel-internal bus control codes from the device stack itself**, not exported user-mode control codes, on numeric grounds.

**Default path (`@0x1400014AD`)**: any other control code (and every other major function) goes to slot `+0x7D8(FxContext, request)` - a single-argument "pass through untouched" call - then to the completion helper. The handler performs **no code-dependent memory operation, no user-pointer dereference, no length arithmetic** in either branch: the only mutation it performs is the 4-byte method-flip inside its own stack copy of the 0x48-byte request descriptor.

### IRP_MJ_READ (3) - `0x14000128E-0x140001380`

`slot +0x860(FxContext, request, &[RBP-0x59])` retrieves a descriptor (return value checked `JNS @0x1400012B7`), `slot +0x150(FxContext, param_1, ret)` yields a target object, then `slot +0x5D8(FxContext, target, request, 0x2200A0, &[RBP-0x59], 0, &[RBP-0x59], 0)` (`0x1400012FA-0x140001336`) - a forward/re-issue of the request against the lower target with literal tag `0x2200A0`. On failure (`JS`) or on return the request is completed (see completion block below).

### IRP_MJ_WRITE (4) - `0x14000141C-0x1400014A2`

Same shape with `slot +0x858(FxContext, request, &[RBP-0x51])` and `slot +0x5C8(FxContext, target, request, [RBP-0x51], 0, 0)` (`0x140001476-0x14000149F`).

### Common completion path - `FUN_140001514` (only caller: `CALL 0x140001514` @`0x1400014EF`)

`slot +0x7E8(FxContext, request, target, &{0x10, 8 or 2, 0})` returns a boolean; if false, `slot +0x7F0(FxContext, request)` obtains a status which is fed to `slot +0x838(FxContext, request, status)` (`FUN_140001514 @0x140001552-0x140001583`) - completions are framework-side; no raw IRP completion (`IoCompleteRequest`) exists in the image (no import, and no such table call is used here).

**Interpretation (behavior-level):** the binary is a **stack-internal request interceptor for a USB device object**: read/write requests are re-issued to the lower stack target with framework-formatted buffers, USB control codes (device type `0x0022`) are accepted only in four fixed method-IN/METHOD-OUT ranges while their method bits are flipped, and everything else is passed through and completed. There is **no arbitrary-IOCTL handling surface for user mode registered by this image** (no interface GUID, no control device): if user mode can reach the *filtered* device at all, the interception applies, and this analysis of the reachable code shows the filter bound to the numeric rewrite above and nothing more. The reconstruction of slot semantics is inference (each inference is anchored to the cited slot offset and argument shape); the code identity of every number above is direct observation.

---

## 4 Access-control audit

Checked every entry in the image:

| Control | Result | Evidence |
|---|---|---|
| `SeSinglePrivilegeCheck` | **absent** | no `Se*` import; import table (section 1) exhausted at two modules |
| SDDL / security descriptor string | **absent** | full 40-string inventory contains none; `IoCreateDeviceSecure` not imported |
| `IoCreateDevice(Secure)` / `IoCreateSymbolicLink` | **absent** | import table; no `\Device\`, `\DosDevices\` strings |
| Exclusive flag on device | **not settable from this image** | device creation via WDF-table slots only (section 2); neither the attributes block at `0x1400050B3-0x1400050BA` (`1,1` = execution/sync scope-style enum fields, not the exclusive bool semantic) nor slot `+0x1E8(deviceInit,3)` establishes an access descriptor |
| Interface GUID registration | **absent** | no 16-byte GUID-shaped constant in `.data` (0x200 raw bytes fully dumped, remainder zero-init: section 1) or `.rdata` (fully inspected: fids/CFG pointers/strings/import names/debug records only) |
| Caller-identity check on the interception path | **none** | `FUN_140001000` dispatches purely on major/code values (`0x140001061-0x140001423`); no framework call that consumes caller context is used before forwarding/rewrite |
| Manual user-buffer access (raw `SystemBuffer`/`UserBuffer` dereference) | **absent** | no direct IRP access; buffers are handled only as opaque handles returned by slots `+0x858/+0x860` and consumed by framework format/send calls |
| Write-what-where / length smuggling | **absent** | the only memory write in the callback is the 4-byte patch into a local 0x48-byte stack copy (`MOV dword ptr [RBP-0x21], EAX` @`0x140001264`, `0x48` bytes bounded by the `MOVUPSx4 + MOVSD` block at `0x140001232-0x14000126D`); no indexes derived from request data are applied to memory |

**Conclusion of the access-control audit:** within this image there is **no privileged operation and no access gate**: nothing here grants, requires, or bypasses a privilege. The dangerous-if-wrong surface of a filter is its position in an existing stack, not a self-opened door; the door-opening code (device creation) is fully enumerated in section 2 and creates no user-visible handle.

Supply-chain note (same audit standard, shipped-artifact observation): signature is `PKCS_SIGNED_DATA`, leaf subject `$WDKTestCert build,1323032564032789080` (section 1). A test-cert-signed kernel image is not accepted by default production kernel-mode code-signing policy; loading the driver therefore already requires a development/test-signing environment, which is itself an access-control property of the deployment, of the file.

---

## 5 Most dangerous exposed capability

**Single most dangerous statically reachable behavior: the unconditional method-bit rewrite + forward of stack control requests in `FUN_140001000` (section 3).**

- Any request with major 14 arriving at the filtered device whose code falls in `0x220021/25/.../0x22003D`, `0x220042...0x22005E`, `0x220191...0x2201AD`, `0x2201B2...0x2201CE` is accepted *without any caller validation* (section 4) and its `IOCTL_...` method bits are flipped between METHOD_IN_DIRECT and METHOD_OUT_DIRECT before the (descriptor-copied) request is re-issued, at `0x140001264-0x14000127A`; any other major is passed through untouched at `0x1400014AD`.
- Why this ranks highest though it is not a memory-safety defect: it changes *what kernel component consumes the request* - an IN-direct request becomes OUT-direct and vice versa, i.e., it re-selects whether the caller's input buffer is interpreted as in/out MDL - with zero authorization. In a compromised/mis-configured stack this is the one lever this code holds; in a well-formed stack the four code ranges it accepts (device type `0x0022`, FILE_ANY_ACCESS) are kernel-bus-internal ranges (the numeric identity check section 3), so the *practical* exposure is bounded to whoever can legitimately send such codes - which is the device stack itself.
- Not the highest risk because: the rewrite is value-bounded (only 32 accepted codes; the patch writes 4 bytes into its own stack copy), the default path forwards rather than completes-forger-style, and there is no user-mode-opened handle attributable to this file (section 2/section 4).
- Honorable mention, second place: none. Dead functions `FUN_140001620/140001640` contain no guard-free privileged call either (they are descriptor nibble arithmetic, section 1).

---

## 6 VERDICT

**Benign-by-structure, low capability - a small KMDF (v1.15) USB-stack filter/interceptor with no self-created user-mode attack surface.**

- The image is a `FILTER_EXTENSION`-context KMDF filter driver whose entire active logic is: bind KMDF 1.15 (`0x1400010B7`), register `EvtDriverDeviceAdd` (`0x140001765`), create one filtered device object (`0x1400050DB-0x140005114`), attach one request callback (`0x1400050C8`), and in that callback re-forward read/write requests and rewrite METHOD bits of a fixed set (32 exact codes) of `FILE_DEVICE_USB`-type control codes before forwarding (`0x140001064-0x14000127A`).
- No privilege-check API, no security descriptor, no interface GUID, no control device, no user buffer dereference exists in the code (section 4, import-table-bounded).
- Attack surface for a user-mode process: **none from this file alone** (no self-registered interface: section 2). Risk concentrates in **what the filtered stack lets callers reach** through the interception point - the method-bit rewrite of `0x220xxx` codes with no caller validation (section 5) is the single most dangerous exposed capability found, and it is bounded (numeric whitelist + 4-byte self-stack patch) rather than arbitrary.
- Code hygiene: /GS + CFG on, one unused helper function pair (`0x140001620/0x140001640`), all 45 indirect framework call-sites guarded.

**Recommendation (ranking of residual audit gaps, static-only):** none mandatory; if the surrounding deployment context allows loading test-signed kernel images (section 4), that is the gate the auditor should audit separately - **not** this file's runtime behavior, which as statically reconstructed grants nothing.

*All hex/VA values are raw observations of `C:\Users\<scrubbed>\Desktop\driver_candidates\AppleKmdfFilter.sys` (SHA-256 `E044B74FF494725D56B292ACE8D558E315AE406085EE3695D859AD97254897FA`). No web, no runtime, no external knowledge used for behavioral conclusions; slot-offset purposes are labeled as inference where so.*
