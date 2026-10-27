# Audit: RzDev_051a.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\RzDev_051a.sys` |
| Recorded SHA-256 | `154902764b64d5cc08d8e37864b3b029709f7ba53a742cb4ae449417f02eccac` |
| Analysis date | 2026-10-23 |
| Method | Static-only audit via REA/Ghidra |
| Format | PE32+ (AMD64) kernel driver, image base `0x140000000`, ~123 procedures, KMDF (WDFLDR stub binding) |
| In-file metadata | FileDescription `Razer Device Driver`, version `1.0.0.71` (from the binary's own resources; metadata only) |

Conventions: code names are image-relative `FUN_<VA>`; `ctx` = KMDF context object of the enclosing callback; `+0xNNN` after the KMDF API table base (loaded from `[0x1400091e8]`, `FxDriverGlobals` from `[0x1400091e0]`, call form `call qword ptr [RAX + <slot>]`) denotes an established framework API slot. Threat model: unprivileged local user. Evidence IDs from REA preserved where available.

## 1. Internals

- KMDF shim `FUN_140006484` (`ev_113b76c8...`) binds the framework (`WdfVersionBind` / `FxStubBindClasses` / `FxStubInitTypes`) and calls vendor `DriverEntry` `FUN_14000d000` (`ev_b4eb7674...`); PE entry `0x140006458` (`ev_dd390c3b...`).
- Established KMDF slot map (verified per call site): `+0x3a0` WdfDriverCreate; `+0x210` PDO-init device type (value `0x2A` at `0x140003d92`, `0x140005259`); `+0x220` PDO-init SDDL assignment (`DAT_140008380` at `0x140003db4`, `0x140005279`); `+0x290/+0x610/+0x680/+0x690` registry & PDO-init helpers; `+0x4c0` queue create (`0x1400055f5`); `+0x4e8` queue-get-device; `+0x650` context fetch; `+0x628` memory copy helper (exact API name unresolved); `+0x68/+0x9d8` driver-object publication into DRIVER ctx `+0x10/+0x18`; `+0x6a0/+0x6b0/+0x6b8/+0x6c8` PDO-init assign HWID / instance / display name / language `0x409`; `+0x150/+0x7d8/+0x7e8` IoTarget send family; `+0x820` completion-callback install; `+0x838` WdfRequestComplete; `+0x848` completion-notify; `+0x860` retrieve input memory; `+0x868/+0x870` retrieve Input/OutputBuffer; `+0x898` complete-with-information; `+0x8c8` forward-to-queue; `+0x8e8` IRP stack inspection; `+0x9f0` timer create (EvtTimerFunc `FUN_1400035dc`, parent `+0xa08`, tick `FUN_1400022b0`).
- Context type descriptors at `0x140009000`: `CONTROLDEVICE_CONTEXT` 0x678, `DRIVER_CONTEXT` 0x20, `DEVICE_CONTEXT` 0x708, `VIRTUALHIDDEVICE_CONTEXT` 0x30 (virtual-IOCTL context type pointer `PTR_DAT_140009098`).
- Callback vtables in `.rdata`:
  - Driver ctx `0x140008138`: `[0]=FUN_140004474` - allocates 0x38-byte object `{Size 0x38, 1, 1, WdfDriver}`, publishes into DRIVER ctx `+0x10/+0x18` (`ev_d4b3ce3f...`).
  - Device ctx `0x140008148`: `[0]=FUN_140002414` (FDO init), `[1]=FUN_140001e00`, `[2]=FUN_140002ae4` (second queue, cfg `{0x60, dispatch 2, 2, mode byte, cb FUN_14000369c @ +0x30}`) (`ev_94019b11...`), `[3]=FUN_140002c68` (internal WDM dispatch), `[4]=FUN_140002b90`, `[5]=FUN_140003020`, `[6]=FUN_140002fdc`, `[7]=FUN_140002394`, `[8]=FUN_14000342c` (report-pump entry).
  - Control-device ctx `0x140008190`: `[0]=0x140001550`, `[1]=0x14000155c`, `[2]=FUN_140001944`, `[3]=FUN_1400015c8`, `[4]=FUN_140001780` (copies 0x230 bytes of DEVICE ctx), `[5]=0x140001000`, `[6]=FUN_1400018e4`, `[7]=FUN_140001c70`.
- Embedded `.rdata` HID data: class-descriptor heads `09 21 00 01 00 01 22 <wDescriptorLength:2>` at `0x140008288` (len `0x91`), `0x1400082d8` (len `0x3f`, boot-mouse-shaped `05 01 09 02 a1 01 09 01 a1 00 05 09 19 01 29 05...`), `0x140008358` (len `0x19`, consumer); full blobs: gamepad/joystick-shaped `05 01 09 04 a1 01...` at `0x1400081f0`, keyboard-shaped `05 01 09 06 a1 01 75 01 95 08...` behind the `0x140008288` head ("KmdfLibrary" string data follows the consumer table).
- SDDL string `DAT_140008380` (buffer `0x140008390`, len `0x7E`) - see section 4. Registry-name -> capability-bit strings - see section 2.
- Imports benign and minimal: `Rtl*`, `wcsstr`, `IoWMIRegistrationControl`, `MmGetSystemRoutineAddress`, `_vsnwprintf`, WPP, WDFLDR. `MmGetSystemRoutineAddress` resolves only `PsGetVersion`, `WmiTraceMessage`, `WmiQueryTraceInformation`, `EtwRegisterClassicProvider`, `EtwUnregister`. No `Se*`, `Zw*`, `Ob*`, `Mm*`-mapping, `PsSetCreate*`, or token/privilege APIs anywhere. Reads in a non-image overlay region (`0xff00000000...`) returned zeros - treated as absent data.
- Overview evidence: `ev_a09e63d6...`.

## 2. Device & entry chain

```
entry 0x140006458                                        [ev_dd390c3b...]
 \- FUN_140006484   KMDF DriverEntry shim                 [ev_113b76c8...]
     \- FUN_14000d000  vendor DriverEntry                 [ev_b4eb7674...]
         |- WDF +0x3a0 -> WdfDriverCreate
         |    cfg: FUN_14000c06c (cleanup/unload family),
         |         FUN_14000c000 = EvtDriverDeviceAdd      [ev_8aa4356f...]
         \- FUN_1400041dc  device bootstrap                [ev_45f0cb39...]
             (DEVICE_CONTEXT 0x708, ctx vtable PTR_FUN_140008148)
             \- first callback FUN_140002414               [ev_0bf241f8...]
```

`FUN_140002414` (FDO device-add work, `ev_0bf241f8...`):
- Creates the FDO; reads VID/PID from the device hardware registry key (WDF `+0x290/+0x610/+0x680` family).
- Parses registry value names into a capability bitmask at DEVICE ctx `+0x448`:

| Registry value | Bit |
|---|---|
| `ControlDevice` | `0x0001` |
| `DkmMouseDevice` | `0x0008` |
| `DkmKeyDevice` | `0x0010` |
| `MPosMouseDevice` | `0x0020` |
| `DkmJsDevice` | `0x0040` |
| `MouseExDevice` | `0x0080` |
| `ConsumerControlDevice` | `0x0100` |

- Values `Virtual_Kbd_%04X` / `Virtual_Mou_%04X` / `Virtual_Js_%04X` / `Virtual_Con_%04X` (formatted with the VID) spawn child virtual HID PDOs via `FUN_140004f8c` (`ev_6af6e3ba...`) for internal types 1 (mouse), 2 (keyboard), 6 (joystick), 8 (consumer control).

Child PDO enumeration surface:
- Hardware IDs: `RZCONTROL\VID_%04X&PID_%04X&MI_%02X` (control PDO, built by `FUN_140003b0c`, `ev_d52bcd03...`) and `RZVIRTUAL\VID_%04X&PID_%04X&MI_%02X&Col%02X` (virtual PDOs).
- Instance IDs: `RAZER\DeviceContol` (sic - literal spelling in the file), `RAZER\VKBDDevice`, `RAZER\VMOUDevice`, `RAZER\VJSDevice`, `RAZER\VCONDevice`; display name `Razer Control Device`.
- Device type `0x2A` + SDDL stamped on every child PDO at `0x140003d92-0x140003db4` (control) and `0x140005259-0x140005279` (virtual) - section 4.

Queues & timers:
- Primary I/O queue created in `FUN_140004f8c` at `0x1400055f5` (WDF `+0x4c0`), EvtIoDeviceControl `FUN_1400056f0` at cfg+0x30.
- Second queue from `FUN_140002ae4` (dispatch type 2 = sequential; callback `FUN_14000369c`); queue handle kept at DEVICE ctx `+0x10` - target of the `0xB000B` forward.
- When the capability mask satisfies `0x140` (checked in `FUN_140002414`, and as `ctx+0x448 & 0x140` guard in `FUN_140003130`), a WDF timer is registered (`+0x9f0`; EvtTimerFunc `FUN_1400035dc` -> parent `+0xa08` -> tick `FUN_1400022b0`).

## 3. IOCTL table

### 3.1 `FUN_1400056f0` - EvtIoDeviceControl (public PDO queues) `ev_f367e1c3...`

| IoControlCode | Handler | Behavior |
|---|---|---|
| `0xB0003` | `FUN_1400059b4` `ev_94db9edf...` | serves the 9-byte HID **class descriptor** block |
| `0xB0007` | `FUN_140005a70` `ev_e20b2e11...` | serves the full embedded HID **report descriptor** |
| `0xB000B` | inline | forwards the raw user request (WDF `+0x8c8`) to the internal queue at DEVICE ctx `+0x10` |
| `0xB0027` | `FUN_1400058bc` | returns a fixed `0x20`-byte structure; completes with `Information = 0x20` |
| `0xB000F` `0xB0013` `0xB001F` `0xB0023` `0xB002B` `0xB0191` `0xB0192` | inline stubs | success complete, no operation (success path requires `OutputBufferLength > 3`) |
| default | inline | completes with invalid-status constant (`0xC00001BB`) |

Encoding: all `0xB000x` are `FILE_DEVICE_KEYBOARD` (`0x0B`), functions 0-10, **METHOD_NEITHER** (low 2 bits = 3 -> raw user-mode pointers, no framework buffering/probing); `0xB0191`/`0xB0192` are function 100, `METHOD_IN_DIRECT`/`METHOD_OUT_DIRECT`.

Descriptor-serving handlers (context = `VIRTUALHIDDEVICE_CONTEXT`, 0x30 bytes; wiring code `0x140005522-0x14000557c`):
- `FUN_1400059b4` (`0xB0003`): retrieves input memory (`+0x860`), reads byte at `[ctx+0x20]` (HID class-descriptor `bLength` = `0x09`), transfers that many bytes via memory-copy helper `+0x628`, completes with `Information = len` (`+0x898`).
- `FUN_140005a70` (`0xB0007`): same flow with length `WORD [ ([ctx+0x20]) + 7 ]` (HID `wDescriptorLength`) and payload at `[ctx+0x28]`; completes with `Information = len` - hands the caller the entire embedded report descriptor from `.rdata`.

Per-type pointer wiring:

| Child type | ctx+0x20 | ctx+0x28 |
|---|---|---|
| 1 mouse | `0x140008328` | `0x1400082e8` |
| 2 keyboard | `0x1400082d8` | `0x140008298` |
| 6 joystick | `0x140008288` | `0x1400081f0` |
| 8 consumer | `0x140008358` | `0x140008338` |

Caveat: descriptor blobs are adjacent in `.rdata`; a +/-few-byte overlap between neighboring blobs could not be fully excluded, and some ctx+0x20/0x28 pairs do not match their child-type labels (e.g., `0x1400082d8` carries a mouse-shaped descriptor while the keyboard child references it). The handler semantics (byte at +0, word at +7) were fully confirmed in disassembly; this does not change the security conclusions.

### 3.2 `FUN_140002c68` - internal/WDM device control (DEVICE ctx vtable `[3]`, code `0x140008160`) `ev_8a270aa2...`

| IoControlCode | Handler | Notes |
|---|---|---|
| `0xB000B` | `FUN_140003130` `ev_1c76c0da...` | guarded forward (`+0x8c8`); guards ctx+8, ctx+0x20, `ctx+0x448 & 0x140`, request handle, optional `+0x9f8` state; forward failure -> complete |
| `0xB000F` `0xB0203` | stubs | complete |
| `0xB0403` | `FUN_1400034c8` | secondary handler |
| `0xF0203` | `FUN_140001f24` `ev_edcabbe2...` | **arming path**; requires `InputBufferLength > 0x10` |
| `0xF0403` | `FUN_140001eb0` | secondary handler |
| `0x220003` | inline | completion-callback feed path (below); `FILE_DEVICE_UNKNOWN` fn 0, METHOD_NEITHER |
| default | inline | complete via `+0x838` |

- `FUN_140001f24`: swaps a 16-byte payload pair into `ctx+0x478/0x480` and `ctx+0x558/0x560`, installs handler `FUN_14000218c`, sets mode bit `ctx+0x448 |= 2` - arms the synthetic-HID feed state.
- `0x220003` branch: inspects the request IRP stack (`+0x8e8`, checks `*(int16_t*)(x+2) == 9`), installs completion callback `FUN_140003260` (`+0x820`), sends down the IoTarget (`+0x150`/`+0x7e8`) or completes directly.
- `FUN_140003260` `ev_09ddfc49...`: completes the held request (`+0x848`) and invokes DEVICE ctx vtable `[8]` = `FUN_14000342c` with captured report parameters.
- `FUN_14000342c` `ev_9f141469...`: gated only by capability bit `0x8` (`DkmMouseDevice`); calls the registered mouse-report pump `[ctx+0x580](ctx+0x578, ...)`.

Net effect: a driver-internal feed/inject chain - request -> completion callback `FUN_140003260` -> `FUN_14000342c` -> `[ctx+0x580]` pump - whose only gates are driver-internal state (armed via `FUN_140001f24`, gated by bits `0x8`, `ctx+0x448 & 0x140`, mode bit `0x2`) and possession of a device handle. No requestor-mode, token, or privilege check exists on any leg.

## 4. Access-control audit

- Single hardcoded SDDL string: `DAT_140008380` (buffer `0x140008390`, len `0x7E` = 63 wchars, matching the exact text length).

  `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)`

| SDDL | Principal | Rights |
|---|---|---|
| `(A;;GA;;;SY)` | SYSTEM | Generic All |
| `(A;;GRGWGX;;;BA)` | BUILTIN\Administrators | Generic Read/Write/Execute |
| `(A;;GRGWGX;;;WD)` | **Everyone** | **Generic Read/Write/Execute** |
| `(A;;GRGWGX;;;RC)` | Restricted Code | Generic Read/Write/Execute |

`D:P` = protected DACL (no inherited ACEs) - it hardens inheritance, it does not restrict the explicit grant.

- Applied at PDO-init sites: device type `0x2A` + SDDL via WDF `+0x210`/`+0x220` at `0x140003d92-0x140003db4` (control PDO, `FUN_140003b0c`) and `0x140005259-0x140005279` (virtual PDOs, `FUN_140004f8c`).
- Findings:
  1. **Every device the driver installs grants Everyone read/write/execute** - any local process can open `RZCONTROL\*` / `RZVIRTUAL\*` device objects and issue every IOCTL in section 3, unconditionally (static SDDL, regardless of VID/PID or capability configuration).
  2. **No compensating controls**: exactly one SDDL-like string in the image; no `Se*`, `Zw*`, `Ob*` references; no requestor-mode validation, caller-identity check, token check, or admin-gate bit anywhere in either dispatch table or the pump chain.
  3. The Everyone grant is consistent with un-elevated vendor companion software as the intended caller - but it converts "requires elevation" into "requires an open handle", which any local user satisfies.

## 5. Most dangerous exposed capability

**Unprivileged user-mode control of a kernel synthetic-HID input-injection feed.** Verified chain:

1. An unprivileged process opens a `RZCONTROL\...` / `RZVIRTUAL\...` PDO (Everyone GR|GW|GX, section 4) - no elevation or privilege needed.
2. `FUN_1400056f0` `0xB000B` (METHOD_NEITHER) re-queues the raw user request into the driver's internal queue (ctx+0x10) via `FUN_140003130`'s guarded forward - user requests leave the public IOCTL plane and enter the internal device-control plane (`ev_1c76c0da...`).
3. The internal plane arms feed state: `FUN_140001f24` (`0xF0203`, needs only `InputBufferLength > 0x10`, writes 16-byte payload pairs to ctx+0x478/0x480 and ctx+0x558/0x560, sets `ctx+0x448 |= 2`, `ev_edcabbe2...`), and the `0x220003` branch installs the completion-callback route -> `FUN_140003260` (`ev_09ddfc49...`).
4. On completion: `FUN_140003260` -> `FUN_14000342c` (gated only by driver-internal bit `0x8`, `ev_9f141469...`) -> `[ctx+0x580](ctx+0x578, ...)` mouse-report pump - report material flows into the virtual HID stack the driver itself enumerates (section 2/section 3.1).
5. The data-bearing `0xB0003`/`0xB0007` IOCTLs deliver fixed `.rdata` HID descriptors - the injection stack's user-facing protocol scaffolding.

Severity qualification: input synthesized at kernel level via virtual HID collections is system-level HID input and is not subject to user-mode input-integrity restrictions (e.g., UIPI); an unprivileged local user driving this feed yields trusted-input synthesis gated only by driver-internal configuration state, not caller authorization. Conversely, no memory-corruption primitive was identified: no `MmMap*`/`ZwMapViewOfSection`, no unchecked pool-boundary copy in the audited handlers (fixed-descriptor delivery only, `OutputBufferLength > 3` gating), and no privilege/token manipulation. The METHOD_NEITHER IOCTL class is a latent memory-safety surface on any future handler change, but was not abused in this build.

## 6. VERDICT

**VERDICT: HIGH - capability exposure.** An Everyone-accessible virtual-HID input-injection stack: unprivileged handles are sufficient, requests can be re-queued into the driver's internal plane (`0xB000B`), and a completion-callback -> report-pump chain (`FUN_140003260 -> FUN_14000342c -> [ctx+0x580]`) synthesizes HID input gated only by driver-internal state. Not a memory-corruption or backdoor verdict: no `Se*`/`Zw*`/`Mm*` primitives, no privilege manipulation, and imports are benign (section 1).

Key exposure facts:
- Static unconditional SDDL `D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)` on every child PDO (`0x140003db4`, `0x140005279`).
- Public `METHOD_NEITHER` IOCTL plane (section 3.1) + `0xB000B` re-queue; internal codes `0xF0203`/`0x220003` arm and route the injection feed (section 3.2).
- HID report descriptors for mouse/keyboard/joystick/consumer collections embedded in `.rdata` and served to user callers.

Defender recommendations (derived from static analysis): treat device opens on `RZCONTROL\*` / `RZVIRTUAL\*` and IOCTLs `0xB000B`/`0xF0203`/`0x220003` as injection-path telemetry; replace the Everyone grant (or add an authorization gate to the arm/inject path) where remediation is possible; re-audit the METHOD_NEITHER handlers on any change.

## Scope & limitations

Static-only, single-image analysis; nothing was executed and no runtime state was observed. Exact KMDF API names behind the pointer-table slots are approximate where noted. No web or external resources were consulted; all conclusions derive from the disassembly and embedded data of this binary. Evidence IDs refer to REA session artifacts recorded 2026-10-23.
