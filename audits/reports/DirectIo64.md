# Audit: DirectIo64.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\_collected5\agentR4\new\DirectIo64_BD9D1B3C.sys` |
| SHA-256 | `BD9D1B3C4DB55CC5A811F632D2D6F032328079DA3AD29567246883808310A7DB` |
| Analysis date | 2026-10-24 |
| Method | Static-only audit via REA/Ghidra (Ghidra 12.1.4), cross-checked with `llvm-objdump` disassembly of the exact file |
| Reach tier | R2 — local administrator |
| Setup required | none (driver load; default admin-only DACL + RSA challenge) |
| Write quality | W3P - physical-memory mapping/write; no arbitrary kernel VA |
| Verdict | **MW3** - reach=R2 setup=none write=W3P load=signed (admin physical-memory/kernel-write toolbox; not a proven unprivileged LPE) |

All addresses below are virtual addresses with image base `0x140000000` (RVA = VA − `0x140000000`). REA evidence IDs were accepted only when the evidence record's subject SHA-256 matched the file above.

---

## 1. Internals

**Binary identity.** PE32+ x86-64 kernel driver, 59,096 bytes, image base `0x140000000`, entry point `0x14000E000` (RVA `0xE000`). Sections: `.text` `0x140001000`–`0x140006B0C`, `fothk` (IAT) `0x140007000`, `.rdata` `0x140008000`–`0x140009364`, `.data` `0x14000A000`, `.pdata` `0x14000B000`, `PAGE` `0x14000C000`–`0x14000DD28`, `INIT` `0x14000E000`–`0x14000ED56`, `.rsrc`, `.reloc`. 206 procedures were recovered (`ev_b5b798b5fa0530029b1722058b6c10d09aa9baa3359b74f0b6f3b780dfc9e90e`; overview `ev_533b960b68ae4339b6a60f577a93dbefe51533948c6a2330375fa1fd0e290dd1`).

**Provenance.** Version resource: CompanyName `PassMark Software`, FileDescription `DirectIo Driver`, FileVersion/ProductVersion `17.0.1001.0`, OriginalFilename `DirectIo.sys`. Debug path: `F:\Source Code\DirectIO-Driver\x64\Release\debug64\DirectIo64.pdb`. PE timestamp `2026-06-25 18:55:45`. Authenticode status **Valid**; signer `CN=Microsoft Windows Hardware Compatibility Publisher` (WHCP attestation), timestamped by Microsoft. The vendor is PassMark, but the direct signer is Microsoft WHCP.

**Relevant imports** (IAT at `0x140008000`, import descriptor RVA `0xE090`): `MmMapIoSpace`, `MmUnmapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmUnmapLockedPages`, `IoAllocateMdl`, `MmBuildMdlForNonPagedPool`, `IoFreeMdl`, `ZwOpenSection`, `ZwMapViewOfSection`, `ZwUnmapViewOfSection`, `ZwCreateFile`, `HalGetBusDataByOffset`, `HalSetBusDataByOffset`, `KeStackAttachProcess`, `ObReferenceObjectByHandle`, `ProbeForWrite`, and the `BCrypt*` API set. There is **no** `MmCopyVirtualMemory`, `MmCopyMemory`, `SeAccessCheck`, `SeSinglePrivilegeCheck`, or `SeTokenIsAdmin` import.

**Recovered strings** (`ev_ccdc6b644b56be6a5a6b6d240619b90273fb4a6ea71463ec303c952d980c4470`): `\Device\PhysicalMemory` `0x1400063B0`, `DIRECTIOLPT` `0x1400064B0`, `\DosDevices\LoopLpt` `0x140006590`, `\Device\LoopLpt` `0x1400066C0`, `\Device\ParallelPort` `0x140006730`, `SHA256` `0x140006AB0`, `RSAPUBLICBLOB` `0x140006AF0`. The SDDL at `0x1400086C0` is a wide string not returned by REA's defined-string inventory; it was recovered from the mapped `.rdata` bytes and is referenced as a `UNICODE_STRING` at `0x1400086F8` by DriverEntry.

---

## 2. Entry, device creation, dispatch

**DriverEntry = `0x1400026C4`** (`ev_8a940b95c8e88514fe73793c047f74740422f60a836f497b96947e08627469fe`; analysis `ev_7dc9d98cf37c5da936927aab02923fd887fcbabecfe384aa6c118160c1f43403`).

1. Allocates a 0x200-byte pool buffer tagged `'RIgl'` and derives the service name from `RegistryPath->Buffer` (`param_2 + 8`) by taking the substring after the last `\` (`wcsrchr`, loop at `0x140002767`–`0x1400027BE`).
2. Formats `\Device\%ws` (`0x1400027C1`–`0x1400027DB`, format string `0x140006270`) and `\DosDevices\%ws` (`0x140002861`–`0x1400028A2`, format string `0x1400062E0`).
3. Calls the `WdmlibIoCreateDeviceSecure` wrapper at **`0x14000C120`** with:
   - `DeviceExtensionSize = 0`
   - `DeviceName = &local_450` (`\Device\<ServiceName>`)
   - `DeviceType = 0x8011`
   - `DeviceCharacteristics = 0x100` (`FILE_DEVICE_SECURE_OPEN`)
   - `Exclusive = 0`
   - `DefaultSDDLString = &DAT_1400086F8` → wide string at `0x1400086C0`: **`D:P(A;;GA;;;SY)(A;;GA;;;BA)`**
   - `DeviceClassGuid = &DAT_140008510`

   The call site is `0x1400027FF`–`0x140002829`; failure is logged with `DIRECTIO ERROR: IoCreateDevice failed` (`0x140006290`).
4. Installs the dispatch table on the driver object: `MajorFunction[IRP_MJ_CREATE]` (`+0x70`), `[IRP_MJ_CLOSE]` (`+0x80`), and `[IRP_MJ_DEVICE_CONTROL]` (`+0xE0`) all point to **`0x140001470`**; `DriverUnload` (`+0x68`) points to **`0x1400023B0`** (`0x140002861`–`0x140002892`).
5. Creates the symbolic link `\DosDevices\<ServiceName>` → `\Device\<ServiceName>` with `IoCreateSymbolicLink` at `0x1400028AE`.
6. Calls **`0x1400036BC`** (LoopCreateDevice) with `(DriverObject, 1)` at `0x1400028DE`.

**LoopCreateDevice = `0x1400036BC`** (`ev_5e7c4759413b70835a62d1d1e732dbf99fac347c34024c7d6c00bb25e5686dec`; analysis `ev_04d22961ab6b3bf95423bd0d0c9438004e4b7b348e75af95feffd45515adf585`).

- Opens `\REGISTRY\MACHINE\SYSTEM\CURRENTCONTROLSET\SERVICES\<ServiceName>` and reads the `REG_DWORD` value **`DIRECTIOLPT`** (`0x1400064B0`); accepts only 1–0x100, otherwise logs `DIRECTIO ERROR: Load LPTNumber INVALID` (`0x140006610`) and returns `0xC000000D`.
- Builds `\Device\LoopLpt<N>` by appending the decimal LPT number (`0x14000387B`–`0x1400038D4`).
- Creates it with **plain `IoCreateDevice`** at `0x140003904`: `DeviceExtensionSize = 0x48`, `DeviceType = 0x16`, `Characteristics = 0`, `Exclusive = TRUE`. **No SDDL and no `ZwSetSecurityObject` call are applied to this device.**
- Opens `\Device\ParallelPort<N-1>` with `IoGetDeviceObjectPointer` (`0x1400039AB`), references it with `ObReferenceObjectByPointer` (`0x1400039ED`), and attaches with `IoAttachDeviceToDeviceStack` (`0x140003A0E` → `0x140008120`).
- Sends a fixed IOCTL **`0x160030`** to the parallel-port stack via `IoBuildDeviceIoControlRequest`/`IofCallDriver` inside **`0x140003B14`** (`0x140003B5D`, `0x140003BB7`) and stores the 0x38-byte response fields in the LoopLpt extension at `+0x18`, `+0x20`, `+0x28`, `+0x30`, `+0x38`, `+0x40` (`0x140003C1A`–`0x140003C45`). These fields include two function pointers used by IOCTLs 0x80116054 / 0x80116058.
- Creates `\DosDevices\LoopLpt<N>` at `0x140003A73`.

**Create/close handling.** On `IRP_MJ_CREATE` (`0x140002329`) the dispatcher allocates a 0x22-byte `'Pass'` pool block, zeroes it, and stores it at `FileObject->FsContext` (`0x14000235F`–`0x140002363`). On `IRP_MJ_CLOSE` (`0x140002302`) it zeroes and frees that block. On device control, `FsContext == NULL` returns `0xC0000008` (`0x140001502`), and `FsContext[1]` is the per-handle “authenticated” flag.

**Correction to the supplied triage:** this driver **opens and attaches to** `\Device\ParallelPort<N-1>`; it does **not** create it. It creates `\Device\<ServiceName>` (SDDL-protected) and `\Device\LoopLpt<N>` (plain `IoCreateDevice`).

---

## 3. IOCTL table

All IOCTLs use `DeviceType = 0x8011` and **METHOD_BUFFERED** (low two bits of every code are 0). Access is `FILE_WRITE_ACCESS` when bits 14–15 are 1, and `FILE_READ_ACCESS|FILE_WRITE_ACCESS` when they are 3. Function = `(code >> 2) & 0xFFF`.

Gate legend: **A** = requires `FsContext[1] != 0` (RSA session unlocked); **M** = requires a valid 16-byte MD5 tag over the request; **N** = none. “Silent no-op” means that if **A** is not satisfied the handler jumps to the completion path with `STATUS_SUCCESS` and performs no action.

| IOCTL | Fn | Access | Method | In / Out | Handler | Kernel action | Gate |
|---|---|---|---|---|---|---|---|
| `0x80116054` | 0x815 | WRITE | BUFFERED | 0 / 0 | `0x1400016E6` | Calls `(*(ext+0x40))(*(ext+0x38))` on the LoopLpt extension; returns `0xC0000055` if the callback returns 0. Only meaningful on `\Device\LoopLpt<N>`. | N |
| `0x80116058` | 0x816 | WRITE | BUFFERED | 0 / 0 | `0x1400016C3` | Calls `(*(ext+0x30))(*(ext+0x38))`; no return-value check. Only meaningful on LoopLpt. | N |
| `0x8011605C` | 0x817 | WRITE | BUFFERED | 0 / 0 | `0x14000155D` | No-op; completes success. | N |
| `0x80116078` | 0x81E | WRITE | BUFFERED | 0 / 8 | `0x140001693` | Writes the 8-byte constant `0x0000000003E90011` to `SystemBuffer`, `Information = 8`. | N |
| `0x8011607C` | 0x81F | WRITE | BUFFERED | 0 / 8 | `0x1400015E8` | `ZwOpenSection(L"\Device\PhysicalMemory", SECTION_MAP_READ=4, OBJ_CASE_INSENSITIVE)` at `0x140001661`; returns the section handle in `SystemBuffer`, `Information = 8`. Read-only physical-memory mapping capability. | A |
| `0x8011E044` | 0x811 | RW | BUFFERED | 0x3D / 0x3D | `0x14000158D` → `0x140003CE4` | Maps a caller-chosen physical address/size into the calling process; returns a user VA at struct `+0x24`. See §5 for exact paths and constraints. | A+M |
| `0x8011E048` | 0x812 | RW | BUFFERED | 0x3D / 0 | `0x140001717` → `0x1400042C0` | Unmaps a prior mapping: if `struct[0] != 0` → `ZwUnmapViewOfSection(CurrentProcess, struct+0x24)`; else `MmUnmapLockedPages(struct+0x24, MDL)`, `IoFreeMdl`, `MmUnmapIoSpace(struct+8, size)` (`0x1400042C0`–`0x140004316`). | A+M |
| `0x8011E04C` | 0x813 | RW | BUFFERED | 0x17 / 0 | `0x140001917` | **`out dx, al/ax/eax`** to a caller-chosen I/O port; width selector at `+0x6` is 1/2/3; value at `+0x2` (`0x14000196C`–`0x1400019A8`). | A+M |
| `0x8011E050` | 0x814 | RW | BUFFERED | 0x17 / 0x17 | `0x140001873` | **`in al/ax/eax, dx`** from a caller-chosen I/O port; returns the value at `+0x2` (`0x1400018C7`–`0x1400018F4`). | A+M |
| `0x8011E060` | 0x818 | RW | BUFFERED | 4 / 8 | `0x14000181D` | **`rdmsr`** on a caller-chosen MSR; explicitly rejects `0xC0000082` (LSTAR) and `0x176` (SYSENTER_EIP) (`0x140001843`–`0x14000185B`). | A |
| `0x8011E064` | 0x819 | RW | BUFFERED | 4 / 8 | `0x1400017E4` | **`rdpmc`** on a caller-chosen performance counter (`0x14000180A`). | A |
| `0x8011E074` | 0x81D | RW | BUFFERED | 4 / 0 | `0x1400017A0` | **`wrmsr`** with value 0, but only for MSR `0xE7` or `0xE8` (`0x1400017C6`–`0x1400017DB`). | A |
| `0x8011E080` | 0x820 | RW | BUFFERED | ≤0x7FFF wide string / 0 | `0x1400019AD` → `0x1400029E0` | Treats the input as a wide file path (`ObjectName` for `ZwCreateFile`, `0x140002A5D`–`0x140002A74`) and writes a system/hardware information blob (NtBuildNumber, process/CPU/debugger state, physical-memory ranges) to that file via `ZwWriteFile` (`0x140002D69`, `0x140002F00`, `0x140002F27`). Admin file write; no kernel memory write. | A |
| `0x8011E084` | 0x821 | RW | BUFFERED | ≤0x7FFF wide string / 0 | `0x140001DBB` → `0x140002FB0` | Opens the caller-supplied path with `ZwCreateFile` (`DesiredAccess=0x100002`), opens `\Device\PhysicalMemory` (`SECTION_MAP_READ`), walks `MmGetPhysicalMemoryRanges`, maps/reads physical ranges, and writes the dump to the named file (`ZwWriteFile` at `0x1400031D8`–`0x1400032EC`). Physical-memory **read/dump** path. | A |
| `0x8011E088` | 0x822 | RW | BUFFERED | 0x1C / 8 | `0x140001D36` | **`wrmsr` then `rdmsr`** for MSRs limited to `{0x38F, 0x38D, 0x199, 0x1A0, 0xC0010015}` (`0x140001D70`–`0x140001DB6`); 64-bit value at `+0x4`. | A+M |
| `0x8011E08C` | 0x823 | RW | BUFFERED | 0x24 / 0x24 | `0x140001C29` | PCI configuration access through `\Driver\PCI`: `ObReferenceObjectByName("\Driver\PCI")` and device enumeration in `0x1400034E0`, bus interface fetch in `0x1400033F0`, 4-byte access via `0x140004324`; echoes the 0x24 request/response block. | A+M |
| `0x8011E090` | 0x824 | RW | BUFFERED | 0x24 / 0 | `0x140001B67` | Same `\Driver\PCI` path and `0x140004324` call; no block echoed back. | A+M |
| `0x8011E094` | 0x825 | RW | BUFFERED | 0x2C / 0x2C | `0x140001A61` | AMD SMU/PM-table access (strings `smuGetBaseAddress`, `mapPmTables`, `smuPollPmTables`); uses the PCI bus interface and returns table data. | A+M |
| `0x8011E09C` | 0x827 | RW | BUFFERED | 0x38 / 0 | `0x140001DF2` | `ObReferenceObjectByHandle(handle, PsProcessType, RequestorMode)` → `KeStackAttachProcess` → reference a second handle → `ObQueryNameString` via `0x140004154`; writes a 4-byte status to a caller pointer after **`ProbeForWrite`** at `0x140002004`. Target `PsInitialSystemProcess` is explicitly poisoned (`or r14, 0xFFFFFFFF80000000` at `0x140001E83`) so the system process cannot be queried. | A+M |
| `0x8011E0A0` | 0x828 | RW | BUFFERED | 0x19 / 0 | `0x1400022B2` → `0x140002948` | **Kernel-mode physical bit-clear:** validates `phys != 0` and `phys < 2^48`, `bit < 4`; `MmMapIoSpace(phys & ~0xFFF, 0x1000, 0)`, read dword at `phys & 0xFFF`, clear `1 << bit` if set, write dword back, `MmUnmapIoSpace` (`0x140002948`–`0x1400029BF`). True kernel write (one bit). | A+M |
| `0x8011E0A4` | 0x829 | RW | BUFFERED | 0x24 / 0x24 | `0x1400021FD` | **`HalGetBusDataByOffset(PCIConfiguration, bus, devfn, buffer, offset, 4)`** — PCI config read; copies the 0x24 block back. | A+M |
| `0x8011E0A8` | 0x82A | RW | BUFFERED | 0x24 / 0 | `0x140002169` | **`HalSetBusDataByOffset(PCIConfiguration, bus, devfn, buffer, offset, 4)`** — PCI config write. | A+M |
| `0x8011E0AC` | 0x82B | RW | BUFFERED | 0 / 0x20 | `0x14000211C` | `BCryptGenRandom(NULL, FsContext+2, 0x20, BCRYPT_USE_SYSTEM_PREFERRED_RNG)`, sets `FsContext[0]=1, FsContext[1]=0`, returns the 32-byte nonce. | N |
| `0x8011E0B0` | 0x82C | RW | BUFFERED | 0x20C / 0 | `0x140002093` → `0x140004888` | **Challenge-response unlock:** requires `FsContext[0] != 0`; input magic `'DIAG'`, version 1, signature length 1–0x200; verifies RSA-2048 PKCS#1 v1.5 over `SHA256(prefix‖nonce)` with the embedded public key at `0x140008530`; on success sets `FsContext[0]=0, FsContext[1]=1` (`0x140002093`–`0x140002164`). | nonce state |

**Input validation.** Fixed-size handlers compare `InputBufferLength` exactly (`0x3D`, `0x24`, `0x2C`, `0x38`, `0x19`, `0x17`, `0x1C`, `4`, `0x20C`). The two string handlers only bound the input at `0x7FFF`. `OutputBufferLength` is explicitly checked only for `0x80116078` (`==8`), `0x8011607C` (`==8`), and `0x8011E0AC` (`==0x20`). The remaining handlers rely on METHOD_BUFFERED's `SystemBuffer` being `max(InputBufferLength, OutputBufferLength)` and write at most the same fixed record length they accepted on input; `Information` is set to that record length. `ProbeForWrite` is used only in the `0x8011E09C` status write.

Read-only side finding: `0x8011E080` and `0x8011E084` call `RtlInitUnicodeString` directly on the buffered input (`0x1400019CC` and `0x140001DDA`) without verifying that a NUL WCHAR exists within `InputBufferLength`. A non-terminated string can cause a bounded pool over-read until the first NUL WCHAR. This is an information-read/DoS issue, not a write primitive.

---

## 4. Access-control audit

### 4.1 Device DACL (the primary gate)

The main device is created with `IoCreateDeviceSecure` and the explicit SDDL

```
D:P(A;;GA;;;SY)(A;;GA;;;BA)
```

at `0x1400086C0`, passed as a `UNICODE_STRING` at `0x1400086F8` (`0x1400027FF`–`0x140002829`). `P` = protected DACL; `GA` = `GENERIC_ALL`; `SY` = `NT AUTHORITY\SYSTEM`; `BA` = `BUILTIN\Administrators`. There is no `WD`/`AU`/`BU` ACE. Combined with `FILE_DEVICE_SECURE_OPEN` (`0x100`), the device is openable only by SYSTEM and members of the local Administrators group. **The requester's local-admin context satisfies this gate.**

The symbolic link is `\DosDevices\<ServiceName>` → `\Device\<ServiceName>`, so the user-mode path is `\\.\<ServiceName>`. The actual service name is not in the binary; it is derived at load time from the `DriverEntry` `RegistryPath` (the service key) by taking the substring after the last backslash (`0x140002767`–`0x1400027BE`), e.g. `DirectIo64` or `DirectIo`.

### 4.2 The `\Device\LoopLpt<N>` caveat

`0x1400036BC` creates `\Device\LoopLpt<N>` with **plain `IoCreateDevice`** (`0x140003904`), extension 0x48, DeviceType 0x16, no SDDL, and no subsequent `ZwSetSecurityObject`. `IoCreateDevice` does not accept a security descriptor; the resulting DACL is the I/O manager's default device-object DACL. This audit could not prove that default statically. The triage's “SYSTEM+Administrators” DACL is the explicit SDDL of the main device, **not necessarily** the LoopLpt device.

Why this matters: the LoopLpt device shares the same driver-object dispatch table (`0x140001470`). If its default DACL is permissive, a non-admin can open `\\.\LoopLpt<N>` and reach the IOCTLs. The no-auth IOCTLs (`0x80116054`, `0x80116058`, `0x8011605C`, `0x80116078`) are then reachable, but they are only LPT extension callbacks, a no-op, and a constant return. The memory-write primitives remain behind the RSA session gate (§4.3). A non-admin would therefore still need the RSA private key; if that key is readable from the user-mode companion, the LoopLpt DACL becomes the difference between an admin-only tool and a local privilege-escalation path. **Dynamic DACL inspection of `\Device\LoopLpt<N>` is required to settle this.**

### 4.3 RSA challenge-response session gate

Every dangerous IOCTL except the nonce request (`0x82B`) and the unlock request (`0x82C`) checks `FsContext[1] != 0`. The state machine is:

1. **`0x8011E0AC`** (`0x14000211C`): `BCryptGenRandom` 32 bytes into `FsContext+2`; sets `FsContext[0]=1`, `FsContext[1]=0`; returns the nonce.
2. **`0x8011E0B0`** (`0x140002093`): requires `FsContext[0]!=0`, input length `0x20C`, magic `'DIAG'` (`0x47414944`), version 1, signature length 1–0x200. Calls **`0x140004888`** (`ev_2380b41d251018e33998745bd874882882867fba548ccc76510e44827dea548e`):
   - builds `0x5797B34A2282AFDC ‖ nonce` (40 bytes);
   - `FUN_14000473C` computes SHA-256 (`BCryptOpenAlgorithmProvider("SHA256")`, `BCryptCreateHash`/`HashData`/`FinishHash`, 32-byte digest; `0x14000473C`);
   - `BCryptOpenAlgorithmProvider("RSA", …, 1)`, `BCryptImportKeyPair(…, "RSAPUBLICBLOB", …, key blob at 0x140008530, 0x11B, 0)`;
   - `BCryptVerifySignature(key, "SHA256", digest, 0x20, signature, sigLen, BCRYPT_PAD_PKCS1=2)`.
   The key blob at `0x140008530` is a `BCRYPT_RSAKEY_BLOB`: magic `RSA1`, 2048 bits, public exponent 3 bytes (`0x010001` = 65537), modulus 256 bytes. On success the handler sets `FsContext[0]=0, FsContext[1]=1` and zeroes the nonce.
3. No `SeSinglePrivilegeCheck`, `SeAccessCheck`, or token inspection is present anywhere in the driver. The session state is per-file-object, not per-process or per-token.

**Strength:** this is a real cryptographic challenge-response, not a fixed password. The private key is not in the driver; it must be held by the user-mode PassMark component that signs the fresh nonce. **Weakness:** the verifier and the public key ship in the driver, and the signer/private key must ship in user-mode software on the same machine. A local administrator can read that software and extract the key; the gate is therefore defeatable by the stated attacker. It does stop blind/casual IOCTL fuzzing and non-admin attackers without the companion app.

### 4.4 Per-request MD5 tags

The memory/PCI/port/MSR-list IOCTLs additionally verify a 16-byte tag computed as `MD5(fixed_prefix ‖ request_fields)` using the driver's own MD5 implementation at **`0x140005500`** (`ev_6d9c827c02c1f08d7fb5b3b10546a05f35ed53406cb2b104f99a97bcbee18465`; MD5 init constants `0x67452301/0xEFCDAB89/0x98BADCFE/0x10325476` at `0x140005634`). Representative checker `0x14000109C` hashes 0x35 bytes with prefix `0xD2EA5CCDFC18499B` and compares the 16-byte digest at struct `+0x2D` (`ev_f92a2d5b05047009825492fed00bc47d42cd5f507386c0236581eeab62a6ac50`). The prefixes are constants in `.text`; the tags are therefore **computable by anyone with the driver file**. They are an integrity/anti-tamper check, not authentication.

The checked prefixes/lengths are: `0x0928B9188C780BFE`/0x11 (tag `+9`), `0xD2EA5CCDFC18499B`/0x35 (tag `+0x2D`), `0x12BE5859B2F5A285`/0x1C (tag `+0x14`), `0x1E20E56B9F105EC8`/0xF (tag `+7`), `0x691F66500B8F0C21`/0x30 (tag `+0x28`), `0xE2C45DD843DD4684`/0x24 (tag `+0x1C`), `0x81E365EEC2338021`/0x14 (tag `+0xC`). A failed tag returns `0xC0000022`; a failed session check silently returns success without acting.

### 4.5 Summary of the gate

| Layer | Applies to | Attacker cost |
|---|---|---|
| Admin-only SDDL on `\Device\<ServiceName>` | all IOCTLs on the main device | already satisfied by “local administrator” |
| Default DACL on `\Device\LoopLpt<N>` | all IOCTLs on LoopLpt | unknown statically; may be admin-only |
| RSA-2048 challenge-response (`0x82B`/`0x82C`) | all memory/port/MSR/PCI primitives | extract private key from user-mode companion |
| MD5 request tags | memory/PCI/port/MSR-list primitives | recompute from driver constants |
| No `Se*` privilege check | everything | none |

For the stated reach (local administrator), the only gate not already satisfied is the RSA session; it is defeatable if the companion app is present. The driver should be treated as an **admin-accessible physical-memory/port-I/O toolbox**, not as a security boundary against administrators.

---

## 5. Most dangerous exposed capability

### 5.1 Primary: user mapping of caller-chosen physical memory — `0x8011E044` + `0x8011E048`

**Path:** `IRP_MJ_DEVICE_CONTROL` `0x140001470` → case `0x8011E044` at `0x14000158D` → `memcpy` of the 0x3D request to the stack (`0x1400015B0`) → **`0x140003CE4`** (`ev_750827bebb9e9832d741049670ece2531f5b3aa6b293c07d2530177d79b540c3`) → `memcpy` of the 0x3D response back to `SystemBuffer` and `Information = 0x3D` (`0x1400015DA`).

**Request layout (0x3D bytes):**

| Offset | Size | Meaning |
|---|---|---|
| `+0x00` | 8 | section handle (output; 0 in MDL fallback) |
| `+0x08` | 8 | kernel VA from `MmMapIoSpace` (fallback only) |
| `+0x10` | 8 | MDL pointer (fallback only) |
| `+0x18` | 4 | size |
| `+0x1C` | 8 | physical address (input) |
| `+0x24` | 8 | **user VA of the mapping (output)** |
| `+0x2C` | 1 | mode flag |
| `+0x2D` | 16 | MD5 tag |

**Mode flag semantics (important):**

- **`flag != 0` (RW path):** size must be exactly `0x1000`. The driver first calls `MmMapIoSpace(phys, 0x1000, 0)`, reads the first DWORD, and accepts only vendor ID `0x8086` (Intel) or `0x1022` (AMD); otherwise `0xC0000022` (`0x140003D11`–`0x140003D6D`). It then opens `\Device\PhysicalMemory` with access `6` (`SECTION_MAP_READ|SECTION_MAP_WRITE`) and maps with `Protect = 0x204` (`PAGE_READWRITE|PAGE_NOCACHE`) at `0x140003DD4`/`0x140003E87`. This yields a **4 KB user-writable mapping of a caller-chosen physical page**; beyond the RSA/MD5 gates, the only additional constraint is the first-DWORD vendor-ID check.
- **`flag == 0` (RO path):** no size or vendor check; opens the section with access `4` (`SECTION_MAP_READ`) and maps with `Protect = 0x202` (`PAGE_READONLY|PAGE_NOCACHE`). This yields an **arbitrary-address, arbitrary-size user-readable mapping of physical memory**, with no vendor check.
- **Fallback (both modes):** if `ZwMapViewOfSection` fails with a status other than `0xC000001F`, the driver calls `MmMapIoSpace(phys, size, 0)` → `IoAllocateMdl` → `MmBuildMdlForNonPagedPool` → **`MmMapLockedPagesSpecifyCache(Mdl, UserMode, 0, NULL, FALSE, 16)`** at `0x140003EF7`–`0x140003F72`, storing the user VA at `+0x24`. This fallback has no vendor-ID check and maps the caller's full size. It is a plausible route to a user-writable mapping that bypasses the RO/vendor constraints of the primary paths; this is a static inference, not dynamically confirmed.

**Unmap:** `0x8011E048` → `0x1400042C0` (`ev_8d6e2b0e58ce306babac0d03fd0715f2586eeca4fc4371b8e300ba342646b01d`) branches on the section handle at `+0x00`: section path → `ZwUnmapViewOfSection(CurrentProcess, +0x24)`; MDL path → `MmUnmapLockedPages(+0x24, MDL)` + `IoFreeMdl` + `MmUnmapIoSpace(+0x08, size)`.

A simpler read-only variant is **`0x8011607C`**, which returns a `\Device\PhysicalMemory` handle opened with `SECTION_MAP_READ` only (`0x1400015E8`–`0x140001683`). It cannot be used for a writable view, but it gives the caller an arbitrary physical-memory read primitive without the 0x3D request/tag structure.

### 5.2 Secondary: true kernel-mode physical bit-clear — `0x8011E0A0` → `0x140002948`

`0x140002948` (`ev_44b2038d2d4b79cbfb56c66411440cfa417335072a1962f13fcfee10ba232270`) is a **true kernel-mode write**: it validates `phys != 0` and `phys < 2^48`, `bit < 4`, maps the page with `MmMapIoSpace`, reads a dword at `phys & 0xFFF`, clears `1 << bit`, writes the dword back, and unmaps. It can clear one bit in any physical page, including kernel code/data or page tables. It cannot set bits, so it is a constrained but genuine write-what-where (bit-clear) primitive.

### 5.3 Tertiary hardware primitives

- **Arbitrary port I/O:** `0x8011E04C` executes `out dx, al/ax/eax` at a caller-chosen port (`0x14000196C`–`0x1400019A8`); `0x8011E050` executes `in`. Port I/O can program chipset/DMA/SMM-adjacent hardware and is a hardware-level write primitive, not a kernel virtual write.
- **PCI configuration writes:** `0x8011E0A8` (`HalSetBusDataByOffset`, `0x140002169`) and `0x8011E090` (via `\Driver\PCI`, `0x140001B67`/`0x1400034E0`/`0x140004324`) can enable bus mastering and reprogram BARs, enabling DMA-based attacks.
- **MSR writes:** `0x8011E088` writes a caller 64-bit value to a fixed set of MSRs (`0x38F`, `0x38D`, `0x199`, `0x1A0`, `0xC0010015`) and reads it back (`0x140001D70`–`0x140001DB6`). `0x8011E074` writes 0 to MSR `0xE7`/`0xE8`. `0x8011E060` permits arbitrary `rdmsr` except LSTAR and SYSENTER_EIP.

### 5.4 Is it a “true kernel memory write”?

**Yes, with qualifications.**

- `0x8011E0A0` is unambiguously a kernel-mode write to an arbitrary physical address (one-bit clear).
- `0x8011E044` is not a kernel `memcpy` to an arbitrary kernel VA; the kernel creates a user mapping of physical memory, and the caller performs the writes. Functionally, for the admin caller, it is an arbitrary **physical** memory read/write primitive that bypasses the normal user-mode restriction on `\Device\PhysicalMemory`. The RW path is constrained to 4 KB and a first-DWORD Intel/AMD vendor ID; the RO path is unconstrained; the MDL fallback may remove the RW constraint (static inference).
- There is **no** arbitrary kernel **virtual-address** write (no `MmCopyVirtualMemory`, no user-supplied kernel pointer dereference, no write-what-where VA loop).

This is therefore a kernel memory-write primitive in the physical-address sense, not a direct kernel-VA write primitive.

---

## 6. VERDICT

**Classification:** signed, admin-only (explicit SDDL) PassMark DirectIO driver exposing physical-memory mapping, physical bit-clear, arbitrary port I/O, PCI configuration access, and MSR access, behind a per-handle RSA-2048 challenge-response and per-request MD5 integrity tags.

**Does it provide a kernel memory write?** Yes, constrained:
1. `0x8011E0A0` — genuine kernel-mode one-bit clear at an arbitrary physical address (no vendor check).
2. `0x8011E044` — user mapping of caller-chosen physical memory; RW path limited to a 4 KB page whose first DWORD is `0x8086`/`0x1022`, RO path arbitrary, and an MDL fallback that may yield a user-writable mapping of an arbitrary-size physical range (static inference).
3. Hardware write paths (`out`, PCI config, MSR) that can be leveraged for DMA/hardware attacks.

**Severity for the stated reach:** **High** as an admin-to-kernel primitive, but **not a privilege-boundary crossing** for a fully trusted local administrator. It is a ready-made, signed BYOVD-style tool that bypasses driver-loading restrictions and the user-mode `\Device\PhysicalMemory` restriction. It is **not** a remote or unauthenticated vulnerability.

**Residual risk / abuse cases:** anti-cheat/EDR bypass, firmware/PCI tampering, physical-memory credential theft, and kernel patching by an admin. The RSA gate is the only non-static barrier; the private key must exist in the user-mode companion and is extractable by the same admin. If `\Device\LoopLpt<N>` has a permissive default DACL, the RSA gate becomes the sole barrier for non-admins and the driver could become an LPE vector; that DACL must be checked on a live system.

**Recommendation:** deny open of `\\.\<ServiceName>` and `\\.\LoopLpt<N>` to non-essential principals; alert on IOCTLs `0x8011E044`, `0x8011E048`, `0x8011E0A0`, `0x8011E04C`, and `0x8011E0A8`; treat the signed binary as a BYOVD candidate; verify the LoopLpt DACL and the presence/location of the user-mode private key.

---

## 7. Limitations

- Static analysis only. The driver was not loaded, no service was created, and no IOCTL was executed.
- REA/Ghidra auto-analysis recovered 206 procedures; several calls are indirect through `_guard_dispatch_icall` (`0x140005A60`) or dynamically resolved (`ObGetObjectType` via `MmGetSystemRoutineAddress` at `0x1400041C6`, `RtlQueryRegistryValuesEx` at `0x14000376F`, `WdmlibIoCreateDeviceSecure` at `0x14000C120`). Targets of those calls were resolved only where the resolver and call site made them unambiguous.
- The LoopLpt device is created with plain `IoCreateDevice`; its runtime DACL was not statically resolvable. The explicit admin-only SDDL applies to the main device.
- The RSA private key was not located; the statement that it resides in the user-mode companion is an inference from the challenge-response design (the driver contains only the public key at `0x140008530`).
- The MDL fallback's writability and its ability to bypass the RW vendor/size check are inferred from `MmMapIoSpace` + `MmBuildMdlForNonPagedPool` + `MmMapLockedPagesSpecifyCache(UserMode)` semantics; they were not dynamically tested.
- METHOD_BUFFERED output truncation was assumed to follow the I/O manager's `min(Information, OutputBufferLength)` rule; the driver itself does not clamp `Information` for most cases.
- No PDB symbols were available; function names (`FUN_*`) and struct offsets are Ghidra/objdump reconstructions. Version/PDB metadata identifies the binary as PassMark DirectIO 17.0.1001.0 (`F:\Source Code\DirectIO-Driver\x64\Release\debug64\DirectIo64.pdb`).
- REA evidence was accepted only when the evidence subject's SHA-256 matched `BD9D1B3C…A7DB`; every cited `ev_` record above passed that check.
