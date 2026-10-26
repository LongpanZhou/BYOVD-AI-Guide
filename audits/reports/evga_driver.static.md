# EVGA low-level driver (`driver-x64` / `driver-x86`) — static audit

| file | arch | size | version | verdict |
|---|---|---|---|---|
| `EVGA\driver-x64_33DA2CE2.sys` | x64 | 39856 | 1.0.0.0 (built 2020‑07‑20) | **WRITE-HIGH primitive — blocked by DACL** (SDDL is admin-only) |
| `EVGA\driver-x86_A154F835.sys` | x86 | 35248 | 1.0.0.0 (built 2020‑07‑20) | **WRITE-HIGH primitive — blocked by DACL** (SDDL is admin-only) |

Internal name: *“EVGA Low-Level Driver”*. Image base `0x140000000` (x64) / `0x400000` (x86).

This is the strongest write primitive in the whole collection: **arbitrary `wrmsr` (LSTAR ⇒ ring‑0), arbitrary port I/O, arbitrary physical-memory write, arbitrary PCI-config write**, all with **no token/privilege check** in the driver. The only gate is the device DACL, and that DACL is admin-only.

---

## 1. Device creation API and SDDL

`DriverEntry` @ `0x140001730` (x64) / `0x401370` (x86):

* Device name is **built at runtime** from the driver's `RegistryPath` — it takes the substring after the last `\` (the service name) and formats `\Device\%ls`:
  ```
  0x140001730  wcsrchr(*(wchar_t **)(param_2 + 4), L'\\')   ; param_2 = RegistryPath
  ...
  FUN_1400016a0(local_408, 0xff, L"\\Device\\%ls", DAT_140004228);
  ```
  so the triage “device = <blank>” is expected — the name depends on the service key.
* Symlink: `\??\%ls` (same service name).
* Creation call:

```c
// x64, 0x1400017xx
uVar2 = WdmlibIoCreateDeviceSecure(param_1, 0x10, local_438 /*\Device\<svc>*/, 0x22,
                                   0x100, 0, &DAT_140003280 /*SDDL*/, 0 /*class GUID*/,
                                   local_res10);
```

`WdmlibIoCreateDeviceSecure` is the WDM security library wrapper around `IoCreateDeviceSecure`. The driver carries a full private copy of the SDDL parser (`SeSddlSecurityDescriptorFromSDDL` @ `0x1400091b8`, `SepSddlDaclFromSDDLString` @ `0x1400090bc`, `SepSddlGetAclForString` @ `0x140008c40`, …), so the SDDL is honoured even on builds where the export is missing.

### SDDL actually used

```
x64  UNICODE_STRING @ 0x140003280:
     36 00 38 00 00 00 00 00 48 32 00 40 01 00 00 00
     len = 0x36 (54 B = 27 chars), max = 0x38, Buffer = 0x140003248
     text @0x140003248: "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

x86  UNICODE_STRING @ 0x4021c0:
     36 00 38 00 88 21 40 00
     len = 0x36, Buffer = 0x402188
     text @0x402188: "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
```

**The EVGA SDDL is admin-only: SYSTEM full, Administrators full, no ACE for Everyone / Users / Interactive / Restricted.**

### Dead-literal finding: CONFIRMED (for the other six)

The file carries the same 7-entry SDDL pool as the MICSYS drivers (`D:P(A;;GA;;;SY)`, `...GRGWGX;;;BA)(A;;GR;;;WD)`, `...RC)`, etc.), but **only `0x140003280` is referenced** (by the create call). The other six table entries and their `UNICODE_STRING`s are unreferenced. Unlike the MICSYS case, the *referenced* one is already admin-only, so the distinction does not change the verdict.

---

## 2. Device surface

* `\Device\<ServiceName>` (e.g. `\Device\EVGA` if the service is `EVGA`) and `\DosDevices` / `\??\<ServiceName>`.
* `DeviceType = 0x22` (`FILE_DEVICE_UNKNOWN`), `Characteristics = 0x100` (`FILE_DEVICE_SECURE_OPEN`), extension 0x10.
* Major functions installed (`DriverObject` offsets):
  * `+0x70` `IRP_MJ_CREATE` → `FUN_140001a90` (just bumps a refcount, completes success)
  * `+0x80` `IRP_MJ_CLOSE` → `FUN_140001ac0`
  * `+0xE0` `IRP_MJ_DEVICE_CONTROL` → **`FUN_140001d20`**
  * `+0xF0` `IRP_MJ_SHUTDOWN`, `+0x100` `IRP_MJ_CLEANUP`, `+0x68` unload
* `IRP_MJ_CREATE` performs **no access check**, only `InterlockedIncrement` on the extension refcount.

---

## 3. IOCTL table (x64: dispatch `FUN_140001d20` @ `0x140001d20`)

All are `METHOD_BUFFERED`, device type `0x8000`, and — unusually — `RequiredAccess = FILE_WRITE_ACCESS` (bits 14‑15 = 01). That bit is **not enforced** by the I/O manager and the driver never calls `IoValidateDeviceIoControlAccess`, so any handle works.

| IOCTL | handler | in / out | action |
|---|---|---|---|
| `0x80006400` | `0x140001d20` case 0 | in 0 / out 4 | return extension refcount |
| `0x80006404` | same | in-len 2, width @stack+8 | **port read** (`in`), width 1/2/4 |
| `0x80006408` | same | in `5/6/8`, out 0 | **port write** (`out`), width encoded in length−4 |
| `0x8000640c` | `FUN_140001ca0` | in 4 / out 8 | **`rdmsr`** |
| `0x80006410` | `FUN_140001c00` | in 12 / out 0 | **`wrmsr`** |
| `0x80006414` | `0x140001d20` | in 8 / out 8 | **`MmMapIoSpace` read** (arbitrary phys addr) |
| `0x80006418` | `0x140001d20` | in ≥16 / out 0 | **`MmMapIoSpace` write** (arbitrary phys addr) |
| `0x8000641c` | `0x140001d20` | in 8 | `HalGetBusDataByOffset` (PCI config read) |
| `0x80006420` | `0x140001d20` | in 10/12 | **`HalSetBusDataByOffset` (PCI config write)** |
| `0x80006401..1f` (odd set) | — | — | `break` → `STATUS_INVALID_DEVICE_REQUEST` (unimplemented) |

x86 mirror: dispatch `FUN_004019a0` @ `0x4019a0`, `wrmsr` handler `FUN_00401770` @ `0x401770`, `rdmsr` `FUN_004018b0`.

---

## 4. Write sinks (decompiled)

**a) Arbitrary MSR write — `FUN_140001c00` @ `0x140001c00` (x64), `FUN_00401770` @ `0x401770` (x86):**

```c
iVar1 = **(int **)(param_2 + 0x18);            // MSR index from input buffer
if ((2 < iVar1 + 0x3fffff7fU) && (2 < iVar1 - 0x174U)) {
    wrmsr(iVar1, *(undefined8 *)(*(int **)(param_2 + 0x18) + 1));   // <-- sink
    return 0;
}
return 0xc000000d;
```

The filter only blocks `0x81..0x83` and `0x174..0x176` (unsigned wrap trick: `iVar1+0x3fffff7f < 2` ⇔ `0x81..0x83`; `iVar1-0x174 < 2` ⇔ `0x174..0x176`). Everything else is writable, including:

* `0xC0000082` **IA32_LSTAR** — point the syscall entry at a user-mapped address ⇒ ring‑0 code execution on the next `syscall`;
* `0xC0000080` EFER (disable NX / enable long mode bits), `0xC0000081` STAR, `0xC0000100/0101` FS/GS base, `0x1B` APIC base, `0x277` PAT, etc.

**b) Arbitrary port write — `0x80006408`:**

```c
case 0x80006408:
  if (*(int *)(lVar3 + 8) == 0) {                 // no output buffer
    cVar2 = *(char *)(lVar3 + 0x10);              // width from length
    if ((cVar2 - 5U & 0xfc) == 0 && cVar2 != 7) {
      puVar4 = *(undefined2 **)(param_2 + 0x18);
      if (cVar2 == '\x05') out(*puVar4, *(undefined1 *)(puVar4 + 2));
      else if (cVar2 == '\x06') out(*puVar4, puVar4[2]);
      if (cVar2 == '\b') out(*puVar4, *(undefined4 *)(puVar4 + 2));
```

**No port filter whatsoever** — every 16-bit port is writable, including `0xCF8/0xCFC` (PCI config), `0xCF9` (reset), DMA controller ports, HPET, etc.

**c) Arbitrary physical-memory write — `0x80006418`:**

```c
puVar10 = *(undefined8 **)(param_2 + 0x18);
puVar11 = (undefined8 *)MmMapIoSpace(*puVar10 /*phys addr*/, bVar12 /*len 1..8*/, 0);
...
if (bVar12 == 4) { *(undefined4 *)puVar11 = *(undefined4 *)(puVar10 + 1); MmUnmapIoSpace(puVar11,4); }
if (bVar12 == 8) { *puVar11 = puVar10[1]; } MmUnmapIoSpace(puVar11, bVar12);
```

No address validation at all (not even the `MmGetPhysicalMemoryRanges` check the MICSYS v1.3 has).

**d) PCI config write — `0x80006420`:**

```c
uVar1 = **(ulonglong **)(param_2 + 0x18);          // {bus/dev/fn, offset, value}
uVar9 = HalSetBusDataByOffset(4, uVar1 & 0xff,
             ((uVar1 >> 0x10) & 7) << 5 | ((uVar1 >> 8) & 0x1f), local_20,
             (int)(uVar1 >> 0x20), (uint)bVar12);
```

`InterfaceType 4` = `PCIBus`; the bus number is user-controlled, so any device on any PCI bus can be reconfigured (enable bus-master, reprogram BARs, write to the chipset).

**e) port read** `0x80006404` (`in`), **f) phys read** `0x80006414` (`MmMapIoSpace` + load), **g) `rdmsr`** `0x8000640c`.

---

## 5. Validation gaps

1. **No privilege check anywhere** — no `SeSinglePrivilegeCheck(SeLoadDriverPrivilege)`, no `SeTokenIsAdmin`, no `RequestorMode` test. The dispatch switches directly on `*(uint *)(stack + 0x18)`.
2. **No `IoValidateDeviceIoControlAccess`** — the `FILE_WRITE_ACCESS` bits in the IOCTL codes are decorative.
3. **MSR blocklist is trivially bypassable** — LSTAR/SYSENTER/EFER/GS base are not in it.
4. **Port write has no range check at all.**
5. **`MmMapIoSpace` address and length come straight from the user buffer** (`*puVar10`, `bVar12` 1/2/4/8) — arbitrary physical read/write, including MMIO (so it can also hit device registers).
6. **`IRP_MJ_CREATE` completes success unconditionally** — access control is 100 % the object DACL.

---

## 6. Setup required

**none** beyond installation/start of the service. The device name and symlink are derived from the service name, so the driver creates its device immediately in `DriverEntry`; there is no PnP/devnode and no hardware probe. No firmware or specific motherboard is needed for the MSR / port / PCI paths (they are chipset-agnostic).

---

## 7. Next dynamic test

1. Standard user: `CreateFileW(L"\\\\.\\<ServiceName>", GENERIC_READ|GENERIC_WRITE, 0, ...)` → expect `ERROR_ACCESS_DENIED` (admin-only SDDL). Confirm the *name* by reading `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` and using the last path component.
2. If (and only if) that open ever succeeds for a non-admin — e.g. an OEM build shipped with a different SDDL — `DeviceIoControl(h, 0x80006410, {msr=0xC0000082, value=<user VA>}, 12, ...)` is an immediate ring‑0 primitive; a safe proof is `0x8000640c` (`rdmsr 0x1B`, APIC base) followed by a read-only `0x80006414` of a known RAM page.
3. Also test with a *restricted* token (UAC-filtered admin, medium IL) to prove `SeTokenIsAdmin`-style filtering is absent (it is absent from the code entirely).

---

## 8. Verdict

**WRITE-HIGH primitive, blocked by DACL.**

* Code quality from an attacker's standpoint: excellent (MSR + port + phys + PCI, no checks).
* Reachability: an unprivileged local user **cannot open the device** because the effective DACL is `D:P(A;;GA;;;SY)(A;;GA;;;BA)`. Mark the primitive **“blocked by DACL”**, not “no write”.
* If a permissive DACL is ever observed on a shipping OEM image, this is the single best driver in the collection — a one-IOCTL `wrmsr` to LSTAR is a deterministic ring‑0 escalation with no hardware dependency.
