# SIV `SIVI64.sys` — admin-reachable kernel memory-write audit (static, architecture check)

| Field | Value |
|---|---|
| File | `drivers/SIVI64_70484F2F.sys` (manifest batch: collected5; previously `_collected5\agentR3\new\SIVI64_70484F2F.sys`) |
| SHA-256 | `70484F2F6D0076F36F82C1956B9ACCAE7827034ED399740727EE1C35E9F50202` |
| Architecture | **IA-64** (PE machine `0x0200`, PE32+ optional-header magic `0x020B`). Not an x64 image. |
| Company / version | Not extracted this pass (IA-64 image; version resource not read). |
| Signature status | Valid. Signer `RH Software Limited` (SIV). |
| Method | Static PE header check only. No decompilation. Nothing loaded, installed, or executed. |
| Reach tier | **Not applicable.** |
| Setup required | Not applicable. |
| Verdict | **BLOCKED** (load=blocked). The image is for IA-64 processors and is not loadable on x64 Windows. Primitive not assessed; no x64 memory-write primitive is reachable from this build. |
| Write quality | not assessed |
| Severity | BLOCKED (IA-64, not loadable on x64) |

> Static-only audit. This report records the architecture check. It does not analyse the IA-64 code, because the machine it targets cannot run it.

## 1. Basis

- PE `machine` field is `0x0200` (IA-64). The x64 value is `0x8664`.
- The optional-header magic `0x020B` is PE32+, which is the 64-bit format used by both IA-64 and x64. The machine field is what determines the target.
- The earlier audit queue listed SIVI64 among the admin-reachable candidates. The architecture check removes it from that queue for x64 systems.

## 2. What would change this

- A genuine x64 SIV driver. The version of SIV in this batch ships an IA-64 binary under the `SIVI64` name. An x64 build would need a different file, which should be collected separately.
- IA-64 hardware would be needed to load this image at all. That is outside the scope of the x64 audit corpus.

## 3. Limitations

- Only the header was read. The driver's behaviour was not analysed, so this report makes no claim about its primitives.
