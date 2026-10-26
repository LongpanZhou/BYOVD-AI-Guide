# Appendix: `megasr.sys` — SCIC/SCIF DCMD path at `0x13878`

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\drivers\megasr.sys` (575,800 bytes) |
| SHA-256 | `8A902DDB6016E4D5C28808FBA5741751D94FFBD4B55724D47BBA0A8C29900E53` |
| Analysis date | 2026-10-25 |
| Method | **Targeted static follow-up**, not a full re-audit. Local Ghidra 12.1.4 headless (project `C:\Users\<scrubbed>\AppData\Local\Temp\opencode\ghidra_megasr`, program `/megasr.sys`), `llvm-objdump` 20.1.5, and direct PE/export parsing. **No REA session was opened.** No load, execution, service creation, registry write, or web lookup. |
| Reach tier | **R3 (hardware)** — the StorPort port device exists only after `HwFindAdapter` matches one of the 30 supported MegaRAID/ESRT2 PCI IDs; the practical opener is a local administrator (**R2**) behind that hardware gate. |
| Setup required | **hardware** |
| Write quality | **W3** — fixed-offset, fixed/reflected-value kernel pool write with a caller-controlled length; no arbitrary value and no caller-selected address. |
| Verdict | **MW4 — reach=R3 setup=hardware write=W3 load=signed** (unchanged) |
| Relationship | **Supplements** `audits/reports/megasr.current.md`. Supersedes **only §5.3** (the SCIC/SCIF DCMD residual) and the `0xF0010400` routing row in §3. It does **not** supersede the main verdict or the confirmed `0x600` zero-fill. |
| HW-only | **No** — the path produces a real CPU pool write (`0x30df9`–`0x30e0d`) and a physical-address SGL, in addition to a queued hardware command. |

**Bottom line.** `DataBuffer+0x30` is a caller-controlled 32-bit length used in three roles: the SGL/DMA length in `0x13878`, the allocation size and CPU copy/copy-back length in `0x2fc64`, and the SCIC request length propagated by `0x2f540`. It is **not** bounded against `DataTransferLength`, `SRB_IO_CONTROL.Length`, or any device limit. The path produces a real CPU kernel-pool write and a physical-address SGL, not merely a hardware command, but the write is fixed-offset with fixed/reflected values and the DMA mapping is bounded by StorPort's VA range check. **The verdict remains MW4/W3; it does not rise to MW3/W2.**

## Coverage statement

This is a **targeted follow-up** to `megasr.current.md`, not a second full audit. It resolves the one residual left open in §5.3.

- **Fully traced (100% of function/chain):** `0x12388` routing, `0x13878` (entire), `0x17af8` → `0x2f43c`, `0x1afd8`, `0x2fc64` (entire dispatcher, prologue, and copy-back epilogue), `0x2f540` type-3 SGL propagation, `0x16744`/`0x166e0` block allocator, and the host `StorPortGetPhysicalAddress` range check.
- **Sampled:** 5 of approximately 80 `+0x34` DCMD opcode handlers were decompiled individually (`0x31aec`, `0x30e68`, `0x312e4`, `0x3153c`, `0x315f4`). All recognized opcodes share the same `0x2fc64` prologue and `0x30dd1` copy-back epilogue, so the length/write behaviour is characterized for the whole table even where individual response layouts were not read.
- **Coverage estimate:** ~100% of the `0x13878` DCMD path and its immediate callees; ~2% of the image added by this pass (~20 functions / 1,275 `.pdata` entries). Overall image coverage remains **~15–20%**, unchanged from `megasr.current.md`.

## 1. Exact call chain

| Stage | Address | Action |
|---|---:|---|
| `SRB_FUNCTION_IO_CONTROL` handler | `0x12388` | Reads `SRB->DataTransferLength` at `SRB+0x10`; only check is `>= 0x1c` (`0x12392`). Requires `"LSILOGIC"` at `DataBuffer+4` (`0x123b2`). |
| Outer control code | `0x12406`–`0x12414` | Accepts only `0xF0010000` or `0xF0020000` from `DataBuffer+0x10`. |
| Inner opcode routing | `0x12420`–`0x1244c` | Six fixed inner opcodes (`0xF0010100/0200/0300`, `0xF0020100/0200/0300`) go to `0x13be0` (`0x12451`). **Everything else** falls through `0x12416` to `0x13878` (`0x12419`). |
| DCMD entry | `0x13878` | Allocates a `0xd40`-byte request (`0x16ffc`), stores it through `SRB+0x38` (`0x138bc`), loads length and data pointer. |
| Length | `0x138de` | `r14d = *(u32 *)(DataBuffer + 0x30)` — **caller-controlled, no validation**. |
| Data pointer | `0x138e5` | `r13 = DataBuffer + 0xbc`. |
| SGL build | `0x138f7`–`0x13956` | Loop calls `StorPortGetPhysicalAddress(adapter, SRB, VA, &chunk_len)` through IAT slot `0x7b040` (`0x13909`); stores VA/PA/len at `request+0x70/+0x78/+0x80` (`0x13932`, `0x1393f`, `0x1394a`); advances VA and subtracts length; caps at **63 entries** (`0x13956`, `0x1395a`). |
| Request fields | `0x13976`–`0x13994` | `request+0x50 = DataBuffer`, `request+0x58 = 8`, `request+0x20 = *(u32 *)(DataBuffer+0x30)`. |
| Direction | `0x139a6`–`0x139ed` | `request+0xc82` = 3 by default; `DataBuffer+0x2c` bit `0x10` → 1; bit `0x08` → 2. |
| Queue | `0x13a2c` | Calls `0x17af8` with the request. |
| Submit | `0x17b0f`–`0x17b39` | Because `request+0x48 == 1` (`0x139e9`), `0x17af8` calls `0x2f43c` (`0x17b39`). |
| Type dispatch | `0x2f4a6`–`0x2f4b4` | Reads `DataBuffer+0x1c`. If `== 5`, calls `0x2fc64` (the DCMD copy path). If `3` or `4`, routes through `0x3c514` to `0x2f540` (the SCIC/SGL path). |
| Precheck | `0x1afd8` | Reads `DataBuffer+0x1c` (`0x1afe8`) and, for type 5, `DataBuffer+0x34` (`0x1b007`); **never reads `+0x30`**. |
| DCMD copy | `0x2fc64` | Length `0x2fca0`; allocation `len+0x8bd` `0x2fcaf`; copy in `0x2fd52`–`0x2fd67`; dispatch on `+0x34` `0x2fd69`; copy back `0x30df9`–`0x30e0d`. |

The chain is reachable with a buffered `IOCTL_SCSI_MINIPORT` (`0x4D008`, `FILE_READ_ACCESS|FILE_WRITE_ACCESS`) whose payload sets `SRB_IO_CONTROL.Signature = "LSILOGIC"`, `ControlCode = 0xF0010000`, `DataBuffer+0x1c = 5`, and `DataBuffer+0x34` to a recognized DCMD opcode. The minimum buffer that reaches `+0x34` is `0x38` bytes; the data area starts at `+0xbc`, already `0x84` bytes beyond a `0x38`-byte buffer.

## 2. What the `+0x30` length actually is

The same 32-bit field is used in **three different roles**:

### 2.1 Physical/DMA mapping length (`0x13878`)

`0x138de` loads it, `0x138e5` sets the start to `DataBuffer+0xbc`, and the loop at `0x138f7`–`0x13956` calls `StorPortGetPhysicalAddress` for each chunk. The returned PA and the requested remaining length are written into the request's SGL (`0x13932`, `0x1393f`, `0x1394a`). This is a **mapping length**, not a CPU copy.

For the type-3 SCIC path, `0x2f540` propagates the SGL and the length into a new request at `0x2fb3d`–`0x2fb78` and queues it (`0x2fbcf`). The length is therefore also the **SCIC data-transfer length**.

### 2.2 Allocation and copy length (`0x2fc64`, type-5 DCMD)

- `0x2fca0`: `eax = *(u32 *)(DataBuffer+0x30)`.
- `0x2fcaf`: `r15d = eax + 0x8bd` (allocation size; 32-bit arithmetic, no overflow check).
- `0x2fcba`–`0x2fcc6`: copy length = `min(len, len+0x8bd)`; for all non-wrapping values this is **`len`**.
- `0x2fccd`: `FUN_00016744(adapter, len+0x8bd, cookie)` acquires a command block from the pool; the block's recorded SGL length is not checked against `len+0x8bd`.
- `0x2fd08`: zero-fills `len+0x8bd` bytes at the block base.
- `0x2fd20`–`0x2fd33`: copies the fixed `0xbd`-byte header from `DataBuffer` to the block.
- `0x2fd52`–`0x2fd67`: copies **`len` bytes** from `DataBuffer+0xbc` to `block+0xbc`.
- `0x30dd1`–`0x30df2`: copies the `0xbd`-byte header **back** to `DataBuffer`.
- `0x30df9`–`0x30e0d`: copies **`len` bytes** from `block+0xbc` **back** to `DataBuffer+0xbc`.

This is a **copy length** and a **copy-back length**. The `movb` loop at `0x30df9`–`0x30e0d` is a real CPU store into the SRB data buffer.

### 2.3 Handler-level zero-fill length (`0x3153c`, opcode `0x1040300`)

The `0x1040300` handler takes the temp block (`0x3153c`), re-reads the copied length at `0x31564`, and executes `memset(temp+0xbc, 0, len)` at `0x31572`–`0x3157e` when `len >= 0x108`. The block capacity is not checked. Other handlers use fixed sizes (`0x31b20` = `0x800`, `0x30db0` = `0x1208`, `0x30dc3` = `0x108`).

**Answer:** the field is a mapping/DMA length, an allocation size, and a CPU copy/copy-back length — not exclusively one of them.

## 3. Bounds

| Potential bound | Used? | Evidence |
|---|---|---|
| `SRB->DataTransferLength` (`SRB+0x10`) | **Only a lower bound** | `0x12392`: `cmpl $0x1c, 0x10(%rdx)`. `DataTransferLength` is also the range StorPort uses for its VA check, but the driver never compares `+0x30` with `DataTransferLength - 0xbc`. |
| `SRB_IO_CONTROL.Length` (`DataBuffer+0x18`) | **Never read** | `0x12396` reads `SRB+0x18` (the DataBuffer pointer), not `DataBuffer+0x18`. No `0x18(%r8)` access exists in `0x12388`–`0x12478`; `0x13878` and `0x2fc64` do not read it either. |
| 63 SGL entries | **Entry-count cap only** | `0x13956`/`0x1395a` (`cmpb $0x3f`); exceeding it frees the request and sets `SrbStatus = 6` at `0x1395c`–`0x13967`. It does not bound the total `+0x30` value; one entry can carry the whole remaining length. |
| 64 KB SCIC command block | **Not checked** | The SCIC pool is created with `FUN_00016744(adapter, 0x10000, ...)` 32 times at `0x35038`. `0x2fc64` uses `len+0x8bd` as the allocation/copy size without consulting the block's recorded SGL length. On a 64 KB block, `len > 0xFF44` overflows the block during the `0x2fd52` copy; `len > 0xF743` overflows it during the `0x2fd08` zero-fill. |
| 32-bit length wrap | **Not checked** | `0x2fcaf` `leal 0x8bd(%rax),%r15d`; `0x2fcbd`–`0x2fcc6` min. A length near `0xFFFFFFFF` wraps the allocation size; the `0x3153c` handler then re-reads the untruncated `+0x30` and can zero-fill almost 4 GB (`0x31564`–`0x3157e`), i.e. a crash-first path. |
| StorPort VA range | **External bound on the SGL** | See §4. The driver itself does not bound the VA range. |

There is **no device-limit check, no `Length` check, and no `DataTransferLength` upper bound** in the DCMD path.

## 4. Is the SGL/DMA part an adjacent-page kernel write?

The baseline's §5.3 hypothesis was that `StorPortGetPhysicalAddress` would translate `DataBuffer+0xbc` VAs beyond the SRB buffer and let the controller DMA into pages that follow the buffer. That hypothesis was tested against the host's `storport.sys`:

- `storport.sys` 10.0.19041.6456, image base `0x1C0000000`, export `StorPortGetPhysicalAddress` RVA `0x1C6B0`.
- The routine compares the supplied VA against the SRB data-buffer range at `0x1C001C76A`–`0x1C001C776`:
  - `cmpq %rdi,%r12` (VA vs `Srb->DataBuffer`);
  - `leaq (%rcx,%r12),%rax` (`DataBuffer + DataTransferLength`);
  - `cmpq %rax,%rdi; jb 0x1C0029E2C` (match).
- If no SRB range matches, it returns NULL at `0x1C001C7FF`; `*Length` was zeroed at entry (`0x1C001C702`) and is not updated.
- For a matched VA, it computes the PA and the physically contiguous run in the MDL entry at `0x1C0029E9A`–`0x1C0029EAF`.

Consequence in `megasr`: when `StorPortGetPhysicalAddress` returns NULL/zero, `0x13916`–`0x13922` does **not** fail. It substitutes the full remaining length (`movl %r14d,%edx` at `0x1391f`) and stores the NULL PA with that length (`0x13932`). The SGL therefore ends with a **PA = 0, length = remaining** entry, and `0x13951` subtracts the whole remaining length, so the loop exits. Out-of-buffer VAs are **not** mapped to adjacent kernel pages.

This is a robustness/firmware bug (a bogus SGL entry pointing at physical 0), not an adjacent-page kernel memory write. It could still produce a fixed physical write to PA 0 if the controller accepts the entry and the IOMMU does not block it; that is fixed, physical-only, and outside the kernel pool. It does not raise the verdict.

**Caveat:** this was verified against the host's 10.0.19041 StorPort, not against the 2013 driver's original target OS. The API contract and MDL-based range check are expected to be the same, but a Win7/8/2012 StorPort was not available for comparison.

## 5. What the CPU copy-back writes

### 5.1 Target and range

- **Target:** the SRB data buffer for `IOCTL_SCSI_MINIPORT` — the StorPort system buffer in nonpaged pool. It is **not** a caller-selected address and not a user pointer.
- **Start:** `DataBuffer + 0xbc`.
- **Length:** `u32` at `DataBuffer + 0x30`, `0 … 0xFFFFFFFF`.
- **Range:** `[DataBuffer+0xbc, DataBuffer+0xbc+len)` with 32-bit wrap.
- **In-bounds portion:** up to `DataTransferLength - 0xbc`.
- **OOB portion:** from `DataTransferLength` to `DataBuffer+0xbc+len`. For the minimum `0x38`-byte buffer, the OOB write starts at offset `0x38` and extends to `0xbc+len`.
- **Secondary target:** the driver's SCIC command block at `block+0xbc` (prologue copy and handler stores), and the request SGL at `request+0x70` (63 × `0x18` bytes, within the `0xd40` request object allocated at `0x16ffc`).

### 5.2 Value control

The `len` bytes copied into the block came from the same `DataBuffer+0xbc` range. The copy-back is therefore, for the bytes beyond the valid input:

- **Reflected** — the same bytes that were read from those addresses;
- **Zero** — where a handler executed a `memset` (`0x31572`–`0x3157e` with `len`, `0x31b20` with `0x800`, `0x30db0` with `0x1208`);
- **Fixed/adapter-derived** — where a handler wrote response fields (e.g. `0x31aec` writes adapter identity, `0x315f4` copies `0x100` bytes of adapter data).

No handler in the sampled set copies arbitrary caller bytes to an arbitrary offset. The caller controls **how much** is written and **which** fixed response layout is used; the caller does not control the value written beyond the in-bounds prefix. That is the definition of W3, not W2.

The prologue copy at `0x2fd52`–`0x2fd67` is also an out-of-bounds read of the same range. If the system buffer is larger than `DataTransferLength`, those bytes can reach the caller through the output buffer; that is an info-leak modifier, not a write, and is not counted in the MW rating.

The strongest net-new fixed store is the `0x9010000` handler's `memset(_Dst, 0, 0x1208)` at `0x30da5`–`0x30db9`, copied back at `0x30df9`–`0x30e0d`. It is larger than the `0x600` zero-fill in `megasr.current.md` §5.1, but it is still a fixed zero value at a fixed offset.

## 6. Verdict analysis

| Question | Answer |
|---|---|
| Copy length, mapping length, or DMA length? | **All three.** `+0x30` is the SGL/DMA length (`0x138de`–`0x1394a`), the SCIC request length (`0x13994`, `0x2fb3d`–`0x2fb43`), and the temp-block allocation/copy/copy-back length (`0x2fca0`–`0x2fd67`, `0x30df9`–`0x30e0d`). |
| Bounded against `DataTransferLength`? | **No.** Only `>= 0x1c` at `0x12392`. |
| Bounded against `SRB_IO_CONTROL.Length`? | **No.** `DataBuffer+0x18` is never read in this path. |
| Bounded against a device limit? | **No driver-side limit.** Only the 63-entry SGL count cap (`0x13956`) and the inferred 64 KB block size, neither of which validates `+0x30`. |
| Kernel memory write, physical/DMA mapping, or only a hardware command? | **A CPU kernel pool write** (`0x30df9`–`0x30e0d`) **plus** a physical-address SGL (`0x13909`) **plus** a queued hardware command (`0x17af8`/`0x2f540`). Not HW-only. |
| Exact caller-controlled range and target? | Length `0 … 0xFFFFFFFF` from fixed `DataBuffer+0xbc`; target is the StorPort SRB system buffer (kernel nonpaged pool), not a caller-selected address. |
| Raise MW4/W3 → MW3/W2? | **No.** The confirmed CPU write is fixed-offset with fixed/reflected values (W3). The DMA mapping is bounded by StorPort's VA range check on the analyzed host. R3/hardware + W3 = **MW4**. |

**Verdict: `MW4 — reach=R3 setup=hardware write=W3 load=signed`.** The path is not `HW-ONLY` and the length is not fully bounded, but the write quality remains W3: the target is fixed, the value is fixed or reflected, and the only stronger (arbitrary-page DMA) hypothesis is blocked by StorPort. It does not become MW3/W2.

## 7. Corrections to `megasr.current.md`

1. **`0xF0010400` and `0xF0010500` do not reach `0x13be0`.** The six-opcode list at `0x12420`–`0x1244c` excludes them; the default branch at `0x12416` calls `0x13878`. `0x13be0`'s `0xF0010400`/`0xF0010500` branches at `0x13c68`/`0x13d30` are dead for this IOCTL path (the only call to `0x13be0` is `0x12451`). The baseline §3 row claiming a `4`-byte zero write at `0x13c68` for `0xF0010400` is therefore not reachable as described.
2. **The §5.3 W2 candidate is downgraded to W3.** The SGL does not map adjacent pages on the analyzed host (§4), and the type-5 copy-back writes fixed/reflected content (§5). The baseline's statement that confirmation "would raise the driver to MW3" is not met.
3. **The baseline's `0x600` zero-fill is still the clearest confirmed primitive.** The DCMD path adds a larger fixed zero-fill (`0x1208` via `0x9010000`) at the same `+0xbc` offset, but it does not change target/value control.
4. **The `0x38` minimum buffer and the `+0xbc` start are confirmed** for the DCMD path as well: `0x1c` (`SRB_IO_CONTROL`) + `0x1c` (DCMD header through `+0x34`) = `0x38`.

## 8. Limitations

- **Static only; no controller, no firmware, no dynamic confirmation.** The DCMD opcode table's device-side effect was not observed.
- **Host StorPort version differs from the driver's era.** The `StorPortGetPhysicalAddress` range check was verified on 10.0.19041.6456 only. If an older StorPort lacked the check, the SGL could map out-of-buffer VAs; that would be a W2 DMA mapping and could raise the verdict. This is the main unresolved environmental dependency.
- **Not all DCMD handlers were read.** 5 of ~80 were decompiled. The shared prologue/epilogue and dispatcher are fully traced, but a handler that copies caller data into `_Dst` at a caller-chosen offset cannot be ruled out for the unexamined handlers. None of the sampled handlers did so.
- **Block size inferred.** The 64 KB SCIC block size is inferred from the `0x10000` allocation requests at `0x35038`; the allocator's recorded SGL length was not exhaustively verified. A smaller block lowers the overflow threshold but does not change the value-control analysis.
- **No REA.** This pass is Ghidra/objdump/PE only, per the tool constraint; no REA evidence IDs are available.
- **No exploit code or PoC.** The report describes the field layout and the exact write range only.
