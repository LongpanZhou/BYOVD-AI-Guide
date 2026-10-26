// t7 fuzz PoC — raw NTSTATUS device probes + object-dir inventory + DACL pull
// subcommands (argv[1]=outfile first):
//   qobj <ntdir> <filterRegex>
//   open <winpath> [accHex] [shareHex]
//   ntopen <ntpath> [accHex]
//   dacl <winpath>
//   ioctl <winpath> <codeHex> <inlen> <outlen> [inhex]
//   sweep <winpath> <fnStartHex> <fnEndHex> [inlen] [outlen]
//   wsock
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

class T7 {
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

  [DllImport("ws2_32.dll")] static extern int WSAStartup(short ver, ref WSADATA data);  [DllImport("ws2_32.dll")] static extern int WSACleanup();
  [DllImport("ws2_32.dll")] static extern IntPtr socket(int af, int type, int proto);
  [DllImport("ws2_32.dll")] static extern int closesocket(IntPtr s);
  [DllImport("ws2_32.dll")] static extern int WSAGetLastError();

  [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
  static extern int CM_Locate_DevNodeW(out uint devinst, string deviceId, uint flags);
  [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
  static extern int CM_Create_DevNodeW(out uint devinst, string deviceId, uint parent, uint flags);
  [DllImport("cfgmgr32.dll")]
  static extern int CM_Get_DevNode_Status(out uint status, out uint problem, uint devinst, uint flags);

  [StructLayout(LayoutKind.Sequential)]
  struct WSADATA {
    public short wVersion; public short wHighVersion;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szDescription;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string szSystemStatus;
    public short iMaxSockets; public short iMaxUdpDg; public IntPtr lpVendorInfo;
  }

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

  static ushort ReadUS(IntPtr p) { return (ushort)Marshal.ReadInt16(p); }

  static void USAt(IntPtr baseP, int off, out string s) {
    ushort len = (ushort)Marshal.ReadInt16(baseP, off);
    IntPtr b = Marshal.ReadIntPtr(baseP, off + 8);
    s = (len == 0 || b == IntPtr.Zero) ? "" : Marshal.PtrToStringUni(b, len / 2);
  }

  // ---------- subcommands ----------
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
      // ReturnSingleEntry=TRUE: one entry per call (batch mode AVs on Win10 \Device parsing)
      st = NtQueryDirectoryObject(h, buf, 65536, true, first, ref ctx, out ret);
      first = false;
      if (st != 0 || ret == 0) break;
      for (uint i = 0; i < ret; i++) {
        string n, t; USAt(buf, (int)(i * 32), out n); USAt(buf, (int)(i * 32 + 16), out t);
        if (rx.IsMatch(n)) Log(string.Format("{0} -> {1} [{2}]", dir, n, t));
      }
      if (st == 0x80000000 + 0x65) break; // unlikely; loop breaks on non-zero above
    }
    Log("qobj " + dir + " scan complete (st=0x" + st.ToString("X8") + ")");
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

  static void CmdDacl(string path) {
    IntPtr h = OpenDevWin(path, 0x00020000, 3); // READ_CONTROL
    if (h == new IntPtr(-1) || h == new IntPtr(-2)) {
      Log("dacl " + path + " open err=" + Marshal.GetLastWin32Error() + " (READ_CONTROL)");
      return;
    }
    DaclOf(h, path);
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

  // input struct with an embedded pointer to the caller's OWN committed user page
  static void CmdIoctlSink(string path, uint code, uint structLen, uint ptrOff, uint dword4, uint outLen) {
    IntPtr h = OpenCtl(path);
    if (h == IntPtr.Zero) return;
    IntPtr sink = Marshal.AllocHGlobal(64);           // committed user page (caller-owned)
    for (int i = 0; i < 64; i++) Marshal.WriteByte(sink, i, 0xEE);
    IntPtr inBuf = Marshal.AllocHGlobal((int)structLen);
    for (uint i = 0; i < structLen; i++) Marshal.WriteByte(inBuf, (int)i, 0);
    if (structLen > 4) Marshal.WriteInt32(inBuf, 4, (int)dword4);
    if (ptrOff + 8 <= structLen) Marshal.WriteInt64(inBuf, (int)ptrOff, sink.ToInt64());
    if (outLen == 0) outLen = 0x1000;
    IntPtr outBuf = Marshal.AllocHGlobal((int)outLen);
    for (uint i = 0; i < outLen; i++) Marshal.WriteByte(outBuf, (int)i, 0xEE);
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    int st = NtDeviceIoControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb, code, inBuf, structLen, outBuf, outLen);
    uint info = (uint)iosb.Information.ToInt64();
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 64; i++) sb.Append(Marshal.ReadByte(sink, i).ToString("x2"));
    bool sinkTouched = false; for (int i = 0; i < 64; i++) if (Marshal.ReadByte(sink, i) != 0xEE) { sinkTouched = true; break; }
    Log(string.Format("ioctlsink {0} code=0x{1:X8} in=0x{2:X} ptrOff={3} dword4={4} -> st=0x{5:X8} ret={6}", path, code, structLen, ptrOff, dword4, st, info));
    Log("   sink(user buf) = " + sb + (sinkTouched ? "  <-- DRIVER WROTE TO USER BUF" : " (untouched)"));
    if (info > 0) Log("   out[0.." + Math.Min(info, 64) + "] = " + HexOf(outBuf, info));
    Marshal.FreeHGlobal(sink); Marshal.FreeHGlobal(inBuf); Marshal.FreeHGlobal(outBuf); CloseHandle(h);
  }

  static IntPtr OpenCtl(string path) {
    IntPtr h = OpenDevWin(path, 0x12019F, 3); // FILE_GENERIC_READ|FILE_GENERIC_WRITE-ish (GR|GW mapped)
    if (h == new IntPtr(-1) || h == new IntPtr(-2)) {
      Log("open " + path + " err=" + Marshal.GetLastWin32Error() + " (access 0x12019F)");
      return IntPtr.Zero;
    }
    return h;
  }

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

  static void CmdSweep(string path, uint fnStart, uint fnEnd, uint inLen, uint outLen) {
    IntPtr h = OpenCtl(path);
    if (h == IntPtr.Zero) return;
    IntPtr inBuf = Marshal.AllocHGlobal((int)inLen);
    IntPtr outBuf = Marshal.AllocHGlobal((int)outLen);
    for (uint i = 0; i < inLen; i++) Marshal.WriteByte(inBuf, (int)i, 0);
    IO_STATUS_BLOCK iosb = new IO_STATUS_BLOCK();
    for (uint fn = fnStart; fn <= fnEnd; fn++) {
      uint code = (0x8103u << 16) | (fn << 2) | 0u; // METHOD_BUFFERED, FILE_ANY_ACCESS
      for (uint i = 0; i < outLen; i++) Marshal.WriteByte(outBuf, (int)i, 0xEE);
      iosb = new IO_STATUS_BLOCK();
      int st = NtDeviceIoControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref iosb, code, inBuf, inLen, outBuf, outLen);
      uint info = (uint)iosb.Information.ToInt64();
      StringBuilder sb = new StringBuilder();
      sb.AppendFormat("fn=0x{0:X3} code=0x{1:X8} st=0x{2:X8} ret={3}", fn, code, st, info);
      if (info > 0 && info <= outLen) sb.Append(" out=" + HexOf(outBuf, info));
      Log(sb.ToString());
    }
    Log(string.Format("sweep {0} fn 0x{1:X3}..0x{2:X3} COMPLETE", path, fnStart, fnEnd));
    Marshal.FreeHGlobal(inBuf); Marshal.FreeHGlobal(outBuf); CloseHandle(h);
  }

  static void CmdWsock() {
    WSADATA w = new WSADATA();
    int rc = WSAStartup((short)0x0202, ref w);
    Log("wsock WSAStartup rc=" + rc);
    if (rc != 0) { Log("wsock lasterr=" + WSAGetLastError()); return; }
    foreach (int proto in new int[] { 0, 2, 5 }) {
      foreach (int ty in new int[] { 1, 2 }) { // SOCK_STREAM, SOCK_DGRAM
        IntPtr s = socket(34, ty, proto); // AF_VSOCK=34
        int err = WSAGetLastError();
        Log(string.Format("wsock socket(AF_VSOCK=34, type={0}, proto={1}) -> h=0x{2:X} lasterr={3}", ty, proto, s.ToInt64(), err));
        if (s != new IntPtr(-1) && s != IntPtr.Zero) closesocket(s);
      }
    }
    WSACleanup();
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

  static void Main(string[] args) {
    OUT = args[0];
    Log("t7_poc start " + DateTime.Now.ToString("o"));
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
      } else if (cmd == "dacl") { CmdDacl(args[2]); }
      else if (cmd == "daclnt") { CmdDaclNt(args[2]); }
      else if (cmd == "ioctlsink") {
        uint code = Convert.ToUInt32(args[3], 16);
        uint sl = Convert.ToUInt32(args[4], 16);
        uint po = args.Length > 5 ? Convert.ToUInt32(args[5], 16) : 0x10u;
        uint d4 = args.Length > 6 ? Convert.ToUInt32(args[6], 16) : 4u;
        uint ol = args.Length > 7 ? Convert.ToUInt32(args[7], 16) : 0u;
        CmdIoctlSink(args[2], code, sl, po, d4, ol);
      }
      else if (cmd == "ioctl") {
        uint code = Convert.ToUInt32(args[3], 16);
        uint inLen = Convert.ToUInt32(args[4], 16);
        uint outLen = Convert.ToUInt32(args[5], 16);
        byte[] inb = args.Length > 6 ? HexToBytes(args[6]) : new byte[0];
        CmdIoctl(args[2], code, inLen, outLen, inb);
      } else if (cmd == "sweep") {
        uint f0 = Convert.ToUInt32(args[3], 16);
        uint f1 = Convert.ToUInt32(args[4], 16);
        uint inLen = args.Length > 5 ? Convert.ToUInt32(args[5], 16) : 16u;
        uint outLen = args.Length > 6 ? Convert.ToUInt32(args[6], 16) : 0x1000u;
        CmdSweep(args[2], f0, f1, inLen, outLen);
      } else if (cmd == "wsock") { CmdWsock(); }
      else if (cmd == "mkdev") { CmdMkDev(args[2], args[3]); }
      else if (cmd == "devstat") { CmdDevStat(args[2]); }
      else Log("unknown cmd: " + cmd);
    } catch (Exception e) {
      Log("EXCEPTION: " + e.GetType().Name + ": " + e.Message);
    }
    Log("t7_poc end " + DateTime.Now.ToString("o"));
  }

  static byte[] HexToBytes(string h) {
    if (h.Length % 2 != 0) h = "0" + h;
    byte[] b = new byte[h.Length / 2];
    for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
    return b;
  }
}
