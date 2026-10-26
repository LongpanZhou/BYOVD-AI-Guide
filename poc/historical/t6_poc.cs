// t6_poc.cs - Phase-A dynamic validation PoC for nvhda64v.sys (agent t6; NON-DESTRUCTIVE)
// PHASE-A SCOPE GUARDS (static audit nvhda64v.md as ground truth):
//   * IOCTL 0x264800 is sent EXACTLY ONCE in Phase A, ALWAYS in-bounds:
//     in=12 B + out=32 B => IO-manager METHOD_BUFFERED allocation = max(12,32) = 32 B
//     => the documented 6-byte write (dword@0 + word@4) lands inside the buffer.
//     NO call with max(in,out) < 6 is ever issued by this binary (that is Phase B, staged separately).
//   * 0x26480C / 0x26880C / 0x8DE0004: static audit says registry-only, user buffer ignored.
//   * 0x264804/0x264808/0x268804/0x268808: static audit says fixed 0xC0000002 path, no buffer touch.
//   * No other codes, no oversized buffers anywhere.
// usage: t6_poc.exe <logfile> <cmd> [args...]
//   mkdev <deviceId>       create ROOT devnode (flags=0, parent HTREE\ROOT\0) + status
//   devstat <deviceId>     devnode status/problem
//   open <path> <accHex>   CreateFileW probe
//   singleopen <path>      open -> second concurrent open -> close first -> re-open (single-open proof)
//   sd <path>              open READ_CONTROL + NtQuerySecurityObject -> SDDL string
//   ifenum <guid>          SetupDiGetClassDevs(PRESENT|DEVICEINTERFACE) enumeration for one GUID
//   ifall <filter>         ALL present device interfaces, path filtered by substring
//   qobj <dir> <filter>    NtQueryDirectoryObject listing of kernel object names
//   session <path>         open RW; safe-code battery; ONE in-bounds 0x264800 probe
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class T6Poc
{
    static string Log;

    static void L(string s)
    {
        Console.WriteLine(s);
        try { if (Log != null) File.AppendAllText(Log, s + "\r\n"); } catch { }
    }

    static int Main(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: t6_poc.exe <logfile> <cmd> [args...]"); return 2; }
        Log = args[0];
        try { return Dispatch(args[1], args); }
        catch (Exception e) { L("FATAL " + e.GetType().Name + ": " + e.Message); return 99; }
    }

    static int Dispatch(string cmd, string[] args)
    {
        switch (cmd)
        {
            case "mkdev":      return MkDev(args[2]);
            case "devstat":    return DevStat(args[2]);
            case "open":       return Open(args[2], args[3]);
            case "singleopen": return SingleOpen(args[2]);
            case "sd":         return Sd(args[2]);
            case "ifenum":     return IfEnum(args[2]);
            case "ifall":      return IfAll(args[2]);
            case "qobj":       return QObj(args[2], args[3]);
            case "session":    return Session(args[2]);
            default: L("unknown cmd " + cmd); return 2;
        }
    }

    // ---------------- cfgmgr32 ----------------
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern int CM_Locate_DevNodeW(out uint pdnDevInst, string pDeviceID, uint ulFlags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern int CM_Create_DevNodeW(out uint pdnDevNode, string pDeviceID, uint pnParent, uint ulFlags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern int CM_Get_DevNode_Status(out uint pulStatus, out uint pulProblem, uint dnDevInst, uint ulFlags);

    static int MkDev(string id)
    {
        uint parent;
        int cr = CM_Locate_DevNodeW(out parent, "HTREE\\ROOT\\0", 0);
        L(String.Format("CM_Locate_DevNodeW(HTREE\\ROOT\\0) -> CR=0x{0:X} parentDevnode=0x{1:X}", (uint)cr, parent));
        if (cr != 0) return 3;
        uint dn;
        cr = CM_Create_DevNodeW(out dn, id, parent, 0);
        L(String.Format("CM_Create_DevNodeW({0}, flags=0) -> CR=0x{1:X} devnode=0x{2:X}", id, (uint)cr, dn));
        if (cr != 0) return 4;
        return StatusOf(dn);
    }

    static int StatusOf(uint dn)
    {
        uint st, pr;
        int cr = CM_Get_DevNode_Status(out st, out pr, dn, 0);
        L(String.Format("CM_Get_DevNode_Status(devnode=0x{0:X}) -> CR=0x{1:X} status=0x{2:X} problem=0x{3:X} (dec {4})", dn, (uint)cr, st, pr, pr));
        return 0;
    }

    static int DevStat(string id)
    {
        uint dn;
        int cr = CM_Locate_DevNodeW(out dn, id, 0);
        L(String.Format("CM_Locate_DevNodeW({0}) -> CR=0x{1:X} devnode=0x{2:X}", id, (uint)cr, dn));
        if (cr != 0) return 3;
        return StatusOf(dn);
    }

    // ---------------- kernel32 ----------------
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint desiredAccess, uint shareMode, IntPtr secAttr, uint creationDisposition, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inBuf, uint inLen, byte[] outBuf, uint outLen, out uint bytesReturned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint FormatMessageW(uint flags, IntPtr source, uint msgId, uint langId, StringBuilder buf, uint size, IntPtr args);

    static IntPtr INVALID = (IntPtr)(-1);

    static string ErrText(int err)
    {
        try
        {
            StringBuilder sb = new StringBuilder(1024);
            if (FormatMessageW(0x1000, IntPtr.Zero, (uint)err, 0, sb, 1024, IntPtr.Zero) != 0)
                return sb.ToString().Trim().TrimEnd('\0', '\r', '\n');
        }
        catch { }
        return "";
    }

    static int Open(string path, string accHex)
    {
        uint acc = Convert.ToUInt32(accHex, 16);
        IntPtr h = CreateFileW(path, acc, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        if (h == INVALID)
        {
            L(String.Format("CreateFileW({0}, acc=0x{1:X8}) -> FAIL lastErr={2} ({3})", path, acc, err, ErrText(err)));
            return 1;
        }
        L(String.Format("CreateFileW({0}, acc=0x{1:X8}) -> handle=0x{2:X} OK", path, acc, h.ToInt64()));
        CloseHandle(h);
        L("handle closed");
        return 0;
    }

    // single-open proof, all in one process
    static int SingleOpen(string path)
    {
        L("--- singleopen {0} ---" + path);
        IntPtr h1 = CreateFileW(path, 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        int e1 = Marshal.GetLastWin32Error();
        if (h1 == INVALID)
        {
            L(String.Format("  open#1 -> FAIL lastErr={0} ({1}) - single-open behavior unobservable", e1, ErrText(e1)));
            return 1;
        }
        L(String.Format("  open#1 -> handle=0x{0:X} OK (holding)", h1.ToInt64()));
        IntPtr h2 = CreateFileW(path, 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        int e2 = Marshal.GetLastWin32Error();
        if (h2 == INVALID) L(String.Format("  open#2 (concurrent, 1st held) -> FAIL lastErr={0} ({1})  [single-open EXPECTED: audit says 0xC0000001]", e2, ErrText(e2)));
        else { L(String.Format("  open#2 (concurrent, 1st held) -> handle=0x{0:X} OK (UNEXPECTED - not single-open!)", h2.ToInt64())); CloseHandle(h2); }
        CloseHandle(h1);
        L("  open#1 closed");
        IntPtr h3 = CreateFileW(path, 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        int e3 = Marshal.GetLastWin32Error();
        if (h3 == INVALID) L(String.Format("  open#3 (after #1 closed) -> FAIL lastErr={0} ({1})  [UNEXPECTED if single-open flag clears on close]", e3, ErrText(e3)));
        else { L(String.Format("  open#3 (after #1 closed) -> handle=0x{0:X} OK [single-open flag cleared on close]", h3.ToInt64())); CloseHandle(h3); }
        return 0;
    }

    // ---------------- security descriptor (SDDL) ----------------
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, uint sdRevision, uint info, out IntPtr sddl, out uint sddlLen);
    [DllImport("ntdll.dll")]
    static extern int NtQuerySecurityObject(IntPtr handle, uint info, IntPtr sdBuf, uint bufLen, out uint retLen);

    static int Sd(string path)
    {
        IntPtr h = CreateFileW(path, 0x20000 /*READ_CONTROL*/, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        if (h == INVALID)
        {
            L(String.Format("SD probe {0} -> open FAIL lastErr={1} ({2}) (no SD query possible)", path, err, ErrText(err)));
            return 1;
        }
        uint SD_REVISION = 1, INFO = 0x7 /*OWNER|GROUP|DACL*/;
        uint need = 0, retLen;
        NtQuerySecurityObject(h, INFO, IntPtr.Zero, 0, out need);
        IntPtr buf = Marshal.AllocHGlobal((int)need + 64);
        int st = NtQuerySecurityObject(h, INFO, buf, need + 64, out retLen);
        if (st != 0)
        {
            L(String.Format("SD probe {0} -> NtQuerySecurityObject FAIL 0x{1:X8}", path, st));
        }
        else
        {
            IntPtr sddl; uint sddlLen;
            if (ConvertSecurityDescriptorToStringSecurityDescriptorW(buf, SD_REVISION, INFO, out sddl, out sddlLen))
            {
                L(String.Format("SD probe {0} -> SDDL: {1}", path, Marshal.PtrToStringUni(sddl)));
                Marshal.FreeHGlobal(sddl);
            }
            else L(String.Format("SD probe {0} -> SDDL convert FAIL err={1}", path, Marshal.GetLastWin32Error()));
        }
        Marshal.FreeHGlobal(buf);
        CloseHandle(h);
        return 0;
    }

    // ---------------- Phase-A IOCTL battery ----------------
    static int Session(string path)
    {
        IntPtr h = CreateFileW(path, 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        if (h == INVALID)
        {
            L(String.Format("SESSION OPEN {0} -> FAIL lastErr={1} ({2})", path, err, ErrText(err)));
            return 2;  // open failed: NO IOCTL sent, zero 0x264800 calls made
        }
        L(String.Format("SESSION OPEN {0} -> handle=0x{1:X} OK (GENERIC_READ|GENERIC_WRITE, share=0)", path, h.ToInt64()));

        // ---- safe registry-only codes first (static audit: buffer ignored entirely) ----
        L("--- safe registry-only codes (audit: 'pure registry reads/writes of the adapter own values; ignore the user buffer') ---");
        Call(h, 0x26480C, null, 32, "FUN_1400121E0 registry-only code");
        Call(h, 0x26880C, null, 32, "FUN_140013A50 registry-only code");
        Call(h, 0x8DE0004, null, 32, "FUN_140013930 registry-only code");

        // ---- dispatcher-routing codes (audit: fixed 0xC0000002 path, no buffer touch) ----
        L("--- routing codes (audit: status 0xC0000002 path, no buffer touch) ---");
        Call(h, 0x264804, null, 32, "routing probe");
        Call(h, 0x264808, null, 32, "routing probe");
        Call(h, 0x268804, null, 32, "routing probe");
        Call(h, 0x268808, null, 32, "routing probe");

        // ---- THE ONE 0x264800 acceptance probe (in-bounds by construction) ----
        L("--- 0x264800 acceptance probe (THE ONLY call of this code in Phase A) ---");
        L("  input  (12 B): zeros (audit: handler ignores input; content irrelevant)");
        L("  output (32 B): 0x20 => METHOD_BUFFERED allocation = max(12,32) = 32 B >= 6 B documented write => IN-BOUNDS");
        byte[] inp = new byte[12];
        Call(h, 0x264800, inp, 32, "acceptance probe (in-bounds: 6-byte write lands inside a 32-B system buffer)");

        CloseHandle(h);
        L("session handle closed");
        return 0;
    }

    static void Call(IntPtr h, uint code, byte[] input, uint outLen, string what)
    {
        byte[] outB = new byte[outLen];
        for (int i = 0; i < outLen; i++) outB[i] = 0xEE; // canary fill (in-bounds write indicator)
        uint ret = 0;
        bool ok = DeviceIoControl(h, code, input, (uint)(input == null ? 0 : input.Length), outB, outLen, out ret, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        L(String.Format("IOCTL 0x{0:X8}  [{1}]", code, what));
        L(String.Format("  ok={0} lastErr={1} ({2}) bytesReturned={3}", ok, err, ErrText(err), ret));
        L("  returned bytes : " + HexDump(outB, (int)ret));
        L("  full buffer    : " + HexDump(outB, outB.Length));
    }

    static string HexDump(byte[] b, int n)
    {
        if (b == null || n <= 0) return "<none>";
        n = Math.Min(n, b.Length);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.AppendFormat("{0:x2} ", b[i]);
        return sb.ToString().TrimEnd();
    }

    // ---------------- setupapi ----------------
    [StructLayout(LayoutKind.Sequential)]
    struct SP_DEVICE_INTERFACE_DATA { public int cbSize; public Guid InterfaceClassGuid; public uint Flags; public IntPtr Reserved; }

    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    struct SP_DEVICE_INTERFACE_DETAIL_DATA_W
    {
        public int cbSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 500)]
        public string DevicePath;
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr SetupDiGetClassDevsW(IntPtr classGuid, IntPtr enumerator, IntPtr hwndParent, uint flags);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiEnumDeviceInterfaces(IntPtr hDevInfo, IntPtr devInfo, IntPtr interfaceClassGuid, int memberIndex, ref SP_DEVICE_INTERFACE_DATA ifaceData);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiEnumDeviceInterfacesG(IntPtr hDevInfo, IntPtr devInfo, ref Guid interfaceClassGuid, int memberIndex, ref SP_DEVICE_INTERFACE_DATA ifaceData);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiGetDeviceInterfaceDetailW(IntPtr hDevInfo, ref SP_DEVICE_INTERFACE_DATA ifaceData, ref SP_DEVICE_INTERFACE_DETAIL_DATA_W detailData, uint detailSize, out uint requiredSize, IntPtr devInfoData);
    [DllImport("setupapi.dll", SetLastError = true)]
    static extern bool SetupDiDestroyDeviceInfoList(IntPtr hDevInfo);

    static int IfEnum(string guidStr)
    {
        Guid g = new Guid(guidStr);
        IntPtr gPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
        Marshal.StructureToPtr(g, gPtr, false);
        IntPtr set = SetupDiGetClassDevsW(gPtr, IntPtr.Zero, IntPtr.Zero, 0x12); // DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
        int err = Marshal.GetLastWin32Error();
        Marshal.FreeHGlobal(gPtr);
        if (set == IntPtr.Zero || set == INVALID)
        {
            L(String.Format("SetupDiGetClassDevsW({0}) -> FAIL lastErr={1}", g, err));
            return 1;
        }
        int n = 0;
        while (true)
        {
            SP_DEVICE_INTERFACE_DATA d = new SP_DEVICE_INTERFACE_DATA();
            d.cbSize = Marshal.SizeOf(typeof(SP_DEVICE_INTERFACE_DATA));
            if (!SetupDiEnumDeviceInterfacesG(set, IntPtr.Zero, ref g, n, ref d)) break;
            uint req;
            SP_DEVICE_INTERFACE_DETAIL_DATA_W det = new SP_DEVICE_INTERFACE_DETAIL_DATA_W();
            det.cbSize = (IntPtr.Size == 8) ? 8 : 6;
            if (!SetupDiGetDeviceInterfaceDetailW(set, ref d, ref det, (uint)Marshal.SizeOf(det), out req, IntPtr.Zero))
                L(String.Format("interface[{0}] flags=0x{1:X} ACTIVE={2} detailFail err={3}", n, d.Flags, (d.Flags & 1) != 0, Marshal.GetLastWin32Error()));
            else
                L(String.Format("interface[{0}] flags=0x{1:X} ACTIVE={2} path={3}", n, d.Flags, (d.Flags & 1) != 0, det.DevicePath));
            n++;
        }
        L(String.Format("interfaces for {0}: count={1}", g, n));
        SetupDiDestroyDeviceInfoList(set);
        return 0;
    }

    static int IfAll(string filter)
    {
        IntPtr set = SetupDiGetClassDevsW(IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0x12); // ALL classes | PRESENT | DEVICEINTERFACE
        int err = Marshal.GetLastWin32Error();
        if (set == IntPtr.Zero || set == INVALID)
        {
            L(String.Format("SetupDiGetClassDevsW(all) -> FAIL lastErr={1}", err));
            return 1;
        }
        int n = 0, shown = 0;
        while (true)
        {
            SP_DEVICE_INTERFACE_DATA d = new SP_DEVICE_INTERFACE_DATA();
            d.cbSize = Marshal.SizeOf(typeof(SP_DEVICE_INTERFACE_DATA));
            if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, IntPtr.Zero, n, ref d)) break;
            uint req;
            SP_DEVICE_INTERFACE_DETAIL_DATA_W det = new SP_DEVICE_INTERFACE_DETAIL_DATA_W();
            det.cbSize = (IntPtr.Size == 8) ? 8 : 6;
            if (SetupDiGetDeviceInterfaceDetailW(set, ref d, ref det, (uint)Marshal.SizeOf(det), out req, IntPtr.Zero))
            {
                string p = det.DevicePath;
                if (String.IsNullOrEmpty(filter) || p.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    shown++;
                    L(String.Format("interface[{0}] flags=0x{1:X} ACTIVE={2} path={3}", n, d.Flags, (d.Flags & 1) != 0, p));
                }
            }
            n++;
        }
        L(String.Format("ALL present interfaces: total={0}; shown(matching '{1}')={2}", n, filter, shown));
        SetupDiDestroyDeviceInfoList(set);
        return 0;
    }

    // ---------------- ntdll: \Device / \GLOBAL?? object directories ----------------
    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }
    [DllImport("ntdll.dll")]
    static extern int NtOpenDirectoryObject(out IntPtr dirHandle, uint desiredAccess, ref OBJECT_ATTRIBUTES oa);
    [DllImport("ntdll.dll")]
    static extern int NtQueryDirectoryObject(IntPtr dirHandle, IntPtr buffer, int length, bool returnSingleEntry, bool restartScan, ref int context, out int returnLength);
    [DllImport("ntdll.dll")]
    static extern int NtClose(IntPtr handle);

    static int QObj(string dir, string filter)
    {
        StringBuilder sb = new StringBuilder();
        UNICODE_STRING us = new UNICODE_STRING();
        us.Buffer = Marshal.StringToHGlobalUni(dir);
        us.Length = (ushort)(dir.Length * 2);
        us.MaximumLength = (ushort)((dir.Length + 1) * 2);
        IntPtr namePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        Marshal.StructureToPtr(us, namePtr, false);
        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
        oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        oa.ObjectName = namePtr;
        oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
        IntPtr h;
        int st = NtOpenDirectoryObject(out h, 0x1 /*DIRECTORY_QUERY*/ | 0x2 /*TRAVERSE*/, ref oa);
        if (st != 0)
        {
            sb.Insert(0, String.Format("NtOpenDirectoryObject({0}) -> 0x{1:X8} FAIL\r\n", dir, st));
            L(sb.ToString());
            return 1;
        }
        int ctx = 0, count = 0, matched = 0;
        IntPtr buf = Marshal.AllocHGlobal(8192);
        while (true)
        {
            int retLen;
            st = NtQueryDirectoryObject(h, buf, 8192, true, ctx == 0, ref ctx, out retLen);
            if (st != 0) break;
            UNICODE_STRING name = (UNICODE_STRING)Marshal.PtrToStructure(buf, typeof(UNICODE_STRING));
            UNICODE_STRING type = (UNICODE_STRING)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + Marshal.SizeOf(typeof(UNICODE_STRING))), typeof(UNICODE_STRING));
            string nm = (name.Buffer != IntPtr.Zero && name.Length > 0) ? Marshal.PtrToStringUni(name.Buffer, name.Length / 2) : "";
            string tn = (type.Buffer != IntPtr.Zero && type.Length > 0) ? Marshal.PtrToStringUni(type.Buffer, type.Length / 2) : "";
            if (nm.Length == 0 && tn.Length == 0) break;
            count++;
            if (filter == null || filter.Length == 0 || nm.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                matched++;
                sb.AppendFormat("  {0}  [{1}]\r\n", nm, tn);
            }
        }
        NtClose(h);
        sb.Insert(0, String.Format("NtOpenDirectoryObject({0}) OK; entries={1}; matches('{2}')={3}; endStatus=0x{4:X8}\r\n", dir, count, filter, matched, st));
        L(sb.ToString());
        return 0;
    }
}
