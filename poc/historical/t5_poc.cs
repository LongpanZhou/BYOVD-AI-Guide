// t5_poc.cs - Phase-A dynamic validation PoC for vpnva64-6.sys (agent t5; NON-DESTRUCTIVE)
// PHASE-A SCOPE (per static audit vpnva.md + phase-A directive):
//   * Only audit-documented codes, small well-formed buffers:
//       0x22201C (query, out>=0x18)   0x222004 (in 8B, two ints in [8,0x100])
//       0x222030 (in 8B, link-speed + media indication)
//       0x22200A (METHOD_IN_DIRECT MDL-map) - issued exactly twice: a pre-0x222004
//         gate probe (audit says it must fail; if static is wrong and it parks, the
//         documented cancel routine resolves it), and once with {8,8} config.
//         Ring = 0x8000 user bytes (>= count*0x800 descriptor span for count=8).
//       0x222027 (METHOD_NEITHER, NULL buffers, receive-pump timer trigger)
//       0x222010 / 0x222018 / 0x222080 / 0x222084 (buffered state/indication codes)
//       0x22200C (disconnect cleanup, exercised last)
//   * SKIPPED (documented as NOT TESTED): 0x222023 (parks IRP, completion write to
//     user ptr with unknown length enforcement), 0x22202B (timer semantics
//     undocumented), 0x22202F (parks IRP with NO cancel routine - static hang risk).
//   * Parked-IRP discipline: every async call gets a bounded wait; timeout ->
//     CancelIoEx (targeted) -> reap. Nothing is left pending when the session ends.
// usage: t5_poc.exe <logfile> <cmd> [args...]
//   mkdev <deviceId>        create ROOT devnode (flags=0, parent HTREE\ROOT\0)
//   devstat <deviceId>      devnode status/problem
//   open <path> <accHex>    CreateFileW probe
//   sd <path>               open MAXIMUM_ALLOWED + dump security descriptor as SDDL
//   qobj <dir> <filter>     NtQueryDirectoryObject listing of kernel object names
//   session <path>          Phase-A IOCTL battery (progressive log)
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class T5Poc
{
    static string Log;

    static void L(string s)
    {
        Console.WriteLine(s);
        try { if (Log != null) File.AppendAllText(Log, s + "\r\n"); } catch { }
    }

    static int Main(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: t5_poc.exe <logfile> <cmd> [args...]"); return 2; }
        Log = args[0];
        try { return Dispatch(args[1], args); }
        catch (Exception e) { L("FATAL " + e.GetType().Name + ": " + e.Message); return 99; }
    }

    static int Dispatch(string cmd, string[] args)
    {
        switch (cmd)
        {
            case "mkdev":   return MkDev(args[2]);
            case "devstat": return DevStat(args[2]);
            case "open":    return Open(args[2], args[3]);
            case "sd":      return Sd(args[2]);
            case "qobj":    return QObj(args[2], args[3]);
            case "instdev": return InstDev(args[2], args[3]);
            case "session": return Session(args[2]);
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
    static extern bool DeviceIoControl(IntPtr h, uint code, IntPtr inBuf, uint inLen, IntPtr outBuf, uint outLen, IntPtr bytesReturned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint FormatMessageW(uint flags, IntPtr source, uint msgId, uint langId, StringBuilder buf, uint size, IntPtr args);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateEventW(IntPtr attrs, bool manualReset, bool initialState, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr h, int ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetOverlappedResult(IntPtr h, IntPtr ov, out uint bytes, bool wait);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CancelIoEx(IntPtr h, IntPtr overlapped);

    [StructLayout(LayoutKind.Sequential)]
    struct OVERLAPPED { public IntPtr Internal; public IntPtr InternalHigh; public uint Offset; public uint OffsetHigh; public IntPtr hEvent; }

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

    // ---------------- newdev: full INF install for matching devices ----------------
    [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool UpdateDriverForPlugAndPlayDevicesW(IntPtr hwndParent, string hardwareId, string fullInfPath, uint installFlags, out bool rebootRequired);

    static int InstDev(string hwid, string inf)
    {
        bool reboot;
        L(String.Format("UpdateDriverForPlugAndPlayDevices(hwid='{0}', inf='{1}', INSTALLFLAG_FORCE)", hwid, inf));
        bool ok = UpdateDriverForPlugAndPlayDevicesW(IntPtr.Zero, hwid, inf, 0x1 /*INSTALLFLAG_FORCE*/, out reboot);
        int err = Marshal.GetLastWin32Error();
        L(String.Format("  -> ok={0} err={1} ({2}) rebootRequired={3}", ok, err, ErrText(err), reboot));
        return ok ? 0 : 1;
    }

    // ---------------- security descriptor dump ----------------
    [DllImport("ntdll.dll")]
    static extern int NtQuerySecurityObject(IntPtr handle, uint secInfo, IntPtr sd, uint len, out uint retLen);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, uint rev, uint info, out IntPtr str, out uint len);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LocalFree(IntPtr h);

    static int Sd(string path)
    {
        // MAXIMUM_ALLOWED: gets READ_CONTROL if the DACL permits it; fails otherwise.
        IntPtr h = CreateFileW(path, 0x02000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        if (h == INVALID)
        {
            L(String.Format("SD QUERY: CreateFileW({0}, MAXIMUM_ALLOWED=0x02000000) -> FAIL lastErr={1} ({2}) - cannot query SD through a handle", path, err, ErrText(err)));
            return 1;
        }
        L(String.Format("SD QUERY: CreateFileW({0}, MAXIMUM_ALLOWED) -> handle=0x{1:X} OK", path, h.ToInt64()));
        uint retLen;
        IntPtr sdBuf = Marshal.AllocHGlobal(1024);
        int st = NtQuerySecurityObject(h, 7 /*OWNER|GROUP|DACL*/, sdBuf, 1024, out retLen);
        L(String.Format("NtQuerySecurityObject(OWNER|GROUP|DACL) -> 0x{0:X8} retLen={1}", (uint)st, retLen));
        if (st == 0)
        {
            IntPtr sddl; uint slen;
            bool ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(sdBuf, 1, 7, out sddl, out slen);
            if (ok) { L("SDDL: " + Marshal.PtrToStringUni(sddl)); LocalFree(sddl); }
            else L("SDDL conversion failed, lastErr=" + Marshal.GetLastWin32Error());
        }
        Marshal.FreeHGlobal(sdBuf);
        CloseHandle(h);
        L("SD QUERY handle closed");
        return 0;
    }

    // ---------------- Phase-A IOCTL battery ----------------
    static int Session(string path)
    {
        IntPtr h = CreateFileW(path, 0xC0000000, 0, IntPtr.Zero, 3, 0x40000000 /*FILE_FLAG_OVERLAPPED*/, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        if (h == INVALID)
        {
            L(String.Format("SESSION OPEN {0} -> FAIL lastErr={1} ({2})", path, err, ErrText(err)));
            L("SESSION DONE rc=2 (no IOCTL sent)");
            return 2;
        }
        L(String.Format("SESSION OPEN {0} -> handle=0x{1:X} OK (GENERIC_READ|GENERIC_WRITE, share=0, FILE_FLAG_OVERLAPPED)", path, h.ToInt64()));

        byte[] ring = new byte[0x8000];
        for (int i = 0; i < ring.Length; i++) ring[i] = (byte)(0x5A ^ (i & 0xFF));

        // ---- S1: identity/state queries (pure, bounded) ----
        L("--- S1: state queries ---");
        CallOv(h, 0x22201C, null, 0x18, 5000, "0x22201C query out=0x18 (expect 24 B {ctx+0x1A8 filter, +0x190, +0xF0}, Information=0x18)");
        CallOv(h, 0x22201C, null, 0x10, 5000, "0x22201C undersized out=0x10 (expect failure status)");

        // ---- S4.0: MDL-map gate probe BEFORE 0x222004 (audit: requires ctx+0x30/0x34 != 0) ----
        L("--- S4.0: 0x22200A gate probe BEFORE 0x222004 (expect failure per audit) ---");
        CallOv(h, 0x22200A, null, (uint)ring.Length, 8000, "0x22200A pre-config gate probe (0x8000 B ring; expect fail, else park+cancel)");

        // ---- S2: frame config (bounded by driver to [8,0x100]) ----
        L("--- S2: 0x222004 frame count/size config ---");
        CallOv(h, 0x222004, new byte[] { 8, 0, 0, 0, 8, 0, 0, 0 }, 0, 5000, "0x222004 in=8B {count=8, size=8} (expect OK)");
        CallOv(h, 0x222004, new byte[] { 4, 0, 0, 0, 1, 1, 0, 0 }, 0, 5000, "0x222004 in=8B {4, 0x101} out-of-range ints (expect 0xC000000D)");

        // ---- S3: link-speed + media indication (8 B stored to ctx+0x28, bounded) ----
        L("--- S3: 0x222030 link-speed / media indication ---");
        CallOv(h, 0x222030, new byte[] { 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 }, 0, 5000, "0x222030 in=8B value=0x10000 (stores ctx+0x28, media connect indication)");

        // ---- S4: THE MDL MAP + park + pump ----
        L("--- S4: 0x22200A MDL->system-VA map (ring 0x8000 B, park, pump via 0x222027) ---");
        L("  ring pattern: byte[i] = 0x5A ^ (i & 0xFF) for 0x8000 bytes");
        GCHandle ringPin = GCHandle.Alloc(ring, GCHandleType.Pinned);
        IntPtr ringPtr = ringPin.AddrOfPinnedObject();

        OVERLAPPED ov = new OVERLAPPED();
        ov.hEvent = CreateEventW(IntPtr.Zero, true, false, null);
        GCHandle ovPin = GCHandle.Alloc(ov, GCHandleType.Pinned);
        IntPtr ovPtr = ovPin.AddrOfPinnedObject();

        L("  >>> pre-call marker " + DateTime.UtcNow.ToString("o"));
        bool ok = DeviceIoControl(h, 0x22200A, IntPtr.Zero, 0, ringPtr, (uint)ring.Length, IntPtr.Zero, ovPtr);
        int errA = Marshal.GetLastWin32Error();
        L(String.Format("  DeviceIoControl(0x22200A, in=0/NULL, out=ring 0x8000) -> ok={0} lastErr={1} ({2})", ok, errA, ErrText(errA)));
        if (!ok && errA == 997)
            L("  -> ERROR_IO_PENDING: IRP QUEUED/PARKED (audit: parked at ctx+0x48, cancel routine FUN_1400038c0)");
        bool resolved = false; uint bytesA = 0; uint stA = 0;
        if (ok) { resolved = true; stA = 0; L("  -> completed synchronously (park NOT observed)"); }
        else if (errA == 997)
        {
            resolved = Reap(h, ovPtr, ov.hEvent, 10000, "parked 0x22200A (wait 1: 10 s)", out bytesA, out stA);
        }
        else { resolved = true; stA = (uint)errA; }

        if (!resolved)
        {
            L("  still parked -> trigger receive pump 0x222027 while parked");
            CallOv(h, 0x222027, null, 0, 5000, "0x222027 METHOD_NEITHER pump trigger (NULL buffers, NdisSetTimerObject ctx+0xD0)");
            resolved = Reap(h, ovPtr, ov.hEvent, 10000, "parked 0x22200A (wait 2: 10 s after pump)", out bytesA, out stA);
        }
        if (!resolved)
        {
            L("  still parked after pump -> CancelIoEx (targeted; documented cancel path FUN_1400038c0)");
            bool c = CancelIoEx(h, ovPtr);
            int ce = Marshal.GetLastWin32Error();
            L(String.Format("  CancelIoEx -> {0} lastErr={1} ({2})", c, ce, ErrText(ce)));
            resolved = Reap(h, ovPtr, ov.hEvent, 10000, "parked 0x22200A (wait 3: after cancel)", out bytesA, out stA);
            if (!resolved) L("  !!! IRP STILL PENDING AFTER CANCEL (cancel routine not effective?)");
        }
        L(String.Format("  0x22200A FINAL: status=0x{0:X8} bytes={1}", stA, bytesA));
        ovPin.Free();
        CloseHandle(ov.hEvent);
        ringPin.Free();

        // ---- S5: documented state/indication codes (post-main-test, one at a time) ----
        L("--- S5: buffered state/indication codes ---");
        CallOv(h, 0x222010, new byte[] { 0, 0, 0, 0 }, 4, 5000, "0x222010 buffered state change (FUN_140001cd0(0))");
        CallOv(h, 0x222018, new byte[] { 0, 0, 0, 0 }, 4, 5000, "0x222018 buffered state change (FUN_140001cd0(0xF))");
        CallOv(h, 0x222080, null, 0, 5000, "0x222080 connect indication (0x4001000B)");
        CallOv(h, 0x222084, null, 0, 5000, "0x222084 disconnect indication (0x4001000C)");

        // ---- S6: post-state query + cleanup code ----
        L("--- S6: post-state query + documented cleanup ---");
        CallOv(h, 0x22201C, null, 0x18, 5000, "0x22201C post-battery state query");
        CallOv(h, 0x22200C, null, 0, 5000, "0x22200C disconnect cleanup (FUN_140003320)");

        CloseHandle(h);
        L("SESSION DONE rc=0");
        return 0;
    }

    static bool Reap(IntPtr h, IntPtr ovPtr, IntPtr ev, int waitMs, string label, out uint bytes, out uint status)
    {
        bytes = 0; status = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < waitMs)
        {
            if (WaitForSingleObject(ev, 250) == 0)
            {
                bool ok = GetOverlappedResult(h, ovPtr, out bytes, false);
                int err = Marshal.GetLastWin32Error();
                status = (uint)Marshal.ReadInt32(ovPtr);
                L(String.Format("  {0}: COMPLETED ok={1} err={2} NTSTATUS=0x{3:X8} bytes={4}", label, ok, err, status, bytes));
                return true;
            }
        }
        L("  " + label + ": STILL PENDING after " + waitMs + " ms");
        return false;
    }

    static void CallOv(IntPtr h, uint code, byte[] input, uint outLen, int waitMs, string what)
    {
        byte[] outB = (outLen > 0) ? new byte[outLen] : null;
        for (int i = 0; outB != null && i < outB.Length; i++) outB[i] = 0xEE; // canary fill
        GCHandle pinOut = GCHandle.Alloc(outB, GCHandleType.Pinned);
        GCHandle pinIn = GCHandle.Alloc(input, GCHandleType.Pinned);
        IntPtr inPtr = (input != null) ? pinIn.AddrOfPinnedObject() : IntPtr.Zero;
        IntPtr outPtr = (outB != null) ? pinOut.AddrOfPinnedObject() : IntPtr.Zero;

        OVERLAPPED ov = new OVERLAPPED();
        ov.hEvent = CreateEventW(IntPtr.Zero, true, false, null);
        GCHandle ovPin = GCHandle.Alloc(ov, GCHandleType.Pinned);
        IntPtr ovPtr = ovPin.AddrOfPinnedObject();

        L(String.Format("IOCTL 0x{0:X8}  [{1}]", code, what));
        L(String.Format("  inLen={0} outLen={1}", input == null ? 0 : input.Length, outLen));
        L("  >>> pre-call marker " + DateTime.UtcNow.ToString("o"));   // flushed BEFORE the kernel call
        bool ok = DeviceIoControl(h, code, inPtr, (uint)(input == null ? 0 : input.Length), outPtr, outLen, IntPtr.Zero, ovPtr);
        int err = Marshal.GetLastWin32Error();
        if (!ok && err == 997)
        {
            L("  -> ERROR_IO_PENDING (queued/parked); waiting up to " + waitMs + " ms");
            uint bytes, status;
            bool resolved = Reap(h, ovPtr, ov.hEvent, waitMs, "  queued call", out bytes, out status);
            if (!resolved)
            {
                bool c = CancelIoEx(h, ovPtr);
                int ce = Marshal.GetLastWin32Error();
                L(String.Format("  CancelIoEx -> {0} lastErr={1} ({2})", c, ce, ErrText(ce)));
                resolved = Reap(h, ovPtr, ov.hEvent, 5000, "  after cancel", out bytes, out status);
                if (!resolved) L("  !!! STILL PENDING AFTER CANCEL");
            }
            DumpOut(outB);
        }
        else if (!ok)
        {
            uint status = (uint)Marshal.ReadInt32(ovPtr);
            L(String.Format("  -> FAIL lastErr={0} (0x{0:X}) NTSTATUS=0x{1:X8} ({2})", err, status, ErrText(err)));
        }
        else
        {
            uint status = (uint)Marshal.ReadInt32(ovPtr);
            L("  -> completed synchronously NTSTATUS=0x" + status.ToString("X8"));
            DumpOut(outB);
        }
        ovPin.Free();
        CloseHandle(ov.hEvent);
        pinOut.Free();
        pinIn.Free();
    }

    static void DumpOut(byte[] outB)
    {
        if (outB == null || outB.Length == 0) return;
        StringBuilder sb = new StringBuilder("  out buffer: ");
        int n = Math.Min(outB.Length, 64);
        for (int i = 0; i < n; i++) sb.AppendFormat("{0:x2} ", outB[i]);
        if (outB.Length > n) sb.AppendFormat("... (+{0} more)", outB.Length - n);
        L(sb.ToString().TrimEnd());
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
        return (matched > 0) ? 0 : 1;
    }
}
