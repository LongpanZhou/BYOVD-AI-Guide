using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

internal static class ObjList
{
    private const uint DIRECTORY_QUERY = 0x0001;
    private const int STATUS_SUCCESS = 0;
    private const int STATUS_NO_MORE_ENTRIES = unchecked((int)0x8000001A);
    private const int STATUS_BUFFER_TOO_SMALL = unchecked((int)0xC0000023);

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_ATTRIBUTES
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_DIRECTORY_INFORMATION
    {
        public UNICODE_STRING Name;
        public UNICODE_STRING TypeName;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtOpenDirectoryObject(out IntPtr DirectoryHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryDirectoryObject(IntPtr DirectoryHandle, IntPtr Buffer, uint Length, bool ReturnSingleEntry,
        bool RestartScan, ref uint Context, out uint ReturnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtClose(IntPtr Handle);

    private static string ReadUnicode(UNICODE_STRING s)
    {
        if (s.Buffer == IntPtr.Zero || s.Length == 0) return string.Empty;
        return Marshal.PtrToStringUni(s.Buffer, s.Length / 2);
    }

    private static void List(string path)
    {
        IntPtr nameBuf = Marshal.StringToHGlobalUni(path);
        IntPtr usBuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        var us = new UNICODE_STRING
        {
            Length = (ushort)(path.Length * 2),
            MaximumLength = (ushort)(path.Length * 2 + 2),
            Buffer = nameBuf
        };
        Marshal.StructureToPtr(us, usBuf, false);
        var oa = new OBJECT_ATTRIBUTES
        {
            Length = (uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
            RootDirectory = IntPtr.Zero,
            ObjectName = usBuf,
            Attributes = 0x40, // OBJ_CASE_INSENSITIVE
            SecurityDescriptor = IntPtr.Zero,
            SecurityQualityOfService = IntPtr.Zero
        };

        IntPtr dir;
        int st = NtOpenDirectoryObject(out dir, DIRECTORY_QUERY, ref oa);
        Marshal.FreeHGlobal(usBuf);
        Marshal.FreeHGlobal(nameBuf);
        if (st != STATUS_SUCCESS)
        {
            Console.WriteLine("[-] open " + path + " status=0x" + st.ToString("X8"));
            return;
        }

        Console.WriteLine("==== " + path + " ====");
        uint ctx = 0;
        uint bufLen = 0x4000;
        IntPtr buf = Marshal.AllocHGlobal((int)bufLen);
        try
        {
            while (true)
            {
                uint retLen;
                st = NtQueryDirectoryObject(dir, buf, bufLen, false, ctx == 0, ref ctx, out retLen);
                if (st == STATUS_NO_MORE_ENTRIES) break;
                if (st == STATUS_BUFFER_TOO_SMALL)
                {
                    bufLen = retLen + 0x1000;
                    Marshal.FreeHGlobal(buf);
                    buf = Marshal.AllocHGlobal((int)bufLen);
                    continue;
                }
                if (st != STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] query status=0x" + st.ToString("X8"));
                    break;
                }
                int entrySize = Marshal.SizeOf(typeof(OBJECT_DIRECTORY_INFORMATION));
                IntPtr p = buf;
                while (true)
                {
                    var info = (OBJECT_DIRECTORY_INFORMATION)Marshal.PtrToStructure(p, typeof(OBJECT_DIRECTORY_INFORMATION));
                    string name = ReadUnicode(info.Name);
                    if (string.IsNullOrEmpty(name)) break;
                    string type = ReadUnicode(info.TypeName);
                    Console.WriteLine("    " + name + "  [" + type + "]");
                    p = new IntPtr(p.ToInt64() + entrySize);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
            NtClose(dir);
        }
    }

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0)
            {
                List(@"\GLOBAL??");
                List(@"\Device");
                List(@"\Device\Global");
            }
            else
            {
                foreach (string a in args) List(a);
            }
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[!] " + ex.Message);
            return 1;
        }
    }
}
