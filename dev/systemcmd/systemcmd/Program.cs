using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace systemcmd_cs
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID
        {
            internal int LowPart;
            internal int HighPart;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TOKEN_PRIVILEGES
        {
            internal Int32 PrivilegeCount;
            internal LUID Luid;
            internal Int32 Attributes;
        }

        private enum ProcessAccessTypes
        {
            PROCESS_TERMINATE = 0x00000001,
            PROCESS_CREATE_THREAD = 0x00000002,
            PROCESS_SET_SESSIONID = 0x00000004,
            PROCESS_VM_OPERATION = 0x00000008,
            PROCESS_VM_READ = 0x00000010,
            PROCESS_VM_WRITE = 0x00000020,
            PROCESS_DUP_HANDLE = 0x00000040,
            PROCESS_CREATE_PROCESS = 0x00000080,
            PROCESS_SET_QUOTA = 0x00000100,
            PROCESS_SET_INFORMATION = 0x00000200,
            PROCESS_QUERY_INFORMATION = 0x00000400,
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            SYNCHRONIZE = 0x00100000,
            PROCESS_ALL_ACCESS = PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION |
              PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA |
              PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE
        }



        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;

        public const UInt32 LOGON_NETCREDENTIALS_ONLY = 0x00000002;

        enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }


        enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }


        public enum ACCESS_MASK : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,

            STANDARD_RIGHTS_REQUIRED = 0x000F0000,

            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,

            STANDARD_RIGHTS_ALL = 0x001F0000,

            SPECIFIC_RIGHTS_ALL = 0x0000FFFF,

            ACCESS_SYSTEM_SECURITY = 0x01000000,

            MAXIMUM_ALLOWED = 0x02000000,

            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,

            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,

            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,

            WINSTA_ALL_ACCESS = 0x0000037F
        }


        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        public enum CreationFlags

        {

            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);


        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AdjustTokenPrivileges(IntPtr tokenhandle, [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges, [MarshalAs(UnmanagedType.Struct)] ref TOKEN_PRIVILEGES newstate, uint bufferlength, IntPtr previousState, IntPtr returnlength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        static bool EnablePrivilege()
        {
            IntPtr currenthandle = (IntPtr)Process.GetCurrentProcess().Handle;
            IntPtr hToken = IntPtr.Zero;
            LUID luidValue = new LUID();
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            TOKEN_PRIVILEGES PreviousState = new TOKEN_PRIVILEGES();
            UInt32 ReturnLengthInBytes = (UInt32)IntPtr.Zero;
            Console.WriteLine("[*] The Current Handle:" + currenthandle);
            bool wdret = OpenProcessToken(currenthandle, TOKEN_ADJUST_PRIVILEGES, out hToken);
            if (wdret == false)
            {
                Console.WriteLine("[-] OpenProcessToken Failre,Error Code:" + Marshal.GetLastWin32Error());
                return false;
            }
            Console.WriteLine("[*] The Token:" + hToken);
            bool privilege = LookupPrivilegeValue(null, "SeDebugPrivilege", ref luidValue);
            if (privilege == false)
            {
                Console.WriteLine("[-] LookupPrivilegeValue Failure,Error Code:" + Marshal.GetLastWin32Error());
                return false;
            }
            Console.WriteLine("[*] LookupPrivilegeValue Sucess");

            tp.PrivilegeCount = 1;
            tp.Luid = luidValue;
            tp.Attributes = SE_PRIVILEGE_ENABLED;
            bool bRet = AdjustTokenPrivileges(hToken, false, ref tp, (uint)IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (bRet == false)
            {
                Console.WriteLine("[-] AdjustTokenPrivileges Failure,Error Code:" + Marshal.GetLastWin32Error());
                return false;
            }
            Console.WriteLine("[*] AdjustTokenPrivileges Sucess");
            return true;
        }

        static int FindPid(string processname)
        {
            Process[] process = Process.GetProcessesByName(processname);
            foreach (Process instace in process)
            {
                return instace.Id;
            }
            return 0;
        }

        static IntPtr GetAccessToken(int pid)
        {
            IntPtr currentProcess = IntPtr.Zero;
            IntPtr Asstoken = IntPtr.Zero;
            currentProcess = OpenProcess((uint)ProcessAccessTypes.PROCESS_QUERY_INFORMATION, true, (uint)pid);
            if (currentProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] OpenProcess Target Failure,Error Code:" + Marshal.GetLastWin32Error());
                return IntPtr.Zero;
            }
            Console.WriteLine("[*] OpenProcess Target Sucess,OpenProcess:" + currentProcess);
            bool wdret = OpenProcessToken(currentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, out Asstoken);
            if (wdret == false)
            {
                Console.WriteLine("[-] OpenProcessToken Failre,Error Code:" + Marshal.GetLastWin32Error());
                return IntPtr.Zero;
            }
            Console.WriteLine("[*] OpenProcessToken Sucess:" + Asstoken);
            return Asstoken;
        }

        static bool Runprocess(IntPtr Token, string executepath)
        {
            bool dtx = DuplicateTokenEx(Token, (uint)ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out Token);
            if (dtx == false)
            {
                Console.WriteLine("[-] DuplicateTokenEx Failure,Error Code:" + Marshal.GetLastWin32Error());
                return false;
            }
            Console.WriteLine("[*] DuplicateTokenEx Sucess,token:" + Token);
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool ret = CreateProcessWithTokenW(Token, LOGON_NETCREDENTIALS_ONLY, executepath, null, CreationFlags.NewConsole, IntPtr.Zero, null, ref si, out pi);
            if (ret == false)
            {
                Console.WriteLine("[-] CreateProcessWithTokenW Failure,Error Code:" + Marshal.GetLastWin32Error());
                return false;
            }
            Console.WriteLine("[+] CreateProcessWithTokenW Sucess");
            return true;

        }

        static int Main(string[] args)
        {
            string processname;
            string executepath;
            if (args.Length == 2)
            {
                processname = args[0];

                executepath = args[1];
            }
            else
            {
                Console.WriteLine("Example:systemcmd.exe <ProcessID> <ExecutePath>");
                return 1;
            }

            //Console.WriteLine("[*] Find ProcessName:" + processname);
            bool enable = EnablePrivilege();
            if (enable == false)
            {
                Console.WriteLine("[-] Enable Privilege:SeDebugPrivilege Failure");
            }
            else
            {
                int targetpid = int.Parse(processname);
                if (targetpid != 0)
                {
                    Console.WriteLine("[*] The target PID:" + targetpid);
                    IntPtr atoken = GetAccessToken(targetpid);
                    Runprocess(atoken, executepath);
                }
            }
            return 0;

        }
    }
}
