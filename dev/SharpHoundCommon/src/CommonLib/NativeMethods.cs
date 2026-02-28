using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Processors;

namespace SharpHoundCommonLib
{
    [ExcludeFromCodeCoverage]
    public class NativeMethods
    {
        public enum NtStatus
        {
            StatusSuccess = 0x0,
            StatusMoreEntries = 0x105,
            StatusSomeMapped = 0x107,
            StatusInvalidHandle = unchecked((int)0xC0000008),
            StatusInvalidParameter = unchecked((int)0xC000000D),
            StatusAccessDenied = unchecked((int)0xC0000022),
            StatusObjectTypeMismatch = unchecked((int)0xC0000024),
            StatusNoSuchDomain = unchecked((int)0xC00000DF),
            StatusRpcServerUnavailable = unchecked((int)0xC0020017),
            StatusNoSuchAlias = unchecked((int)0xC0000151)
        }

        private const string NetWkstaUserEnumQueryName = "NetWkstaUserEnum";
        private const string NetSessionEnumQueryName = "NetSessionEnum";
        private const string NetWkstaGetInfoQueryName = "NetWkstaGetInfo";

        private const int NetWkstaUserEnumQueryLevel = 1;
        private const int NetSessionEnumLevel = 10;
        private const int NetWkstaGetInfoQueryLevel = 100;
        private readonly ILogger _log;

        public NativeMethods(ILogger log = null)
        {
            _log = log ?? Logging.LogProvider.CreateLogger("NativeMethods");
        }

        public NativeMethods()
        {
            _log = Logging.LogProvider.CreateLogger("NativeMethods");
        }

        public virtual WorkstationInfo100 CallNetWkstaGetInfo(string serverName)
        {
            var ptr = IntPtr.Zero;

            try
            {
                var result = NetWkstaGetInfo(serverName, NetWkstaGetInfoQueryLevel, out ptr);
                if (result != NERR.NERR_Success)
                    throw new APIException
                    {
                        Status = result.ToString(),
                        APICall = NetWkstaGetInfoQueryName
                    };

                var wkstaInfo = Marshal.PtrToStructure<WorkstationInfo100>(ptr);
                return wkstaInfo;
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    NetApiBufferFree(ptr);
            }
        }

        public virtual IEnumerable<SESSION_INFO_10> CallNetSessionEnum(string serverName)
        {
            var ptr = IntPtr.Zero;

            _log.LogTrace("Beginning NetSessionEnum for {ServerName}", serverName);
            try
            {
                var resumeHandle = 0;
                var result = NetSessionEnum(serverName, null, null, NetSessionEnumLevel, out ptr, -1,
                    out var entriesread,
                    out _, ref resumeHandle);

                _log.LogTrace("Result of NetSessionEnum for {ServerName} is {Result}", serverName, result);

                if (result != NERR.NERR_Success)
                    throw new APIException
                    {
                        APICall = NetSessionEnumQueryName,
                        Status = result.ToString()
                    };

                var iter = ptr;
                for (var i = 0; i < entriesread; i++)
                {
                    var data = Marshal.PtrToStructure<SESSION_INFO_10>(iter);
                    iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(typeof(SESSION_INFO_10)));

                    yield return data;
                }
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    NetApiBufferFree(ptr);
            }
        }

        public virtual IEnumerable<WKSTA_USER_INFO_1> CallNetWkstaUserEnum(string servername)
        {
            var ptr = IntPtr.Zero;
            try
            {
                var resumeHandle = 0;
                _log.LogTrace("Beginning NetWkstaUserEnum for {ServerName}", servername);
                var result = NetWkstaUserEnum(servername, NetWkstaUserEnumQueryLevel, out ptr, -1, out var entriesread,
                    out _,
                    ref resumeHandle);

                _log.LogTrace("Result of NetWkstaUserEnum for computer {ServerName} is {Result}", servername, result);

                if (result != NERR.NERR_Success && result != NERR.ERROR_MORE_DATA)
                    throw new APIException
                    {
                        APICall = NetWkstaUserEnumQueryName,
                        Status = result.ToString()
                    };

                var iter = ptr;
                for (var i = 0; i < entriesread; i++)
                {
                    var data = Marshal.PtrToStructure<WKSTA_USER_INFO_1>(iter);
                    iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(typeof(WKSTA_USER_INFO_1)));
                    yield return data;
                }
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    NetApiBufferFree(ptr);
            }
        }

        public virtual DOMAIN_CONTROLLER_INFO? CallDsGetDcName(string computerName, string domainName)
        {
            var ptr = IntPtr.Zero;
            try
            {
                var result = DsGetDcName(computerName, domainName, null, null,
                    (uint)(DSGETDCNAME_FLAGS.DS_IS_FLAT_NAME | DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME), out ptr);

                if (result != 0) return null;
                var info = Marshal.PtrToStructure<DOMAIN_CONTROLLER_INFO>(ptr);
                return info;
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    NetApiBufferFree(ptr);
            }
        }

        public virtual NtStatus CallSamConnect(ref UNICODE_STRING serverName, out IntPtr serverHandle,
            SamAccessMasks desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes)
        {
            return SamConnect(ref serverName, out serverHandle, desiredAccess, ref objectAttributes);
        }

        internal virtual NtStatus CallSamOpenDomain(IntPtr serverHandle, DomainAccessMask desiredAccess,
            byte[] domainSid, out IntPtr domainHandle)
        {
            return SamOpenDomain(serverHandle, desiredAccess, domainSid, out domainHandle);
        }

        internal virtual NtStatus CallSamOpenAlias(IntPtr domainHandle, AliasOpenFlags desiredAccess, int aliasId,
            out IntPtr aliasHandle)
        {
            return SamOpenAlias(domainHandle, desiredAccess, aliasId, out aliasHandle);
        }

        internal virtual NtStatus CallSamGetMembersInAlias(IntPtr aliasHandle, out IntPtr members, out int count)
        {
            return SamGetMembersInAlias(aliasHandle, out members, out count);
        }

        internal virtual NtStatus CallSamLookupDomainInSamServer(IntPtr serverHandle, ref UNICODE_STRING name,
            out IntPtr sid)
        {
            return SamLookupDomainInSamServer(serverHandle, ref name, out sid);
        }

        internal virtual NtStatus CallSamFreeMemory(IntPtr handle)
        {
            return SamFreeMemory(handle);
        }

        internal virtual NtStatus CallSamCloseHandle(IntPtr handle)
        {
            return SamCloseHandle(handle);
        }

        // ReSharper disable once InconsistentNaming
        public struct OBJECT_ATTRIBUTES : IDisposable
        {
            public void Dispose()
            {
                if (objectName == IntPtr.Zero) return;
                Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }

            public int len;
            public IntPtr rootDirectory;
            public uint attribs;
            public IntPtr sid;
            public IntPtr qos;
            private IntPtr objectName;
            public UNICODE_STRING ObjectName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            private readonly ushort Length;
            private readonly ushort MaximumLength;
            private IntPtr Buffer;

            public UNICODE_STRING(string s)
                : this()
            {
                if (s == null) return;
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                if (Buffer == IntPtr.Zero) return;
                Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return (Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(Buffer) : null) ??
                       throw new InvalidOperationException();
            }
        }

        #region SAMR Imports

        [DllImport("samlib.dll")]
        private static extern NtStatus SamCloseHandle(
            IntPtr handle
        );

        [DllImport("samlib.dll")]
        private static extern NtStatus SamFreeMemory(
            IntPtr handle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamLookupDomainInSamServer(
            IntPtr serverHandle,
            ref UNICODE_STRING name,
            out IntPtr sid);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamGetMembersInAlias(
            IntPtr aliasHandle,
            out IntPtr members,
            out int count);

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamOpenAlias(
            IntPtr domainHandle,
            AliasOpenFlags desiredAccess,
            int aliasId,
            out IntPtr aliasHandle
        );


        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamConnect(
            ref UNICODE_STRING serverName,
            out IntPtr serverHandle,
            SamAccessMasks desiredAccess,
            ref OBJECT_ATTRIBUTES objectAttributes
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamOpenDomain(
            IntPtr serverHandle,
            DomainAccessMask desiredAccess,
            [MarshalAs(UnmanagedType.LPArray)] byte[] domainSid,
            out IntPtr domainHandle
        );

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        internal enum AliasOpenFlags
        {
            AddMember = 0x1,
            RemoveMember = 0x2,
            ListMembers = 0x4,
            ReadInfo = 0x8,
            WriteAccount = 0x10,
            AllAccess = 0xf001f,
            Read = 0x20004,
            Write = 0x20013,
            Execute = 0x20008
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        internal enum LsaOpenMask
        {
            ViewLocalInfo = 0x1,
            ViewAuditInfo = 0x2,
            GetPrivateInfo = 0x4,
            TrustAdmin = 0x8,
            CreateAccount = 0x10,
            CreateSecret = 0x20,
            CreatePrivilege = 0x40,
            SetDefaultQuotaLimits = 0x80,
            SetAuditRequirements = 0x100,
            AuditLogAdmin = 0x200,
            ServerAdmin = 0x400,
            LookupNames = 0x800,
            Notification = 0x1000
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        internal enum DomainAccessMask
        {
            ReadPasswordParameters = 0x1,
            WritePasswordParameters = 0x2,
            ReadOtherParameters = 0x4,
            WriteOtherParameters = 0x8,
            CreateUser = 0x10,
            CreateGroup = 0x20,
            CreateAlias = 0x40,
            GetAliasMembership = 0x80,
            ListAccounts = 0x100,
            Lookup = 0x200,
            AdministerServer = 0x400,
            AllAccess = 0xf07ff,
            Read = 0x20084,
            Write = 0x2047A,
            Execute = 0x20301
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        internal enum SamAliasFlags
        {
            AddMembers = 0x1,
            RemoveMembers = 0x2,
            ListMembers = 0x4,
            ReadInfo = 0x8,
            WriteAccount = 0x10,
            AllAccess = 0xf001f,
            Read = 0x20004,
            Write = 0x20013,
            Execute = 0x20008
        }

        [Flags]
        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        public enum SamAccessMasks
        {
            SamServerConnect = 0x1,
            SamServerShutdown = 0x2,
            SamServerInitialize = 0x4,
            SamServerCreateDomains = 0x8,
            SamServerEnumerateDomains = 0x10,
            SamServerLookupDomain = 0x20,
            SamServerAllAccess = 0xf003f,
            SamServerRead = 0x20010,
            SamServerWrite = 0x2000e,
            SamServerExecute = 0x20021
        }

        #endregion

        #region Session Enum Imports

        [DllImport("NetAPI32.dll", SetLastError = true)]
        private static extern NERR NetSessionEnum(
            [MarshalAs(UnmanagedType.LPWStr)] string ServerName,
            [MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
            [MarshalAs(UnmanagedType.LPWStr)] string UserName,
            int Level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [StructLayout(LayoutKind.Sequential)]
        public struct SESSION_INFO_10
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string sesi10_cname;
            [MarshalAs(UnmanagedType.LPWStr)] public string sesi10_username;
            public uint sesi10_time;
            public uint sesi10_idle_time;
        }

        public enum NERR
        {
            NERR_Success = 0,
            ERROR_MORE_DATA = 234,
            ERROR_NO_BROWSER_SERVERS_FOUND = 6118,
            ERROR_INVALID_LEVEL = 124,
            ERROR_ACCESS_DENIED = 5,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_NOT_ENOUGH_MEMORY = 8,
            ERROR_NETWORK_BUSY = 54,
            ERROR_BAD_NETPATH = 53,
            ERROR_NO_NETWORK = 1222,
            ERROR_INVALID_HANDLE_STATE = 1609,
            ERROR_EXTENDED_ERROR = 1208,
            NERR_BASE = 2100,
            NERR_UnknownDevDir = NERR_BASE + 16,
            NERR_DuplicateShare = NERR_BASE + 18,
            NERR_BufTooSmall = NERR_BASE + 23
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_USER_INFO_1
        {
            public string wkui1_username;
            public string wkui1_logon_domain;
            public string wkui1_oth_domains;
            public string wkui1_logon_server;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern NERR NetWkstaUserEnum(
            string servername,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(
            IntPtr Buff);

        #endregion

        #region NetAPI PInvoke Calls

        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern NERR NetWkstaGetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            uint level,
            out IntPtr bufPtr);

        public struct WorkstationInfo100
        {
            public int platform_id;
            [MarshalAs(UnmanagedType.LPWStr)] public string computer_name;
            [MarshalAs(UnmanagedType.LPWStr)] public string lan_group;
            public int ver_major;
            public int ver_minor;
        }

        #endregion

        #region DSGetDcName Imports

        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern int DsGetDcName
        (
            [MarshalAs(UnmanagedType.LPTStr)] string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)] string DomainName,
            [In] GuidClass DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)] string SiteName,
            uint Flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
        );

        [StructLayout(LayoutKind.Sequential)]
        public class GuidClass
        {
            public Guid TheGuid;
        }

        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)] public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)] public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)] public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)] public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)] public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)] public string ClientSiteName;
        }

        #endregion
    }
}