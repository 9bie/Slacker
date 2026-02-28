using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class SAMRPCServer : IDisposable
    {
        private static readonly Lazy<byte[]> WellKnownSidBytes = new(() =>
        {
            var sid = new SecurityIdentifier("S-1-5-32");
            var sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);
            return sidBytes;
        }, LazyThreadSafetyMode.PublicationOnly);

        private readonly string _computerDomain;

        private readonly string _computerName;
        private readonly string _computerSAMAccountName;
        private readonly string _computerSID;

        private readonly string[] _filteredSids =
        {
            "S-1-5-2", "S-1-5-2", "S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-5-7", "S-1-2", "S-1-2-0", "S-1-5-18",
            "S-1-5-19", "S-1-5-20"
        };

        private readonly ILogger _log;

        private readonly NativeMethods _nativeMethods;
        private readonly NativeMethods.OBJECT_ATTRIBUTES _obj;
        private readonly ILDAPUtils _utils;
        private IntPtr _domainHandle;

        private IntPtr _serverHandle;

        /// <summary>
        ///     Creates an instance of an RPCServer which is used for making SharpHound specific SAMRPC API calls for computers
        /// </summary>
        /// <param name="computerName">The name of the computer to connect too. This should be the network name of the computer</param>
        /// <param name="samAccountName">The samaccountname of the computer</param>
        /// <param name="computerSid">The security identifier for the computer</param>
        /// <param name="computerDomain">The domain of the computer</param>
        /// <param name="utils">LDAPUtils instance</param>
        /// <param name="methods">NativeMethods instance</param>
        /// <param name="log">ILogger instance</param>
        /// <exception cref="APIException">
        ///     An exception if the an API fails to connect initially. Generally indicates the server is
        ///     unavailable or permissions aren't available.
        /// </exception>
        public SAMRPCServer(string computerName, string samAccountName, string computerSid, string computerDomain,
            ILDAPUtils utils = null,
            NativeMethods methods = null, ILogger log = null)
        {
            _computerSAMAccountName = samAccountName;
            _computerSID = computerSid;
            _computerName = computerName;
            _computerDomain = computerDomain;
            _utils = utils;
            _nativeMethods = methods ?? new NativeMethods();
            _utils = utils ?? new LDAPUtils();
            _log = log ?? Logging.LogProvider.CreateLogger("SAMRPCServer");

            _log.LogTrace("Opening SAM Server for {ComputerName}", computerName);

            var us = new NativeMethods.UNICODE_STRING(computerName);
            //Every API call we make relies on both SamConnect and SamOpenDomain
            //Make these calls immediately and save the handles. If either fails, nothing else is going to work
            var status = _nativeMethods.CallSamConnect(ref us, out _serverHandle,
                NativeMethods.SamAccessMasks.SamServerLookupDomain | NativeMethods.SamAccessMasks.SamServerConnect,
                ref _obj);
            _log.LogTrace("SamConnect returned {Status} for {ComputerName}", status, computerName);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                _nativeMethods.CallSamCloseHandle(_serverHandle);
                throw new APIException
                {
                    Status = status.ToString(),
                    APICall = "SamConnect"
                };
            }

            status = _nativeMethods.CallSamOpenDomain(_serverHandle, NativeMethods.DomainAccessMask.Lookup,
                WellKnownSidBytes.Value, out _domainHandle);
            _log.LogTrace("SamOpenDomain returned {Status} for {ComputerName}", status, computerName);
            if (status != NativeMethods.NtStatus.StatusSuccess)
                throw new APIException
                {
                    Status = status.ToString(),
                    APICall = "SamOpenDomain"
                };
        }

        public void Dispose()
        {
            if (_domainHandle != IntPtr.Zero)
            {
                _nativeMethods.CallSamCloseHandle(_domainHandle);
                _domainHandle = IntPtr.Zero;
            }

            if (_serverHandle != IntPtr.Zero)
            {
                _nativeMethods.CallSamCloseHandle(_serverHandle);
                _serverHandle = IntPtr.Zero;
            }

            _obj.Dispose();
        }

        ~SAMRPCServer()
        {
            Dispose();
        }

        /// <summary>
        ///     Reads the members in a specified local group. The group is referenced by its RID (Relative Identifier).
        ///     Groups current used by SharpHound can be found in <cref>LocalGroupRids</cref>
        /// </summary>
        /// <param name="groupRid"></param>
        /// <returns></returns>
        public LocalGroupAPIResult GetLocalGroupMembers(int groupRid)
        {
            var result = new LocalGroupAPIResult();

            var status = _nativeMethods.CallSamOpenAlias(_domainHandle, NativeMethods.AliasOpenFlags.ListMembers,
                groupRid, out var aliasHandle);
            _log.LogTrace("SamOpenAlias returned {Status} for RID {GroupRID} on {ComputerName}", status, groupRid,
                _computerName);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                _nativeMethods.CallSamCloseHandle(aliasHandle);
                result.FailureReason = $"SamOpenAlias returned {status.ToString()}";
                return result;
            }

            status = _nativeMethods.CallSamGetMembersInAlias(aliasHandle, out var members, out var count);
            _log.LogTrace("SamGetMembersInAlias returned {Status} for RID {GroupRID} on {ComputerName}", status,
                groupRid, _computerName);
            _nativeMethods.CallSamCloseHandle(aliasHandle);

            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                _nativeMethods.CallSamFreeMemory(members);
                result.FailureReason = $"SamGetMembersInAlias returned {status.ToString()}";
                return result;
            }

            _log.LogTrace("SamGetMembersInAlias returned {Count} items for RID {GroupRID} on {ComputerName}", count,
                groupRid, _computerName);

            if (count == 0)
            {
                _nativeMethods.CallSamFreeMemory(members);
                result.Collected = true;
                return result;
            }

            var sids = new List<string>();
            for (var i = 0; i < count; i++)
                try
                {
                    var raw = Marshal.ReadIntPtr(members, Marshal.SizeOf(typeof(IntPtr)) * i);
                    var sid = new SecurityIdentifier(raw).Value;
                    sids.Add(sid);
                }
                catch (Exception e)
                {
                    _log.LogTrace(e, "Exception converting sid");
                }

            _nativeMethods.CallSamFreeMemory(members);

            var machineSid = GetMachineSid();
            _log.LogTrace("Resolved machine sid for {ComputerName} to {MachineSID}", _computerName, machineSid);
            var converted = sids.Select(x =>
            {
                //Filter out machine accounts, service accounts, iis app pool accounts, window manager, font driver
                if (x.StartsWith(machineSid) || x.StartsWith("S-1-5-80") || x.StartsWith("S-1-5-82") ||
                    x.StartsWith("S-1-5-90") || x.StartsWith("S-1-5-96")) return null;

                if (_filteredSids.Contains(x)) return null;

                var res = _utils.ResolveIDAndType(x, _computerDomain);

                return res;
            }).Where(x => x != null);

            result.Collected = true;
            result.Results = converted.ToArray();

            return result;
        }

        /// <summary>
        ///     Uses API calls and caching to attempt to get the local SID of a computer.
        ///     The local SID of a computer will not match its domain SID, and is used to denote local machine accounts
        /// </summary>
        /// <returns></returns>
        public string GetMachineSid()
        {
            if (Cache.GetMachineSid(_computerSID, out var machineSid)) return machineSid;

            NativeMethods.NtStatus status;
            //Try the simplest method first, getting the SID directly using samaccountname
            try
            {
                var san = new NativeMethods.UNICODE_STRING(_computerSAMAccountName);
                status = _nativeMethods.CallSamLookupDomainInSamServer(_serverHandle, ref san, out var temp);
                _log.LogTrace("SamLookupDomainInSamServer returned {Status} on {ComputerName}", status, _computerName);
                if (status == NativeMethods.NtStatus.StatusSuccess)
                {
                    machineSid = new SecurityIdentifier(temp).Value;
                    _nativeMethods.CallSamFreeMemory(temp);
                    Cache.AddMachineSid(_computerSID, machineSid);
                    return machineSid;
                }
            }
            catch
            {
                //pass
            }

            machineSid = "DUMMYSTRING";

            //As a fallback, try and retrieve the local administrators group and get the first account with a rid of 500
            //If at any time we encounter a failure, just return a dummy sid that wont match anything

            status = _nativeMethods.CallSamOpenAlias(_domainHandle, NativeMethods.AliasOpenFlags.ListMembers,
                (int)LocalGroupRids.Administrators, out var aliasHandle);
            _log.LogTrace("SamOpenAlias returned {Status} for Administrators on {ComputerName}", status, _computerName);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                _nativeMethods.CallSamCloseHandle(aliasHandle);
                return machineSid;
            }


            status = _nativeMethods.CallSamGetMembersInAlias(aliasHandle, out var members, out var count);
            _log.LogTrace("SamGetMembersInAlias returned {Status} for Administrators on {ComputerName}", status,
                _computerName);
            if (status != NativeMethods.NtStatus.StatusSuccess)
            {
                _nativeMethods.CallSamCloseHandle(aliasHandle);
                return machineSid;
            }

            _nativeMethods.CallSamCloseHandle(aliasHandle);

            if (count == 0)
            {
                _nativeMethods.CallSamFreeMemory(members);
                return machineSid;
            }

            var sids = new List<string>();
            for (var i = 0; i < count; i++)
                try
                {
                    var ptr = Marshal.ReadIntPtr(members, Marshal.SizeOf(typeof(IntPtr)) * i);
                    var sid = new SecurityIdentifier(ptr).Value;
                    sids.Add(sid);
                }
                catch (Exception e)
                {
                    _log.LogDebug(e, "GetMachineSid - Exception converting sid");
                }

            _nativeMethods.CallSamFreeMemory(members);

            var domainSid = new SecurityIdentifier(_computerSID).AccountDomainSid.Value.ToUpper();

            machineSid = sids.Select(x =>
                {
                    try
                    {
                        return new SecurityIdentifier(x).Value;
                    }
                    catch
                    {
                        return null;
                    }
                }).Where(x => x != null).DefaultIfEmpty(null)
                .FirstOrDefault(x => x.EndsWith("-500") && !x.ToUpper().StartsWith(domainSid));

            if (machineSid == null)
            {
                _log.LogTrace("Did not get a machine SID for {ComputerName}", _computerName);
                return "DUMMYSTRING";
            }

            machineSid = new SecurityIdentifier(machineSid).AccountDomainSid.Value;

            Cache.AddMachineSid(_computerSID, machineSid);
            return machineSid;
        }
    }

    public class APIException : Exception
    {
        public string Status { get; set; }
        public string APICall { get; set; }

        public override string ToString()
        {
            return $"Call to {APICall} returned {Status}";
        }
    }

    public enum LocalGroupRids
    {
        None = 0,
        Administrators = 544,
        RemoteDesktopUsers = 555,
        DcomUsers = 562,
        PSRemote = 580
    }
}