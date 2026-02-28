using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHoundCommonLib.Processors
{
    public class ACLProcessor
    {
        private static readonly Dictionary<Label, string> BaseGuids;
        private static readonly ConcurrentDictionary<string, string> GuidMap = new();
        private static bool _isCacheBuilt;
        private readonly ILogger _log;
        private readonly ILDAPUtils _utils;

        static ACLProcessor()
        {
            //Create a dictionary with the base GUIDs of each object type
            BaseGuids = new Dictionary<Label, string>
            {
                { Label.User, "bf967aba-0de6-11d0-a285-00aa003049e2" },
                { Label.Computer, "bf967a86-0de6-11d0-a285-00aa003049e2" },
                { Label.Group, "bf967a9c-0de6-11d0-a285-00aa003049e2" },
                { Label.Domain, "19195a5a-6da0-11d0-afd3-00c04fd930c9" },
                { Label.GPO, "f30e3bc2-9ff0-11d1-b603-0000f80367c1" },
                { Label.OU, "bf967aa5-0de6-11d0-a285-00aa003049e2" },
                { Label.Container, "bf967a8b-0de6-11d0-a285-00aa003049e2" }
            };
        }

        public ACLProcessor(ILDAPUtils utils, bool noGuidCache = false, ILogger log = null, string domain = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("ACLProc");
            if (!noGuidCache)
                BuildGUIDCache(domain);
        }

        /// <summary>
        ///     Builds a mapping of GUID -> Name for LDAP rights. Used for rights that are created using an extended schema such as
        ///     LAPS
        /// </summary>
        private void BuildGUIDCache(string domain)
        {
            if (_isCacheBuilt)
                return;

            var forest = _utils.GetForest(domain);
            if (forest == null)
            {
                _log.LogError("BuildGUIDCache - Unable to resolve forest");
                return;
            }

            var schema = forest.Schema.Name;
            if (string.IsNullOrEmpty(schema))
            {
                _log.LogError("BuildGUIDCache - Schema string is null or empty");
                return;
            }

            _log.LogTrace("Requesting schema from {Schema}", schema);
            foreach (var entry in _utils.QueryLDAP("(schemaIDGUID=*)", SearchScope.Subtree,
                         new[] { LDAPProperties.SchemaIDGUID, LDAPProperties.Name }, adsPath: schema))
            {
                var name = entry.GetProperty(LDAPProperties.Name)?.ToLower();
                var guid = new Guid(entry.GetByteProperty(LDAPProperties.SchemaIDGUID)).ToString();
                GuidMap.TryAdd(guid, name);
            }

            _log.LogTrace("BuildGUIDCache - Successfully grabbed schema");

            _isCacheBuilt = true;
        }

        /// <summary>
        ///     Helper function to use commonlib types in IsACLProtected
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public bool IsACLProtected(ISearchResultEntry entry)
        {
            var ntsd = entry.GetByteProperty(LDAPProperties.SecurityDescriptor);
            return IsACLProtected(ntsd);
        }

        /// <summary>
        ///     Gets the protection state of the access control list
        /// </summary>
        /// <param name="ntSecurityDescriptor"></param>
        /// <returns></returns>
        public bool IsACLProtected(byte[] ntSecurityDescriptor)
        {
            if (ntSecurityDescriptor == null)
                return false;

            var descriptor = _utils.MakeSecurityDescriptor();
            descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);

            return descriptor.AreAccessRulesProtected();
        }

        /// <summary>
        ///     Helper function to use common lib types and pass appropriate vars to ProcessACL
        /// </summary>
        /// <param name="result"></param>
        /// <param name="searchResult"></param>
        /// <returns></returns>
        public IEnumerable<ACE> ProcessACL(ResolvedSearchResult result, ISearchResultEntry searchResult)
        {
            var descriptor = searchResult.GetByteProperty(LDAPProperties.SecurityDescriptor);
            var domain = result.Domain;
            var type = result.ObjectType;
            var hasLaps = searchResult.HasLAPS();
            var name = result.DisplayName;

            return ProcessACL(descriptor, domain, type, hasLaps, name);
        }

        /// <summary>
        ///     Read's the ntSecurityDescriptor from a SearchResultEntry and processes the ACEs in the ACL, filtering out ACEs that
        ///     BloodHound is not interested in
        /// </summary>
        /// <param name="ntSecurityDescriptor"></param>
        /// <param name="objectDomain"></param>
        /// <param name="objectName"></param>
        /// <param name="objectType"></param>
        /// <param name="hasLaps"></param>
        /// <returns></returns>
        public IEnumerable<ACE> ProcessACL(byte[] ntSecurityDescriptor, string objectDomain,
            Label objectType,
            bool hasLaps, string objectName = "")
        {
            if (ntSecurityDescriptor == null)
            {
                _log.LogDebug("Security Descriptor is null for {Name}", objectName);
                yield break;
            }

            var descriptor = _utils.MakeSecurityDescriptor();
            descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);

            var ownerSid = PreProcessSID(descriptor.GetOwner(typeof(SecurityIdentifier)));

            if (ownerSid != null)
            {
                var resolvedOwner = _utils.ResolveIDAndType(ownerSid, objectDomain);
                if (resolvedOwner != null)
                    yield return new ACE
                    {
                        PrincipalType = resolvedOwner.ObjectType,
                        PrincipalSID = resolvedOwner.ObjectIdentifier,
                        RightName = EdgeNames.Owns,
                        IsInherited = false
                    };
            }
            else
            {
                _log.LogDebug("Owner is null for {Name}", objectName);
            }

            foreach (var ace in descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (ace == null)
                {
                    _log.LogTrace("Skipping null ACE for {Name}", objectName);
                    continue;
                }

                if (ace.AccessControlType() == AccessControlType.Deny)
                {
                    _log.LogTrace("Skipping deny ACE for {Name}", objectName);
                    continue;
                }

                if (!ace.IsAceInheritedFrom(BaseGuids[objectType]))
                {
                    _log.LogTrace("Skipping ACE with unmatched GUID/inheritance for {Name}", objectName);
                    continue;
                }

                var ir = ace.IdentityReference();
                var principalSid = PreProcessSID(ir);

                if (principalSid == null)
                {
                    _log.LogTrace("Pre-Process excluded SID {SID} on {Name}", ir ?? "null", objectName);
                    continue;
                }

                var resolvedPrincipal = _utils.ResolveIDAndType(principalSid, objectDomain);

                var aceRights = ace.ActiveDirectoryRights();
                //Lowercase this just in case. As far as I know it should always come back that way anyways, but better safe than sorry
                var aceType = ace.ObjectType().ToString().ToLower();
                var inherited = ace.IsInherited();

                GuidMap.TryGetValue(aceType, out var mappedGuid);

                _log.LogTrace("Processing ACE with rights {Rights} and guid {GUID} on object {Name}", aceRights,
                    aceType, objectName);

                //GenericAll applies to every object
                if (aceRights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (aceType is ACEGuids.AllGuid or "")
                        yield return new ACE
                        {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.GenericAll
                        };
                    //This is a special case. If we don't continue here, every other ACE will match because GenericAll includes all other permissions
                    continue;
                }

                //WriteDACL and WriteOwner are always useful no matter what the object type is as well because they enable all other attacks
                if (aceRights.HasFlag(ActiveDirectoryRights.WriteDacl))
                    yield return new ACE
                    {
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = inherited,
                        RightName = EdgeNames.WriteDacl
                    };

                if (aceRights.HasFlag(ActiveDirectoryRights.WriteOwner))
                    yield return new ACE
                    {
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = inherited,
                        RightName = EdgeNames.WriteOwner
                    };

                //Cool ACE courtesy of @rookuu. Allows a principal to add itself to a group and no one else
                if (aceRights.HasFlag(ActiveDirectoryRights.Self) &&
                    !aceRights.HasFlag(ActiveDirectoryRights.WriteProperty) &&
                    !aceRights.HasFlag(ActiveDirectoryRights.GenericWrite) && objectType == Label.Group &&
                    aceType == ACEGuids.WriteMember)
                    yield return new ACE
                    {
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = inherited,
                        RightName = EdgeNames.AddSelf
                    };

                //Process object type specific ACEs. Extended rights apply to users, domains, and computers
                if (aceRights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                {
                    if (objectType == Label.Domain)
                    {
                        if (aceType == ACEGuids.DSReplicationGetChanges)
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.GetChanges
                            };
                        else if (aceType == ACEGuids.DSReplicationGetChangesAll)
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.GetChangesAll
                            };
                        else if (aceType == ACEGuids.DSReplicationGetChangesInFilteredSet)
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.GetChangesInFilteredSet
                            };
                        else if (aceType is ACEGuids.AllGuid or "")
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.AllExtendedRights
                            };
                    }
                    else if (objectType == Label.User)
                    {
                        if (aceType == ACEGuids.UserForceChangePassword)
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.ForceChangePassword
                            };
                        else if (aceType is ACEGuids.AllGuid or "")
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.AllExtendedRights
                            };
                    }
                    else if (objectType == Label.Computer)
                    {
                        //ReadLAPSPassword is only applicable if the computer actually has LAPS. Check the world readable property ms-mcs-admpwdexpirationtime
                        if (hasLaps)
                        {
                            if (aceType is ACEGuids.AllGuid or "")
                                yield return new ACE
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.AllExtendedRights
                                };
                            else if (mappedGuid is "ms-mcs-admpwd")
                                yield return new ACE
                                {
                                    PrincipalType = resolvedPrincipal.ObjectType,
                                    PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                    IsInherited = inherited,
                                    RightName = EdgeNames.ReadLAPSPassword
                                };
                        }
                    }
                }

                //GenericWrite encapsulates WriteProperty, so process them in tandem to avoid duplicate edges
                if (aceRights.HasFlag(ActiveDirectoryRights.GenericWrite) ||
                    aceRights.HasFlag(ActiveDirectoryRights.WriteProperty))
                {
                    if (objectType is Label.User or Label.Group or Label.Computer or Label.GPO)
                        if (aceType is ACEGuids.AllGuid or "")
                            yield return new ACE
                            {
                                PrincipalType = resolvedPrincipal.ObjectType,
                                PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                                IsInherited = inherited,
                                RightName = EdgeNames.GenericWrite
                            };

                    if (objectType == Label.User && aceType == ACEGuids.WriteSPN)
                        yield return new ACE
                        {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.WriteSPN
                        };
                    else if (objectType == Label.Computer && aceType == ACEGuids.WriteAllowedToAct)
                        yield return new ACE
                        {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.AddAllowedToAct
                        };
                    else if (objectType == Label.Computer && aceType == ACEGuids.UserAccountRestrictions && !resolvedPrincipal.ObjectIdentifier.EndsWith("-512"))
                        yield return new ACE
                        {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.WriteAccountRestrictions
                        };
                    else if (objectType == Label.Group && aceType == ACEGuids.WriteMember)
                        yield return new ACE
                        {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.AddMember
                        };
                    else if (objectType is Label.User or Label.Computer && aceType == ACEGuids.AddKeyPrincipal)
                        yield return new ACE
                        {
                            PrincipalType = resolvedPrincipal.ObjectType,
                            PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                            IsInherited = inherited,
                            RightName = EdgeNames.AddKeyCredentialLink
                        };
                }
            }
        }

        /// <summary>
        ///     Helper function to use commonlib types and pass to ProcessGMSAReaders
        /// </summary>
        /// <param name="resolvedSearchResult"></param>
        /// <param name="searchResultEntry"></param>
        /// <returns></returns>
        public IEnumerable<ACE> ProcessGMSAReaders(ResolvedSearchResult resolvedSearchResult,
            ISearchResultEntry searchResultEntry)
        {
            var descriptor = searchResultEntry.GetByteProperty(LDAPProperties.GroupMSAMembership);
            var domain = resolvedSearchResult.Domain;
            var name = resolvedSearchResult.DisplayName;

            return ProcessGMSAReaders(descriptor, name, domain);
        }

        /// <summary>
        ///     ProcessGMSAMembership with no account name
        /// </summary>
        /// <param name="groupMSAMembership"></param>
        /// <param name="objectDomain"></param>
        /// <returns></returns>
        public IEnumerable<ACE> ProcessGMSAReaders(byte[] groupMSAMembership, string objectDomain)
        {
            return ProcessGMSAReaders(groupMSAMembership, "", objectDomain);
        }

        /// <summary>
        ///     Processes the msds-groupmsamembership property and returns ACEs representing principals that can read the GMSA
        ///     password from an object
        /// </summary>
        /// <param name="groupMSAMembership"></param>
        /// <param name="objectName"></param>
        /// <param name="objectDomain"></param>
        /// <returns></returns>
        public IEnumerable<ACE> ProcessGMSAReaders(byte[] groupMSAMembership, string objectName, string objectDomain)
        {
            if (groupMSAMembership == null)
            {
                _log.LogTrace("GMSA bytes are null for {Name}", objectName);
                yield break;
            }


            var descriptor = _utils.MakeSecurityDescriptor();
            descriptor.SetSecurityDescriptorBinaryForm(groupMSAMembership);

            foreach (var ace in descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (ace == null)
                {
                    _log.LogTrace("Skipping null GMSA ACE for {Name}", objectName);
                    continue;
                }

                if (ace.AccessControlType() == AccessControlType.Deny)
                {
                    _log.LogTrace("Skipping deny GMSA ACE for {Name}", objectName);
                    continue;
                }

                var ir = ace.IdentityReference();
                var principalSid = PreProcessSID(ir);

                if (principalSid == null)
                {
                    _log.LogTrace("Pre-Process excluded SID {SID} on {Name}", ir ?? "null", objectName);
                    continue;
                }

                _log.LogTrace("Processing GMSA ACE with principal {Principal}", principalSid);

                var resolvedPrincipal = _utils.ResolveIDAndType(principalSid, objectDomain);

                if (resolvedPrincipal != null)
                    yield return new ACE
                    {
                        RightName = EdgeNames.ReadGMSAPassword,
                        PrincipalType = resolvedPrincipal.ObjectType,
                        PrincipalSID = resolvedPrincipal.ObjectIdentifier,
                        IsInherited = ace.IsInherited()
                    };
            }
        }

        /// <summary>
        ///     Removes some commonly seen SIDs that have no use in the schema
        /// </summary>
        /// <param name="sid"></param>
        /// <returns></returns>
        private static string PreProcessSID(string sid)
        {
            sid = sid?.ToUpper();
            if (sid != null)
                //Ignore Local System/Creator Owner/Principal Self
                return sid is "S-1-5-18" or "S-1-3-0" or "S-1-5-10" ? null : sid;

            return null;
        }
    }
}