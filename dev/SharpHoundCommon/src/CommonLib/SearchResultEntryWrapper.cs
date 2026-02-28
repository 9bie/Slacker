using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib
{
    public interface ISearchResultEntry
    {
        string DistinguishedName { get; }
        ResolvedSearchResult ResolveBloodHoundInfo();
        string GetProperty(string propertyName);
        byte[] GetByteProperty(string propertyName);
        string[] GetArrayProperty(string propertyName);
        byte[][] GetByteArrayProperty(string propertyName);
        string GetObjectIdentifier();
        bool IsDeleted();
        Label GetLabel();
        string GetSid();
        string GetGuid();
        int PropCount(string prop);
        IEnumerable<string> PropertyNames();
        bool IsMSA();
        bool IsGMSA();
        bool HasLAPS();
    }

    public class SearchResultEntryWrapper : ISearchResultEntry
    {
        private const string GMSAClass = "msds-groupmanagedserviceaccount";
        private const string MSAClass = "msds-managedserviceaccount";
        private readonly SearchResultEntry _entry;
        private readonly ILogger _log;
        private readonly ILDAPUtils _utils;

        public SearchResultEntryWrapper(SearchResultEntry entry, ILDAPUtils utils = null, ILogger log = null)
        {
            _entry = entry;
            _utils = utils ?? new LDAPUtils();
            _log = log ?? Logging.LogProvider.CreateLogger("SearchResultWrapper");
        }

        public string DistinguishedName => _entry.DistinguishedName;

        public ResolvedSearchResult ResolveBloodHoundInfo()
        {
            var res = new ResolvedSearchResult();

            var objectId = GetObjectIdentifier();
            if (objectId == null)
            {
                _log.LogWarning("ObjectIdentifier is null for {DN}", DistinguishedName);
                return null;
            }

            var uac = _entry.GetProperty(LDAPProperties.UserAccountControl);
            if (int.TryParse(uac, out var flag))
            {
                var flags = (UacFlags)flag;
                if ((flags & UacFlags.ServerTrustAccount) != 0)
                {
                    _log.LogTrace("Marked {SID} as a domain controller", objectId);
                    res.IsDomainController = true;
                    _utils.AddDomainController(objectId);
                }
            }

            res.ObjectId = objectId;
            if (IsDeleted())
            {
                res.Deleted = IsDeleted();
                _log.LogTrace("{SID} is tombstoned, skipping rest of resolution", objectId);
                return res;
            }

            //Try to resolve the domain
            var distinguishedName = DistinguishedName;
            string itemDomain;
            if (distinguishedName == null)
            {
                if (objectId.StartsWith("S-1-"))
                {
                    itemDomain = _utils.GetDomainNameFromSid(objectId);
                }
                else
                {
                    _log.LogWarning("Failed to resolve domain for {ObjectID}", objectId);
                    return null;
                }
            }
            else
            {
                itemDomain = Helpers.DistinguishedNameToDomain(distinguishedName);
            }

            _log.LogTrace("Resolved domain for {SID} to {Domain}", objectId, itemDomain);

            res.Domain = itemDomain;

            if (WellKnownPrincipal.GetWellKnownPrincipal(objectId, out var wkPrincipal))
            {
                res.DomainSid = _utils.GetSidFromDomainName(itemDomain);
                res.DisplayName = $"{wkPrincipal.ObjectIdentifier}@{itemDomain}";
                res.ObjectType = wkPrincipal.ObjectType;
                res.ObjectId = _utils.ConvertWellKnownPrincipal(objectId, itemDomain);

                _log.LogTrace("Resolved {DN} to wkp {ObjectID}", DistinguishedName, res.ObjectId);
                return res;
            }

            if (objectId.StartsWith("S-1-"))
                try
                {
                    res.DomainSid = new SecurityIdentifier(objectId).AccountDomainSid.Value;
                }
                catch
                {
                    res.DomainSid = _utils.GetSidFromDomainName(itemDomain);
                }
            else
                res.DomainSid = _utils.GetSidFromDomainName(itemDomain);

            var samAccountName = GetProperty(LDAPProperties.SAMAccountName);

            var itemType = GetLabel();
            res.ObjectType = itemType;

            if (IsGMSA() || IsMSA())
            {
                res.ObjectType = Label.User;
                itemType = Label.User;
            }

            _log.LogTrace("Resolved type for {SID} to {Label}", objectId, itemType);

            switch (itemType)
            {
                case Label.User:
                case Label.Group:
                    res.DisplayName = $"{samAccountName}@{itemDomain}";
                    break;
                case Label.Computer:
                    var shortName = samAccountName?.TrimEnd('$');
                    var dns = GetProperty(LDAPProperties.DNSHostName);
                    var cn = GetProperty(LDAPProperties.CanonicalName);

                    if (dns != null)
                        res.DisplayName = dns;
                    else if (shortName == null && cn == null)
                        res.DisplayName = $"UNKNOWN.{itemDomain}";
                    else if (shortName != null)
                        res.DisplayName = $"{shortName}.{itemDomain}";
                    else
                        res.DisplayName = $"{cn}.{itemDomain}";

                    break;
                case Label.GPO:
                    res.DisplayName = $"{GetProperty(LDAPProperties.DisplayName)}@{itemDomain}";
                    break;
                case Label.Domain:
                    res.DisplayName = itemDomain;
                    break;
                case Label.OU:
                case Label.Container:
                    res.DisplayName = $"{GetProperty(LDAPProperties.Name)}@{itemDomain}";
                    break;
                case Label.Base:
                    res.DisplayName = $"{samAccountName}@{itemDomain}";
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return res;
        }

        public string GetProperty(string propertyName)
        {
            return _entry.GetProperty(propertyName);
        }

        public byte[] GetByteProperty(string propertyName)
        {
            return _entry.GetPropertyAsBytes(propertyName);
        }

        public string[] GetArrayProperty(string propertyName)
        {
            return _entry.GetPropertyAsArray(propertyName);
        }

        public byte[][] GetByteArrayProperty(string propertyName)
        {
            return _entry.GetPropertyAsArrayOfBytes(propertyName);
        }

        public string GetObjectIdentifier()
        {
            return _entry.GetObjectIdentifier();
        }

        public bool IsDeleted()
        {
            return _entry.IsDeleted();
        }

        public Label GetLabel()
        {
            return _entry.GetLabel();
        }

        public string GetSid()
        {
            return _entry.GetSid();
        }

        public string GetGuid()
        {
            return _entry.GetGuid();
        }

        public int PropCount(string prop)
        {
            var coll = _entry.Attributes[prop];
            return coll.Count;
        }

        public IEnumerable<string> PropertyNames()
        {
            foreach (var property in _entry.Attributes.AttributeNames) yield return property.ToString().ToLower();
        }

        public bool IsMSA()
        {
            var classes = GetArrayProperty(LDAPProperties.ObjectClass);
            return classes.Contains(MSAClass, StringComparer.InvariantCultureIgnoreCase);
        }

        public bool IsGMSA()
        {
            var classes = GetArrayProperty(LDAPProperties.ObjectClass);
            return classes.Contains(GMSAClass, StringComparer.InvariantCultureIgnoreCase);
        }

        public bool HasLAPS()
        {
            return GetProperty(LDAPProperties.LAPSExpirationTime) != null;
        }

        public SearchResultEntry GetEntry()
        {
            return _entry;
        }
    }
}