using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using SecurityMasks = System.DirectoryServices.Protocols.SecurityMasks;

namespace SharpHoundCommonLib
{
    public class LDAPUtils : ILDAPUtils
    {
        private const string NullCacheKey = "UNIQUENULL";

        // The following byte stream contains the necessary message to request a NetBios name from a machine
        // http://web.archive.org/web/20100409111218/http://msdn.microsoft.com/en-us/library/system.net.sockets.socket.aspx
        private static readonly byte[] NameRequest =
        {
            0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
            0x00, 0x01
        };

        private static readonly ConcurrentDictionary<string, ResolvedWellKnownPrincipal>
            SeenWellKnownPrincipals = new();

        private static readonly ConcurrentDictionary<string, byte> DomainControllers = new();

        private readonly ConcurrentDictionary<string, Domain> _domainCache = new();
        private readonly ConcurrentDictionary<string, string> _domainControllerCache = new();
        private readonly ConcurrentDictionary<string, string> _gcControllerCache = new();

        private readonly ConcurrentDictionary<string, LdapConnection> _globalCatalogConnections = new();
        private readonly ConcurrentDictionary<string, string> _hostResolutionMap = new();
        private readonly ConcurrentDictionary<string, LdapConnection> _ldapConnections = new();
        private readonly ILogger _log;
        private readonly NativeMethods _nativeMethods;
        private readonly ConcurrentDictionary<string, string> _netbiosCache = new();
        private readonly PortScanner _portScanner;
        private LDAPConfig _ldapConfig = new();

        /// <summary>
        ///     Creates a new instance of LDAP Utils with defaults
        /// </summary>
        public LDAPUtils()
        {
            _nativeMethods = new NativeMethods();
            _portScanner = new PortScanner();
            _log = Logging.LogProvider.CreateLogger("LDAPUtils");
        }

        /// <summary>
        ///     Creates a new instance of LDAP utils and allows overriding implementations
        /// </summary>
        /// <param name="nativeMethods"></param>
        /// <param name="scanner"></param>
        /// <param name="log"></param>
        public LDAPUtils(NativeMethods nativeMethods = null, PortScanner scanner = null, ILogger log = null)
        {
            _nativeMethods = nativeMethods ?? new NativeMethods();
            _portScanner = scanner ?? new PortScanner();
            _log = log ?? Logging.LogProvider.CreateLogger("LDAPUtils");
        }

        /// <summary>
        ///     Sets the configuration for LDAP queries
        /// </summary>
        /// <param name="config"></param>
        /// <exception cref="Exception"></exception>
        public void SetLDAPConfig(LDAPConfig config)
        {
            _ldapConfig = config ?? throw new Exception("LDAP Configuration can not be null");
        }

        /// <summary>
        ///     Turns a sid into a well known principal ID.
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="domain"></param>
        /// <param name="commonPrincipal"></param>
        /// <returns>True if a well known principal was identified, false if not</returns>
        public bool GetWellKnownPrincipal(string sid, string domain, out TypedPrincipal commonPrincipal)
        {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(sid, out commonPrincipal)) return false;
            var tempDomain = domain ?? GetDomain()?.Name ?? "UNKNOWN";
            commonPrincipal.ObjectIdentifier = ConvertWellKnownPrincipal(sid, tempDomain);
            SeenWellKnownPrincipals.TryAdd(commonPrincipal.ObjectIdentifier, new ResolvedWellKnownPrincipal
            {
                DomainName = domain,
                WkpId = sid
            });
            return true;
        }

        /// <summary>
        ///     Adds a SID to an internal list of domain controllers
        /// </summary>
        /// <param name="domainControllerSID"></param>
        public void AddDomainController(string domainControllerSID)
        {
            DomainControllers.TryAdd(domainControllerSID, new byte());
        }

        /// <summary>
        ///     Gets output objects for currently observed well known principals
        /// </summary>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public IEnumerable<OutputBase> GetWellKnownPrincipalOutput(string domain)
        {
            foreach (var wkp in SeenWellKnownPrincipals)
            {
                WellKnownPrincipal.GetWellKnownPrincipal(wkp.Value.WkpId, out var principal);
                OutputBase output = principal.ObjectType switch
                {
                    Label.User => new User(),
                    Label.Computer => new Computer(),
                    Label.Group => new Group(),
                    Label.GPO => new GPO(),
                    Label.Domain => new OutputTypes.Domain(),
                    Label.OU => new OU(),
                    Label.Container => new Container(),
                    _ => throw new ArgumentOutOfRangeException()
                };

                output.Properties.Add("name", $"{principal.ObjectIdentifier}@{wkp.Value.DomainName}".ToUpper());
                var domainSid = GetSidFromDomainName(wkp.Value.DomainName);
                output.Properties.Add("domainsid", domainSid);
                output.Properties.Add("domain", wkp.Value.DomainName.ToUpper());
                output.ObjectIdentifier = wkp.Key;
                yield return output;
            }

            var entdc = GetBaseEnterpriseDC(domain);
            entdc.Members = DomainControllers.Select(x => new TypedPrincipal(x.Key, Label.Computer)).ToArray();
            yield return entdc;
        }

        /// <summary>
        ///     Converts a
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public string ConvertWellKnownPrincipal(string sid, string domain)
        {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(sid, out _)) return sid;

            if (sid != "S-1-5-9") return $"{domain}-{sid}".ToUpper();

            var forest = GetForest(domain)?.Name;
            if (forest == null) _log.LogWarning("Error getting forest, ENTDC sid is likely incorrect");
            return $"{forest ?? "UNKNOWN"}-{sid}".ToUpper();
        }

        /// <summary>
        ///     Queries the global catalog to get potential SID matches for a username in the forest
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public string[] GetUserGlobalCatalogMatches(string name)
        {
            var tempName = name.ToLower();
            if (Cache.GetGCCache(tempName, out var sids))
                return sids;

            var query = new LDAPFilter().AddUsers($"samaccountname={tempName}").GetFilter();
            var results = QueryLDAP(query, SearchScope.Subtree, new[] { "objectsid" }, globalCatalog: true)
                .Select(x => x.GetSid()).Where(x => x != null).ToArray();
            Cache.AddGCCache(tempName, results);
            return results;
        }

        /// <summary>
        ///     Uses an LDAP lookup to attempt to find the Label for a given SID
        ///     Will also convert to a well known principal ID if needed
        /// </summary>
        /// <param name="id"></param>
        /// <param name="fallbackDomain"></param>
        /// <returns></returns>
        public TypedPrincipal ResolveIDAndType(string id, string fallbackDomain)
        {
            //This is a duplicated SID object which is weird and makes things unhappy. Throw it out
            if (id.Contains("0ACNF"))
                return null;

            if (GetWellKnownPrincipal(id, fallbackDomain, out var principal))
                return principal;

            var type = id.StartsWith("S-") ? LookupSidType(id, fallbackDomain) : LookupGuidType(id, fallbackDomain);
            return new TypedPrincipal(id, type);
        }

        /// <summary>
        ///     Attempts to lookup the Label for a sid
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public Label LookupSidType(string sid, string domain)
        {
            if (Cache.GetIDType(sid, out var type))
                return type;

            var hex = Helpers.ConvertSidToHexSid(sid);
            if (hex == null)
                return Label.Base;

            var rDomain = GetDomainNameFromSid(sid) ?? domain;

            var result =
                QueryLDAP($"(objectsid={hex})", SearchScope.Subtree, CommonProperties.TypeResolutionProps, rDomain)
                    .DefaultIfEmpty(null).FirstOrDefault();

            type = result?.GetLabel() ?? Label.Base;
            Cache.AddType(sid, type);
            return type;
        }

        /// <summary>
        ///     Attempts to lookup the Label for a GUID
        /// </summary>
        /// <param name="guid"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public Label LookupGuidType(string guid, string domain)
        {
            if (Cache.GetIDType(guid, out var type))
                return type;

            var hex = Helpers.ConvertGuidToHexGuid(guid);
            if (hex == null)
                return Label.Base;

            var result =
                QueryLDAP($"(objectguid={hex})", SearchScope.Subtree, CommonProperties.TypeResolutionProps, domain)
                    .DefaultIfEmpty(null).FirstOrDefault();

            type = result?.GetLabel() ?? Label.Base;
            Cache.AddType(guid, type);
            return type;
        }

        /// <summary>
        ///     Attempts to find the domain associated with a SID
        /// </summary>
        /// <param name="sid"></param>
        /// <returns></returns>
        public string GetDomainNameFromSid(string sid)
        {
            try
            {
                var parsedSid = new SecurityIdentifier(sid);
                var domainSid = parsedSid.AccountDomainSid?.Value.ToUpper();
                if (domainSid == null)
                    return null;

                _log.LogDebug("Resolving sid {DomainSid}", domainSid);

                if (Cache.GetDomainSidMapping(domainSid, out var domain))
                    return domain;

                _log.LogDebug("No cache hit for {DomainSid}", domainSid);
                domain = GetDomainNameFromSidLdap(domainSid);
                _log.LogDebug("Resolved to {Domain}", domain);

                //Cache both to and from so we can use this later
                if (domain != null)
                {
                    Cache.AddSidToDomain(domainSid, domain);
                    Cache.AddSidToDomain(domain, domainSid);
                }

                return domain;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        ///     Attempts to get the SID associated with a domain name
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        public string GetSidFromDomainName(string domainName)
        {
            var tempDomainName = NormalizeDomainName(domainName);
            if (tempDomainName == null)
                return null;
            if (Cache.GetDomainSidMapping(tempDomainName, out var sid)) return sid;

            var domainObj = GetDomain(tempDomainName);

            if (domainObj != null)
                sid = domainObj.GetDirectoryEntry().GetSid();
            else
                sid = null;

            if (sid != null)
            {
                Cache.AddSidToDomain(sid, tempDomainName);
                Cache.AddSidToDomain(tempDomainName, sid);
            }

            return sid;
        }

        /// <summary>
        ///     Performs Attribute Ranged Retrieval
        ///     https://docs.microsoft.com/en-us/windows/win32/adsi/attribute-range-retrieval
        ///     The function self-determines the range and internally handles the maximum step allowed by the server
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="attributeName"></param>
        /// <returns></returns>
        public IEnumerable<string> DoRangedRetrieval(string distinguishedName, string attributeName)
        {
            var domainName = Helpers.DistinguishedNameToDomain(distinguishedName);
            var task = Task.Run(() => CreateLDAPConnection(domainName, authType: _ldapConfig.AuthType));

            LdapConnection conn;

            try
            {
                conn = task.ConfigureAwait(false).GetAwaiter().GetResult();
            }
            catch
            {
                yield break;
            }

            if (conn == null)
                yield break;

            var index = 0;
            var step = 0;
            var baseString = $"{attributeName}";
            //Example search string: member;range=0-1000
            var currentRange = $"{baseString};range={index}-*";
            var complete = false;

            var searchRequest = CreateSearchRequest($"{attributeName}=*", SearchScope.Base, new[] { currentRange }, domainName, 
                distinguishedName);

            if (searchRequest == null)
                yield break;

            while (true)
            {
                SearchResponse response;

                response = (SearchResponse)conn.SendRequest(searchRequest);

                //If we ever get more than one response from here, something is horribly wrong
                if (response?.Entries.Count == 1)
                {
                    var entry = response.Entries[0];
                    //Process the attribute we get back to determine a few things
                    foreach (string attr in entry.Attributes.AttributeNames)
                    {
                        //Set our current range to the name of the attribute, which will tell us how far we are in "paging"
                        currentRange = attr;
                        //Check if the string has the * character in it. If it does, we've reached the end of this search 
                        complete = currentRange.IndexOf("*", 0, StringComparison.Ordinal) > 0;
                        //Set our step to the number of attributes that came back.
                        step = entry.Attributes[currentRange].Count;
                    }

                    foreach (string val in entry.Attributes[currentRange].GetValues(typeof(string)))
                    {
                        yield return val;
                        index++;
                    }

                    if (complete) yield break;

                    currentRange = $"{baseString};range={index}-{index + step}";
                    searchRequest.Attributes.Clear();
                    searchRequest.Attributes.Add(currentRange);
                }
                else
                {
                    //Something went wrong here.
                    yield break;
                }
            }
        }

        /// <summary>
        ///     Takes a host in most applicable forms from AD and attempts to resolve it into a SID.
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public async Task<string> ResolveHostToSid(string hostname, string domain)
        {
            var strippedHost = Helpers.StripServicePrincipalName(hostname).ToUpper().TrimEnd('$');

            if (_hostResolutionMap.TryGetValue(strippedHost, out var sid)) return sid;

            var normalDomain = NormalizeDomainName(domain);

            string tempName;
            string tempDomain = null;

            //Step 1: Handle non-IP address values
            if (!IPAddress.TryParse(strippedHost, out _))
            {
                // Format: ABC.TESTLAB.LOCAL
                if (strippedHost.Contains("."))
                {
                    var split = strippedHost.Split('.');
                    tempName = split[0];
                    tempDomain = string.Join(".", split.Skip(1).ToArray());
                }
                // Format: WINDOWS
                else
                {
                    tempName = strippedHost;
                    tempDomain = normalDomain;
                }

                // Add $ to the end of the name to match how computers are stored in AD
                tempName = $"{tempName}$".ToUpper();
                var principal = ResolveAccountName(tempName, tempDomain);
                sid = principal?.ObjectIdentifier;
                if (sid != null)
                {
                    _hostResolutionMap.TryAdd(strippedHost, sid);
                    return sid;
                }
            }

            //Step 2: Try NetWkstaGetInfo
            //Next we'll try calling NetWkstaGetInfo in hopes of getting the NETBIOS name directly from the computer
            //We'll use the hostname that we started with instead of the one from our previous step
            var workstationInfo = await CallNetWkstaGetInfo(strippedHost);
            if (workstationInfo.HasValue)
            {
                tempName = workstationInfo.Value.computer_name;
                tempDomain = workstationInfo.Value.lan_group;

                if (string.IsNullOrEmpty(tempDomain))
                    tempDomain = normalDomain;

                if (!string.IsNullOrEmpty(tempName))
                {
                    //Append the $ to indicate this is a computer
                    tempName = $"{tempName}$".ToUpper();
                    var principal = ResolveAccountName(tempName, tempDomain);
                    if (principal != null)
                    {
                        _hostResolutionMap.TryAdd(strippedHost, sid);
                        return sid;
                    }
                }
            }

            //Step 3: Socket magic
            // Attempt to request the NETBIOS name of the computer directly
            if (RequestNETBIOSNameFromComputer(strippedHost, normalDomain, out tempName))
            {
                tempDomain ??= normalDomain;
                tempName = $"{tempName}$".ToUpper();

                var principal = ResolveAccountName(tempName, tempDomain);
                sid = principal?.ObjectIdentifier;
                if (sid != null)
                {
                    _hostResolutionMap.TryAdd(strippedHost, sid);
                    return sid;
                }
            }

            //Try DNS resolution next
            string resolvedHostname;
            try
            {
                resolvedHostname = (await Dns.GetHostEntryAsync(strippedHost)).HostName;
            }
            catch
            {
                resolvedHostname = null;
            }

            if (resolvedHostname != null)
            {
                var splitName = resolvedHostname.Split('.');
                tempName = $"{splitName[0]}$".ToUpper();
                tempDomain = string.Join(".", splitName.Skip(1));

                var principal = ResolveAccountName(tempName, tempDomain);
                sid = principal?.ObjectIdentifier;
                if (sid != null)
                {
                    _hostResolutionMap.TryAdd(strippedHost, sid);
                    return sid;
                }
            }

            //If we get here, everything has failed, and life is very sad.
            tempName = strippedHost;
            tempDomain = normalDomain;

            if (tempName.Contains("."))
            {
                _hostResolutionMap.TryAdd(strippedHost, tempName);
                return tempName;
            }

            tempName = $"{tempName}.{tempDomain}";
            _hostResolutionMap.TryAdd(strippedHost, tempName);
            return tempName;
        }

        /// <summary>
        ///     Attempts to convert a bare account name (usually from session enumeration) to its corresponding ID and object type
        /// </summary>
        /// <param name="name"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public TypedPrincipal ResolveAccountName(string name, string domain)
        {
            if (string.IsNullOrWhiteSpace(name))
                return null;
            
            if (Cache.GetPrefixedValue(name, domain, out var id) && Cache.GetIDType(id, out var type))
                return new TypedPrincipal
                {
                    ObjectIdentifier = id,
                    ObjectType = type
                };

            var d = NormalizeDomainName(domain);
            var result = QueryLDAP($"(samaccountname={name})", SearchScope.Subtree,
                CommonProperties.TypeResolutionProps,
                d).DefaultIfEmpty(null).FirstOrDefault();

            if (result == null)
            {
                _log.LogDebug("ResolveAccountName - unable to get result for {Name}", name);
                return null;
            }


            type = result.GetLabel();
            id = result.GetObjectIdentifier();

            if (id == null)
            {
                _log.LogDebug("ResolveAccountName - could not retrieve ID on {DN} for {Name}", result.DistinguishedName,
                    name);
                return null;
            }

            Cache.AddPrefixedValue(name, domain, id);
            Cache.AddType(id, type);

            id = ConvertWellKnownPrincipal(id, domain);

            return new TypedPrincipal
            {
                ObjectIdentifier = id,
                ObjectType = type
            };
        }

        /// <summary>
        ///     Attempts to convert a distinguishedname to its corresponding ID and object type.
        /// </summary>
        /// <param name="dn">DistinguishedName</param>
        /// <returns>A <c>TypedPrincipal</c> object with the SID and Label</returns>
        public TypedPrincipal ResolveDistinguishedName(string dn)
        {
            if (Cache.GetConvertedValue(dn, out var id) && Cache.GetIDType(id, out var type))
                return new TypedPrincipal
                {
                    ObjectIdentifier = id,
                    ObjectType = type
                };

            var domain = Helpers.DistinguishedNameToDomain(dn);
            var result = QueryLDAP("(objectclass=*)", SearchScope.Base, CommonProperties.TypeResolutionProps, domain,
                    adsPath: dn)
                .DefaultIfEmpty(null).FirstOrDefault();

            if (result == null)
            {
                _log.LogDebug("ResolveDistinguishedName - No result for {DN}", dn);
                return null;
            }

            id = result.GetObjectIdentifier();
            if (id == null)
            {
                _log.LogDebug("ResolveDistinguishedName - could not retrieve object identifier from {DN}", dn);
                return null;
            }

            if (GetWellKnownPrincipal(id, domain, out var principal)) return principal;

            type = result.GetLabel();

            Cache.AddConvertedValue(dn, id);
            Cache.AddType(id, type);

            id = ConvertWellKnownPrincipal(id, domain);

            return new TypedPrincipal
            {
                ObjectIdentifier = id,
                ObjectType = type
            };
        }

        /// <summary>
        ///     Queries LDAP using LDAPQueryOptions
        /// </summary>
        /// <param name="options"></param>
        /// <returns></returns>
        public IEnumerable<ISearchResultEntry> QueryLDAP(LDAPQueryOptions options)
        {
            return QueryLDAP(
                options.Filter,
                options.Scope,
                options.Properties,
                options.CancellationToken,
                options.DomainName,
                options.IncludeAcl,
                options.ShowDeleted,
                options.AdsPath,
                options.GlobalCatalog,
                options.SkipCache
            );
        }

        /// <summary>
        ///     Performs an LDAP query using the parameters specified by the user.
        /// </summary>
        /// <param name="ldapFilter">LDAP filter</param>
        /// <param name="scope">SearchScope to query</param>
        /// <param name="props">LDAP properties to fetch for each object</param>
        /// <param name="cancellationToken">Cancellation Token</param>
        /// <param name="includeAcl">Include the DACL and Owner values in the NTSecurityDescriptor</param>
        /// <param name="showDeleted">Include deleted objects</param>
        /// <param name="domainName">Domain to query</param>
        /// <param name="adsPath">ADS path to limit the query too</param>
        /// <param name="globalCatalog">Use the global catalog instead of the regular LDAP server</param>
        /// <param name="skipCache">
        ///     Skip the connection cache and force a new connection. You must dispose of this connection
        ///     yourself.
        /// </param>
        /// <returns>All LDAP search results matching the specified parameters</returns>
        public IEnumerable<ISearchResultEntry> QueryLDAP(string ldapFilter, SearchScope scope,
            string[] props, CancellationToken cancellationToken, string domainName = null, bool includeAcl = false,
            bool showDeleted = false, string adsPath = null, bool globalCatalog = false, bool skipCache = false)
        {
            _log.LogTrace("Creating ldap connection for {Target} with filter {Filter}",
                globalCatalog ? "Global Catalog" : "DC", ldapFilter);
            var task = globalCatalog
                ? Task.Run(() => CreateGlobalCatalogConnection(domainName, _ldapConfig.AuthType))
                : Task.Run(() => CreateLDAPConnection(domainName, skipCache, _ldapConfig.AuthType));

            LdapConnection conn;
            try
            {
                conn = task.ConfigureAwait(false).GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                _log.LogWarning(e, "Exception getting LDAP connection for {Filter} and domain {Domain}", ldapFilter, domainName ?? "Default Domain");
                yield break;
            }

            if (conn == null)
            {
                _log.LogWarning("LDAP connection is null for filter {Filter} and domain {Domain}", ldapFilter,
                    domainName ?? "Default Domain");
                yield break;
            }

            var request = CreateSearchRequest(ldapFilter, scope, props, domainName, adsPath, showDeleted);

            if (request == null)
            {
                _log.LogWarning("Search request is null for filter {Filter} and domain {Domain}", ldapFilter, domainName ?? "Default Domain");
                yield break;
            }

            var pageControl = new PageResultRequestControl(500);
            request.Controls.Add(pageControl);

            if (includeAcl)
                request.Controls.Add(new SecurityDescriptorFlagControl
                {
                    SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
                });

            PageResultResponseControl pageResponse = null;
            while (true)
            {
                if (cancellationToken.IsCancellationRequested)
                    yield break;

                SearchResponse response;
                try
                {
                    _log.LogTrace("Sending LDAP request for {Filter}", ldapFilter);
                    response = (SearchResponse)conn.SendRequest(request);
                    if (response != null)
                        pageResponse = (PageResultResponseControl)response.Controls
                            .Where(x => x is PageResultResponseControl).DefaultIfEmpty(null).FirstOrDefault();
                }
                catch (LdapException le)
                {
                    if (le.ErrorCode != 82)
                        _log.LogWarning(le,
                            "LDAP Exception in Loop: {ErrorCode}. {ServerErrorMessage}. {Message}. Filter: {Filter}. Domain: {Domain}",
                            le.ErrorCode, le.ServerErrorMessage, le.Message, ldapFilter, domainName);

                    yield break;
                }
                catch (Exception e)
                {
                    _log.LogWarning(e, "Exception in LDAP loop for {Filter} and {Domain}", ldapFilter, domainName);
                    yield break;
                }

                if (cancellationToken.IsCancellationRequested)
                    yield break;

                if (response == null || pageResponse == null)
                    continue;

                foreach (SearchResultEntry entry in response.Entries)
                {
                    if (cancellationToken.IsCancellationRequested)
                        yield break;

                    yield return new SearchResultEntryWrapper(entry, this);
                }

                if (pageResponse.Cookie.Length == 0 || response.Entries.Count == 0 ||
                    cancellationToken.IsCancellationRequested)
                    yield break;

                pageControl.Cookie = pageResponse.Cookie;
            }
        }

        /// <summary>
        ///     Performs an LDAP query using the parameters specified by the user.
        /// </summary>
        /// <param name="ldapFilter">LDAP filter</param>
        /// <param name="scope">SearchScope to query</param>
        /// <param name="props">LDAP properties to fetch for each object</param>
        /// <param name="includeAcl">Include the DACL and Owner values in the NTSecurityDescriptor</param>
        /// <param name="showDeleted">Include deleted objects</param>
        /// <param name="domainName">Domain to query</param>
        /// <param name="adsPath">ADS path to limit the query too</param>
        /// <param name="globalCatalog">Use the global catalog instead of the regular LDAP server</param>
        /// <param name="skipCache">
        ///     Skip the connection cache and force a new connection. You must dispose of this connection
        ///     yourself.
        /// </param>
        /// <returns>All LDAP search results matching the specified parameters</returns>
        public IEnumerable<ISearchResultEntry> QueryLDAP(string ldapFilter, SearchScope scope,
            string[] props, string domainName = null, bool includeAcl = false, bool showDeleted = false,
            string adsPath = null, bool globalCatalog = false, bool skipCache = false)
        {
            _log.LogTrace("Creating ldap connection for {Target} with filter {Filter}",
                globalCatalog ? "Global Catalog" : "DC", ldapFilter);
            var task = globalCatalog
                ? Task.Run(() => CreateGlobalCatalogConnection(domainName, _ldapConfig.AuthType))
                : Task.Run(() => CreateLDAPConnection(domainName, skipCache, _ldapConfig.AuthType));

            LdapConnection conn;
            try
            {
                conn = task.ConfigureAwait(false).GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                _log.LogWarning(e, "Exception getting LDAP connection for filter {Filter} and domain {Domain}", ldapFilter, domainName ?? "Default Domain");
                yield break;
            }

            if (conn == null)
            {
                _log.LogWarning("LDAP connection is null for filter {Filter} and domain {Domain}", ldapFilter,
                    domainName ?? "Default Domain");
                yield break;
            }

            var request = CreateSearchRequest(ldapFilter, scope, props, domainName, adsPath, showDeleted);

            if (request == null)
            {
                _log.LogWarning("Search request is null for filter {Filter} and domain {Domain}", ldapFilter, domainName ?? "Default Domain");
                yield break;
            }

            var pageControl = new PageResultRequestControl(500);
            request.Controls.Add(pageControl);

            if (includeAcl)
                request.Controls.Add(new SecurityDescriptorFlagControl
                {
                    SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
                });

            PageResultResponseControl pageResponse = null;
            while (true)
            {
                SearchResponse response;
                try
                {
                    _log.LogTrace("Sending LDAP request for {Filter}", ldapFilter);
                    response = (SearchResponse)conn.SendRequest(request);
                    if (response != null)
                        pageResponse = (PageResultResponseControl)response.Controls
                            .Where(x => x is PageResultResponseControl).DefaultIfEmpty(null).FirstOrDefault();
                }
                catch (LdapException le)
                {
                    if (le.ErrorCode != 82)
                        _log.LogWarning(le,
                            "LDAP Exception in Loop: {ErrorCode}. {ServerErrorMessage}. {Message}. Filter: {Filter}. Domain: {Domain}",
                            le.ErrorCode, le.ServerErrorMessage, le.Message, ldapFilter, domainName);
                    yield break;
                }
                catch (Exception e)
                {
                    _log.LogWarning(e, "Exception in LDAP loop for {Filter} and {Domain}", ldapFilter, domainName ?? "Default Domain");
                    yield break;
                }

                if (response == null || pageResponse == null) continue;

                if (response.Entries == null)
                    yield break;

                foreach (SearchResultEntry entry in response.Entries)
                    yield return new SearchResultEntryWrapper(entry, this);

                if (pageResponse.Cookie.Length == 0 || response.Entries.Count == 0)
                    yield break;

                pageControl.Cookie = pageResponse.Cookie;
            }
        }

        /// <summary>
        ///     Gets the forest associated with a domain.
        ///     If no domain is provided, defaults to current domain
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        public virtual Forest GetForest(string domainName = null)
        {
            try
            {
                if (domainName == null && _ldapConfig.Username == null)
                    return Forest.GetCurrentForest();

                var domain = GetDomain(domainName);
                return domain?.Forest;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        ///     Creates a new ActiveDirectorySecurityDescriptor
        ///     Function created for testing purposes
        /// </summary>
        /// <returns></returns>
        public ActiveDirectorySecurityDescriptor MakeSecurityDescriptor()
        {
            return new ActiveDirectorySecurityDescriptor(new ActiveDirectorySecurity());
        }

        /// <summary>
        ///     Tests the current LDAP config to ensure its valid by pulling a domain object
        /// </summary>
        /// <returns>True if connection was successful, else false</returns>
        public bool TestLDAPConfig(string domain)
        {
            var filter = new LDAPFilter();
            filter.AddDomains();
            
            var resDomain = GetDomain(domain)?.Name ?? domain;
            _log.LogTrace("Testing LDAP connection for domain {Domain}", resDomain);
            
            var result = QueryLDAP(filter.GetFilter(), SearchScope.Subtree, CommonProperties.ObjectID, resDomain)
                .DefaultIfEmpty(null).FirstOrDefault();
            
            _log.LogTrace("Result object from LDAP connection test is {DN}", result?.DistinguishedName ?? "null");

            return result != null;
        }

        /// <summary>
        ///     Gets the domain object associated with the specified domain name.
        ///     Defaults to current domain if none specified
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        public Domain GetDomain(string domainName = null)
        {
            var cacheKey = domainName ?? NullCacheKey;
            if (_domainCache.TryGetValue(cacheKey, out var domain)) return domain;

            try
            {
                DirectoryContext context;
                if (_ldapConfig.Username != null)
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName, _ldapConfig.Username,
                            _ldapConfig.Password)
                        : new DirectoryContext(DirectoryContextType.Domain, _ldapConfig.Username,
                            _ldapConfig.Password);
                else
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName)
                        : new DirectoryContext(DirectoryContextType.Domain);

                domain = Domain.GetDomain(context);
            }
            catch
            {
                domain = null;
            }

            _domainCache.TryAdd(cacheKey, domain);
            return domain;
        }

        private Group GetBaseEnterpriseDC(string domain)
        {
            var forest = GetForest(domain)?.Name;
            if (forest == null) _log.LogWarning("Error getting forest, ENTDC sid is likely incorrect");
            var g = new Group { ObjectIdentifier = $"{forest}-S-1-5-9".ToUpper() };
            g.Properties.Add("name", $"ENTERPRISE DOMAIN CONTROLLERS@{forest ?? "UNKNOWN"}".ToUpper());
            g.Properties.Add("domainsid", GetSidFromDomainName(forest));
            g.Properties.Add("domain", forest);
            return g;
        }

        /// <summary>
        ///     Updates the config for querying LDAP
        /// </summary>
        /// <param name="config"></param>
        public void UpdateLDAPConfig(LDAPConfig config)
        {
            _ldapConfig = config;
        }

        private string GetDomainNameFromSidLdap(string sid)
        {
            var hexSid = Helpers.ConvertSidToHexSid(sid);

            if (hexSid == null)
                return null;

            //Search using objectsid first
            var result =
                QueryLDAP($"(&(objectclass=domain)(objectsid={hexSid}))", SearchScope.Subtree,
                    new[] { "distinguishedname" }, globalCatalog: true).DefaultIfEmpty(null).FirstOrDefault();

            if (result != null)
            {
                var domainName = Helpers.DistinguishedNameToDomain(result.DistinguishedName);
                return domainName;
            }

            //Try trusteddomain objects with the securityidentifier attribute
            result =
                QueryLDAP($"(&(objectclass=trusteddomain)(securityidentifier={sid}))", SearchScope.Subtree,
                    new[] { "cn" }, globalCatalog: true).DefaultIfEmpty(null).FirstOrDefault();

            if (result != null)
            {
                var domainName = result.GetProperty(LDAPProperties.CanonicalName);
                return domainName;
            }

            //We didn't find anything so just return null
            return null;
        }

        /// <summary>
        ///     Uses a socket and a set of bytes to request the NETBIOS name from a remote computer
        /// </summary>
        /// <param name="server"></param>
        /// <param name="domain"></param>
        /// <param name="netbios"></param>
        /// <returns></returns>
        private static bool RequestNETBIOSNameFromComputer(string server, string domain, out string netbios)
        {
            var receiveBuffer = new byte[1024];
            var requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                //Set receive timeout to 1 second
                requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1000);
                EndPoint remoteEndpoint;

                //We need to create an endpoint to bind too. If its an IP, just use that.
                if (IPAddress.TryParse(server, out var parsedAddress))
                    remoteEndpoint = new IPEndPoint(parsedAddress, 137);
                else
                    //If its not an IP, we're going to try and resolve it from DNS
                    try
                    {
                        IPAddress address;
                        if (server.Contains("."))
                            address = Dns
                                .GetHostAddresses(server).First(x => x.AddressFamily == AddressFamily.InterNetwork);
                        else
                            address = Dns.GetHostAddresses($"{server}.{domain}")[0];

                        if (address == null)
                        {
                            netbios = null;
                            return false;
                        }

                        remoteEndpoint = new IPEndPoint(address, 137);
                    }
                    catch
                    {
                        //Failed to resolve an IP, so return null
                        netbios = null;
                        return false;
                    }

                var originEndpoint = new IPEndPoint(IPAddress.Any, 0);
                requestSocket.Bind(originEndpoint);

                try
                {
                    requestSocket.SendTo(NameRequest, remoteEndpoint);
                    var receivedByteCount = requestSocket.ReceiveFrom(receiveBuffer, ref remoteEndpoint);
                    if (receivedByteCount >= 90)
                    {
                        netbios = new ASCIIEncoding().GetString(receiveBuffer, 57, 16).Trim('\0', ' ');
                        return true;
                    }

                    netbios = null;
                    return false;
                }
                catch (SocketException)
                {
                    netbios = null;
                    return false;
                }
            }
            finally
            {
                //Make sure we close the socket if its open
                requestSocket.Close();
            }
        }

        /// <summary>
        ///     Calls the NetWkstaGetInfo API on a hostname
        /// </summary>
        /// <param name="hostname"></param>
        /// <returns></returns>
        private async Task<NativeMethods.WorkstationInfo100?> CallNetWkstaGetInfo(string hostname)
        {
            if (!await _portScanner.CheckPort(hostname))
                return null;

            try
            {
                return _nativeMethods.CallNetWkstaGetInfo(hostname);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        ///     Creates a SearchRequest object for use in querying LDAP.
        /// </summary>
        /// <param name="filter">LDAP filter</param>
        /// <param name="scope">SearchScope to query</param>
        /// <param name="attributes">LDAP properties to fetch for each object</param>
        /// <param name="domainName">Domain to query</param>
        /// <param name="adsPath">ADS path to limit the query too</param>
        /// <param name="showDeleted">Include deleted objects in results</param>
        /// <returns>A built SearchRequest</returns>
        private SearchRequest CreateSearchRequest(string filter, SearchScope scope, string[] attributes,
            string domainName = null, string adsPath = null, bool showDeleted = false)
        {
            var domain = GetDomain(domainName)?.Name ?? domainName;

            if (domain == null)
                return null;

            var adPath = adsPath?.Replace("LDAP://", "") ?? $"DC={domain.Replace(".", ",DC=")}";

            var request = new SearchRequest(adPath, filter, scope, attributes);
            request.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
            if (showDeleted)
                request.Controls.Add(new ShowDeletedControl());

            return request;
        }

        /// <summary>
        ///     Creates a LDAP connection to a global catalog server
        /// </summary>
        /// <param name="domainName">Domain to connect too</param>
        /// <param name="authType">Auth type to use. Defaults to Kerberos. Use Negotiate for netonly scenarios</param>
        /// <returns>A connected LdapConnection or null</returns>
        private async Task<LdapConnection> CreateGlobalCatalogConnection(string domainName = null, AuthType authType = AuthType.Kerberos)
        {
            string targetServer;
            if (_ldapConfig.Server != null)
            {
                targetServer = _ldapConfig.Server;
            }
            else
            {
                var domain = GetDomain(domainName);
                if (domain == null)
                {
                    _log.LogDebug("Unable to create global catalog connection for domain {DomainName}", domainName);
                    return null;
                }
                
                targetServer = await GetUsableDomainController(domain);
            }

            if (targetServer == null)
                return null;

            if (_globalCatalogConnections.TryGetValue(targetServer, out var connection))
                return connection;

            connection = new LdapConnection(new LdapDirectoryIdentifier(targetServer, 3268));

            connection.SessionOptions.ProtocolVersion = 3;
            
            if (_ldapConfig.Username != null)
            {
                var cred = new NetworkCredential(_ldapConfig.Username, _ldapConfig.Password);
                connection.Credential = cred;
            }

            if (_ldapConfig.DisableSigning)
            {
                connection.SessionOptions.Sealing = false;
                connection.SessionOptions.Signing = false;
            }
            
            connection.AuthType = authType;

            _globalCatalogConnections.TryAdd(targetServer, connection);
            return connection;
        }

        /// <summary>
        ///     Creates an LDAP connection with appropriate options based off the ldap configuration. Caches connections
        /// </summary>
        /// <param name="domainName">The domain to connect too</param>
        /// <param name="skipCache">Skip the connection cache</param>
        /// <param name="authType">Auth type to use. Defaults to Kerberos. Use Negotiate for netonly scenarios</param>
        /// <returns>A connected LDAP connection or null</returns>
        private async Task<LdapConnection> CreateLDAPConnection(string domainName = null, bool skipCache = false, AuthType authType = AuthType.Kerberos)
        {
            string targetServer;
            if (_ldapConfig.Server != null)
            {
                targetServer = _ldapConfig.Server;
            }
            else
            {
                var domain = GetDomain(domainName);
                if (domain == null)
                {
                    _log.LogDebug("Unable to create ldap connection for domain {DomainName}", domainName);
                    return null;
                }
                
                targetServer = await GetUsableDomainController(domain);
            }

            if (targetServer == null)
                return null;

            if (!skipCache)
                if (_ldapConnections.TryGetValue(targetServer, out var conn))
                    return conn;

            var port = _ldapConfig.GetPort();
            var ident = new LdapDirectoryIdentifier(targetServer, port, false, false);
            var connection = new LdapConnection(ident) { Timeout = new TimeSpan(0, 0, 5, 0) };
            if (_ldapConfig.Username != null)
            {
                var cred = new NetworkCredential(_ldapConfig.Username, _ldapConfig.Password);
                connection.Credential = cred;
            }

            //These options are important!
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;

            if (_ldapConfig.DisableSigning)
            {
                connection.SessionOptions.Sealing = false;
                connection.SessionOptions.Signing = false;
            }

            if (_ldapConfig.SSL)
                connection.SessionOptions.SecureSocketLayer = true;
            
            if (_ldapConfig.DisableCertVerification)
                connection.SessionOptions.VerifyServerCertificate = (ldapConnection, certificate) => true;

            connection.AuthType = authType;

            if (!skipCache)
                _ldapConnections.TryAdd(targetServer, connection);

            return connection;
        }

        private async Task<string> GetUsableDomainController(Domain domain, bool gc = false)
        {
            if (gc && _gcControllerCache.TryGetValue(domain.Name.ToUpper(), out var dc))
                return dc;

            if (!gc && _domainControllerCache.TryGetValue(domain.Name.ToUpper(), out dc))
                return dc;
            
            var port = gc ? 3268 : _ldapConfig.GetPort();
            var pdc = domain.PdcRoleOwner.Name;
            if (await _portScanner.CheckPort(pdc, port))
            {
                _domainControllerCache.TryAdd(domain.Name.ToUpper(), pdc);
                _log.LogInformation("Found usable Domain Controller for {Domain} : {PDC}", domain.Name, pdc);
                return pdc;
            }

            //If the PDC isn't reachable loop through the rest
            foreach (DomainController domainController in domain.DomainControllers)
            {
                var name = domainController.Name;
                if (!await _portScanner.CheckPort(name, port)) continue;
                _log.LogInformation("Found usable Domain Controller for {Domain} : {PDC}", domain.Name, name);
                _domainControllerCache.TryAdd(domain.Name.ToUpper(), name);
                return name;
            }

            //If we get here, somehow we didn't get any usable DCs. Save it off as null
            _domainControllerCache.TryAdd(domain.Name.ToUpper(), null);
            _log.LogWarning("Unable to find usable domain controller for {Domain}", domain.Name);
            return null;
        }

        /// <summary>
        ///     Normalizes a domain name to its full DNS name
        /// </summary>
        /// <param name="domain"></param>
        /// <returns></returns>
        internal string NormalizeDomainName(string domain)
        {
            if (domain == null)
                return null;

            var resolved = domain;

            if (resolved.Contains("."))
                return domain.ToUpper();

            resolved = ResolveDomainNetbiosToDns(domain) ?? domain;

            return resolved.ToUpper();
        }

        /// <summary>
        ///     Turns a domain Netbios name into its FQDN using the DsGetDcName function (TESTLAB -> TESTLAB.LOCAL)
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        internal string ResolveDomainNetbiosToDns(string domainName)
        {
            var key = domainName.ToUpper();
            if (_netbiosCache.TryGetValue(key, out var flatName))
                return flatName;

            var domain = GetDomain(domainName);
            if (domain != null)
            {
                _netbiosCache.TryAdd(key, domain.Name);
                return domain.Name;
            }

            var computerName = _ldapConfig.Server;

            var dci = _nativeMethods.CallDsGetDcName(computerName, domainName);
            if (dci.HasValue)
            {
                flatName = dci.Value.DomainName;
                _netbiosCache.TryAdd(key, flatName);
                return flatName;
            }

            return domainName.ToUpper();
        }

        private class ResolvedWellKnownPrincipal
        {
            public string DomainName { get; set; }
            public string WkpId { get; set; }
        }
    }
}