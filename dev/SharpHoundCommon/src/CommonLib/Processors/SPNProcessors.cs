using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class SPNProcessors
    {
        private const string MSSQLSPNString = "mssqlsvc";
        private readonly ILogger _log;
        private readonly ILDAPUtils _utils;

        public SPNProcessors(ILDAPUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("SPNProc");
        }

        public IAsyncEnumerable<SPNPrivilege> ReadSPNTargets(ResolvedSearchResult result,
            ISearchResultEntry entry)
        {
            var members = entry.GetArrayProperty(LDAPProperties.ServicePrincipalNames);
            var name = result.DisplayName;
            var dn = entry.DistinguishedName;

            return ReadSPNTargets(members, dn, name);
        }

        public async IAsyncEnumerable<SPNPrivilege> ReadSPNTargets(string[] servicePrincipalNames,
            string distinguishedName, string objectName = "")
        {
            if (servicePrincipalNames.Length == 0)
            {
                _log.LogTrace("SPN Array is empty for {Name}", objectName);
                yield break;
            }

            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);

            foreach (var spn in servicePrincipalNames)
            {
                //This SPN format isn't useful for us right now (username@domain)
                if (spn.Contains("@"))
                {
                    _log.LogTrace("Skipping spn without @ {SPN} for {Name}", spn, objectName);
                    continue;
                }

                _log.LogTrace("Processing SPN {SPN} for {Name}", spn, objectName);

                if (spn.ToLower().Contains(MSSQLSPNString))
                {
                    _log.LogTrace("Matched SQL SPN {SPN} for {Name}", spn, objectName);
                    var port = 1433;

                    if (spn.Contains(":"))
                        if (!int.TryParse(spn.Split(':')[1], out port))
                            port = 1433;

                    var host = await _utils.ResolveHostToSid(spn, domain);
                    _log.LogTrace("Resolved {SPN} to {Hostname}", spn, host);
                    if (host != null && host.StartsWith("S-1-"))
                        yield return new SPNPrivilege
                        {
                            ComputerSID = host,
                            Port = port,
                            Service = EdgeNames.SQLAdmin
                        };
                }
            }
        }
    }
}