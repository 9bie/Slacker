using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ContainerProcessor
    {
        private readonly ILogger _log;
        private readonly ILDAPUtils _utils;

        public ContainerProcessor(ILDAPUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("ContainerProc");
        }

        private static bool IsDistinguishedNameFiltered(string distinguishedName)
        {
            var dn = distinguishedName.ToUpper();
            if (dn.Contains("CN=PROGRAM DATA,DC=")) return true;

            if (dn.Contains("CN=SYSTEM,DC=")) return true;

            return false;
        }

        /// <summary>
        /// Helper function using commonlib types to pass to GetContainerChildObjects
        /// </summary>
        /// <param name="result"></param>
        /// <param name="entry"></param>
        /// <returns></returns>
        public IEnumerable<TypedPrincipal> GetContainerChildObjects(ResolvedSearchResult result,
            ISearchResultEntry entry)
        {
            var name = result.DisplayName;
            var dn = entry.DistinguishedName;

            return GetContainerChildObjects(dn, name);
        }

        /// <summary>
        ///     Finds all immediate child objects of a container.
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="containerName"></param>
        /// <returns></returns>
        public IEnumerable<TypedPrincipal> GetContainerChildObjects(string distinguishedName, string containerName = "")
        {
            var filter = new LDAPFilter().AddComputers().AddUsers().AddGroups().AddOUs().AddContainers();
            foreach (var childEntry in _utils.QueryLDAP(filter.GetFilter(), SearchScope.OneLevel,
                CommonProperties.ObjectID, Helpers.DistinguishedNameToDomain(distinguishedName),
                adsPath: distinguishedName))
            {
                var dn = childEntry.DistinguishedName;
                if (IsDistinguishedNameFiltered(dn))
                {
                    _log.LogTrace("Skipping filtered child {Child} for {Container}", dn, containerName);
                    continue;
                }

                var id = childEntry.GetObjectIdentifier();
                if (id == null)
                {
                    _log.LogTrace("Got null ID for {ChildDN} under {Container}", childEntry.DistinguishedName,
                        containerName);
                    continue;
                }

                var res = _utils.ResolveIDAndType(id, Helpers.DistinguishedNameToDomain(dn));
                if (res == null)
                {
                    _log.LogTrace("Failed to resolve principal for {ID}", id);
                    continue;
                }

                yield return res;
            }
        }

        public IEnumerable<GPLink> ReadContainerGPLinks(ResolvedSearchResult result, ISearchResultEntry entry)
        {
            var links = entry.GetProperty(LDAPProperties.GPLink);

            return ReadContainerGPLinks(links);
        }

        /// <summary>
        ///     Reads the "gplink" property from a SearchResult and converts the links into the acceptable SharpHound format
        /// </summary>
        /// <param name="gpLink"></param>
        /// <returns></returns>
        public IEnumerable<GPLink> ReadContainerGPLinks(string gpLink)
        {
            if (gpLink == null)
                yield break;

            foreach (var link in Helpers.SplitGPLinkProperty(gpLink))
            {
                var enforced = link.Status.Equals("2");

                var res = _utils.ResolveDistinguishedName(link.DistinguishedName);

                if (res == null)
                {
                    _log.LogTrace("Failed to resolve DN {DN}", link.DistinguishedName);
                    continue;
                }

                yield return new GPLink
                {
                    GUID = res.ObjectIdentifier,
                    IsEnforced = enforced
                };
            }
        }

        /// <summary>
        ///     Checks if a container blocks privilege inheritance
        /// </summary>
        /// <param name="gpOptions"></param>
        /// <returns></returns>
        public static bool ReadBlocksInheritance(string gpOptions)
        {
            return gpOptions is "1";
        }
    }
}