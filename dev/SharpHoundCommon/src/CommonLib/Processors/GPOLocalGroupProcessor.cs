using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.XPath;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class GPOLocalGroupProcessor
    {
        private static readonly Regex KeyRegex = new(@"(.+?)\s*=(.*)", RegexOptions.Compiled);

        private static readonly Regex MemberRegex =
            new(@"\[Group Membership\](.*)(?:\[|$)", RegexOptions.Compiled | RegexOptions.Singleline);

        private static readonly Regex MemberLeftRegex =
            new(@"(.*(?:S-1-5-32-544|S-1-5-32-555|S-1-5-32-562|S-1-5-32-580)__Members)", RegexOptions.Compiled |
                RegexOptions.IgnoreCase);

        private static readonly Regex MemberRightRegex =
            new(@"(S-1-5-32-544|S-1-5-32-555|S-1-5-32-562|S-1-5-32-580)", RegexOptions.Compiled |
                                                                          RegexOptions.IgnoreCase);

        private static readonly Regex ExtractRid =
            new(@"S-1-5-32-([0-9]{3})", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly ConcurrentDictionary<string, List<GroupAction>> GpoActionCache = new();

        private static readonly Dictionary<string, LocalGroupRids> ValidGroupNames =
            new(StringComparer.OrdinalIgnoreCase)
            {
                {"Administrators", LocalGroupRids.Administrators},
                {"Remote Desktop Users", LocalGroupRids.RemoteDesktopUsers},
                {"Remote Management Users", LocalGroupRids.PSRemote},
                {"Distributed COM Users", LocalGroupRids.DcomUsers}
            };

        private readonly ILDAPUtils _utils;
        private readonly ILogger _log;

        public GPOLocalGroupProcessor(ILDAPUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("GPOLocalGroupProc");
        }

        public Task<ResultingGPOChanges> ReadGPOLocalGroups(ISearchResultEntry entry)
        {
            var links = entry.GetProperty(LDAPProperties.GPLink);
            var dn = entry.DistinguishedName;
            return ReadGPOLocalGroups(links, dn);
        }
        
        public async Task<ResultingGPOChanges> ReadGPOLocalGroups(string gpLink, string distinguishedName)
        {
            var ret = new ResultingGPOChanges();
            //If the gplink property is null, we don't need to process anything
            if (gpLink == null)
                return ret;

            // First lets check if this OU actually has computers that it contains. If not, then we'll ignore it.
            // Its cheaper to fetch the affected computers from LDAP first and then process the GPLinks 
            var options = new LDAPQueryOptions
            {
                Filter = new LDAPFilter().AddComputers().GetFilter(),
                Scope = SearchScope.Subtree,
                Properties = CommonProperties.ObjectSID,
                AdsPath = distinguishedName
            };

            var affectedComputers = _utils.QueryLDAP(options)
                .Select(x => x.GetSid())
                .Where(x => x != null)
                .Select(x => new TypedPrincipal
                {
                    ObjectIdentifier = x,
                    ObjectType = Label.Computer
                }).ToArray();

            //If there's no computers then we don't care about this OU
            if (affectedComputers.Length == 0)
                return ret;

            var enforced = new List<string>();
            var unenforced = new List<string>();

            // Split our link property up and remove disabled links
            foreach (var link in Helpers.SplitGPLinkProperty(gpLink))
                switch (link.Status)
                {
                    case "0":
                        unenforced.Add(link.DistinguishedName);
                        break;
                    case "2":
                        enforced.Add(link.DistinguishedName);
                        break;
                }

            //Set up our links in the correct order.
            // Enforced links override unenforced, and also respect the order in which they are placed in the GPLink property
            var orderedLinks = new List<string>();
            orderedLinks.AddRange(unenforced);
            orderedLinks.AddRange(enforced);

            var data = new Dictionary<LocalGroupRids, GroupResults>();
            foreach (var rid in Enum.GetValues(typeof(LocalGroupRids))) data[(LocalGroupRids) rid] = new GroupResults();

            foreach (var linkDn in orderedLinks)
            {
                if (!GpoActionCache.TryGetValue(linkDn.ToLower(), out var actions))
                {
                    actions = new List<GroupAction>();

                    var gpoDomain = Helpers.DistinguishedNameToDomain(linkDn);

                    var opts = new LDAPQueryOptions
                    {
                        Filter = new LDAPFilter().AddAllObjects().GetFilter(),
                        Scope = SearchScope.Base,
                        Properties = CommonProperties.GPCFileSysPath,
                        AdsPath = linkDn
                    };
                    var filePath = _utils.QueryLDAP(opts).FirstOrDefault()?
                        .GetProperty(LDAPProperties.GPCFileSYSPath);

                    if (filePath == null)
                    {
                        GpoActionCache.TryAdd(linkDn, actions);
                        continue;
                    }

                    //Add the actions for each file. The GPO template file actions will override the XML file actions
                    actions.AddRange(ProcessGPOXmlFile(filePath, gpoDomain).ToList());
                    await foreach (var item in ProcessGPOTemplateFile(filePath, gpoDomain))
                    {
                        actions.Add(item);
                    }
                }

                //Cache the actions for this GPO for later
                GpoActionCache.TryAdd(linkDn.ToLower(), actions);

                //If there are no actions, then we can move on from this GPO
                if (actions.Count == 0)
                    continue;

                //First lets process restricted members
                var restrictedMemberSets = actions.Where(x => x.Target == GroupActionTarget.RestrictedMember)
                    .GroupBy(x => x.TargetRid);

                foreach (var set in restrictedMemberSets)
                {
                    var results = data[set.Key];
                    var members = set.Select(x => x.ToTypedPrincipal()).ToList();
                    results.RestrictedMember = members;
                    data[set.Key] = results;
                }

                //Next add in our restricted MemberOf sets
                var restrictedMemberOfSets = actions.Where(x => x.Target == GroupActionTarget.RestrictedMemberOf)
                    .GroupBy(x => x.TargetRid);

                foreach (var set in restrictedMemberOfSets)
                {
                    var results = data[set.Key];
                    var members = set.Select(x => x.ToTypedPrincipal()).ToList();
                    results.RestrictedMemberOf = members;
                    data[set.Key] = results;
                }

                // Now work through the LocalGroup targets
                var localGroupSets = actions.Where(x => x.Target == GroupActionTarget.LocalGroup)
                    .GroupBy(x => x.TargetRid);

                foreach (var set in localGroupSets)
                {
                    var results = data[set.Key];
                    foreach (var temp in set)
                    {
                        var res = temp.ToTypedPrincipal();
                        var newMembers = results.LocalGroups;
                        switch (temp.Action)
                        {
                            case GroupActionOperation.Add:
                                newMembers.Add(res);
                                break;
                            case GroupActionOperation.Delete:
                                newMembers.RemoveAll(x => x.ObjectIdentifier == res.ObjectIdentifier);
                                break;
                            case GroupActionOperation.DeleteUsers:
                                newMembers.RemoveAll(x => x.ObjectType == Label.User);
                                break;
                            case GroupActionOperation.DeleteGroups:
                                newMembers.RemoveAll(x => x.ObjectType == Label.Group);
                                break;
                        }

                        data[set.Key].LocalGroups = newMembers;
                    }
                }
            }

            ret.AffectedComputers = affectedComputers;

            //At this point, we've resolved individual add/substract methods for each linked GPO.
            //Now we need to actually squish them together into the resulting set of changes
            foreach (var kvp in data)
            {
                var key = kvp.Key;
                var val = kvp.Value;
                var rm = val.RestrictedMember;
                var rmo = val.RestrictedMemberOf;
                var gm = val.LocalGroups;

                var final = new List<TypedPrincipal>();

                // If we're setting RestrictedMembers, it overrides LocalGroups due to order of operations. Restricted MemberOf always applies.
                final.AddRange(rmo);
                final.AddRange(rm.Count > 0 ? rm : gm);

                var finalArr = final.Distinct().ToArray();

                switch (key)
                {
                    case LocalGroupRids.Administrators:
                        ret.LocalAdmins = finalArr;
                        break;
                    case LocalGroupRids.RemoteDesktopUsers:
                        ret.RemoteDesktopUsers = finalArr;
                        break;
                    case LocalGroupRids.DcomUsers:
                        ret.DcomUsers = finalArr;
                        break;
                    case LocalGroupRids.PSRemote:
                        ret.PSRemoteUsers = finalArr;
                        break;
                }
            }

            return ret;
        }

        /// <summary>
        ///     Parses a GPO GptTmpl.inf file and pulls group membership changes out
        /// </summary>
        /// <param name="basePath"></param>
        /// <param name="gpoDomain"></param>
        /// <returns></returns>
        internal async IAsyncEnumerable<GroupAction> ProcessGPOTemplateFile(string basePath, string gpoDomain)
        {
            var templatePath = Path.Combine(basePath, "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf");

            if (!File.Exists(templatePath))
                yield break;

            FileStream fs;
            try
            {
                fs = new FileStream(templatePath, FileMode.Open, FileAccess.Read);
            }
            catch
            {
                yield break;
            }

            using var reader = new StreamReader(fs);
            var content = await reader.ReadToEndAsync();
            var memberMatch = MemberRegex.Match(content);

            if (!memberMatch.Success)
                yield break;

            //We've got a match! Lets figure out whats going on
            var memberText = memberMatch.Groups[1].Value.Trim();
            //Split our text into individual lines
            var memberLines = Regex.Split(memberText, @"\r\n|\r|\n");

            foreach (var memberLine in memberLines)
            {
                //Check if the Key regex matches (S-1-5.*_memberof=blah)
                var keyMatch = KeyRegex.Match(memberLine);

                if (!keyMatch.Success)
                    continue;

                var key = keyMatch.Groups[1].Value.Trim();
                var val = keyMatch.Groups[2].Value.Trim();

                var leftMatch = MemberLeftRegex.Match(key);
                var rightMatches = MemberRightRegex.Matches(val);

                //If leftmatch is a success, the members of a group are being explicitly set
                if (leftMatch.Success)
                {
                    var extracted = ExtractRid.Match(leftMatch.Value);
                    var rid = int.Parse(extracted.Groups[1].Value);

                    if (Enum.IsDefined(typeof(LocalGroupRids), rid))
                        //Loop over the members in the match, and try to convert them to SIDs
                        foreach (var member in val.Split(','))
                        {
                            var res = GetSid(member.Trim('*'), gpoDomain);
                            if (res == null)
                                continue;
                            yield return new GroupAction
                            {
                                Target = GroupActionTarget.RestrictedMember,
                                Action = GroupActionOperation.Add,
                                TargetSid = res.ObjectIdentifier,
                                TargetType = res.ObjectType,
                                TargetRid = (LocalGroupRids) rid
                            };
                        }
                }

                //If right match is a success, a group has been set as a member of one of our local groups
                var index = key.IndexOf("MemberOf", StringComparison.CurrentCultureIgnoreCase);
                if (rightMatches.Count > 0 && index > 0)
                {
                    var account = key.Trim('*').Substring(0, index - 3).ToUpper();

                    var res = GetSid(account, gpoDomain);
                    if (res == null)
                        continue;

                    foreach (var match in rightMatches)
                    {
                        var rid = int.Parse(ExtractRid.Match(match.ToString()).Groups[1].Value);
                        if (!Enum.IsDefined(typeof(LocalGroupRids), rid)) continue;

                        var targetGroup = (LocalGroupRids) rid;
                        yield return new GroupAction
                        {
                            Target = GroupActionTarget.RestrictedMemberOf,
                            Action = GroupActionOperation.Add,
                            TargetRid = targetGroup,
                            TargetSid = res.ObjectIdentifier,
                            TargetType = res.ObjectType
                        };
                    }
                }
            }
        }

        /// <summary>
        ///     Resolves a SID to its type
        /// </summary>
        /// <param name="account"></param>
        /// <param name="domainName"></param>
        /// <returns></returns>
        private TypedPrincipal GetSid(string account, string domainName)
        {
            if (!account.StartsWith("S-1-", StringComparison.CurrentCulture))
            {
                string user;
                string domain;
                if (account.Contains('\\'))
                {
                    //The account is in the format DOMAIN\\username
                    var split = account.Split('\\');
                    domain = split[0];
                    user = split[1];
                }
                else
                {
                    //The account is just a username, so try with the current domain
                    domain = domainName;
                    user = account;
                }

                user = user.ToUpper();

                //Try to resolve as a user object first
                var res = _utils.ResolveAccountName(user, domain);
                if (res != null)
                    return res;

                res = _utils.ResolveAccountName($"{user}$", domain);
                return res;
            }

            //The element is just a sid, so return it straight
            var lType = _utils.LookupSidType(account, domainName);
            return new TypedPrincipal
            {
                ObjectIdentifier = account,
                ObjectType = lType
            };
        }

        /// <summary>
        ///     Parses a GPO Groups.xml file and pulls group membership changes out
        /// </summary>
        /// <param name="basePath"></param>
        /// <param name="gpoDomain"></param>
        /// <returns>A list of GPO "Actions"</returns>
        internal IEnumerable<GroupAction> ProcessGPOXmlFile(string basePath, string gpoDomain)
        {
            var xmlPath = Path.Combine(basePath, "MACHINE", "Preferences", "Groups", "Groups.xml");

            //If the file doesn't exist, then just return
            if (!File.Exists(xmlPath))
                yield break;

            //Create an XPathDocument to let us navigate the XML
            XPathDocument doc;
            try
            {
                doc = new XPathDocument(xmlPath);
            }
            catch (Exception e)
            {
                _log.LogError(e, "error reading GPO XML file {File}", xmlPath);
                yield break;
            }
             
            var navigator = doc.CreateNavigator();
            //Grab all the Groups nodes
            var groupsNodes = navigator.Select("/Groups");

            while (groupsNodes.MoveNext())
            {
                var current = groupsNodes.Current;
                //If disable is set to 1, then this Group wont apply
                if (current.GetAttribute("disabled", "") is "1")
                    continue;

                var groupNodes = current.Select("Group");
                while (groupNodes.MoveNext())
                {
                    //Grab the properties for each Group node. Current path is /Groups/Group
                    var groupProperties = groupNodes.Current.Select("Properties");
                    while (groupProperties.MoveNext())
                    {
                        var currentProperties = groupProperties.Current;
                        var action = currentProperties.GetAttribute("action", "");

                        //The only action that works for built in groups is Update.
                        if (!action.Equals("u", StringComparison.OrdinalIgnoreCase))
                            continue;

                        var groupSid = currentProperties.GetAttribute("groupSid", "")?.Trim();
                        var groupName = currentProperties.GetAttribute("groupName", "")?.Trim();

                        //Next is to determine what group is being updated.

                        var targetGroup = LocalGroupRids.None;
                        if (!string.IsNullOrWhiteSpace(groupSid))
                        {
                            //Use a regex to match and attempt to extract the RID
                            var s = ExtractRid.Match(groupSid);
                            if (s.Success)
                            {
                                var rid = int.Parse(s.Groups[1].Value);
                                if (Enum.IsDefined(typeof(LocalGroupRids), rid))
                                    targetGroup = (LocalGroupRids) rid;
                            }
                        }

                        if (!string.IsNullOrWhiteSpace(groupName) && targetGroup == LocalGroupRids.None)
                            ValidGroupNames.TryGetValue(groupName, out targetGroup);

                        //If targetGroup is still None, we've failed to resolve a group target. No point in continuing
                        if (targetGroup == LocalGroupRids.None)
                            continue;

                        var deleteUsers = currentProperties.GetAttribute("deleteAllUsers", "") == "1";
                        var deleteGroups = currentProperties.GetAttribute("deleteAllGroups", "") == "1";

                        if (deleteUsers)
                            yield return new GroupAction
                            {
                                Action = GroupActionOperation.DeleteUsers,
                                Target = GroupActionTarget.LocalGroup,
                                TargetRid = targetGroup
                            };

                        if (deleteGroups)
                            yield return new GroupAction
                            {
                                Action = GroupActionOperation.DeleteGroups,
                                Target = GroupActionTarget.LocalGroup,
                                TargetRid = targetGroup
                            };

                        //Get all the actual members being added
                        var members = currentProperties.Select("Members/Member");
                        while (members.MoveNext())
                        {
                            var memberAction = members.Current.GetAttribute("action", "")
                                .Equals("ADD", StringComparison.OrdinalIgnoreCase)
                                ? GroupActionOperation.Add
                                : GroupActionOperation.Delete;

                            var memberName = members.Current.GetAttribute("name", "");
                            var memberSid = members.Current.GetAttribute("sid", "");

                            var ga = new GroupAction
                            {
                                Action = memberAction
                            };

                            //If we have a memberSid, this is the best case scenario
                            if (!string.IsNullOrWhiteSpace(memberSid))
                            {
                                var memberType = _utils.LookupSidType(memberSid, _utils.GetDomainNameFromSid(memberSid));
                                ga.Target = GroupActionTarget.LocalGroup;
                                ga.TargetSid = memberSid;
                                ga.TargetType = memberType;
                                ga.TargetRid = targetGroup;

                                yield return ga;
                                continue;
                            }

                            //If we have a memberName, we need to resolve it to a SID/Type
                            if (!string.IsNullOrWhiteSpace(memberName))
                            {
                                //Check if the name is domain prefixed
                                if (memberName.Contains("\\"))
                                {
                                    var s = memberName.Split('\\');
                                    var name = s[1];
                                    var domain = s[0];

                                    var res = _utils.ResolveAccountName(name, domain);
                                    ga.Target = GroupActionTarget.LocalGroup;
                                    ga.TargetSid = res.ObjectIdentifier;
                                    ga.TargetType = res.ObjectType;
                                    ga.TargetRid = targetGroup;
                                    yield return ga;
                                }
                                else
                                {
                                    var res = _utils.ResolveAccountName(memberName, gpoDomain);
                                    ga.Target = GroupActionTarget.LocalGroup;
                                    ga.TargetSid = res.ObjectIdentifier;
                                    ga.TargetType = res.ObjectType;
                                    ga.TargetRid = targetGroup;
                                    yield return ga;
                                }
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        ///     Represents an action from a GPO
        /// </summary>
        internal class GroupAction
        {
            internal GroupActionOperation Action { get; set; }
            internal GroupActionTarget Target { get; set; }
            internal string TargetSid { get; set; }
            internal Label TargetType { get; set; }
            internal LocalGroupRids TargetRid { get; set; }

            public TypedPrincipal ToTypedPrincipal()
            {
                return new()
                {
                    ObjectIdentifier = TargetSid,
                    ObjectType = TargetType
                };
            }

            public override string ToString()
            {
                return
                    $"{nameof(Action)}: {Action}, {nameof(Target)}: {Target}, {nameof(TargetSid)}: {TargetSid}, {nameof(TargetType)}: {TargetType}, {nameof(TargetRid)}: {TargetRid}";
            }
        }

        /// <summary>
        ///     Storage for each different group type
        /// </summary>
        public class GroupResults
        {
            public List<TypedPrincipal> LocalGroups = new();
            public List<TypedPrincipal> RestrictedMember = new();
            public List<TypedPrincipal> RestrictedMemberOf = new();
        }

        internal enum GroupActionOperation
        {
            Add,
            Delete,
            DeleteUsers,
            DeleteGroups
        }

        internal enum GroupActionTarget
        {
            RestrictedMemberOf,
            RestrictedMember,
            LocalGroup
        }
    }
}