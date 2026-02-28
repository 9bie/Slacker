using System;

namespace SharpHoundCommonLib.Enums
{
    [Flags]
    public enum ResolvedCollectionMethod
    {
        None = 0,
        Group = 1,
        LocalAdmin = 1 << 1,
        GPOLocalGroup = 1 << 2,
        Session = 1 << 3,
        LoggedOn = 1 << 4,
        Trusts = 1 << 5,
        ACL = 1 << 6,
        Container = 1 << 7,
        RDP = 1 << 8,
        ObjectProps = 1 << 9,
        SessionLoop = 1 << 10,
        LoggedOnLoop = 1 << 11,
        DCOM = 1 << 12,
        SPNTargets = 1 << 13,
        PSRemote = 1 << 14,
        LocalGroups = DCOM | RDP | LocalAdmin | PSRemote,
        ComputerOnly = LocalGroups | Session,
        DCOnly = ACL | Container | Group | ObjectProps | Trusts | GPOLocalGroup,
        Default = Group | Session | Trusts | ACL | ObjectProps | LocalGroups | SPNTargets | Container,
        All = Default | LoggedOn | GPOLocalGroup
    }
}