using System;

namespace SharpHoundCommonLib.Enums
{
    [Flags]
    public enum TrustAttributes
    {
        NonTransitive = 0x1,
        UplevelOnly = 0x2,
        FilterSids = 0x4,
        ForestTransitive = 0x8,
        CrossOrganization = 0x10,
        WithinForest = 0x20,
        TreatAsExternal = 0x40,
        TrustUsesRc4 = 0x80,
        TrustUsesAes = 0x100,
        CrossOrganizationNoTGTDelegation = 0x200,
        PIMTrust = 0x400
    }
}