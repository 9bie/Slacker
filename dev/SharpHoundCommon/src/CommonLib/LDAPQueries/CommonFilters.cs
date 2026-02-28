namespace SharpHoundCommonLib.LDAPQueries
{
    public static class CommonFilters
    {
        public static string EnabledOnly => "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))";

        public static string NeedsGPCFilePath => "(gpcfilesyspath=*)";

        public static string NeedsSPN => "(serviceprincipalname=*)";

        public static string ExcludeDomainControllers => "(!(userAccountControl:1.2.840.113556.1.4.803:=8192))";

        public static string DomainControllers => "(userAccountControl:1.2.840.113556.1.4.803:=8192)";

        public static string TrustedDomains => "(objectclass=trusteddomain)";

        public static string SpecificSID(string sid)
        {
            var hSid = Helpers.ConvertSidToHexSid(sid);
            return $"(objectsid={hSid})";
        }

        public static string SpecificGUID(string guid)
        {
            var hGuid = Helpers.ConvertGuidToHexGuid(guid);
            return $"(objectguid={hGuid})";
        }
    }
}