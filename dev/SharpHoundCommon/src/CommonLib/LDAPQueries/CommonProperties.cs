namespace SharpHoundCommonLib.LDAPQueries
{
    public static class CommonProperties
    {
        public static readonly string[] TypeResolutionProps =
            { "samaccounttype", "objectsid", "objectguid", "objectclass", "samaccountname", "msds-groupmsamembership" };

        public static readonly string[] ObjectID = { "objectsid", "objectguid" };
        public static readonly string[] ObjectSID = { "objectsid" };
        public static readonly string[] GPCFileSysPath = { "gpcfilesyspath" };

        public static readonly string[] BaseQueryProps =
        {
            "objectsid", "distiguishedname", "objectguid", "ms-mcs-admpwdexpirationtime", "isDeleted",
            "useraccountcontrol"
        };

        public static readonly string[] GroupResolutionProps =
        {
            "samaccountname", "distinguishedname", "samaccounttype", "member", "cn", "primarygroupid", "dnshostname"
        };

        public static readonly string[] ComputerMethodProps =
        {
            "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "operatingsystem", "pwdlastset"
        };

        public static readonly string[] ACLProps =
        {
            "samaccountname", "distinguishedname", "dnshostname", "samaccounttype", "ntsecuritydescriptor",
            "displayname", "objectclass", "objectsid", "name"
        };

        public static readonly string[] ObjectPropsProps =
        {
            "samaccountname", "distinguishedname", "samaccounttype", "pwdlastset", "lastlogon", "lastlogontimestamp",
            "objectsid",
            "sidhistory", "dnshostname", "operatingsystem",
            "operatingsystemservicepack", "serviceprincipalname", "displayname", "mail", "title",
            "homedirectory", "description", "admincount", "userpassword", "gpcfilesyspath", "objectclass",
            "msds-behavior-version", "objectguid", "name", "gpoptions", "msds-allowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity", "whenCreated"
        };

        public static readonly string[] ContainerProps =
        {
            "displayname", "name", "objectguid", "gplink", "gpoptions", "objectclass"
        };

        public static readonly string[] SPNTargetProps =
        {
            "serviceprincipalname", "samaccountname", "samaccounttype"
        };

        public static readonly string[] DomainTrustProps =
            { "trustattributes", "securityidentifier", "trustdirection", "trusttype", "cn" };

        public static readonly string[] GPOLocalGroupProps =
        {
            "gplink", "name"
        };
    }
}