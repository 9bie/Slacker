using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class User : OutputBase
    {
        public TypedPrincipal[] AllowedToDelegate { get; set; } = Array.Empty<TypedPrincipal>();
        public string PrimaryGroupSID { get; set; }
        public TypedPrincipal[] HasSIDHistory { get; set; } = Array.Empty<TypedPrincipal>();
        public SPNPrivilege[] SPNTargets { get; set; } = Array.Empty<SPNPrivilege>();
    }
}