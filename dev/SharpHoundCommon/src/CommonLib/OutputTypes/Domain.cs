using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class Domain : OutputBase
    {
        public TypedPrincipal[] ChildObjects { get; set; } = Array.Empty<TypedPrincipal>();
        public DomainTrust[] Trusts { get; set; } = Array.Empty<DomainTrust>();
        public GPLink[] Links { get; set; } = Array.Empty<GPLink>();
        public ResultingGPOChanges GPOChanges = new();
    }
}