using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class LocalGroupAPIResult : APIResult
    {
        public TypedPrincipal[] Results { get; set; } = Array.Empty<TypedPrincipal>();
    }
}