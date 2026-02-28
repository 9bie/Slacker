using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class Group : OutputBase
    {
        public TypedPrincipal[] Members { get; set; } = Array.Empty<TypedPrincipal>();
    }
}