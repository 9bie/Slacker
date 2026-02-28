using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class OU : OutputBase
    {
        public GPLink[] Links { get; set; } = Array.Empty<GPLink>();
        public TypedPrincipal[] ChildObjects { get; set; } = Array.Empty<TypedPrincipal>();
        public ResultingGPOChanges GPOChanges = new();
    }
}