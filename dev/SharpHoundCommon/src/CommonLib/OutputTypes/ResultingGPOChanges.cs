using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class ResultingGPOChanges
    {
        public TypedPrincipal[] LocalAdmins { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] RemoteDesktopUsers { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] DcomUsers { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] PSRemoteUsers { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] AffectedComputers { get; set; } = Array.Empty<TypedPrincipal>();
    }
}