using System;

namespace SharpHoundCommonLib.OutputTypes
{
    /// <summary>
    ///     Represents a computer object in Active Directory. Contains all the properties BloodHound cares about
    /// </summary>
    public class Computer : OutputBase
    {
        public string PrimaryGroupSID { get; set; }
        public TypedPrincipal[] AllowedToDelegate { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] AllowedToAct { get; set; } = Array.Empty<TypedPrincipal>();
        public TypedPrincipal[] HasSIDHistory { get; set; } = Array.Empty<TypedPrincipal>();
        public SessionAPIResult Sessions { get; set; } = new();
        public SessionAPIResult PrivilegedSessions { get; set; } = new();
        public SessionAPIResult RegistrySessions { get; set; } = new();
        public LocalGroupAPIResult LocalAdmins { get; set; } = new();
        public LocalGroupAPIResult RemoteDesktopUsers { get; set; } = new();
        public LocalGroupAPIResult DcomUsers { get; set; } = new();
        public LocalGroupAPIResult PSRemoteUsers { get; set; } = new();
        public ComputerStatus Status { get; set; }
    }

    public class ComputerStatus
    {
        public bool Connectable { get; set; }
        public string Error { get; set; }

        public static string NonWindowsOS => "NonWindowsOS";
        public static string OldPwd => "PwdLastSetOutOfRange";
        public static string PortNotOpen => "PortNotOpen";

        public CSVComputerStatus GetCSVStatus(string computerName)
        {
            return new CSVComputerStatus
            {
                Status = Error,
                Task = "CheckAvailability",
                ComputerName = computerName
            };
        }
    }
}