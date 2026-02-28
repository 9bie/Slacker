using System;
using System.Collections.Generic;

namespace SharpHoundCommonLib.OutputTypes
{
    /// <summary>
    ///     Represents a base JSON object which other objects will inherit from.
    /// </summary>
    public class OutputBase
    {
        public Dictionary<string, object> Properties = new();
        public ACE[] Aces { get; set; } = Array.Empty<ACE>();
        public string ObjectIdentifier { get; set; }
        public bool IsDeleted { get; set; }
        public bool IsACLProtected { get; set; }
    }
}