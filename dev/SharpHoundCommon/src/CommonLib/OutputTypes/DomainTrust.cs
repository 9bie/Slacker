using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib.OutputTypes
{
    public class DomainTrust
    {
        public string TargetDomainSid { get; set; }
        public string TargetDomainName { get; set; }
        public bool IsTransitive { get; set; }
        public bool SidFilteringEnabled { get; set; }
        public TrustDirection TrustDirection { get; set; }
        public TrustType TrustType { get; set; }
    }
}