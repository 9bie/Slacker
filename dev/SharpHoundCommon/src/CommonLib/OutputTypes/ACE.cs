using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib.OutputTypes
{
    public class ACE
    {
        public string PrincipalSID { get; set; }
        public Label PrincipalType { get; set; }
        public string RightName { get; set; }
        public bool IsInherited { get; set; }

        public override string ToString()
        {
            return $"{PrincipalType} {PrincipalSID} - {RightName} {(IsInherited ? "" : "Not")} Inherited";
        }

        protected bool Equals(ACE other)
        {
            return PrincipalSID == other.PrincipalSID && PrincipalType == other.PrincipalType &&
                   RightName == other.RightName && IsInherited == other.IsInherited;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((ACE) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = PrincipalSID != null ? PrincipalSID.GetHashCode() : 0;
                hashCode = (hashCode * 397) ^ (int) PrincipalType;
                hashCode = (hashCode * 397) ^ (RightName != null ? RightName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ IsInherited.GetHashCode();
                return hashCode;
            }
        }
    }
}