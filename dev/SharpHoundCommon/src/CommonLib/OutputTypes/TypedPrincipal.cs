using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib.OutputTypes
{
    public class TypedPrincipal
    {
        public TypedPrincipal()
        {
        }

        public TypedPrincipal(string objectIdentifier, Label type)
        {
            ObjectIdentifier = objectIdentifier;
            ObjectType = type;
        }

        public string ObjectIdentifier { get; set; }
        public Label ObjectType { get; set; }

        public override string ToString()
        {
            return $"{ObjectIdentifier} - {ObjectType}";
        }

        protected bool Equals(TypedPrincipal other)
        {
            return ObjectIdentifier == other.ObjectIdentifier && ObjectType == other.ObjectType;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((TypedPrincipal) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((ObjectIdentifier != null ? ObjectIdentifier.GetHashCode() : 0) * 397) ^ (int) ObjectType;
            }
        }
    }
}