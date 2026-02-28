namespace SharpHoundCommonLib.OutputTypes
{
    public class GPLink
    {
        private string _guid;

        public bool IsEnforced { get; set; }

        public string GUID
        {
            get => _guid;
            set => _guid = value?.ToUpper();
        }

        protected bool Equals(GPLink other)
        {
            return _guid == other._guid && IsEnforced == other.IsEnforced;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((GPLink) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((_guid != null ? _guid.GetHashCode() : 0) * 397) ^ IsEnforced.GetHashCode();
            }
        }
    }
}