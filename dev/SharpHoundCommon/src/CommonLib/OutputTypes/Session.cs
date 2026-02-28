namespace SharpHoundCommonLib.OutputTypes
{
    public class Session
    {
        private string _computerSID;
        private string _userSID;

        public string UserSID
        {
            get => _userSID;
            set => _userSID = value?.ToUpper();
        }

        public string ComputerSID
        {
            get => _computerSID;
            set => _computerSID = value?.ToUpper();
        }

        protected bool Equals(Session other)
        {
            return _computerSID == other._computerSID && _userSID == other._userSID;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((Session) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((_computerSID != null ? _computerSID.GetHashCode() : 0) * 397) ^
                       (_userSID != null ? _userSID.GetHashCode() : 0);
            }
        }
    }
}