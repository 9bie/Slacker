using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib
{
    public class ResolvedSearchResult
    {
        private string _displayName;
        private string _objectID;

        public string DisplayName
        {
            get => _displayName.ToUpper();
            set => _displayName = value;
        }

        public Label ObjectType { get; set; }

        public string ObjectId
        {
            get => _objectID;
            set => _objectID = value.ToUpper();
        }

        public bool Deleted { get; set; }

        public string Domain { get; set; }
        public string DomainSid { get; set; }
        public bool IsDomainController { get; set; }

        public override string ToString()
        {
            return $"{DisplayName} - {ObjectType}";
        }
    }
}