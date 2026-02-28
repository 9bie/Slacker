using System.Runtime.Serialization;

namespace SharpHoundCommonLib.OutputTypes
{
    [DataContract]
    public class MetaTag
    {
        [DataMember(Name="methods")] public long CollectionMethods { get; set; }
        [DataMember(Name="type")] public string DataType { get; set; }
        [DataMember(Name="count")] public long Count { get; set; }
        [DataMember(Name="version")] public int Version { get; set; }
    }
}