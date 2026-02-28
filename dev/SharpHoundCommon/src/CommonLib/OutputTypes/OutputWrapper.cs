using System.Collections.Generic;
using System.Runtime.Serialization;

namespace SharpHoundCommonLib.OutputTypes
{
    public class OutputWrapper<T>
    {
        [DataMember(Name = "meta")] public MetaTag Meta { get; set; }
        [DataMember(Name = "data")] public List<T> Data { get; set; }
    }
}