using System;
using System.Collections;
using System.Collections.Generic;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;

namespace CommonLibTest.Facades
{
    public class MockSearchResultEntry : ISearchResultEntry
    {
        private readonly string _objectId;
        private readonly Label _objectType;
        private readonly IDictionary _properties;

        public MockSearchResultEntry(string distinguishedName, IDictionary properties, string objectId,
            Label objectType)
        {
            DistinguishedName = distinguishedName;
            _properties = properties;
            _objectId = objectId;
            _objectType = objectType;
        }

        public string DistinguishedName { get; }

        public ResolvedSearchResult ResolveBloodHoundInfo()
        {
            throw new NotImplementedException();
        }

        public string GetProperty(string propertyName)
        {
            return _properties[propertyName] as string;
        }

        public byte[] GetByteProperty(string propertyName)
        {
            return _properties[propertyName] as byte[];
        }

        public string[] GetArrayProperty(string propertyName)
        {
            return _properties[propertyName] as string[];
        }

        public byte[][] GetByteArrayProperty(string propertyName)
        {
            return _properties[propertyName] as byte[][];
        }

        public string GetObjectIdentifier()
        {
            return _objectId;
        }

        public bool IsDeleted()
        {
            throw new NotImplementedException();
        }

        public Label GetLabel()
        {
            return _objectType;
        }

        public string GetSid()
        {
            return _objectId;
        }

        public string GetGuid()
        {
            return _objectId;
        }

        public int PropCount(string prop)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<string> PropertyNames()
        {
            throw new NotImplementedException();
        }

        public bool IsMSA()
        {
            throw new NotImplementedException();
        }

        public bool IsGMSA()
        {
            throw new NotImplementedException();
        }

        public bool HasLAPS()
        {
            throw new NotImplementedException();
        }
    }
}