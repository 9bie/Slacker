using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using SharpHoundCommonLib.Processors;

namespace SharpHoundCommonLib
{
    public class ActiveDirectoryRuleDescriptor
    {
        private readonly ActiveDirectoryAccessRule _inner;

        public ActiveDirectoryRuleDescriptor(ActiveDirectoryAccessRule inner)
        {
            _inner = inner;
        }

        public virtual AccessControlType AccessControlType()
        {
            return _inner.AccessControlType;
        }

        public virtual string IdentityReference()
        {
            return _inner.IdentityReference.Value;
        }

        public virtual bool IsInherited()
        {
            return _inner.IsInherited;
        }

        public virtual bool IsAceInheritedFrom(string guid)
        {
            //Check if the ace is inherited
            var isInherited = _inner.IsInherited;

            //The inheritedobjecttype needs to match the guid of the object type being enumerated or the guid for All
            var inheritedType = _inner.InheritedObjectType.ToString();
            isInherited = isInherited && (inheritedType == ACEGuids.AllGuid || inheritedType == guid);

            //Special case for Exchange
            //If the ACE is not Inherited and is not an inherit-only ace, then it's set by exchange for reasons
            if (!isInherited &&
                (_inner.PropagationFlags & PropagationFlags.InheritOnly) != PropagationFlags.InheritOnly &&
                !_inner.IsInherited)
                isInherited = true;

            return isInherited;
        }

        public virtual ActiveDirectoryRights ActiveDirectoryRights()
        {
            return _inner.ActiveDirectoryRights;
        }

        public virtual Guid ObjectType()
        {
            return _inner.ObjectType;
        }
    }

    public class ActiveDirectorySecurityDescriptor
    {
        private readonly ActiveDirectorySecurity _sd;

        public ActiveDirectorySecurityDescriptor(ActiveDirectorySecurity sd)
        {
            _sd = sd;
        }

        public virtual bool AreAccessRulesProtected()
        {
            return _sd.AreAccessRulesProtected;
        }

        public virtual List<ActiveDirectoryRuleDescriptor> GetAccessRules(bool includeExplicit, bool includeInherited,
            Type targetType)
        {
            var result = new List<ActiveDirectoryRuleDescriptor>();
            foreach (ActiveDirectoryAccessRule ace in _sd.GetAccessRules(includeExplicit, includeInherited, targetType))
                result.Add(new ActiveDirectoryRuleDescriptor(ace));

            return result;
        }

        public virtual void SetSecurityDescriptorBinaryForm(byte[] binaryForm)
        {
            _sd.SetSecurityDescriptorBinaryForm(binaryForm);
        }

        public virtual void SetSecurityDescriptorBinaryForm(byte[] binaryForm, AccessControlSections type)
        {
            _sd.SetSecurityDescriptorBinaryForm(binaryForm, type);
        }

        public virtual string GetOwner(Type targetType)
        {
            return _sd.GetOwner(targetType).Value;
        }
    }
}