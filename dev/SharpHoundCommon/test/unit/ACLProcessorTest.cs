using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using CommonLibTest.Facades;
using Moq;
using Newtonsoft.Json;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class ACLProcessorTest : IDisposable
    {
        private const string ProtectedUserNTSecurityDescriptor =
            "AQAEnIgEAAAAAAAAAAAAABQAAAAEAHQEGAAAAAUAPAAQAAAAAwAAAABCFkzAINARp2gAqgBuBSkUzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAABCFkzAINARp2gAqgBuBSm6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAABAgIF+ledARkCAAwE/C1M8UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAABAgIF+ledARkCAAwE/C1M+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEDCCrypedARkCAAwE/C1M8UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEDCCrypedARkCAAwE/C1M+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEIvulmiedARkCAAwE/C088UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEIvulmiedARkCAAwE/C08+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAPiIcAPhCtIRtCIAoMlo+TkUzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAPiIcAPhCtIRtCIAoMlo+Tm6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAOAAwAAAAAQAAAH96lr/mDdARooUAqgAwSeIBBQAAAAAABRUAAAAgT5C6f0aEpXZIFpAFAgAABQAsABAAAAABAAAAHbGpRq5gWkC36P+KWNRW0gECAAAAAAAFIAAAADACAAAFACwAMAAAAAEAAAAcmrZtIpTREa69AAD4A2fBAQIAAAAAAAUgAAAAMQIAAAUALAAwAAAAAQAAAGK8BVjJvShEpeKFag9MGF4BAgAAAAAABSAAAAAxAgAABQAsAJQAAgACAAAAFMwoSDcUvEWbB61vAV5fKAECAAAAAAAFIAAAACoCAAAFACwAlAACAAIAAAC6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAKAAAAQAAAQAAAFMacqsvHtARmBkAqgBAUpsBAQAAAAAAAQAAAAAFACgAAAEAAAEAAABTGnKrLx7QEZgZAKoAQFKbAQEAAAAAAAUKAAAABQIoADABAAABAAAA3kfmkW/ZcEuVV9Y/9PPM2AEBAAAAAAAFCgAAAAAAJAC/AQ4AAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQAAIAAAAAJAC/AQ4AAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQBwIAAAAAGAC/AQ8AAQIAAAAAAAUgAAAAIAIAAAAAFACUAAIAAQEAAAAAAAULAAAAAAAUAP8BDwABAQAAAAAABRIAAAABBQAAAAAABRUAAAAgT5C6f0aEpXZIFpAAAgAA";

        private const string UnProtectedUserNtSecurityDescriptor =
            "AQAEjJgGAAAAAAAAAAAAABQAAAAEAIQGJwAAAAUAOAAQAAAAAQAAAABCFkzAINARp2gAqgBuBSkBBQAAAAAABRUAAAAgT5C6f0aEpXZIFpApAgAABQA4ABAAAAABAAAAECAgX6V50BGQIADAT8LUzwEFAAAAAAAFFQAAACBPkLp/RoSldkgWkCkCAAAFADgAEAAAAAEAAABAwgq8qXnQEZAgAMBPwtTPAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQKQIAAAUAOAAQAAAAAQAAAPiIcAPhCtIRtCIAoMlo+TkBBQAAAAAABRUAAAAgT5C6f0aEpXZIFpApAgAABQA4ADAAAAABAAAAf3qWv+YN0BGihQCqADBJ4gEFAAAAAAAFFQAAACBPkLp/RoSldkgWkAUCAAAFACwAEAAAAAEAAAAdsalGrmBaQLfo/4pY1FbSAQIAAAAAAAUgAAAAMAIAAAUALAAwAAAAAQAAAByatm0ilNERrr0AAPgDZ8EBAgAAAAAABSAAAAAxAgAABQAsADAAAAABAAAAYrwFWMm9KESl4oVqD0wYXgECAAAAAAAFIAAAADECAAAFACgAAAEAAAEAAABTGnKrLx7QEZgZAKoAQFKbAQEAAAAAAAEAAAAABQAoAAABAAABAAAAUxpyqy8e0BGYGQCqAEBSmwEBAAAAAAAFCgAAAAUAKAAAAQAAAQAAAFQacqsvHtARmBkAqgBAUpsBAQAAAAAABQoAAAAFACgAAAEAAAEAAABWGnKrLx7QEZgZAKoAQFKbAQEAAAAAAAUKAAAABQAoABAAAAABAAAAQi+6WaJ50BGQIADAT8LTzwEBAAAAAAAFCwAAAAUAKAAQAAAAAQAAAFQBjeT4vNERhwIAwE+5YFABAQAAAAAABQsAAAAFACgAEAAAAAEAAACGuLV3SpTREa69AAD4A2fBAQEAAAAAAAULAAAABQAoABAAAAABAAAAs5VX5FWU0RGuvQAA+ANnwQEBAAAAAAAFCwAAAAUAKAAwAAAAAQAAAIa4tXdKlNERrr0AAPgDZ8EBAQAAAAAABQoAAAAFACgAMAAAAAEAAACylVfkVZTREa69AAD4A2fBAQEAAAAAAAUKAAAABQAoADAAAAABAAAAs5VX5FWU0RGuvQAA+ANnwQEBAAAAAAAFCgAAAAAAJAD/AQ8AAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQAAIAAAAAGAD/AQ8AAQIAAAAAAAUgAAAAJAIAAAAAFAAAAAIAAQEAAAAAAAULAAAAAAAUAJQAAgABAQAAAAAABQoAAAAAABQA/wEPAAEBAAAAAAAFEgAAAAUSOAAAAQAAAQAAAKr2MREHnNER958AwE/C3NIBBQAAAAAABRUAAAAgT5C6f0aEpXZIFpBKCAAABRI4AAABAAABAAAArfYxEQec0RH3nwDAT8Lc0gEFAAAAAAAFFQAAACBPkLp/RoSldkgWkD8IAAAFEjgAAAEAAAEAAACt9jERB5zREfefAMBPwtzSAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQSggAAAUaOAAQAAAAAwAAAG2exrfHLNIRhU4AoMmD9giGepa/5g3QEaKFAKoAMEniAQEAAAAAAAUJAAAABRo4ABAAAAADAAAAbZ7Gt8cs0hGFTgCgyYP2CJx6lr/mDdARooUAqgAwSeIBAQAAAAAABQkAAAAFEjgAEAAAAAMAAABtnsa3xyzSEYVOAKDJg/YIunqWv+YN0BGihQCqADBJ4gEBAAAAAAAFCQAAAAUaOAAgAAAAAwAAAJN7G+pIXtVGvGxN9P2nijWGepa/5g3QEaKFAKoAMEniAQEAAAAAAAUKAAAABRosAJQAAgACAAAAFMwoSDcUvEWbB61vAV5fKAECAAAAAAAFIAAAACoCAAAFGiwAlAACAAIAAACcepa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUSLACUAAIAAgAAALp6lr/mDdARooUAqgAwSeIBAgAAAAAABSAAAAAqAgAABRIoADAAAAABAAAA5cN4P5r3vUaguJ0YEW3ceQEBAAAAAAAFCgAAAAUSKAAwAQAAAQAAAN5H5pFv2XBLlVfWP/TzzNgBAQAAAAAABQoAAAAAEiQA/wEPAAEFAAAAAAAFFQAAACBPkLp/RoSldkgWkAcCAAAAEhgABAAAAAECAAAAAAAFIAAAACoCAAAAEhgAvQEPAAECAAAAAAAFIAAAACACAAABBQAAAAAABRUAAAAgT5C6f0aEpXZIFpAAAgAA";

        private const string GMSAProperty =
            "AQAEgEAAAAAAAAAAAAAAABQAAAAEACwAAQAAAAAAJAD/AQ8AAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQ9AEAAAECAAAAAAAFIAAAACACAAA\u003d";

        private const string AddMemberSecurityDescriptor =
            "AQAEjGADAAAAAAAAAAAAABQAAAAEAEwDFQAAAAUAOAAIAAAAAQAAAMB5lr/mDdARooUAqgAwSeIBBQAAAAAABRUAAAAgT5C6f0aEpXZIFpAuCgAABQA4ACAAAAABAAAAwHmWv+YN0BGihQCqADBJ4gEFAAAAAAAFFQAAACBPkLp/RoSldkgWkEcIAAAFACwAEAAAAAEAAAAdsalGrmBaQLfo/4pY1FbSAQIAAAAAAAUgAAAAMAIAAAUAKAAAAQAAAQAAAFUacqsvHtARmBkAqgBAUpsBAQAAAAAABQsAAAAAACQA/wEPAAEFAAAAAAAFFQAAACBPkLp/RoSldkgWkAACAAAAABgA/wEPAAECAAAAAAAFIAAAACQCAAAAABQAlAACAAEBAAAAAAAFCgAAAAAAFACUAAIAAQEAAAAAAAULAAAAAAAUAP8BDwABAQAAAAAABRIAAAAFGjgAEAAAAAMAAABtnsa3xyzSEYVOAKDJg/YIhnqWv+YN0BGihQCqADBJ4gEBAAAAAAAFCQAAAAUSOAAQAAAAAwAAAG2exrfHLNIRhU4AoMmD9gicepa/5g3QEaKFAKoAMEniAQEAAAAAAAUJAAAABRo4ABAAAAADAAAAbZ7Gt8cs0hGFTgCgyYP2CLp6lr/mDdARooUAqgAwSeIBAQAAAAAABQkAAAAFGjgAIAAAAAMAAACTexvqSF7VRrxsTfT9p4o1hnqWv+YN0BGihQCqADBJ4gEBAAAAAAAFCgAAAAUaLACUAAIAAgAAABTMKEg3FLxFmwetbwFeXygBAgAAAAAABSAAAAAqAgAABRIsAJQAAgACAAAAnHqWv+YN0BGihQCqADBJ4gECAAAAAAAFIAAAACoCAAAFGiwAlAACAAIAAAC6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUSKAAwAAAAAQAAAOXDeD+a971GoLidGBFt3HkBAQAAAAAABQoAAAAFEigAMAEAAAEAAADeR+aRb9lwS5VX1j/088zYAQEAAAAAAAUKAAAAABIkAP8BDwABBQAAAAAABRUAAAAgT5C6f0aEpXZIFpAHAgAAABIYAAQAAAABAgAAAAAABSAAAAAqAgAAABIYAL0BDwABAgAAAAAABSAAAAAgAgAAAQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQAAIAAA==";

        private readonly ACLProcessor _baseProcessor;

        private readonly string _testDomainName;
        private readonly ITestOutputHelper _testOutputHelper;

        public ACLProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _testDomainName = "TESTLAB.LOCAL";
            _baseProcessor = new ACLProcessor(new LDAPUtils());
        }

        public void Dispose()
        {
        }

        [Fact]
        public void SanityCheck()
        {
            Assert.True(true);
        }

        [Fact]
        public void ACLProcessor_IsACLProtected_NullNTSD_ReturnsFalse()
        {
            var processor = new ACLProcessor(new MockLDAPUtils(), true);
            var result = processor.IsACLProtected((byte[])null);
            Assert.False(result);
        }

        [WindowsOnlyFact]
        public void ACLProcessor_TestKnownDataAddMember()
        {
            var mockLdapUtils = new MockLDAPUtils();
            var mockUtils = new Mock<ILDAPUtils>();
            mockUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string a, string b) => mockLdapUtils.ResolveIDAndType(a, b));
            var sd = new ActiveDirectorySecurityDescriptor(new ActiveDirectorySecurity());
            mockUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(sd);

            var processor = new ACLProcessor(mockUtils.Object, true);
            var bytes = Helpers.B64ToBytes(AddMemberSecurityDescriptor);
            var result = processor.ProcessACL(bytes, "TESTLAB.LOCAL", Label.Group, false);

            _testOutputHelper.WriteLine(JsonConvert.SerializeObject(result));

            Assert.Contains(result,
                x => x.RightName == EdgeNames.AddSelf &&
                     x.PrincipalSID == "S-1-5-21-3130019616-2776909439-2417379446-2606");
            Assert.Contains(result,
                x => x.RightName == EdgeNames.AddMember &&
                     x.PrincipalSID == "S-1-5-21-3130019616-2776909439-2417379446-2119");
        }

        [Fact]
        public void ACLProcessor_IsACLProtected_ReturnsTrue()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            mockSecurityDescriptor.Setup(x => x.AreAccessRulesProtected()).Returns(true);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(ProtectedUserNTSecurityDescriptor);
            var result = processor.IsACLProtected(bytes);
            Assert.True(result);
        }

        [Fact]
        public void ACLProcessor_IsACLProtected_ReturnsFalse()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            mockSecurityDescriptor.Setup(m => m.AreAccessRulesProtected()).Returns(false);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.IsACLProtected(bytes);
            Assert.False(result);
        }

        [Fact]
        public void ACLProcessor_ProcessGMSAReaders_NullNTSD_ReturnsNothing()
        {
            var test = _baseProcessor.ProcessGMSAReaders(null, "");
            Assert.Empty(test);
        }

        [Fact]
        public void ACLProcess_ProcessGMSAReaders_YieldsCorrectAce()
        {
            var expectedRightName = "ReadGMSAPassword";
            var expectedSID = "S-1-5-21-3130019616-2776909439-2417379446-500";
            var expectedPrincipalType = Label.User;
            var expectedInheritance = false;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);

            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedSID);

            var collection = new List<ActiveDirectoryRuleDescriptor>();
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(GMSAProperty);
            var result = processor.ProcessGMSAReaders(bytes, _testDomainName).ToArray();

            Assert.Single(result);
            var actual = result.First();
            _testOutputHelper.WriteLine(actual.ToString());
            Assert.Equal(expectedRightName, actual.RightName);
            Assert.Equal(expectedSID, actual.PrincipalSID);
            Assert.Equal(expectedPrincipalType, actual.PrincipalType);
            Assert.Equal(expectedInheritance, actual.IsInherited);
        }

        [Fact]
        public void ACLProcessor_ProcessGMSAReaders_Null_ACE()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            collection.Add(null);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(GMSAProperty);
            var result = processor.ProcessGMSAReaders(bytes, _testDomainName).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessGMSAReaders_Deny_ACE()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();

            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Deny);
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(GMSAProperty);
            var result = processor.ProcessGMSAReaders(bytes, _testDomainName).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessGMSAReaders_Null_PrincipalID()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();

            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IdentityReference()).Returns((string)null);
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(GMSAProperty);
            var result = processor.ProcessGMSAReaders(bytes, _testDomainName).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_Null_NTSecurityDescriptor()
        {
            var processor = new ACLProcessor(new MockLDAPUtils(), true);
            var result = processor.ProcessACL(null, _testDomainName, Label.User, false).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_Yields_Owns_ACE()
        {
            var expectedSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedPrincipalType = Label.Group;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns(expectedSID);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalSID, expectedSID);
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, EdgeNames.Owns);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_Null_SID()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_Null_ACE()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            collection.Add(null);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_Deny_ACE()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Deny);
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_Unmatched_Inheritance_ACE()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(false);
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_Null_SID_ACE()
        {
            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns((string)null);
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_GenericAll_Unmatched_Guid()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var unmatchedGuid = new Guid("583991c8-629d-4a07-8a70-74d19d22ac9c");

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.GenericAll);
            mockRule.Setup(x => x.ObjectType()).Returns(unmatchedGuid);
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_GenericAll()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.GenericAll);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.AllGuid));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, EdgeNames.GenericAll);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_WriteDacl()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = ActiveDirectoryRights.WriteDacl;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(expectedRightName);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.AllGuid));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, expectedRightName.ToString());
        }

        [Fact]
        public void ACLProcessor_ProcessACL_WriteOwner()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = ActiveDirectoryRights.WriteOwner;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(expectedRightName);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.AllGuid));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, expectedRightName.ToString());
        }

        [Fact]
        public void ACLProcessor_ProcessACL_Self()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.AddSelf;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.Self);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.WriteMember));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(AddMemberSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.Group, false).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, expectedRightName);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_ExtendedRight_Domain_Unmatched()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.AddSelf;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.ExtendedRight);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.WriteMember));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.Domain, false).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_ExtendedRight_Domain_DSReplicationGetChanges()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.GetChanges;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.ExtendedRight);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.DSReplicationGetChanges));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.Domain, false).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, expectedRightName);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_ExtendedRight_Domain_All()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.AllExtendedRights;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.ExtendedRight);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.AllGuid));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.Domain, false).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, expectedRightName);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_ExtendedRight_Domain_DSReplicationGetChangesAll()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.GetChangesAll;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.ExtendedRight);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.DSReplicationGetChangesAll));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.Domain, false).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, expectedRightName);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_ExtendedRight_User_Unmatched()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.GetChangesAll;
            var unmatchedGuid = new Guid("583991c8-629d-4a07-8a70-74d19d22ac9c");

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.ExtendedRight);
            mockRule.Setup(x => x.ObjectType()).Returns(unmatchedGuid);
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_ExtendedRight_User_UserForceChangePassword()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.ForceChangePassword;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.ExtendedRight);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.UserForceChangePassword));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, expectedRightName);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_ExtendedRight_User_All()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.AllExtendedRights;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.ExtendedRight);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.AllGuid));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, false).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, expectedRightName);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_ExtendedRight_Computer_NoLAPS()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.AllExtendedRights;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.ExtendedRight);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.AllGuid));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.Computer, false).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_ExtendedRight_Computer_All()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.AllExtendedRights;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.ExtendedRight);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.AllGuid));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.Computer, true).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, expectedRightName);
        }

        [Fact(Skip = "Need to populate cache to reach this case")]
        public void ACLProcessor_ProcessACL_ExtendedRight_Computer_MappedGuid()
        {
        }

        [Fact]
        public void ACLProcessor_ProcessACL_GenericWrite_Unmatched()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.AllExtendedRights;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.GenericWrite);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.AllGuid));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.Container, true).ToArray();

            Assert.Empty(result);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_GenericWrite_User_All()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.GenericWrite;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.GenericWrite);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.AllGuid));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.User, true).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, expectedRightName);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_GenericWrite_User_WriteMember()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.AddMember;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.GenericWrite);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.WriteMember));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(AddMemberSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.Group, true).ToArray();

            _testOutputHelper.WriteLine(JsonConvert.SerializeObject(result));

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, expectedRightName);
        }

        [Fact]
        public void ACLProcessor_ProcessACL_GenericWrite_Computer_WriteAllowedToAct()
        {
            var expectedPrincipalType = Label.Group;
            var expectedPrincipalSID = "S-1-5-21-3130019616-2776909439-2417379446-512";
            var expectedRightName = EdgeNames.AddAllowedToAct;

            var mockLDAPUtils = new Mock<ILDAPUtils>();
            var mockSecurityDescriptor = new Mock<ActiveDirectorySecurityDescriptor>(MockBehavior.Loose, null);
            var mockRule = new Mock<ActiveDirectoryRuleDescriptor>(MockBehavior.Loose, null);
            var collection = new List<ActiveDirectoryRuleDescriptor>();
            mockRule.Setup(x => x.AccessControlType()).Returns(AccessControlType.Allow);
            mockRule.Setup(x => x.IsAceInheritedFrom(It.IsAny<string>())).Returns(true);
            mockRule.Setup(x => x.IdentityReference()).Returns(expectedPrincipalSID);
            mockRule.Setup(x => x.ActiveDirectoryRights()).Returns(ActiveDirectoryRights.GenericWrite);
            mockRule.Setup(x => x.ObjectType()).Returns(new Guid(ACEGuids.WriteAllowedToAct));
            collection.Add(mockRule.Object);

            mockSecurityDescriptor.Setup(m => m.GetAccessRules(It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<Type>()))
                .Returns(collection);
            mockSecurityDescriptor.Setup(m => m.GetOwner(It.IsAny<Type>())).Returns((string)null);
            mockLDAPUtils.Setup(x => x.MakeSecurityDescriptor()).Returns(mockSecurityDescriptor.Object);
            mockLDAPUtils.Setup(x => x.ResolveIDAndType(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new TypedPrincipal(expectedPrincipalSID, expectedPrincipalType));

            var processor = new ACLProcessor(mockLDAPUtils.Object, true);
            var bytes = Helpers.B64ToBytes(UnProtectedUserNtSecurityDescriptor);
            var result = processor.ProcessACL(bytes, _testDomainName, Label.Computer, true).ToArray();

            Assert.Single(result);
            var actual = result.First();
            Assert.Equal(actual.PrincipalType, expectedPrincipalType);
            Assert.Equal(actual.PrincipalSID, expectedPrincipalSID);
            Assert.Equal(actual.IsInherited, false);
            Assert.Equal(actual.RightName, expectedRightName);
        }
    }
}