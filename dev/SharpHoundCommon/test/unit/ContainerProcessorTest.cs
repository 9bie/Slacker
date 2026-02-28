using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class ContainerProcessorTest : IDisposable
    {
        private readonly string _testGpLinkString;
        private readonly ITestOutputHelper _testOutputHelper;

        public ContainerProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _testGpLinkString =
                "[LDAP://cn={94DD0260-38B5-497E-8876-10E7A96E80D0},cn=policies,cn=system,DC=testlab,DC=local;0][LDAP://cn={C52F168C-CD05-4487-B405-564934DA8EFF},cn=policies,cn=system,DC=testlab,DC=local;0][LDAP://cn={1E860A30-603A-45C7-A768-26EE74BE6D5D},cn=policies,cn=system,DC=testlab,DC=local;0]";
        }

        public void Dispose()
        {
        }

        [Fact]
        public void ContainerProcessor_ReadContainerGPLinks_IgnoresNull()
        {
            var processor = new ContainerProcessor(new MockLDAPUtils());
            var test = processor.ReadContainerGPLinks(null);
            Assert.Empty(test);
        }

        [Fact]
        public void ContainerProcessor_ReadContainerGPLinks_UnresolvedGPLink_IsIgnored()
        {
            var processor = new ContainerProcessor(new MockLDAPUtils());
            //GPLink that doesn't exist
            const string s =
                "[LDAP://cn={94DD0260-38B5-497E-8876-ABCDEFG},cn=policies,cn=system,DC=testlab,DC=local;0]";
            var test = processor.ReadContainerGPLinks(s);
            Assert.Empty(test);
        }

        [Fact]
        public void ContainerProcessor_ReadContainerGPLinks_ReturnsCorrectValues()
        {
            var processor = new ContainerProcessor(new MockLDAPUtils());
            var test = processor.ReadContainerGPLinks(_testGpLinkString).ToArray();

            var expected = new GPLink[]
            {
                new()
                {
                    GUID = "B39818AF-6349-401A-AE0A-E4972F5BF6D9",
                    IsEnforced = false
                },
                new()
                {
                    GUID = "ACDD64D3-67B3-401F-A6CC-804B3F7B1533",
                    IsEnforced = false
                },
                new()
                {
                    GUID = "C45E9585-4932-4C03-91A8-1856869D49AF",
                    IsEnforced = false
                }
            };

            Assert.Equal(3, test.Length);
            Assert.Equal(expected, test);
        }

        [Fact]
        public void ContainerProcessor_GetContainerChildObjects_ReturnsCorrectData()
        {
            var mock = new Mock<MockLDAPUtils>();

            var searchResults = new MockSearchResultEntry[]
            {
                //These first 4 should be filtered by our DN filters
                new(
                    "CN=7868d4c8-ac41-4e05-b401-776280e8e9f1,CN=Operations,CN=DomainUpdates,CN=System,DC=testlab,DC=local"
                    , null, null, Label.Base),
                new("CN=Microsoft,CN=Program Data,DC=testlab,DC=local", null, null, Label.Base),
                new("CN=Operations,CN=DomainUpdates,CN=System,DC=testlab,DC=local", null, null, Label.Base),
                new("CN=User,CN={C52F168C-CD05-4487-B405-564934DA8EFF},CN=Policies,CN=System,DC=testlab,DC=local", null,
                    null, Label.Base),
                //This is a real object in our mock
                new("CN=Users,DC=testlab,DC=local", null, "ECAD920E-8EB1-4E31-A80E-DD36367F81F4", Label.Container),
                //This object does not exist in our mock
                new("CN=Users,DC=testlab,DC=local", null, "ECAD920E-8EB1-4E31-A80E-DD36367F81FD", Label.Container),
                //Test null objectid
                new("CN=Users,DC=testlab,DC=local", null, null, Label.Container)
            };

            mock.Setup(x => x.QueryLDAP(It.IsAny<string>(), It.IsAny<SearchScope>(), It.IsAny<string[]>(),
                It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<string>(), It.IsAny<bool>(),
                It.IsAny<bool>())).Returns(searchResults);

            var processor = new ContainerProcessor(mock.Object);
            var test = processor.GetContainerChildObjects(_testGpLinkString).ToArray();

            var expected = new TypedPrincipal[]
            {
                new()
                {
                    ObjectIdentifier = "ECAD920E-8EB1-4E31-A80E-DD36367F81F4",
                    ObjectType = Label.Container
                }
            };

            Assert.Single(test);
            Assert.Equal(expected, test);
        }

        [Fact]
        public void ContainerProcessor_ReadBlocksInheritance_ReturnsCorrectValues()
        {
            var test = ContainerProcessor.ReadBlocksInheritance(null);
            var test2 = ContainerProcessor.ReadBlocksInheritance("3");
            var test3 = ContainerProcessor.ReadBlocksInheritance("1");

            Assert.False(test);
            Assert.False(test2);
            Assert.True(test3);
        }
    }
}