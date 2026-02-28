using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class DomainTrustProcessorTest
    {
        private ITestOutputHelper _testOutputHelper;

        public DomainTrustProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [WindowsOnlyFact]
        public void DomainTrustProcessor_EnumerateDomainTrusts_HappyPath()
        {
            var mockUtils = new Mock<MockLDAPUtils>();
            var searchResults = new[]
            {
                new MockSearchResultEntry("CN\u003dexternal.local,CN\u003dSystem,DC\u003dtestlab,DC\u003dlocal",
                    new Dictionary<string, object>
                    {
                        {"trustdirection", "3"},
                        {"trusttype", "2"},
                        {"trustattributes", 0x24.ToString()},
                        {"cn", "external.local"},
                        {"securityidentifier", Helpers.B64ToBytes("AQQAAAAAAAUVAAAA7JjftxhaHTnafGWh")}
                    }, "", Label.Domain)
            };

            mockUtils.Setup(x => x.QueryLDAP(It.IsAny<string>(), It.IsAny<SearchScope>(), It.IsAny<string[]>(),
                It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<string>(), It.IsAny<bool>(),
                It.IsAny<bool>())).Returns(searchResults);
            var processor = new DomainTrustProcessor(mockUtils.Object);
            var test = processor.EnumerateDomainTrusts("testlab.local").ToArray();
            Assert.Single(test);
            var trust = test.First();
            Assert.Equal(TrustDirection.Bidirectional, trust.TrustDirection);
            Assert.Equal("EXTERNAL.LOCAL", trust.TargetDomainName);
            Assert.Equal("S-1-5-21-3084884204-958224920-2707782874", trust.TargetDomainSid);
            Assert.True(trust.IsTransitive);
            Assert.Equal(TrustType.ParentChild, trust.TrustType);
            Assert.True(trust.SidFilteringEnabled);
        }

        [Fact]
        public void DomainTrustProcessor_EnumerateDomainTrusts_SadPaths()
        {
            var mockUtils = new Mock<MockLDAPUtils>();
            var searchResults = new[]
            {
                new MockSearchResultEntry("CN\u003dexternal.local,CN\u003dSystem,DC\u003dtestlab,DC\u003dlocal",
                    new Dictionary<string, object>
                    {
                        {"trustdirection", "3"},
                        {"trusttype", "2"},
                        {"trustattributes", 0x24.ToString()},
                        {"cn", "external.local"},
                        {"securityIdentifier", Array.Empty<byte>()}
                    }, "", Label.Domain),
                new MockSearchResultEntry("CN\u003dexternal.local,CN\u003dSystem,DC\u003dtestlab,DC\u003dlocal",
                    new Dictionary<string, object>
                    {
                        {"trustdirection", "3"},
                        {"trusttype", "2"},
                        {"trustattributes", 0x24.ToString()},
                        {"cn", "external.local"},
                        {"securityIdentifier", Helpers.B64ToBytes("QQQAAAAAAAUVAAAA7JjftxhaHTnafGWh")}
                    }, "", Label.Domain),
                new MockSearchResultEntry("CN\u003dexternal.local,CN\u003dSystem,DC\u003dtestlab,DC\u003dlocal",
                    new Dictionary<string, object>
                    {
                        {"trusttype", "2"},
                        {"trustattributes", 0x24.ToString()},
                        {"cn", "external.local"},
                        {"securityIdentifier", Helpers.B64ToBytes("AQQAAAAAAAUVAAAA7JjftxhaHTnafGWh")}
                    }, "", Label.Domain),
                new MockSearchResultEntry("CN\u003dexternal.local,CN\u003dSystem,DC\u003dtestlab,DC\u003dlocal",
                    new Dictionary<string, object>
                    {
                        {"trustdirection", "3"},
                        {"trusttype", "2"},
                        {"cn", "external.local"},
                        {"securityIdentifier", Helpers.B64ToBytes("AQQAAAAAAAUVAAAA7JjftxhaHTnafGWh")}
                    }, "", Label.Domain)
            };

            mockUtils.Setup(x => x.QueryLDAP(It.IsAny<string>(), It.IsAny<SearchScope>(), It.IsAny<string[]>(),
                It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<string>(), It.IsAny<bool>(),
                It.IsAny<bool>())).Returns(searchResults);
            var processor = new DomainTrustProcessor(mockUtils.Object);
            var test = processor.EnumerateDomainTrusts("testlab.local");
            Assert.Empty(test);
        }

        [Fact]
        public void DomainTrustProcessor_TrustAttributesToType()
        {
            var attrib = TrustAttributes.WithinForest;
            var test = DomainTrustProcessor.TrustAttributesToType(attrib);
            Assert.Equal(TrustType.ParentChild, test);

            attrib = TrustAttributes.ForestTransitive;
            test = DomainTrustProcessor.TrustAttributesToType(attrib);
            Assert.Equal(TrustType.Forest, test);

            attrib = TrustAttributes.TreatAsExternal;
            test = DomainTrustProcessor.TrustAttributesToType(attrib);
            Assert.Equal(TrustType.External, test);

            attrib = TrustAttributes.CrossOrganization;
            test = DomainTrustProcessor.TrustAttributesToType(attrib);
            Assert.Equal(TrustType.External, test);

            attrib = TrustAttributes.FilterSids;
            test = DomainTrustProcessor.TrustAttributesToType(attrib);
            Assert.Equal(TrustType.Unknown, test);
        }
    }
}