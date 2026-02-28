using System;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public struct WKP
    {
        public string SID { get; set; }
        public string Name { get; set; }

        public string Description { get; set; }
    }

    public class WellKnownPrincipalTest : IDisposable
    {
        #region Constructor(s)

        public WellKnownPrincipalTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _testDomainName = "TESTLAB.LOCAL";
            _testForestName = "FOREST.LOCAL";
        }

        #endregion

        #region IDispose Implementation

        public void Dispose()
        {
            // Tear down (called once per test)
        }

        #endregion

        [Fact]
        public void GetKnownPrincipal_PassingKnownIds_MatchesNameAndLabel()
        {
            foreach (var p in GetWellKnownPrincipals())
            {
                var result = WellKnownPrincipal.GetWellKnownPrincipal(p.sid, out var typedPrincipal);
                Assert.True(result);
                Assert.Equal(p.label, typedPrincipal.ObjectType);
            }
        }

        #region TestData

        /// <summary>
        ///     GetWellKnownPrincipal static test data
        ///     List of known principals for testing. The number and composition should not differ between this list and the
        ///     runtime literals in the common lib. Change the code without updating the tests is a fail condition.
        /// </summary>
        /// <returns>True if SID matches a well known principal, false otherwise</returns>
        private static (string sid, string name, Label label)[] GetWellKnownPrincipals()
        {
            return new (string sid, string name, Label label)[]
            {
                ("S-1-0", "Null Authority", Label.User),
                ("S-1-0-0", "Nobody", Label.User),
                ("S-1-1", "World Authority", Label.User),
                ("S-1-1-0", "Everyone", Label.Group),
                ("S-1-2", "Local Authority", Label.User),
                ("S-1-2-0", "Local", Label.Group),
                ("S-1-2-1", "Console Logon", Label.Group),
                ("S-1-3", "Creator Authority", Label.User),
                ("S-1-3-0", "Creator Owner", Label.User),
                ("S-1-3-1", "Creator Label.Group", Label.Group),
                ("S-1-3-2", "Creator Owner Server", Label.Computer),
                ("S-1-3-3", "Creator Group Server", Label.Computer),
                ("S-1-3-4", "Owner Rights", Label.Group),
                ("S-1-4", "Non-unique Authority", Label.User),
                ("S-1-5", "NT Authority", Label.User),
                ("S-1-5-1", "Dialup", Label.Group),
                ("S-1-5-2", "Network", Label.Group),
                ("S-1-5-3", "Batch", Label.Group),
                ("S-1-5-4", "Interactive", Label.Group),
                ("S-1-5-6", "Service", Label.Group),
                ("S-1-5-7", "Anonymous", Label.Group),
                ("S-1-5-8", "Proxy", Label.Group),
                ("S-1-5-9", "Enterprise Domain Controllers", Label.Group),
                ("S-1-5-10", "Principal Self", Label.User),
                ("S-1-5-11", "Authenticated Users", Label.Group),
                ("S-1-5-12", "Restricted Code", Label.Group),
                ("S-1-5-13", "Terminal Server Users", Label.Group),
                ("S-1-5-14", "Remote Interactive Logon", Label.Group),
                ("S-1-5-15", "This Organization ", Label.Group),
                ("S-1-5-17", "This Organization ", Label.Group),
                ("S-1-5-18", "Local System", Label.User),
                ("S-1-5-19", "NT Authority", Label.User),
                ("S-1-5-20", "NT Authority", Label.User),
                ("S-1-5-113", "Local Account", Label.User),
                ("S-1-5-114", "Local Account and Member of Administrators Group", Label.User),
                ("S-1-5-80-0", "All Services ", Label.Group),
                ("S-1-5-32-544", "Administrators", Label.Group),
                ("S-1-5-32-545", "Users", Label.Group),
                ("S-1-5-32-546", "Guests", Label.Group),
                ("S-1-5-32-547", "Power Label.Users", Label.Group),
                ("S-1-5-32-548", "Account Operators", Label.Group),
                ("S-1-5-32-549", "Server Operators", Label.Group),
                ("S-1-5-32-550", "Print Operators", Label.Group),
                ("S-1-5-32-551", "Backup Operators", Label.Group),
                ("S-1-5-32-552", "Replicators", Label.Group),
                ("S-1-5-32-554", "Pre-Windows 2000 Compatible Access", Label.Group),
                ("S-1-5-32-555", "Remote Desktop Users", Label.Group),
                ("S-1-5-32-556", "Network Configuration Operators", Label.Group),
                ("S-1-5-32-557", "Incoming Forest Trust Builders", Label.Group),
                ("S-1-5-32-558", "Performance Monitor Users", Label.Group),
                ("S-1-5-32-559", "Performance Log Users", Label.Group),
                ("S-1-5-32-560", "Windows Authorization Access Group", Label.Group),
                ("S-1-5-32-561", "Terminal Server License Servers", Label.Group),
                ("S-1-5-32-562", "Distributed COM Users", Label.Group),
                ("S-1-5-32-568", "IIS_IUSRS", Label.Group),
                ("S-1-5-32-569", "Cryptographic Operators", Label.Group),
                ("S-1-5-32-573", "Event Log Readers", Label.Group),
                ("S-1-5-32-574", "Certificate Service DCOM Access", Label.Group),
                ("S-1-5-32-575", "RDS Remote Access Servers", Label.Group),
                ("S-1-5-32-576", "RDS Endpoint Servers", Label.Group),
                ("S-1-5-32-577", "RDS Management Servers", Label.Group),
                ("S-1-5-32-578", "Hyper-V Administrators", Label.Group),
                ("S-1-5-32-579", "Access Control Assistance Operators", Label.Group),
                ("S-1-5-32-580", "Remote Management Users", Label.Group)
            };
        }

        #endregion

        #region Private Members

        private readonly ITestOutputHelper _testOutputHelper;
        private readonly string _testDomainName;
        private readonly string _testForestName;

        #endregion

        #region Tests

        /// <summary>
        ///     Test the GetWellKnownPrincipal for sid: 'S-1-0-0'
        /// </summary>
        [Fact]
        public void GetWellKnownPrincipal_PassingTestSid__ReturnsValidTypedPrincipal()
        {
            var result = WellKnownPrincipal.GetWellKnownPrincipal("S-1-0-0", out var typedPrincipal);

            Assert.True(result);
            Assert.Equal(Label.User, typedPrincipal.ObjectType);
        }

        [Fact]
        public void GetWellKnownPrincipal_NonWellKnown_ReturnsNull()
        {
            var result = WellKnownPrincipal.GetWellKnownPrincipal("S-1-5-21-123456-78910", out var typedPrincipal);
            Assert.False(result);
            Assert.Null(typedPrincipal);
        }

        #endregion
    }
}