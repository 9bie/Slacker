using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class LDAPPropertyTests
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public LDAPPropertyTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadDomainProperties_TestGoodData()
        {
            var mock = new MockSearchResultEntry("DC\u003dtestlab,DC\u003dlocal", new Dictionary<string, object>
            {
                {"description", "TESTLAB Domain"},
                {"msds-behavior-version", "6"}
            }, "S-1-5-21-3130019616-2776909439-2417379446", Label.Domain);

            var test = LDAPPropertyProcessor.ReadDomainProperties(mock);
            Assert.Contains("functionallevel", test.Keys);
            Assert.Equal("2012 R2", test["functionallevel"] as string);
            Assert.Contains("description", test.Keys);
            Assert.Equal("TESTLAB Domain", test["description"] as string);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadDomainProperties_TestBadFunctionalLevel()
        {
            var mock = new MockSearchResultEntry("DC\u003dtestlab,DC\u003dlocal", new Dictionary<string, object>
            {
                {"msds-behavior-version", "a"}
            }, "S-1-5-21-3130019616-2776909439-2417379446", Label.Domain);

            var test = LDAPPropertyProcessor.ReadDomainProperties(mock);
            Assert.Contains("functionallevel", test.Keys);
            Assert.Equal("Unknown", test["functionallevel"] as string);
        }

        [Fact]
        public void LDAPPropertyProcessor_FunctionalLevelToString_TestFunctionalLevels()
        {
            var expected = new Dictionary<int, string>
            {
                {0, "2000 Mixed/Native"},
                {1, "2003 Interim"},
                {2, "2003"},
                {3, "2008"},
                {4, "2008 R2"},
                {5, "2012"},
                {6, "2012 R2"},
                {7, "2016"},
                {-1, "Unknown"}
            };

            foreach (var (key, value) in expected)
                Assert.Equal(value, LDAPPropertyProcessor.FunctionalLevelToString(key));
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadGPOProperties_TestGoodData()
        {
            var mock = new MockSearchResultEntry(
                "CN\u003d{94DD0260-38B5-497E-8876-10E7A96E80D0},CN\u003dPolicies,CN\u003dSystem,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {
                        "gpcfilesyspath",
                        Helpers.B64ToString(
                            "XFx0ZXN0bGFiLmxvY2FsXFN5c1ZvbFx0ZXN0bGFiLmxvY2FsXFBvbGljaWVzXHs5NEREMDI2MC0zOEI1LTQ5N0UtODg3Ni0xMEU3QTk2RTgwRDB9")
                    },
                    {"description", "Test"}
                }, "S-1-5-21-3130019616-2776909439-2417379446", Label.GPO);

            var test = LDAPPropertyProcessor.ReadGPOProperties(mock);

            Assert.Contains("description", test.Keys);
            Assert.Equal("Test", test["description"] as string);
            Assert.Contains("gpcpath", test.Keys);
            Assert.Equal(@"\\TESTLAB.LOCAL\SYSVOL\TESTLAB.LOCAL\POLICIES\{94DD0260-38B5-497E-8876-10E7A96E80D0}",
                test["gpcpath"] as string);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadOUProperties_TestGoodData()
        {
            var mock = new MockSearchResultEntry("OU\u003dTestOU,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"}
                }, "2A374493-816A-4193-BEFD-D2F4132C6DCA", Label.OU);

            var test = LDAPPropertyProcessor.ReadOUProperties(mock);
            Assert.Contains("description", test.Keys);
            Assert.Equal("Test", test["description"] as string);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadGroupProperties_TestGoodData()
        {
            var mock = new MockSearchResultEntry("CN\u003dDomain Admins,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"admincount", "1"}
                }, "S-1-5-21-3130019616-2776909439-2417379446-512", Label.Group);

            var test = LDAPPropertyProcessor.ReadGroupProperties(mock);
            Assert.Contains("description", test.Keys);
            Assert.Equal("Test", test["description"] as string);
            Assert.Contains("admincount", test.Keys);
            Assert.True((bool) test["admincount"]);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadGroupProperties_TestGoodData_FalseAdminCount()
        {
            var mock = new MockSearchResultEntry("CN\u003dDomain Admins,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"admincount", "0"}
                }, "S-1-5-21-3130019616-2776909439-2417379446-512", Label.Group);

            var test = LDAPPropertyProcessor.ReadGroupProperties(mock);
            Assert.Contains("description", test.Keys);
            Assert.Equal("Test", test["description"] as string);
            Assert.Contains("admincount", test.Keys);
            Assert.False((bool) test["admincount"]);
        }

        [Fact]
        public void LDAPPropertyProcessor_ReadGroupProperties_NullAdminCount()
        {
            var mock = new MockSearchResultEntry("CN\u003dDomain Admins,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"}
                }, "S-1-5-21-3130019616-2776909439-2417379446-512", Label.Group);

            var test = LDAPPropertyProcessor.ReadGroupProperties(mock);
            Assert.Contains("description", test.Keys);
            Assert.Equal("Test", test["description"] as string);
            Assert.Contains("admincount", test.Keys);
            Assert.False((bool) test["admincount"]);
        }

        [Fact]
        public async Task LDAPPropertyProcessor_ReadUserProperties_TestTrustedToAuth()
        {
            var mock = new MockSearchResultEntry("CN\u003ddfm,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", 0x1000000.ToString()},
                    {"lastlogon", "132673011142753043"},
                    {"lastlogontimestamp", "132670318095676525"},
                    {"homedirectory", @"\\win10\testdir"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "MSSQLSVC\\win10"
                        }
                    },
                    {"admincount", "1"},
                    {
                        "sidhistory", new[]
                        {
                            Helpers.B64ToBytes("AQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQUQQAAA==")
                        }
                    },
                    {"pwdlastset", "132131667346106691"},
                    {
                        "msds-allowedtodelegateto", new[]
                        {
                            "host/primary",
                            "rdpman/win10"
                        }
                    }
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101", Label.User);

            var processor = new LDAPPropertyProcessor(new MockLDAPUtils());
            var test = await processor.ReadUserProperties(mock);
            var props = test.Props;
            var keys = props.Keys;

            Assert.Contains("allowedtodelegate", keys);
            var atd = props["allowedtodelegate"] as string[];
            Assert.Equal(2, atd.Length);
            Assert.Contains("host/primary", atd);
            Assert.Contains("rdpman/win10", atd);

            var atdr = test.AllowedToDelegate;
            Assert.Equal(2, atdr.Length);
            var expected = new TypedPrincipal[]
            {
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-1001",
                    ObjectType = Label.Computer
                },
                new()
                {
                    ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-1104",
                    ObjectType = Label.Computer
                }
            };
            Assert.Equal(expected, atdr);
        }

        [Fact]
        public async Task LDAPPropertyProcessor_ReadUserProperties_NullAdminCount()
        {
            var mock = new MockSearchResultEntry("CN\u003ddfm,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", "66048"},
                    {"lastlogon", "132673011142753043"},
                    {"lastlogontimestamp", "132670318095676525"},
                    {"homedirectory", @"\\win10\testdir"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "MSSQLSVC\\win10"
                        }
                    },
                    {
                        "sidhistory", new[]
                        {
                            Helpers.B64ToBytes("AQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQUQQAAA==")
                        }
                    },
                    {"pwdlastset", "132131667346106691"}
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101", Label.User);

            var processor = new LDAPPropertyProcessor(new MockLDAPUtils());
            var test = await processor.ReadUserProperties(mock);
            var props = test.Props;
            var keys = props.Keys;
            Assert.Contains("admincount", keys);
            Assert.False((bool) props["admincount"]);
        }

        [WindowsOnlyFact]
        public async Task LDAPPropertyProcessor_ReadUserProperties_HappyPath()
        {
            var mock = new MockSearchResultEntry("CN\u003ddfm,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", "66048"},
                    {"lastlogon", "132673011142753043"},
                    {"lastlogontimestamp", "132670318095676525"},
                    {"homedirectory", @"\\win10\testdir"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "MSSQLSVC/win10"
                        }
                    },
                    {"admincount", "1"},
                    {
                        "sidhistory", new[]
                        {
                            Helpers.B64ToBytes("AQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQUQQAAA==")
                        }
                    },
                    {"pwdlastset", "132131667346106691"}
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101", Label.User);

            var processor = new LDAPPropertyProcessor(new MockLDAPUtils());
            var test = await processor.ReadUserProperties(mock);
            var props = test.Props;
            var keys = props.Keys;

            //Random Stuff
            Assert.Contains("description", keys);
            Assert.Equal("Test", props["description"] as string);
            Assert.Contains("admincount", keys);
            Assert.True((bool) props["admincount"]);
            Assert.Contains("lastlogon", keys);
            Assert.Equal(1622827514, (long) props["lastlogon"]);
            Assert.Contains("lastlogontimestamp", keys);
            Assert.Equal(1622558209, (long) props["lastlogontimestamp"]);
            Assert.Contains("pwdlastset", keys);
            Assert.Equal(1568693134, (long) props["pwdlastset"]);
            Assert.Contains("homedirectory", keys);
            Assert.Equal(@"\\win10\testdir", props["homedirectory"] as string);

            //UAC stuff
            Assert.Contains("sensitive", keys);
            Assert.False((bool) props["sensitive"]);
            Assert.Contains("dontreqpreauth", keys);
            Assert.False((bool) props["dontreqpreauth"]);
            Assert.Contains("passwordnotreqd", keys);
            Assert.False((bool) props["passwordnotreqd"]);
            Assert.Contains("unconstraineddelegation", keys);
            Assert.False((bool) props["unconstraineddelegation"]);
            Assert.Contains("enabled", keys);
            Assert.True((bool) props["enabled"]);
            Assert.Contains("trustedtoauth", keys);
            Assert.False((bool) props["trustedtoauth"]);

            //SPN
            Assert.Contains("hasspn", keys);
            Assert.True((bool) props["hasspn"]);
            Assert.Contains("serviceprincipalnames", keys);
            Assert.Contains("MSSQLSVC/win10", props["serviceprincipalnames"] as string[]);

            //SidHistory
            Assert.Contains("sidhistory", keys);
            var sh = props["sidhistory"] as string[];
            Assert.Single(sh);
            Assert.Contains("S-1-5-21-3130019616-2776909439-2417379446-1105", sh);
            Assert.Single(test.SidHistory);
            Assert.Contains(new TypedPrincipal
            {
                ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-1105",
                ObjectType = Label.User
            }, test.SidHistory);
        }

        [Fact]
        public async Task LDAPPropertyProcessor_ReadUserProperties_TestBadPaths()
        {
            var mock = new MockSearchResultEntry("CN\u003ddfm,CN\u003dUsers,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", "abc"},
                    {"lastlogon", "132673011142753043"},
                    {"lastlogontimestamp", "132670318095676525"},
                    {"homedirectory", @"\\win10\testdir"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "MSSQLSVC/win10"
                        }
                    },
                    {"admincount", "c"},
                    {
                        "sidhistory", new[]
                        {
                            Array.Empty<byte>()
                        }
                    },
                    {"pwdlastset", "132131667346106691"}
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101", Label.User);

            var processor = new LDAPPropertyProcessor(new MockLDAPUtils());
            var test = await processor.ReadUserProperties(mock);
            var props = test.Props;
            var keys = props.Keys;

            Assert.Contains("sidhistory", keys);
            Assert.Empty(props["sidhistory"] as string[]);
            Assert.Contains("admincount", keys);
            Assert.False((bool) props["admincount"]);
            Assert.Contains("sensitive", keys);
            Assert.Contains("dontreqpreauth", keys);
            Assert.Contains("passwordnotreqd", keys);
            Assert.Contains("unconstraineddelegation", keys);
            Assert.Contains("pwdneverexpires", keys);
            Assert.Contains("enabled", keys);
            Assert.Contains("trustedtoauth", keys);
            Assert.False((bool) props["trustedtoauth"]);
            Assert.False((bool) props["sensitive"]);
            Assert.False((bool) props["dontreqpreauth"]);
            Assert.False((bool) props["passwordnotreqd"]);
            Assert.False((bool) props["unconstraineddelegation"]);
            Assert.False((bool) props["pwdneverexpires"]);
            Assert.True((bool) props["enabled"]);
        }

        [WindowsOnlyFact]
        public async Task LDAPPropertyProcessor_ReadComputerProperties_HappyPath()
        {
            //TODO: Add coverage for allowedtoact
            var mock = new MockSearchResultEntry("CN\u003dWIN10,OU\u003dTestOU,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", 0x1001000.ToString()},
                    {"lastlogon", "132673011142753043"},
                    {"lastlogontimestamp", "132670318095676525"},
                    {"operatingsystem", "Windows 10 Enterprise"},
                    {"operatingsystemservicepack", "1607"},
                    {"admincount", "c"},
                    {
                        "sidhistory", new[]
                        {
                            Helpers.B64ToBytes("AQUAAAAAAAUVAAAAIE+Qun9GhKV2SBaQUQQAAA==")
                        }
                    },
                    {
                        "msds-allowedtodelegateto", new[]
                        {
                            "ldap/PRIMARY.testlab.local/testlab.local",
                            "ldap/PRIMARY.testlab.local",
                            "ldap/PRIMARY"
                        }
                    },
                    {"pwdlastset", "132131667346106691"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "WSMAN/WIN10",
                            "WSMAN/WIN10.testlab.local",
                            "RestrictedKrbHost/WIN10",
                            "HOST/WIN10",
                            "RestrictedKrbHost/WIN10.testlab.local",
                            "HOST/WIN10.testlab.local"
                        }
                    }
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101", Label.Computer);

            var processor = new LDAPPropertyProcessor(new MockLDAPUtils());
            var test = await processor.ReadComputerProperties(mock);
            var props = test.Props;
            var keys = props.Keys;

            //UAC
            Assert.Contains("enabled", keys);
            Assert.Contains("unconstraineddelegation", keys);
            Assert.Contains("lastlogon", keys);
            Assert.Contains("lastlogontimestamp", keys);
            Assert.Contains("pwdlastset", keys);
            Assert.True((bool) props["enabled"]);
            Assert.False((bool) props["unconstraineddelegation"]);

            Assert.Contains("lastlogon", keys);
            Assert.Equal(1622827514, (long) props["lastlogon"]);
            Assert.Contains("lastlogontimestamp", keys);
            Assert.Equal(1622558209, (long) props["lastlogontimestamp"]);
            Assert.Contains("pwdlastset", keys);
            Assert.Equal(1568693134, (long) props["pwdlastset"]);

            //AllowedToDelegate
            Assert.Single(test.AllowedToDelegate);
            Assert.Contains(new TypedPrincipal
            {
                ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-1001",
                ObjectType = Label.Computer
            }, test.AllowedToDelegate);

            //Other Stuff
            Assert.Contains("serviceprincipalnames", keys);
            Assert.Equal(6, (props["serviceprincipalnames"] as string[]).Length);
            Assert.Contains("operatingsystem", keys);
            Assert.Equal("Windows 10 Enterprise 1607", props["operatingsystem"] as string);
            Assert.Contains("description", keys);
            Assert.Equal("Test", props["description"] as string);

            //SidHistory
            Assert.Contains("sidhistory", keys);
            var sh = props["sidhistory"] as string[];
            Assert.Single(sh);
            Assert.Contains("S-1-5-21-3130019616-2776909439-2417379446-1105", sh);
            Assert.Single(test.SidHistory);
            Assert.Contains(new TypedPrincipal
            {
                ObjectIdentifier = "S-1-5-21-3130019616-2776909439-2417379446-1105",
                ObjectType = Label.User
            }, test.SidHistory);
        }

        [Fact]
        public async Task LDAPPropertyProcessor_ReadComputerProperties_TestBadPaths()
        {
            var mock = new MockSearchResultEntry("CN\u003dWIN10,OU\u003dTestOU,DC\u003dtestlab,DC\u003dlocal",
                new Dictionary<string, object>
                {
                    {"description", "Test"},
                    {"useraccountcontrol", "abc"},
                    {"lastlogon", "132673011142753043"},
                    {"lastlogontimestamp", "132670318095676525"},
                    {"operatingsystem", "Windows 10 Enterprise"},
                    {"admincount", "c"},
                    {
                        "sidhistory", new[]
                        {
                            Array.Empty<byte>()
                        }
                    },
                    {
                        "msds-allowedToDelegateTo", new[]
                        {
                            "ldap/PRIMARY.testlab.local/testlab.local",
                            "ldap/PRIMARY.testlab.local",
                            "ldap/PRIMARY"
                        }
                    },
                    {"pwdlastset", "132131667346106691"},
                    {
                        "serviceprincipalname", new[]
                        {
                            "WSMAN/WIN10",
                            "WSMAN/WIN10.testlab.local",
                            "RestrictedKrbHost/WIN10",
                            "HOST/WIN10",
                            "RestrictedKrbHost/WIN10.testlab.local",
                            "HOST/WIN10.testlab.local"
                        }
                    }
                }, "S-1-5-21-3130019616-2776909439-2417379446-1101", Label.Computer);

            var processor = new LDAPPropertyProcessor(new MockLDAPUtils());
            var test = await processor.ReadComputerProperties(mock);
            var props = test.Props;
            var keys = props.Keys;

            Assert.Contains("unconstraineddelegation", keys);
            Assert.Contains("enabled", keys);
            Assert.Contains("trustedtoauth", keys);
            Assert.False((bool) props["unconstraineddelegation"]);
            Assert.True((bool) props["enabled"]);
            Assert.False((bool) props["trustedtoauth"]);
            Assert.Contains("sidhistory", keys);
            Assert.Empty(props["sidhistory"] as string[]);
        }

        //TODO: Add coverage for ParseAllProperties
    }
}