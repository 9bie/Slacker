using System;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Moq;
using Newtonsoft.Json;
using SharpHoundCommonLib;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class ComputerSessionProcessorTest : IDisposable
    {
        private readonly string _computerDomain;
        private readonly string _computerSid;
        private readonly ITestOutputHelper _testOutputHelper;

        public ComputerSessionProcessorTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            _computerDomain = "TESTLAB.LOCAL";
            _computerSid = "S-1-5-21-3130019616-2776909439-2417379446-1104";
        }

        #region IDispose Implementation

        public void Dispose()
        {
            // Tear down (called once per test)
        }

        #endregion

        [WindowsOnlyFact]
        public async Task ComputerSessionProcessor_ReadUserSessions_FilteringWorks()
        {
            var mockNativeMethods = new Mock<NativeMethods>();
            var apiResult = new NativeMethods.SESSION_INFO_10[]
            {
                new()
                {
                    sesi10_username = "dfm",
                    sesi10_cname = "\\\\192.168.92.110"
                },
                new()
                {
                    sesi10_cname = "",
                    sesi10_username = "admin"
                },
                new()
                {
                    sesi10_username = "admin",
                    sesi10_cname = "\\\\192.168.92.110"
                }
            };
            mockNativeMethods.Setup(x => x.CallNetSessionEnum(It.IsAny<string>())).Returns(apiResult);

            var processor = new ComputerSessionProcessor(new MockLDAPUtils(), "dfm", mockNativeMethods.Object);
            var result = await processor.ReadUserSessions("win10", _computerSid, _computerDomain);
            Assert.True(result.Collected);
            Assert.Empty(result.Results);
        }

        [WindowsOnlyFact]
        public async Task ComputerSessionProcessor_ReadUserSessions_ResolvesHost()
        {
            var mockNativeMethods = new Mock<NativeMethods>();
            var apiResult = new NativeMethods.SESSION_INFO_10[]
            {
                new()
                {
                    sesi10_username = "admin",
                    sesi10_cname = "\\\\192.168.1.1"
                }
            };
            mockNativeMethods.Setup(x => x.CallNetSessionEnum(It.IsAny<string>())).Returns(apiResult);

            var expected = new Session[]
            {
                new()
                {
                    ComputerSID = "S-1-5-21-3130019616-2776909439-2417379446-1104",
                    UserSID = "S-1-5-21-3130019616-2776909439-2417379446-2116"
                }
            };

            var processor = new ComputerSessionProcessor(new MockLDAPUtils(), "dfm", mockNativeMethods.Object);
            var result = await processor.ReadUserSessions("win10", _computerSid, _computerDomain);
            Assert.True(result.Collected);
            Assert.Equal(expected, result.Results);
        }

        [WindowsOnlyFact]
        public async Task ComputerSessionProcessor_ReadUserSessions_ResolvesLocalHostEquivalent()
        {
            var mockNativeMethods = new Mock<NativeMethods>();
            var apiResult = new NativeMethods.SESSION_INFO_10[]
            {
                new()
                {
                    sesi10_username = "admin",
                    sesi10_cname = "\\\\127.0.0.1"
                }
            };
            mockNativeMethods.Setup(x => x.CallNetSessionEnum(It.IsAny<string>())).Returns(apiResult);

            var expected = new Session[]
            {
                new()
                {
                    ComputerSID = _computerSid,
                    UserSID = "S-1-5-21-3130019616-2776909439-2417379446-2116"
                }
            };

            var processor = new ComputerSessionProcessor(new MockLDAPUtils(), "dfm", mockNativeMethods.Object);
            var result = await processor.ReadUserSessions("win10", _computerSid, _computerDomain);
            Assert.True(result.Collected);
            Assert.Equal(expected, result.Results);
        }

        [WindowsOnlyFact]
        public async Task ComputerSessionProcessor_ReadUserSessions_MultipleMatches_AddsAll()
        {
            var mockNativeMethods = new Mock<NativeMethods>();
            var apiResult = new NativeMethods.SESSION_INFO_10[]
            {
                new()
                {
                    sesi10_username = "administrator",
                    sesi10_cname = "\\\\127.0.0.1"
                }
            };
            mockNativeMethods.Setup(x => x.CallNetSessionEnum(It.IsAny<string>())).Returns(apiResult);

            var expected = new Session[]
            {
                new()
                {
                    ComputerSID = _computerSid,
                    UserSID = "S-1-5-21-3130019616-2776909439-2417379446-500"
                },
                new()
                {
                    ComputerSID = _computerSid,
                    UserSID = "S-1-5-21-3084884204-958224920-2707782874-500"
                }
            };

            var processor = new ComputerSessionProcessor(new MockLDAPUtils(), "dfm", mockNativeMethods.Object);
            var result = await processor.ReadUserSessions("win10", _computerSid, _computerDomain);
            Assert.True(result.Collected);
            Assert.Equal(expected, result.Results);
        }

        [WindowsOnlyFact]
        public async Task ComputerSessionProcessor_ReadUserSessions_NoGCMatch_TriesResolve()
        {
            var mockNativeMethods = new Mock<NativeMethods>();
            var apiResult = new NativeMethods.SESSION_INFO_10[]
            {
                new()
                {
                    sesi10_username = "test",
                    sesi10_cname = "\\\\127.0.0.1"
                }
            };
            mockNativeMethods.Setup(x => x.CallNetSessionEnum(It.IsAny<string>())).Returns(apiResult);

            var expected = new Session[]
            {
                new()
                {
                    ComputerSID = _computerSid,
                    UserSID = "S-1-5-21-3130019616-2776909439-2417379446-1106"
                }
            };

            var processor = new ComputerSessionProcessor(new MockLDAPUtils(), "dfm", mockNativeMethods.Object);
            var result = await processor.ReadUserSessions("win10", _computerSid, _computerDomain);
            Assert.True(result.Collected);
            Assert.Equal(expected, result.Results);
        }

        [WindowsOnlyFact]
        public async Task ComputerSessionProcessor_ReadUserSessions_ComputerAccessDenied_ExceptionCaught()
        {
            var mockNativeMethods = new Mock<NativeMethods>();
            //mockNativeMethods.Setup(x => x.CallSamConnect(ref It.Ref<NativeMethods.UNICODE_STRING>.IsAny, out It.Ref<IntPtr>.IsAny, It.IsAny<NativeMethods.SamAccessMasks>(), ref It.Ref<NativeMethods.OBJECT_ATTRIBUTES>.IsAny)).Returns(NativeMethods.NtStatus.StatusAccessDenied);
            var ex = new APIException
            {
                Status = NativeMethods.NERR.ERROR_ACCESS_DENIED.ToString()
            };
            mockNativeMethods.Setup(x => x.CallNetSessionEnum(It.IsAny<string>())).Throws(ex);
            var processor = new ComputerSessionProcessor(new MockLDAPUtils(), "dfm", mockNativeMethods.Object);
            var test = await processor.ReadUserSessions("test", "test", "test");
            Assert.False(test.Collected);
            Assert.Equal(NativeMethods.NERR.ERROR_ACCESS_DENIED.ToString(), test.FailureReason);
        }

        [WindowsOnlyFact]
        public async Task ComputerSessionProcessor_ReadUserSessionsPrivileged_ComputerAccessDenied_ExceptionCaught()
        {
            var mockNativeMethods = new Mock<NativeMethods>();
            //mockNativeMethods.Setup(x => x.CallSamConnect(ref It.Ref<NativeMethods.UNICODE_STRING>.IsAny, out It.Ref<IntPtr>.IsAny, It.IsAny<NativeMethods.SamAccessMasks>(), ref It.Ref<NativeMethods.OBJECT_ATTRIBUTES>.IsAny)).Returns(NativeMethods.NtStatus.StatusAccessDenied);
            var ex = new APIException
            {
                Status = NativeMethods.NERR.ERROR_ACCESS_DENIED.ToString()
            };
            mockNativeMethods.Setup(x => x.CallNetWkstaUserEnum(It.IsAny<string>())).Throws(ex);
            var processor = new ComputerSessionProcessor(new MockLDAPUtils(), "dfm", mockNativeMethods.Object);
            var test = processor.ReadUserSessionsPrivileged("test", "test", "test");
            Assert.False(test.Collected);
            Assert.Equal(NativeMethods.NERR.ERROR_ACCESS_DENIED.ToString(), test.FailureReason);
        }

        [WindowsOnlyFact]
        public async Task ComputerSessionProcessor_ReadUserSessionsPrivileged_FilteringWorks()
        {
            var mockNativeMethods = new Mock<NativeMethods>();
            const string samAccountName = "WIN10";

            //This is a sample response from a computer in a test environment. The duplicates are intentional
            var apiResults = new NativeMethods.WKSTA_USER_INFO_1[]
            {
                new()
                {
                    wkui1_logon_domain = "TESTLAB",
                    wkui1_logon_server = "PRIMARY",
                    wkui1_oth_domains = "",
                    wkui1_username = "dfm"
                },
                new()
                {
                    wkui1_logon_domain = "PRIMARY",
                    wkui1_logon_server = "",
                    wkui1_oth_domains = "",
                    wkui1_username = "Administrator"
                },
                new()
                {
                    wkui1_logon_domain = "",
                    wkui1_logon_server = "PRIMARY",
                    wkui1_oth_domains = "",
                    wkui1_username = "Administrator"
                },
                new()
                {
                    wkui1_logon_domain = "TESTLAB",
                    wkui1_logon_server = "",
                    wkui1_oth_domains = "",
                    wkui1_username = "WIN10$"
                },
                new()
                {
                    wkui1_logon_domain = "TESTLAB",
                    wkui1_logon_server = "",
                    wkui1_oth_domains = "",
                    wkui1_username = "WIN10$"
                },
                new()
                {
                    wkui1_logon_domain = "TESTLAB",
                    wkui1_logon_server = "",
                    wkui1_oth_domains = "",
                    wkui1_username = "WIN10$"
                },
                new()
                {
                    wkui1_logon_domain = "TESTLAB",
                    wkui1_logon_server = "",
                    wkui1_oth_domains = "",
                    wkui1_username = "WIN10$"
                },
                new()
                {
                    wkui1_logon_domain = "WIN10",
                    wkui1_logon_server = "",
                    wkui1_oth_domains = "",
                    wkui1_username = "JOHN"
                },
                new()
                {
                    wkui1_logon_domain = "NT AUTHORITY",
                    wkui1_logon_server = "",
                    wkui1_oth_domains = "",
                    wkui1_username = "SYSTEM"
                },
                new()
                {
                    wkui1_logon_domain = "TESTLAB",
                    wkui1_logon_server = "",
                    wkui1_oth_domains = "",
                    wkui1_username = "ABC"
                }
            };
            mockNativeMethods.Setup(x => x.CallNetWkstaUserEnum(It.IsAny<string>())).Returns(apiResults);

            var expected = new Session[]
            {
                new()
                {
                    ComputerSID = _computerSid,
                    UserSID = "S-1-5-21-3130019616-2776909439-2417379446-1105"
                },
                new()
                {
                    ComputerSID = _computerSid,
                    UserSID = "S-1-5-21-3130019616-2776909439-2417379446-500"
                }
            };

            var processor = new ComputerSessionProcessor(new MockLDAPUtils(), nativeMethods: mockNativeMethods.Object);
            var test = processor.ReadUserSessionsPrivileged("WIN10.TESTLAB.LOCAL", samAccountName, _computerSid);
            Assert.True(test.Collected);
            _testOutputHelper.WriteLine(JsonConvert.SerializeObject(test.Results));
            Assert.Equal(2, test.Results.Length);
            Assert.Equal(expected, test.Results);
        }
    }
}