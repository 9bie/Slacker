using System;
using System.Text;
using SharpHoundCommonLib.Enums;
using Xunit;

namespace CommonLibTest
{
    public class CommonLibHelperTest
    {
        [Fact]
        public void SplitGPLinkProperty_ValidPropFilterEnabled_ExpectedResult()
        {
            var isPropFilterEnabled = false;
            //TODO: Ari, proper test string?
            var testGPLinkProperty =
                "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123; SIP:foouser@example.co.uk; smtp:foouser@sub1.example.co.uk; smtp:foouser@sub2.example.co.uk; SMTP:foouser@example.co.uk][]";

            var res = SharpHoundCommonLib.Helpers.SplitGPLinkProperty(testGPLinkProperty, isPropFilterEnabled);

            foreach (var parsedGPLink in res)
                Assert.Equal("cn=foouser (blah)123", parsedGPLink.DistinguishedName);
            // TODO: issue here with test data? Assert.Equal("1", parsedGPLink.Status);
        }

        [Fact]
        public void SplitGPLinkProperty_ValidPropFilterDisabled_ExpectedResult()
        {
            var isPropFilterEnabled = false;
            //TODO: Ari, proper test string?
            var testGPLinkProperty =
                "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123; SIP:foouser@example.co.uk; smtp:foouser@sub1.example.co.uk; smtp:foouser@sub2.example.co.uk; SMTP:foouser@example.co.uk][]";

            var res = SharpHoundCommonLib.Helpers.SplitGPLinkProperty(testGPLinkProperty, isPropFilterEnabled);

            foreach (var parsedGPLink in res)
                Assert.Equal("cn=foouser (blah)123", parsedGPLink.DistinguishedName);
            // TODO: issue here with test data? Assert.Equal("1", parsedGPLink.Status);
        }

        /// 
        [Fact]
        public void SplitGPLinkProperty_PropWithUnsupportedDelimiter_FilterEnabled_ExpectedResult()
        {
            var isPropFilterEnabled = true;
            //TODO: Ari, proper test string?
            var testGPLinkProperty =
                "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123; DC=somedomainName; SIP:foouser@example.co.uk; smtp:foouser@sub1.example.co.uk; smtp:foouser@sub2.example.co.uk; SMTP:foouser@example.co.uk][]";

            var res = SharpHoundCommonLib.Helpers.SplitGPLinkProperty(testGPLinkProperty, isPropFilterEnabled);

            foreach (var parsedGPLink in res)
                Assert.Equal("cn=foouser (blah)123", parsedGPLink.DistinguishedName);
            // TODO: issue here with test data? Assert.Equal("1", parsedGPLink.Status);
        }

        [Fact]
        public void SplitGPLinkProperty_InValidPropFilterDisabled_ExpectedResult()
        {
            var isPropFilterEnabled = false;
            //TODO: Ari, proper test string?
            var testGPLinkProperty = "/*obviously wrong data*/";
            var res = SharpHoundCommonLib.Helpers.SplitGPLinkProperty(testGPLinkProperty, isPropFilterEnabled);
            Assert.Empty(res);
        }

        [Fact]
        public void SamAccountTypeToType_ValidString_CorrectLabel()
        {
            var accountTypeLookup = new (string accountType, Label label)[]
            {
                (accountType: "268435456", label: Label.Group),
                (accountType: "268435457", label: Label.Group),
                (accountType: "536870912", label: Label.Group),
                (accountType: "536870913", label: Label.Group),
                (accountType: "805306369", Label.Computer),
                (accountType: "805306368", Label.User)
            };

            foreach (var e in accountTypeLookup)
            {
                var result = SharpHoundCommonLib.Helpers.SamAccountTypeToType(e.accountType);
                Assert.Equal(result, e.label);
            }
        }

        [Fact]
        public void SamAccountTypeToType_InValidString_CorrectLabel()
        {
            var result = SharpHoundCommonLib.Helpers.SamAccountTypeToType("nonsense_^&^^&(*^*^*&(&^&(^*AAAA");
            Assert.Equal(Label.Base, result);
        }

        // [Fact]
        // public void ConvertSidToHexSid_ValidString_ValidHex()
        // {
        //     var hexString = SharpHoundCommonLib.Helpers.ConvertSidToHexSid("268435457");
        //     var securityIdentifier = new SecurityIdentifier("268435457");
        //     var sidBytes = new byte[securityIdentifier.BinaryLength];
        //     securityIdentifier.GetBinaryForm(sidBytes, 0);

        //     var output = $"\\{BitConverter.ToString(sidBytes).Replace('-', '\\')}";
        //     Assert.Equal(output, hexString);
        // }

        [Fact]
        public void ConvertGuidToHexGuid_ValidStringGuid_ValidHex()
        {
            // Atmoic conversion test. Add as many variants as needed to increase confidence.

            var guid = Guid.NewGuid();
            var hexString = SharpHoundCommonLib.Helpers.ConvertGuidToHexGuid(guid.ToString());

            // We recreate part of thr operation here to test parity. If you the function under test changes this code then the test may fail and indicate drift in the code away from expected behavior.
            var output = $"\\{BitConverter.ToString(guid.ToByteArray()).Replace('-', '\\')}";
            Assert.Equal(output, hexString);
        }

        [Fact]
        public void DistinguishedNameToDomain_ValidDistinguishedName_ExpectedDomainValue()
        {
            var expected = "FABRIKAM.COM";
            var actual =
                SharpHoundCommonLib.Helpers.DistinguishedNameToDomain("CN=Jeff Smith,OU=Sales,DC=Fabrikam,DC=COM");
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void DistinguishedNameToDomain_InValidDistinguishedName_ReturnsNull()
        {
            var testDCQuery = "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123; DX=wjatvar][]";
            var actual = SharpHoundCommonLib.Helpers.DistinguishedNameToDomain(testDCQuery);
            Assert.Null(actual);
        }

        [Fact]
        public void StripServicePrincipalName_ValidServicePrincipal_ExpectedHostName()
        {
            var testString = "www/WEB-SERVER-01.adsec.local";
            var expected = "WEB-SERVER-01.adsec.local";
            var actual = SharpHoundCommonLib.Helpers.StripServicePrincipalName(testString);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void StripServicePrincipalName_InValidServicePrincipal_ExpectedHostName()
        {
            var testString = "234234f___bb4::fadfs";
            var expected = "234234f___bb4::fadfs";
            var actual = SharpHoundCommonLib.Helpers.StripServicePrincipalName(testString);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void B64ToBytes_String_ValidBase64String()
        {
            var testString = "obviously nonsense";
            var exampleBytes = Encoding.UTF8.GetBytes(testString);
            var compareString = Convert.ToBase64String(exampleBytes);
            var result = SharpHoundCommonLib.Helpers.Base64(testString);
            Assert.Equal(compareString, result);
        }

        [Fact]
        public void ConvertFileTimeToUnixEpoch_ValidFileTime_ValidUnixEpoch()
        {
            var testFileTime = "132260149842749745";
            var result = SharpHoundCommonLib.Helpers.ConvertFileTimeToUnixEpoch(testFileTime);
            var expected = 1581541384;
            Assert.Equal(expected, result);
        }

        [Fact]
        public void ConvertFileTimeToUnixEpoch_Null_NegativeOne()
        {
            var result = SharpHoundCommonLib.Helpers.ConvertFileTimeToUnixEpoch(null);
            Assert.Equal(-1, result);
        }

        [Fact]
        public void ConvertFileTimeToUnixEpoch_WrongFormat_FortmatException()
        {
            Exception ex =
                Assert.Throws<FormatException>(() => SharpHoundCommonLib.Helpers.ConvertFileTimeToUnixEpoch("asdsf"));
            Assert.Equal("Input string was not in a correct format.", ex.Message);
        }

        [Fact]
        public void ConvertFileTimeToUnixEpoch_BadInput_CastExceptionReturnsNegativeOne()
        {
            var result = SharpHoundCommonLib.Helpers.ConvertFileTimeToUnixEpoch("-3242432");
            Assert.Equal(-1, result);
        }

        [Fact]
        public void ConvertTimestampToUnixEpoch_ValidTimestamp_ValidUnixEpoch()
        {
            var d = DateTime.Parse("2021-06-21T00:00:00");
            var result =
                SharpHoundCommonLib.Helpers.ConvertFileTimeToUnixEpoch(d.ToFileTimeUtc().ToString()); // get the epoch
            var dateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(result); // create an offset from the epoch
            var testDate = dateTimeOffset.UtcDateTime;

            Assert.Equal(d.ToUniversalTime().Date, testDate);
        }

        [Fact]
        public void ConvertTimestampToUnixEpoch_InvalidTimestamp_FormatException()
        {
            Exception ex = Assert.Throws<FormatException>(() =>
                SharpHoundCommonLib.Helpers.ConvertFileTimeToUnixEpoch("-201adsfasf12180244"));
            Assert.Equal("Input string was not in a correct format.", ex.Message);
        }
    }
}