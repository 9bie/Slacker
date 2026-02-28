using System;
using SharpHoundCommonLib.LDAPQueries;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class LDAPFilterTest : IDisposable
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public LDAPFilterTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            // This runs once per test.
        }

        public void Dispose()
        {
        }

        #region Creation

        [Fact]
        public void LDAPFilter_CreateNewFilter_FilterNotNull()
        {
            var test = new LDAPFilter();
            Assert.NotNull(test);
        }

        #endregion

        #region Behavioral

        [Fact]
        public void LDAPFilter_GroupFilter_FilterCorrect()
        {
            var test = new LDAPFilter();
            test.AddGroups();
            var filter = test.GetFilter();
            _testOutputHelper.WriteLine(filter);
            Assert.Equal(
                "(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))",
                filter);
        }

        [Fact]
        public void LDAPFilter_GroupFilter_ExtraFilter_FilterCorrect()
        {
            var test = new LDAPFilter();
            test.AddGroups("objectclass=*");
            var filter = test.GetFilter();
            _testOutputHelper.WriteLine(filter);
            Assert.Equal(
                "(&(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))(objectclass=*))",
                filter);
        }

        #endregion
    }
}