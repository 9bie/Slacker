using FluentAssertions;
using Xbehave;
using Xunit;

namespace CommonLibTest
{
    public class SmokeTest
    {
        [Fact]
        public void Show_FluentAssertions_TestWorks()
        {
            var actual = "ABCDEFGHI";
            actual.Should().StartWith("AB").And.EndWith("HI").And.Contain("EF").And.HaveLength(9);
        }

        [Scenario]
        public void Show_xBehave_TestWorks()
        {
            int x = 0,
                y = 0,
                answer = 0;

            "Given the number 1"
                .x(() => x = 1);

            "And the number 2"
                .x(() => y = 2);

            "When I add the numbers together"
                .x(() => answer = x + y);

            "Then the answer is 3"
                .x(() => Assert.Equal(3, answer));
        }

        #region xUnit [Classic]

        [Fact]
        public void SanityCheck()
        {
            Assert.True(true);
        }

        [Fact]
        public void Throw_FileExistsException_ExceptionIsThrown()
        {
            Assert.True(true);
        }

        #endregion
    }
}