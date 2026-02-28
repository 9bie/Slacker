using System;
using System.Threading.Tasks;
using Moq;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class ComputerAvailabilityTests : IDisposable
    {
        private readonly PortScanner _falsePortScanner;
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly PortScanner _truePortScanner;

        public ComputerAvailabilityTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            var m = new Mock<PortScanner>();
            m.Setup(x => x.CheckPort(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<int>()))
                .Returns(Task.FromResult(false));
            _falsePortScanner = m.Object;

            var m2 = new Mock<PortScanner>();
            m2.Setup(x => x.CheckPort(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<int>()))
                .Returns(Task.FromResult(true));
            _truePortScanner = m2.Object;
        }

        public void Dispose()
        {
        }

        [Fact]
        public async Task ComputerAvailability_IsComputerAvailable_BadOperatingSystem_ReturnsFalse()
        {
            var processor = new ComputerAvailability();
            var test = await processor.IsComputerAvailable("test", "Linux Mint 1.0", "132682398326125518");

            Assert.False(test.Connectable);
            Assert.Equal(ComputerStatus.NonWindowsOS, test.Error);
        }

        [Fact]
        public async Task ComputerAvailability_IsComputerAvailable_OldPwdLastSet_ReturnsFalse()
        {
            var processor = new ComputerAvailability();

            //Create a date 91 days ago. Our threshold for pwdlastset is 90 days
            var n = DateTime.Now.AddDays(-91) - new DateTime(1601, 01, 01, 0, 0, 0, DateTimeKind.Utc);

            var test = await processor.IsComputerAvailable("test", "Windows 10 Enterprise", n.Ticks.ToString());

            Assert.False(test.Connectable);
            Assert.Equal(ComputerStatus.OldPwd, test.Error);
        }

        [Fact]
        public async Task ComputerAvailability_IsComputerAvailable_PortClosed_ReturnsFalse()
        {
            var processor = new ComputerAvailability(_falsePortScanner);

            //Create a date 5 days ago
            var n = DateTime.Now.AddDays(-5) - new DateTime(1601, 01, 01, 0, 0, 0, DateTimeKind.Utc);

            var test = await processor.IsComputerAvailable("test", "Windows 10 Enterprise", n.Ticks.ToString());

            Assert.False(test.Connectable);
            Assert.Equal(ComputerStatus.PortNotOpen, test.Error);
        }

        [Fact]
        public async Task ComputerAvailability_IsComputerAvailable_PortOpen_ReturnsTrue()
        {
            var processor = new ComputerAvailability(_truePortScanner);

            //Create a date 5 days ago 
            var n = DateTime.Now.AddDays(-5) - new DateTime(1601, 01, 01, 0, 0, 0, DateTimeKind.Utc);

            var test = await processor.IsComputerAvailable("test", "Windows 10 Enterprise", n.Ticks.ToString());

            Assert.True(test.Connectable);
        }
    }
}