using System;
using Microsoft.Extensions.Logging;
using Xunit.Abstractions;

namespace CommonLibTest
{
    public class TestLogger : ILogger
    {
        private readonly LogLevel _level;
        private readonly ITestOutputHelper _output;

        public TestLogger(ITestOutputHelper output, LogLevel level)
        {
            _output = output;
            _level = level;
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
            Func<TState, Exception, string> formatter)
        {
            if (IsEnabled(logLevel))
                _output.WriteLine(formatter(state, exception));
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return logLevel >= _level;
        }

        public IDisposable BeginScope<TState>(TState state)
        {
            return default;
        }
    }
}