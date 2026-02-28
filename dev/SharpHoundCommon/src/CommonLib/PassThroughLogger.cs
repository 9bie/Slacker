using System;
using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib
{
    /// <summary>
    /// ILogger implementation that passes log entries through to the configured ILogger and prepends an identification string
    /// </summary>
    internal class PassThroughLogger : ILogger
    {
        private readonly string _name;

        public PassThroughLogger(string name)
        {
            _name = name;
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
            Func<TState, Exception, string> formatter)
        {
            var newLog = FormatLog(formatter(state, exception), exception);
            Logging.Logger.Log(logLevel, newLog);
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return true;
        }

        public IDisposable BeginScope<TState>(TState state)
        {
            return default;
        }

        private string FormatLog(string message, Exception e)
        {
            return $"[CommonLib {_name}]{message}{(e != null ? $"\n{e}" : "")}";
        }
    }
}