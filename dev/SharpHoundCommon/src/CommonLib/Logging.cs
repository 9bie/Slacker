#nullable enable
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib
{
    internal static class Logging
    {
        internal static readonly ILoggerProvider LogProvider = new LogProvider();
        internal static ILogger Logger { get; set; } = new NoOpLogger();

        /// <summary>
        ///     Configures logging for the common library using an ILogger interface
        /// </summary>
        /// <param name="logger">ILogger interface desired for logging</param>
        internal static void ConfigureLogging(ILogger logger)
        {
            Logger = logger;
        }
    }
    
    internal class LogProvider : ILoggerProvider
    {
        private readonly ConcurrentDictionary<string, PassThroughLogger> _loggers = new();

        public void Dispose()
        {
            _loggers.Clear();
        }

        public ILogger CreateLogger(string categoryName)
        {
            return _loggers.GetOrAdd(categoryName, name => new PassThroughLogger(name));
        }
    }
}