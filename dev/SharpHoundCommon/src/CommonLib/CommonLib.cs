using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib
{
    public class CommonLib
    {
        private static bool _initialized;

        /// <summary>
        /// Initializes the common library with a log and cache instance.
        /// If log/cache aren't provided, will use defaults
        /// </summary>
        /// <param name="log"></param>
        /// <param name="cache"></param>
        public static void InitializeCommonLib(ILogger log = null, Cache cache = null)
        {
            if (_initialized)
            {
                log?.LogWarning("Common Library is already initialized");
                return;
            }

            _initialized = true;
            if (log != null)
                Logging.ConfigureLogging(log);

            if (cache == null)
            {
                var newCache = Cache.CreateNewCache();
                Cache.SetCacheInstance(newCache);
            }
            else
            {
                Cache.SetCacheInstance(cache);
            }
        }

        /// <summary>
        /// Replaces the current logging instance with a new one
        /// </summary>
        /// <param name="log"></param>
        public static void ReconfigureLogging(ILogger log)
        {
            Logging.ConfigureLogging(log);
        }
    }
}