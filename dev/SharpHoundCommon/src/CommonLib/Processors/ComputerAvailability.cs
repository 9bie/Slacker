using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ComputerAvailability
    {
        private readonly ILogger _log;
        private readonly PortScanner _scanner;
        private readonly int _scanTimeout;
        private readonly bool _skipPortScan;
        private readonly int _computerExpiryDays;
        private readonly bool _skipPasswordCheck;

        public ComputerAvailability(int timeout = 500, int computerExpiryDays = 60, bool skipPortScan = false, bool skipPasswordCheck = false, ILogger log = null)
        {
            _scanner = new PortScanner();
            _scanTimeout = timeout;
            _skipPortScan = skipPortScan;
            _log = log ?? Logging.LogProvider.CreateLogger("CompAvail");
            _computerExpiryDays = computerExpiryDays;
            _skipPasswordCheck = skipPasswordCheck;
        }

        public ComputerAvailability(PortScanner scanner, int timeout = 500, int computerExpiryDays = 60, bool skipPortScan = false, bool skipPasswordCheck = false,
            ILogger log = null)
        {
            _scanner = scanner;
            _scanTimeout = timeout;
            _skipPortScan = skipPortScan;
            _log = log ?? Logging.LogProvider.CreateLogger("CompAvail");
            _computerExpiryDays = computerExpiryDays;
            _skipPasswordCheck = skipPasswordCheck;
        }

        /// <summary>
        /// Helper function to use commonlib types for IsComputerAvailable
        /// </summary>
        /// <param name="result"></param>
        /// <param name="entry"></param>
        /// <returns></returns>
        public Task<ComputerStatus> IsComputerAvailable(ResolvedSearchResult result, ISearchResultEntry entry)
        {
            var name = result.DisplayName;
            var os = entry.GetProperty(LDAPProperties.OperatingSystem);
            var pwdlastset = entry.GetProperty(LDAPProperties.PasswordLastSet);

            return IsComputerAvailable(name, os, pwdlastset);
        }

        /// <summary>
        ///     Checks if a computer is available for SharpHound enumeration using the following criteria:
        ///     The "operatingsystem" LDAP attribute must contain the string "Windows"
        ///     The "pwdlastset" LDAP attribute must be within 60 days of the current date by default.
        ///     Port 445 must be open to allow API calls to succeed
        /// </summary>
        /// <param name="computerName">The computer to check availability for</param>
        /// <param name="operatingSystem">The LDAP operatingsystem attribute value</param>
        /// <param name="pwdLastSet">The LDAP pwdlastset attribute value</param>
        /// <returns>A <cref>ComputerStatus</cref> object that represents the availability of the computer</returns>
        public async Task<ComputerStatus> IsComputerAvailable(string computerName, string operatingSystem,
            string pwdLastSet)
        {
            if (operatingSystem != null && !operatingSystem.StartsWith("Windows", StringComparison.OrdinalIgnoreCase))
            {
                _log.LogDebug("{ComputerName} is not available because operating system {OperatingSystem} is not valid", computerName, operatingSystem);
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = ComputerStatus.NonWindowsOS
                };
            }

            if (!_skipPasswordCheck)
            {
                var passwordLastSet = Helpers.ConvertLdapTimeToLong(pwdLastSet);
                var threshold = DateTime.Now.AddDays(_computerExpiryDays * -1).ToFileTimeUtc();

                if (passwordLastSet < threshold)
                {
                    _log.LogDebug("{ComputerName} is not available because password last set {PwdLastSet} is out of range",
                        computerName, passwordLastSet);
                    return new ComputerStatus
                    {
                        Connectable = false,
                        Error = ComputerStatus.OldPwd
                    };
                }
            }

            if (_skipPortScan)
                return new ComputerStatus
                {
                    Connectable = true,
                    Error = null
                };


            if (!await _scanner.CheckPort(computerName, timeout: _scanTimeout))
            {
                _log.LogDebug("{ComputerName} is not available because port 445 is unavailable", computerName);
                return new ComputerStatus
                {
                    Connectable = false,
                    Error = ComputerStatus.PortNotOpen
                };
            }


            return new ComputerStatus
            {
                Connectable = true,
                Error = null
            };
        }
    }
}