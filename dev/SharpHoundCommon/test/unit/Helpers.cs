using System;
using System.Runtime.InteropServices;
using System.Text;
using Xunit;

namespace CommonLibTest
{
    public class Helpers
    {
        internal static byte[] B64ToBytes(string base64)
        {
            return Convert.FromBase64String(base64);
        }

        internal static string B64ToString(string base64)
        {
            var b = B64ToBytes(base64);
            return Encoding.UTF8.GetString(b);
        }
    }

    public sealed class WindowsOnlyFact : FactAttribute
    {
        public WindowsOnlyFact()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) Skip = "Ignore on non-Windows platforms";
        }
    }
}