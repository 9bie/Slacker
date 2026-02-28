using System.Text;
using System.Text.RegularExpressions;

namespace SharpHoundCommonLib
{
    public class CSVComputerStatus
    {
        public string ComputerName { get; set; }
        public string Task { get; set; }
        public string Status { get; set; }

        /// <summary>
        ///     Converts to CSV format for output
        /// </summary>
        /// <returns></returns>
        public string ToCsv()
        {
            return $"{StringToCsvCell(ComputerName)}, {StringToCsvCell(Task)}, {StringToCsvCell(Status)}";
        }

        /// <summary>
        ///     Helper function to escape text before encoding to CSV
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        private static string StringToCsvCell(string str)
        {
            if (str == null)
                return null;
            str = Regex.Replace(str, @"\t|\n|\r", "");
            var mustQuote = str.Contains(",") || str.Contains("\"") || str.Contains("\r") || str.Contains("\n");
            if (!mustQuote) return str;
            var sb = new StringBuilder();
            sb.Append("\"");
            foreach (var nextChar in str)
            {
                sb.Append(nextChar);
                if (nextChar == '"')
                    sb.Append("\"");
            }

            sb.Append("\"");
            return sb.ToString();
        }
    }
}