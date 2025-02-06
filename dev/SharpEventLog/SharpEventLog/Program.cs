using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace SharpEventLog
{
    class Program
    {
        static void Main(string[] args)
        {
            System.Console.WriteLine("");
            System.Console.WriteLine("Author: Uknow");
            System.Console.WriteLine("Github: https://github.com/uknowsec/SharpEventLog");
            System.Console.WriteLine("");
            
            EventLog_4624();
            EventLog_4625();
        }

        public static void EventLog_4624()
        {
            EventLog log = new EventLog("Security");
            Console.WriteLine("\r\n========== SharpEventLog -> 4624 ==========\r\n");
            var entries = log.Entries.Cast<EventLogEntry>().Where(x => x.InstanceId == 4624);
            entries.Select(x => new
            {
                x.MachineName,
                x.Site,
                x.Source,
                x.Message,
                x.TimeGenerated
            }).ToList();
            foreach (EventLogEntry log1 in entries)
            {
                string text = log1.Message;
                string ipaddress = MidStrEx(text, "	源网络地址:	", "	源端口:");
                string username = MidStrEx(text, "新登录:", "进程信息:");
                username = MidStrEx(username, "	帐户名:		", "	帐户域:		");
                DateTime Time = log1.TimeGenerated;
                if (ipaddress.Length >= 7)
                {
                    Console.WriteLine("\r\n-----------------------------------");
                    Console.WriteLine("Time: " + Time);
                    Console.WriteLine("Status: True");
                    Console.WriteLine("Username: " + username.Replace("\n", "").Replace(" ", "").Replace("\t", "").Replace("\r", ""));
                    Console.WriteLine("Remote ip: " + ipaddress.Replace("\n", "").Replace(" ", "").Replace("\t", "").Replace("\r", ""));
                }
            }
        }

        public static void EventLog_4625()
        {
            EventLog log = new EventLog("Security");
            Console.WriteLine("\r\n========== SharpEventLog -> 4625 ==========\r\n");
            var entries = log.Entries.Cast<EventLogEntry>().Where(x => x.InstanceId == 4625);
            entries.Select(x => new
            {
                x.MachineName,
                x.Site,
                x.Source,
                x.Message,
                x.TimeGenerated
            }).ToList();
            foreach (EventLogEntry log1 in entries)
            {
                string text = log1.Message;
                string ipaddress = MidStrEx(text, "	源网络地址:	", "	源端口:");
                string username = MidStrEx(text, "新登录:", "进程信息:");
                username = MidStrEx(username, "	帐户名:		", "	帐户域:		");
                DateTime Time = log1.TimeGenerated;
                if (ipaddress.Length >= 7)
                {
                    Console.WriteLine("\r\n-----------------------------------");
                    Console.WriteLine("Time: " + Time);
                    Console.WriteLine("Status: Flase");
                    Console.WriteLine("Username: " + username.Replace("\n", "").Replace(" ", "").Replace("\t", "").Replace("\r", ""));
                    Console.WriteLine("Remote ip: " + ipaddress.Replace("\n", "").Replace(" ", "").Replace("\t", "").Replace("\r", ""));
                }
            }
        }

        public static string MidStrEx(string sourse, string startstr, string endstr)
        {
            string result = string.Empty;
            int startindex, endindex;
            startindex = sourse.IndexOf(startstr);
            if (startindex == -1)
                return result;
            string tmpstr = sourse.Substring(startindex + startstr.Length);
            endindex = tmpstr.IndexOf(endstr);
            if (endindex == -1)
                return result;
            result = tmpstr.Remove(endindex);

            return result;
        }
    }
}
