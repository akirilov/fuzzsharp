using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FuzzSharp
{
    class Program
    {
        private const string WinDbgPath = "windbg";

        private static string dbgArgs = ".logopen {0}-l.log;" +
                                        "g;" +
                                        ".echo;" +
                                        ".echo #############;" +
                                        ".echo # REGISTERS #;" +
                                        ".echo #############;" +
                                        ".echo;" +
                                        "r;" +
                                        ".echo;" +
                                        ".echo ###############;" +
                                        ".echo # STACK TRACE #;" +
                                        ".echo ###############;" +
                                        ".echo;" +
                                        "kP;" +
                                        ".echo;" +
                                        ".echo ###############;" +
                                        ".echo # DISASSEMBLY #;"+
                                        ".echo ###############;" +
                                        ".echo;" +
                                        "ub;" +
                                        "uu;" +
                                        ".echo;" +
                                        ".echo ################;" +
                                        ".echo # !EXPLOITABLE #;" +
                                        ".echo ################;" +
                                        ".echo;" +
                                        "!load winext\\msec.dll;" +
                                        "!exploitable;" +
                                        ".logclose;" +
                                        ".dump /ma {0}-d.dmp;" +
                                        "q";
        static void Main(string[] args)
        {
            string app = args[0];
            string templateDir = args[1];
            double factor = double.Parse(args[2]);
            int iterations = int.Parse(args[3]);
            string[] templates = Directory.EnumerateFiles(templateDir).ToArray();
            Random rand = new Random();

            for (int i = 0; i < iterations; i++)
            {
                // Get a random file and process it
                string fOriginal = templates[rand.Next(templates.Length)];
                ProcessFile(fOriginal, app, factor);
            }
        }

        private static void ProcessFile(string oFile, string app, double factor)
        {
            // Read and fuzz
            byte[] buf = File.ReadAllBytes(oFile);
            MillerFuzz(buf, factor);

            // Generate output name
            string fHash;
            using (var md5 = MD5.Create())
            {
                fHash = BitConverter.ToString(md5.ComputeHash(buf)).Replace("-", "").ToLower();
            }
            string oDir = Path.GetDirectoryName(oFile);
            string oName = Path.GetFileNameWithoutExtension(oFile);
            string ext = Path.GetExtension(oFile);
            string fName = String.Format("{0}-{1}", oName, fHash);
            string fFileNoExt = Path.Combine(oDir, fName);
            string fFile = fFileNoExt + ext;
            string fLog = fFileNoExt + "-l.log";
            string fDump = fFileNoExt + "-d.dmp";
            string dbCommandLine = String.Format(dbgArgs, fFileNoExt);

            // Write to file
            File.WriteAllBytes(fFile, buf);

            // Run
            Process proc = new Process();
            proc.StartInfo.FileName = WinDbgPath;
            proc.StartInfo.Arguments = String.Format("-c \"{2}\" \"{0}\" \"{1}\"", app, fFile, dbCommandLine);
            proc.Start();

            while (!proc.HasExited)
            {
                // Sleep for 0.1 seconds
                Thread.Sleep(100);
                // Close Popups
                EnumWindows(GetKillChildWindowProcByPid(proc.Id), IntPtr.Zero);
                // Refresh
                proc.Refresh();
            }
            //int lastChild = GetLastChild(Process.GetCurrentProcess().Id);
            //Process.GetProcessById(lastChild).Kill();
            proc.WaitForExit();

            // Search logfile for crashes
            string[] logfile = File.ReadAllLines(fLog);
            foreach (var line in logfile)
            {
                if (line.StartsWith("Exploitability Classification"))
                {
                    string exploitability = line.Split(':')[1].Trim().ToUpper();
                    string bDir = Path.Combine(oDir, exploitability);
                    string bFileNoExt = Path.Combine(bDir, fName);
                    string bFile = bFileNoExt + ext;
                    string bLog = bFileNoExt + "-l.log";
                    string bDump = bFileNoExt + "-d.dmp";

                    // Delete if not an exception
                    if (exploitability != "NOT_AN_EXCEPTION")
                    {
                        if (!Directory.Exists(bDir))
                        {
                            Directory.CreateDirectory(bDir);
                        }
                        File.Copy(fFile, bFile);
                        File.Copy(fLog, bLog);
                        File.Copy(fDump, bDump);
                    }

                    // Else move to the correct bucket
                    // TODO: do additional filtering here
                    File.Delete(fFile);
                    File.Delete(fLog);
                    File.Delete(fDump);
                }
            }
        }

        /// <summary>
        /// Returns all Child processes of the current process
        /// </summary>
        /// <param name="parentProcessId"></param>
        /// <returns></returns>
        private static int GetLastChild(int parentProcessId)
        {
            int result = -1;

            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Process WHERE ParentProcessId = " + parentProcessId);
            ManagementObjectCollection collection = searcher.Get();

            if (collection.Count > 0)
            {
                foreach (var item in collection)
                {
                    int childProcessId = (int)(UInt32)item["ProcessId"];
                    if (childProcessId != parentProcessId)
                    {
                        result = childProcessId;
                        int child = GetLastChild(childProcessId);
                        if (child > -1)
                        {
                            result = child;
                        }
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// Mutates the passed buffer with a simple Charlie Miller fuzzer
        /// </summary>
        /// <param name="buf">buffer to fuzz</param>
        /// <param name="factor">maximum % of string to change</param>
        private static void MillerFuzz(byte[] buf, double factor)
        {
            Random rand = new Random();
            int numwrites = rand.Next(Convert.ToInt32(Math.Round(buf.Length * factor)));
            for (int i = 0; i < numwrites; i++)
            {
                int pos = rand.Next(buf.Length);
                buf[pos] = Convert.ToByte(rand.Next(256));
            }
        }

        /// <summary>
        /// Return a WindowProc that only matches windows with the given pid
        /// </summary>
        /// <param name="pid">parent pid</param>
        /// <returns></returns>
        private static EnumWindowsProc GetKillChildWindowProcByPid(int pid)
        {
            // Get child processes
            int lastChild = GetLastChild(pid);

            EnumWindowsProc f = delegate(IntPtr hWnd, IntPtr lParam)
            {
                StringBuilder s = new StringBuilder(100);
                int lpdwProcessId = 0;
                GetWindowThreadProcessId(hWnd, out lpdwProcessId);
                if (lpdwProcessId == lastChild)
                {
                    GetWindowText(hWnd, s, 100);

                    // Perform Action
                    Console.WriteLine("Killed {0}: {1}", lpdwProcessId, s);
                    SendMessage(hWnd, WM_SYSCOMMAND, (IntPtr)SC_CLOSE, IntPtr.Zero);
                }
                return true;
            };

            return f;
        }

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        // These are right. Trust me. I'm a professional
        public const int WM_SYSCOMMAND = 0x0112;
        public const int SC_CLOSE = 0xF060;

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr extraData);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int GetWindowText(IntPtr hWnd, [Out, MarshalAs(UnmanagedType.LPTStr)] StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SendMessage(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);
    }
}
