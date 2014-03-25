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

        private static string dbgArgs = ".logopen {0}.log;" +
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
                                        ".dump /ma {0}.dmp;" +
                                        "q";
        static void Main(string[] args)
        {
            string app = args[0];
            string templateDir = args[1];
            double factor = double.Parse(args[2]);

            foreach (string fOriginal in Directory.EnumerateFiles(templateDir))
            {
                ProcessFile(fOriginal, app, factor);
            }
        }

        private static void ProcessFile(string fOriginal, string app, double factor)
        {
            // Read and fuzz
            byte[] buf = File.ReadAllBytes(fOriginal);
            MillerFuzz(buf, factor);

            // Generate output name
            string fHash;
            using (var md5 = MD5.Create())
            {
                fHash = BitConverter.ToString(md5.ComputeHash(buf)).Replace("-", "").ToLower();
            }
            string fDir = Path.GetDirectoryName(fOriginal);
            string fName = Path.GetFileNameWithoutExtension(fOriginal);
            string fExt = Path.GetExtension(fOriginal);
            string fNameFuzzed = String.Format("{0}-{1}", fName, fHash);
            string fFuzzedNoExt = Path.Combine(fDir, fNameFuzzed);
            string fFuzzed = fFuzzedNoExt + fExt;
            string fLog = fFuzzedNoExt + ".log";
            string fDump = fFuzzedNoExt + ".dmp";
            string dbCommandLine = String.Format(dbgArgs, fFuzzedNoExt);

            // Write to file
            File.WriteAllBytes(fFuzzed, buf);

            // Run
            Process proc = new Process();
            proc.StartInfo.FileName = WinDbgPath;
            proc.StartInfo.Arguments = String.Format("-c \"{2}\" \"{0}\" \"{1}\"", app, fFuzzed, dbCommandLine);
            proc.Start();
            Thread.Sleep(1000);

            // Close Popups
            EnumWindows(GetKillChildWindowProcByPid(proc.Id), IntPtr.Zero);
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
                    string fBucketDir = Path.Combine(fDir, exploitability);

                    // Delete if not an exception
                    if (exploitability != "NOT_AN_EXCEPTION")
                    {
                        if (!Directory.Exists(fBucketDir))
                        {
                            Directory.CreateDirectory(fBucketDir);
                        }
                        File.Copy(fFuzzed, Path.Combine(fBucketDir, fNameFuzzed + fExt));
                        File.Copy(fLog, Path.Combine(fBucketDir, fNameFuzzed + ".log"));
                        File.Copy(fDump, Path.Combine(fBucketDir, fNameFuzzed + ".dmp"));
                    }

                    // Else move to the correct bucket
                    // TODO: do additional filtering here
                    File.Delete(fFuzzed);
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
