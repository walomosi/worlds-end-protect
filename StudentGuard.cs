// StudentGuard.cs — World's End Protect student endpoint (headless)
// Runs as a Windows service on every student PC. Pulls the policy from the
// teacher console over HTTP, keeps the classroom software alive, kills banned
// processes, isolates freshly downloaded executables, and guards itself against
// tampering (3-replica mutual guard + ACL lockdown + integrity check).
//
// Remote policy may only drive: guarded targets, banned processes, whitelist,
// scan paths, poll interval. Self-protection (replicas, hashes, protected paths)
// is set at local install and is never overwritten by the network.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using WorldEndProtect;

namespace WorldEndProtect
{
    internal static class Log
    {
        private static readonly object Sync = new object();
        public static readonly string Dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WorldEndProtect");
        public static string LogPath = Path.Combine(Dir, "student.log");

        public static void Write(string msg)
        {
            lock (Sync)
            {
                try
                {
                    Directory.CreateDirectory(Dir);
                    if (!File.Exists(LogPath))
                        File.WriteAllBytes(LogPath, new byte[] { 0xEF, 0xBB, 0xBF });
                    File.AppendAllText(LogPath,
                        string.Format("[{0:yyyy-MM-dd HH:mm:ss}] {1}{2}", DateTime.Now, msg, Environment.NewLine),
                        Encoding.UTF8);
                }
                catch { /* logging must never break the guard */ }
            }
        }
    }

    // Pulls policy from the teacher console and reports heartbeat.
    internal static class PolicyClient
    {
        // Teacher console base URL, e.g. http://192.168.1.10:8300
        public static string TeacherUrl = "";
        public const int PollSeconds = 10;
        private const int TimeoutMs = 5000;

        // The policy the guard loop reads; swapped atomically on each successful pull.
        public static volatile GuardConfig Live;

        public static void Start()
        {
            if (string.IsNullOrEmpty(TeacherUrl))
            {
                Log.Write("Teacher URL not configured; running on local config only.");
                return;
            }
            Log.Write("Policy client started, teacher: " + TeacherUrl);
            Thread t = new Thread(() =>
            {
                while (true)
                {
                    try
                    {
                        Pull();
                        Heartbeat();
                    }
                    catch (Exception ex) { Log.Write("Policy client error: " + ex.Message); }
                    Thread.Sleep(PollSeconds * 1000);
                }
            });
            t.IsBackground = true;
            t.Start();
        }

        private static void Pull()
        {
            string url = TeacherUrl.TrimEnd('/') + "/policy";
            using (WebClient wc = NewClient())
            {
                string enc = wc.DownloadString(url).Trim();
                if (enc.Length == 0) return;
                GuardConfig remote = GuardConfig.Parse(AesBox.Decrypt(enc));
                // Remote policy drives only these fields; local self-protection stays.
                GuardConfig live = Live ?? new GuardConfig();
                live.Targets = remote.Targets;
                live.Banned = remote.Banned;
                live.Whitelist = remote.Whitelist;
                live.ScanPaths = remote.ScanPaths;
                if (remote.WatchMs >= 500 && remote.WatchMs <= 30000) live.WatchMs = remote.WatchMs;
                Live = live;
            }
        }

        private static void Heartbeat()
        {
            string url = TeacherUrl.TrimEnd('/') + "/heartbeat?host=" +
                         Uri.EscapeDataString(Environment.MachineName);
            using (WebClient wc = NewClient()) wc.DownloadString(url);
        }

        private static WebClient NewClient()
        {
            return new TimeoutWebClient(TimeoutMs) { Encoding = Encoding.UTF8 };
        }
    }

    // WebClient has no timeout; default 100s would hang the guard on a dead teacher.
    internal sealed class TimeoutWebClient : WebClient
    {
        private readonly int _ms;
        public TimeoutWebClient(int ms) { _ms = ms; }
        protected override WebRequest GetWebRequest(Uri address)
        {
            WebRequest r = base.GetWebRequest(address);
            r.Timeout = _ms;
            return r;
        }
    }

    // Isolates freshly downloaded executables so students cannot run cracked tools/viruses.
    internal static class DownloadWatch
    {
        private static readonly string[] SuspiciousExt =
            { ".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".dll" };
        private const int IntervalMs = 30000;

        public static void Start(GuardConfig cfg)
        {
            string quarantine = Path.Combine(Log.Dir, "quarantine");
            Directory.CreateDirectory(quarantine);
            Thread t = new Thread(() =>
            {
                while (true)
                {
                    try
                    {
                        GuardConfig live = PolicyClient.Live ?? cfg;
                        foreach (string dir in ResolveScanPaths(live.ScanPaths))
                        {
                            if (!Directory.Exists(dir)) continue;
                            foreach (string f in Directory.GetFiles(dir))
                            {
                                if (!IsSuspicious(f)) continue;
                                try { if (DateTime.Now - File.GetCreationTime(f) > TimeSpan.FromSeconds(IntervalMs)) continue; }
                                catch { continue; }
                                string dest = Path.Combine(quarantine,
                                    DateTime.Now.ToString("yyyyMMdd_HHmmss_") + Path.GetFileName(f));
                                try { File.Move(f, dest); Log.Write("Quarantined: " + f); }
                                catch (Exception ex) { Log.Write("Isolate failed " + f + ": " + ex.Message); }
                            }
                        }
                    }
                    catch (Exception ex) { Log.Write("Download watch error: " + ex.Message); }
                    Thread.Sleep(IntervalMs);
                }
            });
            t.IsBackground = true;
            t.Start();
        }

        private static bool IsSuspicious(string path)
        {
            string ext = Path.GetExtension(path).ToLowerInvariant();
            return Array.IndexOf(SuspiciousExt, ext) >= 0;
        }

        private static List<string> ResolveScanPaths(List<string> configured)
        {
            var list = new List<string>();
            if (configured.Count > 0) { list.AddRange(configured); return list; }
            string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] defaults = {
                Path.Combine(user, "Downloads"),
                Path.Combine(user, "Desktop"),
                Path.GetTempPath()
            };
            foreach (string d in defaults) if (Directory.Exists(d)) list.Add(d);
            return list;
        }
    }

    internal static class GuardCore
    {
        private const string BackupDir = "backup";
        private const int IntegrityIntervalMs = 300000;

        public static void ServiceLoop(GuardConfig cfg, string installDir, Func<bool> running)
        {
            Log.Write("Student guard started.");
            DownloadWatch.Start(cfg);
            DateTime nextHeavy = DateTime.MinValue;
            while (running())
            {
                try
                {
                    GuardConfig live = PolicyClient.Live ?? cfg;

                    // 1) keep classroom software alive
                    foreach (KeyValuePair<string, string> kv in live.Targets)
                    {
                        if (Process.GetProcessesByName(kv.Key).Length == 0 && File.Exists(kv.Value))
                        {
                            Log.Write("Target '" + kv.Key + "' not running, launching.");
                            try
                            {
                                Process.Start(new ProcessStartInfo(kv.Value)
                                { WorkingDirectory = Path.GetDirectoryName(kv.Value) });
                            }
                            catch (Exception ex) { Log.Write("Launch failed: " + ex.Message); }
                        }
                    }

                    // 2) kill banned processes on sight
                    foreach (string ban in live.Banned)
                    {
                        foreach (Process p in Process.GetProcessesByName(ban))
                        {
                            try { p.Kill(); Log.Write("Banned process killed: " + ban); }
                            catch (Exception ex) { Log.Write("Kill failed " + ban + ": " + ex.Message); }
                        }
                    }

                    // 3) every 5 min: lock ACL + verify own binaries
                    if (DateTime.Now >= nextHeavy)
                    {
                        nextHeavy = DateTime.Now.AddMilliseconds(IntegrityIntervalMs);
                        foreach (string p in cfg.ProtectPaths)
                        {
                            if (File.Exists(p)) LockAcl(p, false);
                            else if (Directory.Exists(p)) LockAcl(p, true);
                        }
                        VerifyIntegrity(cfg, installDir);
                    }
                }
                catch (Exception ex) { Log.Write("Guard loop error: " + ex.Message); }
                Thread.Sleep((PolicyClient.Live ?? cfg).WatchMs);
            }
        }

        public static void GuardLoop(GuardConfig cfg, string installDir, Func<bool> running)
        {
            string self = Process.GetCurrentProcess().MainModule.FileName;
            Log.Write("Replica mode: " + self);
            DateTime nextIntegrity = DateTime.MinValue;
            while (running())
            {
                try
                {
                    foreach (string guard in cfg.Guards)
                    {
                        if (string.Equals(guard, self, StringComparison.OrdinalIgnoreCase)) continue;
                        string name = Path.GetFileNameWithoutExtension(guard);
                        if (Process.GetProcessesByName(name).Length == 0 && File.Exists(guard))
                        {
                            Log.Write("Replica '" + name + "' down, restarting.");
                            try
                            {
                                Process.Start(new ProcessStartInfo(guard, "--guard")
                                {
                                    WorkingDirectory = Path.GetDirectoryName(guard),
                                    WindowStyle = ProcessWindowStyle.Hidden,
                                    CreateNoWindow = true
                                });
                            }
                            catch (Exception ex) { Log.Write("Replica start failed: " + ex.Message); }
                        }
                    }
                    if (DateTime.Now >= nextIntegrity)
                    {
                        nextIntegrity = DateTime.Now.AddMilliseconds(IntegrityIntervalMs);
                        VerifyIntegrity(cfg, installDir);
                    }
                }
                catch (Exception ex) { Log.Write("Replica loop error: " + ex.Message); }
                Thread.Sleep(cfg.WatchMs);
            }
        }

        private static void VerifyIntegrity(GuardConfig cfg, string installDir)
        {
            try
            {
                string self = Process.GetCurrentProcess().MainModule.FileName;
                string selfHash;
                if (cfg.Hashes.TryGetValue(self, out selfHash) && !Integrity.Check(self, selfHash))
                {
                    Log.Write("Self binary replaced, restoring from backup: " + self);
                    string bak = Path.Combine(installDir, BackupDir, Path.GetFileName(self) + ".bak");
                    if (File.Exists(bak))
                    {
                        File.Copy(bak, self, true);
                        Thread t = new Thread(() =>
                        {
                            Thread.Sleep(1000);
                            Process.Start(new ProcessStartInfo(self, "--guard")
                            { WindowStyle = ProcessWindowStyle.Hidden, CreateNoWindow = true });
                        });
                        t.IsBackground = true; t.Start();
                        Environment.Exit(0);
                    }
                }
            }
            catch (Exception ex) { Log.Write("Integrity check error: " + ex.Message); }
        }

        private static void LockAcl(string path, bool isDir)
        {
            try
            {
                string inherit = isDir ? "(OI)(CI)" : "";
                string args = "\"" + path + "\" /inheritance:r /grant:r \"SYSTEM:" + inherit +
                              "(M)\" \"Administrators:" + inherit + "(M)\" \"Users:R\"";
                ProcessStartInfo psi = new ProcessStartInfo("icacls.exe", args)
                { WindowStyle = ProcessWindowStyle.Hidden, CreateNoWindow = true, UseShellExecute = false };
                using (Process pr = Process.Start(psi)) { pr.WaitForExit(15000); }
            }
            catch (Exception ex) { Log.Write("ACL lock failed " + path + ": " + ex.Message); }
        }
    }

    internal sealed class GuardService : ServiceBase
    {
        private Thread _worker;
        private volatile bool _running;

        public GuardService()
        {
            ServiceName = "WEPStudent";
            CanStop = true; CanShutdown = true;
        }

        protected override void OnStart(string[] args)
        {
            _running = true;
            _worker = new Thread(() =>
            {
                string dir = AppDomain.CurrentDomain.BaseDirectory;
                GuardConfig cfg = GuardConfig.Load(dir);
                // teacher endpoint URL lives in a small side file (set at deploy)
                PolicyClient.TeacherUrl = LoadTeacherUrl(dir);
                PolicyClient.Live = cfg;
                PolicyClient.Start();
                GuardCore.ServiceLoop(cfg, dir, () => _running);
            });
            _worker.IsBackground = true;
            _worker.Start();
        }

        private static string LoadTeacherUrl(string dir)
        {
            try
            {
                string f = Path.Combine(dir, "teacher.url");
                if (File.Exists(f)) return File.ReadAllText(f).Trim();
            }
            catch { }
            return "";
        }

        protected override void OnStop()
        {
            _running = false;
            if (_worker != null) _worker.Join(3000);
        }
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            bool serviceMode = args.Length > 0 &&
                               string.Equals(args[0], "--service", StringComparison.OrdinalIgnoreCase);
            if (!serviceMode && !Environment.UserInteractive) serviceMode = true;
            if (serviceMode) { ServiceBase.Run(new ServiceBase[] { new GuardService() }); return 0; }
            if (args.Length > 0 && string.Equals(args[0], "--guard", StringComparison.OrdinalIgnoreCase))
            {
                string dir = AppDomain.CurrentDomain.BaseDirectory;
                GuardConfig cfg = GuardConfig.Load(dir);
                PolicyClient.TeacherUrl = "";
                PolicyClient.Live = cfg;
                GuardCore.GuardLoop(cfg, dir, () => true);
                return 0;
            }
            Console.WriteLine("World's End Protect - StudentGuard (headless)");
            Console.WriteLine("  Runs as a Windows service on student PCs. Deploy via TeacherConsole.");
            Console.WriteLine("  StudentGuard.exe --guard   mutual-guard replica mode");
            return 1;
        }
    }
}
