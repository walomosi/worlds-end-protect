// GuardApp.cs — 教学软件守护程序（防御侧，防止学生结束进程/改配置绕过教学管控）
// 运行模式：
//   --service  服务模式（由 SCM 启动）：守护目标进程、配置 ACL 巡检、完整性校验
//   --guard    副本模式：环形互守（GUARDS 列表内任一副本死亡，其余副本将其拉起）+ 完整性校验
// 配置：GuardConfig（config.bin 加密优先，回退 config.txt 明文）——见 GuardCrypto.cs
// 完整性：HASH 基准比对，自身 exe 被替换时从备份恢复并重启
// 用法（老师/管理员）：见 README.txt；部署用 install.cmd 或 GuardGui.exe
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace GuardKit
{
    internal static class Log
    {
        private static readonly object Sync = new object();
        public static string Path = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "GuardKit", "guard.log");

        public static void Write(string msg)
        {
            lock (Sync)
            {
                try
                {
                    string dir = System.IO.Path.GetDirectoryName(Path);
                    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                    // 首次创建写 UTF-8 BOM，保证记事本打开中文不乱码
                    if (!File.Exists(Path)) File.WriteAllBytes(Path, new byte[] { 0xEF, 0xBB, 0xBF });
                    File.AppendAllText(Path, string.Format("[{0:yyyy-MM-dd HH:mm:ss}] {1}{2}",
                        DateTime.Now, msg, Environment.NewLine), Encoding.UTF8);
                }
                catch { /* 日志失败不影响守护 */ }
            }
        }
    }

    // 恶意文件隔离监控：扫描下载/临时目录中新出现的可执行文件，移入隔离区
    internal static class DownloadWatch
    {
        private static readonly string[] SuspiciousExt =
            { ".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".dll" };
        private const int WatchIntervalMs = 30000;

        public static void Start(GuardConfig cfg)
        {
            string quarantine = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "GuardKit", "quarantine");
            Directory.CreateDirectory(quarantine);
            Log.Write("恶意文件监控启动，扫描目录: " +
                      (cfg.ScanPaths.Count > 0 ? string.Join(", ", cfg.ScanPaths) : "(默认)"));
            Thread t = new Thread(() =>
            {
                while (true)
                {
                    try
                    {
                        foreach (string dir in ResolveScanPaths(cfg.ScanPaths))
                        {
                            if (!Directory.Exists(dir)) continue;
                            foreach (string f in Directory.GetFiles(dir))
                            {
                                if (!IsSuspicious(f)) continue;
                                // 只看最近 30 秒出现的文件，避免误动旧文件
                                try
                                {
                                    if (DateTime.Now - File.GetCreationTime(f) > TimeSpan.FromSeconds(WatchIntervalMs))
                                        continue;
                                }
                                catch { continue; }
                                string dest = System.IO.Path.Combine(quarantine,
                                    DateTime.Now.ToString("yyyyMMdd_HHmmss_") + System.IO.Path.GetFileName(f));
                                try
                                {
                                    File.Move(f, dest);
                                    Log.Write("已隔离可疑文件: " + f + " -> " + dest);
                                }
                                catch (Exception ex) { Log.Write("隔离失败 " + f + ": " + ex.Message); }
                            }
                        }
                    }
                    catch (Exception ex) { Log.Write("恶意文件监控异常: " + ex.Message); }
                    Thread.Sleep(WatchIntervalMs);
                }
            });
            t.IsBackground = true;
            t.Start();
        }

        private static bool IsSuspicious(string path)
        {
            string ext = System.IO.Path.GetExtension(path).ToLowerInvariant();
            return Array.IndexOf(SuspiciousExt, ext) >= 0;
        }

        // 扫描路径：配置优先；未配置时用默认（Downloads/Desktop/Temp 存在的部分）
        private static List<string> ResolveScanPaths(List<string> configured)
        {
            var list = new List<string>();
            if (configured.Count > 0) { list.AddRange(configured); return list; }
            string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] defaults = {
                System.IO.Path.Combine(user, "Downloads"),
                System.IO.Path.Combine(user, "Desktop"),
                System.IO.Path.GetTempPath()
            };
            foreach (string d in defaults)
                if (Directory.Exists(d)) list.Add(d);
            return list;
        }
    }

    // 守护核心：服务模式与副本模式共用
    internal static class GuardCore
    {
        private const string BackupDir = "backup";   // 安装目录下，存 exe 原始副本
        private const int IntegrityIntervalMs = 300000; // 完整性/ACL 巡检间隔 5 分钟

        // 服务模式主循环：守护目标 + ACL 巡检 + 完整性
        public static void ServiceLoop(GuardConfig cfg, string installDir, Func<bool> running)
        {
            Log.Write("服务模式启动，守护目标: " +
                      (cfg.Targets.Count > 0 ? string.Join(", ", cfg.Targets.Keys) : "(无)"));
            DownloadWatch.Start(cfg);   // 恶意文件隔离监控
            DateTime nextHeavy = DateTime.MinValue;
            while (running())
            {
                try
                {
                    foreach (KeyValuePair<string, string> kv in cfg.Targets)
                    {
                        if (Process.GetProcessesByName(kv.Key).Length == 0)
                        {
                            Log.Write(string.Format("目标进程 '{0}' 不在，尝试启动: {1}", kv.Key, kv.Value));
                            if (File.Exists(kv.Value))
                            {
                                try
                                {
                                    Process.Start(new ProcessStartInfo(kv.Value)
                                    {
                                        WorkingDirectory = Path.GetDirectoryName(kv.Value)
                                    });
                                }
                                catch (Exception ex) { Log.Write("启动失败: " + ex.Message); }
                            }
                            else { Log.Write("启动路径不存在: " + kv.Value); }
                        }
                    }

                    // 每 5 分钟：ACL 收紧 + 完整性校验（防学生改权限/替换 exe）
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
                catch (Exception ex) { Log.Write("守护循环异常: " + ex.Message); }
                Thread.Sleep(cfg.WatchMs);
            }
        }

        // 副本模式主循环：环形互守（GuardKit 各副本互相拉起）+ 完整性
        public static void GuardLoop(GuardConfig cfg, string installDir, Func<bool> running)
        {
            string self = Process.GetCurrentProcess().MainModule.FileName;
            Log.Write("副本模式启动: " + self);
            DateTime nextIntegrity = DateTime.MinValue;
            while (running())
            {
                try
                {
                    foreach (string guard in cfg.Guards)
                    {
                        if (string.Equals(guard, self, StringComparison.OrdinalIgnoreCase)) continue;
                        string name = Path.GetFileNameWithoutExtension(guard);
                        if (Process.GetProcessesByName(name).Length == 0)
                        {
                            Log.Write("互守副本 '" + name + "' 不在，重新拉起: " + guard);
                            if (File.Exists(guard))
                            {
                                try
                                {
                                    Process.Start(new ProcessStartInfo(guard, "--guard")
                                    {
                                        WorkingDirectory = Path.GetDirectoryName(guard),
                                        WindowStyle = ProcessWindowStyle.Hidden,
                                        CreateNoWindow = true
                                    });
                                }
                                catch (Exception ex) { Log.Write("拉起副本失败: " + ex.Message); }
                            }
                        }
                    }
                    if (DateTime.Now >= nextIntegrity)
                    {
                        nextIntegrity = DateTime.Now.AddMilliseconds(IntegrityIntervalMs);
                        VerifyIntegrity(cfg, installDir);
                    }
                }
                catch (Exception ex) { Log.Write("副本循环异常: " + ex.Message); }
                Thread.Sleep(cfg.WatchMs);
            }
        }

        // 完整性校验：自身与目标客户端 exe 对照 HASH 基准；自身被替换则从备份恢复并重启
        private static void VerifyIntegrity(GuardConfig cfg, string installDir)
        {
            try
            {
                string self = Process.GetCurrentProcess().MainModule.FileName;
                string selfHash;
                if (cfg.Hashes.TryGetValue(self, out selfHash) && !Integrity.Check(self, selfHash))
                {
                    Log.Write("检测到自身 exe 被替换，尝试从备份恢复: " + self);
                    string bak = Path.Combine(installDir, BackupDir, Path.GetFileName(self) + ".bak");
                    if (File.Exists(bak))
                    {
                        File.Copy(bak, self, true);
                        Log.Write("已恢复自身 exe，即将重启");
                        Thread t = new Thread(() =>
                        {
                            Thread.Sleep(1000);
                            Process.Start(new ProcessStartInfo(self, "--guard")
                            { WindowStyle = ProcessWindowStyle.Hidden, CreateNoWindow = true });
                        });
                        t.IsBackground = true;
                        t.Start();
                        Environment.Exit(0);
                    }
                }
                foreach (KeyValuePair<string, string> kv in cfg.Targets)
                {
                    string expect;
                    if (cfg.Hashes.TryGetValue(kv.Value, out expect) && !Integrity.Check(kv.Value, expect))
                    {
                        Log.Write("目标客户端 exe 与基准不一致（可能被替换）: " + kv.Value);
                    }
                }
            }
            catch (Exception ex) { Log.Write("完整性校验异常: " + ex.Message); }
        }

        // icacls 收紧：仅 SYSTEM/Administrators 可写，Users 只读
        private static void LockAcl(string path, bool isDir)
        {
            try
            {
                string inherit = isDir ? "(OI)(CI)" : "";
                string args = "\"" + path + "\" /inheritance:r /grant:r \"SYSTEM:" + inherit +
                              "(M)\" \"Administrators:" + inherit + "(M)\" \"Users:R\"";
                ProcessStartInfo psi = new ProcessStartInfo("icacls.exe", args)
                {
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using (Process pr = Process.Start(psi)) { pr.WaitForExit(15000); }
            }
            catch (Exception ex) { Log.Write("ACL 收紧失败 " + path + ": " + ex.Message); }
        }
    }

    internal sealed class GuardService : ServiceBase
    {
        private Thread _worker;
        private volatile bool _running;

        public GuardService()
        {
            ServiceName = "GuardKitSvc";
            CanStop = true;
            CanShutdown = true;
        }

        protected override void OnStart(string[] args)
        {
            _running = true;
            _worker = new Thread(() =>
            {
                string dir = AppDomain.CurrentDomain.BaseDirectory;
                GuardConfig cfg = GuardConfig.Load(dir);
                Log.Write("GuardKit 服务启动");
                GuardCore.ServiceLoop(cfg, dir, () => _running);
            });
            _worker.IsBackground = true;
            _worker.Start();
        }

        protected override void OnStop()
        {
            _running = false;
            if (_worker != null) _worker.Join(3000);
            Log.Write("GuardKit 服务停止");
        }

        protected override void OnShutdown() { OnStop(); }
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            // 服务模式：显式 --service 或由 SCM 启动（UserInteractive=false）都走服务
            // 这样 sc create 的 binPath 只需 exe 路径，无需内嵌参数（sc 不解析 binPath 内参数）
            bool serviceMode = args.Length > 0 &&
                               string.Equals(args[0], "--service", StringComparison.OrdinalIgnoreCase);
            if (!serviceMode && !Environment.UserInteractive) serviceMode = true;
            if (serviceMode)
            {
                ServiceBase.Run(new ServiceBase[] { new GuardService() });
                return 0;
            }
            if (args.Length > 0 && string.Equals(args[0], "--guard", StringComparison.OrdinalIgnoreCase))
            {
                string dir = AppDomain.CurrentDomain.BaseDirectory;
                GuardConfig cfg = GuardConfig.Load(dir);
                GuardCore.GuardLoop(cfg, dir, () => true);
                return 0;
            }
            // 无参数：打印用法（避免双击误启动黑窗常驻）
            Console.WriteLine("GuardKit 守护程序用法:");
            Console.WriteLine("  由服务管理器启动（部署后自动以服务模式运行）");
            Console.WriteLine("  GuardApp.exe --guard     以副本模式运行（互守）");
            Console.WriteLine("  部署与管理请使用 GuardGui.exe 或 install.cmd");
            return 1;
        }
    }
}
