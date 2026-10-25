// GuardGui.cs — GuardKit 管理控制台（WinForms 图形界面）
// 功能：服务/副本状态查看、守护目标增删改（加密配置）、日志 tail、一键部署/启停/卸载
// 权限：管理员可全部操作；非管理员只读查看（写操作禁用）
// 依赖：GuardCrypto.cs（配置编解码与加密）
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Windows.Forms;
using Microsoft.Win32;

namespace GuardKit
{
    internal static class Deploy
    {
        // 安装目录与三副本文件名
        public const string InstallDir = @"C:\Program Files\GuardKit";
        public static readonly string[] ReplicaNames = { "GuardKitA.exe", "GuardKitB.exe", "GuardKitC.exe" };
        public const string ServiceName = "GuardKitSvc";
        private const string TaskName = "GuardKitWatch";
        private const string RunValue = "GuardKitWatch";

        public static bool IsAdmin()
        {
            try
            {
                WindowsIdentity id = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        public static void RunExe(string exe, string args)
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args)
            {
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using (Process p = Process.Start(psi)) { p.WaitForExit(20000); }
        }

        // 一键部署：三副本 + 备份 + 加密配置 + 服务 + 计划任务 + Run 键 + 崩溃自启
        public static string Install(GuardConfig cfg)
        {
            if (!IsAdmin()) return "需要管理员权限";
            try
            {
                Directory.CreateDirectory(InstallDir);
                string srcExe = Process.GetCurrentProcess().MainModule.FileName; // GuardGui 所在目录
                string srcDir = Path.GetDirectoryName(srcExe);
                string appExe = Path.Combine(srcDir, "GuardApp.exe");
                if (!File.Exists(appExe)) return "找不到 GuardApp.exe（请先 build.cmd 编译）";

                // 1) 三副本 + 备份
                foreach (string name in ReplicaNames)
                {
                    File.Copy(appExe, Path.Combine(InstallDir, name), true);
                    File.Copy(Path.Combine(InstallDir, name),
                              Path.Combine(InstallDir, "backup", name + ".bak"), true);
                }

                // 2) 配置：目标 + 副本列表 + 完整性基准，加密写入
                cfg.Guards = ReplicaNames
                    .Select(n => Path.Combine(InstallDir, n)).ToList();
                cfg.Hashes.Clear();
                foreach (string g in cfg.Guards)
                    cfg.Hashes[g] = Integrity.Sha256File(g);
                foreach (KeyValuePair<string, string> kv in cfg.Targets)
                    if (File.Exists(kv.Value))
                        cfg.Hashes[kv.Value] = Integrity.Sha256File(kv.Value);
                cfg.Save(InstallDir, true);

                // 3) 服务：指向第一个副本（无参数——程序自动检测 SCM 启动进入服务模式，
                //    sc 的 binPath 不支持内嵌参数，这是最稳的注册方式）
                string binPath = "\"" + Path.Combine(InstallDir, ReplicaNames[0]) + "\"";
                RunExe("sc.exe", "stop " + ServiceName);
                RunExe("sc.exe", "delete " + ServiceName);
                RunExe("sc.exe", "create " + ServiceName + " binPath= " + binPath +
                       " start= auto DisplayName= \"GuardKit 教学软件守护\"");
                RunExe("sc.exe", "failure " + ServiceName +
                       " reset= 0 actions= restart/5000/restart/5000/restart/5000");
                RunExe("sc.exe", "start " + ServiceName);

                // 4) 计划任务：每分钟检查服务，未运行则启动（SYSTEM 权限，学生无权删除）
                string taskCmd = "schtasks.exe /create /tn " + TaskName +
                                 " /sc MINUTE /mo 1 /ru SYSTEM /rl HIGHEST /f /tr \"" +
                                 "cmd /c sc query " + ServiceName + "|findstr /i RUNNING||sc start " +
                                 ServiceName + "\"";
                RunExe("cmd.exe", "/c " + taskCmd);

                // 5) 开机自启 Run 键（HKLM，管理员写入）：启动一个副本参与互守
                using (RegistryKey rk = Registry.LocalMachine.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (rk != null)
                        rk.SetValue(RunValue, "\"" + Path.Combine(InstallDir, ReplicaNames[1]) + "\" --guard");
                }
                return "部署完成：3 副本互守 + 服务 + 计划任务 + 开机自启 + 配置加密";
            }
            catch (Exception ex) { return "部署失败: " + ex.Message; }
        }

        public static string Uninstall()
        {
            if (!IsAdmin()) return "需要管理员权限";
            try
            {
                RunExe("sc.exe", "stop " + ServiceName);
                RunExe("sc.exe", "delete " + ServiceName);
                RunExe("schtasks.exe", "/delete /tn " + TaskName + " /f");
                using (RegistryKey rk = Registry.LocalMachine.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (rk != null) rk.DeleteValue(RunValue, false);
                }
                return "已卸载服务/计划任务/自启项（安装目录保留，可手动删除）";
            }
            catch (Exception ex) { return "卸载失败: " + ex.Message; }
        }

        // 服务运行状态：空串=未安装，否则为状态词
        public static string ServiceState()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("sc.exe", "query " + ServiceName)
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using (Process p = Process.Start(psi))
                {
                    string o = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(5000);
                    foreach (string line in o.Split('\n'))
                        if (line.Contains("STATE"))
                            return line.Trim();
                }
            }
            catch { }
            return "未安装";
        }

        // 副本存活数
        public static int ReplicasAlive()
        {
            int n = 0;
            foreach (string r in ReplicaNames)
                n += Process.GetProcessesByName(Path.GetFileNameWithoutExtension(r)).Length;
            return n;
        }
    }

    public class GuardGuiForm : Form
    {
        private Label _lblService, _lblReplicas, _lblAdmin;
        private DataGridView _gridTargets;
        private ListBox _listProtect;
        private TextBox _txtLog;
        private Timer _timer;
        private Button _btnAdd, _btnRemove, _btnSave, _btnDeploy, _btnStart, _btnStop, _btnUninstall;
        private GuardConfig _cfg;
        private readonly bool _admin;

        public GuardGuiForm()
        {
            Text = "GuardKit 管理控制台";
            Width = 920; Height = 640; StartPosition = FormStartPosition.CenterScreen;
            _admin = Deploy.IsAdmin();
            _cfg = GuardConfig.Load(Path.GetDirectoryName(Application.ExecutablePath));

            BuildUi();
            RefreshStatus();
        }

        private void BuildUi()
        {
            var tabs = new TabControl { Dock = DockStyle.Fill };
            // --- 状态页 ---
            var pageStatus = new TabPage("状态");
            _gridTargets = new DataGridView
            {
                Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect
            };
            _gridTargets.Columns.Add("Name", "进程名");
            _gridTargets.Columns.Add("Path", "路径");
            _gridTargets.Columns.Add("Alive", "运行状态");
            pageStatus.Controls.Add(_gridTargets);

            // --- 守护目标页 ---
            var pageEdit = new TabPage("守护目标");
            var editTop = new Label { Dock = DockStyle.Top, Height = 60, Padding = new Padding(8) };
            editTop.Text = _admin
                ? "配置教学软件客户端：进程名（不含 .exe）= 完整路径。保护路径限 SYSTEM/管理员可写。\n保存后写入加密配置并重启服务。"
                : "当前非管理员：只读查看。请以管理员身份运行以修改配置。";
            editTop.Font = new Font(editTop.Font, FontStyle.Regular);
            _gridTargets2 = new DataGridView
            {
                Dock = DockStyle.Fill, AllowUserToAddRows = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
            };
            _gridTargets2.Columns.Add("Name", "进程名（不含 .exe）");
            _gridTargets2.Columns.Add("Path", "完整启动路径");
            var bottom = new Panel { Dock = DockStyle.Bottom, Height = 120 };
            _listProtect = new ListBox { Dock = DockStyle.Fill };
            var protectPanel = new Panel { Dock = DockStyle.Fill };
            protectPanel.Controls.Add(_listProtect);
            var editSplit = new SplitContainer { Dock = DockStyle.Top, Height = 260, SplitterDistance = 420 };
            editSplit.Panel1.Controls.Add(_gridTargets2);
            editSplit.Panel2.Controls.Add(protectPanel);
            pageEdit.Controls.Add(editSplit);
            pageEdit.Controls.Add(bottom);

            _btnAdd = new Button { Text = "添加目标", Width = 90 };
            _btnAdd.Click += (s, e) =>
            {
                _gridTargets2.Rows.Add("", "");
                RefreshTargetGrid();
            };
            _btnRemove = new Button { Text = "删除选中", Width = 90, Left = 100 };
            _btnRemove.Click += (s, e) =>
            {
                if (_gridTargets2.CurrentRow != null) _gridTargets2.Rows.Remove(_gridTargets2.CurrentRow);
            };
            _btnSave = new Button { Text = "保存配置并重启服务", Width = 160, Left = 200 };
            _btnSave.Click += (s, e) => SaveAndApply();
            var protectAdd = new Button { Text = "+ 保护路径", Width = 90, Left = 380 };
            protectAdd.Click += (s, e) =>
            {
                var dlg = new OpenFileDialog { Filter = "文件|*.*" };
                if (dlg.ShowDialog() == DialogResult.OK)
                {
                    _listProtect.Items.Add(dlg.FileName);
                }
            };
            var protectDel = new Button { Text = "删选中路径", Width = 90, Left = 480 };
            protectDel.Click += (s, e) =>
            {
                if (_listProtect.SelectedIndex >= 0) _listProtect.Items.RemoveAt(_listProtect.SelectedIndex);
            };
            var protectFolder = new Button { Text = "+ 保护目录", Width = 90, Left = 580 };
            protectFolder.Click += (s, e) =>
            {
                var dlg = new FolderBrowserDialog { Description = "选择要收紧写权限的配置目录" };
                if (dlg.ShowDialog() == DialogResult.OK)
                {
                    _listProtect.Items.Add(dlg.SelectedPath);
                }
            };
            bottom.Controls.AddRange(new Control[] { _btnAdd, _btnRemove, _btnSave,
                protectAdd, protectDel, protectFolder });
            pageEdit.Controls.Add(editTop);

            // --- 防线页（应用白名单 + 下载扫描） ---
            var pageDefense = new TabPage("恶意程序防线");
            var defenseTip = new Label { Dock = DockStyle.Top, Height = 44, Padding = new Padding(8) };
            defenseTip.Text = "应用白名单（AppLocker）：只允许白名单程序运行，学生下载的病毒/破解工具 exe 无法启动。\n" +
                              "下载扫描：新出现的可执行文件（exe/msi/scr/bat 等）自动移入隔离区。";
            var defenseSplit = new SplitContainer { Dock = DockStyle.Top, Height = 240, SplitterDistance = 420 };
            _listWhitelist = new ListBox { Dock = DockStyle.Fill };
            _listScan = new ListBox { Dock = DockStyle.Fill };
            defenseSplit.Panel1.Controls.Add(_listWhitelist);
            defenseSplit.Panel2.Controls.Add(_listScan);
            var defenseBar = new Panel { Dock = DockStyle.Top, Height = 92 };
            var wlAdd = new Button { Text = "+ 白名单路径", Width = 100 };
            wlAdd.Click += (s, e) =>
            {
                var dlg = new FolderBrowserDialog { Description = "选择允许运行的目录（如教学软件安装目录）" };
                if (dlg.ShowDialog() == DialogResult.OK)
                {
                    _listWhitelist.Items.Add(dlg.SelectedPath + @"\*");
                    _cfg.Whitelist = _listWhitelist.Items.Cast<string>().ToList();
                }
            };
            var wlDel = new Button { Text = "删选中", Width = 70, Left = 110 };
            wlDel.Click += (s, e) =>
            {
                if (_listWhitelist.SelectedIndex >= 0) _listWhitelist.Items.RemoveAt(_listWhitelist.SelectedIndex);
                _cfg.Whitelist = _listWhitelist.Items.Cast<string>().ToList();
            };
            var scanAdd = new Button { Text = "+ 扫描目录", Width = 90, Left = 200 };
            scanAdd.Click += (s, e) =>
            {
                var dlg = new FolderBrowserDialog { Description = "选择要监控的下载/临时目录" };
                if (dlg.ShowDialog() == DialogResult.OK)
                {
                    _listScan.Items.Add(dlg.SelectedPath);
                    _cfg.ScanPaths = _listScan.Items.Cast<string>().ToList();
                }
            };
            var scanDel = new Button { Text = "删选中", Width = 70, Left = 300 };
            scanDel.Click += (s, e) =>
            {
                if (_listScan.SelectedIndex >= 0) _listScan.Items.RemoveAt(_listScan.SelectedIndex);
                _cfg.ScanPaths = _listScan.Items.Cast<string>().ToList();
            };
            var btnGen = new Button { Text = "生成策略(预览)", Width = 110, Left = 400 };
            btnGen.Click += (s, e) => RunAppLocker(false);
            var btnApply = new Button { Text = "应用白名单", Width = 100, Left = 520, BackColor = Color.MistyRose };
            btnApply.Click += (s, e) =>
            {
                if (MessageBox.Show("应用后未列入白名单的程序将全部无法运行（含学生下载的 exe）。确认应用？",
                        "应用 AppLocker 白名单", MessageBoxButtons.YesNo) == DialogResult.Yes)
                {
                    RunAppLocker(true);
                }
            };
            defenseBar.Controls.AddRange(new Control[] { wlAdd, wlDel, scanAdd, scanDel, btnGen, btnApply });
            pageDefense.Controls.Add(defenseSplit);
            pageDefense.Controls.Add(defenseBar);
            pageDefense.Controls.Add(defenseTip);

            // --- 日志页 ---
            var pageLog = new TabPage("日志");
            _txtLog = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
                ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 9) };
            pageLog.Controls.Add(_txtLog);

            tabs.TabPages.AddRange(new TabPage[] { pageStatus, pageEdit, pageDefense, pageLog });
            Controls.Add(tabs);

            // --- 底部操作条 ---
            var bar = new Panel { Dock = DockStyle.Bottom, Height = 44 };
            _lblService = new Label { AutoSize = true, Left = 10, Top = 14 };
            _lblReplicas = new Label { AutoSize = true, Left = 260, Top = 14 };
            _lblAdmin = new Label { AutoSize = true, Left = 460, Top = 14,
                ForeColor = _admin ? Color.ForestGreen : Color.Firebrick };
            _btnDeploy = new Button { Text = "一键部署", Width = 90, Left = 650, Top = 8 };
            _btnStart = new Button { Text = "启动服务", Width = 80, Left = 748, Top = 8 };
            _btnStop = new Button { Text = "停止服务", Width = 80, Left = 836, Top = 8 };
            _btnUninstall = new Button { Text = "卸载", Width = 60, Left = 924 - 60 - 10, Top = 8 };
            _btnDeploy.Click += (s, e) => { MessageBox.Show(Deploy.Install(_cfg)); RefreshStatus(); };
            _btnStart.Click += (s, e) => { Deploy.RunExe("sc.exe", "start " + Deploy.ServiceName); RefreshStatus(); };
            _btnStop.Click += (s, e) => { Deploy.RunExe("sc.exe", "stop " + Deploy.ServiceName); RefreshStatus(); };
            _btnUninstall.Click += (s, e) =>
            {
                if (MessageBox.Show("确认卸载 GuardKit 服务/计划任务/自启项？", "卸载",
                        MessageBoxButtons.YesNo) == DialogResult.Yes)
                {
                    MessageBox.Show(Deploy.Uninstall()); RefreshStatus();
                }
            };
            bar.Controls.AddRange(new Control[] { _lblService, _lblReplicas, _lblAdmin,
                _btnDeploy, _btnStart, _btnStop, _btnUninstall });
            Controls.Add(bar);

            if (!_admin)
            {
                _btnAdd.Enabled = _btnRemove.Enabled = _btnSave.Enabled =
                _btnDeploy.Enabled = _btnStart.Enabled = _btnStop.Enabled =
                _btnUninstall.Enabled = false;
                protectAdd.Enabled = protectDel.Enabled = protectFolder.Enabled = false;
                _gridTargets2.ReadOnly = true;
            }

            // 定时刷新（状态 + 日志）
            _timer = new Timer { Interval = 2000 };
            _timer.Tick += (s, e) => { RefreshStatus(); RefreshLog(); };
            _timer.Start();
            LoadConfigToUi();
        }

        private DataGridView _gridTargets2;
        private ListBox _listWhitelist, _listScan;

        private void LoadConfigToUi()
        {
            _gridTargets2.Rows.Clear();
            foreach (KeyValuePair<string, string> kv in _cfg.Targets)
                _gridTargets2.Rows.Add(kv.Key, kv.Value);
            _listProtect.Items.Clear();
            foreach (string p in _cfg.ProtectPaths) _listProtect.Items.Add(p);
            _listWhitelist.Items.Clear();
            foreach (string w in _cfg.Whitelist) _listWhitelist.Items.Add(w);
            _listScan.Items.Clear();
            foreach (string s in _cfg.ScanPaths) _listScan.Items.Add(s);
        }

        // 调用 AppLocker 策略脚本：预览（默认）或应用（-Apply，管理员）
        private void RunAppLocker(bool apply)
        {
            try
            {
                if (apply && !_admin) { MessageBox.Show("需要管理员权限"); return; }
                string srcDir = Path.GetDirectoryName(Application.ExecutablePath);
                string script = Path.Combine(srcDir, "..", "scripts", "gen_applocker.ps1");
                if (!File.Exists(script))
                {
                    // 部署后 scripts 在安装目录外，尝试常见相对位置
                    script = Path.Combine(srcDir, "gen_applocker.ps1");
                }
                if (!File.Exists(script)) { MessageBox.Show("找不到 gen_applocker.ps1（应与工程 scripts 目录一起分发）"); return; }

                string cfgPath = Path.Combine(srcDir, "config.txt");
                string args = string.Format("-ExecutionPolicy Bypass -File \"{0}\" -ConfigPath \"{1}\"{2}",
                    script, cfgPath, apply ? " -Apply" : "");
                ProcessStartInfo psi = new ProcessStartInfo("powershell.exe", args)
                {
                    WindowStyle = apply ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal,
                    CreateNoWindow = apply,
                    UseShellExecute = false,
                    RedirectStandardOutput = apply,
                    RedirectStandardError = apply
                };
                using (Process p = Process.Start(psi))
                {
                    if (apply)
                    {
                        string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                        p.WaitForExit(30000);
                        MessageBox.Show("应用结果：\n" + (o.Trim().Length > 0 ? o.Trim() : "(无输出，请查日志)"));
                    }
                    else { p.WaitForExit(10000); }
                }
            }
            catch (Exception ex) { MessageBox.Show("调用策略脚本失败: " + ex.Message); }
        }

        private void RefreshTargetGrid()
        {
            _gridTargets.Rows.Clear();
            foreach (KeyValuePair<string, string> kv in _cfg.Targets)
            {
                bool alive = Process.GetProcessesByName(kv.Key).Length > 0;
                _gridTargets.Rows.Add(kv.Key, kv.Value, alive ? "运行中" : "未运行");
            }
        }

        private void SaveAndApply()
        {
            if (!_admin) return;
            var t = new Dictionary<string, string>();
            foreach (DataGridViewRow r in _gridTargets2.Rows)
            {
                if (r.Cells[0].Value == null || r.Cells[1].Value == null) continue;
                string name = r.Cells[0].Value.ToString().Trim();
                string path = r.Cells[1].Value.ToString().Trim();
                if (name.Length > 0 && path.Length > 0) t[name] = path;
            }
            _cfg.Targets = t;
            _cfg.ProtectPaths = _listProtect.Items.Cast<string>().ToList();
            try
            {
                // 编辑期写入明文（部署后加密锁定）；随后重启服务加载
                _cfg.Save(Path.GetDirectoryName(Application.ExecutablePath), false);
                Deploy.RunExe("sc.exe", "stop " + Deploy.ServiceName);
                Deploy.RunExe("sc.exe", "start " + Deploy.ServiceName);
                MessageBox.Show("配置已保存，服务已重启。\n注意：一键部署后配置转为加密 config.bin。");
                RefreshStatus();
            }
            catch (Exception ex) { MessageBox.Show("保存失败: " + ex.Message); }
        }

        private void RefreshStatus()
        {
            _lblService.Text = "服务: " + Deploy.ServiceState();
            _lblReplicas.Text = "副本存活: " + Deploy.ReplicasAlive() + "/3";
            _lblAdmin.Text = _admin ? "管理员" : "非管理员（只读）";
            RefreshTargetGrid();
        }

        private void RefreshLog()
        {
            string logPath = Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData), "GuardKit", "guard.log");
            if (!File.Exists(logPath)) return;
            try
            {
                using (FileStream fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    fs.Seek(-Math.Min(6000, fs.Length), SeekOrigin.End);
                    using (StreamReader rd = new StreamReader(fs))
                    {
                        string text = rd.ReadToEnd();
                        if (text != _txtLog.Text) _txtLog.Text = text;
                    }
                }
            }
            catch { }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new GuardGuiForm());
        }
    }
}
