// TeacherConsole.cs — World's End Protect teacher console (WinForms, English)
// Runs on the teacher PC. Lets the teacher freely edit what classroom software
// to guard, which features/processes to ban, the AppLocker whitelist and scan
// dirs, then serves the encrypted policy to student endpoints over HTTP and shows
// which students are online.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using WorldEndProtect;

namespace WorldEndProtect
{
    // Minimal policy server: /policy -> encrypted policy text, /heartbeat?host= -> online roster.
    internal static class PolicyServer
    {
        private static HttpListener _listener;
        private static Thread _thread;
        public static readonly Dictionary<string, DateTime> Online = new Dictionary<string, DateTime>();
        public static Func<GuardConfig> Current;      // console supplies the live policy
        public static event Action OnRosterChanged;

        public static bool IsRunning { get; private set; }
        public static int Port = 8300;

        public static void Start()
        {
            if (IsRunning) return;
            _listener = new HttpListener();
            _listener.Prefixes.Add("http://+:" + Port + "/");
            _listener.Start();
            IsRunning = true;
            _thread = new Thread(Loop) { IsBackground = true };
            _thread.Start();
        }

        public static void Stop()
        {
            IsRunning = false;
            try { _listener.Stop(); _listener.Close(); } catch { }
        }

        private static void Loop()
        {
            while (IsRunning)
            {
                HttpListenerContext ctx;
                try { ctx = _listener.GetContext(); }
                catch { break; }
                try
                {
                    string path = ctx.Request.Url.AbsolutePath.TrimEnd('/');
                    if (path.Equals("/policy", StringComparison.OrdinalIgnoreCase))
                    {
                        GuardConfig cfg = Current != null ? Current() : new GuardConfig();
                        byte[] body = Encoding.UTF8.GetBytes(AesBox.Encrypt(cfg.ToText()));
                        ctx.Response.ContentType = "text/plain";
                        ctx.Response.ContentLength64 = body.Length;
                        ctx.Response.OutputStream.Write(body, 0, body.Length);
                        ctx.Response.Close();
                    }
                    else if (path.Equals("/heartbeat", StringComparison.OrdinalIgnoreCase))
                    {
                        string host = ctx.Request.QueryString["host"];
                        if (!string.IsNullOrEmpty(host))
                        {
                            lock (Online) { Online[host] = DateTime.Now; }
                            var h = OnRosterChanged; if (h != null) h();
                        }
                        ctx.Response.StatusCode = 200;
                        ctx.Response.Close();
                    }
                    else
                    {
                        ctx.Response.StatusCode = 404;
                        ctx.Response.Close();
                    }
                }
                catch { /* a single bad request must not kill the server */ }
            }
        }
    }

    public class TeacherConsoleForm : Form
    {
        private GuardConfig _cfg;
        private DataGridView _gridTargets, _gridOnline;
        private ListBox _listBanned, _listWhitelist, _listScan;
        private TextBox _txtPort, _txtStatus;
        private Button _btnStart, _btnStop;
        private System.Windows.Forms.Timer _rosterTimer;

        public TeacherConsoleForm()
        {
            Text = "World's End Protect — Teacher Console";
            Width = 960; Height = 660; StartPosition = FormStartPosition.CenterScreen;
            _cfg = GuardConfig.Load(Path.GetDirectoryName(Application.ExecutablePath));
            PolicyServer.Current = () => _cfg;
            PolicyServer.OnRosterChanged += () => { if (IsHandleCreated) BeginInvoke((Action)RefreshRoster); };
            BuildUi();
            LoadToUi();
        }

        private void BuildUi()
        {
            var tabs = new TabControl { Dock = DockStyle.Fill };

            // --- Targets: classroom software to keep alive ---
            var pTargets = new TabPage("Guarded software");
            _gridTargets = new DataGridView
            {
                Dock = DockStyle.Fill, AllowUserToAddRows = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
            };
            _gridTargets.Columns.Add("Name", "Process name (no .exe)");
            _gridTargets.Columns.Add("Path", "Full launch path");
            var tBar = new Panel { Dock = DockStyle.Bottom, Height = 40 };
            var tAdd = new Button { Text = "Add", Width = 80, Left = 8, Top = 8 };
            tAdd.Click += (s, e) => _gridTargets.Rows.Add("", "");
            var tDel = new Button { Text = "Remove selected", Width = 110, Left = 96, Top = 8 };
            tDel.Click += (s, e) => { if (_gridTargets.CurrentRow != null) _gridTargets.Rows.Remove(_gridTargets.CurrentRow); };
            tBar.Controls.AddRange(new Control[] { tAdd, tDel });
            pTargets.Controls.Add(_gridTargets);
            pTargets.Controls.Add(tBar);

            // --- Banned: features/processes students must not run ---
            var pBanned = new TabPage("Banned features");
            var bTip = new Label { Dock = DockStyle.Top, Height = 40, Padding = new Padding(8),
                Text = "List process names (no .exe) to kill on sight, e.g. cracked clients, task managers, registry editors students should not touch." };
            _listBanned = new ListBox { Dock = DockStyle.Fill };
            var bBar = new Panel { Dock = DockStyle.Bottom, Height = 40 };
            var bAdd = new Button { Text = "Add banned process", Width = 130, Left = 8, Top = 8 };
            bAdd.Click += (s, e) =>
            {
                string n = Interaction.Input("Banned process name (no .exe):", "Add banned");
                if (!string.IsNullOrWhiteSpace(n)) _listBanned.Items.Add(n.Trim());
            };
            var bDel = new Button { Text = "Remove selected", Width = 110, Left = 146, Top = 8 };
            bDel.Click += (s, e) => { if (_listBanned.SelectedIndex >= 0) _listBanned.Items.RemoveAt(_listBanned.SelectedIndex); };
            bBar.Controls.AddRange(new Control[] { bAdd, bDel });
            pBanned.Controls.Add(_listBanned);
            pBanned.Controls.Add(bBar);
            pBanned.Controls.Add(bTip);

            // --- Defense: whitelist + scan dirs ---
            var pDef = new TabPage("Defense");
            var dSplit = new SplitContainer { Dock = DockStyle.Top, Height = 260, SplitterDistance = 440 };
            _listWhitelist = new ListBox { Dock = DockStyle.Fill };
            _listScan = new ListBox { Dock = DockStyle.Fill };
            dSplit.Panel1.Controls.Add(_listWhitelist);
            dSplit.Panel2.Controls.Add(_listScan);
            var dBar = new Panel { Dock = DockStyle.Top, Height = 40 };
            var wAdd = new Button { Text = "+ whitelist dir", Width = 100, Left = 8, Top = 8 };
            wAdd.Click += (s, e) =>
            {
                var dlg = new FolderBrowserDialog { Description = "Directory allowed to run (e.g. classroom software install dir)" };
                if (dlg.ShowDialog() == DialogResult.OK) _listWhitelist.Items.Add(dlg.SelectedPath + @"\*");
            };
            var sAdd = new Button { Text = "+ scan dir", Width = 90, Left = 116, Top = 8 };
            sAdd.Click += (s, e) =>
            {
                var dlg = new FolderBrowserDialog { Description = "Download/temp dir to watch for new executables" };
                if (dlg.ShowDialog() == DialogResult.OK) _listScan.Items.Add(dlg.SelectedPath);
            };
            dBar.Controls.AddRange(new Control[] { wAdd, sAdd });
            var dTip = new Label { Dock = DockStyle.Top, Height = 44, Padding = new Padding(8),
                Text = "Whitelist = AppLocker allow paths. Scan dirs = freshly dropped .exe/.bat/.ps1 are moved to quarantine automatically." };
            pDef.Controls.Add(dSplit);
            pDef.Controls.Add(dBar);
            pDef.Controls.Add(dTip);

            // --- Online students ---
            var pOnline = new TabPage("Online students");
            _gridOnline = new DataGridView
            {
                Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
            };
            _gridOnline.Columns.Add("Host", "Student PC");
            _gridOnline.Columns.Add("LastSeen", "Last heartbeat");
            pOnline.Controls.Add(_gridOnline);

            tabs.TabPages.AddRange(new[] { pTargets, pBanned, pDef, pOnline });
            Controls.Add(tabs);

            // --- Bottom bar: port + server control + status ---
            var bar = new Panel { Dock = DockStyle.Bottom, Height = 70 };
            bar.Controls.Add(new Label { Text = "Port:", Left = 10, Top = 14, Width = 40 });
            _txtPort = new TextBox { Text = "8300", Left = 50, Top = 11, Width = 60 };
            _btnStart = new Button { Text = "Start policy server", Left = 120, Top = 9, Width = 140, Height = 28 };
            _btnStop = new Button { Text = "Stop", Left = 268, Top = 9, Width = 70, Height = 28, Enabled = false };
            var btnSave = new Button { Text = "Save policy", Left = 346, Top = 9, Width = 100, Height = 28 };
            _txtStatus = new TextBox { Left = 460, Top = 11, Width = 470, ReadOnly = true, BorderStyle = BorderStyle.FixedSingle };

            _btnStart.Click += (s, e) =>
            {
                int port;
                if (!int.TryParse(_txtPort.Text.Trim(), out port) || port < 1 || port > 65535)
                { MessageBox.Show("Invalid port."); return; }
                SaveToConfig();
                PolicyServer.Port = port;
                try { PolicyServer.Start(); }
                catch (Exception ex) { MessageBox.Show("Failed to start server (run as Administrator for http://+:):\n" + ex.Message); return; }
                _btnStart.Enabled = false; _btnStop.Enabled = true;
                _txtStatus.Text = "Serving policy on port " + port + ". Students pull every " + 10 + "s.";
            };
            _btnStop.Click += (s, e) =>
            {
                PolicyServer.Stop();
                _btnStart.Enabled = true; _btnStop.Enabled = false;
                _txtStatus.Text = "Server stopped.";
            };
            btnSave.Click += (s, e) => { SaveToConfig(); MessageBox.Show("Policy saved. It is served live while the server runs."); };
            bar.Controls.AddRange(new Control[] { _txtPort, _btnStart, _btnStop, btnSave, _txtStatus });
            Controls.Add(bar);

            _rosterTimer = new System.Windows.Forms.Timer { Interval = 5000 };
            _rosterTimer.Tick += (s, e) => RefreshRoster();
            _rosterTimer.Start();
        }

        private void LoadToUi()
        {
            _gridTargets.Rows.Clear();
            foreach (KeyValuePair<string, string> kv in _cfg.Targets) _gridTargets.Rows.Add(kv.Key, kv.Value);
            _listBanned.Items.Clear(); foreach (string b in _cfg.Banned) _listBanned.Items.Add(b);
            _listWhitelist.Items.Clear(); foreach (string w in _cfg.Whitelist) _listWhitelist.Items.Add(w);
            _listScan.Items.Clear(); foreach (string sc in _cfg.ScanPaths) _listScan.Items.Add(sc);
        }

        private void SaveToConfig()
        {
            var t = new Dictionary<string, string>();
            foreach (DataGridViewRow r in _gridTargets.Rows)
            {
                if (r.Cells[0].Value == null || r.Cells[1].Value == null) continue;
                string n = r.Cells[0].Value.ToString().Trim();
                string p = r.Cells[1].Value.ToString().Trim();
                if (n.Length > 0 && p.Length > 0) t[n] = p;
            }
            _cfg.Targets = t;
            _cfg.Banned = _listBanned.Items.Cast<string>().ToList();
            _cfg.Whitelist = _listWhitelist.Items.Cast<string>().ToList();
            _cfg.ScanPaths = _listScan.Items.Cast<string>().ToList();
            _cfg.Save(Path.GetDirectoryName(Application.ExecutablePath), false);
        }

        private void RefreshRoster()
        {
            if (!IsHandleCreated) return;
            _gridOnline.Rows.Clear();
            lock (PolicyServer.Online)
                foreach (KeyValuePair<string, DateTime> kv in PolicyServer.Online.OrderByDescending(x => x.Value))
                    _gridOnline.Rows.Add(kv.Key, kv.Value.ToString("HH:mm:ss"));
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            PolicyServer.Stop();
            base.OnFormClosing(e);
        }
    }

    // Tiny modal input helper to avoid pulling in a dialog file.
    internal static class Interaction
    {
        public static string Input(string prompt, string title)
        {
            using (var form = new Form())
            {
                form.Text = title;
                form.Width = 360; form.Height = 150;
                form.StartPosition = FormStartPosition.CenterParent;
                var lbl = new Label { Left = 12, Top = 12, Width = 320, Text = prompt };
                var txt = new TextBox { Left = 12, Top = 40, Width = 320 };
                var ok = new Button { Text = "OK", Left = 176, Top = 72, Width = 75, DialogResult = DialogResult.OK };
                var cancel = new Button { Text = "Cancel", Left = 257, Top = 72, Width = 75, DialogResult = DialogResult.Cancel };
                form.Controls.AddRange(new Control[] { lbl, txt, ok, cancel });
                form.AcceptButton = ok; form.CancelButton = cancel;
                return form.ShowDialog() == DialogResult.OK ? txt.Text.Trim() : null;
            }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new TeacherConsoleForm());
        }
    }
}
