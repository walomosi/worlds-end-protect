// PolicyCore.cs — World's End Protect shared core
// Config model + AES-256 encryption + SHA-256 integrity, shared by
// StudentGuard.exe (student endpoint) and TeacherConsole.exe (teacher console).
//
// Line-based policy format (plain text; encrypted with AES before network send):
//   <processName>=<fullPath>       guarded target (kept alive), repeatable
//   PROTECT=<path>                 write-locked path, repeatable
//   GUARDS=<exePath>               mutual-guard replica, repeatable
//   HASH=<exePath>=<sha256>        integrity baseline, repeatable
//   WHITELIST=<glob>               AppLocker extra allowed path, repeatable
//   SCANPATH=<dir>                 download/watch scan dir, repeatable
//   BAN=<processName>              banned process (killed on sight), repeatable
//   WATCH_MS=<milliseconds>        polling interval
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace WorldEndProtect
{
    internal class GuardConfig
    {
        public Dictionary<string, string> Targets = new Dictionary<string, string>();
        public List<string> ProtectPaths = new List<string>();
        public List<string> Guards = new List<string>();
        public Dictionary<string, string> Hashes = new Dictionary<string, string>();
        public List<string> Whitelist = new List<string>();
        public List<string> ScanPaths = new List<string>();
        public List<string> Banned = new List<string>();   // processes the student endpoint must kill
        public int WatchMs = 2000;

        public const string ConfigName = "config.bin";   // encrypted policy on the student machine
        public const string PlainName = "config.txt";    // plain template (editing/pre-deploy)

        public static GuardConfig Parse(string text)
        {
            GuardConfig c = new GuardConfig();
            foreach (string raw in text.Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith("//")) continue;
                if (line.StartsWith("PROTECT=", StringComparison.OrdinalIgnoreCase))
                    Add(c.ProtectPaths, line.Substring(8));
                else if (line.StartsWith("GUARDS=", StringComparison.OrdinalIgnoreCase))
                    Add(c.Guards, line.Substring(7));
                else if (line.StartsWith("WHITELIST=", StringComparison.OrdinalIgnoreCase))
                    Add(c.Whitelist, line.Substring(10));
                else if (line.StartsWith("SCANPATH=", StringComparison.OrdinalIgnoreCase))
                    Add(c.ScanPaths, line.Substring(9));
                else if (line.StartsWith("BAN=", StringComparison.OrdinalIgnoreCase))
                    Add(c.Banned, line.Substring(4));
                else if (line.StartsWith("HASH=", StringComparison.OrdinalIgnoreCase))
                {
                    int eq = line.IndexOf('=', 5);
                    if (eq > 5)
                    {
                        string p = line.Substring(5, eq - 5).Trim().Trim('"');
                        string h = line.Substring(eq + 1).Trim();
                        if (p.Length > 0 && h.Length == 64) c.Hashes[p] = h.ToLowerInvariant();
                    }
                }
                else if (line.StartsWith("WATCH_MS=", StringComparison.OrdinalIgnoreCase))
                {
                    int ms;
                    if (int.TryParse(line.Substring(9).Trim(), out ms) && ms >= 500 && ms <= 30000)
                        c.WatchMs = ms;
                }
                else
                {
                    int eq = line.IndexOf('=');
                    if (eq > 0)
                    {
                        string name = line.Substring(0, eq).Trim();
                        string path = line.Substring(eq + 1).Trim().Trim('"');
                        if (name.Length > 0 && path.Length > 0) c.Targets[name] = path;
                    }
                }
            }
            return c;
        }

        private static void Add(List<string> list, string raw)
        {
            string p = raw.Trim().Trim('"');
            if (p.Length > 0) list.Add(p);
        }

        public string ToText()
        {
            StringBuilder sb = new StringBuilder();
            foreach (KeyValuePair<string, string> kv in Targets)
                sb.AppendLine(kv.Key + "=" + kv.Value);
            foreach (string p in ProtectPaths) sb.AppendLine("PROTECT=" + p);
            foreach (string g in Guards) sb.AppendLine("GUARDS=" + g);
            foreach (string w in Whitelist) sb.AppendLine("WHITELIST=" + w);
            foreach (string s in ScanPaths) sb.AppendLine("SCANPATH=" + s);
            foreach (string b in Banned) sb.AppendLine("BAN=" + b);
            foreach (KeyValuePair<string, string> h in Hashes)
                sb.AppendLine("HASH=" + h.Key + "=" + h.Value);
            sb.AppendLine("WATCH_MS=" + WatchMs);
            return sb.ToString();
        }

        // Load: prefer encrypted config.bin, fall back to plain config.txt
        public static GuardConfig Load(string dir)
        {
            string bin = Path.Combine(dir, ConfigName);
            if (File.Exists(bin))
            {
                try { return Parse(AesBox.Decrypt(File.ReadAllText(bin).Trim())); }
                catch { /* encrypted policy corrupt: fall through to plain text for repair */ }
            }
            string txt = Path.Combine(dir, PlainName);
            if (File.Exists(txt)) return Parse(File.ReadAllText(txt));
            return new GuardConfig();
        }

        // Save; encrypt=true writes config.bin and removes the plain template
        public void Save(string dir, bool encrypt)
        {
            Directory.CreateDirectory(dir);
            if (encrypt)
            {
                File.WriteAllText(Path.Combine(dir, ConfigName), AesBox.Encrypt(ToText()));
                string plain = Path.Combine(dir, PlainName);
                if (File.Exists(plain)) File.Delete(plain);
            }
            else
            {
                File.WriteAllText(Path.Combine(dir, PlainName), ToText());
            }
        }
    }

    // AES-256-CBC. Key/IV stored as byte arrays so no plain string appears in the binary.
    internal static class AesBox
    {
        private static readonly byte[] Key = {
            0x6E, 0x2B, 0xA1, 0xC7, 0x3D, 0x0F, 0x95, 0x58,
            0x81, 0x4C, 0xE3, 0x1A, 0xB6, 0x77, 0x02, 0xDE,
            0x39, 0x64, 0x0B, 0xEF, 0x52, 0x8A, 0xCD, 0x14,
            0x70, 0xF9, 0x26, 0x43, 0x98, 0x5E, 0xB1, 0x07
        };
        private static readonly byte[] Iv = {
            0x4F, 0x12, 0x8C, 0x3A, 0xE7, 0x50, 0x9B, 0x2D,
            0xC5, 0x68, 0xF3, 0x1E, 0x84, 0x0A, 0x6D, 0xB9
        };

        public static string Encrypt(string plain)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key; aes.IV = Iv;
                aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform t = aes.CreateEncryptor())
                {
                    byte[] data = Encoding.UTF8.GetBytes(plain);
                    return Convert.ToBase64String(t.TransformFinalBlock(data, 0, data.Length));
                }
            }
        }

        public static string Decrypt(string b64)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key; aes.IV = Iv;
                aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform t = aes.CreateDecryptor())
                {
                    byte[] enc = Convert.FromBase64String(b64.Trim());
                    return Encoding.UTF8.GetString(t.TransformFinalBlock(enc, 0, enc.Length));
                }
            }
        }
    }

    internal static class Integrity
    {
        public static string Sha256File(string path)
        {
            try
            {
                using (SHA256 sha = SHA256.Create())
                using (FileStream fs = File.OpenRead(path))
                {
                    byte[] h = sha.ComputeHash(fs);
                    return BitConverter.ToString(h).Replace("-", "").ToLowerInvariant();
                }
            }
            catch { return null; }
        }

        // Missing baseline means "pass"
        public static bool Check(string path, string expectedHash)
        {
            if (string.IsNullOrEmpty(expectedHash)) return true;
            string actual = Sha256File(path);
            return actual != null && string.Equals(actual, expectedHash, StringComparison.OrdinalIgnoreCase);
        }
    }
}
