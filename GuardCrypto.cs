// GuardCrypto.cs — GuardKit 共享模块：配置编解码 + AES-256 加密 + SHA256 完整性
// 被 GuardApp.exe 与 GuardGui.exe 共同编译引用。
// 设计目标：学生篡改/读取配置需要逆向 exe 提取密钥，无法"短时破解"。
// 说明：密钥硬编码于 exe 内（自用场景下已足够；如需防专业逆向需驱动级方案，超出本工具范围）。
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace GuardKit
{
    // 行式配置模型：
    //   <进程名>=<完整路径>          守护目标（可多行）
    //   PROTECT=<路径>               配置保护路径（可多行）
    //   GUARDS=<守护副本exe路径>      互守副本列表（可多行）
    //   HASH=<exe路径>=<sha256>      完整性基准（可多行）
    //   WHITELIST=<路径通配>          应用白名单额外允许路径（可多行，AppLocker 用）
    //   SCANPATH=<目录>               下载监控扫描目录（可多行，默认 Downloads/Desktop/Temp）
    //   WATCH_MS=<毫秒>               巡检间隔
    internal class GuardConfig
    {
        public Dictionary<string, string> Targets = new Dictionary<string, string>();
        public List<string> ProtectPaths = new List<string>();
        public List<string> Guards = new List<string>();
        public Dictionary<string, string> Hashes = new Dictionary<string, string>();
        public List<string> Whitelist = new List<string>();   // AppLocker 白名单额外路径
        public List<string> ScanPaths = new List<string>();   // 恶意文件扫描目录
        public int WatchMs = 2000;

        public const string ConfigName = "config.bin";   // 加密配置（部署后）
        public const string PlainName = "config.txt";    // 明文模板（编辑/部署前）

        // 从明文文本解析
        public static GuardConfig Parse(string text)
        {
            GuardConfig c = new GuardConfig();
            foreach (string raw in text.Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith("//")) continue;
                if (line.StartsWith("PROTECT=", StringComparison.OrdinalIgnoreCase))
                {
                    string p = line.Substring(8).Trim().Trim('"');
                    if (p.Length > 0) c.ProtectPaths.Add(p);
                }
                else if (line.StartsWith("GUARDS=", StringComparison.OrdinalIgnoreCase))
                {
                    string p = line.Substring(7).Trim().Trim('"');
                    if (p.Length > 0) c.Guards.Add(p);
                }
                else if (line.StartsWith("WHITELIST=", StringComparison.OrdinalIgnoreCase))
                {
                    string p = line.Substring(10).Trim().Trim('"');
                    if (p.Length > 0) c.Whitelist.Add(p);
                }
                else if (line.StartsWith("SCANPATH=", StringComparison.OrdinalIgnoreCase))
                {
                    string p = line.Substring(9).Trim().Trim('"');
                    if (p.Length > 0) c.ScanPaths.Add(p);
                }
                else if (line.StartsWith("HASH=", StringComparison.OrdinalIgnoreCase))
                {
                    // HASH=<exe路径>=<sha256>
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

        // 序列化为明文文本（模板/备份用）
        public string ToText()
        {
            StringBuilder sb = new StringBuilder();
            foreach (KeyValuePair<string, string> kv in Targets)
                sb.AppendLine(kv.Key + "=" + kv.Value);
            foreach (string p in ProtectPaths)
                sb.AppendLine("PROTECT=" + p);
            foreach (string g in Guards)
                sb.AppendLine("GUARDS=" + g);
            foreach (string w in Whitelist)
                sb.AppendLine("WHITELIST=" + w);
            foreach (string s in ScanPaths)
                sb.AppendLine("SCANPATH=" + s);
            foreach (KeyValuePair<string, string> h in Hashes)
                sb.AppendLine("HASH=" + h.Key + "=" + h.Value);
            sb.AppendLine("WATCH_MS=" + WatchMs);
            return sb.ToString();
        }

        // 加载：优先加密 config.bin，无则回退明文 config.txt
        public static GuardConfig Load(string dir)
        {
            string bin = Path.Combine(dir, ConfigName);
            if (File.Exists(bin))
            {
                try
                {
                    string plain = AesBox.Decrypt(File.ReadAllText(bin).Trim());
                    return Parse(plain);
                }
                catch { /* 加密配置损坏时回退明文，便于 GUI 修复 */ }
            }
            string txt = Path.Combine(dir, PlainName);
            if (File.Exists(txt)) return Parse(File.ReadAllText(txt));
            return new GuardConfig();
        }

        // 保存：encrypt=true 写 config.bin（并清理明文）；false 写 config.txt
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

    // AES-256-CBC 加解密。密钥/IV 以字节数组硬编码，避免明文字符串出现在二进制里。
    internal static class AesBox
    {
        // 固定密钥（256 位）与 IV（128 位）——自用部署场景足够；如需对抗专业逆向请用驱动级方案
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
                aes.Key = Key;
                aes.IV = Iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform t = aes.CreateEncryptor())
                {
                    byte[] data = Encoding.UTF8.GetBytes(plain);
                    byte[] enc = t.TransformFinalBlock(data, 0, data.Length);
                    return Convert.ToBase64String(enc);
                }
            }
        }

        public static string Decrypt(string b64)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = Iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform t = aes.CreateDecryptor())
                {
                    byte[] enc = Convert.FromBase64String(b64.Trim());
                    byte[] data = t.TransformFinalBlock(enc, 0, enc.Length);
                    return Encoding.UTF8.GetString(data);
                }
            }
        }
    }

    // 文件完整性：SHA256 基准比对
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

        // 校验给定路径是否与基准一致；缺失基准视为通过
        public static bool Check(string path, string expectedHash)
        {
            if (string.IsNullOrEmpty(expectedHash)) return true;
            string actual = Sha256File(path);
            return actual != null && string.Equals(actual, expectedHash, StringComparison.OrdinalIgnoreCase);
        }
    }
}
