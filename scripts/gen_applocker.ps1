# gen_applocker.ps1 — 生成并（可选）应用 AppLocker 应用白名单策略
# 作用：只允许白名单内的程序运行（系统目录 + Program Files + 配置 WHITELIST 路径），
#       学生下载的病毒/破解工具 exe 一律无法启动。系统级强制，学生无权修改策略。
# 用法：
#   powershell -ExecutionPolicy Bypass -File gen_applocker.ps1 -ConfigPath <config.txt> [-ExtraPaths "path1;path2"] [-Apply]
#   -Apply 才真正写入系统策略；不加 -Apply 只输出策略 XML 到本目录 applocker-policy.xml（安全预览）
# 前提：Windows 10/11 Pro/Enterprise 或 Windows Server（含 AppLocker 功能）
param(
    [string]$ConfigPath = "",
    [string]$ExtraPaths = "",
    [switch]$Apply
)

$ErrorActionPreference = "Stop"

# 基础允许路径（系统正常运行必需）
$baseAllow = @("C:\Windows\*", "C:\Program Files\*", "C:\Program Files (x86)\*")

# 从配置读取 WHITELIST= 行
$extra = New-Object System.Collections.ArrayList
if ($ExtraPaths) { foreach ($p in ($ExtraPaths -split ";")) { if ($p) { [void]$extra.Add($p.Trim('"')) } } }
if ($ConfigPath -and (Test-Path $ConfigPath)) {
    foreach ($line in Get-Content $ConfigPath) {
        $t = $line.Trim()
        if ($t -like "WHITELIST=*") {
            $p = $t.Substring(10).Trim().Trim('"')
            if ($p) { [void]$extra.Add($p) }
        }
    }
}

# 检查 AppLocker cmdlet 可用性
if (-not (Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: AppLocker cmdlets 不可用（需 Win10/11 Pro/Enterprise 或 Windows Server）" -ForegroundColor Red
    exit 1
}

$allPaths = @($baseAllow) + $extra
Write-Host "白名单规则路径:"
foreach ($p in $allPaths) { Write-Host "  ALLOW  $p" }

# 生成策略 XML（手工构造：Exe / WindowsInstaller 允许白名单；Script 只允许系统）
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('<?xml version="1.0"?>')
[void]$sb.AppendLine('<AppLockerPolicy Version="1">')
foreach ($coll in @("Exe", "WindowsInstaller")) {
    [void]$sb.AppendLine("  <RuleCollection Type=`"$coll`" EnforcementMode=`"Enabled`">")
    foreach ($p in $allPaths) {
        $name = "Allow " + $p
        [void]$sb.AppendLine('    <FilePathRule Id="' + [guid]::NewGuid().ToString() + '" Name="' + $name + '" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">')
        [void]$sb.AppendLine('      <Conditions>')
        [void]$sb.AppendLine('        <FilePathCondition Path="' + $p + '" />')
        [void]$sb.AppendLine('      </Conditions>')
        [void]$sb.AppendLine('    </FilePathRule>')
    }
    [void]$sb.AppendLine('  </RuleCollection>')
}
[void]$sb.AppendLine('  <RuleCollection Type="Script" EnforcementMode="Enabled">')
[void]$sb.AppendLine('    <FilePathRule Id="' + [guid]::NewGuid().ToString() + '" Name="Allow Windows Scripts" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">')
[void]$sb.AppendLine('      <Conditions>')
[void]$sb.AppendLine('        <FilePathCondition Path="C:\Windows\*" />')
[void]$sb.AppendLine('      </Conditions>')
[void]$sb.AppendLine('    </FilePathRule>')
[void]$sb.AppendLine('  </RuleCollection>')
[void]$sb.AppendLine('</AppLockerPolicy>')
$xml = $sb.ToString()

if ($Apply) {
    Write-Host "正在应用策略（白名单模式：未列出的程序全部无法运行）..."
    $tmp = Join-Path $env:TEMP "guardkit_applocker.xml"
    [IO.File]::WriteAllText($tmp, $xml, (New-Object Text.UTF8Encoding $false))
    Set-AppLockerPolicy -XmlPolicy $tmp -Merge $false
    Remove-Item $tmp -Force
    Start-Service AppIDSvc -ErrorAction SilentlyContinue
    Write-Host "已应用。重启后完全生效；立即生效请重启 AppIDSvc 服务。"
} else {
    $out = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "applocker-policy.xml"
    [IO.File]::WriteAllText($out, $xml, (New-Object Text.UTF8Encoding $false))
    Write-Host "预览模式：策略 XML 已输出到 $out"
    Write-Host "确认无误后用 -Apply 参数应用。"
}
