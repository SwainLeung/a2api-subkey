#requires -Version 5.1
<#
.SYNOPSIS
    A2 子 Key 读取诊断器 —— SUBKEY_WORKFLOW.md 的机器执行入口（WF-1 ~ WF-4、WF-6）。

.DESCRIPTION
    只读取本地凭据 txt，按 G0→G3 闸门校验「先 IP、后 Key」，再把请求推导成只读探测，
    最后输出掩码化的诊断结论。默认完全离线；任何网络探测都必须显式 -Probe。

    设计约束（与 SUBKEY_WORKFLOW.md 一致）：
      * 地址只从 txt 的 ip 字段来，缺失即硬停，绝不回退到文档/记忆中的地址；
      * Key 只以 maki_288***（前 8 字符）与 sha256 前 8 位指纹出现；
      * 从不打印完整 Key、完整 base_url、Authorization 头的值、凭据文件内容；
      * 不改主机、不改客户端配置、不写任何凭据。

.PARAMETER CredentialFile
    凭据 txt 路径。省略时在 credentials readonly\*.txt 中自动发现唯一候选。

.PARAMETER Probe
    允许只读 GET 探测（/health 与 models）。不加则完全离线。

.PARAMETER CheckClient
    核对 Codex 客户端接线（config.toml / auth.json / 环境变量），全部只读 + 指纹。

.PARAMETER Model
    指定则做一次 responses 探测。会消耗 1 次子 Key 配额，必须显式给出。

.PARAMETER TimeoutSec
    单次网络探测超时秒数，默认 8。

.PARAMETER JsonOut
    把掩码证据 JSON 写到该路径。

.EXAMPLE
    .\tools\subkey-doctor.ps1 -CredentialFile "credentials readonly\a2-subkey.txt"

.EXAMPLE
    .\tools\subkey-doctor.ps1 -Probe -CheckClient -JsonOut "evidence\subkey-doctor.json"
#>
[CmdletBinding()]
param(
    [string]$CredentialFile,
    [switch]$Probe,
    [switch]$CheckClient,
    [string]$Model,
    [int]$TimeoutSec = 8,
    [string]$JsonOut
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:SchemaVersion = 'subkey-doctor@1.0.0'
$script:Stages = New-Object System.Collections.ArrayList
$script:FirstFailCode = $null
$script:ProbeCount = 0
$script:QuotaConsuming = $false

# ---------------------------------------------------------------------------
# 掩码 / 指纹（唯一允许的输出形态）
# ---------------------------------------------------------------------------

function Get-MaskedKey {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '(none)' }
    if ($Value.Length -le 8) { return '***' }
    return $Value.Substring(0, 8) + '***'
}

function Get-MaskedHost {
    # 地址不留任何可识别片段：只给 sha256 前 6 位指纹，同址可比、不可还原
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '(none)' }
    return 'host#' + (Get-Fingerprint $Value).Substring(0, 6)
}

function Get-Fingerprint {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $null }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hex = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
        return $hex.Substring(0, 8)
    } finally {
        $sha.Dispose()
    }
}

function Get-SanitizedText {
    param([string]$Text, [string]$SecretValue, [string]$HostValue)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = $Text
    if (-not [string]::IsNullOrEmpty($SecretValue)) { $t = $t.Replace($SecretValue, (Get-MaskedKey $SecretValue)) }
    $t = [regex]::Replace($t, 'maki_[0-9a-fA-F]{32}', 'maki_****')
    if (-not [string]::IsNullOrEmpty($HostValue)) { $t = $t.Replace($HostValue, (Get-MaskedHost $HostValue)) }
    $t = ($t -replace '\s+', ' ').Trim()
    if ($t.Length -gt 600) { $t = $t.Substring(0, 600) + '...' }
    return $t
}

# ---------------------------------------------------------------------------
# 结论收集
# ---------------------------------------------------------------------------

function Add-Stage {
    param(
        [string]$Id,
        [ValidateSet('pass', 'warn', 'fail', 'skip')][string]$Status,
        [string]$Code,
        [string]$Detail
    )
    [void]$script:Stages.Add([pscustomobject]@{
        id     = $Id
        status = $Status
        code   = $Code
        detail = $Detail
    })
    if ($Status -eq 'fail' -and [string]::IsNullOrEmpty($script:FirstFailCode)) {
        $script:FirstFailCode = $Code
    }
    $tag = switch ($Status) {
        'pass' { 'PASS' }
        'warn' { 'WARN' }
        'fail' { 'FAIL' }
        default { 'SKIP' }
    }
    Write-Host ("[{0,-2}] {1,-5} {2,-16} {3}" -f $Id, $tag, $Code, $Detail)
}

function Get-ExitCodeFor {
    param([string]$Code)
    if ([string]::IsNullOrEmpty($Code)) { return 0 }
    $c = $Code.ToUpperInvariant()
    if ($c -match '^SK-00[0-4]') { return 2 }
    if ($c -eq 'SK-101') { return 3 }
    if ($c -match '^SK-40[13]') { return 4 }
    if ($c -eq 'SK-429') { return 5 }
    if ($c -match '^SK-(102|400|404|500|502)') { return 6 }
    if ($c -match '^SK-00[5-8]') { return 7 }
    return 0
}

# ---------------------------------------------------------------------------
# WF-0 定位凭据文件
# ---------------------------------------------------------------------------

function Find-CredentialFile {
    $candidates = New-Object System.Collections.ArrayList
    $roots = New-Object System.Collections.ArrayList
    $here = $PSScriptRoot
    if ([string]::IsNullOrEmpty($here)) { $here = (Get-Location).Path }
    if ($here) {
        $parent = Split-Path -Parent $here
        if ($parent) { [void]$roots.Add((Join-Path $parent 'credentials readonly')) }
    }
    [void]$roots.Add((Join-Path (Get-Location).Path 'credentials readonly'))

    foreach ($root in ($roots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $files = Get-ChildItem -LiteralPath $root -Filter '*.txt' -File -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            $raw = $null
            try { $raw = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 -ErrorAction Stop } catch { continue }
            if ([string]::IsNullOrEmpty($raw)) { continue }
            if ($raw -match '(?im)^\s*(ip|host|hostname|addr|address|subkey|key|api[_-]?key)\s*[:=]') {
                [void]$candidates.Add($f.FullName)
            }
        }
    }
    return $candidates
}

# ---------------------------------------------------------------------------
# WF-1 闸门 G0：文件
# ---------------------------------------------------------------------------

function Read-Credential {
    param([string]$Path)

    $res = [pscustomobject]@{
        Path          = $Path
        Exists        = $false
        Sha256        = $null
        Size          = 0
        Fields        = @{}
        Warnings      = (New-Object System.Collections.ArrayList)
        UnparsedLines = 0
        HasNul        = $false
        HasBom        = $false
        Raw           = $null
    }

    if ([string]::IsNullOrEmpty($Path)) { return $res }
    if (-not (Test-Path -LiteralPath $Path)) { return $res }
    if ((Get-Item -LiteralPath $Path) -is [System.IO.DirectoryInfo]) { return $res }

    $item = Get-Item -LiteralPath $Path
    $res.Exists = $true
    $res.Size = $item.Length
    $res.Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $res.Raw = $raw
    if ([string]::IsNullOrEmpty($raw)) { return $res }

    if ($raw.IndexOf([char]0) -ge 0) { $res.HasNul = $true }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $res.HasBom = $true }
    } catch { }

    $lines = $raw -split "`r?`n"
    foreach ($line in $lines) {
        $t = $line.Trim()
        if ($t.Length -eq 0) { continue }
        if ($t.StartsWith('#')) { continue }
        if ($t.StartsWith('|') -or $t.StartsWith('`')) { [void]$res.Warnings.Add('W-MARKDOWN'); continue }

        $norm = $t -replace [char]0xFF1D, '=' -replace [char]0xFF1A, '='
        if ($norm -ne $t) { [void]$res.Warnings.Add('W-FULLWIDTH') }

        if ($norm -match '^(?<k>[A-Za-z][A-Za-z0-9_.\-]*)\s*[:=]\s*(?<v>.*)$') {
            $k = $Matches['k'].ToLowerInvariant()
            $v = $Matches['v'].Trim()
            if ($v.Length -ge 2) {
                if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) {
                    $v = $v.Substring(1, $v.Length - 2)
                }
            }
            if ($res.Fields.ContainsKey($k)) { [void]$res.Warnings.Add('W-DUPLICATE:' + $k) }
            $res.Fields[$k] = $v
        } else {
            $res.UnparsedLines++
        }
    }
    return $res
}

function Get-FieldValue {
    param([hashtable]$Fields, [string[]]$Names)
    foreach ($n in $Names) {
        if ($Fields.ContainsKey($n)) {
            $v = [string]$Fields[$n]
            if ($v.Length -gt 0) { return $v }
        }
    }
    return ''
}

# ---------------------------------------------------------------------------
# WF-1 闸门 G1：地址（必须来自 txt）
# ---------------------------------------------------------------------------

function Test-HostValue {
    param([string]$Value)
    $r = [pscustomobject]@{ Valid = $false; Code = 'SK-001'; Reason = '' }
    if ([string]::IsNullOrEmpty($Value)) {
        $r.Code = 'SK-001'
        $r.Reason = 'txt 缺少 ip 字段（地址必须由 txt 提供，不允许回退到文档里的地址）'
        return $r
    }
    if ($Value -match '^[A-Za-z][A-Za-z0-9+.\-]*://') {
        $r.Code = 'SK-001-SCHEME'
        $r.Reason = 'ip 字段带了协议前缀，只写主机'
        return $r
    }
    if ($Value.Contains('/')) {
        $r.Code = 'SK-001-PATH'
        $r.Reason = 'ip 字段带了路径或斜杠，只写主机'
        return $r
    }
    if ($Value -match '^[^:\[\]]+:\d{1,5}$') {
        $r.Code = 'SK-001-PORT'
        $r.Reason = 'ip 字段带了端口，端口请用 port 字段'
        return $r
    }
    if ($Value -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        foreach ($oct in @($Matches[1], $Matches[2], $Matches[3], $Matches[4])) {
            if ([int]$oct -gt 255) {
                $r.Code = 'SK-001-FORMAT'
                $r.Reason = 'IPv4 段超过 255'
                return $r
            }
        }
        $r.Valid = $true
        $r.Code = 'SK-001'
        return $r
    }
    if ($Value -match '^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$') {
        $r.Valid = $true
        $r.Code = 'SK-001'
        return $r
    }
    $r.Code = 'SK-001-FORMAT'
    $r.Reason = 'ip 既不是合法 IPv4 也不是合法主机名'
    return $r
}

# ---------------------------------------------------------------------------
# WF-1 闸门 G2：Key
# ---------------------------------------------------------------------------

function Test-KeyValue {
    param([string]$Value)
    $r = [pscustomobject]@{ Valid = $false; Code = 'SK-002'; Reason = ''; Normalized = $Value }
    if ([string]::IsNullOrEmpty($Value)) {
        $r.Code = 'SK-002'
        $r.Reason = 'txt 缺少 subkey 字段'
        return $r
    }
    if ($Value.Contains('*')) {
        $r.Code = 'SK-003-MASKED'
        $r.Reason = '值里含 *，看起来是文档里的掩码占位符，不是真 Key'
        return $r
    }
    if (-not $Value.StartsWith('maki_')) {
        $r.Code = 'SK-003-PREFIX'
        $r.Reason = '不以 maki_ 开头；这是 provider/兜底 Key，不是子 Key'
        return $r
    }
    $body = $Value.Substring(5)
    if ($body -notmatch '^[0-9a-fA-F]{32}$') {
        $r.Code = 'SK-003-LENGTH'
        $r.Reason = ('Key 体不是 32 位十六进制（实际总长 {0}，期望 37）' -f $Value.Length)
        return $r
    }
    if ($body -cmatch '[A-F]') {
        $r.Code = 'SK-003-CASE'
        $r.Reason = '包含大写十六进制；A2 按精确字符串比对，需归一为小写'
        return $r
    }
    if ($Value.Length -ne 37) {
        $r.Code = 'SK-003-LENGTH'
        $r.Reason = ('长度 {0}，期望 37' -f $Value.Length)
        return $r
    }
    $r.Valid = $true
    $r.Code = 'SK-003'
    return $r
}

# ---------------------------------------------------------------------------
# 网络探测（只读）
# ---------------------------------------------------------------------------

function Invoke-A2Request {
    param(
        [string]$Uri,
        [hashtable]$Headers,
        [string]$Method = 'GET',
        [string]$Body,
        [int]$TimeoutSeconds = 8
    )
    $out = [pscustomobject]@{ Status = 0; Body = ''; Error = ''; Ms = 0 }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $p = @{
            Uri             = $Uri
            Method          = $Method
            TimeoutSec      = $TimeoutSeconds
            UseBasicParsing = $true
            ErrorAction     = 'Stop'
        }
        if ($null -ne $Headers -and $Headers.Count -gt 0) { $p.Headers = $Headers }
        if (-not [string]::IsNullOrEmpty($Body)) {
            $p.Body = $Body
            $p.ContentType = 'application/json'
        }
        $resp = Invoke-WebRequest @p
        $out.Status = [int]$resp.StatusCode
        $out.Body = [string]$resp.Content
    } catch {
        $ex = $_.Exception
        $status = 0
        try {
            if ($null -ne $ex.Response -and $null -ne $ex.Response.StatusCode) {
                $status = [int]$ex.Response.StatusCode
            }
        } catch { $status = 0 }
        if ($status -gt 0) {
            $out.Status = $status
            try {
                if ($null -ne $ex.Response.Content -and $null -ne $ex.Response.Content.ReadAsStringAsync) {
                    $out.Body = $ex.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                } elseif ($null -ne $ex.Response.GetResponseStream) {
                    $sr = New-Object System.IO.StreamReader($ex.Response.GetResponseStream())
                    $out.Body = $sr.ReadToEnd()
                    $sr.Dispose()
                }
            } catch { }
        } else {
            $out.Error = [string]$ex.Message
        }
    } finally {
        $sw.Stop()
    }
    $out.Ms = [int]$sw.ElapsedMilliseconds
    return $out
}

function Get-ErrorClass {
    param([string]$Message)
    if ([string]::IsNullOrEmpty($Message)) { return 'unknown' }
    $m = $Message.ToLowerInvariant()
    if ($m -match 'refused|actively refused|10061') { return 'connection_refused' }
    if ($m -match 'timed out|timeout|10060') { return 'timeout' }
    if ($m -match 'resolve|dns|name or service|11001') { return 'dns' }
    if ($m -match 'unreachable|10051|10065') { return 'unreachable' }
    return 'other'
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '=== a2api 子 Key 读取诊断（SUBKEY_WORKFLOW.md） ===' -ForegroundColor Cyan
Write-Host ("schema={0}  offline={1}  checkClient={2}" -f $script:SchemaVersion, (-not $Probe), [bool]$CheckClient)

# --- WF-0 定位 -------------------------------------------------------------
$filePath = $CredentialFile
if ([string]::IsNullOrEmpty($filePath)) {
    $found = @(Find-CredentialFile)
    if ($found.Count -eq 1) {
        $filePath = $found[0]
        Write-Host ("自动发现凭据文件：{0}" -f $filePath)
    } elseif ($found.Count -gt 1) {
        Add-Stage -Id 'G0' -Status 'fail' -Code 'SK-000' -Detail ("发现 {0} 个候选凭据文件，必须显式 -CredentialFile 指定其一" -f $found.Count)
        foreach ($f in $found) { Write-Host ("  候选：{0}" -f $f) }
    } else {
        Add-Stage -Id 'G0' -Status 'fail' -Code 'SK-000' -Detail '未发现凭据 txt；按 SUBKEY_WORKFLOW.md 第 2 节建立：ip=… / subkey=maki_…'
    }
}

# --- G0 文件 ---------------------------------------------------------------
$cred = $null
if (-not [string]::IsNullOrEmpty($filePath)) {
    $cred = Read-Credential -Path $filePath
    if (-not $cred.Exists) {
        Add-Stage -Id 'G0' -Status 'fail' -Code 'SK-000' -Detail ("凭据文件不存在或不是普通文件：{0}" -f $filePath)
    } elseif ($cred.HasNul) {
        Add-Stage -Id 'G0' -Status 'fail' -Code 'SK-000' -Detail '凭据文件含 NUL 字节，不是纯文本'
    } elseif ($cred.Size -gt 8192) {
        Add-Stage -Id 'G0' -Status 'fail' -Code 'SK-000' -Detail ("凭据文件 {0} 字节，超过 8 KiB 上限，疑似放错文件" -f $cred.Size)
    } else {
        Add-Stage -Id 'G0' -Status 'pass' -Code 'SK-200' -Detail ("exists size={0}B sha256={1}..." -f $cred.Size, $cred.Sha256.Substring(0, 12))
        if ($cred.HasBom) { Add-Stage -Id 'G0' -Status 'warn' -Code 'W-BOM' -Detail '文件带 UTF-8 BOM（可解析，但建议另存为无 BOM）' }
        if ($cred.UnparsedLines -gt 0) { Add-Stage -Id 'G0' -Status 'warn' -Code 'W-UNPARSED' -Detail ("{0} 行不符合 key=value 形态（内容未回显）" -f $cred.UnparsedLines) }
        foreach ($w in ($cred.Warnings | Select-Object -Unique)) {
            Add-Stage -Id 'G0' -Status 'warn' -Code $w -Detail '凭据文件格式告警，见 SUBKEY_WORKFLOW.md 第 2 节'
        }
    }
}

# --- G1 地址 ---------------------------------------------------------------
$hostValue = ''
$portValue = 3000
$hostCheck = $null
if ($null -ne $cred -and $cred.Exists -and -not $cred.HasNul -and $cred.Size -le 8192) {
    $hostValue = Get-FieldValue -Fields $cred.Fields -Names @('ip', 'host', 'hostname', 'addr', 'address')
    $portRaw = Get-FieldValue -Fields $cred.Fields -Names @('port')
    if ($portRaw -match '^\d+$') {
        $p = [int]$portRaw
        if ($p -ge 1 -and $p -le 65535) { $portValue = $p }
        else { Add-Stage -Id 'G1' -Status 'warn' -Code 'W-PORT' -Detail 'port 越界，回退 3000' }
    }
    $hostCheck = Test-HostValue -Value $hostValue
    if ($hostCheck.Valid) {
        Add-Stage -Id 'G1' -Status 'pass' -Code 'SK-200' -Detail ("ip 已由 txt 提供：[{0}] port={1}" -f (Get-MaskedHost $hostValue), $portValue)
    } else {
        Add-Stage -Id 'G1' -Status 'fail' -Code $hostCheck.Code -Detail $hostCheck.Reason
    }
}

# --- G2 Key（只有 G1 通过才允许读） ---------------------------------------
$keyValue = ''
$keyCheck = $null
$keyMasked = '(none)'
$keyFingerprint = $null
if ($null -ne $hostCheck -and $hostCheck.Valid) {
    $keyValue = Get-FieldValue -Fields $cred.Fields -Names @('subkey', 'key', 'api_key', 'apikey', 'token')
    $keyCheck = Test-KeyValue -Value $keyValue
    if ($keyCheck.Code -eq 'SK-003-CASE') {
        $keyValue = $keyValue.ToLowerInvariant()
        $keyCheck = Test-KeyValue -Value $keyValue
        Add-Stage -Id 'G2' -Status 'warn' -Code 'W-CASE' -Detail 'Key 含大写 hex，已归一为小写'
    }
    if ($keyCheck.Valid) {
        $keyMasked = Get-MaskedKey $keyValue
        $keyFingerprint = Get-Fingerprint $keyValue
        Add-Stage -Id 'G2' -Status 'pass' -Code 'SK-200' -Detail ("subkey={0} len={1} fp={2}" -f $keyMasked, $keyValue.Length, $keyFingerprint)
    } else {
        Add-Stage -Id 'G2' -Status 'fail' -Code $keyCheck.Code -Detail $keyCheck.Reason
    }
} elseif ($null -ne $hostCheck) {
    Add-Stage -Id 'G2' -Status 'skip' -Code 'SK-001' -Detail '地址闸门未通过，按规则不读取 Key'
}

# --- G3 掩码自检 -----------------------------------------------------------
if ($keyCheck -and $keyCheck.Valid) {
    $leak = $false
    foreach ($s in $script:Stages) { if ($s.detail -and $keyValue -and $s.detail.Contains($keyValue)) { $leak = $true } }
    if ($leak) {
        Add-Stage -Id 'G3' -Status 'fail' -Code 'SK-004' -Detail '检测到明文 Key 进入输出，立即中止'
    } else {
        Add-Stage -Id 'G3' -Status 'pass' -Code 'SK-200' -Detail '输出仅含掩码与指纹'
    }
}

# --- WF-2/3 探测 -----------------------------------------------------------
$base = $null
if ($null -ne $hostCheck -and $hostCheck.Valid) {
    $base = 'http://{0}:{1}' -f $hostValue, $portValue
}

if ($Probe -and $null -ne $base -and $keyCheck -and $keyCheck.Valid) {
    # D2 连通性
    $script:ProbeCount++
    $health = Invoke-A2Request -Uri ($base + '/health') -TimeoutSeconds $TimeoutSec
    if ($health.Status -eq 200) {
        $body = Get-SanitizedText -Text $health.Body -SecretValue $keyValue -HostValue $hostValue
        Add-Stage -Id 'D2' -Status 'pass' -Code 'SK-200' -Detail ("/health 200 ({0}ms) {1}" -f $health.Ms, $body)
    } elseif ($health.Status -eq 0) {
        Add-Stage -Id 'D2' -Status 'fail' -Code 'SK-101' -Detail ("/health 不可达：{0}（{1}）" -f (Get-ErrorClass $health.Error), (Get-SanitizedText -Text $health.Error -HostValue $hostValue))
    } else {
        Add-Stage -Id 'D2' -Status 'fail' -Code 'SK-102' -Detail ("/health 返回 {0}" -f $health.Status)
    }

    # D3 认证
    $script:ProbeCount++
    $headers = @{ Authorization = 'Bearer ' + $keyValue }
    $models = Invoke-A2Request -Uri ($base + '/openai-codex-oauth/v1/models') -Headers $headers -TimeoutSeconds $TimeoutSec
    $modelsBody = Get-SanitizedText -Text $models.Body -SecretValue $keyValue -HostValue $hostValue
    $modelCount = $null
    $modelIds = @()
    if ($models.Status -eq 200 -and -not [string]::IsNullOrEmpty($models.Body)) {
        try {
            $j = $models.Body | ConvertFrom-Json
            if ($null -ne $j.data) {
                $modelIds = @($j.data | ForEach-Object { [string]$_.id })
                $modelCount = $modelIds.Count
            }
        } catch { }
    }
    switch ($models.Status) {
        200 {
            $detail = "models 200 ({0}ms) count={1}" -f $models.Ms, $modelCount
            if ($Model -and $modelIds.Count -gt 0) {
                $has = $modelIds -contains $Model
                $detail += (" requestedModelPresent={0}" -f $has)
            }
            Add-Stage -Id 'D3' -Status 'pass' -Code 'SK-200' -Detail $detail
        }
        401 { Add-Stage -Id 'D3' -Status 'fail' -Code 'SK-401' -Detail ("models 401：客户端/请求未通过认证 — {0}" -f $modelsBody) }
        403 { Add-Stage -Id 'D3' -Status 'fail' -Code 'SK-403' -Detail ("models 403：Key 存在但被停用 — {0}" -f $modelsBody) }
        404 { Add-Stage -Id 'D3' -Status 'fail' -Code 'SK-404' -Detail 'models 404：路径/网关版本不符，核对 /openai-codex-oauth/v1 前缀' }
        429 {
            $quota = ''
            try {
                $q = $models.Body | ConvertFrom-Json
                $quota = (" used={0} limit={1} reset={2}" -f $q.used, $q.limit, $q.resetDate)
            } catch { }
            Add-Stage -Id 'D3' -Status 'fail' -Code 'SK-429' -Detail ("models 429：日配额已满{0}" -f $quota)
        }
        500 {
            $code = 'SK-500'
            if ($modelsBody -notmatch '(?i)no healthy provider') { $code = 'SK-500-UPSTREAM' }
            Add-Stage -Id 'D3' -Status 'fail' -Code $code -Detail ("models 500：池/上游层 — {0}" -f $modelsBody)
        }
        { $_ -in 502, 503, 504 } { Add-Stage -Id 'D3' -Status 'fail' -Code 'SK-502' -Detail ("models {0}：上游/代理不可用" -f $models.Status) }
        0 { Add-Stage -Id 'D3' -Status 'fail' -Code 'SK-101' -Detail ("models 不可达：{0}" -f (Get-ErrorClass $models.Error)) }
        default { Add-Stage -Id 'D3' -Status 'fail' -Code 'SK-500-UPSTREAM' -Detail ("models 异常状态 {0} — {1}" -f $models.Status, $modelsBody) }
    }

    # D5 路由（显式 -Model 才做，消耗配额）
    if (-not [string]::IsNullOrEmpty($Model)) {
        $script:QuotaConsuming = $true
        $script:ProbeCount++
        $payload = '{"model":"' + $Model + '","input":"ping","max_output_tokens":16}'
        $resp = Invoke-A2Request -Uri ($base + '/openai-codex-oauth/v1/responses') -Headers $headers -Method 'POST' -Body $payload -TimeoutSeconds $TimeoutSec
        $respBody = Get-SanitizedText -Text $resp.Body -SecretValue $keyValue -HostValue $hostValue
        if ($resp.Status -eq 200) {
            $reported = ''
            try { $rj = $resp.Body | ConvertFrom-Json; $reported = [string]$rj.model } catch { }
            if ($reported -and $reported -ne $Model) {
                Add-Stage -Id 'D5' -Status 'warn' -Code 'W-FALLBACK' -Detail ("200 但响应 model={0} ≠ 请求 {1}（静默替换）" -f $reported, $Model)
            } else {
                Add-Stage -Id 'D5' -Status 'pass' -Code 'SK-200' -Detail ("responses 200 ({0}ms) model={1}" -f $resp.Ms, $reported)
            }
        } elseif ($resp.Status -eq 400) {
            Add-Stage -Id 'D5' -Status 'fail' -Code 'SK-400' -Detail ("responses 400：模型层拒绝 — {0}" -f $respBody)
        } elseif ($resp.Status -eq 429) {
            Add-Stage -Id 'D5' -Status 'fail' -Code 'SK-429' -Detail 'responses 429：配额或上游限流'
        } elseif ($resp.Status -ge 500) {
            $code = 'SK-502'
            if ($respBody -match '(?i)no healthy provider') { $code = 'SK-500' }
            Add-Stage -Id 'D5' -Status 'fail' -Code $code -Detail ("responses {0}：{1}" -f $resp.Status, $respBody)
        } else {
            Add-Stage -Id 'D5' -Status 'fail' -Code 'SK-400' -Detail ("responses {0}：{1}" -f $resp.Status, $respBody)
        }
    } else {
        Add-Stage -Id 'D5' -Status 'skip' -Code 'SK-200' -Detail '未指定 -Model，跳过路由探测（避免消耗配额）'
    }
} elseif ($Probe) {
    Add-Stage -Id 'D2' -Status 'skip' -Code 'SK-001' -Detail '闸门未通过，未发起任何网络请求'
} else {
    Add-Stage -Id 'D2' -Status 'skip' -Code 'SK-200' -Detail '离线模式（未加 -Probe），未发起网络请求'
    Add-Stage -Id 'D3' -Status 'skip' -Code 'SK-200' -Detail '离线模式，跳过认证探测'
}

# --- D6 客户端接线 ---------------------------------------------------------
if ($CheckClient -and $keyCheck -and $keyCheck.Valid -and $null -ne $hostCheck -and $hostCheck.Valid) {
    $codexHome = $env:CODEX_HOME
    if ([string]::IsNullOrEmpty($codexHome)) { $codexHome = Join-Path $env:USERPROFILE '.codex' }
    $cfgPath = Join-Path $codexHome 'config.toml'
    $authPath = Join-Path $codexHome 'auth.json'

    if (Test-Path -LiteralPath $cfgPath) {
        $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8
        $urlMatch = [regex]::Match($cfg, '(?m)^\s*base_url\s*=\s*"(?<u>[^"]+)"')
        if (-not $urlMatch.Success) {
            Add-Stage -Id 'D6' -Status 'fail' -Code 'SK-007' -Detail 'config.toml 未声明 base_url'
        } else {
            $baseUrl = $urlMatch.Groups['u'].Value
            if ($baseUrl -notmatch '/openai-codex-oauth') {
                Add-Stage -Id 'D6' -Status 'fail' -Code 'SK-007' -Detail 'base_url 未指向 openai-codex-oauth 路径'
            }
            $cfgHost = ''
            try { $cfgHost = ([uri]$baseUrl).Host } catch { }
            if ($cfgHost -and $cfgHost -ne $hostValue) {
                Add-Stage -Id 'D6' -Status 'fail' -Code 'SK-007' -Detail ("config.toml 主机（{0}）≠ txt 主机（{1}）" -f (Get-MaskedHost $cfgHost), (Get-MaskedHost $hostValue))
            } elseif ($cfgHost) {
                Add-Stage -Id 'D6' -Status 'pass' -Code 'SK-200' -Detail ("base_url 主机一致（{0}）" -f (Get-MaskedHost $cfgHost))
            }

            $idx = 0
            $lines = $cfg -split "`r?`n"
            for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*base_url\s*=') { $idx = $i; break } }
            $start = 0
            for ($i = $idx; $i -ge 0; $i--) { if ($lines[$i] -match '^\s*\[') { $start = $i; break } }
            $end = $lines.Count - 1
            for ($i = $idx; $i -lt $lines.Count; $i++) { if ($i -gt $idx -and $lines[$i] -match '^\s*\[') { $end = $i - 1; break } }
            $block = ($lines[$start..$end] -join "`n")
            if ($block -match '(?m)^\s*env_key\s*=') {
                Add-Stage -Id 'D6' -Status 'pass' -Code 'SK-200' -Detail 'provider 块已声明 env_key'
            } else {
                Add-Stage -Id 'D6' -Status 'fail' -Code 'SK-006' -Detail 'provider 块缺 env_key（0.167.0 起必须显式声明，否则请求不带鉴权头）'
            }
            if ($block -match '(?m)^\s*wire_api\s*=\s*"(?<w>[^"]+)"') {
                $wire = $Matches['w']
                if ($wire -ne 'responses') {
                    Add-Stage -Id 'D6' -Status 'warn' -Code 'W-WIRE' -Detail ("wire_api={0}，codex-oauth 需要 responses" -f $wire)
                } else {
                    Add-Stage -Id 'D6' -Status 'pass' -Code 'SK-200' -Detail 'wire_api=responses'
                }
            }
        }
    } else {
        Add-Stage -Id 'D6' -Status 'skip' -Code 'SK-200' -Detail '未找到 config.toml'
    }

    if (Test-Path -LiteralPath $authPath) {
        try {
            $auth = Get-Content -LiteralPath $authPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $mode = [string]$auth.auth_mode
            if ($mode -and $mode -ne 'apikey') {
                Add-Stage -Id 'D6' -Status 'warn' -Code 'W-AUTHMODE' -Detail ("auth_mode={0}，期望 apikey" -f $mode)
            }
            $clientKey = [string]$auth.OPENAI_API_KEY
            if ([string]::IsNullOrEmpty($clientKey)) {
                Add-Stage -Id 'D6' -Status 'fail' -Code 'SK-005' -Detail 'auth.json 无 OPENAI_API_KEY'
            } else {
                $fp = Get-Fingerprint $clientKey
                if ($fp -ne $keyFingerprint) {
                    Add-Stage -Id 'D6' -Status 'fail' -Code 'SK-005' -Detail ("auth.json 指纹 {0} ≠ txt 指纹 {1}（客户端会发另一把 Key）" -f $fp, $keyFingerprint)
                } else {
                    Add-Stage -Id 'D6' -Status 'pass' -Code 'SK-200' -Detail ("auth.json 指纹一致 {0}" -f $fp)
                }
            }
        } catch {
            Add-Stage -Id 'D6' -Status 'warn' -Code 'W-AUTHJSON' -Detail 'auth.json 无法解析'
        }
    }

    $envKey = [Environment]::GetEnvironmentVariable('OPENAI_API_KEY', 'Process')
    if ([string]::IsNullOrEmpty($envKey)) { $envKey = [Environment]::GetEnvironmentVariable('OPENAI_API_KEY', 'User') }
    if ([string]::IsNullOrEmpty($envKey)) { $envKey = [Environment]::GetEnvironmentVariable('OPENAI_API_KEY', 'Machine') }
    if ([string]::IsNullOrEmpty($envKey)) {
        Add-Stage -Id 'D6' -Status 'fail' -Code 'SK-008' -Detail '进程/用户/机器级均无 OPENAI_API_KEY，env_key 指不到值'
    } else {
        $fp = Get-Fingerprint $envKey
        if ($fp -ne $keyFingerprint) {
            Add-Stage -Id 'D6' -Status 'fail' -Code 'SK-005' -Detail ("环境变量指纹 {0} ≠ txt 指纹 {1}" -f $fp, $keyFingerprint)
        } else {
            Add-Stage -Id 'D6' -Status 'pass' -Code 'SK-200' -Detail ("环境变量指纹一致 {0}" -f $fp)
        }
    }
} else {
    Add-Stage -Id 'D6' -Status 'skip' -Code 'SK-200' -Detail '未加 -CheckClient，跳过客户端接线核对'
}

# ---------------------------------------------------------------------------
# 结论
# ---------------------------------------------------------------------------

$fails = @($script:Stages | Where-Object { $_.status -eq 'fail' })
$warns = @($script:Stages | Where-Object { $_.status -eq 'warn' })
$verdict = 'pass'
if ($fails.Count -gt 0) { $verdict = 'blocked' }
elseif ($warns.Count -gt 0) { $verdict = 'warn' }
$exitCode = Get-ExitCodeFor -Code $script:FirstFailCode

Write-Host ''
Write-Host ('verdict={0}  exit={1}  probes={2}  quotaConsuming={3}' -f $verdict, $exitCode, $script:ProbeCount, $script:QuotaConsuming) -ForegroundColor ($(if ($verdict -eq 'pass') { 'Green' } elseif ($verdict -eq 'warn') { 'Yellow' } else { 'Red' }))
if ($fails.Count -gt 0) {
    Write-Host ('首要失败码：{0}' -f $script:FirstFailCode) -ForegroundColor Red
    Write-Host '下一步：按 SUBKEY_WORKFLOW.md 第 7 节对应 R 剧本处理；主机侧变更需 L3。'
}

if (-not [string]::IsNullOrEmpty($JsonOut)) {
    $report = [pscustomobject]@{
        schema_version  = $script:SchemaVersion
        generated_at    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        credential_file = [pscustomobject]@{
            path   = $filePath
            sha256 = $(if ($cred -and $cred.Sha256) { $cred.Sha256 } else { $null })
            exists = [bool]($cred -and $cred.Exists)
        }
        host            = [pscustomobject]@{
            masked = (Get-MaskedHost $hostValue)
            source = 'txt:ip'
            valid  = [bool]($hostCheck -and $hostCheck.Valid)
        }
        subkey          = [pscustomobject]@{
            masked      = $keyMasked
            fingerprint = $keyFingerprint
            length      = $(if ($keyValue) { $keyValue.Length } else { 0 })
            valid       = [bool]($keyCheck -and $keyCheck.Valid)
        }
        stages          = @($script:Stages)
        probes          = [pscustomobject]@{
            network         = [bool]$Probe
            quota_consuming = [bool]$script:QuotaConsuming
            count           = $script:ProbeCount
        }
        verdict         = $verdict
        exit_code       = $exitCode
    }
    $dir = Split-Path -Parent $JsonOut
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonOut -Encoding UTF8
    Write-Host ("证据已写入：{0}" -f $JsonOut)
}

exit $exitCode
