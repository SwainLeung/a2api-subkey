# A2 子 Key 读取 Workflow — 诊断与修复

> workflow id：`a2-subkey-read@1.0.0`
> 适用范围：任何 Agent（Codex / Claude / 自建 orchestrator）在**不接触主机、不读取明文地址**的前提下，
> 定位「子 Key 读取失败 → Codex 认证不成功 → 调不到模型」这一类问题。
> 本文件**不含**任何主机地址、域名、端口绑定、Key 明文。地址一律写作 `<host>`，Key 一律写作 `maki_288***`。
> 地址与 Key 只从**凭据 txt**在运行时读取（见第 2、3 节）。

---

## 0. 这个 workflow 是什么

一条可被机械执行的状态机：

```text
WF-0 定位凭据文件
      │
      ▼
WF-1 四道闸门 G0→G3（读 IP → 再读 Key → 再掩码）
      │ 任何一道不过 = 硬停，绝不猜地址、绝不猜 Key
      ▼
WF-2 推导请求（占位符 → 运行时拼装，绝不回显明文）
      │
      ▼
WF-3 八级诊断 D0→D7（先池后 Key，顺序不可换）
      │
      ▼
WF-4 归类到根因 E1→E7 / SK-* 错误码
      │
      ▼
WF-5 修复剧本（区分只读动作 / 需 L3 动作）
      │
      ▼
WF-6 留证（掩码 + 指纹，不含明文）
```

它**不是**：审批记录、主机操作授权、部署步骤。任何 SSH / Docker / 重启 / Provider 保存 / 子 Key 增删，
仍然需要精确范围的 L3 决策（见 `AGENTS.md`、`decisions/`）。

机器执行入口：`tools/subkey-doctor.ps1`（第 9 节），实现 WF-1～WF-4 与 WF-6。

---

## 1. 机制模型：子 Key 在 a2api 里是怎么被「读」到的

```text
        凭据 txt（本地，不入库）                A2 网关（api-potluck，优先级 10）
   ┌──────────────────────────┐            ┌────────────────────────────────────┐
   │ ip=<host>                │  闸门 G1   │ 1. 从请求头按固定顺序取 Key         │
   │ subkey=maki_288***       │ ─────────▶ │    Authorization: Bearer …          │
   └──────────────────────────┘  闸门 G2   │    x-api-key / x-goog-api-key       │
              │                            │    ?key=                            │
              │ 掩码 G3                    │ 2. 前缀必须是 maki_，否则跳过本插件  │
              ▼                            │ 3. Key 存在？enabled？日配额未满？   │
    请求头 Authorization: Bearer maki_288***│ 4. 通过 → 选 provider 池节点 → 上游  │
                                           └────────────────────────────────────┘
                                                        │
                                                        ▼
                                            模型响应（或 401/403/429/5xx）
```

关键事实（决定诊断顺序，别记反）：

| 事实 | 值 / 含义 |
|---|---|
| Key 形态 | `maki_` + 32 位小写 hex，总长 **37** |
| 子 Key 插件 | `api-potluck`，优先级 **10**；`default-auth` 是**兜底**（9999） |
| 提取顺序 | `Authorization: Bearer` → `x-api-key` → `x-goog-api-key` → `?key=` |
| 前缀不符 | 不是 `maki_` 开头 → 直接**跳过 potluck**，交给其他认证插件（常见表现为 401） |
| 校验链 | 存在 → `enabled=true` → `dailyLimit` 未满；任一失败分别对应 401 / 403 / 429 |
| 状态存储 | 主机侧 `/opt/a2/configs/api-potluck-keys.json`（内存缓存，约 5 秒落盘） |
| `regenerate` | 旧 ID **立即失效**，统计保留 → txt 必须同步，否则 401 |
| `toggle` 关闭 | 返回 403（Key 正确但被停用） |
| 配额满 | 返回 429 + used/limit/resetDate |
| 池不健康 | 返回 5xx `No healthy provider found in pool …` —— **与子 Key 无关** |

⚠ 两个反复踩到的坑：

1. **`/v1/models` 不能证明可用性**。它是静态/聚合列表，历史上一直列出账号实际服务不了的 id。
2. **网关不是「拒绝」而是「静默降级」**：不在支持清单里的模型会被换成别的模型回答，响应体报的是替换后的名字。
   所以「能连上」≠「用的是你点的那颗模型」。

---

## 2. 输入契约：凭据 txt

WF-0 只接受**一个** txt 文件作为地址与 Key 的唯一来源。格式（值全部是占位符）：

```text
# A2 网关凭据载体 —— 本地只读，不进仓库、不进 Git、不上传
ip = <host>              # 必填。只写主机，不带 http://、不带端口、不带斜杠
port = 3000              # 选填，默认 3000
subkey = maki_288***     # 必填。真值只在本地文件里，文档与输出里永远是掩码
label = laptop-codex     # 选填。设备/用途，用于区分多个 Key
```

字段别名（大小写不敏感）：`ip|host|hostname|addr|address`、`subkey|key|api_key|apikey|token`。

文件硬约束：

| 项 | 要求 | 违反后果 |
|---|---|---|
| 编码 | UTF-8，**无 BOM**，LF 或 CRLF 均可 | 首行键名带不可见字符 → 解析失败 |
| 分隔符 | 半角 `=` 或 `:` | 全角 `＝`/`：` 会解析失败（doctor 会 W-FULLWIDTH 告警并尝试归一） |
| 键值 | 一行一个键，`#` 开头为注释 | Markdown 表格粘贴进来 → 整行不可解析 |
| 值 | 不加引号（加了会被剥掉）、不换行、不含空格 | 换行/空格 → Key 长度异常 |
| 位置 | 例如 `credentials readonly/` 之类的**本地只读目录** | 放进文档目录 = 凭据入库，违规 |
| 权限 | 仅当前用户可读 | 泄露面扩大 |

铁律（WF-1 会强制执行）：

1. **地址必须由 txt 提供**。txt 没有 `ip` 就不许读 Key，更不许回退到 README / 记忆 / 聊天记录里的地址。
2. **Key 不以明文出现在任何输出**。日志、证据、回复、提交里只能是 `maki_288***` 或指纹。
3. **一个 txt 对应一个 Key**。多设备就有多个 txt，靠 `label` 区分，不要在一个文件里堆多行 `subkey`。

---

## 3. 闸门 G0–G3（按序，硬停）

| 闸门 | 检查 | 通过 | 失败码 | 失败时动作 |
|---|---|---|---|---|
| **G0 文件** | 存在、是普通文件、0 < 大小 ≤ 8 KiB、无 NUL 字节 | 进入 G1 | `SK-000` | 停止，回报「凭据文件缺失」+ 模板；**不**尝试别的路径 |
| **G1 地址** | `ip` 字段存在，且是合法 IPv4 或主机名（不含 scheme/端口/路径） | **此时才允许读 Key** | `SK-001` | 停止。禁止猜测或复用文档中的历史地址 |
| **G2 Key** | `subkey` 存在，匹配 `^maki_[0-9a-f]{32}$`，长度 37 | 进入 G3 | `SK-002` `SK-003` | 停止，按第 7 节 R2/R3 修文件 |
| **G3 掩码** | 已计算 mask + 指纹，后续所有输出只用手里的掩码值 | 进入 WF-2 | `SK-004` | 任何要打印原文的路径都视为缺陷，立即中止 |

`G2` 的一个专门分支很重要：**值里出现 `*`**（例如 `maki_288***`）说明有人把文档里的掩码复制进了 txt ——
判 `SK-003-MASKED`，提示「这是占位符，不是真 Key」。这正是「子 Key 读取失败」最常见的人为原因。

---

## 4. 请求推导（本节是唯一出现地址形状的地方，一律占位符）

运行时用 `ip` + `port` 拼出 `BASE`，**不打印 BASE**；输出里只出现 `host#<6 hex>`（host 的 sha256 指纹）。

```bash
# 0) 由 txt 组出来，不落盘、不进 shell 历史（示例用环境变量承载）
A2_BASE="http://<host>:<port>"
A2_KEY="maki_288***"          # 由 txt 读取，本节不写明文

# 1) 网关存活（无需 Key）
GET  $A2_BASE/health

# 2) 认证 + 模型清单（证明 Key 被接受）
GET  $A2_BASE/openai-codex-oauth/v1/models
     Authorization: Bearer $A2_KEY

# 3) 路由（证明能真的调用模型；1 次请求 = 1 次配额）
POST $A2_BASE/openai-codex-oauth/v1/responses
     Authorization: Bearer $A2_KEY
     Content-Type: application/json
     {"model":"<known-good-id>","input":"ping","max_output_tokens":16}

# 4) 个人用量（子 Key 认证，不限管理员）
GET  $A2_BASE/api/potluckuser/...     # 具体子路径以网关注册的路由为准，404 不代表 Key 无效
```

```powershell
# PowerShell 等价（同样不打印 BASE / KEY）
$h = @{ Authorization = "Bearer $env:A2_SUBKEY" }
Invoke-WebRequest -Uri "$env:A2_BASE/openai-codex-oauth/v1/models" -Headers $h -UseBasicParsing
```

客户端侧（Codex）接线，地址仍是占位符：

```toml
model_provider = "custom"
model = "<known-good-id>"

[model_providers.custom]
name = "A2 Gateway"
env_key = "OPENAI_API_KEY"                        # 0.167.0 起必须显式声明，否则不带鉴权头 → 401
base_url = "http://<host>:3000/openai-codex-oauth/v1"
wire_api = "responses"                            # codex-oauth 只吃 responses
```

- `env_key` 指向的变量必须在**进程能继承到的地方**：用户级环境变量、或启动脚本注入。GUI 改完要重启。
- `~/.codex/auth.json` 的 `auth_mode` 应为 `apikey`，其 `OPENAI_API_KEY` 与 txt 里的 Key **必须是同一把**（指纹对比，见 D6）。

---

## 5. 诊断阶梯 D0–D7（顺序不可交换）

顺序的理由：**先排除池/网络，再谈 Key**。池死的时候，任何 Key 都拿 500，你会把网关故障误判成 Key 失效。

| 步 | 动作 | 判据 | 失败码 |
|---|---|---|---|
| **D0** | 读凭据（G0–G3），算出掩码与指纹 | 三道闸门全过 | `SK-000/001/002/003/004` |
| **D1** | 静态自检：Key 长度、前缀、大小写、是否有 `*`、文件编码 | 37 字符、`maki_` 前缀、纯小写 hex | `SK-003-*` |
| **D2** | 连通性：`GET /health`（不带 Key） | 200 | `SK-101` `SK-102` |
| **D3** | 认证：`GET /openai-codex-oauth/v1/models` + Bearer | 200 | `SK-401` `SK-403` `SK-404` |
| **D4** | 配额：看 429 的 used/limit/resetDate，或 `potluckuser` 用量 | 未满 | `SK-429` |
| **D5** | 路由：`POST .../v1/responses` 用**已知可用**模型 | 200 且响应 `model` == 请求 id | `SK-400` `SK-500` `W-FALLBACK` |
| **D6** | 客户端接线：`config.toml` 的 `env_key`/`base_url` host/`wire_api`；`auth.json` 指纹；环境变量指纹 | 全部一致 | `SK-005` `SK-006` `SK-007` `SK-008` |
| **D7** | 归类 + 留证 | 命中唯一根因 E1–E7 | — |

**判定纪律（务必照做）**

1. D2 非 200 → 停。这是网络/网关问题，与子 Key 无关（转 `README.md` 的池诊断）。
2. D2 = 200 且 D3 = 500 且正文含 `No healthy provider` → 仍是池问题，**不是** Key 问题。
3. D3 = 401 且正文显示 `Authorization=N/A, x-api-key=N/A` → Key 根本没发出去，去 D6，不要去换 Key。
4. D3 = 401 且请求确实带了 Key → Key 已失效/被 regenerate/写错，走 R4。
5. D3 = 403 → Key 对但被 `toggle` 停用，走 R4。
6. D3 = 200 而 D5 失败 → 是**模型层**问题（支持清单/静默降级/上游），不是子 Key 问题。
7. 只有 D3 拿到 200，才有资格说「子 Key 读取成功」。

---

## 6. 错误码表

| 码 | 现象 | 判定 | 首要修复 | 变更边界 |
|---|---|---|---|---|
| `SK-000` | 找不到凭据文件 / 多个候选 | 定位失败 | 按第 2 节建文件，或显式给路径 | 只读 |
| `SK-001` | txt 无 `ip`，或 `ip` 带 `http://`/端口/路径 | 地址闸门失败 | 只写主机名/IP | 只读 |
| `SK-002` | txt 无 `subkey` | Key 闸门失败 | 补字段；向管理员索取 | 只读 |
| `SK-003-MASKED` | 值形如 `maki_288***` | 复制了掩码 | 换成真 Key（受控渠道） | 只读 |
| `SK-003-PREFIX` | 不以 `maki_` 开头（`sk-…`/`REQUIRED_API_KEY`） | 拿错类型的 Key | 用子 Key，不是 provider key | 只读 |
| `SK-003-LENGTH` | 长度 ≠ 37 / 被换行截断 | 复制不完整 | 单行复制 | 只读 |
| `SK-003-CASE` | 含大写 hex | 大小写不匹配 | 归一为小写 | 只读 |
| `SK-004` | 输出里出现明文 Key/地址 | 掩码闸门被绕过 | 中止并修工具 | 只读 |
| `SK-101` | 连接失败/超时/DNS 失败 | 网络或地址错 | 核对 txt 的 ip/port 与网关是否在跑 | 只读 |
| `SK-102` | `/health` 非 200 | 网关入口异常 | 转池/容器诊断 | 需 L3 |
| `SK-401` | models 返回 401 | 未认证 | 先看 D6（是否发 Key），再 R4（Key 是否失效） | 只读 |
| `SK-403` | models 返回 403 | Key 被停用 | 管理员 `toggle` 启用或换 Key | 需 L3（管理 API） |
| `SK-404` | models 返回 404 | 路径/版本不符 | 核对 `/openai-codex-oauth/v1` 前缀 | 只读 |
| `SK-429` | 429 + used/limit/resetDate | 日配额满 | 等 reset 或提额/换 Key | 需 L3（改限额） |
| `SK-400` | 400 `model is not supported when using Codex with a ChatGPT account` | 账号侧不支持该 id | 换已知可用 id（见 `README.md`） | 只读 |
| `SK-500` | 500 `No healthy provider found in pool` | **池**不健康 | 池恢复/健康检查，**不是 Key 问题** | 需 L3 |
| `SK-502` | 502/503/504 | 上游或代理 | 转上游诊断 | 需 L3 |
| `W-FALLBACK` | 200，但响应 `model` ≠ 请求 id | 静默降级 | 告知使用者；别把它当目标模型 | 只读 |
| `SK-005` | `auth.json` / 环境变量的 Key 指纹 ≠ txt | 客户端发了另一把 Key | 同步为同一把 | 只读（本机） |
| `SK-006` | provider 块缺 `env_key` | 0.167.0 回归 | 补 `env_key = "OPENAI_API_KEY"` | 只读（本机） |
| `SK-007` | `config.toml` 的 host ≠ txt 的 ip | 客户端指向别处 | 对齐（地址仍以 txt 为准） | 只读 |
| `SK-008` | 环境变量 `OPENAI_API_KEY` 缺失 | 新进程继承不到 | 写入用户级变量后**重启客户端** | 只读（本机） |

---

## 7. 修复剧本（按根因，R1–R7）

### R1 文件/路径漂移 → `SK-000`
1. 只读：列出候选 txt，比对 `label` 与设备。
2. 只读：确认文件不在被文档化的目录（否则先移出）。
3. 修：显式传路径给 doctor；不要「顺手」在仓库里建凭据文件。

### R2 解析失败 → `SK-002` / 未解析行
1. 只读：`Format-Hex` 看首 3 字节（`EF BB BF` = BOM）、看是否有全角字符。
2. 只读：确认不是 Markdown 表格粘贴（`| ip | … |`）。
3. 修：UTF-8 无 BOM 另存；分隔符换半角；删引号与行尾空格。

### R3 值不合法 → `SK-003-*`
1. 只读：核对长度 37、前缀 `maki_`、纯小写 hex、无 `*`、无换行。
2. 修：从受控渠道重新复制一次（单行）；归一大小写。
3. 若拿到的本来就是 `sk-…` 或 `REQUIRED_API_KEY`：那是 provider/兜底 Key，**不是**子 Key，走流程向管理员索取子 Key。

### R4 Key 已失效 → `SK-401` / `SK-403`
1. 只读：确认请求真的带了 Key（网关日志 `Authorization=N/A` 就是没带，回到 R6）。
2. 只读：确认该 Key 在插件 Tab 里仍存在、`enabled=true`、未超配额。
3. 修（需 L3）：管理员 `regenerate` 或新建 Key → **立即**更新 txt → 更新客户端凭据（`auth.json`、环境变量）→ 重跑 D3。
4. 注意 `regenerate` 保留历史统计但换 ID，旧 ID 立刻 401；这是「昨天还能用，今天全挂」的典型原因。

### R5 配额 → `SK-429`
1. 只读：读 429 正文的 used/limit/resetDate，确认是日配额而非上游限流。
2. 修（需 L3）：提额或换 Key；不要把上游 429 当成子 Key 配额（前者是 `SK-502/上游`，后者才是 `SK-429`）。

### R6 客户端没把 Key 发出去 → `SK-006` / `SK-008`
1. 只读：`config.toml` 的 provider 块是否有 `env_key`；`wire_api` 是否 `responses`。
2. 只读：`auth_mode` 是否 `apikey`；环境变量是否存在且指纹与 txt 一致。
3. 修（本机只读范围之外的部分按需）：补 `env_key`；写入用户级变量；**重启 CLI / GUI**（新进程才继承）。
4. 判定口诀：网关说 `Authorization=N/A` = 客户端没发；说 `API key is invalid` = 发了但不对。

### R7 网关侧（与子 Key 无关）→ `SK-102` / `SK-500` / `SK-502` / `SK-400`
1. 只读：`/health`、池节点 `isHealthy`/`errorCount`/`checkModelName`、`No healthy provider` 计数。
2. 修（需 L3）：按 `README.md` 的池诊断与 `decisions/` 里已批准的范围处理；**不要在 Key 上找原因**。
3. 模型层：换已知可用 id；注意 `W-FALLBACK` 的静默替换。

---

## 8. 掩码与证据

| 对象 | 允许出现 | 禁止出现 |
|---|---|---|
| 子 Key | `maki_288***`（前 8 字符 + `***`）、指纹 `sha256(key)[0:8]` | 完整 Key、Key 后缀、`Authorization` 头的值 |
| 主机地址 | `host#a1b2c3`（host 的 sha256 前 6 位，同址可比、不可还原） | 完整 IP/域名、任何 IP 段、完整 `base_url`、`Host` 头 |
| 响应体 | 状态码、错误文案、模型 id、用量字段 | 完整响应体、上游密钥、会话 token |
| 凭据文件 | 路径、大小、SHA-256 | 内容、逐行原文、`label` 之外的身份信息 |

证据 JSON 最小字段（doctor 的 `-JsonOut` 即此形状）：

```json
{
  "schema_version": "subkey-doctor@1.0.0",
  "generated_at": "<utc>",
  "credential_file": { "path": "<path>", "sha256": "<64 hex>", "exists": true },
  "host":  { "masked": "host#a1b2c3", "source": "txt:ip", "valid": true },
  "subkey":{ "masked": "maki_288***", "fingerprint": "a1b2c3d4", "length": 37, "valid": true },
  "stages": [ { "id": "G0", "status": "pass", "code": "SK-200", "detail": "..." } ],
  "probes": { "network": true, "quota_consuming": false, "count": 2 },
  "verdict": "pass|warn|blocked",
  "exit_code": 0
}
```

禁令：不把 txt 内容写进证据；不把完整 `base_url` 写进日志；不把 Key 贴进 issue/聊天/提交信息。

---

## 9. 机器执行入口

```powershell
# 只看凭据（离线，默认行为，不发任何请求）
powershell -NoProfile -File tools\subkey-doctor.ps1 -CredentialFile "<path>\a2-subkey.txt"

# 允许网络探测（只读 GET：/health + models）
powershell -NoProfile -File tools\subkey-doctor.ps1 -Probe

# 再加客户端接线核对（config.toml / auth.json / 环境变量，全部只读 + 指纹）
powershell -NoProfile -File tools\subkey-doctor.ps1 -Probe -CheckClient

# 端到端路由验证（会消耗 1 次子 Key 配额，显式才做）
powershell -NoProfile -File tools\subkey-doctor.ps1 -Probe -CheckClient -Model "<known-good-id>"

# 留证
powershell -NoProfile -File tools\subkey-doctor.ps1 -Probe -CheckClient -JsonOut "evidence\subkey-doctor-<date>.json"
```

参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `-CredentialFile` | 自动发现 | 省略时在 `credentials readonly\*.txt` 里找唯一候选；多于一个则 `SK-000` 并列出（不回显内容） |
| `-Probe` | 关 | 允许只读 GET。不开则完全离线 |
| `-CheckClient` | 关 | 核对 Codex 客户端接线与指纹 |
| `-Model` | 空 | 指定则做一次 `responses` 探测，**消耗配额** |
| `-TimeoutSec` | 8 | 单次探测超时 |
| `-JsonOut` | 空 | 写掩码证据 JSON |

> 维护提示：脚本在 Windows PowerShell 5.1 下运行，文件必须保存为 **UTF-8 with BOM**；
> 否则中文输出会乱码并触发解析错误。改完先做一次解析自检（`[Parser]::ParseFile`）。

退出码：

| 码 | 含义 |
|---|---|
| 0 | 通过（含仅 warn） |
| 2 | 输入闸门失败（`SK-000/001/002/003/004`） |
| 3 | 不可达（`SK-101`） |
| 4 | 认证/授权失败（`SK-401/403`） |
| 5 | 配额（`SK-429`） |
| 6 | 网关/模型层（`SK-102/400/404/500/502`） |
| 7 | 客户端接线不一致（`SK-005/006/007/008`） |
| 1 | 工具自身异常 |

---

## 10. 完成判定（DoD）

- [ ] 凭据 txt 通过 G0–G3，输出里只有掩码与指纹。
- [ ] D2 `/health` = 200（否则归 R7，不碰 Key）。
- [ ] D3 `models` = 200（此时**才有资格**说「子 Key 读取成功」）。
- [ ] D6 三项一致：txt 指纹 = `auth.json` 指纹 = 环境变量指纹；`env_key` 存在；`wire_api` = responses。
- [ ] D5 至少一次 200，且响应 `model` 与请求一致（不一致 = `W-FALLBACK`，必须告知）。
- [ ] 证据落 `evidence/`，且通过第 8 节的禁令自查。
- [ ] 若动过主机/客户端配置：有 L3 决策或明确的本地只读边界说明。

---

## 11. 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-11-09 | 1.0.0 | 首版：G0–G3 闸门、D0–D7 阶梯、`SK-*` 错误码、R1–R7 修复剧本、`tools/subkey-doctor.ps1` |
