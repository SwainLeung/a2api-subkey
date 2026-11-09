# a2api-subkey

把 **AIClient2API（a2api）子 Key 的读取机制**写成一条可被任何 Agent 机械执行的 workflow：
凭据从哪里读、读到之后怎么发请求、读不到或读错了怎么定位与修复。

> 仓库里**没有**主机地址，也**没有**真实 Key。地址只从本地凭据 txt 在运行时读取；
> Key 在任何输出里都是 `maki_288***` 加指纹。

---

## 它解决什么问题

A2 网关通过 `api-potluck` 插件做多子 Key 认证：每台设备一把 `maki_` 前缀的 Key，
Codex CLI / GUI 把它放进请求头就能调模型。但只要「子 Key 读取失败」，症状会互相掩盖：

| 看到的现象 | 真实原因（常常不是同一层） |
|---|---|
| `401` | Key 没发出去（客户端没配 `env_key`，或新进程没继承环境变量），或者 Key 被 regenerate 了 |
| `403` | Key 正确，但被停用（插件 Tab 里 `enabled=false`） |
| `429` | 日配额满（正文带 used / limit / resetDate） |
| `500 No healthy provider found` | **池不健康** —— 与子 Key 无关，却最容易被误判成 Key 失效 |
| `200` 但模型不对 | 静默降级：不在支持清单里的 id 被换成别的模型回答 |

所以 workflow 的顺序是固定的：**先排除池与网络，再谈 Key**。

---

## 内容

| 文件 | 说明 |
|---|---|
| [`SUBKEY_WORKFLOW.md`](SUBKEY_WORKFLOW.md) | workflow 正文：G0–G3 闸门（先 IP 后 Key）、D0–D7 诊断阶梯、`SK-*` 错误码、R1–R7 修复剧本、掩码与证据规则 |
| [`tools/subkey-doctor.ps1`](tools/subkey-doctor.ps1) | 只读诊断器：默认离线；`-Probe` 才发只读 GET；`-CheckClient` 比对客户端指纹；`-Model` 才消耗配额 |
| [`SUBKEY_ANALYSIS.md`](SUBKEY_ANALYSIS.md) | 分层说明：主账号 / Provider / Provider Pool / 插件 Tab / 子 Key 的职责边界 |
| [`examples/`](examples/) | 凭据 txt 与 Codex `config.toml` 的占位符示例 |

---

## 快速开始

### 1. 建凭据 txt

放在**仓库之外**的本地只读目录（示例见 [`examples/a2-subkey.example.txt`](examples/a2-subkey.example.txt)），三行就够：

```text
ip = <host>            # 只写主机，不带 http://、不带端口、不带路径
port = 3000
subkey = maki_<32 hex> # 真值只存在这个文件里
label = laptop-codex
```

`ip` 是硬闸门：txt 里没有 `ip`，工具直接 `SK-001` 停下，**不会**回退到文档或记忆里的任何地址。

### 2. 跑诊断

```powershell
# 离线：只校验凭据（默认，不发任何请求）
powershell -NoProfile -File tools\subkey-doctor.ps1

# 只读探测：/health + models
powershell -NoProfile -File tools\subkey-doctor.ps1 -Probe

# 加客户端接线核对（config.toml / auth.json / 环境变量指纹）
powershell -NoProfile -File tools\subkey-doctor.ps1 -Probe -CheckClient

# 端到端路由验证（显式才消耗 1 次子 Key 配额）
powershell -NoProfile -File tools\subkey-doctor.ps1 -Probe -CheckClient -Model "<known-good-id>"

# 留证（掩码 JSON）
powershell -NoProfile -File tools\subkey-doctor.ps1 -Probe -CheckClient -JsonOut "evidence\subkey-doctor.json"
```

退出码：`0` 通过 · `2` 凭据闸门 · `3` 不可达 · `4` 认证/授权 · `5` 配额 · `6` 网关/模型层 · `7` 客户端接线。

### 3. 查错误码

`SUBKEY_WORKFLOW.md` 第 6 节是错误码表（`SK-000` … `SK-008`、`W-FALLBACK`），第 7 节是按根因分的 R1–R7 修复剧本，
每条都标了「只读 / 需审批」。

---

## 机制速览

| 事实 | 值 |
|---|---|
| Key 形态 | `maki_` + 32 位小写 hex，总长 37 |
| 认证插件 | `api-potluck`（优先级 10）；`default-auth` 是兜底（9999） |
| 提取顺序 | `Authorization: Bearer` → `x-api-key` → `x-goog-api-key` → `?key=` |
| 前缀不符 | 不是 `maki_` 开头 → 跳过 potluck，交给其他插件（常见表现为 401） |
| 校验链 | Key 存在 → `enabled` → 日配额未满；失败分别对应 401 / 403 / 429 |
| 客户端要求 | Codex ≥ 0.167 必须在 provider 块显式写 `env_key = "OPENAI_API_KEY"`，否则请求不带鉴权头 |
| 常见陷阱 | `/v1/models` 是聚合/静态列表，**不能**用来判断可用性 |

---

## 安全约束

- 本仓库不含地址与 Key；`tools/` 也不会把凭据写到磁盘。
- 输出只允许三种形态：`maki_288***`（前 8 字符）、`sha256[0:8]` 指纹、`host#<6 hex>` 主机指纹。
- 诊断器默认离线；唯一的写动作是 `-JsonOut` 的掩码证据 JSON。
- 主机侧变更（SSH / 容器 / 重启 / 子 Key 增删 / 配额调整）**不在**本工具范围内 —— 那些按各自项目的审批流程走。

---

## 发布说明

本仓库是私有项目的**公开发布子集**。`SUBKEY_WORKFLOW.md` 里提到的 `AGENTS.md`、`decisions/`、
以及「README 的池诊断」属于私项目的治理记录，未随本仓库发布；阅读时把它们当作「项目侧文档」即可，
workflow 本身是自包含的。

`tools/subkey-doctor.ps1` 面向 Windows PowerShell 5.1，文件保存为 UTF-8 with BOM；
修改后先做一次 `[Parser]::ParseFile` 解析自检再提交。

---

## 许可

未附许可证文件。如需对外授权，请由作者补充（MIT / Apache-2.0 均可）。
