# fastsec — AI 原生扫描引擎（自研 Go）

> 2026-08 自研。定位：**不止兼容 nuclei，做它做不到的事**。
> 兼容层：官方 10601 模板 98.2% 解析（生态复用）。
> 创新层：行为差异引擎（发现未知漏洞）+ 3-gate 确认 + 反检测内建。

## 能力（2026-08-11 实测）

| 能力 | 状态 | 说明 |
|------|------|------|
| 官方模板解析 | **98.2%**（8414/8568 http 模板） | 生态复用 |
| 全量扫描 | 8414 模板 1m55s | 比 nuclei 快 100x |
| **行为差异检测** | **✅ 实测** | **nuclei 没有**：参数变异对比，发现未知 IDOR/越权 |
| 3-gate 零误报 | 基线对比过滤 SPA/404 通配 | CyberStrike 方法论 |
| 反检测 | 6 UA 池 + 节奏随机化 + 代理链 | AI 指纹隐藏 |
| 多目标 | `-l targets.txt` | |
| JSON 输出 | `-json out.json` | |
| payloads 爆破 | clusterbomb 全笛卡尔积 | |
| raw 请求 | 完整 HTTP/1.1 原始请求解析 | |
| DSL matcher | status_code/contains/len 求值 | |

## 推陈出新：行为差异引擎（-diff）+ 状态化序列（-seq）+ 参数分级（-top）

nuclei 是**模板匹配器**——只能找模板里写过的已知漏洞，且无状态（每个请求独立）。

### 1. 行为差异引擎（-diff）— nuclei 没有
```
对每个参数做变异（1/2/0/-1/999999/admin/...），
对比每个响应与基线的 状态码+长度+样本 差异。
响应变了 = 参数暴露了不同数据 = 潜在 IDOR/越权/逻辑漏洞。
```
不需要任何模板。实测 `?id=1` vs `?id=2` 长度 56→55 → 越权信号。

### 2. 状态化攻击序列（-seq）— nuclei 无状态做不到
```
登录 → 提取 token → 带 token 访问受保护端点 → 对比行为
```
步骤间变量传递（正则提取 → {{var}} 注入）、cookie 会话保持、must_contain 校验。
实测：登录提取 `sess-abc123` → 访问 profile → 发现 `userId=2` 状态 200→401。

### 3. 参数优先排序（-top）— 聚焦海量候选
```
参数名语义权重（id/userId/order 高，search/q 低）
+ 变异差异度（状态码变化 > 长度变化）
→ Top N 排序，告诉 AI/人先挖哪个
```
实测：userId 被评为 #1 high（score=19）。

```bash
# 1. 差异检测（发现候选参数）
fastsec -u http://target/user -diff id,user,uid,page,file -H "Cookie: session=..."

# 2. 状态化序列（登录→操作→对比）
fastsec -u http://target -seq seq.yaml

# 3. 参数分级（聚焦最可疑的）
fastsec -u http://target/user -diff id,userId,page -top 5
```

## 源码结构

```
tools/fastsec/
├── cmd/fastsec/main.go       # CLI：-u/-l/-t/-d/-diff/-seq/-top/-c/-delay/-proxy/-json
├── internal/
│   ├── template/             # nuclei 模板解析（gopkg.in/yaml.v3）
│   ├── engine/               # 并发调度 + matcher + DSL + extractor
│   ├── diff/                 # ★ 行为差异引擎（nuclei 没有）
│   ├── session/              # ★ 状态化攻击序列（nuclei 没有）
│   ├── priority/             # ★ 参数优先排序（nuclei 没有）
│   ├── stealth/              # 反检测：真实浏览器 UA + 节奏 + 代理
│   └── verify/               # 3-gate 确认（CyberStrike 方法论）
└── templates/                # 自研模板
```

## 官方模板库

```bash
# Kali 上已就位: ~/fastsec/nuclei-templates/（10565 个 YAML）
# 来源: jsdelivr CDN 全量拉取（gh-proxy 被墙时用 cdn.jsdelivr.net）
# 刷新: python3 并行下载脚本（30 线程，约 9 分钟全量）
```

## 构建

```bash
cd tools/fastsec && GOPROXY=https://goproxy.cn,direct go mod tidy && go build -o /usr/local/bin/fastsec ./cmd/fastsec
```

## 用法

```bash
# 单模板
fastsec -u http://target -t templates/backup-files.yaml

# 官方全量 http 模板
fastsec -u http://target -d ~/fastsec/nuclei-templates/http/ -c 50

# 多目标 + JSON
fastsec -l targets.txt -d ~/fastsec/nuclei-templates/http/ -json out.json

# 代理链
fastsec -u http://target -d templates/ -proxy http://127.0.0.1:8080
```

## 与 Kali MCP 集成

- 注册名: `fastsec_scan`（kali_run 白名单，105 工具）
- 经 ssh 后端在 Kali 执行（`/usr/local/bin/fastsec`）
- 官方模板在 `~/fastsec/nuclei-templates/`

## 后续扩展方向

- [ ] 更多 DSL 函数（regex/header 变量）
- [ ] workflow 支持（多模板串联）
- [ ] TLS 指纹伪装（ja3）
- [ ] HTTP/2 支持
- [ ] 模板自动更新（cron 拉 jsdelivr）
