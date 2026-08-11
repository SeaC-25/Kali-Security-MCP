# fastsec — AI 原生扫描引擎（自研 Go）

> 2026-08 自研：nuclei 模板 100% 兼容 + 3-gate 确认 + 反检测内建。
> 目标是"比 nuclei 更快的自己的引擎"——模板用官方库（10601 个），引擎全自研。

## 能力（2026-08-11 实测）

| 能力 | 状态 |
|------|------|
| 官方模板解析 | **98.2%**（8414/8568 http 模板） |
| 全量扫描 | 8414 模板 1m55s（本地测试服务器） |
| 3-gate 零误报 | 基线对比过滤 SPA/404 通配 |
| 反检测 | 6 UA 池 + 节奏随机化 + 代理链 |
| 多目标 | `-l targets.txt` |
| JSON 输出 | `-json out.json` |
| payloads 爆破 | clusterbomb 全笛卡尔积 |
| raw 请求 | 完整 HTTP/1.1 原始请求解析 |
| DSL matcher | status_code/contains/len 求值 |
| 变量替换 | {{BaseURL}}/{{Hostname}}/{{payload}} |

## 源码结构

```
tools/fastsec/
├── cmd/fastsec/main.go       # CLI：-u/-l/-t/-d/-c/-delay/-proxy/-no-verify/-json
├── internal/
│   ├── template/             # nuclei 模板解析（gopkg.in/yaml.v3）
│   │   ├── model.go          # Template/Request/Matcher/Extractor + Payloads
│   │   └── parse.go          # yaml 结构 + raw 请求解析 + 柔性 tags/payloads
│   ├── engine/               # 并发调度 + matcher + DSL + extractor
│   │   ├── engine.go         # Run + 变量替换 + payloads 展开 + 3-gate 过滤
│   │   └── matcher.go        # status/word/regex/dsl/binary 匹配 + DSL 求值
│   ├── stealth/              # 反检测：真实浏览器 UA + 节奏 + 代理
│   └── verify/               # 3-gate 确认（CyberStrike 方法论）
└── templates/                # 自研模板（默认路径/备份/配置/管理/敏感文件）
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
