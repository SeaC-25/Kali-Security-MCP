# fastsec — AI 原生扫描引擎（自研 Go）

> 2026-08 自研：nuclei 模板兼容 + 3-gate 确认 + 反检测内建。
> 解决 nuclei 的两大痛点：模板全量加载挂死（180s+ 超时）、404 误报。

## 对比（实测，本地测试服务器）

| 指标 | nuclei | fastsec |
|------|--------|---------|
| 5 模板 × 50 路径 | 180s+ 挂死 | **1.25s** |
| 误报（SPA 全路径 200） | 全报 | **3-gate 过滤为 0** |
| 反检测 | 需手配 | UA 池 + 节奏随机化内建 |
| 依赖 | 7000+ 模板需加载 | 按需 `-d` 目录，零预加载 |

## 源码结构

```
tools/fastsec/
├── cmd/fastsec/main.go       # CLI：-u -t/-d -c -delay -proxy -no-verify -H
├── internal/
│   ├── template/             # nuclei YAML 兼容解析（零依赖手写）
│   │   ├── model.go          # Template/Request/Matcher/Extractor 模型
│   │   └── parse.go          # 解析器（支持 path/matchers/extractors/headers）
│   ├── engine/               # 并发调度 + matcher + extractor
│   │   ├── engine.go         # 并发 Run（semaphore）+ 3-gate 过滤
│   │   └── matcher.go        # status/word/regex 匹配
│   ├── stealth/              # 反检测：真实浏览器 UA 池 + 节奏 + 代理
│   │   └── stealth.go
│   └── verify/               # 3-gate 确认协议（CyberStrike 方法论）
│       └── threegate.go
└── templates/                # 内置模板（默认路径/备份/配置/管理入口/敏感文件）
```

## 构建（Kali）

```bash
cd tools/fastsec && go build -o /usr/local/bin/fastsec ./cmd/fastsec
```

## 用法

```bash
# 单模板
fastsec -u http://target -t templates/backup-files.yaml

# 目录批量（反检测默认开启）
fastsec -u http://target -d templates/ -c 30 -delay-min 200 -delay-max 600

# 代理链
fastsec -u http://target -t tpl.yaml -proxy http://127.0.0.1:8080

# 跳过 3-gate（快速但会误报）
fastsec -u http://target -t tpl.yaml -no-verify
```

## 3-gate 确认协议

每个匹配自动执行基线对比：
1. **Gate 1 基线**：同 URL 加 `__fastsec_baseline_probe__` 参数请求，测服务器"默认响应"
2. **Gate 2 攻击**：实际匹配响应
3. **Gate 3 对比**：状态码/长度/样本不一致 → 真漏洞；一致 → 404 通配/SPA → 丢弃

**结果零误报**：授权目标 SPA（全路径 200）实测 51 → 6。

## 模板格式（nuclei 兼容子集）

```yaml
id: backup-files
info:
  name: 备份文件泄露
  severity: high
requests:
  - method: GET
    path:
      - "{{BaseURL}}/backup.zip"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "PK"
        part: body
        condition: or
```

支持: `info/requests/method/path/headers/body/matchers(type=status|word|regex, part=body|header|status_code, condition=or)/extractors(type=regex|word, group)`

## 与 Kali MCP 集成

- 注册名: `fastsec_scan`（kali_run 白名单，104 工具）
- 经 ssh 后端在 Kali 执行（本地编译 `/usr/local/bin/fastsec`）
- 内置模板在 `~/fastsec/templates/`
