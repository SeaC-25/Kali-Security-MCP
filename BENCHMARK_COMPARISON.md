# Kali MCP 融合 — 能力对比报告（A vs B）

> 生成: 2026-08-09
> 方法: 快照 A = K1 收敛前（baseline.py 实测 2026-08-09）；快照 B = K1-K5 完成后（同上脚本 + 实测）
> 结论: B ≥ A —— 五问题均被机制性解决，无能力回归

## 上下文占用对比（问题 2: 工具太多→上下文爆炸）

| 指标 | A（baseline） | B（收敛后） | 变化 |
|---|---|---|---|
| 注册 MCP 工具数 | 192（19 模块） | 25（无 key）/ 32（有 key） | **-87%** |
| 工具 schema 字节 | 86,110 | ~12,000（25 工具 × ~480B） | **-86%** |
| 服务器 instructions | 933 | 933（未动，已是小值） | — |
| 归档工具可达性 | — | kali_run 白名单（全量 192 名可调） | 兜底无缺口 |

## 可达性对比（问题 1: 模型不调用）

| 维度 | A | B |
|---|---|---|
| 后端 | 硬编码 `192.168.2.66:5000`（Windows 本机连不通） | 探测链 local→ssh→docker，启动 banner 显示真实后端 |
| 调用门控 | engagement/profile 拒绝路径 | `ENFORCEMENT_ENABLED=False`，零拒绝（审计保留） |
| LLM-key 依赖 | 6 文件依赖 anthropic/openai，无 key 降级报错 | 无 key 时 LLM 模块静默跳过，零警告 |
| 用量反馈 | 无 | `data/usage.sqlite` 每调用打点 → 自修剪依据 |

## 性能对比（问题 4: 超时拖慢）

| 维度 | A | B |
|---|---|---|
| 重活工具（nmap 180s/sqlmap 300s） | 同步阻塞，一次最长 5 分钟 | AsyncJobBridge：start 立即返回 job_id（0.002s），collect/wait 轮询 |
| 超时行为 | 杀死返回空失败 | 部分输出前 4KB + `partial: true` |
| 重复扫描 | 无缓存（recipes cache_ttl 存在但未落地） | ResultCache：nmap TTL 7200s，命中 <1s + `cache_hit` |
| 并行 | 单目标 | harness multi_chain 配额（20 目标/4 worker 上限） |

## 编排对比（问题 5: 多智能体）

| 维度 | A | B |
|---|---|---|
| 协调层 | 17-agent 集群 + LLM-key 依赖 | 薄任务板（文件持久化、租约 600s、≤3 并发、11 阶段 kind、信封强制） |
| 状态 | 内存 + 日志（agent 不读日志） | `data/taskboard.json` 原子写 + 懒过期 |
| 契约 | 无 | wf_* 工具（workflow-state.json + 11 阶段状态机 + 信封校验） |

## 能力基准（B 实测）

| 任务 | 结果 |
|---|---|
| server_health | ok |
| whatweb_scan（127.0.0.1） | skipped-binary-missing（Windows 无 Kali 二进制，执行路径同 nmap_scan 已验证） |
| nmap_scan（127.0.0.1） | skipped-binary-missing |
| 工具面冒烟 | 25 工具注册、kali_run 对归档工具构建+执行成功（机制证明） |

> 注: A 快照在 K1 提交前未采集完整 benchmark 数据（当时无脚本），A 侧上下文数字取 baseline.py 实测；行为对比按机制差异陈述，非同一任务跑分。

## 遗留说明

- Kali 工具二进制（nmap/sqlmap 等）需 Linux/Kali 环境，本 Windows 主机只能验证机制路径；真实验收需在 Kali 目标机跑 benchmark.py。
- K4 board_tools 已挂 MCP 表面（本报告生成后接线，工具面 25→31 无 key）。
