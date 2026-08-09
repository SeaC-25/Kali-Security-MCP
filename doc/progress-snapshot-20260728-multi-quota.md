# 进度快照 2026-07-28（multi 配额推进）

## 本轮目标

Phase4 硬化小步：为 `run_surface_chain_multi` 补**可配置并发/目标配额**，避免无界 fan-out。

## 代码改动

| 文件 | 变更 |
|------|------|
| `kali_mcp/mcp_tools/harness_tools.py` | `multi_chain_quotas` / `clamp_multi_workers`；超 `max_targets` 直接 `ok=false`；并行 worker 受 env 硬顶；返回体增加 `quota` |
| `tests/test_p0_harness.py` | `test_multi_chain_quotas` + multi 返回含 `quota` 断言 |
| `doc/runbook-internal.md` | 环境变量表与「已做」清单更新 |

## 配额口径

| 变量 | 默认 | 硬顶 | 行为 |
|------|------|------|------|
| `KALI_MCP_MULTI_MAX_TARGETS` | 20 | 50 | 目标数超限 → 不启动 chain，返回 error |
| `KALI_MCP_MULTI_MAX_WORKERS` | 4 | 8 | 与调用方 `max_workers`、目标数取 min |

## 验证（本机 Windows）

```text
cd Kali-Security-MCP-main/Kali-Security-MCP-main
py -3 -m pytest tests/test_p0_harness.py -q
```

**已验证：** Windows + Kali 均为 **48 passed**（见 `doc/lab-acceptance/pytest_dual_green_20260728_multi_quota.json`）。

## 进度判断

| 里程碑 | 状态 |
|--------|------|
| P0/M1～M3 harness 主链路 | **已完成**（见 `progress-snapshot-20260728.md`） |
| Phase4 multi 并行 + elapsed | **已完成**（既有） |
| Phase4 multi 配额硬顶 | **本轮完成** |
| multi 配额后双机 pytest | **48=48 已对账** |
| 真机 Kali e2e 当日重跑 | **未在本切片重跑**（配额不改 lab 逻辑；沿用 `lab_reg_20260728*_acceptance.json`） |
| git baseline commit | **未做**（需负责人明确要求） |

## 推荐下一步（按优先级）

1. **若产品点名**：任务级 wall-clock / 资源配额（与 multi 配额不同层，需方案确认）。
2. **移交侧**：负责人决定是否做工作区 git baseline；根目录大 zip/杂项是否移出交付面。
3. **有环境且需保鲜**：可选新 `lab_reg_*` e2e（非 multi 配额强制项）。
