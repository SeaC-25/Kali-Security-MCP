# 进度快照 2026-07-27

## 单测

- 本地 Windows：`py -3 -m pytest tests/test_p0_harness.py -q` → **42 passed**
- Kali `192.168.157.8` venv：同命令 → **42 passed**

## 主链路回归（真机 lab，非 rpt_probe）

- task_id：`lab_no_enqueue_1`（此前 `lab_clean_queue_1` / `lab_reg_20260727` 仍可对照）
- target：`http://127.0.0.1:18081/`
- `run_surface_chain` depth=`mixed`：四 surface 均 ok；**6 verified**
- `report_md` 存在；`continue_ok=true`
- 终端态：`chain_done` + `REPORT`；continue 后 **不**改 `resumed`；`next_count_with_insights=0`
- insights：`created_count=5`（candidate only）；默认 **不** sticky 入队 `insight_verify`
- Observer 不含 `observer_analyze` 自引用
- 产物：`workspace/tasks/lab_no_enqueue_1/`

## handoff / insight 修复要点

- 空 next / 只读 / 仅 insight 残队列：不写 `status=resumed`
- 成功 chain 清空 next_checks + `last_tool=surface_chain`，防默认 recon 回流
- `propose_insights(..., enqueue_verify=False)` 为默认；MCP 可显式 true

## 口径

- 默认 profile：`harness`
- 无 `run_goal` 大包
- 合成任务 `rpt_probe` **不得**作交付证明
- 未做且不空口：docx、并行吞吐实测数字
