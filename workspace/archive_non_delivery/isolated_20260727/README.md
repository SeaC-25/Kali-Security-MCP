# 非交付任务隔离区

以下目录从 `workspace/tasks/` 移出，**不得**作为验收或移交证据：

- `rpt_probe` — 文档明确禁止的 probe 任务
- `chain_clear_dbg` / `dbg_next` — 调试残留，完成态可能与 verified/edges 不一致

真验收请用 `lab_reg_*` 任务或 `doc/lab-acceptance/*.json`。
隔离日期（UTC）：2026-07-27T18:24:38.374886+00:00
