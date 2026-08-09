# Crow5 Kali Research Lab

轻量本地靶场（仅 Python 标准库），给 harness 剧本研究用。

## 启动 / 停止

```bash
cd ~/MCP-v2/Kali-Security-MCP-main/utils/lab
bash start_lab.sh
bash stop_lab.sh
```

默认地址：`http://127.0.0.1:18081/`

## 路由

| 路径 | 说明 |
|------|------|
| `/` | 首页导航 |
| `/login` | 登录页（admin / admin123） |
| `/admin/` | 管理页（含 FLAG_LAB_OK） |
| `/admin/secret` | 需 cookie `lab_session=admin` |
| `/api/` `/api/health` `/api/v1/users` | JSON API |
| `/console` | 控制台登录样式页 |
| `/search?q=` | 反射查询（仅研究） |
| `/robots.txt` | robots |

## 对 harness 自测

单剧本：

```bash
cd ~/MCP-v2/Kali-Security-MCP-main
. .venv/bin/activate
export PYTHONPATH=$PWD
export KALI_MCP_WORKSPACE=$PWD/workspace
export KALI_MCP_HTTPX_BIN=/home/zss/go/bin/httpx
python - <<'PY'
from kali_mcp.core.local_executor import LocalCommandExecutor
from kali_mcp.core.playbooks import run_playbook
ex = LocalCommandExecutor(timeout=180)
for pb in ["web_surface", "api_surface", "auth_surface", "svc_surface"]:
    out = run_playbook(pb, f"lab_{pb}", "http://127.0.0.1:18081/", ex, depth="quick")
    print(pb, out.get("ok"), "findings", out.get("findings_total"))
PY
```

顺序串联（**不是** `run_goal`；与 MCP `run_surface_chain` 同一实现）：

```bash
cd ~/MCP-v2/Kali-Security-MCP-main
. .venv/bin/activate
export PYTHONPATH=$PWD KALI_MCP_WORKSPACE=$PWD/workspace KALI_MCP_HTTPX_BIN=/home/zss/go/bin/httpx
python utils/lab/run_chain.py http://127.0.0.1:18081/ lab_chain_manual
# 或在 harness profile 下调用 MCP 工具 run_surface_chain(task_id, target, depth="mixed")
```
