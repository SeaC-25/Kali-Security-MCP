# 进度快照 2026-07-25

## Kali-Security-MCP（工程目录）

- 路径（本机）：`Kali-Security-MCP-main/Kali-Security-MCP-main`
- 路径（Kali）：`/home/zss/MCP-v2/Kali-Security-MCP-main`
- 单测：`tests/test_p0_harness.py` → **39 passed**（Windows 2026-07-27：含 status_check 工作区摘要）
- 主能力：图 / 四 surface / `run_surface_chain` / verify / handoff / observe / insight / ATT&CK / markdown 报告 / **result cache TTL** / **YAML recipes 试点** / **status_check 任务摘要**
- 默认 MCP profile：`harness`
- lab：`http://127.0.0.1:18081/`（`utils/lab/start_lab.sh`）
- 配方：`tools_recipes/{httpx,nmap,gobuster,whatweb,nuclei}.yaml`
- `status_check.py`：跨平台（Windows 无 emoji 崩溃）；第 6 节展示 nodes/edges/phase/verified/actions 日志与 report/handoff 路径
- 未做：docx、并行吞吐实测、更深 autonomous→insight

## 本地靶场验收

- Kali `192.168.157.8`，证据：`doc/lab-acceptance/`
- 18081 Web/登录闭环已绿；Docker 起 DVWA 仍受 docker.sock 权限阻塞

## 网络问题（OpenCode → API）

- 目标：`http://23.251.34.35:3000/v1`
- 主机：可连通（HTTP 有响应）
- VM：TCP 3000 open / ping 通；**curl 默认走 `192.168.157.1:7890` 代理被拒**
- 处理方向：去掉失效代理或对 API 设 `NO_PROXY` / `curl --noproxy "*"`
