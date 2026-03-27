#!/usr/bin/env python3
"""
双层并行调度器 - Kali MCP 并行执行核心

层一（被动并行）：ToolWorkerPool
    每次 MCP 工具调用都在独立 worker 线程中执行，互不阻塞。
    blocking=True  → 等待结果（与原 execute_tool_with_data 接口一致）
    blocking=False → 返回 task_id，调用方之后 poll

层二（主动并行）：AgentBoundExecutor
    高级工具（ORCHESTRATED_TOOLS）调用时，通过 AgentCoordinator 拆解为
    子任务，每个子任务并发提交到 ToolWorkerPool 执行，汇总结果。
    AgentCoordinator 不可用时自动降级到单线程串行执行。
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from typing import Dict, Any, Callable, Optional, List

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 工具 → Agent category 亲和映射
# ---------------------------------------------------------------------------
TOOL_AGENT_AFFINITY: Dict[str, str] = {
    # 侦察类
    "nmap_scan":              "information_gathering",
    "masscan_fast_scan":      "information_gathering",
    "subfinder_scan":         "information_gathering",
    "dnsrecon_scan":          "information_gathering",
    "netdiscover_scan":       "information_gathering",
    "arp_scan":               "information_gathering",
    "fping_scan":             "information_gathering",
    "enum4linux_scan":        "information_gathering",
    # Web 侦察
    "gobuster_scan":          "web_recon",
    "ffuf_scan":              "web_recon",
    "whatweb_scan":           "web_recon",
    "nikto_scan":             "web_recon",
    "wfuzz_scan":             "web_recon",
    "dirb_scan":              "web_recon",
    "feroxbuster_scan":       "web_recon",
    "wpscan_scan":            "web_recon",
    "joomscan_scan":          "web_recon",
    # 漏洞发现
    "nuclei_scan":            "vulnerability_discovery",
    "nuclei_cve_scan":        "vulnerability_discovery",
    "nuclei_web_scan":        "vulnerability_discovery",
    "nuclei_network_scan":    "vulnerability_discovery",
    "sqlmap_scan":            "vulnerability_discovery",
    # 利用
    "metasploit_run":         "exploitation",
    "hydra_attack":           "exploitation",
    "medusa_attack":          "exploitation",
    "ncrack_attack":          "exploitation",
    "patator_attack":         "exploitation",
    "crowbar_attack":         "exploitation",
    # PWN 专项
    "pwnpasi_auto_pwn":       "pwn",
    "pwn_comprehensive_attack": "pwn",
    "ctf_pwn_solver":         "pwn",
    # 密码破解
    "john_crack":             "specialized",
    "hashcat_crack":          "specialized",
    "aircrack_attack":        "specialized",
    # 取证
    "forensics_full_analysis": "forensics",
    "stego_detect":           "forensics",
    "memory_forensics":       "forensics",
    "binwalk_analysis":       "forensics",
    # OSINT
    "theharvester_osint":     "information_gathering",
    "sherlock_search":        "information_gathering",
    "amass_scan":             "information_gathering",
    "sublist3r_scan":         "information_gathering",
}

# 触发层二任务分解的高级工具集合
ORCHESTRATED_TOOLS = {
    "auto_pentest",
    "smart_full_pentest",
    "intelligent_ctf_solver",
    "apt_comprehensive_attack",
    "apt_web_application_attack",
    "apt_network_penetration",
    "intelligent_attack_with_poc",
    "auto_ctf_solve_with_poc",
    "ctf_ultimate_solve",
    "intelligent_penetration_testing",
    "auto_web_security_workflow",
    "auto_network_discovery_workflow",
    "smart_web_recon",
    "smart_network_recon",
    "smart_ctf_solve",
    "comprehensive_network_scan",
    "advanced_web_security_assessment",
}


# ---------------------------------------------------------------------------
# 层一：ToolWorkerPool
# ---------------------------------------------------------------------------

class ToolWorkerPool:
    """
    层一被动并行池。

    每次工具调用 submit() 到线程池，所有调用互不阻塞。
    blocking=True  → 等待结果，接口与原 execute_tool_with_data 完全一致。
    blocking=False → 立即返回 task_id，调用方之后调用 get_result(task_id)。
    """

    def __init__(self, max_workers: int = 32):
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="kali-tool-worker",
        )
        self._futures: Dict[str, Future] = {}
        self._lock = threading.Lock()
        logger.info(f"ToolWorkerPool 初始化完成，max_workers={max_workers}")

    def submit(
        self,
        tool_name: str,
        executor_fn: Callable,
        data: Dict[str, Any],
        blocking: bool = True,
        task_id: Optional[str] = None,
    ) -> Any:
        """
        提交工具调用到线程池。

        Args:
            tool_name:   工具名称
            executor_fn: LocalCommandExecutor.execute_tool_with_data
            data:        工具参数
            blocking:    True=等待结果并返回，False=返回 task_id
            task_id:     blocking=False 时用于 poll 的 key
        """
        fut = self._pool.submit(executor_fn, tool_name, data)

        if blocking:
            return fut.result()

        key = task_id or f"{tool_name}_{id(fut)}"
        with self._lock:
            self._futures[key] = fut
        return key

    def get_result(self, task_id: str, timeout: Optional[float] = None) -> Optional[Dict]:
        """获取异步任务结果，任务不存在时返回 None。"""
        with self._lock:
            fut = self._futures.get(task_id)
        if fut is None:
            return None
        return fut.result(timeout=timeout)

    def is_done(self, task_id: str) -> bool:
        """检查异步任务是否完成。"""
        with self._lock:
            fut = self._futures.get(task_id)
        return fut is not None and fut.done()

    def shutdown(self, wait: bool = False):
        self._pool.shutdown(wait=wait)


# ---------------------------------------------------------------------------
# 层二：AgentBoundExecutor
# ---------------------------------------------------------------------------

class AgentBoundExecutor:
    """
    层二主动并行执行器。

    对 ORCHESTRATED_TOOLS 中的高级工具：
    1. 尝试用 AgentCoordinator 做意图分析 + 任务分解
    2. 将子任务并发提交到 ToolWorkerPool
    3. 汇总所有子任务结果后返回

    AgentCoordinator 不可用或分解失败时，自动降级到
    ToolWorkerPool 的单次阻塞调用（行为与原串行执行一致）。
    """

    def __init__(
        self,
        coordinator,          # AgentCoordinator 实例，可为 None
        worker_pool: ToolWorkerPool,
        executor_fn: Callable,  # LocalCommandExecutor.execute_tool_with_data
    ):
        self._coordinator = coordinator
        self._pool = worker_pool
        self._executor_fn = executor_fn

    def run_orchestrated(
        self,
        tool_name: str,
        data: Dict[str, Any],
        subtask_timeout: float = 300.0,
    ) -> Dict[str, Any]:
        """
        分解并并发执行高级工具。

        Returns:
            {
                'success': bool,
                'orchestrated': True,
                'sub_tasks': int,
                'results': List[{'task': str, 'result': dict}],
            }
            降级时返回原 execute_tool_with_data 的结果。
        """
        if self._coordinator is None:
            logger.debug(f"AgentCoordinator 不可用，{tool_name} 降级到单线程执行")
            return self._pool.submit(tool_name, self._executor_fn, data, blocking=True)

        # 尝试任务分解
        sub_tasks = self._decompose(tool_name, data)
        if not sub_tasks:
            logger.debug(f"{tool_name} 任务分解返回空，降级到单线程执行")
            return self._pool.submit(tool_name, self._executor_fn, data, blocking=True)

        logger.info(f"[ParallelDispatcher] {tool_name} 分解为 {len(sub_tasks)} 个子任务，并发执行")

        # 并发提交所有子任务
        future_map: Dict[Future, Dict] = {}
        for task in sub_tasks:
            t_name = task.get("tool_name", tool_name)
            t_data = task.get("parameters", data)
            fut = self._pool._pool.submit(self._executor_fn, t_name, t_data)
            future_map[fut] = task

        # 汇总结果
        results: List[Dict] = []
        for fut in as_completed(future_map, timeout=subtask_timeout):
            task_meta = future_map[fut]
            try:
                result = fut.result()
                results.append({"task": task_meta.get("name", ""), "result": result})
            except Exception as e:
                results.append({"task": task_meta.get("name", ""), "error": str(e)})
                logger.debug(f"子任务 {task_meta.get('name')} 失败: {e}")

        success = any(
            r.get("result", {}).get("success") for r in results
        )
        return {
            "success": success,
            "orchestrated": True,
            "sub_tasks": len(sub_tasks),
            "results": results,
        }

    def _decompose(self, tool_name: str, data: Dict[str, Any]) -> List[Dict]:
        """
        调用 AgentCoordinator 做任务分解，返回子任务列表。
        失败时返回空列表（触发降级）。

        子任务格式：{'name': str, 'tool_name': str, 'parameters': dict}
        """
        try:
            target = data.get("target", "")
            # AgentCoordinator.decompose_task() 返回 TaskGraph
            # 兼容两种可能的接口名
            if hasattr(self._coordinator, "decompose_task"):
                task_graph = self._coordinator.decompose_task(target, tool_name, data)
            elif hasattr(self._coordinator, "create_execution_plan"):
                task_graph = self._coordinator.create_execution_plan(target, tool_name, data)
            else:
                return []

            tasks = getattr(task_graph, "tasks", []) or []
            result = []
            for t in tasks:
                result.append({
                    "name": getattr(t, "name", str(t)),
                    "tool_name": getattr(t, "tool_name", tool_name),
                    "parameters": getattr(t, "parameters", data),
                })
            return result
        except Exception as e:
            logger.debug(f"任务分解失败（将降级）: {e}")
            return []


# ---------------------------------------------------------------------------
# 公共工厂函数
# ---------------------------------------------------------------------------

def make_parallel_execute(
    orig_fn: Callable,
    coordinator=None,
    max_workers: int = 32,
) -> tuple:
    """
    工厂函数：创建 ToolWorkerPool + AgentBoundExecutor，
    返回 (pool, agent_executor, parallel_execute_fn)。

    parallel_execute_fn 签名与 execute_tool_with_data 完全一致：
        fn(tool_name: str, data: dict) -> dict
    """
    pool = ToolWorkerPool(max_workers=max_workers)
    agent_exec = AgentBoundExecutor(
        coordinator=coordinator,
        worker_pool=pool,
        executor_fn=orig_fn,
    )

    def parallel_execute(tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name in ORCHESTRATED_TOOLS and coordinator is not None:
            return agent_exec.run_orchestrated(tool_name, data)
        return pool.submit(tool_name, orig_fn, data, blocking=True)

    return pool, agent_exec, parallel_execute
