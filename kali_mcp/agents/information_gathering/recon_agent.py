#!/usr/bin/env python3
"""
侦察智能体 (ReconAgent)

负责信息收集和侦察：
- 端口扫描和服务识别
- 网络拓扑发现
- 技术栈识别
- 操作系统指纹识别

集成工具：20个
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from kali_mcp.agents.base_agent_v2 import AgentCapability, LoadReport
from kali_mcp.agents.llm_agent_base import LLMAgentBase, MissionTicket
from kali_mcp.core.task_decomposer import Task, TaskCategory
from kali_mcp.core.result_aggregator import AgentResult, Finding, ResultType, ResultSeverity

logger = logging.getLogger(__name__)


class ReconPhase(Enum):
    """侦察阶段"""
    PORT_SCANNING = "port_scanning"           # 端口扫描
    SERVICE_ENUM = "service_enum"               # 服务枚举
    OS_FINGERPRINT = "os_fingerprint"           # 操作系统指纹
    TECH_DETECT = "tech_detect"                 # 技术检测
    TOPOLOGY = "topology"                       # 拓扑发现


@dataclass
class ReconTarget:
    """侦察目标"""
    target: str                                 # 目标（IP、域名、URL）
    target_type: str                             # 目标类型
    priority: int                                # 优先级
    phases: List[ReconPhase]                    # 侦察阶段列表


class ReconAgent(LLMAgentBase):
    """
    侦察智能体

    专门负责信息收集和侦察工作，包括：
    - 端口扫描（nmap, masscan）
    - 服务识别（版本检测）
    - 操作系统指纹识别
    - 网络拓扑发现
    - 技术栈识别
    """

    ROLE_PROMPT = (
        "ReconAgent，负责信息收集与侦察的专业评估代理。"
        "目标：识别开放端口、服务与版本、操作系统指纹、技术栈与网络拓扑。"
        "可用工具边界：nmap_scan / masscan_scan / masscan_fast_scan / arp_scan / "
        "fping_scan / netdiscover_scan / fastsec_scan / whatweb_scan / whatweb_identify / "
        "httpx_probe / onesixtyone_scan / comprehensive_network_scan / tshark_capture / ngrep_search。"
        "回报标准：收集到足以判断目标暴露面的技术事实即 done；"
        "done 时 structured_summary.findings 每项给出 title / severity / confidence / evidence，"
        "evidence 必须来自真实工具输出。"
    )

    def __init__(self, message_bus=None, tool_registry=None, executor=None,
                 brain=None, retriever=None, dag_service=None):
        # 创建能力对象
        capabilities = AgentCapability(
            name="reconnaissance",
            category="information_gathering",
            supported_tools={
                # 端口扫描工具
                "nmap_scan", "masscan_scan", "masscan_fast_scan",
                "arp_scan", "fping_scan", "netdiscover_scan",

                # 服务识别/技术检测（fastsec -cms / -fingerprint，替代 whatweb/httpx）
                "fastsec_scan",
                "whatweb_scan", "whatweb_identify", "httpx_probe",

                # 网络发现工具
                "onesixtyone_scan",

                # 综合扫描
                "comprehensive_network_scan",

                # 其他侦察工具
                "tshark_capture", "ngrep_search"
            },
            max_concurrent_tasks=5,
            specialties=["reconnaissance", "port_scanning", "service_enum"]
        )

        super().__init__(
            agent_id="recon_agent",
            name="Reconnaissance Agent",
            message_bus=message_bus,
            capabilities=capabilities,
            tool_registry=tool_registry,
            executor=executor,
            brain=brain,
            retriever=retriever,
            dag_service=dag_service
        )

        # 侦察配置
        self.scan_priorities = {
            "quick": ["80", "443", "22", "21", "23", "25", "53", "110", "143", "3306", "3389", "8080"],
            "standard": "1-1000",
            "comprehensive": "1-65535"
        }

        logger.info("ReconAgent初始化完成")

    # ==================== BaseAgent抽象方法实现 ====================

    def handle_message(self, message):
        """
        处理接收到的消息（BaseAgent抽象方法）

        Args:
            message: AgentMessage对象
        """
        # 记录接收到的消息
        logger.info(f"[{self.agent_id}] 收到消息: {message.type.value} 来自 {message.sender}")

        # 根据消息类型处理
        from kali_mcp.core.ctf_agent_framework import MessageType

        if message.type == MessageType.TASK:
            # 任务消息 - 可以触发新的侦察任务
            logger.info(f"收到任务消息: {message.content}")
        elif message.type == MessageType.STATUS:
            # 状态消息
            logger.debug(f"收到状态更新: {message.content}")
        elif message.type == MessageType.ERROR:
            # 错误消息
            logger.warning(f"收到错误消息: {message.content}")
        else:
            # 其他消息类型
            logger.debug(f"收到消息: {message.type}")

    async def run(self, context):
        """
        执行Agent任务（BaseAgent抽象方法）

        Args:
            context: AgentContext对象

        Returns:
            执行结果字典
        """
        logger.info(f"[{self.agent_id}] 开始执行任务")

        # 从context中获取参数
        target = context.parameters.get("target", "") if hasattr(context, 'parameters') else ""

        if not target:
            return {
                "success": False,
                "error": "未指定目标"
            }

        # 执行标准侦察流程
        try:
            # 1. 端口扫描
            logger.info(f"开始端口扫描: {target}")
            # 这里应该调用实际的扫描工具
            # 目前返回模拟结果
            port_scan_result = await self._call_tool("nmap_scan", {"target": target})

            # 2. 服务识别（fastsec -cms 技术栈识别）
            logger.info(f"开始服务识别: {target}")
            service_scan_result = await self._call_tool("fastsec_scan", {
                "cms": target
            })

            return {
                "success": True,
                "target": target,
                "port_scan": port_scan_result[:100] + "..." if len(port_scan_result) > 100 else port_scan_result,
                "service_scan": service_scan_result[:100] + "..." if len(service_scan_result) > 100 else service_scan_result
            }

        except Exception as e:
            logger.error(f"执行任务失败: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    # ==================== Task对象支持（BaseAgentV2）====================

    async def execute_task_with_task_obj(self, task: Task) -> AgentResult:
        """
        执行侦察任务

        Args:
            task: 任务对象

        Returns:
            AgentResult: 执行结果
        """
        start_time = datetime.now()
        output = ""
        parsed_findings = []
        errors = []
        success = False

        try:
            target = task.parameters.get("target", "")
            scan_type = task.parameters.get("scan_type", "standard")

            logger.info(f"开始侦察目标: {target}, 工具: {task.tool_name}")

            # 调用内部实现方法获取输出
            output = await self._execute_task_impl(
                task_type=task.tool_name,
                task_data=task.parameters,
                task_id=task.task_id
            )

            # LLM 自主路径：_execute_task_impl 已返回最终 AgentResult，直接透传
            if isinstance(output, AgentResult):
                return output

            # 解析结果（工具失败/被拒绝的输出不得生成 finding）
            if self.is_tool_failure_output(output):
                errors.append(output[:300])
            else:
                parsed_findings = self._parse_recon_output(
                    task.tool_name,
                    output,
                    target
                )
                success = True

        except Exception as e:
            error_msg = f"侦察任务执行失败: {str(e)}"
            logger.error(error_msg, exc_info=True)
            errors.append(error_msg)
            output = str(e)

        # 计算执行时间
        execution_time = (datetime.now() - start_time).total_seconds()

        return AgentResult(
            agent_id=self.agent_id,
            task_id=task.task_id,
            tool_name=task.tool_name,
            target=task.parameters.get("target", ""),
            success=success,
            execution_time=execution_time,
            output=output,
            parsed_data={"findings": [self._finding_to_dict(f) for f in parsed_findings]},
            findings=parsed_findings,
            errors=errors
        )

    def _parse_tool_output(
        self,
        tool_name: str,
        output: str,
        target: str
    ) -> List[Finding]:
        """LLM 自主路径的证据提炼：复用确定性正则解析器（LLM 决定调什么，正则提炼证据）。"""
        return self._parse_recon_output(tool_name, output, target)

    def _parse_recon_output(
        self,
        tool_name: str,
        output: str,
        target: str
    ) -> List[Finding]:
        """解析侦察输出"""
        findings = []

        # 解析nmap输出（fastsec -scan 端口扫描同格式兜底）
        if tool_name in ("nmap_scan", "masscan_fast_scan", "masscan_scan", "fastsec_scan"):
            findings.extend(self._parse_port_scan_output(output, target))

        # 解析whatweb输出（fastsec -cms / -fingerprint 技术识别兜底）
        if tool_name in ("whatweb_scan", "whatweb_identify", "httpx_probe", "fastsec_scan"):
            findings.extend(self._parse_tech_detect_output(output, target))

        # 解析arp扫描输出
        if tool_name == "arp_scan":
            findings.extend(self._parse_arp_scan_output(output, target))

        return findings

    def _parse_port_scan_output(self, output: str, target: str) -> List[Finding]:
        """解析端口扫描输出"""
        findings = []

        import re

        # 匹配开放端口
        port_pattern = re.compile(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)')

        for match in port_pattern.finditer(output):
            port = match.group(1)
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4).strip()

            # 提取版本信息
            version = ""
            if " " in service:
                parts = service.split(" ", 1)
                service_name = parts[0]
                if len(parts) > 1:
                    version = parts[1]
            else:
                service_name = service

            findings.append(Finding(
                finding_type=ResultType.ASSET,
                severity=ResultSeverity.INFO,
                title=f"开放端口: {port}/{protocol}",
                description=f"发现 {service_name} 服务运行在 {target}:{port}",
                evidence=[f"{port}/{protocol} {state} {service}"],
                source=self.agent_id,
                confidence=0.95
            ))

        # 检测操作系统指纹
        os_pattern = re.compile(r'OS details:\s+(.+)')
        os_match = os_pattern.search(output)
        if os_match:
            findings.append(Finding(
                finding_type=ResultType.INFO,
                severity=ResultSeverity.INFO,
                title="操作系统识别",
                description=f"目标操作系统: {os_match.group(1)}",
                evidence=[os_match.group(0)],
                source=self.agent_id,
                confidence=0.8
            ))

        return findings

    def _parse_tech_detect_output(self, output: str, target: str) -> List[Finding]:
        """解析技术检测输出"""
        findings = []

        # whatweb输出格式: "Technology, Version, ... "
        # fastsec -cms/-fingerprint 输出头（[cms] / [fingerprint] / 其他模式头）跳过
        skip_prefixes = ("[cms]", "[fingerprint]", "[portscan]", "[osint]",
                         "[brute]", "[injector]", "[username]", "[+]", "[-]",
                         "===", "提取:")
        lines = output.split('\n')
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('|') and not stripped.startswith('+') \
                    and not stripped.startswith(skip_prefixes):
                # 提取技术栈信息
                parts = stripped.split(',')
                if len(parts) >= 1:
                    tech = parts[0].strip()
                    findings.append(Finding(
                        finding_type=ResultType.INFO,
                        severity=ResultSeverity.INFO,
                        title=f"检测到技术: {tech}",
                        description=f"目标 {target} 使用 {tech}",
                        evidence=[stripped],
                        source=self.agent_id,
                        confidence=0.85
                    ))

        return findings

    def _parse_arp_scan_output(self, output: str, target: str) -> List[Finding]:
        """解析ARP扫描输出"""
        findings = []

        import re

        # 支持多种ARP扫描输出格式
        # 格式1: "IP: 192.168.1.1    MAC: 00:11:22:33:44:55"
        # 格式2: "192.168.1.1    00:11:22:33:44:55"
        # 格式3: "192.168.1.1 at 00:11:22:33:44:55"

        ip_mac_patterns = [
            re.compile(r'IP:\s*(\d+\.\d+\.\d+\.\d+)\s+MAC:\s*([0-9A-Fa-f:]{17})', re.IGNORECASE),
            re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})'),
            re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+at\s+([0-9A-Fa-f:]{17})', re.IGNORECASE)
        ]

        for pattern in ip_mac_patterns:
            for match in pattern.finditer(output):
                ip = match.group(1)
                mac = match.group(2)

                # 检查是否已经记录过这个IP
                if not any(f"发现主机: {ip}" == existing_find.title for existing_find in findings):
                    findings.append(Finding(
                        finding_type=ResultType.ASSET,
                        severity=ResultSeverity.INFO,
                        title=f"发现主机: {ip}",
                        description=f"MAC地址: {mac}",
                        evidence=[f"{ip} -> {mac}"],
                        source=self.agent_id,
                        confidence=0.95
                    ))

        return findings

    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """将Finding对象转换为字典"""
        return {
            "type": finding.finding_type.value,
            "severity": finding.severity.value,
            "title": finding.title,
            "description": finding.description,
            "evidence": finding.evidence,
            "confidence": finding.confidence
        }

    async def report_load(self) -> LoadReport:
        """报告负载"""
        # 调用父类的report_load方法
        return super().report_load()

    # ==================== BaseAgentV2抽象方法实现 ====================

    async def _execute_task_impl(
        self,
        task_type: str,
        task_data: Dict[str, Any],
        task_id: str
    ) -> Any:
        """执行任务实现（BaseAgentV2抽象方法）—— LLM 自主 / legacy 规则路由。

        brain 可用且 task_data 显式开启 llm_autonomous → LLM 决策循环；
        否则回退到旧 if/else 规则路径（降级安全，不空转）。
        """
        if self.brain.available and task_data.get("llm_autonomous"):
            return await self.llm_drive_mission(MissionTicket.from_task(task_data))
        return await self._execute_task_impl_legacy(task_type, task_data, task_id)

    async def _execute_task_impl_legacy(
        self,
        task_type: str,
        task_data: Dict[str, Any],
        task_id: str
    ) -> Any:
        """
        旧规则路径（架构设计 §3.3 降级保留）：根据工具类型调用相应的执行方法
        """
        if task_type == "nmap_scan":
            return await self._execute_nmap_scan_impl(task_data)
        elif task_type in ("masscan_fast_scan", "masscan_scan"):
            return await self._execute_masscan_scan_impl(task_data)
        elif task_type in ("whatweb_scan", "whatweb_identify", "httpx_probe"):
            return await self._execute_fastsec_cms_impl(task_data)
        elif task_type == "fastsec_scan":
            return await self._execute_fastsec_scan_impl(task_data)
        elif task_type == "arp_scan":
            return await self._execute_arp_scan_impl(task_data)
        elif task_type == "comprehensive_network_scan":
            return await self._execute_comprehensive_scan_impl(task_data)
        else:
            # 通用工具调用
            return await self._call_tool(task_type, task_data)

    async def _execute_nmap_scan_impl(self, parameters: Dict[str, Any]) -> str:
        """执行nmap扫描（内部实现）"""
        target = parameters.get("target", "")
        ports = parameters.get("ports", self.scan_priorities["standard"])
        scan_type = parameters.get("scan_type", "-sV")

        return await self._call_tool("nmap_scan", {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": "-T4"  # 快速扫描
        })

    async def _execute_masscan_scan_impl(self, parameters: Dict[str, Any]) -> str:
        """执行快速端口扫描（fastsec -scan，替代 masscan）"""
        target = parameters.get("target", parameters.get("scan", ""))
        ports = parameters.get("ports", "80,443,22,21,25,53,110,143,443,8080,3389")
        rate = parameters.get("rate", "10000")

        return await self._call_tool("fastsec_scan", {
            "scan": target,
            "ports": ports,
            "rate": rate
        })

    async def _execute_fastsec_cms_impl(self, parameters: Dict[str, Any]) -> str:
        """执行技术/CMS识别（fastsec -cms，替代 whatweb/httpx）"""
        target = parameters.get("target", parameters.get("cms", parameters.get("fingerprint", "")))
        aggression = parameters.get("aggression", "1")

        return await self._call_tool("fastsec_scan", {
            "cms": target,
            "delay_min": 10,
            "delay_max": 30
        })

    async def _execute_fastsec_scan_impl(self, parameters: Dict[str, Any]) -> str:
        """执行 fastsec 统一扫描（按模式参数路由）"""
        if parameters.get("scan"):
            return await self._execute_masscan_scan_impl(parameters)
        elif parameters.get("cms") or parameters.get("fingerprint"):
            return await self._execute_fastsec_cms_impl(parameters)
        elif parameters.get("dir"):
            return await self._call_tool("fastsec_scan", {
                "dir": parameters.get("dir", parameters.get("url", "")),
                "delay_min": 10,
                "delay_max": 30
            })
        else:
            return await self._call_tool("fastsec_scan", parameters)

    async def _execute_arp_scan_impl(self, parameters: Dict[str, Any]) -> str:
        """执行ARP扫描（内部实现）"""
        target = parameters.get("network", "local")
        interface = parameters.get("interface", "")

        return await self._call_tool("arp_scan", {
            "interface": interface,
            "network": target
        })

    async def _execute_comprehensive_scan_impl(self, parameters: Dict[str, Any]) -> str:
        """执行综合网络扫描（内部实现）"""
        target = parameters.get("target", "")
        deep_scan = parameters.get("deep_scan", False)

        return await self._call_tool("comprehensive_network_scan", {
            "target": target,
            "deep_scan": deep_scan
        })

    def get_scan_priority(self, urgency: str) -> str:
        """获取扫描端口范围"""
        return self.scan_priorities.get(urgency, self.scan_priorities["standard"])

    async def plan_reconnaissance(
        self,
        target: str,
        urgency: str = "standard",
        phases: Optional[List[ReconPhase]] = None
    ) -> List[Task]:
        """
        规划侦察任务

        Args:
            target: 目标
            urgency: 紧急程度 (quick, standard, comprehensive)
            phases: 侦察阶段列表

        Returns:
            任务列表
        """
        if phases is None:
            phases = [
                ReconPhase.PORT_SCANNING,
                ReconPhase.SERVICE_ENUM,
                ReconPhase.TECH_DETECT
            ]

        tasks = []
        task_id = 0

        for phase in phases:
            if phase == ReconPhase.PORT_SCANNING:
                tasks.append(Task(
                    task_id=f"recon_{task_id}",
                    name=f"端口扫描: {target}",
                    category=TaskCategory.RECONNAISSANCE,
                    tool_name="nmap_scan",
                    parameters={
                        "target": target,
                        "scan_type": "-sV",
                        "ports": self.get_scan_priority(urgency)
                    },
                    priority=8 if urgency == "quick" else 7,
                    estimated_duration=120 if urgency == "quick" else 300,
                    tags=["recon", "port_scan"]
                ))

            elif phase == ReconPhase.SERVICE_ENUM:
                tasks.append(Task(
                    task_id=f"recon_{task_id}",
                    name=f"服务枚举: {target}",
                    category=TaskCategory.SCANNING,
                    tool_name="fastsec_scan",
                    parameters={
                        "cms": target
                    },
                    priority=7,
                    estimated_duration=60,
                    tags=["recon", "service_enum"]
                ))

            elif phase == ReconPhase.TECH_DETECT:
                tasks.append(Task(
                    task_id=f"recon_{task_id}",
                    name=f"技术检测: {target}",
                    category=TaskCategory.SCANNING,
                    tool_name="fastsec_scan",
                    parameters={
                        "fingerprint": target
                    },
                    priority=6,
                    estimated_duration=30,
                    tags=["recon", "tech_detect"]
                ))

            elif phase == ReconPhase.TOPOLOGY:
                tasks.append(Task(
                    task_id=f"recon_{task_id}",
                    name=f"网络拓扑: {target}",
                    category=TaskCategory.RECONNAISSANCE,
                    tool_name="arp_scan",
                    parameters={
                        "network": target
                    },
                    priority=5,
                    estimated_duration=60,
                    tags=["recon", "topology"]
                ))

            task_id += 1

        return tasks
