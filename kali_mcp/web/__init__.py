#!/usr/bin/env python3
"""
Kali MCP Web模块

提供Web可视化界面:
- API服务
- 实时进度显示
- 报告查看
"""

from .app import create_app, WebServer

__all__ = [
    "create_app",
    "WebServer",
]
