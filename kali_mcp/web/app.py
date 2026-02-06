#!/usr/bin/env python3
"""
Web应用模块

提供REST API和Web界面:
- 扫描管理API
- 实时进度WebSocket
- 报告查看
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

# 尝试导入Flask，如果不可用则提供占位符
try:
    from flask import Flask, jsonify, request, render_template_string
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    logger.warning("Flask未安装，Web界面功能不可用")


# HTML模板
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kali MCP Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #1a1a2e;
            color: #eee;
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        header h1 { font-size: 1.8em; }
        header p { opacity: 0.8; margin-top: 5px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card {
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            border: 1px solid #0f3460;
        }
        .card h2 {
            font-size: 1.2em;
            margin-bottom: 15px;
            color: #667eea;
            border-bottom: 1px solid #0f3460;
            padding-bottom: 10px;
        }
        .stat { display: flex; justify-content: space-between; margin: 10px 0; }
        .stat-value { font-weight: bold; color: #4ecca3; }
        .status-healthy { color: #4ecca3; }
        .status-degraded { color: #ffc107; }
        .status-unhealthy { color: #e94560; }
        .tool-list { max-height: 300px; overflow-y: auto; }
        .tool-item {
            display: flex;
            justify-content: space-between;
            padding: 8px;
            border-bottom: 1px solid #0f3460;
        }
        .tool-available { color: #4ecca3; }
        .tool-missing { color: #e94560; }
        .progress-bar {
            background: #0f3460;
            border-radius: 5px;
            height: 20px;
            overflow: hidden;
            margin-top: 10px;
        }
        .progress-fill {
            background: linear-gradient(90deg, #667eea, #764ba2);
            height: 100%;
            transition: width 0.3s;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 10px;
        }
        .btn:hover { opacity: 0.9; }
        .log-area {
            background: #0a0a15;
            border-radius: 5px;
            padding: 10px;
            font-family: monospace;
            font-size: 0.9em;
            max-height: 200px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Kali MCP Dashboard</h1>
            <p>智能安全测试平台</p>
        </header>

        <div class="grid">
            <div class="card">
                <h2>📊 系统状态</h2>
                <div class="stat">
                    <span>状态</span>
                    <span id="system-status" class="stat-value">加载中...</span>
                </div>
                <div class="stat">
                    <span>CPU使用率</span>
                    <span id="cpu-usage" class="stat-value">-</span>
                </div>
                <div class="stat">
                    <span>内存使用率</span>
                    <span id="memory-usage" class="stat-value">-</span>
                </div>
                <div class="stat">
                    <span>磁盘使用率</span>
                    <span id="disk-usage" class="stat-value">-</span>
                </div>
                <button class="btn" onclick="refreshHealth()">刷新状态</button>
            </div>

            <div class="card">
                <h2>🛠️ 工具统计</h2>
                <div class="stat">
                    <span>总执行次数</span>
                    <span id="total-executions" class="stat-value">0</span>
                </div>
                <div class="stat">
                    <span>成功次数</span>
                    <span id="total-successes" class="stat-value">0</span>
                </div>
                <div class="stat">
                    <span>成功率</span>
                    <span id="success-rate" class="stat-value">0%</span>
                </div>
                <div class="stat">
                    <span>缓存命中率</span>
                    <span id="cache-hit-rate" class="stat-value">0%</span>
                </div>
            </div>

            <div class="card">
                <h2>🔧 可用工具</h2>
                <div class="stat">
                    <span>核心工具</span>
                    <span id="core-tools" class="stat-value">-</span>
                </div>
                <div class="stat">
                    <span>可选工具</span>
                    <span id="optional-tools" class="stat-value">-</span>
                </div>
                <div class="tool-list" id="tool-list">
                    <p>加载中...</p>
                </div>
            </div>

            <div class="card">
                <h2>📈 活跃任务</h2>
                <div id="active-tasks">
                    <p>暂无活跃任务</p>
                </div>
            </div>
        </div>

        <div class="card" style="margin-top: 20px;">
            <h2>📝 最近活动</h2>
            <div class="log-area" id="activity-log">
                <p>等待活动...</p>
            </div>
        </div>
    </div>

    <script>
        async function refreshHealth() {
            try {
                const response = await fetch('/api/health');
                const data = await response.json();

                document.getElementById('system-status').textContent = data.status;
                document.getElementById('system-status').className = 'stat-value status-' + data.status;

                if (data.system) {
                    document.getElementById('cpu-usage').textContent = data.system.cpu_usage.toFixed(1) + '%';
                    document.getElementById('memory-usage').textContent = data.system.memory_usage.toFixed(1) + '%';
                    document.getElementById('disk-usage').textContent = data.system.disk_usage.toFixed(1) + '%';
                }

                if (data.summary) {
                    document.getElementById('core-tools').textContent =
                        data.summary.core_available + '/' + data.summary.core_total;
                    document.getElementById('optional-tools').textContent =
                        data.summary.optional_available + '/' + data.summary.optional_total;
                }
            } catch (e) {
                console.error('Failed to refresh health:', e);
            }
        }

        async function refreshMetrics() {
            try {
                const response = await fetch('/api/metrics');
                const data = await response.json();

                document.getElementById('total-executions').textContent = data.total_executions || 0;
                document.getElementById('total-successes').textContent = data.total_successes || 0;
                document.getElementById('success-rate').textContent =
                    ((data.overall_success_rate || 0) * 100).toFixed(1) + '%';
                document.getElementById('cache-hit-rate').textContent =
                    ((data.cache_hit_rate || 0) * 100).toFixed(1) + '%';
            } catch (e) {
                console.error('Failed to refresh metrics:', e);
            }
        }

        // 初始加载
        refreshHealth();
        refreshMetrics();

        // 定期刷新
        setInterval(refreshHealth, 30000);
        setInterval(refreshMetrics, 10000);
    </script>
</body>
</html>
"""


def create_app() -> Optional[Any]:
    """
    创建Flask应用

    Returns:
        Flask应用实例，如果Flask不可用则返回None
    """
    if not FLASK_AVAILABLE:
        logger.error("Flask未安装，无法创建Web应用")
        return None

    app = Flask(__name__)
    CORS(app)

    # 延迟导入以避免循环依赖
    from ..monitor import get_metrics_collector, get_health_checker
    from ..output import get_progress_tracker

    @app.route('/')
    def dashboard():
        """主页仪表板"""
        return render_template_string(DASHBOARD_TEMPLATE)

    @app.route('/api/health')
    def api_health():
        """健康检查API"""
        checker = get_health_checker()

        # 同步执行异步检查
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            report = loop.run_until_complete(checker.full_health_check())
        finally:
            loop.close()

        return jsonify(report)

    @app.route('/api/health/quick')
    def api_health_quick():
        """快速健康检查"""
        checker = get_health_checker()
        return jsonify(checker.get_quick_status())

    @app.route('/api/metrics')
    def api_metrics():
        """获取指标"""
        collector = get_metrics_collector()
        return jsonify(collector.get_summary())

    @app.route('/api/metrics/tools')
    def api_metrics_tools():
        """获取工具指标"""
        collector = get_metrics_collector()
        return jsonify(collector.get_all_tool_metrics())

    @app.route('/api/metrics/top')
    def api_metrics_top():
        """获取排名靠前的工具"""
        collector = get_metrics_collector()
        by = request.args.get('by', 'execution_count')
        limit = int(request.args.get('limit', 10))
        return jsonify(collector.get_top_tools(by=by, limit=limit))

    @app.route('/api/progress')
    def api_progress():
        """获取任务进度"""
        tracker = get_progress_tracker()
        return jsonify(tracker.get_all_progress())

    @app.route('/api/progress/active')
    def api_progress_active():
        """获取活跃任务"""
        tracker = get_progress_tracker()
        active = tracker.get_active_tasks()
        return jsonify([t.to_dict() for t in active])

    logger.info("Flask应用创建成功")
    return app


class WebServer:
    """Web服务器封装"""

    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        """
        初始化Web服务器

        Args:
            host: 监听地址
            port: 监听端口
        """
        self.host = host
        self.port = port
        self.app = create_app()

    def run(self, debug: bool = False):
        """
        启动服务器

        Args:
            debug: 是否启用调试模式
        """
        if self.app is None:
            logger.error("无法启动Web服务器: Flask未安装")
            return

        logger.info(f"启动Web服务器: http://{self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=debug)

    def get_app(self):
        """获取Flask应用"""
        return self.app
