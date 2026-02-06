#!/usr/bin/env python3
"""
性能指标收集模块

收集和统计系统性能指标:
- 工具执行时间
- 成功率统计
- 资源使用情况
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class ToolMetric:
    """工具指标"""
    tool_name: str
    execution_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    total_execution_time: float = 0
    min_execution_time: float = float('inf')
    max_execution_time: float = 0
    total_findings: int = 0

    @property
    def avg_execution_time(self) -> float:
        """平均执行时间"""
        if self.execution_count == 0:
            return 0
        return self.total_execution_time / self.execution_count

    @property
    def success_rate(self) -> float:
        """成功率"""
        if self.execution_count == 0:
            return 0
        return self.success_count / self.execution_count

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "tool_name": self.tool_name,
            "execution_count": self.execution_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": self.success_rate,
            "avg_execution_time": self.avg_execution_time,
            "min_execution_time": self.min_execution_time if self.min_execution_time != float('inf') else 0,
            "max_execution_time": self.max_execution_time,
            "total_findings": self.total_findings
        }


@dataclass
class SystemMetric:
    """系统指标"""
    timestamp: float
    active_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    cache_hits: int = 0
    cache_misses: int = 0


class MetricsCollector:
    """指标收集器"""

    def __init__(self):
        """初始化指标收集器"""
        self.tool_metrics: Dict[str, ToolMetric] = {}
        self.system_metrics: List[SystemMetric] = []
        self._lock = threading.Lock()

        # 计数器
        self.total_executions = 0
        self.total_successes = 0
        self.total_failures = 0
        self.cache_hits = 0
        self.cache_misses = 0

        # 时间窗口统计（最近1小时）
        self.recent_executions: List[Dict[str, Any]] = []
        self.window_size = 3600  # 1小时

        logger.info("MetricsCollector 初始化完成")

    def record_execution(
        self,
        tool_name: str,
        success: bool,
        execution_time: float,
        findings_count: int = 0
    ):
        """
        记录工具执行

        Args:
            tool_name: 工具名称
            success: 是否成功
            execution_time: 执行时间（秒）
            findings_count: 发现数量
        """
        with self._lock:
            # 更新工具指标
            if tool_name not in self.tool_metrics:
                self.tool_metrics[tool_name] = ToolMetric(tool_name=tool_name)

            metric = self.tool_metrics[tool_name]
            metric.execution_count += 1
            metric.total_execution_time += execution_time
            metric.min_execution_time = min(metric.min_execution_time, execution_time)
            metric.max_execution_time = max(metric.max_execution_time, execution_time)
            metric.total_findings += findings_count

            if success:
                metric.success_count += 1
                self.total_successes += 1
            else:
                metric.failure_count += 1
                self.total_failures += 1

            self.total_executions += 1

            # 记录到时间窗口
            self.recent_executions.append({
                "tool": tool_name,
                "success": success,
                "time": execution_time,
                "findings": findings_count,
                "timestamp": time.time()
            })

            # 清理过期记录
            self._cleanup_old_records()

        logger.debug(f"记录执行: {tool_name} - 成功={success}, 耗时={execution_time:.2f}s")

    def record_cache_hit(self):
        """记录缓存命中"""
        with self._lock:
            self.cache_hits += 1

    def record_cache_miss(self):
        """记录缓存未命中"""
        with self._lock:
            self.cache_misses += 1

    def _cleanup_old_records(self):
        """清理过期记录"""
        cutoff = time.time() - self.window_size
        self.recent_executions = [
            r for r in self.recent_executions
            if r["timestamp"] > cutoff
        ]

    def get_tool_metrics(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """获取工具指标"""
        with self._lock:
            metric = self.tool_metrics.get(tool_name)
            if metric:
                return metric.to_dict()
            return None

    def get_all_tool_metrics(self) -> Dict[str, Dict[str, Any]]:
        """获取所有工具指标"""
        with self._lock:
            return {
                name: metric.to_dict()
                for name, metric in self.tool_metrics.items()
            }

    def get_top_tools(
        self,
        by: str = "execution_count",
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        获取排名靠前的工具

        Args:
            by: 排序字段 (execution_count, success_rate, avg_execution_time)
            limit: 返回数量

        Returns:
            工具列表
        """
        with self._lock:
            metrics = [m.to_dict() for m in self.tool_metrics.values()]

            reverse = by != "avg_execution_time"  # 执行时间越短越好
            metrics.sort(key=lambda x: x.get(by, 0), reverse=reverse)

            return metrics[:limit]

    def get_summary(self) -> Dict[str, Any]:
        """获取汇总统计"""
        with self._lock:
            # 计算缓存命中率
            total_cache = self.cache_hits + self.cache_misses
            cache_hit_rate = self.cache_hits / total_cache if total_cache > 0 else 0

            # 计算最近1小时的统计
            recent_success = sum(1 for r in self.recent_executions if r["success"])
            recent_total = len(self.recent_executions)
            recent_success_rate = recent_success / recent_total if recent_total > 0 else 0

            return {
                "total_executions": self.total_executions,
                "total_successes": self.total_successes,
                "total_failures": self.total_failures,
                "overall_success_rate": self.total_successes / self.total_executions if self.total_executions > 0 else 0,
                "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses,
                "cache_hit_rate": cache_hit_rate,
                "tools_tracked": len(self.tool_metrics),
                "recent_executions": recent_total,
                "recent_success_rate": recent_success_rate
            }

    def get_execution_trend(
        self,
        interval_minutes: int = 5
    ) -> List[Dict[str, Any]]:
        """
        获取执行趋势

        Args:
            interval_minutes: 时间间隔（分钟）

        Returns:
            趋势数据
        """
        with self._lock:
            if not self.recent_executions:
                return []

            interval = interval_minutes * 60
            now = time.time()

            # 创建时间桶
            buckets = defaultdict(lambda: {"count": 0, "success": 0})

            for record in self.recent_executions:
                bucket_key = int((now - record["timestamp"]) / interval)
                buckets[bucket_key]["count"] += 1
                if record["success"]:
                    buckets[bucket_key]["success"] += 1

            # 转换为列表
            trend = []
            for bucket_key in sorted(buckets.keys()):
                bucket = buckets[bucket_key]
                trend.append({
                    "minutes_ago": bucket_key * interval_minutes,
                    "executions": bucket["count"],
                    "successes": bucket["success"],
                    "success_rate": bucket["success"] / bucket["count"] if bucket["count"] > 0 else 0
                })

            return trend

    def reset(self):
        """重置所有指标"""
        with self._lock:
            self.tool_metrics.clear()
            self.system_metrics.clear()
            self.recent_executions.clear()
            self.total_executions = 0
            self.total_successes = 0
            self.total_failures = 0
            self.cache_hits = 0
            self.cache_misses = 0

        logger.info("指标已重置")


# 全局实例
_global_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """获取全局指标收集器"""
    global _global_collector
    if _global_collector is None:
        _global_collector = MetricsCollector()
    return _global_collector
