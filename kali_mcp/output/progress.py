#!/usr/bin/env python3
"""
进度追踪模块

追踪长时间任务的执行进度:
- 任务进度管理
- 实时状态更新
- 预估剩余时间
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


@dataclass
class TaskProgress:
    """任务进度"""
    task_id: str
    name: str
    status: TaskStatus = TaskStatus.PENDING
    current: int = 0
    total: int = 100
    message: str = ""
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    subtasks: List['TaskProgress'] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def percentage(self) -> float:
        """进度百分比"""
        if self.total == 0:
            return 0
        return min(100, (self.current / self.total) * 100)

    @property
    def elapsed_time(self) -> float:
        """已用时间（秒）"""
        if self.start_time is None:
            return 0
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def estimated_remaining(self) -> Optional[float]:
        """预估剩余时间（秒）"""
        if self.current == 0 or self.start_time is None:
            return None
        elapsed = self.elapsed_time
        rate = self.current / elapsed
        remaining = self.total - self.current
        return remaining / rate if rate > 0 else None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "task_id": self.task_id,
            "name": self.name,
            "status": self.status.value,
            "current": self.current,
            "total": self.total,
            "percentage": self.percentage,
            "message": self.message,
            "elapsed_time": self.elapsed_time,
            "estimated_remaining": self.estimated_remaining,
            "subtasks": [s.to_dict() for s in self.subtasks]
        }


class ProgressTracker:
    """进度追踪器"""

    def __init__(self):
        """初始化进度追踪器"""
        self.tasks: Dict[str, TaskProgress] = {}
        self.callbacks: List[Callable[[TaskProgress], None]] = []
        self._task_counter = 0
        logger.info("ProgressTracker 初始化完成")

    def create_task(
        self,
        name: str,
        total: int = 100,
        task_id: Optional[str] = None
    ) -> TaskProgress:
        """
        创建新任务

        Args:
            name: 任务名称
            total: 总步骤数
            task_id: 任务ID（可选）

        Returns:
            任务进度对象
        """
        if task_id is None:
            self._task_counter += 1
            task_id = f"task_{self._task_counter}"

        progress = TaskProgress(
            task_id=task_id,
            name=name,
            total=total
        )

        self.tasks[task_id] = progress
        logger.debug(f"创建任务: {task_id} - {name}")
        return progress

    def start_task(self, task_id: str, message: str = "") -> bool:
        """
        开始任务

        Args:
            task_id: 任务ID
            message: 状态消息

        Returns:
            是否成功
        """
        if task_id not in self.tasks:
            return False

        progress = self.tasks[task_id]
        progress.status = TaskStatus.RUNNING
        progress.start_time = time.time()
        progress.message = message or f"开始执行 {progress.name}"

        self._notify_callbacks(progress)
        logger.debug(f"开始任务: {task_id}")
        return True

    def update_progress(
        self,
        task_id: str,
        current: Optional[int] = None,
        increment: int = 0,
        message: str = ""
    ) -> bool:
        """
        更新进度

        Args:
            task_id: 任务ID
            current: 当前进度
            increment: 增量
            message: 状态消息

        Returns:
            是否成功
        """
        if task_id not in self.tasks:
            return False

        progress = self.tasks[task_id]

        if current is not None:
            progress.current = min(current, progress.total)
        else:
            progress.current = min(progress.current + increment, progress.total)

        if message:
            progress.message = message

        self._notify_callbacks(progress)
        return True

    def complete_task(
        self,
        task_id: str,
        message: str = "",
        success: bool = True
    ) -> bool:
        """
        完成任务

        Args:
            task_id: 任务ID
            message: 完成消息
            success: 是否成功

        Returns:
            是否成功
        """
        if task_id not in self.tasks:
            return False

        progress = self.tasks[task_id]
        progress.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
        progress.current = progress.total if success else progress.current
        progress.end_time = time.time()
        progress.message = message or (
            f"完成 {progress.name}" if success else f"失败 {progress.name}"
        )

        self._notify_callbacks(progress)
        logger.debug(f"完成任务: {task_id} - 成功={success}")
        return True

    def fail_task(self, task_id: str, error: str = "") -> bool:
        """
        任务失败

        Args:
            task_id: 任务ID
            error: 错误信息

        Returns:
            是否成功
        """
        return self.complete_task(task_id, error, success=False)

    def cancel_task(self, task_id: str) -> bool:
        """
        取消任务

        Args:
            task_id: 任务ID

        Returns:
            是否成功
        """
        if task_id not in self.tasks:
            return False

        progress = self.tasks[task_id]
        progress.status = TaskStatus.CANCELLED
        progress.end_time = time.time()
        progress.message = "任务已取消"

        self._notify_callbacks(progress)
        logger.debug(f"取消任务: {task_id}")
        return True

    def add_subtask(
        self,
        parent_id: str,
        name: str,
        total: int = 100
    ) -> Optional[TaskProgress]:
        """
        添加子任务

        Args:
            parent_id: 父任务ID
            name: 子任务名称
            total: 总步骤数

        Returns:
            子任务进度对象
        """
        if parent_id not in self.tasks:
            return None

        parent = self.tasks[parent_id]
        subtask = TaskProgress(
            task_id=f"{parent_id}_sub_{len(parent.subtasks) + 1}",
            name=name,
            total=total
        )
        parent.subtasks.append(subtask)
        self.tasks[subtask.task_id] = subtask

        return subtask

    def get_progress(self, task_id: str) -> Optional[TaskProgress]:
        """
        获取任务进度

        Args:
            task_id: 任务ID

        Returns:
            任务进度对象
        """
        return self.tasks.get(task_id)

    def get_all_progress(self) -> Dict[str, Dict[str, Any]]:
        """获取所有任务进度"""
        return {
            task_id: progress.to_dict()
            for task_id, progress in self.tasks.items()
        }

    def get_active_tasks(self) -> List[TaskProgress]:
        """获取活跃的任务"""
        return [
            p for p in self.tasks.values()
            if p.status == TaskStatus.RUNNING
        ]

    def register_callback(self, callback: Callable[[TaskProgress], None]):
        """
        注册进度回调

        Args:
            callback: 回调函数
        """
        self.callbacks.append(callback)

    def _notify_callbacks(self, progress: TaskProgress):
        """通知所有回调"""
        for callback in self.callbacks:
            try:
                callback(progress)
            except Exception as e:
                logger.error(f"进度回调错误: {e}")

    def format_progress_bar(
        self,
        task_id: str,
        width: int = 40
    ) -> str:
        """
        格式化进度条

        Args:
            task_id: 任务ID
            width: 进度条宽度

        Returns:
            进度条字符串
        """
        progress = self.tasks.get(task_id)
        if not progress:
            return ""

        percentage = progress.percentage
        filled = int(width * percentage / 100)
        empty = width - filled

        bar = f"[{'█' * filled}{'░' * empty}] {percentage:.1f}%"

        if progress.estimated_remaining:
            remaining = timedelta(seconds=int(progress.estimated_remaining))
            bar += f" ETA: {remaining}"

        return bar

    def print_progress(self, task_id: str):
        """
        打印进度（用于终端）

        Args:
            task_id: 任务ID
        """
        progress = self.tasks.get(task_id)
        if not progress:
            return

        bar = self.format_progress_bar(task_id)
        status_icon = {
            TaskStatus.PENDING: "⏳",
            TaskStatus.RUNNING: "🔄",
            TaskStatus.COMPLETED: "✅",
            TaskStatus.FAILED: "❌",
            TaskStatus.CANCELLED: "🚫",
            TaskStatus.PAUSED: "⏸️",
        }.get(progress.status, "")

        print(f"\r{status_icon} {progress.name}: {bar} - {progress.message}", end="", flush=True)

        if progress.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
            print()  # 换行

    def cleanup_completed(self, max_age: float = 3600):
        """
        清理已完成的任务

        Args:
            max_age: 最大保留时间（秒）
        """
        now = time.time()
        to_remove = []

        for task_id, progress in self.tasks.items():
            if progress.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
                if progress.end_time and (now - progress.end_time) > max_age:
                    to_remove.append(task_id)

        for task_id in to_remove:
            del self.tasks[task_id]

        if to_remove:
            logger.debug(f"清理了 {len(to_remove)} 个已完成的任务")


class ProgressContext:
    """进度上下文管理器"""

    def __init__(
        self,
        tracker: ProgressTracker,
        name: str,
        total: int = 100
    ):
        """
        初始化

        Args:
            tracker: 进度追踪器
            name: 任务名称
            total: 总步骤数
        """
        self.tracker = tracker
        self.name = name
        self.total = total
        self.progress: Optional[TaskProgress] = None

    async def __aenter__(self) -> TaskProgress:
        """进入上下文"""
        self.progress = self.tracker.create_task(self.name, self.total)
        self.tracker.start_task(self.progress.task_id)
        return self.progress

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """退出上下文"""
        if self.progress:
            if exc_type:
                self.tracker.fail_task(self.progress.task_id, str(exc_val))
            else:
                self.tracker.complete_task(self.progress.task_id)

    def __enter__(self) -> TaskProgress:
        """同步进入上下文"""
        self.progress = self.tracker.create_task(self.name, self.total)
        self.tracker.start_task(self.progress.task_id)
        return self.progress

    def __exit__(self, exc_type, exc_val, exc_tb):
        """同步退出上下文"""
        if self.progress:
            if exc_type:
                self.tracker.fail_task(self.progress.task_id, str(exc_val))
            else:
                self.tracker.complete_task(self.progress.task_id)


# 全局进度追踪器
_global_tracker: Optional[ProgressTracker] = None


def get_progress_tracker() -> ProgressTracker:
    """获取全局进度追踪器"""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = ProgressTracker()
    return _global_tracker
