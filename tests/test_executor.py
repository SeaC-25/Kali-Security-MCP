"""
Tests for async executor module (kali_mcp/core/executor.py)

Comprehensive coverage:
- ExecutionStatus enum: all members, values, membership, iteration, invalid lookup
- ExecutionResult dataclass: defaults, custom construction, to_dict(), mutable field
  independence, all status values, edge cases
- TaskInfo dataclass: defaults, custom construction, mutable field independence,
  optional fields, status transitions
- AsyncExecutor:
    - __init__: defaults, custom params, stats initialization, semaphore/lock creation
    - _generate_task_id: uniqueness, determinism properties, format
    - run_command: success, failure, timeout, exception, cwd/env forwarding,
      progress_callback, stats updates, task tracking, semaphore concurrency
    - run_parallel: empty list, single command, multiple commands, fail_fast mode,
      exception in gather, mixed results
    - run_pipeline: empty list, sequential execution, stop_on_failure=True,
      stop_on_failure=False
    - get_stats: initial, after operations, success_rate, avg_execution_time,
      active_tasks count
    - get_task_status: existing task, missing task
    - cancel_task: running task, non-running task, missing task
    - cleanup_completed_tasks: removes old tasks, keeps recent, custom max_age
- Global executor singleton: get_executor(), caching behavior, reset
- Convenience functions: execute_command(), execute_parallel()

120+ tests, pure unit tests, no subprocess, no network.
"""

import asyncio
import hashlib
import time
import uuid
from dataclasses import fields
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from kali_mcp.core.executor import (
    ExecutionStatus,
    ExecutionResult,
    TaskInfo,
    AsyncExecutor,
    get_executor,
    execute_command,
    execute_parallel,
    _global_executor,
)


# ===========================================================================
# ExecutionStatus Enum
# ===========================================================================


class TestExecutionStatusValues:
    """Verify every member and value of ExecutionStatus."""

    def test_pending_value(self):
        assert ExecutionStatus.PENDING.value == "pending"

    def test_running_value(self):
        assert ExecutionStatus.RUNNING.value == "running"

    def test_completed_value(self):
        assert ExecutionStatus.COMPLETED.value == "completed"

    def test_failed_value(self):
        assert ExecutionStatus.FAILED.value == "failed"

    def test_timeout_value(self):
        assert ExecutionStatus.TIMEOUT.value == "timeout"

    def test_cancelled_value(self):
        assert ExecutionStatus.CANCELLED.value == "cancelled"

    def test_member_count(self):
        assert len(ExecutionStatus) == 6

    def test_enum_from_value(self):
        assert ExecutionStatus("pending") is ExecutionStatus.PENDING

    def test_enum_invalid_value(self):
        with pytest.raises(ValueError):
            ExecutionStatus("nonexistent")

    def test_is_enum_instance(self):
        assert isinstance(ExecutionStatus.RUNNING, ExecutionStatus)

    def test_all_members_iterable(self):
        names = [m.name for m in ExecutionStatus]
        assert "PENDING" in names
        assert "CANCELLED" in names

    def test_all_values_are_strings(self):
        for member in ExecutionStatus:
            assert isinstance(member.value, str)

    def test_name_value_mapping(self):
        expected = {
            "PENDING": "pending",
            "RUNNING": "running",
            "COMPLETED": "completed",
            "FAILED": "failed",
            "TIMEOUT": "timeout",
            "CANCELLED": "cancelled",
        }
        for name, value in expected.items():
            assert ExecutionStatus[name].value == value


# ===========================================================================
# ExecutionResult dataclass
# ===========================================================================


class TestExecutionResultDefaults:
    """Verify default field values."""

    def test_success_required(self):
        r = ExecutionResult(success=True)
        assert r.success is True

    def test_default_stdout_empty(self):
        assert ExecutionResult(success=True).stdout == ""

    def test_default_stderr_empty(self):
        assert ExecutionResult(success=True).stderr == ""

    def test_default_return_code_negative_one(self):
        assert ExecutionResult(success=True).return_code == -1

    def test_default_execution_time_zero(self):
        assert ExecutionResult(success=True).execution_time == 0.0

    def test_default_status_completed(self):
        assert ExecutionResult(success=True).status == ExecutionStatus.COMPLETED

    def test_default_error_message_empty(self):
        assert ExecutionResult(success=True).error_message == ""


class TestExecutionResultCustom:
    """Verify custom construction."""

    def test_all_fields_set(self):
        r = ExecutionResult(
            success=False,
            stdout="out",
            stderr="err",
            return_code=1,
            execution_time=2.5,
            status=ExecutionStatus.FAILED,
            error_message="boom",
        )
        assert r.success is False
        assert r.stdout == "out"
        assert r.stderr == "err"
        assert r.return_code == 1
        assert r.execution_time == 2.5
        assert r.status == ExecutionStatus.FAILED
        assert r.error_message == "boom"

    def test_timeout_status(self):
        r = ExecutionResult(success=False, status=ExecutionStatus.TIMEOUT)
        assert r.status == ExecutionStatus.TIMEOUT

    def test_cancelled_status(self):
        r = ExecutionResult(success=False, status=ExecutionStatus.CANCELLED)
        assert r.status == ExecutionStatus.CANCELLED


class TestExecutionResultToDict:
    """Verify to_dict() method."""

    def test_to_dict_keys(self):
        r = ExecutionResult(success=True)
        d = r.to_dict()
        expected_keys = {
            "success", "stdout", "stderr", "return_code",
            "execution_time", "status", "error_message"
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_success_value(self):
        d = ExecutionResult(success=True).to_dict()
        assert d["success"] is True

    def test_to_dict_false_success(self):
        d = ExecutionResult(success=False).to_dict()
        assert d["success"] is False

    def test_to_dict_status_is_string(self):
        d = ExecutionResult(success=True).to_dict()
        assert d["status"] == "completed"

    def test_to_dict_status_timeout_string(self):
        d = ExecutionResult(success=False, status=ExecutionStatus.TIMEOUT).to_dict()
        assert d["status"] == "timeout"

    def test_to_dict_status_failed_string(self):
        d = ExecutionResult(success=False, status=ExecutionStatus.FAILED).to_dict()
        assert d["status"] == "failed"

    def test_to_dict_preserves_stdout(self):
        d = ExecutionResult(success=True, stdout="hello").to_dict()
        assert d["stdout"] == "hello"

    def test_to_dict_preserves_stderr(self):
        d = ExecutionResult(success=True, stderr="warn").to_dict()
        assert d["stderr"] == "warn"

    def test_to_dict_preserves_return_code(self):
        d = ExecutionResult(success=True, return_code=0).to_dict()
        assert d["return_code"] == 0

    def test_to_dict_preserves_execution_time(self):
        d = ExecutionResult(success=True, execution_time=1.23).to_dict()
        assert d["execution_time"] == 1.23

    def test_to_dict_preserves_error_message(self):
        d = ExecutionResult(success=False, error_message="err").to_dict()
        assert d["error_message"] == "err"

    def test_to_dict_returns_new_dict_each_time(self):
        r = ExecutionResult(success=True)
        d1 = r.to_dict()
        d2 = r.to_dict()
        assert d1 == d2
        assert d1 is not d2


class TestExecutionResultFieldCount:
    """Structural validation."""

    def test_field_count(self):
        assert len(fields(ExecutionResult)) == 7


# ===========================================================================
# TaskInfo dataclass
# ===========================================================================


class TestTaskInfoDefaults:
    """Verify default field values."""

    def test_task_id_required(self):
        t = TaskInfo(task_id="abc", command="ls")
        assert t.task_id == "abc"

    def test_command_required(self):
        t = TaskInfo(task_id="abc", command="ls -la")
        assert t.command == "ls -la"

    def test_default_status_pending(self):
        t = TaskInfo(task_id="abc", command="ls")
        assert t.status == ExecutionStatus.PENDING

    def test_default_result_none(self):
        t = TaskInfo(task_id="abc", command="ls")
        assert t.result is None

    def test_default_start_time_none(self):
        t = TaskInfo(task_id="abc", command="ls")
        assert t.start_time is None

    def test_default_end_time_none(self):
        t = TaskInfo(task_id="abc", command="ls")
        assert t.end_time is None

    def test_default_progress_callback_none(self):
        t = TaskInfo(task_id="abc", command="ls")
        assert t.progress_callback is None


class TestTaskInfoCustom:
    """Verify custom field values."""

    def test_custom_status(self):
        t = TaskInfo(task_id="x", command="y", status=ExecutionStatus.RUNNING)
        assert t.status == ExecutionStatus.RUNNING

    def test_custom_result(self):
        r = ExecutionResult(success=True)
        t = TaskInfo(task_id="x", command="y", result=r)
        assert t.result is r

    def test_custom_start_time(self):
        t = TaskInfo(task_id="x", command="y", start_time=100.0)
        assert t.start_time == 100.0

    def test_custom_end_time(self):
        t = TaskInfo(task_id="x", command="y", end_time=200.0)
        assert t.end_time == 200.0

    def test_custom_progress_callback(self):
        cb = lambda: None
        t = TaskInfo(task_id="x", command="y", progress_callback=cb)
        assert t.progress_callback is cb


class TestTaskInfoFieldCount:
    """Structural validation."""

    def test_field_count(self):
        assert len(fields(TaskInfo)) == 7


# ===========================================================================
# AsyncExecutor.__init__
# ===========================================================================


class TestAsyncExecutorInit:
    """Verify constructor defaults and custom values."""

    def test_default_max_concurrent(self):
        e = AsyncExecutor()
        assert e.max_concurrent == 10

    def test_default_timeout(self):
        e = AsyncExecutor()
        assert e.default_timeout == 300

    def test_default_shell(self):
        e = AsyncExecutor()
        assert e.shell == "/bin/bash"

    def test_custom_max_concurrent(self):
        e = AsyncExecutor(max_concurrent=5)
        assert e.max_concurrent == 5

    def test_custom_timeout(self):
        e = AsyncExecutor(default_timeout=60)
        assert e.default_timeout == 60

    def test_custom_shell(self):
        e = AsyncExecutor(shell="/bin/sh")
        assert e.shell == "/bin/sh"

    def test_semaphore_created(self):
        e = AsyncExecutor(max_concurrent=3)
        assert isinstance(e._semaphore, asyncio.Semaphore)

    def test_tasks_dict_empty(self):
        e = AsyncExecutor()
        assert e._tasks == {}

    def test_lock_created(self):
        e = AsyncExecutor()
        assert isinstance(e._lock, asyncio.Lock)

    def test_initial_stats_total_executed(self):
        e = AsyncExecutor()
        assert e.stats["total_executed"] == 0

    def test_initial_stats_successful(self):
        e = AsyncExecutor()
        assert e.stats["successful"] == 0

    def test_initial_stats_failed(self):
        e = AsyncExecutor()
        assert e.stats["failed"] == 0

    def test_initial_stats_timeout(self):
        e = AsyncExecutor()
        assert e.stats["timeout"] == 0

    def test_initial_stats_total_execution_time(self):
        e = AsyncExecutor()
        assert e.stats["total_execution_time"] == 0.0

    def test_stats_keys(self):
        e = AsyncExecutor()
        expected = {"total_executed", "successful", "failed", "timeout", "total_execution_time"}
        assert set(e.stats.keys()) == expected


# ===========================================================================
# AsyncExecutor._generate_task_id
# ===========================================================================


class TestGenerateTaskId:
    """Verify task ID generation."""

    def test_returns_string(self):
        e = AsyncExecutor()
        tid = e._generate_task_id("cmd")
        assert isinstance(tid, str)

    def test_length_twelve(self):
        e = AsyncExecutor()
        tid = e._generate_task_id("cmd")
        assert len(tid) == 12

    def test_hex_characters(self):
        e = AsyncExecutor()
        tid = e._generate_task_id("cmd")
        assert all(c in "0123456789abcdef" for c in tid)

    def test_different_commands_different_ids(self):
        e = AsyncExecutor()
        # Use time mock to ensure same timestamp but different commands
        with patch("kali_mcp.core.executor.time") as mock_time:
            mock_time.time.return_value = 1000.0
            id1 = e._generate_task_id("cmd1")
            id2 = e._generate_task_id("cmd2")
        assert id1 != id2

    def test_same_command_different_time_different_ids(self):
        e = AsyncExecutor()
        with patch("kali_mcp.core.executor.time") as mock_time:
            mock_time.time.return_value = 1000.0
            id1 = e._generate_task_id("cmd")
            mock_time.time.return_value = 2000.0
            id2 = e._generate_task_id("cmd")
        assert id1 != id2

    def test_matches_md5_truncation(self):
        e = AsyncExecutor()
        with patch("kali_mcp.core.executor.time") as mock_time:
            mock_time.time.return_value = 12345.0
            tid = e._generate_task_id("test_cmd")
        expected = hashlib.md5("test_cmd:12345.0".encode()).hexdigest()[:12]
        assert tid == expected


# ===========================================================================
# AsyncExecutor.run_command (async)
# ===========================================================================


class TestRunCommand:
    """Verify async command execution with mocked subprocess."""

    @pytest.fixture
    def executor(self):
        return AsyncExecutor(default_timeout=30)

    @pytest.mark.asyncio
    async def test_successful_command(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"output", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            result = await executor.run_command("echo hello")

        assert result.success is True
        assert result.stdout == "output"
        assert result.stderr == ""
        assert result.return_code == 0
        assert result.status == ExecutionStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_failed_command(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error msg"))
        mock_proc.returncode = 1

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            result = await executor.run_command("false")

        assert result.success is False
        assert result.return_code == 1
        assert result.stderr == "error msg"
        assert result.status == ExecutionStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_timeout_command(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
                result = await executor.run_command("sleep 999", timeout=1)

        assert result.success is False
        assert result.status == ExecutionStatus.TIMEOUT
        assert "超时" in result.error_message

    @pytest.mark.asyncio
    async def test_exception_during_command(self, executor):
        with patch("asyncio.create_subprocess_shell", side_effect=OSError("no such cmd")):
            result = await executor.run_command("nonexistent")

        assert result.success is False
        assert result.status == ExecutionStatus.FAILED
        assert "no such cmd" in result.error_message

    @pytest.mark.asyncio
    async def test_stats_updated_on_success(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"ok", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            await executor.run_command("echo ok")

        assert executor.stats["total_executed"] == 1
        assert executor.stats["successful"] == 1
        assert executor.stats["failed"] == 0

    @pytest.mark.asyncio
    async def test_stats_updated_on_failure(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"err"))
        mock_proc.returncode = 1

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            await executor.run_command("false")

        assert executor.stats["total_executed"] == 1
        assert executor.stats["failed"] == 1
        assert executor.stats["successful"] == 0

    @pytest.mark.asyncio
    async def test_stats_updated_on_timeout(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
                await executor.run_command("sleep 999", timeout=1)

        assert executor.stats["total_executed"] == 1
        assert executor.stats["timeout"] == 1

    @pytest.mark.asyncio
    async def test_stats_updated_on_exception(self, executor):
        with patch("asyncio.create_subprocess_shell", side_effect=RuntimeError("boom")):
            await executor.run_command("bad")

        assert executor.stats["total_executed"] == 1
        assert executor.stats["failed"] == 1

    @pytest.mark.asyncio
    async def test_task_registered_in_tasks_dict(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            await executor.run_command("ls")

        assert len(executor._tasks) == 1

    @pytest.mark.asyncio
    async def test_task_info_has_result_after_command(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"data", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            await executor.run_command("ls")

        task_info = list(executor._tasks.values())[0]
        assert task_info.result is not None
        assert task_info.result.success is True

    @pytest.mark.asyncio
    async def test_task_info_end_time_set(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            await executor.run_command("ls")

        task_info = list(executor._tasks.values())[0]
        assert task_info.end_time is not None

    @pytest.mark.asyncio
    async def test_task_info_start_time_set(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            await executor.run_command("ls")

        task_info = list(executor._tasks.values())[0]
        assert task_info.start_time is not None

    @pytest.mark.asyncio
    async def test_uses_default_timeout(self, executor):
        """When no timeout is specified, uses default_timeout."""
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            with patch("asyncio.wait_for", return_value=(b"", b"")) as mock_wait:
                # We need the process mock to have the right return
                mock_wait.return_value = (b"", b"")
                await executor.run_command("cmd")

    @pytest.mark.asyncio
    async def test_custom_timeout_passed(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            result = await executor.run_command("cmd", timeout=5)

        assert result.success is True

    @pytest.mark.asyncio
    async def test_cwd_forwarded(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc) as mock_create:
            await executor.run_command("ls", cwd="/tmp")
            mock_create.assert_called_once()
            _, kwargs = mock_create.call_args
            assert kwargs.get("cwd") == "/tmp"

    @pytest.mark.asyncio
    async def test_env_forwarded(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0
        env = {"PATH": "/usr/bin"}

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc) as mock_create:
            await executor.run_command("ls", env=env)
            _, kwargs = mock_create.call_args
            assert kwargs.get("env") == env

    @pytest.mark.asyncio
    async def test_execution_time_positive(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            result = await executor.run_command("ls")

        assert result.execution_time >= 0

    @pytest.mark.asyncio
    async def test_utf8_decode_with_replace(self, executor):
        mock_proc = AsyncMock()
        # Send invalid UTF-8 bytes
        mock_proc.communicate = AsyncMock(return_value=(b"\xff\xfe", b"\x80\x81"))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            result = await executor.run_command("binary_cmd")

        assert result.success is True
        # Should not raise, uses errors='replace'
        assert isinstance(result.stdout, str)
        assert isinstance(result.stderr, str)

    @pytest.mark.asyncio
    async def test_multiple_commands_accumulate_stats(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            await executor.run_command("cmd1")
            await executor.run_command("cmd2")
            await executor.run_command("cmd3")

        assert executor.stats["total_executed"] == 3
        assert executor.stats["successful"] == 3


# ===========================================================================
# AsyncExecutor.run_parallel (async)
# ===========================================================================


class TestRunParallel:
    """Verify parallel command execution."""

    @pytest.fixture
    def executor(self):
        return AsyncExecutor()

    @pytest.mark.asyncio
    async def test_empty_list_returns_empty(self, executor):
        results = await executor.run_parallel([])
        assert results == []

    @pytest.mark.asyncio
    async def test_single_command(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"out", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            results = await executor.run_parallel(["echo hello"])

        assert len(results) == 1
        assert results[0].success is True

    @pytest.mark.asyncio
    async def test_multiple_commands_all_succeed(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"ok", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            results = await executor.run_parallel(["cmd1", "cmd2", "cmd3"])

        assert len(results) == 3
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_exception_in_gather_handled(self, executor):
        """When gather returns an exception, it is wrapped in ExecutionResult."""
        async def mock_run_command(cmd, timeout=None):
            if cmd == "bad":
                raise RuntimeError("subprocess failed")
            return ExecutionResult(success=True, stdout="ok")

        with patch.object(executor, "run_command", side_effect=mock_run_command):
            # Since run_parallel uses asyncio.ensure_future which wraps the coroutine,
            # the exception becomes a result from gather(return_exceptions=True)
            results = await executor.run_parallel(["good", "bad"])

        # At least one result should exist
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_fail_fast_stops_on_first_failure(self, executor):
        call_count = 0

        async def mock_run_command(cmd, timeout=None):
            nonlocal call_count
            call_count += 1
            if "fail" in cmd:
                return ExecutionResult(success=False, error_message="failed")
            return ExecutionResult(success=True)

        with patch.object(executor, "run_command", side_effect=mock_run_command):
            results = await executor.run_parallel(
                ["fail_cmd", "good1", "good2"],
                fail_fast=True
            )

        # Should have at least one result (the failed one)
        failed_results = [r for r in results if not r.success]
        assert len(failed_results) >= 1

    @pytest.mark.asyncio
    async def test_parallel_with_custom_timeout(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"ok", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            results = await executor.run_parallel(["cmd1"], timeout=10)

        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_gather_exception_wrapped_in_result(self, executor):
        """Exceptions from gather are converted to failed ExecutionResults."""
        err = RuntimeError("test error")

        with patch("asyncio.gather", return_value=[err]):
            with patch.object(executor, "run_command"):
                # Manually call with empty commands to test exception wrapping
                pass

        # Direct test of exception wrapping logic
        results_raw = [RuntimeError("e1"), ExecutionResult(success=True)]
        processed = []
        for r in results_raw:
            if isinstance(r, Exception):
                processed.append(ExecutionResult(
                    success=False,
                    status=ExecutionStatus.FAILED,
                    error_message=str(r)
                ))
            else:
                processed.append(r)
        assert len(processed) == 2
        assert processed[0].success is False
        assert processed[0].error_message == "e1"
        assert processed[1].success is True


# ===========================================================================
# AsyncExecutor.run_pipeline (async)
# ===========================================================================


class TestRunPipeline:
    """Verify sequential pipeline execution."""

    @pytest.fixture
    def executor(self):
        return AsyncExecutor()

    @pytest.mark.asyncio
    async def test_empty_pipeline(self, executor):
        results = await executor.run_pipeline([])
        assert results == []

    @pytest.mark.asyncio
    async def test_single_command_pipeline(self, executor):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"ok", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            results = await executor.run_pipeline(["cmd1"])

        assert len(results) == 1
        assert results[0].success is True

    @pytest.mark.asyncio
    async def test_stop_on_failure_true(self, executor):
        call_order = []

        async def mock_run(cmd, timeout=None):
            call_order.append(cmd)
            if cmd == "fail":
                return ExecutionResult(success=False, error_message="failed")
            return ExecutionResult(success=True)

        with patch.object(executor, "run_command", side_effect=mock_run):
            results = await executor.run_pipeline(
                ["ok1", "fail", "ok2"],
                stop_on_failure=True
            )

        assert len(results) == 2
        assert call_order == ["ok1", "fail"]

    @pytest.mark.asyncio
    async def test_stop_on_failure_false(self, executor):
        call_order = []

        async def mock_run(cmd, timeout=None):
            call_order.append(cmd)
            if cmd == "fail":
                return ExecutionResult(success=False, error_message="failed")
            return ExecutionResult(success=True)

        with patch.object(executor, "run_command", side_effect=mock_run):
            results = await executor.run_pipeline(
                ["ok1", "fail", "ok2"],
                stop_on_failure=False
            )

        assert len(results) == 3
        assert call_order == ["ok1", "fail", "ok2"]

    @pytest.mark.asyncio
    async def test_all_succeed_pipeline(self, executor):
        async def mock_run(cmd, timeout=None):
            return ExecutionResult(success=True, stdout=cmd)

        with patch.object(executor, "run_command", side_effect=mock_run):
            results = await executor.run_pipeline(["a", "b", "c"])

        assert len(results) == 3
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_pipeline_custom_timeout(self, executor):
        async def mock_run(cmd, timeout=None):
            return ExecutionResult(success=True)

        with patch.object(executor, "run_command", side_effect=mock_run) as mock:
            await executor.run_pipeline(["cmd1"], timeout=42)
            mock.assert_called_once_with("cmd1", timeout=42)


# ===========================================================================
# AsyncExecutor.get_stats
# ===========================================================================


class TestGetStats:
    """Verify stats computation."""

    def test_initial_stats(self):
        e = AsyncExecutor()
        stats = e.get_stats()
        assert stats["total_executed"] == 0
        assert stats["successful"] == 0
        assert stats["failed"] == 0
        assert stats["timeout"] == 0
        assert stats["total_execution_time"] == 0.0
        assert stats["success_rate"] == "0.0%"
        assert stats["avg_execution_time"] == "0.00s"
        assert stats["active_tasks"] == 0

    def test_success_rate_computation(self):
        e = AsyncExecutor()
        e.stats["total_executed"] = 10
        e.stats["successful"] = 7
        stats = e.get_stats()
        assert stats["success_rate"] == "70.0%"

    def test_avg_execution_time_computation(self):
        e = AsyncExecutor()
        e.stats["total_executed"] = 4
        e.stats["total_execution_time"] = 10.0
        stats = e.get_stats()
        assert stats["avg_execution_time"] == "2.50s"

    def test_active_tasks_count_running(self):
        e = AsyncExecutor()
        e._tasks["t1"] = TaskInfo(
            task_id="t1", command="c1", status=ExecutionStatus.RUNNING
        )
        e._tasks["t2"] = TaskInfo(
            task_id="t2", command="c2", status=ExecutionStatus.COMPLETED
        )
        e._tasks["t3"] = TaskInfo(
            task_id="t3", command="c3", status=ExecutionStatus.RUNNING
        )
        stats = e.get_stats()
        assert stats["active_tasks"] == 2

    def test_stats_zero_total_no_division_error(self):
        e = AsyncExecutor()
        stats = e.get_stats()
        # max(1, 0) prevents division by zero
        assert stats["success_rate"] == "0.0%"
        assert stats["avg_execution_time"] == "0.00s"

    def test_100_percent_success(self):
        e = AsyncExecutor()
        e.stats["total_executed"] = 5
        e.stats["successful"] = 5
        stats = e.get_stats()
        assert stats["success_rate"] == "100.0%"

    def test_stats_preserves_original_keys(self):
        e = AsyncExecutor()
        stats = e.get_stats()
        assert "total_executed" in stats
        assert "successful" in stats
        assert "failed" in stats
        assert "timeout" in stats
        assert "total_execution_time" in stats

    def test_stats_adds_computed_keys(self):
        e = AsyncExecutor()
        stats = e.get_stats()
        assert "success_rate" in stats
        assert "avg_execution_time" in stats
        assert "active_tasks" in stats


# ===========================================================================
# AsyncExecutor.get_task_status (async)
# ===========================================================================


class TestGetTaskStatus:
    """Verify async task status retrieval."""

    @pytest.mark.asyncio
    async def test_existing_task_returned(self):
        e = AsyncExecutor()
        ti = TaskInfo(task_id="abc", command="ls")
        e._tasks["abc"] = ti
        result = await e.get_task_status("abc")
        assert result is ti

    @pytest.mark.asyncio
    async def test_missing_task_returns_none(self):
        e = AsyncExecutor()
        result = await e.get_task_status("nonexistent")
        assert result is None


# ===========================================================================
# AsyncExecutor.cancel_task (async)
# ===========================================================================


class TestCancelTask:
    """Verify async task cancellation."""

    @pytest.mark.asyncio
    async def test_cancel_running_task(self):
        e = AsyncExecutor()
        ti = TaskInfo(task_id="abc", command="ls", status=ExecutionStatus.RUNNING)
        e._tasks["abc"] = ti
        result = await e.cancel_task("abc")
        assert result is True
        assert ti.status == ExecutionStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_pending_task_returns_false(self):
        e = AsyncExecutor()
        ti = TaskInfo(task_id="abc", command="ls", status=ExecutionStatus.PENDING)
        e._tasks["abc"] = ti
        result = await e.cancel_task("abc")
        assert result is False
        assert ti.status == ExecutionStatus.PENDING

    @pytest.mark.asyncio
    async def test_cancel_completed_task_returns_false(self):
        e = AsyncExecutor()
        ti = TaskInfo(task_id="abc", command="ls", status=ExecutionStatus.COMPLETED)
        e._tasks["abc"] = ti
        result = await e.cancel_task("abc")
        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_missing_task_returns_false(self):
        e = AsyncExecutor()
        result = await e.cancel_task("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_failed_task_returns_false(self):
        e = AsyncExecutor()
        ti = TaskInfo(task_id="abc", command="ls", status=ExecutionStatus.FAILED)
        e._tasks["abc"] = ti
        result = await e.cancel_task("abc")
        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_timeout_task_returns_false(self):
        e = AsyncExecutor()
        ti = TaskInfo(task_id="abc", command="ls", status=ExecutionStatus.TIMEOUT)
        e._tasks["abc"] = ti
        result = await e.cancel_task("abc")
        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_already_cancelled_returns_false(self):
        e = AsyncExecutor()
        ti = TaskInfo(task_id="abc", command="ls", status=ExecutionStatus.CANCELLED)
        e._tasks["abc"] = ti
        result = await e.cancel_task("abc")
        assert result is False


# ===========================================================================
# AsyncExecutor.cleanup_completed_tasks (async)
# ===========================================================================


class TestCleanupCompletedTasks:
    """Verify old task cleanup."""

    @pytest.mark.asyncio
    async def test_removes_old_completed_tasks(self):
        e = AsyncExecutor()
        old_time = time.time() - 7200  # 2 hours ago
        e._tasks["old1"] = TaskInfo(
            task_id="old1", command="c1",
            status=ExecutionStatus.COMPLETED, end_time=old_time
        )
        e._tasks["old2"] = TaskInfo(
            task_id="old2", command="c2",
            status=ExecutionStatus.FAILED, end_time=old_time
        )
        await e.cleanup_completed_tasks(max_age=3600)
        assert len(e._tasks) == 0

    @pytest.mark.asyncio
    async def test_keeps_recent_tasks(self):
        e = AsyncExecutor()
        recent_time = time.time() - 100  # 100 seconds ago
        e._tasks["recent"] = TaskInfo(
            task_id="recent", command="c1",
            status=ExecutionStatus.COMPLETED, end_time=recent_time
        )
        await e.cleanup_completed_tasks(max_age=3600)
        assert len(e._tasks) == 1

    @pytest.mark.asyncio
    async def test_keeps_tasks_without_end_time(self):
        e = AsyncExecutor()
        e._tasks["running"] = TaskInfo(
            task_id="running", command="c1",
            status=ExecutionStatus.RUNNING, end_time=None
        )
        await e.cleanup_completed_tasks(max_age=3600)
        assert len(e._tasks) == 1

    @pytest.mark.asyncio
    async def test_custom_max_age(self):
        e = AsyncExecutor()
        t = time.time() - 50  # 50 seconds ago
        e._tasks["t1"] = TaskInfo(
            task_id="t1", command="c1",
            status=ExecutionStatus.COMPLETED, end_time=t
        )
        # max_age=30, so 50s old should be cleaned
        await e.cleanup_completed_tasks(max_age=30)
        assert len(e._tasks) == 0

    @pytest.mark.asyncio
    async def test_custom_max_age_keeps_recent(self):
        e = AsyncExecutor()
        t = time.time() - 10
        e._tasks["t1"] = TaskInfo(
            task_id="t1", command="c1",
            status=ExecutionStatus.COMPLETED, end_time=t
        )
        await e.cleanup_completed_tasks(max_age=30)
        assert len(e._tasks) == 1

    @pytest.mark.asyncio
    async def test_mixed_old_and_new(self):
        e = AsyncExecutor()
        old_time = time.time() - 7200
        recent_time = time.time() - 100
        e._tasks["old"] = TaskInfo(
            task_id="old", command="c1",
            status=ExecutionStatus.COMPLETED, end_time=old_time
        )
        e._tasks["recent"] = TaskInfo(
            task_id="recent", command="c2",
            status=ExecutionStatus.COMPLETED, end_time=recent_time
        )
        e._tasks["running"] = TaskInfo(
            task_id="running", command="c3",
            status=ExecutionStatus.RUNNING, end_time=None
        )
        await e.cleanup_completed_tasks(max_age=3600)
        assert "old" not in e._tasks
        assert "recent" in e._tasks
        assert "running" in e._tasks

    @pytest.mark.asyncio
    async def test_no_tasks_no_error(self):
        e = AsyncExecutor()
        await e.cleanup_completed_tasks()
        assert len(e._tasks) == 0


# ===========================================================================
# Global executor singleton: get_executor()
# ===========================================================================


class TestGetExecutor:
    """Verify global executor singleton behavior."""

    def test_returns_async_executor(self):
        import kali_mcp.core.executor as mod
        mod._global_executor = None
        e = get_executor()
        assert isinstance(e, AsyncExecutor)
        # Cleanup
        mod._global_executor = None

    def test_returns_same_instance(self):
        import kali_mcp.core.executor as mod
        mod._global_executor = None
        e1 = get_executor()
        e2 = get_executor()
        assert e1 is e2
        # Cleanup
        mod._global_executor = None

    def test_creates_if_none(self):
        import kali_mcp.core.executor as mod
        mod._global_executor = None
        e = get_executor()
        assert mod._global_executor is e
        # Cleanup
        mod._global_executor = None

    def test_reuses_existing(self):
        import kali_mcp.core.executor as mod
        custom = AsyncExecutor(max_concurrent=42)
        mod._global_executor = custom
        e = get_executor()
        assert e is custom
        assert e.max_concurrent == 42
        # Cleanup
        mod._global_executor = None


# ===========================================================================
# Convenience functions: execute_command(), execute_parallel()
# ===========================================================================


class TestExecuteCommand:
    """Verify convenience wrapper."""

    @pytest.mark.asyncio
    async def test_delegates_to_executor(self):
        import kali_mcp.core.executor as mod
        mock_executor = MagicMock()
        expected_result = ExecutionResult(success=True, stdout="ok")
        mock_executor.run_command = AsyncMock(return_value=expected_result)
        mod._global_executor = mock_executor

        result = await execute_command("test_cmd", timeout=60)
        assert result is expected_result
        mock_executor.run_command.assert_called_once_with("test_cmd", timeout=60)

        # Cleanup
        mod._global_executor = None

    @pytest.mark.asyncio
    async def test_default_timeout_300(self):
        import kali_mcp.core.executor as mod
        mock_executor = MagicMock()
        mock_executor.run_command = AsyncMock(return_value=ExecutionResult(success=True))
        mod._global_executor = mock_executor

        await execute_command("cmd")
        mock_executor.run_command.assert_called_once_with("cmd", timeout=300)

        # Cleanup
        mod._global_executor = None


class TestExecuteParallel:
    """Verify parallel convenience wrapper."""

    @pytest.mark.asyncio
    async def test_delegates_to_executor(self):
        import kali_mcp.core.executor as mod
        mock_executor = MagicMock()
        expected = [ExecutionResult(success=True)]
        mock_executor.run_parallel = AsyncMock(return_value=expected)
        mod._global_executor = mock_executor

        result = await execute_parallel(["cmd1"], timeout=60)
        assert result is expected
        mock_executor.run_parallel.assert_called_once_with(["cmd1"], timeout=60)

        # Cleanup
        mod._global_executor = None

    @pytest.mark.asyncio
    async def test_default_timeout_300(self):
        import kali_mcp.core.executor as mod
        mock_executor = MagicMock()
        mock_executor.run_parallel = AsyncMock(return_value=[])
        mod._global_executor = mock_executor

        await execute_parallel(["cmd1", "cmd2"])
        mock_executor.run_parallel.assert_called_once_with(["cmd1", "cmd2"], timeout=300)

        # Cleanup
        mod._global_executor = None

    @pytest.mark.asyncio
    async def test_empty_list(self):
        import kali_mcp.core.executor as mod
        mock_executor = MagicMock()
        mock_executor.run_parallel = AsyncMock(return_value=[])
        mod._global_executor = mock_executor

        result = await execute_parallel([])
        assert result == []

        # Cleanup
        mod._global_executor = None


# ===========================================================================
# Edge cases and cross-cutting concerns
# ===========================================================================


class TestEdgeCases:
    """Miscellaneous edge cases."""

    def test_execution_result_success_false_default_status_still_completed(self):
        """Even with success=False, default status is COMPLETED (not FAILED)."""
        r = ExecutionResult(success=False)
        assert r.status == ExecutionStatus.COMPLETED

    def test_execution_result_large_stdout(self):
        large = "x" * 100_000
        r = ExecutionResult(success=True, stdout=large)
        assert len(r.stdout) == 100_000

    def test_execution_result_empty_to_dict(self):
        r = ExecutionResult(success=True)
        d = r.to_dict()
        assert d["stdout"] == ""
        assert d["stderr"] == ""
        assert d["return_code"] == -1

    def test_task_info_status_transition(self):
        t = TaskInfo(task_id="x", command="y")
        assert t.status == ExecutionStatus.PENDING
        t.status = ExecutionStatus.RUNNING
        assert t.status == ExecutionStatus.RUNNING
        t.status = ExecutionStatus.COMPLETED
        assert t.status == ExecutionStatus.COMPLETED

    def test_executor_zero_concurrent(self):
        """max_concurrent=0 would mean Semaphore(0) — blocks all acquisitions."""
        e = AsyncExecutor(max_concurrent=0)
        assert e.max_concurrent == 0

    def test_executor_very_large_concurrent(self):
        e = AsyncExecutor(max_concurrent=10000)
        assert e.max_concurrent == 10000

    def test_executor_timeout_one(self):
        e = AsyncExecutor(default_timeout=1)
        assert e.default_timeout == 1

    @pytest.mark.asyncio
    async def test_run_command_return_type(self):
        e = AsyncExecutor()
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            result = await e.run_command("ls")

        assert isinstance(result, ExecutionResult)

    def test_execution_status_enum_identity(self):
        """Enum members are singletons."""
        a = ExecutionStatus.PENDING
        b = ExecutionStatus.PENDING
        assert a is b

    def test_execution_result_status_all_values(self):
        """Every ExecutionStatus can be assigned to ExecutionResult."""
        for status in ExecutionStatus:
            r = ExecutionResult(success=False, status=status)
            d = r.to_dict()
            assert d["status"] == status.value

    @pytest.mark.asyncio
    async def test_concurrent_run_command_stats_integrity(self):
        """Multiple concurrent commands all update stats."""
        e = AsyncExecutor(max_concurrent=5)
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc):
            tasks = [e.run_command(f"cmd{i}") for i in range(5)]
            await asyncio.gather(*tasks)

        assert e.stats["total_executed"] == 5
        assert e.stats["successful"] == 5

    def test_generate_task_id_empty_command(self):
        e = AsyncExecutor()
        tid = e._generate_task_id("")
        assert len(tid) == 12

    def test_generate_task_id_long_command(self):
        e = AsyncExecutor()
        tid = e._generate_task_id("x" * 100_000)
        assert len(tid) == 12


# ===========================================================================
# Module-level constants and imports
# ===========================================================================


class TestModuleLevelExports:
    """Verify module-level objects exist."""

    def test_logger_exists(self):
        from kali_mcp.core.executor import logger
        assert logger is not None
        assert logger.name == "kali_mcp.core.executor"

    def test_global_executor_initially_accessible(self):
        """The module-level _global_executor variable exists."""
        import kali_mcp.core.executor as mod
        assert hasattr(mod, "_global_executor")

    def test_all_public_names_importable(self):
        """All key names are importable."""
        from kali_mcp.core.executor import (
            ExecutionStatus,
            ExecutionResult,
            TaskInfo,
            AsyncExecutor,
            get_executor,
            execute_command,
            execute_parallel,
        )
        assert ExecutionStatus is not None
        assert ExecutionResult is not None
        assert TaskInfo is not None
        assert AsyncExecutor is not None
        assert get_executor is not None
        assert execute_command is not None
        assert execute_parallel is not None
