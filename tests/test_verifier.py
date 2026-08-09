"""Test verifier core logic — _match_signal pure function + verify_finding error paths."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from kali_mcp.core.verifier import _match_signal, verify_finding


class TestMatchSignal(unittest.TestCase):
    """_match_signal is a pure function — no executor, no side effects."""

    def test_re_prefix_match(self):
        self.assertTrue(_match_signal("HTTP 200 OK", "re:200"))

    def test_re_prefix_no_match(self):
        self.assertFalse(_match_signal("HTTP 404 Not Found", "re:200"))

    def test_re_malformed_falls_back_to_substring(self):
        self.assertTrue(_match_signal("? invalid (bar", "re:? invalid"))

    def test_status_prefix_match(self):
        self.assertTrue(_match_signal("200", "status:200"))

    def test_status_prefix_no_match(self):
        self.assertFalse(_match_signal("301 Moved", "status:200"))

    def test_plain_substring_case_insensitive(self):
        self.assertTrue(_match_signal("Hello World", "hello"))

    def test_plain_substring_no_match(self):
        self.assertFalse(_match_signal("Hello World", "foo"))

    def test_empty_signal_returns_false(self):
        self.assertFalse(_match_signal("anything", ""))
        self.assertFalse(_match_signal("anything", "  "))

    def test_none_body_returns_false(self):
        self.assertFalse(_match_signal(None, "ok"))


class TestVerifyFindingErrors(unittest.TestCase):
    """verify_finding error paths that don't need a real executor."""

    def tearDown(self):
        # get_finding/set_status create workspace dirs via get_workspace(create=True).
        from kali_mcp.core.task_workspace import tasks_root
        import shutil
        for name in ("nope", "t1"):
            p = tasks_root() / name
            if p.is_dir():
                shutil.rmtree(str(p))

    def test_missing_finding(self):
        result = verify_finding("nope", "nope_finding")
        self.assertFalse(result.get("ok"))
        self.assertIn("not found", (result.get("error") or "").lower())

    @patch("kali_mcp.core.verifier.get_finding")
    def test_missing_reproduce_cmd_returns_blocked(self, mock_get):
        mock_get.return_value = {"finding_id": "f1", "target": "http://x/",
                                 "reproduce_cmd": "", "expected_signal": "200",
                                 "evidence_paths": []}
        result = verify_finding("t1", "f1")
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("status"), "blocked")
        self.assertIn("missing reproduce_cmd", (result.get("error") or "").lower())

    @patch("kali_mcp.core.verifier.get_finding")
    def test_no_executor_returns_blocked(self, mock_get):
        mock_get.return_value = {"finding_id": "f2", "target": "http://x/",
                                 "reproduce_cmd": "curl http://x/", "expected_signal": "200",
                                 "evidence_paths": []}
        result = verify_finding("t1", "f2")
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("status"), "blocked")
        self.assertIn("no executor", (result.get("error") or "").lower())

    @patch("kali_mcp.core.verifier.get_finding")
    @patch("kali_mcp.core.verifier.save_evidence")
    @patch("kali_mcp.core.verifier.set_status")
    def test_executor_crash_returns_false_positive(self, mock_status, mock_ev, mock_get):
        mock_get.return_value = {"finding_id": "f3", "target": "http://x/",
                                 "reproduce_cmd": "curl http://x/", "expected_signal": "200",
                                 "evidence_paths": []}
        mock_ev.return_value = {"path": "/tmp/ev.json"}
        mock_status.return_value = {"status": "false_positive"}
        ex = MagicMock()
        ex.execute_command.side_effect = RuntimeError("executor crash")
        result = verify_finding("t1", "f3", executor=ex)
        self.assertFalse(result.get("ok"))
