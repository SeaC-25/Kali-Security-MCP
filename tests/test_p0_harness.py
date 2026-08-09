#!/usr/bin/env python3
"""P0 harness unit tests: workspace, graph, log, evidence, verify, playbook."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock


class TestP0Harness(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)
        os.environ["KALI_MCP_WORKSPACE"] = str(self.workspace)
        # clear graph cache between tests
        from kali_mcp.core import target_graph as tg

        tg._GRAPH_CACHE.clear()

    def tearDown(self):
        from kali_mcp.core import target_graph as tg

        tg._GRAPH_CACHE.clear()
        self._tmpdir.cleanup()
        os.environ.pop("KALI_MCP_WORKSPACE", None)

    def test_workspace_layout(self):
        from kali_mcp.core.task_workspace import get_workspace

        ws = get_workspace("demo_task", create=True)
        self.assertTrue(ws.root.exists())
        self.assertTrue(ws.graph_dir.exists())
        self.assertTrue(ws.evidence_dir.exists())
        self.assertTrue(ws.logs_dir.exists())
        self.assertEqual(ws.read_meta().get("task_id"), "demo_task")

    def test_graph_upsert_query_mark_dead_next_actions(self):
        from kali_mcp.core.target_graph import get_graph

        g = get_graph("g1")
        n = g.upsert_node("url", "http://lab.local/", confidence=0.9, next_checks=["fingerprint"])
        g.save()
        g2 = get_graph("g1", reload=True)
        nodes = g2.query(node_type="url")
        self.assertEqual(len(nodes), 1)
        # trailing slash on bare origin is normalized away for keying/storage
        self.assertIn(nodes[0]["value"], {"http://lab.local", "http://lab.local/"})
        actions = g2.next_actions()
        self.assertTrue(any(a["action"] == "fingerprint" for a in actions))
        g2.mark_dead(n.id, "404")
        g2.save()
        actions2 = g2.next_actions()
        self.assertFalse(any(a["node_id"] == n.id for a in actions2))

    def test_graph_path_trailing_slash_dedupe(self):
        from kali_mcp.core.target_graph import get_graph

        g = get_graph("g_slash")
        a = g.upsert_node("path", "http://127.0.0.1:18081/api", confidence=0.7)
        b = g.upsert_node("path", "http://127.0.0.1:18081/api/", confidence=0.8)
        c = g.upsert_node("path", "http://127.0.0.1:18081/login", confidence=0.7)
        d = g.upsert_node("path", "http://127.0.0.1:18081/login/", confidence=0.7)
        g.save()
        paths = g.query(node_type="path", alive_only=False, limit=50)
        self.assertEqual(len(paths), 2)
        self.assertEqual(a.id, b.id)
        self.assertEqual(c.id, d.id)
        self.assertEqual(b.confidence, 0.8)

    def test_web_surface_clears_url_next_after_slash_normalize(self):
        """After url trailing-slash normalize, cleanup must still clear next_checks."""
        from unittest.mock import MagicMock
        from kali_mcp.core.playbooks import run_playbook
        from kali_mcp.core.target_graph import get_graph

        ex = MagicMock()

        def _tool(name, data):
            return {
                "success": True,
                "output": f"{name} ok http://lab.local/ [200]",
                "error": "",
                "return_code": 0,
                "parsed": {
                    "tool_name": name,
                    "success": True,
                    "summary": f"{name} summary",
                    "structured_data": (
                        {"technologies": ["nginx"]}
                        if name == "whatweb"
                        else {"paths": ["/admin", "/api"]}
                        if name == "gobuster"
                        else {}
                    ),
                    "confidence": 0.7,
                    "severity": "info",
                },
            }

        def _cmd(cmd):
            return {
                "success": True,
                "output": "admin panel html ok",
                "error": "",
                "return_code": 0,
                "command": cmd,
            }

        ex.execute_tool_with_data.side_effect = _tool
        ex.execute_command.side_effect = _cmd
        out = run_playbook(
            "web_surface",
            "ws_slash_clean",
            "http://lab.local/",
            ex,
            depth="standard",
        )
        self.assertTrue(out.get("ok"))
        g = get_graph("ws_slash_clean", reload=True)
        url_nodes = [n for n in g.nodes.values() if n.type == "url"]
        self.assertEqual(len(url_nodes), 1)
        # no residual recon queue after successful playbook
        residual = set(url_nodes[0].next_checks or []) & {
            "fingerprint",
            "shallow_dir",
            "nuclei_subset",
            "http_probe",
        }
        self.assertEqual(residual, set())
        # next_actions should not re-offer those recon actions for the url
        recon_next = [
            a
            for a in g.next_actions(limit=20)
            if a.get("action") in {"fingerprint", "shallow_dir", "nuclei_subset", "http_probe"}
        ]
        self.assertEqual(recon_next, [])

    def test_ingest_parsed_ports(self):
        from kali_mcp.core.target_graph import get_graph

        g = get_graph("g2")
        parsed = {
            "tool_name": "nmap",
            "success": True,
            "summary": "2 open ports",
            "confidence": 0.8,
            "severity": "info",
            "structured_data": {
                "ports": [
                    {"port": "80", "service": "http"},
                    {"port": "443", "service": "https"},
                ]
            },
        }
        out = g.ingest_parsed("nmap", parsed, target="10.0.0.5", evidence_path="/tmp/e.txt")
        self.assertGreaterEqual(out["nodes_touched"], 1)
        ports = g.query(node_type="port")
        self.assertEqual(len(ports), 2)

    def test_action_log_and_evidence(self):
        from kali_mcp.core.action_log import (
            ACTION_EVENT_FIELDS,
            log_action,
            read_actions,
            task_timeline,
        )
        from kali_mcp.core.evidence_store import save_evidence

        log_action(
            "tlog",
            phase="RECON",
            target="http://a",
            tool="httpx",
            args={"u": "http://a"},
            exit_code=0,
            duration_ms=12.5,
            source="playbook",
            finding_ids=["f1"],
        )
        actions = read_actions("tlog")
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["tool"], "httpx")
        for key in ACTION_EVENT_FIELDS:
            self.assertIn(key, actions[0], msg=f"missing schema field {key}")
        self.assertEqual(actions[0]["duration_ms"], 12.5)
        self.assertEqual(actions[0]["finding_ids"], ["f1"])

        log_action(
            "tlog",
            phase="RECON",
            target="http://a",
            tool="run_surface_chain_step",
            args={"playbook": "web_surface"},
            exit_code=0,
            duration_ms=40.0,
            source="harness",
            extra={"playbook": "web_surface", "event": "chain_step"},
        )
        tl = task_timeline("tlog", limit=50)
        self.assertTrue(tl.get("ok"))
        self.assertEqual(tl.get("task_id"), "tlog")
        self.assertGreaterEqual(tl.get("count") or 0, 2)
        self.assertIn("events", tl)
        self.assertIn("duration_ms_sum", tl)
        self.assertGreaterEqual(float(tl.get("duration_ms_sum") or 0), 52.5)
        tools = [e.get("tool") for e in (tl.get("events") or [])]
        self.assertIn("httpx", tools)
        self.assertIn("run_surface_chain_step", tools)

        ev = save_evidence("tlog", name="httpx_out", content="OK 200", meta={"tool": "httpx"})
        self.assertTrue(Path(ev["path"]).exists())
        self.assertIn("OK 200", Path(ev["path"]).read_text(encoding="utf-8"))

    def test_chain_logs_step_duration(self):
        """Each surface step writes action_log with duration_ms; chain summary exposes total."""
        from unittest.mock import patch
        from kali_mcp.core.action_log import read_actions, task_timeline
        from kali_mcp.core.playbooks.chain import run_surface_chain
        from kali_mcp.core.task_workspace import get_workspace

        tid = "chain_dur1"
        get_workspace(tid, create=True)

        def _fake_pb(name, task_id, target, executor, depth="quick"):
            return {"ok": True, "playbook": name, "depth": depth}

        with patch(
            "kali_mcp.core.playbooks.list_playbooks",
            return_value=["web_surface", "api_surface"],
        ):
            with patch("kali_mcp.core.playbooks.run_playbook", side_effect=_fake_pb):
                with patch("kali_mcp.core.playbooks.chain.compile_handoff", return_value={}):
                    with patch(
                        "kali_mcp.core.playbooks.chain.continue_from_handoff",
                        return_value={"ok": True},
                    ):
                        with patch(
                            "kali_mcp.core.observer.apply_observer_hints",
                            return_value={"duplicate_count": 0, "suggestions": []},
                        ):
                            with patch(
                                "kali_mcp.core.insight_bridge.propose_insights",
                                return_value={"ok": True, "created_count": 0, "skipped": True},
                            ):
                                with patch(
                                    "kali_mcp.core.report_export.export_task_report",
                                    return_value={
                                        "ok": True,
                                        "markdown_path": f"/tmp/{tid}/report.md",
                                        "paths": {"markdown": f"/tmp/{tid}/report.md"},
                                    },
                                ):
                                    out = run_surface_chain(
                                        tid,
                                        "http://lab.local/",
                                        executor=MagicMock(),
                                        depth="quick",
                                        playbooks="web_surface,api_surface",
                                        seed_task=True,
                                    )
        self.assertTrue(out.get("ok"))
        self.assertIn("elapsed_ms", out)
        self.assertIsInstance(out.get("elapsed_ms"), (int, float))
        steps = out.get("steps") or []
        self.assertEqual(len(steps), 2)
        for s in steps:
            self.assertIn("duration_ms", s)
            self.assertIsInstance(s.get("duration_ms"), (int, float))

        acts = read_actions(tid, limit=50)
        step_acts = [a for a in acts if a.get("tool") == "run_surface_chain_step"]
        self.assertGreaterEqual(len(step_acts), 2)
        for a in step_acts:
            self.assertIsNotNone(a.get("duration_ms"))
            self.assertEqual((a.get("extra") or {}).get("event"), "chain_step")

        end_acts = [a for a in acts if a.get("tool") == "run_surface_chain" and (a.get("extra") or {}).get("event") == "chain_end"]
        self.assertTrue(end_acts, msg="chain_end action missing")
        self.assertIsNotNone(end_acts[-1].get("duration_ms"))

        export_acts = [a for a in acts if a.get("tool") == "export_task_report"]
        self.assertTrue(export_acts, msg="export_task_report action missing")
        self.assertIsNotNone(export_acts[-1].get("duration_ms"))

        tl = task_timeline(tid)
        self.assertTrue(tl.get("ok"))
        self.assertGreaterEqual(tl.get("count") or 0, 3)

    def test_verify_finding_match(self):
        from kali_mcp.core.verifier import register_candidate, verify_finding

        f = register_candidate(
            "tv",
            title="demo",
            target="http://lab",
            reproduce_cmd="echo FLAG_HIT",
            expected_signal="FLAG_HIT",
            source="test",
        )
        executor = MagicMock()
        executor.execute_command.return_value = {
            "success": True,
            "output": "line\nFLAG_HIT\n",
            "error": "",
            "return_code": 0,
            "command": "echo FLAG_HIT",
        }
        result = verify_finding("tv", f["finding_id"], executor=executor)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "verified")

    def test_verify_finding_false_positive(self):
        from kali_mcp.core.verifier import register_candidate, verify_finding

        f = register_candidate(
            "tv2",
            title="demo2",
            target="http://lab",
            reproduce_cmd="echo nope",
            expected_signal="FLAG_HIT",
            source="test",
        )
        executor = MagicMock()
        executor.execute_command.return_value = {
            "success": True,
            "output": "nothing here",
            "error": "",
            "return_code": 0,
            "command": "echo nope",
        }
        result = verify_finding("tv2", f["finding_id"], executor=executor)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "false_positive")

    def test_web_surface_playbook_with_mock_executor(self):
        from kali_mcp.core.playbooks import run_playbook

        executor = MagicMock()

        def _exec_tool(tool_name, data):
            return {
                "success": True,
                "output": f"{tool_name} ok for {data.get('url') or data.get('target')}",
                "error": "",
                "return_code": 0,
                "parsed": {
                    "tool_name": tool_name,
                    "success": True,
                    "summary": f"{tool_name} summary",
                    "structured_data": {"technologies": ["nginx"]} if tool_name == "whatweb" else {},
                    "confidence": 0.7,
                    "severity": "info",
                },
            }

        executor.execute_tool_with_data.side_effect = _exec_tool
        out = run_playbook("web_surface", "pb1", "http://lab.local", executor, depth="quick")
        self.assertTrue(out["ok"])
        self.assertEqual(out["playbook"], "web_surface")
        self.assertGreaterEqual(len(out["steps"]), 2)
        self.assertGreaterEqual(out["graph_summary"]["nodes"], 1)

    def test_harness_register_importable(self):
        from kali_mcp.mcp_tools.harness_tools import register_harness_tools

        mcp = MagicMock()
        # simulate decorator
        def tool_decorator():
            def deco(fn):
                return fn

            return deco

        mcp.tool = tool_decorator
        register_harness_tools(mcp, MagicMock())

    def test_httpx_builder_uses_target_url(self):
        from kali_mcp.core.tool_registry import build_command

        cmd1 = build_command("httpx", {"target": "http://127.0.0.1:18080/"})
        cmd2 = build_command("httpx", {"url": "http://lab.local/"})
        cmd3 = build_command("httpx", {"targets": "http://a/"})
        self.assertIn("httpx", cmd1)
        self.assertIn("-u", cmd1)
        self.assertIn("http://127.0.0.1:18080/", cmd1)
        self.assertNotIn("echo  |", cmd1)
        self.assertIn("http://lab.local/", cmd2)
        self.assertIn("http://a/", cmd3)
        empty = build_command("httpx", {})
        self.assertEqual(empty, "")

    def test_httpx_prefers_go_binary_when_present(self):
        from unittest.mock import patch
        from kali_mcp.core import tool_registry as tr

        fake = "/tmp/fake-pd-httpx"
        with patch.object(tr.os.path, "isfile", side_effect=lambda p: p == fake), patch.object(
            tr.os, "access", return_value=True
        ), patch.object(tr.os.path, "getsize", return_value=10_000_000), patch.dict(
            tr.os.environ, {"KALI_MCP_HTTPX_BIN": fake}, clear=False
        ):
            cmd = tr.build_command("httpx", {"target": "http://x/"})
        self.assertIn(fake, cmd)
        self.assertIn("-u", cmd)
        self.assertIn("http://x/", cmd)

    def test_gobuster_path_extract_and_handoff(self):
        from kali_mcp.core.handoff import compile_handoff, continue_from_handoff
        from kali_mcp.core.playbooks.web_surface import _extract_gobuster_paths
        from kali_mcp.core.target_graph import get_graph
        from kali_mcp.core.task_workspace import get_workspace

        paths = _extract_gobuster_paths(
            "/admin (Status: 200)\n/api (Status: 200)\n/nope (Status: 404)\n",
            "http://lab/",
        )
        self.assertIn("http://lab/admin", paths)
        self.assertIn("http://lab/api", paths)
        self.assertTrue(all("404" not in p for p in paths))

        ws = get_workspace("handoff1", create=True)
        g = get_graph(ws.task_id)
        g.upsert_node("url", "http://lab/", next_checks=["verify_candidates"])
        g.save()
        payload = compile_handoff(ws.task_id)
        self.assertTrue(Path(payload["handoff_json"]).exists())
        self.assertTrue(Path(payload["progress_md"]).exists())
        cont = continue_from_handoff(ws.task_id)
        self.assertTrue(cont["ok"])
        self.assertEqual(cont["task_id"], ws.task_id)

    def test_continue_from_handoff_does_not_clobber_terminal_meta(self):
        """chain_done + empty next must not become status=resumed."""
        from kali_mcp.core.handoff import compile_handoff, continue_from_handoff
        from kali_mcp.core.task_workspace import get_workspace

        ws = get_workspace("handoff_term1", create=True)
        ws.update_meta(status="chain_done", phase="REPORT", targets=["http://lab/"])
        compile_handoff(ws.task_id)
        # read-only check used by chain finalization
        cont_ro = continue_from_handoff(ws.task_id, update_status=False)
        self.assertTrue(cont_ro["ok"])
        self.assertFalse((cont_ro.get("resume") or {}).get("mutated_meta"))
        meta_ro = ws.read_meta()
        self.assertEqual(meta_ro.get("status"), "chain_done")
        self.assertEqual(meta_ro.get("phase"), "REPORT")
        # mutating continue with empty next still leaves terminal alone
        cont = continue_from_handoff(ws.task_id, update_status=True)
        self.assertTrue(cont["ok"])
        meta = ws.read_meta()
        self.assertEqual(meta.get("status"), "chain_done")
        self.assertEqual(meta.get("phase"), "REPORT")

    def test_continue_keeps_terminal_when_only_insight_residual(self):
        """chain_done + residual insight_verify must not become status=resumed."""
        from kali_mcp.core.handoff import compile_handoff, continue_from_handoff
        from kali_mcp.core.target_graph import get_graph
        from kali_mcp.core.task_workspace import get_workspace

        ws = get_workspace("handoff_insight_res", create=True)
        ws.update_meta(status="chain_done", phase="REPORT", targets=["http://lab/"])
        g = get_graph(ws.task_id)
        g.upsert_node(
            "url",
            "http://lab/",
            confidence=0.9,
            next_checks=["insight_verify:abc123"],
            meta={"last_tool": "web_surface"},
        )
        g.save()
        compile_handoff(ws.task_id)
        cont = continue_from_handoff(ws.task_id, update_status=True)
        self.assertTrue(cont["ok"])
        self.assertFalse((cont.get("resume") or {}).get("mutated_meta"))
        self.assertTrue((cont.get("resume") or {}).get("next_actions"))
        self.assertTrue((cont.get("resume") or {}).get("insight_residual_only"))
        meta = ws.read_meta()
        self.assertEqual(meta.get("status"), "chain_done")
        self.assertEqual(meta.get("phase"), "REPORT")

    def test_chain_clears_insight_residual_on_success(self):
        """Successful chain_done should clear sticky insight_verify next_checks."""
        from unittest.mock import MagicMock, patch
        from kali_mcp.core.playbooks.chain import run_surface_chain
        from kali_mcp.core.target_graph import get_graph
        from kali_mcp.core.task_workspace import get_workspace

        tid = "chain_clear_insight"
        ws = get_workspace(tid, create=True)
        g = get_graph(tid)
        g.upsert_node(
            "url",
            "http://lab.local/",
            confidence=0.9,
            next_checks=["insight_verify:deadbeef"],
            meta={"last_tool": "web_surface"},
        )
        g.save()
        ex = MagicMock()

        def _pb(name, task_id, target, executor, depth="quick", **kwargs):
            return {"ok": True, "playbook": name}

        with patch("kali_mcp.core.playbooks.run_playbook", side_effect=_pb), patch(
            "kali_mcp.core.playbooks.list_playbooks",
            return_value=["web_surface"],
        ), patch(
            "kali_mcp.core.report_export.export_task_report",
            return_value={
                "ok": True,
                "markdown_path": f"/tmp/{tid}/report.md",
                "paths": {"markdown": f"/tmp/{tid}/report.md"},
            },
        ), patch(
            "kali_mcp.core.observer.apply_observer_hints",
            return_value={"ok": True, "duplicate_count": 0, "suggestions": []},
        ), patch(
            "kali_mcp.core.insight_bridge.propose_insights",
            return_value={"ok": True, "created_count": 0, "hypotheses": [], "skipped": True},
        ):
            out = run_surface_chain(
                tid,
                "http://lab.local/",
                ex,
                depth="quick",
                playbooks=["web_surface"],
            )
        self.assertTrue(out.get("ok"))
        self.assertEqual(out.get("status"), "chain_done")
        g2 = get_graph(tid, reload=True)
        residual = g2.next_actions(limit=20, include_insights=True)
        self.assertEqual(residual, [])
        meta = ws.read_meta()
        self.assertEqual(meta.get("status"), "chain_done")
        self.assertEqual(meta.get("phase"), "REPORT")

    def test_finding_dedupe_by_title_target(self):
        from kali_mcp.core.findings_store import list_findings, upsert_finding
        from kali_mcp.core.verifier import register_candidate

        a = register_candidate(
            "dedupe1",
            title="interesting_path:http://lab/admin",
            target="http://lab/admin",
            severity="medium",
            source="playbook",
        )
        b = register_candidate(
            "dedupe1",
            title="interesting_path:http://lab/admin",
            target="http://lab/admin",
            severity="medium",
            source="playbook",
            evidence_paths=["/tmp/e2.txt"],
        )
        items = list_findings("dedupe1")
        same = [x for x in items if "interesting_path:http://lab/admin" in str(x.get("title") or "")]
        self.assertEqual(len(same), 1)
        self.assertEqual(a["finding_id"], b["finding_id"])
        upsert_finding(
            "dedupe1",
            {
                "finding_id": a["finding_id"],
                "title": "interesting_path:http://lab/admin",
                "target": "http://lab/admin",
                "status": "verified",
            },
        )
        upsert_finding(
            "dedupe1",
            {
                "title": "interesting_path:http://lab/admin",
                "target": "http://lab/admin",
                "status": "candidate",
            },
        )
        final = list_findings("dedupe1")
        self.assertEqual(len(final), 1)
        self.assertEqual(final[0]["status"], "verified")
        from kali_mcp.core.findings_store import set_status

        set_status("dedupe1", a["finding_id"], "false_positive", note="test")
        after = list_findings("dedupe1")
        self.assertEqual(after[0]["status"], "false_positive")

    def test_finding_dedupe_trailing_slash_variants(self):
        from kali_mcp.core.findings_store import list_findings
        from kali_mcp.core.verifier import register_candidate

        a = register_candidate(
            "dedupe_slash",
            title="auth_entry:http://127.0.0.1:18081/login",
            target="http://127.0.0.1:18081/login",
            severity="medium",
            source="playbook",
        )
        b = register_candidate(
            "dedupe_slash",
            title="auth_entry:http://127.0.0.1:18081/login/",
            target="http://127.0.0.1:18081/login/",
            severity="medium",
            source="playbook",
        )
        c = register_candidate(
            "dedupe_slash",
            title="api_endpoint:http://127.0.0.1:18081/api",
            target="http://127.0.0.1:18081/api",
            severity="medium",
            source="playbook",
        )
        d = register_candidate(
            "dedupe_slash",
            title="api_endpoint:http://127.0.0.1:18081/api/",
            target="http://127.0.0.1:18081/api/",
            severity="medium",
            source="playbook",
        )
        items = list_findings("dedupe_slash")
        self.assertEqual(len(items), 2)
        self.assertEqual(a["finding_id"], b["finding_id"])
        self.assertEqual(c["finding_id"], d["finding_id"])
        titles = sorted(str(x.get("title") or "") for x in items)
        targets = sorted(str(x.get("target") or "") for x in items)
        self.assertTrue(all(not t.endswith("/") or t.endswith("://") for t in titles))
        self.assertTrue(all(not t.endswith("/") for t in targets))
        self.assertIn("auth_entry:http://127.0.0.1:18081/login", titles)
        self.assertIn("api_endpoint:http://127.0.0.1:18081/api", titles)

    def test_generic_parser_success_summary_not_failed(self):
        from kali_mcp.core.output_parsers._generic import GenericParser
        from kali_mcp.core.output_parsers import parse_output

        p = GenericParser()
        r = p.parse(
            "http://127.0.0.1:18080/ [200] [P0 Lab] [SimpleHTTP]",
            0,
            {"_tool_name": "httpx", "target": "http://127.0.0.1:18080/"},
        )
        self.assertTrue(r.success)
        self.assertIn("执行成功", r.summary)
        self.assertNotIn("执行失败", r.summary)
        fixed = parse_output(
            "httpx",
            "http://127.0.0.1:18080/ [200] [P0 Lab]",
            0,
            {"target": "http://127.0.0.1:18080/"},
        )
        self.assertTrue(fixed.success)
        self.assertIn("执行成功", fixed.summary)
        # bool True as return_code is int(True)==1 -> non-zero failure path
        broken = parse_output(
            "httpx",
            "http://127.0.0.1:18080/ [200] [P0 Lab]",
            True,  # type: ignore[arg-type]
            {"target": "http://127.0.0.1:18080/"},
        )
        self.assertFalse(broken.success)
        self.assertIn("执行失败", broken.summary)

    def test_next_actions_skips_defaults_after_evidence(self):
        from kali_mcp.core.target_graph import get_graph

        g = get_graph("na1")
        g.upsert_node(
            "url",
            "http://lab/",
            next_checks=[],
            evidence_path="/tmp/e.txt",
            meta={"last_tool": "httpx"},
        )
        g.save()
        actions = g.next_actions()
        self.assertFalse(any(a.get("source") == "default" for a in actions))
        self.assertFalse(any(a.get("action") == "fingerprint" for a in actions))

    def test_gobuster_build_single_u(self):
        from kali_mcp.core.tool_registry import build_command

        cmd = build_command(
            "gobuster",
            {
                "url": "http://127.0.0.1:18080/",
                "target": "http://127.0.0.1:18080/",
                "wordlist": "/usr/share/wordlists/dirb/common.txt",
                "threads": 20,
            },
        )
        self.assertEqual(cmd.count("-u"), 1)
        self.assertIn("http://127.0.0.1:18080/", cmd)

    def test_harness_profile_only_allows_harness_module(self):
        from kali_mcp.security.tool_profile import load_tool_profile

        p = load_tool_profile("harness")
        self.assertTrue(p.allows("harness"))
        self.assertFalse(p.allows("recon"))
        self.assertFalse(p.allows("apt"))
        self.assertFalse(p.allows("browser"))
        self.assertFalse(p.allows("assessment"))

    def test_playbook_registry_four(self):
        from kali_mcp.core.playbooks import list_playbooks

        names = list_playbooks()
        self.assertEqual(
            names, ["api_surface", "auth_surface", "svc_surface", "web_surface"]
        )

    def test_api_surface_with_mock_executor(self):
        from unittest.mock import MagicMock
        from kali_mcp.core.playbooks import run_playbook
        from kali_mcp.core.findings_store import list_findings

        ex = MagicMock()
        seen = []

        def _cmd(cmd):
            seen.append(cmd)
            # only exact /api root returns 200 (not /api/v1, not /api/)
            if "http://lab.local/api\"" in cmd or "http://lab.local/api " in cmd:
                body = '{"status":"ok","version":"1.0"}\n__HTTP_CODE__:200'
            else:
                body = "Not Found\n__HTTP_CODE__:404"
            return {
                "success": True,
                "output": body,
                "error": "",
                "return_code": 0,
                "command": cmd,
            }

        ex.execute_command.side_effect = _cmd
        out = run_playbook(
            "api_surface",
            "api_mock1",
            "http://lab.local/",
            ex,
            depth="quick",
        )
        self.assertTrue(out.get("ok"))
        self.assertEqual(out.get("playbook"), "api_surface")
        self.assertGreaterEqual(len(out.get("hits") or []), 1)
        # assert on playbook path list, not raw curl strings (verify also curls root)
        step_paths = [str(s.get("path") or "") for s in (out.get("steps") or [])]
        self.assertEqual(step_paths.count("/api"), 1)
        self.assertNotIn("/api/", step_paths)
        findings = out.get("findings") or list_findings("api_mock1")
        api_findings = [
            f for f in findings if str(f.get("title") or "").startswith("api_endpoint:")
        ]
        self.assertEqual(len(api_findings), 1)
        # optional: no explicit trailing-slash twin in probe phase commands
        self.assertFalse(any('http://lab.local/api/"' in s for s in seen if "__HTTP_CODE__" in s))

    def test_auth_surface_with_mock_executor(self):
        from unittest.mock import MagicMock
        from kali_mcp.core.playbooks import run_playbook
        from kali_mcp.core.findings_store import list_findings

        ex = MagicMock()

        def _cmd(cmd):
            # only exact /login root is a login page; avoid /admin/login etc.
            if '"http://lab.local/login"' in cmd and "admin/login" not in cmd:
                body = (
                    '<html><body><form>'
                    '<input name="username">'
                    '<input type="password" name="password">'
                    "login"
                    "</form></body></html>\n__HTTP_CODE__:200"
                )
            else:
                body = "Not Found\n__HTTP_CODE__:404"
            return {
                "success": True,
                "output": body,
                "error": "",
                "return_code": 0,
                "command": cmd,
            }

        ex.execute_command.side_effect = _cmd
        out = run_playbook(
            "auth_surface",
            "auth_mock1",
            "http://lab.local/",
            ex,
            depth="quick",
        )
        self.assertTrue(out.get("ok"))
        self.assertEqual(out.get("playbook"), "auth_surface")
        self.assertGreaterEqual(len(out.get("hits") or []), 1)
        step_paths = [str(s.get("path") or "") for s in (out.get("steps") or [])]
        self.assertEqual(step_paths.count("/login"), 1)
        self.assertNotIn("/login/", step_paths)
        findings = out.get("findings") or list_findings("auth_mock1")
        auth_findings = [
            f for f in findings if str(f.get("title") or "").startswith("auth_entry:")
        ]
        self.assertEqual(len(auth_findings), 1)

    def test_svc_surface_with_mock_executor(self):
        from unittest.mock import MagicMock
        from kali_mcp.core.playbooks import run_playbook
        from kali_mcp.core.findings_store import list_findings

        ex = MagicMock()

        def _tool(name, data):
            return {
                "success": True,
                "output": "22/tcp open ssh\n80/tcp open http\n",
                "error": "",
                "return_code": 0,
                "parsed": {
                    "tool_name": "nmap",
                    "success": True,
                    "summary": "2 open ports",
                    "structured_data": {
                        "ports": [
                            {"port": "22", "service": "ssh"},
                            {"port": "80", "service": "http"},
                        ]
                    },
                    "confidence": 0.8,
                    "severity": "info",
                },
            }

        def _cmd(cmd):
            return {
                "success": True,
                "output": str(cmd) + "\n22/tcp open ssh\n",
                "error": "",
                "return_code": 0,
                "command": cmd,
            }

        ex.execute_tool_with_data.side_effect = _tool
        ex.execute_command.side_effect = _cmd
        out = run_playbook(
            "svc_surface",
            "svc_mock1",
            "http://10.0.0.5/",
            ex,
            depth="quick",
        )
        self.assertTrue(out.get("ok"))
        self.assertEqual(out.get("playbook"), "svc_surface")
        self.assertGreaterEqual(len(out.get("open_ports") or []), 1)
        findings = out.get("findings") or list_findings("svc_mock1")
        port_findings = [
            f for f in findings if str(f.get("title") or "").startswith("open_port:")
        ]
        self.assertGreaterEqual(len(port_findings), 1)

    def test_executor_active_task_hook(self):
        from kali_mcp.core.local_executor import LocalCommandExecutor
        from kali_mcp.core.task_context import clear_active_task, set_active_task
        from kali_mcp.core.target_graph import get_graph
        from kali_mcp.core.action_log import read_actions

        set_active_task("hook1")
        try:
            ex = LocalCommandExecutor(timeout=10)
            r = ex.execute_tool_with_data(
                "whatweb",
                {"target": "http://example.invalid/", "url": "http://example.invalid/", "phase": "RECON"},
            )
            # may fail network; hook should still attach task fields when possible
            self.assertIn("tool_name", r)
            logs = read_actions("hook1")
            # if command built and ran, executor hook logs; allow empty if build failed early
            g = get_graph("hook1", reload=True)
            self.assertEqual(g.task_id, "hook1")
        finally:
            clear_active_task()

    def test_run_surface_chain_order_and_depths(self):
        """Sequential four-surface chain without run_goal; mixed depths."""
        from unittest.mock import MagicMock, patch
        from kali_mcp.core.playbooks import DEFAULT_SURFACE_ORDER, run_surface_chain
        from kali_mcp.core.task_workspace import get_workspace

        ex = MagicMock()
        calls = []

        def _fake_run(name, task_id, target, executor, depth="standard", **kwargs):
            calls.append({"name": name, "depth": depth, "target": target, "task_id": task_id})
            return {"ok": True, "playbook": name, "depth": depth}

        with patch("kali_mcp.core.playbooks.run_playbook", side_effect=_fake_run):
            out = run_surface_chain(
                task_id="chain_mock1",
                target="http://lab.local/",
                executor=ex,
                depth="mixed",
                seed_task=True,
            )
        self.assertTrue(out.get("ok"))
        self.assertEqual(out.get("mode"), "surface_chain")
        self.assertEqual([c["name"] for c in calls], list(DEFAULT_SURFACE_ORDER))
        self.assertEqual(calls[0]["depth"], "standard")
        self.assertEqual(calls[1]["depth"], "quick")
        self.assertEqual(calls[2]["depth"], "quick")
        self.assertEqual(calls[3]["depth"], "quick")
        self.assertEqual(len(out.get("steps") or []), 4)
        self.assertTrue(all(s.get("ok") for s in out["steps"]))
        ws = get_workspace("chain_mock1", create=True)
        self.assertTrue((ws.report_dir / "chain_summary.json").exists())
        self.assertEqual(out.get("continue_ok"), True)
        self.assertTrue(out.get("report_path"))

    def test_run_surface_chain_subset_and_stop_on_error(self):
        from unittest.mock import MagicMock, patch
        from kali_mcp.core.playbooks import run_surface_chain

        ex = MagicMock()
        calls = []

        def _fake_run(name, task_id, target, executor, depth="standard", **kwargs):
            calls.append(name)
            if name == "api_surface":
                return {"ok": False, "error": "boom"}
            return {"ok": True, "playbook": name}

        with patch("kali_mcp.core.playbooks.run_playbook", side_effect=_fake_run):
            out = run_surface_chain(
                task_id="chain_stop1",
                target="http://lab.local/",
                executor=ex,
                depth="quick",
                playbooks="web_surface,api_surface,auth_surface",
                stop_on_error=True,
            )
        self.assertFalse(out.get("ok"))
        self.assertTrue(out.get("aborted"))
        self.assertEqual(calls, ["web_surface", "api_surface"])
        self.assertEqual(out.get("status"), "chain_aborted")
        self.assertEqual(len(out.get("steps") or []), 2)

    def test_observer_detects_duplicates(self):
        from kali_mcp.core.action_log import log_action
        from kali_mcp.core.observer import analyze_actions, apply_observer_hints

        tid = "obs_dup1"
        for _ in range(3):
            log_action(
                tid,
                phase="RECON",
                target="http://lab.local/",
                tool="httpx",
                args={"u": "http://lab.local/"},
                exit_code=0,
                source="playbook",
            )
        report = analyze_actions(tid, duplicate_threshold=2)
        self.assertGreaterEqual(report.get("duplicate_count") or 0, 1)
        self.assertTrue(report.get("suggestions"))
        applied = apply_observer_hints(tid, auto_mark_dead=False)
        self.assertTrue(applied.get("ok"))
        self.assertEqual(applied.get("marked_dead"), [])

    def test_propose_insights_bound_and_no_execute(self):
        from kali_mcp.core.findings_store import list_findings
        from kali_mcp.core.insight_bridge import propose_insights
        from kali_mcp.core.target_graph import get_graph

        tid = "insight1"
        g = get_graph(tid)
        g.upsert_node("url", "http://lab.local/", confidence=0.9, next_checks=[])
        # mark as "done" so default next_actions empty → stuck
        node = list(g.nodes.values())[0]
        node.meta["last_tool"] = "httpx"
        node.evidence_paths = ["e1"]
        g.save()

        out = propose_insights(tid, force=True, max_per_phase=2)
        self.assertTrue(out.get("ok"))
        self.assertFalse(out.get("drive_executor"))
        self.assertFalse(out.get("enqueue_verify"))
        self.assertGreaterEqual(out.get("created_count") or 0, 1)
        findings = list_findings(tid)
        insight_fs = [f for f in findings if f.get("source") == "insight"]
        self.assertTrue(insight_fs)
        for f in insight_fs:
            self.assertEqual(f.get("status"), "candidate")
            self.assertTrue(f.get("reproduce_cmd"))
            self.assertTrue(f.get("meta", {}).get("bound_node_id"))
            # must not appear as verified without verify
            self.assertNotEqual(f.get("status"), "verified")

        # default enqueue_verify=False: no sticky insight_verify on graph
        g2 = get_graph(tid, reload=True)
        plain = g2.next_actions(limit=50, include_insights=False)
        with_i = g2.next_actions(limit=50, include_insights=True)
        self.assertFalse(any(a.get("source") == "insight" for a in plain))
        self.assertFalse(any(str(a.get("action") or "").startswith("insight_verify:") for a in with_i))

        # opt-in sticky queue still works when explicitly requested
        out2 = propose_insights(tid, force=True, max_per_phase=1, enqueue_verify=True)
        self.assertTrue(out2.get("ok"))
        self.assertTrue(out2.get("enqueue_verify"))
        g3 = get_graph(tid, reload=True)
        with_i2 = g3.next_actions(limit=50, include_insights=True)
        self.assertTrue(
            any(str(a.get("action") or "").startswith("insight_verify:") for a in with_i2)
            or any(a.get("source") == "insight" for a in with_i2)
        )

    def test_propose_insights_rejects_unbound_via_dead(self):
        from kali_mcp.core.insight_bridge import propose_insights
        from kali_mcp.core.target_graph import get_graph

        tid = "insight_dead"
        g = get_graph(tid)
        n = g.upsert_node("url", "http://dead.local/", confidence=0.9)
        g.mark_dead(n.id, "blocked")
        g.save()
        out = propose_insights(tid, force=True, max_per_phase=5)
        self.assertTrue(out.get("ok"))
        # dead nodes should not yield created hypotheses on that target
        for f in out.get("hypotheses") or []:
            self.assertNotIn("dead.local", (f.get("target") or ""))

    def test_attack_coverage_stats(self):
        from kali_mcp.core.attack_coverage import task_attack_coverage
        from kali_mcp.core.findings_store import upsert_finding

        tid = "atk_cov1"
        upsert_finding(
            tid,
            {
                "title": "n1",
                "target": "http://x/",
                "status": "verified",
                "technique_ids": ["T1190", "T1595"],
                "source": "scan",
            },
        )
        upsert_finding(
            tid,
            {
                "title": "n2",
                "target": "http://y/",
                "status": "candidate",
                "technique_ids": [],
                "source": "insight",
            },
        )
        cov = task_attack_coverage(tid)
        self.assertTrue(cov.get("ok"))
        self.assertIn("T1190", cov["all"]["techniques"])
        self.assertEqual(cov["all"]["unlabeled_count"], 1)
        self.assertEqual(cov["verified_only"]["labeled_count"], 1)
        self.assertIn("Initial Access", cov["verified_only"]["tactics_present"])

    def test_export_task_report_markdown(self):
        from kali_mcp.core.action_log import log_action
        from kali_mcp.core.findings_store import upsert_finding
        from kali_mcp.core.report_export import export_task_report, render_markdown, build_report_payload
        from kali_mcp.core.target_graph import get_graph
        from kali_mcp.core.task_workspace import get_workspace

        tid = "rpt_md1"
        ws = get_workspace(tid, create=True)
        ws.update_meta(targets=["http://lab.local/"], phase="REPORT", status="open", depth="standard")
        g = get_graph(tid)
        g.upsert_node("url", "http://lab.local/", confidence=0.9)
        g.save()
        upsert_finding(
            tid,
            {
                "title": "open_admin",
                "target": "http://lab.local/admin",
                "status": "verified",
                "severity": "high",
                "reproduce_cmd": "curl -i http://lab.local/admin",
                "expected_signal": "200",
                "evidence_paths": ["evidence/admin.txt"],
                "technique_ids": ["T1190"],
                "source": "scan",
                "raw_notes": "admin panel reachable",
            },
        )
        upsert_finding(
            tid,
            {
                "title": "insight_guess",
                "target": "http://lab.local/debug",
                "status": "candidate",
                "source": "insight",
                "reproduce_cmd": "curl -i http://lab.local/debug",
            },
        )
        log_action(
            tid,
            phase="VERIFY",
            target="http://lab.local/admin",
            tool="curl",
            args={"u": "http://lab.local/admin"},
            exit_code=0,
            duration_ms=42.5,
            evidence_path="evidence/admin.txt",
            finding_ids=["x"],
            source="playbook",
        )

        out = export_task_report(tid, formats=["json", "markdown"])
        self.assertTrue(out.get("ok"))
        self.assertEqual(out.get("verified_count"), 1)
        self.assertEqual(out.get("candidate_count"), 1)
        md_path = Path(out["markdown_path"])
        self.assertTrue(md_path.exists())
        text = md_path.read_text(encoding="utf-8")
        self.assertIn("Verified Findings", text)
        self.assertIn("open_admin", text)
        self.assertIn("curl -i http://lab.local/admin", text)
        self.assertIn("执行时间线", text)
        self.assertIn("duration_ms", text)
        self.assertIn("42.5", text)
        self.assertIn("duration_ms_sum", text)
        self.assertIn("ATT&CK", text)
        # candidate only in appendix section, not mixed as sole main content
        self.assertIn("Candidate", text)
        self.assertIn("insight_guess", text)
        self.assertTrue((ws.report_dir / "summary.json").exists())

        payload = build_report_payload(tid)
        self.assertIn("timeline", payload)
        self.assertGreaterEqual(float((payload.get("timeline") or {}).get("duration_ms_sum") or 0), 42.5)
        md2 = render_markdown(payload)
        self.assertIn(tid, md2)
        self.assertGreater(len(md2), 200)

    def test_status_check_summarizes_action_duration(self):
        """status_check task summary surfaces duration_ms_sum from actions.jsonl."""
        from kali_mcp.core.action_log import log_action
        from kali_mcp.core.task_workspace import get_workspace
        import status_check as sc

        tid = "status_dur1"
        ws = get_workspace(tid, create=True)
        ws.update_meta(phase="RECON", status="open", targets=["http://lab.local/"])
        log_action(tid, tool="httpx", phase="RECON", duration_ms=10.0, source="executor", exit_code=0)
        log_action(tid, tool="curl", phase="VERIFY", duration_ms=5.5, source="playbook", exit_code=0)
        summary = sc.summarize_task_dir(ws.root)
        self.assertEqual(summary.get("task_id"), tid)
        self.assertGreaterEqual(int(summary.get("actions_count") or 0), 2)
        self.assertGreaterEqual(float(summary.get("duration_ms_sum") or 0), 15.5)
        self.assertGreaterEqual(int(summary.get("duration_ms_known_count") or 0), 2)

    def test_export_task_report_docx(self):
        """Optional docx export: report/report.docx + docx_path; missing dep is soft-fail."""
        from kali_mcp.core.findings_store import upsert_finding
        from kali_mcp.core.report_export import export_task_report, render_docx, build_report_payload
        from kali_mcp.core.task_workspace import get_workspace

        tid = "rpt_docx1"
        ws = get_workspace(tid, create=True)
        ws.update_meta(targets=["http://lab.local/"], phase="REPORT", status="open", depth="standard")
        upsert_finding(
            tid,
            {
                "title": "open_admin",
                "target": "http://lab.local/admin",
                "status": "verified",
                "severity": "high",
                "reproduce_cmd": "curl -i http://lab.local/admin",
                "expected_signal": "200",
                "technique_ids": ["T1190"],
                "source": "scan",
            },
        )
        upsert_finding(
            tid,
            {
                "title": "insight_guess",
                "target": "http://lab.local/debug",
                "status": "candidate",
                "source": "insight",
            },
        )

        out = export_task_report(tid, formats=["docx"])
        self.assertTrue(out.get("ok"))
        self.assertEqual(out.get("verified_count"), 1)
        docx_path = out.get("docx_path") or (out.get("paths") or {}).get("docx") or ""
        self.assertTrue(docx_path, msg=f"docx_path missing: {out}")
        p = Path(docx_path)
        self.assertTrue(p.exists())
        self.assertEqual(p.name, "report.docx")
        self.assertGreater(p.stat().st_size, 500)
        # no default redaction of reproduce cmd in payload path
        payload = build_report_payload(tid)
        built = render_docx(payload)
        self.assertTrue(built.get("ok"), msg=str(built))
        self.assertTrue(built.get("bytes") or built.get("path") or built.get("document"))

    def test_executor_result_cache_hit(self):
        """Same tool+target+params second call returns cache_hit without re-exec."""
        from unittest.mock import patch
        from kali_mcp.core.local_executor import LocalCommandExecutor
        from kali_mcp.core.result_cache import reset_result_cache

        reset_result_cache()
        ex = LocalCommandExecutor(timeout=10)
        data = {"target": "http://cache.lab/", "url": "http://cache.lab/"}
        real = {
            "success": True,
            "output": "httpx 200 cache.lab",
            "error": "",
            "return_code": 0,
            "command": "httpx -u http://cache.lab/",
        }
        with patch.object(ex, "execute_command", return_value=dict(real)) as mock_run:
            with patch.object(ex, "_build_tool_command", return_value="httpx -u http://cache.lab/"):
                r1 = ex.execute_tool_with_data("httpx", dict(data))
                r2 = ex.execute_tool_with_data("httpx", dict(data))
        self.assertTrue(r1.get("success"))
        self.assertFalse(r1.get("cache_hit"))
        self.assertTrue(r2.get("success"))
        self.assertTrue(r2.get("cache_hit"))
        self.assertTrue(r2.get("cached"))
        self.assertEqual(mock_run.call_count, 1)
        # no_cache bypass
        with patch.object(ex, "execute_command", return_value=dict(real)) as mock_run2:
            with patch.object(ex, "_build_tool_command", return_value="httpx -u http://cache.lab/"):
                r3 = ex.execute_tool_with_data(
                    "httpx", {**data, "no_cache": True}
                )
        self.assertFalse(r3.get("cache_hit"))
        self.assertEqual(mock_run2.call_count, 1)
        reset_result_cache()

    def test_yaml_recipes_pilot_render_and_fallback(self):
        """tools_recipes pilot: list/load/render; no_recipe falls back to registry."""
        from kali_mcp.core.recipe_loader import (
            get_recipe,
            list_recipes,
            render_recipe_command,
            reset_recipes,
        )
        from kali_mcp.core.tool_registry import build_command

        reset_recipes()
        names = list_recipes()
        for need in ("httpx", "nmap", "gobuster", "whatweb", "nuclei"):
            self.assertIn(need, names)
            self.assertIsNotNone(get_recipe(need))

        hx = render_recipe_command("httpx", {"target": "http://127.0.0.1:18081/"})
        self.assertIn("-u", hx)
        self.assertIn("http://127.0.0.1:18081/", hx)
        self.assertIn("-no-stdin", hx)
        self.assertIn("-timeout", hx)

        nm = render_recipe_command(
            "nmap",
            {"target": "10.0.0.5", "ports": "22,80", "scan_type": "-sV -T4 --open"},
        )
        self.assertIn("nmap", nm)
        self.assertIn("10.0.0.5", nm)
        self.assertIn("-p", nm)

        gb = render_recipe_command(
            "gobuster",
            {"url": "http://lab.local/", "target": "http://lab.local/"},
        )
        self.assertIn("gobuster", gb)
        self.assertEqual(gb.count("-u"), 1)

        # build_command prefers recipe when present
        via_build = build_command("whatweb", {"target": "http://lab.local/"})
        self.assertIn("whatweb", via_build)
        self.assertIn("http://lab.local/", via_build)

        # skip recipe falls back (still builds via registry/custom)
        via_skip = build_command(
            "httpx",
            {"target": "http://lab.local/", "no_recipe": True},
        )
        self.assertIn("httpx", via_skip)
        self.assertIn("-u", via_skip)
        reset_recipes()

    def test_new_recipes_render(self):
        """sqlmap / ffuf / nikto / curl_probe / feroxbuster recipes load and render."""
        from kali_mcp.core.recipe_loader import (
            get_recipe,
            list_recipes,
            render_recipe_command,
            reset_recipes,
        )

        reset_recipes()
        names = list_recipes()
        for need in ("sqlmap", "ffuf", "nikto", "curl_probe", "feroxbuster", "nuclei", "httpx"):
            self.assertIn(need, names)
        sq = render_recipe_command("sqlmap", {"url": "http://lab.local/?id=1"})
        self.assertIn("sqlmap", sq)
        self.assertIn("http://lab.local/?id=1", sq)
        self.assertIn("--batch", sq)

        ff = render_recipe_command("ffuf", {"url": "http://lab.local/"})
        self.assertIn("ffuf", ff)
        self.assertIn("FUZZ", ff)

        nk = render_recipe_command("nikto", {"target": "http://lab.local/"})
        self.assertIn("nikto", nk)
        self.assertIn("http://lab.local/", nk)

        cp = render_recipe_command("curl_probe", {"target": "http://lab.local/admin"})
        self.assertIn("curl", cp)
        self.assertIn("http://lab.local/admin", cp)
        self.assertIn("__HTTP_CODE__", cp)

        fb = render_recipe_command("feroxbuster", {"url": "http://lab.local/"})
        self.assertIn("feroxbuster", fb)
        self.assertIn("FUZZ" if "FUZZ" in fb else "http://lab.local/", fb)

        # nuclei recipe aligns with registry-style flags (severity + silent + rate/timeout)
        nu = render_recipe_command("nuclei", {"target": "http://lab.local/"})
        self.assertIn("nuclei", nu)
        self.assertIn("http://lab.local/", nu)
        self.assertTrue("-s " in nu or "-severity" in nu)
        self.assertIn("-silent", nu)
        self.assertIn("-rl", nu)
        self.assertIn("-timeout", nu)
        nu_meta = get_recipe("nuclei") or {}
        self.assertTrue(nu_meta.get("notes") or nu_meta.get("min_version_note"))

        hx = get_recipe("httpx") or {}
        self.assertTrue(hx.get("notes") or hx.get("min_version_note"))
        reset_recipes()

    def test_status_check_tool_versions_shape(self):
        """status_check exposes path + version probe fields (availability independent)."""
        import status_check as sc

        rows = sc.probe_tool_versions()
        self.assertIsInstance(rows, list)
        self.assertGreaterEqual(len(rows), 5)
        names = {r.get("tool") for r in rows}
        for need in ("nmap", "nuclei", "httpx", "sqlmap", "ffuf"):
            self.assertIn(need, names)
        for r in rows:
            self.assertIn("tool", r)
            self.assertIn("available", r)
            self.assertIn("path", r)
            self.assertIn("version", r)
            self.assertIn("probe_ok", r)
            if r.get("available") and r.get("path"):
                self.assertTrue(isinstance(r.get("version"), str))

    def test_task_status_and_multi_chain(self):
        """task_status returns phase/graph/findings; run_surface_chain_multi iterates targets."""
        from unittest.mock import MagicMock
        from kali_mcp.core.task_workspace import get_workspace
        from kali_mcp.core.target_graph import get_graph
        from kali_mcp.core.findings_store import upsert_finding

        ws = get_workspace("status_test1", create=True)
        g = get_graph(ws.task_id)
        g.upsert_node("url", "http://status.lab/", confidence=0.9)
        g.save()
        upsert_finding(ws.task_id, {
            "title": "open_admin:http://status.lab/admin",
            "target": "http://status.lab/admin",
            "status": "verified",
            "source": "playbook",
        })

        mcp = MagicMock()
        calls = {}
        def _tool():
            def deco(fn):
                calls[fn.__name__] = fn
                return fn
            return deco
        mcp.tool = _tool
        from kali_mcp.mcp_tools.harness_tools import register_harness_tools
        register_harness_tools(mcp, MagicMock())

        ts = calls["task_status"]("status_test1")
        self.assertTrue(ts["ok"])
        self.assertIn("graph", ts)
        self.assertIn("findings_by_status", ts)
        self.assertEqual(ts["findings_by_status"].get("verified"), 1)
        self.assertIn("phase", ts)

        # list mode
        ts_all = calls["task_status"]()
        self.assertTrue(ts_all["ok"])
        self.assertIsInstance(ts_all["tasks"], list)

        multi = calls["run_surface_chain_multi"]
        from unittest.mock import patch

        def _fake_chain(**kwargs):
            return {
                "ok": True,
                "task_id": kwargs.get("task_id"),
                "target": kwargs.get("target"),
                "by_status": {"verified": 1},
                "findings_total": 1,
            }

        with patch(
            "kali_mcp.core.playbooks.chain.run_surface_chain",
            side_effect=lambda **kw: _fake_chain(**kw),
        ):
            seq = multi(
                targets="http://a.lab/ http://b.lab/",
                task_id="multi_seq1",
                depth="quick",
                parallel=False,
            )
            self.assertTrue(seq.get("ok"))
            self.assertEqual(seq.get("mode"), "sequential")
            self.assertIn("elapsed_sec", seq)
            self.assertEqual(len(seq.get("per_target") or []), 2)
            # sequential keeps one shared task_id
            self.assertEqual(seq.get("task_id"), "multi_seq1")

            par = multi(
                targets="http://a.lab/ http://b.lab/",
                task_id="multi_par1",
                depth="quick",
                parallel=True,
                max_workers=2,
            )
            self.assertTrue(par.get("ok"))
            self.assertEqual(par.get("mode"), "parallel")
            self.assertIn("elapsed_sec", par)
            self.assertEqual(len(par.get("per_target") or []), 2)
            # parallel uses per-target task ids (no shared graph race)
            tids = [r.get("task_id") for r in (par.get("per_target") or [])]
            self.assertEqual(len(set(tids)), 2)
            for tid in tids:
                self.assertTrue(str(tid).startswith("multi_par1"))
            self.assertIn("quota", par)
            self.assertIn("max_workers", par.get("quota") or {})

    def test_multi_chain_quotas(self):
        """Phase4: multi max_targets / max_workers env quotas are enforced."""
        import os
        from unittest.mock import MagicMock, patch

        from kali_mcp.mcp_tools.harness_tools import (
            clamp_multi_workers,
            multi_chain_quotas,
            register_harness_tools,
        )

        with patch.dict(
            os.environ,
            {
                "KALI_MCP_MULTI_MAX_TARGETS": "3",
                "KALI_MCP_MULTI_MAX_WORKERS": "2",
            },
            clear=False,
        ):
            q = multi_chain_quotas()
            self.assertEqual(q["max_targets"], 3)
            self.assertEqual(q["max_workers"], 2)
            workers, q2 = clamp_multi_workers(99, 10)
            self.assertEqual(workers, 2)
            self.assertEqual(q2["max_workers"], 2)

            mcp = MagicMock()
            calls = {}

            def _tool():
                def deco(fn):
                    calls[fn.__name__] = fn
                    return fn

                return deco

            mcp.tool = _tool
            register_harness_tools(mcp, MagicMock())
            multi = calls["run_surface_chain_multi"]

            rejected = multi(
                targets=" ".join(f"http://t{i}.lab/" for i in range(5)),
                task_id="multi_quota_reject",
                depth="quick",
            )
            self.assertFalse(rejected.get("ok"))
            self.assertIn("exceeds multi max_targets", rejected.get("error") or "")
            self.assertEqual((rejected.get("quota") or {}).get("max_targets"), 3)

            def _fake_chain(**kwargs):
                return {
                    "ok": True,
                    "task_id": kwargs.get("task_id"),
                    "target": kwargs.get("target"),
                    "by_status": {"verified": 0},
                    "findings_total": 0,
                }

            with patch(
                "kali_mcp.core.playbooks.chain.run_surface_chain",
                side_effect=lambda **kw: _fake_chain(**kw),
            ):
                ok_run = multi(
                    targets="http://a.lab/ http://b.lab/",
                    task_id="multi_quota_ok",
                    depth="quick",
                    parallel=True,
                    max_workers=99,
                )
            self.assertTrue(ok_run.get("ok"))
            self.assertEqual(ok_run.get("max_workers"), 2)
            self.assertEqual((ok_run.get("quota") or {}).get("max_workers"), 2)

    def test_cross_domain_insights_produced(self):
        """propose_insights generates cross-domain hypotheses when sqli finding exists."""
        from kali_mcp.core.task_workspace import get_workspace
        from kali_mcp.core.target_graph import get_graph
        from kali_mcp.core.findings_store import upsert_finding
        from kali_mcp.core.insight_bridge import propose_insights

        ws = get_workspace("xd_unit1", create=True)
        g = get_graph(ws.task_id)
        g.upsert_node("url", "http://127.0.0.1:18081/", confidence=0.9)
        g.save()
        upsert_finding(ws.task_id, {
            "title": "sqli_found:http://127.0.0.1:18081/?id=1",
            "target": "http://127.0.0.1:18081/?id=1",
            "status": "verified",
            "source": "playbook",
            "reproduce_cmd": "sqlmap -u 'http://127.0.0.1:18081/?id=1' --batch",
            "expected_signal": "sql",
        })
        out = propose_insights(ws.task_id, force=True, max_per_phase=10)
        self.assertTrue(out["ok"])
        self.assertFalse(out.get("drive_executor"))
        # should produce both node-bound and cross-domain hypotheses
        self.assertGreater(out["created_count"], 3)
        titles = [h.get("title", "") for h in out["hypotheses"]]
        xd = [t for t in titles if "xdomain" in t]
        self.assertGreater(len(xd), 0, "Expected at least one cross-domain hypothesis")
        for h in out["hypotheses"]:
            self.assertEqual(h.get("status"), "candidate")
            self.assertEqual(h.get("source"), "insight")

    def test_cross_domain_prefers_autonomous_engine_map(self):
        """Cross-domain hyps prefer engine mappings; still candidates only, never execute."""
        from kali_mcp.core.task_workspace import get_workspace
        from kali_mcp.core.target_graph import get_graph
        from kali_mcp.core.findings_store import list_findings, upsert_finding
        from kali_mcp.core.insight_bridge import propose_insights, get_cross_domain_map

        cmap = get_cross_domain_map()
        self.assertTrue(cmap.get("sql_injection"), msg="engine/fallback map must expose sql_injection")
        self.assertIn("command_injection", cmap["sql_injection"] or {})

        ws = get_workspace("xd_engine1", create=True)
        g = get_graph(ws.task_id)
        g.upsert_node("url", "http://127.0.0.1:18081/", confidence=0.9)
        g.save()
        upsert_finding(
            ws.task_id,
            {
                "title": "sql_injection verified path",
                "target": "http://127.0.0.1:18081/?id=1",
                "status": "verified",
                "source": "playbook",
                "reproduce_cmd": "sqlmap -u 'http://127.0.0.1:18081/?id=1' --batch",
                "expected_signal": "sql",
            },
        )
        out = propose_insights(ws.task_id, force=True, max_per_phase=10)
        self.assertTrue(out["ok"])
        self.assertFalse(out.get("drive_executor"))
        self.assertEqual((out.get("config") or {}).get("drive_executor"), False)

        insight_fs = [f for f in list_findings(ws.task_id) if f.get("source") == "insight"]
        xd = [
            f
            for f in insight_fs
            if str((f.get("meta") or {}).get("created_via") or "").find("cross_domain") >= 0
            or "xdomain" in str(f.get("title") or "")
        ]
        self.assertGreater(len(xd), 0)
        engine_tagged = [
            f
            for f in xd
            if (f.get("meta") or {}).get("mapping_source") == "autonomous_engine"
        ]
        # When engine import works, at least one xd hyp must carry engine mapping_source
        if (out.get("config") or {}).get("engine_map_loaded"):
            self.assertGreater(len(engine_tagged), 0, msg=f"engine map loaded but no tag: {xd[:2]}")
        for f in xd:
            self.assertEqual(f.get("status"), "candidate")
            self.assertFalse((f.get("meta") or {}).get("drive_executor"))
            self.assertTrue(f.get("reproduce_cmd"))

    def test_observer_ignores_meta_tools(self):
        from kali_mcp.core.action_log import log_action
        from kali_mcp.core.observer import analyze_actions
        from kali_mcp.core.task_workspace import get_workspace

        tid = "obs_meta1"
        get_workspace(tid, create=True)
        for _ in range(3):
            log_action(
                tid,
                tool="observer_analyze",
                target="",
                args={"k": 1},
                exit_code=0,
                source="observer",
            )
            log_action(
                tid,
                tool="propose_insights",
                target="",
                args={"k": 1},
                exit_code=0,
                source="insight",
            )
        log_action(
            tid,
            tool="nmap",
            target="10.0.0.1",
            args={"p": "22"},
            exit_code=0,
            source="playbook",
        )
        log_action(
            tid,
            tool="nmap",
            target="10.0.0.1",
            args={"p": "22"},
            exit_code=0,
            source="playbook",
        )
        rep = analyze_actions(tid, duplicate_threshold=2)
        tools = {d.get("tool") for d in rep.get("duplicates") or []}
        self.assertNotIn("observer_analyze", tools)
        self.assertNotIn("propose_insights", tools)
        self.assertIn("nmap", tools)

    def test_chain_summary_maps_markdown_path(self):
        """export_task_report key is markdown_path; chain must surface report_md."""
        from unittest.mock import MagicMock, patch
        from kali_mcp.core.playbooks.chain import run_surface_chain
        from kali_mcp.core.task_workspace import get_workspace

        tid = "chain_md_map"
        get_workspace(tid, create=True)
        ex = MagicMock()

        def _pb(name, task_id, target, executor, depth="quick", **kwargs):
            return {"ok": True, "playbook": name}

        with patch("kali_mcp.core.playbooks.run_playbook", side_effect=_pb), patch(
            "kali_mcp.core.playbooks.list_playbooks",
            return_value=["web_surface", "api_surface", "auth_surface", "svc_surface"],
        ), patch(
            "kali_mcp.core.report_export.export_task_report",
            return_value={
                "ok": True,
                "markdown_path": f"/tmp/{tid}/report/report.md",
                "paths": {
                    "markdown": f"/tmp/{tid}/report/report.md",
                    "json": f"/tmp/{tid}/report/summary.json",
                },
            },
        ), patch(
            "kali_mcp.core.observer.apply_observer_hints",
            return_value={"ok": True, "duplicate_count": 0, "suggestions": []},
        ), patch(
            "kali_mcp.core.insight_bridge.propose_insights",
            return_value={"ok": True, "created_count": 2, "hypotheses": []},
        ):
            out = run_surface_chain(
                tid,
                "http://lab.local/",
                ex,
                depth="quick",
                playbooks=["web_surface"],
            )
        self.assertTrue(out.get("ok"))
        self.assertEqual(out.get("report_md"), f"/tmp/{tid}/report/report.md")
        self.assertFalse(out.get("insights", {}).get("skipped"))
        self.assertEqual(out.get("insights", {}).get("created_count"), 2)

    def test_status_check_workspace_summary(self):
        """Phase4: status_check must summarize graph / phase / verified / log paths."""
        import importlib.util

        from kali_mcp.core.findings_store import upsert_finding
        from kali_mcp.core.target_graph import get_graph
        from kali_mcp.core.task_workspace import get_workspace

        tid = "status_sum_1"
        ws = get_workspace(tid, create=True)
        ws.update_meta(phase="VERIFY", status="open", targets=["http://lab.local"])
        g = get_graph(tid)
        g.upsert_node("url", "http://lab.local/", confidence=0.9, next_checks=["fingerprint"])
        g.save()
        upsert_finding(
            tid,
            {
                "finding_id": "f1",
                "title": "demo",
                "severity": "info",
                "status": "verified",
                "target": "http://lab.local",
            },
        )
        (ws.logs_dir / "actions.jsonl").write_text(
            '{"ts":"t","tool":"httpx"}\n{"ts":"t2","tool":"nmap"}\n',
            encoding="utf-8",
        )

        # load status_check from repo root (sibling of tests/)
        status_path = Path(__file__).resolve().parents[1] / "status_check.py"
        spec = importlib.util.spec_from_file_location("kali_status_check", status_path)
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        summary = mod.summarize_task_dir(ws.root)
        self.assertEqual(summary["task_id"], tid)
        self.assertEqual(summary["phase"], "VERIFY")
        self.assertEqual(summary["nodes"], 1)
        self.assertEqual(summary["verified"], 1)
        self.assertEqual(summary["actions_count"], 2)
        self.assertTrue(summary["actions_log"])

        bulk = mod.collect_workspace_summaries(limit=5)
        self.assertGreaterEqual(bulk.get("task_count", 0), 1)
        ids = {t["task_id"] for t in bulk.get("tasks") or []}
        self.assertIn(tid, ids)


if __name__ == "__main__":
    unittest.main()

