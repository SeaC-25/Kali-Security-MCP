"""Test insight_bridge: pure helpers, config, cross-domain logic, no executor."""
from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, PropertyMock, patch

from kali_mcp.core.insight_bridge import (
    _env_bool,
    _env_int,
    _normalize_engine_cross_domain_map,
    engine_cross_domain_map_available,
    get_cross_domain_map,
    insight_config,
    _is_stuck,
    _dead_values,
    _existing_hypothesis_keys,
    _infer_vuln_type,
    _base_url_from_graph,
    _cross_domain_hypotheses,
    _build_hypotheses_for_node,
)


class TestEnvHelpers(unittest.TestCase):
    """_env_bool / _env_int — pure env wrappers."""

    def setUp(self):
        for k in ["TEST_BOOL", "TEST_INT"]:
            os.environ.pop(k, None)

    def test_env_bool_default_true(self):
        self.assertTrue(_env_bool("TEST_BOOL", True))

    def test_env_bool_default_false(self):
        self.assertFalse(_env_bool("TEST_BOOL", False))

    def test_env_bool_1_is_true(self):
        os.environ["TEST_BOOL"] = "1"
        self.assertTrue(_env_bool("TEST_BOOL", False))

    def test_env_bool_0_is_false(self):
        os.environ["TEST_BOOL"] = "0"
        self.assertFalse(_env_bool("TEST_BOOL", True))

    def test_env_bool_random_is_false(self):
        os.environ["TEST_BOOL"] = "random"
        self.assertFalse(_env_bool("TEST_BOOL", True))

    def test_env_int_default(self):
        self.assertEqual(_env_int("TEST_INT", 42), 42)

    def test_env_int_valid(self):
        os.environ["TEST_INT"] = "99"
        self.assertEqual(_env_int("TEST_INT", 42), 99)

    def test_env_int_invalid_returns_default(self):
        os.environ["TEST_INT"] = "not_a_number"
        self.assertEqual(_env_int("TEST_INT", 42), 42)


class TestNormalizeMap(unittest.TestCase):
    """_normalize_engine_cross_domain_map — pure dict normalizer."""

    def test_empty(self):
        self.assertEqual(_normalize_engine_cross_domain_map({}), {})

    def test_none(self):
        self.assertEqual(_normalize_engine_cross_domain_map(None), {})

    def test_to_prefix_stripped(self):
        raw = {"sql_injection": {"to_command_injection": ["xp_cmdshell"]}}
        out = _normalize_engine_cross_domain_map(raw)
        self.assertIn("command_injection", out["sql_injection"])

    def test_non_dict_values_skipped(self):
        raw = {"sql_injection": "not_a_dict"}
        out = _normalize_engine_cross_domain_map(raw)
        self.assertEqual(out, {})

    def test_multiple_targets(self):
        raw = {
            "sql_injection": {
                "command_injection": ["rce1", "rce2"],
                "file_inclusion": ["lfi1"],
            },
            "xss": {"ssrf": ["csrf"]},
        }
        out = _normalize_engine_cross_domain_map(raw)
        self.assertIn("sql_injection", out)
        self.assertIn("xss", out)
        self.assertEqual(len(out["sql_injection"]["command_injection"]), 2)
        self.assertEqual(len(out["sql_injection"]["file_inclusion"]), 1)


class TestGetCrossDomainMap(unittest.TestCase):
    """Prefer engine map, fall back to inline."""

    @patch("kali_mcp.core.insight_bridge._normalize_engine_cross_domain_map", return_value={})
    @patch("kali_mcp.core.insight_bridge.get_cross_domain_map", wraps=get_cross_domain_map)
    def test_fallback_has_keys(self, *_):
        m = get_cross_domain_map()
        self.assertIn("sql_injection", m)
        self.assertIn("command_injection", m)
        self.assertIn("file_inclusion", m)

    def test_fallback_returns_inline(self):
        """Without engine override, fallback returns inline map keys."""
        m = get_cross_domain_map()
        # inline always has these top-level keys
        for need in ("sql_injection", "command_injection", "file_inclusion", "xss", "ssrf"):
            self.assertIn(need, m)


class TestEngineMapAvailable(unittest.TestCase):
    """engine_cross_domain_map_available returns True/False."""

    @patch("kali_mcp.core.insight_bridge._normalize_engine_cross_domain_map", return_value={"a": {"b": ["c"]}})
    def test_available_true(self, *_):
        self.assertTrue(engine_cross_domain_map_available())

    @patch("kali_mcp.core.insight_bridge._normalize_engine_cross_domain_map", return_value={})
    def test_available_false(self, *_):
        self.assertFalse(engine_cross_domain_map_available())


class TestInsightConfig(unittest.TestCase):
    """config shape and defaults."""

    def test_config_shape(self):
        cfg = insight_config()
        self.assertIn("enabled", cfg)
        self.assertIn("drive_executor", cfg)
        self.assertFalse(cfg["drive_executor"])
        self.assertIn("max_per_phase", cfg)
        self.assertIn("only_when_stuck", cfg)
        self.assertIn("engine_map_loaded", cfg)

    def test_drive_executor_never_true(self):
        cfg = insight_config()
        self.assertFalse(cfg["drive_executor"])


class TestIsStuck(unittest.TestCase):
    """Requires action log with >5 failures."""

    def tearDown(self):
        # read_actions/list_findings create workspace dirs via get_workspace(create=True).
        from kali_mcp.core.task_workspace import tasks_root
        import shutil
        for name in ("nope", "t"):
            p = tasks_root() / name
            if p.is_dir():
                shutil.rmtree(str(p))

    @patch("kali_mcp.core.insight_bridge.read_actions", return_value=[])
    def test_empty_log_not_stuck(self, *_):
        self.assertFalse(_is_stuck("nope", MagicMock()))

    @patch("kali_mcp.core.insight_bridge.read_actions", return_value=[])
    def test_small_log_not_stuck(self, *_):
        self.assertFalse(_is_stuck("t", MagicMock()))


class TestDeadValues(unittest.TestCase):
    def _node(self, value="x", dead=True):
        n = MagicMock()
        n.value = value
        n.dead_reason = "timeout" if dead else None
        return n

    def test_returns_dead_values(self):
        graph = MagicMock()
        graph.nodes = {"a": self._node("a"), "b": self._node("b"), "c": self._node("c", dead=False)}
        out = _dead_values(graph)
        self.assertIn("a", out)
        self.assertIn("b", out)
        self.assertNotIn("c", out)


class TestExistingHypothesisKeys(unittest.TestCase):
    def tearDown(self):
        # list_findings creates the workspace dir via get_workspace(create=True).
        from kali_mcp.core.task_workspace import tasks_root
        import shutil
        for name in ("t1", "nope"):
            p = tasks_root() / name
            if p.is_dir():
                shutil.rmtree(str(p))

    @patch("kali_mcp.core.insight_bridge.list_findings", return_value=[
        {"source": "insight", "title": "h1", "target": "http://x/"},
        {"source": "playbook", "title": "scan", "target": "http://x/"},
        {"source": "insight", "title": "h2", "target": "http://y/"},
    ])
    def test_returns_insight_only_keys(self, *_):
        keys = _existing_hypothesis_keys("t1")
        self.assertIn("h1|http://x/", keys)
        self.assertIn("h2|http://y/", keys)
        self.assertEqual(len(keys), 2)

    @patch("kali_mcp.core.insight_bridge.list_findings", return_value=[])
    def test_empty(self, *_):
        self.assertEqual(_existing_hypothesis_keys("t1"), set())


class TestInferVulnType(unittest.TestCase):
    def _node(self, value="", title="", status="", service=""):
        n = MagicMock()
        n.value = value
        n.meta = {"title": title, "status": status, "service": service}
        return n

    def test_sql_keyword_in_title(self):
        self.assertEqual(_infer_vuln_type(self._node(title="sql injection in login")), "sql_injection")

    def test_rce_keyword(self):
        self.assertEqual(_infer_vuln_type(self._node(title="rce via upload")), "command_injection")

    def test_xss_keyword(self):
        self.assertEqual(_infer_vuln_type(self._node(title="cross-site scripting")), "xss")

    def test_no_match_returns_none(self):
        self.assertIsNone(_infer_vuln_type(self._node(title="normal page")))

    def test_service_fallback(self):
        self.assertEqual(_infer_vuln_type(self._node(title="", service="sql server")), "sql_injection")

    def test_empty_node(self):
        n = MagicMock()
        n.value = ""
        n.meta = {}
        self.assertIsNone(_infer_vuln_type(n))


class TestBaseUrlFromGraph(unittest.TestCase):
    def _node(self, ntype="url", value="http://x/", confidence=0.9, dead=False):
        n = MagicMock()
        n.type = ntype
        n.value = value
        n.confidence = confidence
        n.dead_reason = "dead" if dead else None
        return n

    def test_picks_highest_confidence_url(self):
        g = MagicMock()
        g.nodes = {"a": self._node("url", "http://a/", 0.5), "b": self._node("url", "http://b/", 0.9)}
        self.assertEqual(_base_url_from_graph(g), "http://b/")

    def test_skips_dead_nodes(self):
        g = MagicMock()
        g.nodes = {"a": self._node("url", "http://a/", 0.9, dead=True), "b": self._node("url", "http://b/", 0.5)}
        self.assertEqual(_base_url_from_graph(g), "http://b/")

    def test_falls_back_to_host(self):
        g = MagicMock()
        g.nodes = {"h": self._node("host", "x.com", 0.8)}
        self.assertEqual(_base_url_from_graph(g), "http://x.com/")

    def test_no_nodes_returns_none(self):
        g = MagicMock()
        g.nodes = {}
        self.assertIsNone(_base_url_from_graph(g))

    def test_all_dead_returns_none(self):
        g = MagicMock()
        g.nodes = {"a": self._node("url", "http://a/", 0.9, dead=True)}
        self.assertIsNone(_base_url_from_graph(g))


class TestBuildHypothesesForNode(unittest.TestCase):
    def _url_node(self, value="http://lab.local/", dead=False):
        n = MagicMock()
        n.type = "url"
        n.value = value
        n.dead_reason = "dead" if dead else None
        n.meta = {}
        n.confidence = 0.9
        return n

    def _host_node(self, value="host.local"):
        n = MagicMock()
        n.type = "host"
        n.value = value
        n.dead_reason = None
        n.meta = {}
        n.confidence = 0.5
        return n

    @patch("kali_mcp.core.insight_bridge._cross_domain_hypotheses", return_value=[])
    def test_url_node_produces_auth_path_hypotheses(self, *_):
        hyps = _build_hypotheses_for_node(self._url_node("http://lab.local/"))
        titles = [h["title"] for h in hyps]
        self.assertTrue(any("insight_auth_surface" in t for t in titles))
        self.assertTrue(any("insight_" in t for t in titles))

    @patch("kali_mcp.core.insight_bridge._cross_domain_hypotheses", return_value=[])
    def test_host_node_produces_recon_hypotheses(self, *_):
        hyps = _build_hypotheses_for_node(self._host_node("10.0.0.1"))
        titles = [h["title"] for h in hyps]
        self.assertTrue(any("http_probe" in t for t in titles))

    @patch("kali_mcp.core.insight_bridge._cross_domain_hypotheses", return_value=[])
    def test_dead_node_returns_empty(self, *_):
        hyps = _build_hypotheses_for_node(self._url_node("http://x/", dead=True))
        self.assertEqual(hyps, [])

    def test_empty_value_returns_empty(self):
        n = MagicMock()
        n.type = "url"
        n.value = ""
        n.dead_reason = None
        n.meta = {}
        hyps = _build_hypotheses_for_node(n)
        self.assertEqual(hyps, [])


class TestCrossDomainHypotheses(unittest.TestCase):
    """Endpoint: needs graph + findings + cross-domain map."""

    def setUp(self):
        self.tid = "xd_" + str(id(self))

    @patch("kali_mcp.core.insight_bridge.get_cross_domain_map", return_value={})
    def test_no_map_returns_empty(self, *_):
        g = MagicMock()
        g.nodes = {}
        out = _cross_domain_hypotheses(self.tid, g)
        self.assertEqual(out, [])

    @patch("kali_mcp.core.insight_bridge.get_cross_domain_map", return_value={
        "sql_injection": {"command_injection": ["xp_cmdshell"], "file_inclusion": ["read file"]}
    })
    @patch("kali_mcp.core.insight_bridge.engine_cross_domain_map_available", return_value=True)
    @patch("kali_mcp.core.insight_bridge._base_url_from_graph", return_value="http://t/")
    @patch("kali_mcp.core.insight_bridge.list_findings", return_value=[
        {"title": "sql injection in id param", "target": "http://t/?id=1", "status": "verified", "source": "playbook", "finding_id": "f1"},
        {"title": "unrelated", "target": "http://t/x", "status": "candidate", "source": "playbook", "finding_id": "f2"},
        {"title": "insight_x", "target": "http://t/", "status": "candidate", "source": "insight", "finding_id": "f3"},
    ])
    def test_sql_finding_triggers_xdomain_hyp(self, *_):
        out = _cross_domain_hypotheses(self.tid, MagicMock())
        self.assertEqual(len(out), 2)
        titles = [h["title"] for h in out]
        self.assertTrue(any("command_injection" in t for t in titles))
        self.assertTrue(any("file_inclusion" in t for t in titles))
        for h in out:
            self.assertEqual(h.get("_mapping_source"), "autonomous_engine")

    @patch("kali_mcp.core.insight_bridge.get_cross_domain_map", return_value={
        "sql_injection": {"command_injection": ["xp_cmdshell"]}
    })
    @patch("kali_mcp.core.insight_bridge.engine_cross_domain_map_available", return_value=False)
    @patch("kali_mcp.core.insight_bridge._base_url_from_graph", return_value=None)
    @patch("kali_mcp.core.insight_bridge.list_findings", return_value=[])
    def test_no_base_url_returns_none(self, *_):
        out = _cross_domain_hypotheses(self.tid, MagicMock())
        self.assertEqual(out, [])
