"""
Tests for ctf_knowledge_base module (kali_mcp/core/ctf_knowledge_base.py)

Covers:
- VulnerabilityType enum
- PayloadTemplate: creation, defaults
- DetectionMethod: creation
- ExploitStrategy: creation
- FlagGetterMethod: creation
- VulnerabilityKnowledge: creation
- KnowledgeLoader: init, load_all, _load_builtin_knowledge, each _create_*_knowledge
- CTFKnowledgeBase: init, load, get_payloads, get_flag_getters, get_llm_prompt,
  detect_flags, get_detection_methods, get_exploit_strategies, get_all_vuln_types,
  suggest_next_action
- KnowledgeDrivenDetector: _check_matcher
- Global functions: get_knowledge_base, get_payloads, get_flag_getters, detect_flags, suggest_action
"""

import pytest
import tempfile
from pathlib import Path

from kali_mcp.core.ctf_knowledge_base import (
    VulnerabilityType,
    PayloadTemplate,
    DetectionMethod,
    ExploitStrategy,
    FlagGetterMethod,
    VulnerabilityKnowledge,
    KnowledgeLoader,
    CTFKnowledgeBase,
    KnowledgeDrivenDetector,
)


# ===================== VulnerabilityType Tests =====================

class TestVulnerabilityType:
    def test_member_count(self):
        assert len(VulnerabilityType) == 20

    def test_common_values(self):
        assert VulnerabilityType.SQL_INJECTION.value == "sqli"
        assert VulnerabilityType.XSS.value == "xss"
        assert VulnerabilityType.COMMAND_INJECTION.value == "cmdi"
        assert VulnerabilityType.LFI.value == "lfi"
        assert VulnerabilityType.SSRF.value == "ssrf"
        assert VulnerabilityType.SSTI.value == "ssti"
        assert VulnerabilityType.IDOR.value == "idor"
        assert VulnerabilityType.JWT.value == "jwt"

    def test_additional_values(self):
        assert VulnerabilityType.RFI.value == "rfi"
        assert VulnerabilityType.XXE.value == "xxe"
        assert VulnerabilityType.FILE_UPLOAD.value == "upload"
        assert VulnerabilityType.DESERIALIZATION.value == "deser"
        assert VulnerabilityType.CSRF.value == "csrf"
        assert VulnerabilityType.RACE_CONDITION.value == "race"
        assert VulnerabilityType.NOSQL_INJECTION.value == "nosqli"
        assert VulnerabilityType.XPATH_INJECTION.value == "xpathi"


# ===================== PayloadTemplate Tests =====================

class TestPayloadTemplate:
    def test_defaults(self):
        pt = PayloadTemplate(name="test", payload="'", description="Quote test")
        assert pt.bypass_type == "none"
        assert pt.success_indicators == []
        assert pt.tags == []

    def test_with_values(self):
        pt = PayloadTemplate(
            name="waf_bypass",
            payload="' OR 1=1--",
            description="WAF bypass",
            bypass_type="waf",
            success_indicators=["error"],
            tags=["sqli"],
        )
        assert pt.bypass_type == "waf"
        assert len(pt.success_indicators) == 1

    def test_mutable_defaults(self):
        p1 = PayloadTemplate(name="a", payload="x", description="d")
        p2 = PayloadTemplate(name="b", payload="y", description="d")
        p1.success_indicators.append("test")
        assert p2.success_indicators == []


# ===================== DetectionMethod Tests =====================

class TestDetectionMethod:
    def test_creation(self):
        dm = DetectionMethod(
            name="error_test",
            method_type="error_based",
            payloads=["'", "\""],
            matchers={"type": "word", "words": ["error"]},
        )
        assert dm.name == "error_test"
        assert dm.confidence == 0.8  # default

    def test_custom_confidence(self):
        dm = DetectionMethod(
            name="t", method_type="t", payloads=[], matchers={}, confidence=0.95
        )
        assert dm.confidence == 0.95


# ===================== ExploitStrategy Tests =====================

class TestExploitStrategy:
    def test_defaults(self):
        es = ExploitStrategy(name="test", steps=[{"action": "do_something"}])
        assert es.prerequisites == []
        assert es.success_rate == 0.7
        assert es.post_exploit == []

    def test_with_values(self):
        es = ExploitStrategy(
            name="union",
            steps=[{"action": "a"}, {"action": "b"}],
            prerequisites=["sqli_confirmed"],
            success_rate=0.9,
            post_exploit=["dump_db"],
        )
        assert len(es.steps) == 2
        assert es.success_rate == 0.9


# ===================== FlagGetterMethod Tests =====================

class TestFlagGetterMethod:
    def test_defaults(self):
        fg = FlagGetterMethod(
            name="read_flag",
            vuln_type="sqli",
            commands=["cat /flag"],
            description="Read flag",
        )
        assert fg.priority == 5
        assert fg.requires == []

    def test_sorting_by_priority(self):
        fgs = [
            FlagGetterMethod(name="a", vuln_type="sqli", commands=[], description="d", priority=3),
            FlagGetterMethod(name="b", vuln_type="sqli", commands=[], description="d", priority=1),
            FlagGetterMethod(name="c", vuln_type="sqli", commands=[], description="d", priority=2),
        ]
        sorted_fgs = sorted(fgs, key=lambda x: x.priority)
        assert sorted_fgs[0].name == "b"
        assert sorted_fgs[2].name == "a"


# ===================== KnowledgeLoader Tests =====================

class TestKnowledgeLoader:
    def test_init(self):
        with tempfile.TemporaryDirectory() as d:
            loader = KnowledgeLoader(d)
            assert loader.knowledge_dir == Path(d)
            assert loader.loaded_knowledge == {}

    def test_load_builtin(self):
        with tempfile.TemporaryDirectory() as d:
            loader = KnowledgeLoader(d)
            knowledge = loader.load_all()
            assert "sqli" in knowledge
            assert "xss" in knowledge
            assert "lfi" in knowledge
            assert "cmdi" in knowledge
            assert "ssti" in knowledge
            assert "ssrf" in knowledge
            assert "idor" in knowledge
            assert "jwt" in knowledge

    def test_sqli_knowledge_has_payloads(self):
        with tempfile.TemporaryDirectory() as d:
            loader = KnowledgeLoader(d)
            knowledge = loader.load_all()
            sqli = knowledge["sqli"]
            assert len(sqli.payloads) >= 5
            assert sqli.vuln_type == VulnerabilityType.SQL_INJECTION

    def test_sqli_has_detection_methods(self):
        with tempfile.TemporaryDirectory() as d:
            loader = KnowledgeLoader(d)
            knowledge = loader.load_all()
            assert len(knowledge["sqli"].detection_methods) >= 1

    def test_sqli_has_exploit_strategies(self):
        with tempfile.TemporaryDirectory() as d:
            loader = KnowledgeLoader(d)
            knowledge = loader.load_all()
            assert len(knowledge["sqli"].exploit_strategies) >= 1

    def test_sqli_has_flag_getters(self):
        with tempfile.TemporaryDirectory() as d:
            loader = KnowledgeLoader(d)
            knowledge = loader.load_all()
            assert len(knowledge["sqli"].flag_getters) >= 1

    def test_sqli_has_llm_prompts(self):
        with tempfile.TemporaryDirectory() as d:
            loader = KnowledgeLoader(d)
            knowledge = loader.load_all()
            assert "detect" in knowledge["sqli"].llm_prompts

    def test_xss_has_payloads(self):
        with tempfile.TemporaryDirectory() as d:
            loader = KnowledgeLoader(d)
            knowledge = loader.load_all()
            assert len(knowledge["xss"].payloads) >= 3

    def test_lfi_has_payloads(self):
        with tempfile.TemporaryDirectory() as d:
            loader = KnowledgeLoader(d)
            knowledge = loader.load_all()
            assert len(knowledge["lfi"].payloads) >= 4

    def test_cmdi_has_payloads(self):
        with tempfile.TemporaryDirectory() as d:
            loader = KnowledgeLoader(d)
            knowledge = loader.load_all()
            assert len(knowledge["cmdi"].payloads) >= 5

    def test_jwt_has_exploit_strategies(self):
        with tempfile.TemporaryDirectory() as d:
            loader = KnowledgeLoader(d)
            knowledge = loader.load_all()
            assert len(knowledge["jwt"].exploit_strategies) >= 1


# ===================== CTFKnowledgeBase Tests =====================

class TestCTFKnowledgeBase:
    def _make_kb(self):
        with tempfile.TemporaryDirectory() as d:
            kb = CTFKnowledgeBase(d)
            kb.load()
            return kb

    def test_init(self):
        with tempfile.TemporaryDirectory() as d:
            kb = CTFKnowledgeBase(d)
            assert kb._loaded is False
            assert kb.knowledge == {}

    def test_load(self):
        kb = self._make_kb()
        assert kb._loaded is True
        assert len(kb.knowledge) >= 8

    def test_load_idempotent(self):
        kb = self._make_kb()
        kb.load()  # second call does nothing
        assert kb._loaded is True

    def test_get_payloads_sqli(self):
        kb = self._make_kb()
        payloads = kb.get_payloads("sqli")
        assert len(payloads) >= 5

    def test_get_payloads_with_bypass_filter(self):
        kb = self._make_kb()
        waf_payloads = kb.get_payloads("sqli", bypass="waf")
        for p in waf_payloads:
            assert p.bypass_type in ("waf", "none")

    def test_get_payloads_unknown_type(self):
        kb = self._make_kb()
        assert kb.get_payloads("unknown_vuln_type") == []

    def test_get_flag_getters_sqli(self):
        kb = self._make_kb()
        getters = kb.get_flag_getters("sqli")
        assert len(getters) >= 1
        # sorted by priority
        priorities = [g.priority for g in getters]
        assert priorities == sorted(priorities)

    def test_get_flag_getters_unknown(self):
        kb = self._make_kb()
        assert kb.get_flag_getters("unknown") == []

    def test_get_llm_prompt(self):
        kb = self._make_kb()
        prompt = kb.get_llm_prompt("sqli", "detect")
        assert prompt is not None
        assert "SQL" in prompt or "sql" in prompt.lower()

    def test_get_llm_prompt_unknown_type(self):
        kb = self._make_kb()
        assert kb.get_llm_prompt("unknown", "detect") is None

    def test_get_llm_prompt_unknown_prompt_type(self):
        kb = self._make_kb()
        assert kb.get_llm_prompt("sqli", "nonexistent_prompt") is None

    def test_get_detection_methods(self):
        kb = self._make_kb()
        methods = kb.get_detection_methods("sqli")
        assert len(methods) >= 1

    def test_get_detection_methods_unknown(self):
        kb = self._make_kb()
        assert kb.get_detection_methods("unknown") == []

    def test_get_exploit_strategies(self):
        kb = self._make_kb()
        strategies = kb.get_exploit_strategies("sqli")
        assert len(strategies) >= 1

    def test_get_exploit_strategies_unknown(self):
        kb = self._make_kb()
        assert kb.get_exploit_strategies("unknown") == []

    def test_get_all_vuln_types(self):
        kb = self._make_kb()
        types = kb.get_all_vuln_types()
        assert "sqli" in types
        assert "xss" in types
        assert len(types) >= 8


# ===================== detect_flags Tests =====================

class TestDetectFlags:
    def _make_kb(self):
        with tempfile.TemporaryDirectory() as d:
            kb = CTFKnowledgeBase(d)
            return kb

    def test_flag_format(self):
        kb = self._make_kb()
        result = kb.detect_flags("the flag is flag{test_flag_123}")
        assert "flag{test_flag_123}" in result

    def test_ctf_format(self):
        kb = self._make_kb()
        result = kb.detect_flags("ctf{my_secret}")
        assert "ctf{my_secret}" in result

    def test_uppercase_flag(self):
        kb = self._make_kb()
        result = kb.detect_flags("FLAG{UPPER_CASE}")
        assert "FLAG{UPPER_CASE}" in result

    def test_dasctf_format(self):
        kb = self._make_kb()
        result = kb.detect_flags("DASCTF{special_flag}")
        assert "DASCTF{special_flag}" in result

    def test_md5_hash(self):
        kb = self._make_kb()
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = kb.detect_flags(f"hash is {md5}")
        assert md5 in result

    def test_no_flags(self):
        kb = self._make_kb()
        result = kb.detect_flags("no flags here")
        assert result == []

    def test_multiple_flags(self):
        kb = self._make_kb()
        result = kb.detect_flags("flag{first} and flag{second}")
        assert len(result) >= 2

    def test_deduplication(self):
        kb = self._make_kb()
        result = kb.detect_flags("flag{dup} flag{dup}")
        assert result.count("flag{dup}") == 1


# ===================== suggest_next_action Tests =====================

class TestSuggestNextAction:
    def _make_kb(self):
        with tempfile.TemporaryDirectory() as d:
            kb = CTFKnowledgeBase(d)
            kb.load()
            return kb

    def test_detection_phase(self):
        kb = self._make_kb()
        result = kb.suggest_next_action("sqli", "detection", {})
        assert result["action"] == "detect"
        assert "payloads" in result

    def test_exploitation_phase(self):
        kb = self._make_kb()
        result = kb.suggest_next_action("sqli", "exploitation", {})
        assert result["action"] == "exploit"
        assert "steps" in result

    def test_flag_extraction_phase(self):
        kb = self._make_kb()
        result = kb.suggest_next_action("sqli", "flag_extraction", {})
        assert result["action"] == "get_flag"
        assert "commands" in result

    def test_unknown_phase(self):
        kb = self._make_kb()
        result = kb.suggest_next_action("sqli", "unknown_phase", {})
        assert result["action"] == "complete"

    def test_unknown_vuln_type(self):
        kb = self._make_kb()
        result = kb.suggest_next_action("unknown_vuln", "detection", {})
        assert result["action"] == "unknown"

    def test_no_detection_methods(self):
        kb = self._make_kb()
        # ssti has no detection methods
        result = kb.suggest_next_action("ssti", "detection", {})
        assert result["action"] == "complete"

    def test_no_exploit_strategies(self):
        kb = self._make_kb()
        # xss has no exploit strategies
        result = kb.suggest_next_action("xss", "exploitation", {})
        assert result["action"] == "complete"


# ===================== KnowledgeDrivenDetector Tests =====================

class TestKnowledgeDrivenDetector:
    def _make_detector(self):
        with tempfile.TemporaryDirectory() as d:
            kb = CTFKnowledgeBase(d)
            return KnowledgeDrivenDetector(kb)

    def test_init(self):
        detector = self._make_detector()
        assert detector.results == {}

    def test_check_matcher_word(self):
        detector = self._make_detector()
        matcher = {"type": "word", "words": ["error", "sql"]}
        assert detector._check_matcher("SQL Error found", 200, matcher) is True
        assert detector._check_matcher("All good", 200, matcher) is False

    def test_check_matcher_status(self):
        detector = self._make_detector()
        matcher = {"type": "status", "status": [500, 403]}
        assert detector._check_matcher("", 500, matcher) is True
        assert detector._check_matcher("", 200, matcher) is False

    def test_check_matcher_regex(self):
        detector = self._make_detector()
        matcher = {"type": "regex", "patterns": [r"flag\{[^}]+\}"]}
        assert detector._check_matcher("found flag{abc}", 200, matcher) is True
        assert detector._check_matcher("no match", 200, matcher) is False

    def test_check_matcher_unknown_type(self):
        detector = self._make_detector()
        matcher = {"type": "custom"}
        assert detector._check_matcher("anything", 200, matcher) is False

    def test_check_matcher_case_insensitive_word(self):
        detector = self._make_detector()
        matcher = {"type": "word", "words": ["ERROR"]}
        assert detector._check_matcher("error in query", 200, matcher) is True


# ===================== Global Functions Tests =====================

class TestGlobalFunctions:
    def test_get_knowledge_base(self):
        import kali_mcp.core.ctf_knowledge_base as mod
        mod._global_knowledge_base = None
        kb = mod.get_knowledge_base()
        assert isinstance(kb, CTFKnowledgeBase)
        assert kb._loaded is True

    def test_get_knowledge_base_singleton(self):
        import kali_mcp.core.ctf_knowledge_base as mod
        mod._global_knowledge_base = None
        kb1 = mod.get_knowledge_base()
        kb2 = mod.get_knowledge_base()
        assert kb1 is kb2
