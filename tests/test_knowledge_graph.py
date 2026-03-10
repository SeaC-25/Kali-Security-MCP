"""
Tests for VulnerabilityKnowledgeGraph (kali_mcp/reasoning/knowledge_graph.py)

Covers:
- VulnerabilityType enum
- AttackChain: creation, to_dict
- VulnerabilityKnowledgeGraph: init, get_next_chains, _check_conditions,
  get_chain_by_types, get_all_vulnerabilities, visualize_graph
"""

import pytest

from kali_mcp.reasoning.knowledge_graph import (
    VulnerabilityType,
    AttackChain,
    VulnerabilityKnowledgeGraph,
)


# ===================== VulnerabilityType Tests =====================

class TestVulnerabilityType:
    def test_sql_injection(self):
        assert VulnerabilityType.SQL_INJECTION.value == "sql_injection"

    def test_command_injection(self):
        assert VulnerabilityType.COMMAND_INJECTION.value == "command_injection"

    def test_xss(self):
        assert VulnerabilityType.XSS.value == "xss"

    def test_file_inclusion(self):
        assert VulnerabilityType.FILE_INCLUSION.value == "file_inclusion"

    def test_file_upload(self):
        assert VulnerabilityType.FILE_UPLOAD.value == "file_upload"

    def test_all_types_exist(self):
        names = [v.value for v in VulnerabilityType]
        assert "sql_injection" in names
        assert "privilege_escalation" in names
        assert "pwn" in names
        assert "ssrf" in names
        assert "xxe" in names
        assert "deserialization" in names


# ===================== AttackChain Tests =====================

class TestAttackChain:
    def test_creation(self):
        chain = AttackChain(
            from_vuln=VulnerabilityType.SQL_INJECTION,
            to_vuln=VulnerabilityType.COMMAND_INJECTION,
            reasoning="SQL注入可以执行系统命令",
            success_prob=0.5,
            time_cost=45,
            tools=["sqlmap"],
            conditions=["has_file_write_priv"],
        )
        assert chain.from_vuln == VulnerabilityType.SQL_INJECTION
        assert chain.to_vuln == VulnerabilityType.COMMAND_INJECTION
        assert chain.success_prob == 0.5
        assert chain.time_cost == 45
        assert "sqlmap" in chain.tools
        assert "has_file_write_priv" in chain.conditions

    def test_to_dict(self):
        chain = AttackChain(
            from_vuln=VulnerabilityType.XSS,
            to_vuln=VulnerabilityType.XSS,
            reasoning="Cookie窃取",
            success_prob=0.7,
            time_cost=25,
            tools=["curl"],
            conditions=["xss_reflected"],
        )
        d = chain.to_dict()
        assert d["from"] == "xss"
        assert d["to"] == "xss"
        assert d["reasoning"] == "Cookie窃取"
        assert d["success_prob"] == 0.7
        assert d["time_cost"] == 25
        assert d["tools"] == ["curl"]
        assert d["conditions"] == ["xss_reflected"]


# ===================== VulnerabilityKnowledgeGraph Tests =====================

@pytest.fixture
def graph():
    return VulnerabilityKnowledgeGraph()


class TestGraphInit:
    def test_has_chains(self, graph):
        assert len(graph.chains) > 0

    def test_chains_are_attack_chains(self, graph):
        for chain in graph.chains:
            assert isinstance(chain, AttackChain)

    def test_multiple_source_types(self, graph):
        source_types = set(c.from_vuln for c in graph.chains)
        # Should have chains from multiple vuln types
        assert len(source_types) >= 5


class TestGetNextChains:
    def test_sql_injection_has_chains(self, graph):
        chains = graph.get_next_chains(
            VulnerabilityType.SQL_INJECTION,
            context={}
        )
        # With empty context, only chains with no conditions should match
        assert isinstance(chains, list)

    def test_command_injection_with_shell_context(self, graph):
        chains = graph.get_next_chains(
            VulnerabilityType.COMMAND_INJECTION,
            context={"shell_access": True}
        )
        assert len(chains) > 0
        # All returned chains should have from_vuln == COMMAND_INJECTION
        for chain in chains:
            assert chain.from_vuln == VulnerabilityType.COMMAND_INJECTION

    def test_sorted_by_success_prob(self, graph):
        chains = graph.get_next_chains(
            VulnerabilityType.FILE_UPLOAD,
            context={}
        )
        if len(chains) >= 2:
            for i in range(len(chains) - 1):
                # Higher probability first
                assert chains[i].success_prob >= chains[i + 1].success_prob

    def test_conditions_filter(self, graph):
        # Without shell_access, command injection chains requiring it should be filtered
        no_shell = graph.get_next_chains(
            VulnerabilityType.COMMAND_INJECTION,
            context={"shell_access": False}
        )
        with_shell = graph.get_next_chains(
            VulnerabilityType.COMMAND_INJECTION,
            context={"shell_access": True}
        )
        assert len(with_shell) >= len(no_shell)


class TestCheckConditions:
    def test_empty_conditions(self, graph):
        assert graph._check_conditions([], {}) is True

    def test_file_read_priv(self, graph):
        assert graph._check_conditions(
            ["has_file_read_priv"],
            {"file_read_enabled": True}
        ) is True
        assert graph._check_conditions(
            ["has_file_read_priv"],
            {"file_read_enabled": False}
        ) is False

    def test_file_write_priv(self, graph):
        assert graph._check_conditions(
            ["has_file_write_priv"],
            {"file_write_enabled": True}
        ) is True

    def test_shell_access(self, graph):
        assert graph._check_conditions(
            ["has_shell_access"],
            {"shell_access": True}
        ) is True
        assert graph._check_conditions(
            ["has_shell_access"],
            {}
        ) is False

    def test_internal_network(self, graph):
        assert graph._check_conditions(
            ["has_internal_network"],
            {"internal_network": True}
        ) is True

    def test_webshell_uploaded(self, graph):
        assert graph._check_conditions(
            ["webshell_uploaded"],
            {"webshell_uploaded": True}
        ) is True

    def test_can_read_logs(self, graph):
        assert graph._check_conditions(
            ["can_read_log_files"],
            {"can_read_logs": True}
        ) is True

    def test_multiple_conditions_all_met(self, graph):
        assert graph._check_conditions(
            ["has_shell_access", "has_internal_network"],
            {"shell_access": True, "internal_network": True}
        ) is True

    def test_multiple_conditions_partial(self, graph):
        assert graph._check_conditions(
            ["has_shell_access", "has_internal_network"],
            {"shell_access": True, "internal_network": False}
        ) is False

    def test_unknown_condition_passes(self, graph):
        # Unknown conditions fall through to True
        assert graph._check_conditions(
            ["unknown_condition"],
            {}
        ) is True


class TestGetChainByTypes:
    def test_existing_chain(self, graph):
        chain = graph.get_chain_by_types("sql_injection", "file_inclusion")
        assert chain is not None
        assert chain.from_vuln == VulnerabilityType.SQL_INJECTION
        assert chain.to_vuln == VulnerabilityType.FILE_INCLUSION

    def test_nonexistent_chain(self, graph):
        # Try a combination that likely doesn't exist
        chain = graph.get_chain_by_types("invalid_type", "also_invalid")
        assert chain is None

    def test_invalid_type(self, graph):
        chain = graph.get_chain_by_types("not_a_vuln", "xss")
        assert chain is None


class TestGetAllVulnerabilities:
    def test_returns_all_types(self, graph):
        vulns = graph.get_all_vulnerabilities()
        assert isinstance(vulns, list)
        assert "sql_injection" in vulns
        assert "xss" in vulns
        assert "pwn" in vulns
        assert len(vulns) == len(VulnerabilityType)


class TestVisualizeGraph:
    def test_returns_dot_format(self, graph):
        dot = graph.visualize_graph()
        assert isinstance(dot, str)
        assert "digraph" in dot
        assert "VulnerabilityGraph" in dot
        assert "->" in dot

    def test_contains_nodes(self, graph):
        dot = graph.visualize_graph()
        assert "sql_injection" in dot
        assert "command_injection" in dot
