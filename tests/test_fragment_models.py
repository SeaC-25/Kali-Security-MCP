"""
Tests for fragment_models module (kali_mcp/core/fragment_models.py)

Covers:
- FragmentStatus enum
- FragmentType enum
- Fragment: creation, defaults, to_dict, from_dict, severity_order property,
  round-trip serialization, field filtering
"""

import pytest

from kali_mcp.core.fragment_models import (
    FragmentStatus,
    FragmentType,
    Fragment,
)


# ===================== FragmentStatus Tests =====================

class TestFragmentStatus:
    def test_values(self):
        assert FragmentStatus.DISCOVERED.value == "discovered"
        assert FragmentStatus.ANALYZING.value == "analyzing"
        assert FragmentStatus.CONFIRMED.value == "confirmed"
        assert FragmentStatus.CHAINED.value == "chained"
        assert FragmentStatus.DISMISSED.value == "dismissed"

    def test_member_count(self):
        assert len(FragmentStatus) == 5


# ===================== FragmentType Tests =====================

class TestFragmentType:
    def test_values(self):
        assert FragmentType.INFO_LEAK.value == "info_leak"
        assert FragmentType.WEAK_CONFIG.value == "weak_config"
        assert FragmentType.AUTH_PARTIAL.value == "auth_partial"
        assert FragmentType.PATH_DISCLOSURE.value == "path_disclosure"
        assert FragmentType.VERSION_LEAK.value == "version_leak"
        assert FragmentType.CREDENTIAL_HINT.value == "credential_hint"
        assert FragmentType.DEBUG_INFO.value == "debug_info"
        assert FragmentType.BACKUP_FILE.value == "backup_file"
        assert FragmentType.SOURCE_LEAK.value == "source_leak"
        assert FragmentType.ENDPOINT_FOUND.value == "endpoint_found"
        assert FragmentType.TECH_STACK.value == "tech_stack"
        assert FragmentType.OTHER.value == "other"

    def test_member_count(self):
        assert len(FragmentType) == 12


# ===================== Fragment Creation Tests =====================

class TestFragmentCreation:
    def test_defaults(self):
        frag = Fragment()
        assert frag.fragment_id.startswith("FRAG-")
        assert len(frag.fragment_id) == 13  # "FRAG-" + 8 hex chars
        assert frag.title == ""
        assert frag.fragment_type == "other"
        assert frag.description == ""
        assert frag.target == ""
        assert frag.evidence == ""
        assert frag.status == "discovered"
        assert frag.severity == "info"
        assert frag.related_fragments == []
        assert frag.discovered_by == ""
        assert frag.discovered_at != ""
        assert frag.tags == []

    def test_unique_ids(self):
        f1 = Fragment()
        f2 = Fragment()
        assert f1.fragment_id != f2.fragment_id

    def test_with_values(self):
        frag = Fragment(
            title="Admin credentials in source",
            fragment_type="credential_hint",
            description="Found hardcoded admin password in JavaScript",
            target="http://target.com",
            evidence="var admin_pass = 'P@ssw0rd';",
            status="confirmed",
            severity="high",
            related_fragments=["FRAG-ABCD"],
            discovered_by="gobuster_scan",
            tags=["credentials", "javascript"],
        )
        assert frag.title == "Admin credentials in source"
        assert frag.fragment_type == "credential_hint"
        assert frag.severity == "high"
        assert len(frag.related_fragments) == 1
        assert len(frag.tags) == 2

    def test_mutable_defaults_independent(self):
        """Ensure list defaults don't share state between instances."""
        f1 = Fragment()
        f2 = Fragment()
        f1.related_fragments.append("FRAG-1")
        f1.tags.append("test")
        assert f2.related_fragments == []
        assert f2.tags == []


# ===================== Fragment severity_order Tests =====================

class TestFragmentSeverityOrder:
    def test_high(self):
        f = Fragment(severity="high")
        assert f.severity_order == 4

    def test_medium(self):
        f = Fragment(severity="medium")
        assert f.severity_order == 3

    def test_low(self):
        f = Fragment(severity="low")
        assert f.severity_order == 2

    def test_info(self):
        f = Fragment(severity="info")
        assert f.severity_order == 1

    def test_unknown(self):
        f = Fragment(severity="unknown")
        assert f.severity_order == 0


# ===================== Fragment to_dict Tests =====================

class TestFragmentToDict:
    def test_basic(self):
        frag = Fragment(title="Test", severity="high", target="10.0.0.1")
        d = frag.to_dict()
        assert d["title"] == "Test"
        assert d["severity"] == "high"
        assert d["target"] == "10.0.0.1"

    def test_includes_all_fields(self):
        frag = Fragment()
        d = frag.to_dict()
        expected_keys = {"fragment_id", "title", "fragment_type", "description",
                         "target", "evidence", "status", "severity",
                         "related_fragments", "discovered_by", "discovered_at", "tags"}
        assert set(d.keys()) == expected_keys

    def test_lists_are_copies(self):
        frag = Fragment(tags=["a", "b"])
        d = frag.to_dict()
        d["tags"].append("c")
        assert len(frag.tags) == 2  # original unchanged


# ===================== Fragment from_dict Tests =====================

class TestFragmentFromDict:
    def test_basic(self):
        data = {"title": "Info Leak", "fragment_type": "info_leak", "severity": "medium"}
        frag = Fragment.from_dict(data)
        assert frag.title == "Info Leak"
        assert frag.fragment_type == "info_leak"
        assert frag.severity == "medium"

    def test_ignores_extra_keys(self):
        data = {"title": "Test", "extra_field": "should_be_ignored", "foo": 42}
        frag = Fragment.from_dict(data)
        assert frag.title == "Test"
        assert not hasattr(frag, "extra_field")

    def test_missing_fields_use_defaults(self):
        data = {"title": "Only Title"}
        frag = Fragment.from_dict(data)
        assert frag.title == "Only Title"
        assert frag.severity == "info"
        assert frag.fragment_type == "other"

    def test_round_trip(self):
        original = Fragment(
            title="Path disclosure",
            fragment_type="path_disclosure",
            description="Full path revealed in error",
            target="http://target.com/error",
            evidence="/var/www/html/config.php",
            status="confirmed",
            severity="medium",
            related_fragments=["FRAG-1111"],
            discovered_by="nuclei_scan",
            tags=["path", "error_page"],
        )
        d = original.to_dict()
        restored = Fragment.from_dict(d)
        assert restored.title == original.title
        assert restored.fragment_type == original.fragment_type
        assert restored.description == original.description
        assert restored.severity == original.severity
        assert restored.related_fragments == original.related_fragments
        assert restored.tags == original.tags
        assert restored.fragment_id == original.fragment_id

    def test_with_custom_id(self):
        data = {"fragment_id": "FRAG-CUSTOM01", "title": "Custom"}
        frag = Fragment.from_dict(data)
        assert frag.fragment_id == "FRAG-CUSTOM01"
