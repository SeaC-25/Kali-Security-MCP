"""
Tests for Fragment model and FragmentManager (kali_mcp/core/fragment_models.py, fragment_manager.py)

Covers:
- Fragment dataclass: to_dict, from_dict, severity_order
- FragmentStatus / FragmentType enums
- FragmentManager: CRUD, relate, status, statistics
"""

import os
import tempfile

import pytest

from kali_mcp.core.fragment_models import Fragment, FragmentStatus, FragmentType
from kali_mcp.core.fragment_manager import FragmentManager


# ===================== Fragment Model Tests =====================

class TestFragment:
    def test_default_values(self):
        f = Fragment()
        assert f.fragment_id.startswith("FRAG-")
        assert f.status == "discovered"
        assert f.severity == "info"
        assert f.fragment_type == "other"

    def test_to_dict(self):
        f = Fragment(title="Info leak", target="http://example.com")
        d = f.to_dict()
        assert d["title"] == "Info leak"
        assert isinstance(d["tags"], list)
        assert isinstance(d["related_fragments"], list)

    def test_from_dict_roundtrip(self):
        f = Fragment(title="Path disclosure", severity="high",
                     fragment_type="path_disclosure", target="http://t.com")
        d = f.to_dict()
        restored = Fragment.from_dict(d)
        assert restored.title == f.title
        assert restored.severity == f.severity
        assert restored.fragment_type == f.fragment_type

    def test_from_dict_ignores_extra(self):
        d = {"title": "Test", "unknown_field": "ignored"}
        f = Fragment.from_dict(d)
        assert f.title == "Test"

    def test_severity_order(self):
        assert Fragment(severity="high").severity_order == 4
        assert Fragment(severity="medium").severity_order == 3
        assert Fragment(severity="low").severity_order == 2
        assert Fragment(severity="info").severity_order == 1
        assert Fragment(severity="unknown").severity_order == 0


class TestFragmentEnums:
    def test_status_values(self):
        assert FragmentStatus.DISCOVERED.value == "discovered"
        assert FragmentStatus.CHAINED.value == "chained"
        assert FragmentStatus.DISMISSED.value == "dismissed"

    def test_type_values(self):
        assert FragmentType.INFO_LEAK.value == "info_leak"
        assert FragmentType.CREDENTIAL_HINT.value == "credential_hint"
        assert FragmentType.TECH_STACK.value == "tech_stack"


# ===================== FragmentManager Tests =====================

@pytest.fixture
def tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def fm(tmp_db):
    return FragmentManager(db_path=tmp_db)


class TestFragmentManagerCRUD:
    def test_create_and_get(self, fm):
        frag = Fragment(title="Test frag", target="http://t.com",
                        fragment_type="info_leak", severity="medium")
        fid = fm.create_fragment(frag)
        assert fid == frag.fragment_id

        retrieved = fm.get_by_id(fid)
        assert retrieved is not None
        assert retrieved.title == "Test frag"
        assert retrieved.severity == "medium"

    def test_get_nonexistent(self, fm):
        assert fm.get_by_id("FRAG-FAKE") is None

    def test_get_all(self, fm):
        fm.create_fragment(Fragment(title="F1", target="t1"))
        fm.create_fragment(Fragment(title="F2", target="t2"))
        all_frags = fm.get_all()
        assert len(all_frags) == 2

    def test_get_all_filter_target(self, fm):
        fm.create_fragment(Fragment(title="F1", target="http://example.com"))
        fm.create_fragment(Fragment(title="F2", target="http://other.com"))
        results = fm.get_all(target="example")
        assert len(results) == 1

    def test_get_all_filter_status(self, fm):
        f1 = Fragment(title="F1")
        f2 = Fragment(title="F2")
        fm.create_fragment(f1)
        fm.create_fragment(f2)
        fm.update_status(f2.fragment_id, "confirmed")
        results = fm.get_all(status="discovered")
        assert len(results) == 1

    def test_get_by_type(self, fm):
        fm.create_fragment(Fragment(title="F1", fragment_type="info_leak"))
        fm.create_fragment(Fragment(title="F2", fragment_type="weak_config"))
        results = fm.get_by_type("info_leak")
        assert len(results) == 1


class TestFragmentRelation:
    def test_relate_two_fragments(self, fm):
        f1 = Fragment(title="F1")
        f2 = Fragment(title="F2")
        fm.create_fragment(f1)
        fm.create_fragment(f2)

        ok = fm.relate_fragments(f1.fragment_id, f2.fragment_id)
        assert ok is True

        # Check bidirectional
        r1 = fm.get_by_id(f1.fragment_id)
        assert f2.fragment_id in r1.related_fragments

        r2 = fm.get_by_id(f2.fragment_id)
        assert f1.fragment_id in r2.related_fragments

    def test_relate_nonexistent(self, fm):
        f1 = Fragment(title="F1")
        fm.create_fragment(f1)
        ok = fm.relate_fragments(f1.fragment_id, "FRAG-FAKE")
        assert ok is False

    def test_get_related(self, fm):
        f1 = Fragment(title="F1")
        f2 = Fragment(title="F2")
        fm.create_fragment(f1)
        fm.create_fragment(f2)
        fm.relate_fragments(f1.fragment_id, f2.fragment_id)

        related = fm.get_related(f1.fragment_id)
        assert len(related) == 1
        assert related[0].fragment_id == f2.fragment_id

    def test_get_related_empty(self, fm):
        f1 = Fragment(title="F1")
        fm.create_fragment(f1)
        related = fm.get_related(f1.fragment_id)
        assert related == []


class TestFragmentStatus:
    def test_update_status(self, fm):
        f = Fragment(title="F1")
        fm.create_fragment(f)
        ok = fm.update_status(f.fragment_id, "confirmed")
        assert ok is True
        assert fm.get_by_id(f.fragment_id).status == "confirmed"

    def test_update_nonexistent(self, fm):
        ok = fm.update_status("FRAG-FAKE", "confirmed")
        assert ok is False

    def test_dismiss(self, fm):
        f = Fragment(title="F1")
        fm.create_fragment(f)
        ok = fm.dismiss(f.fragment_id)
        assert ok is True
        assert fm.get_by_id(f.fragment_id).status == "dismissed"


class TestFragmentStatistics:
    def test_empty(self, fm):
        stats = fm.get_statistics()
        assert stats["total"] == 0

    def test_with_data(self, fm):
        f1 = Fragment(title="F1", fragment_type="info_leak")
        f2 = Fragment(title="F2", fragment_type="weak_config")
        fm.create_fragment(f1)
        fm.create_fragment(f2)
        fm.update_status(f2.fragment_id, "confirmed")

        stats = fm.get_statistics()
        assert stats["total"] == 2
        assert stats["discovered"] == 1
        assert stats["confirmed"] == 1
        assert "info_leak" in stats["by_type"]
