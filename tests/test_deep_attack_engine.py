"""
Comprehensive unit tests for kali_mcp.core.deep_attack_engine

Covers:
- Enum types: AttackPhase, ExploitDifficulty, TargetOS
- Dataclasses: ExploitTechnique, PrivilegeEscalation, LateralMoveTechnique,
               PersistenceTechnique, AttackChainResult
- Module-level technique lists: LINUX_PRIVESC_TECHNIQUES, WINDOWS_PRIVESC_TECHNIQUES,
                                 LATERAL_MOVEMENT_TECHNIQUES, PERSISTENCE_TECHNIQUES
- DeepAttackEngine class (all methods)
- Global singleton and convenience functions

Pure unit tests — no subprocess, no network.
"""

import pytest
from datetime import datetime
from unittest.mock import patch

from kali_mcp.core.deep_attack_engine import (
    # Enums
    AttackPhase,
    ExploitDifficulty,
    TargetOS,
    # Dataclasses
    ExploitTechnique,
    PrivilegeEscalation,
    LateralMoveTechnique,
    PersistenceTechnique,
    AttackChainResult,
    # Module-level lists
    LINUX_PRIVESC_TECHNIQUES,
    WINDOWS_PRIVESC_TECHNIQUES,
    LATERAL_MOVEMENT_TECHNIQUES,
    PERSISTENCE_TECHNIQUES,
    # Engine class
    DeepAttackEngine,
    # Global functions
    get_deep_attack_engine,
    get_privesc,
    get_lateral,
    get_persistence,
    generate_plan,
    # Module metadata
    __version__,
    __description__,
)


# =====================================================================
# Section 1: AttackPhase enum
# =====================================================================

class TestAttackPhase:
    """Tests for the AttackPhase enum — 13 MITRE ATT&CK phases."""

    def test_phase_count(self):
        assert len(AttackPhase) == 13

    @pytest.mark.parametrize("member,value", [
        ("RECONNAISSANCE", "reconnaissance"),
        ("RESOURCE_DEVELOPMENT", "resource_dev"),
        ("INITIAL_ACCESS", "initial_access"),
        ("EXECUTION", "execution"),
        ("PERSISTENCE", "persistence"),
        ("PRIVILEGE_ESCALATION", "priv_esc"),
        ("DEFENSE_EVASION", "defense_evasion"),
        ("CREDENTIAL_ACCESS", "cred_access"),
        ("DISCOVERY", "discovery"),
        ("LATERAL_MOVEMENT", "lateral_move"),
        ("COLLECTION", "collection"),
        ("EXFILTRATION", "exfiltration"),
        ("IMPACT", "impact"),
    ])
    def test_phase_values(self, member, value):
        assert AttackPhase[member].value == value

    def test_phase_from_value(self):
        assert AttackPhase("reconnaissance") == AttackPhase.RECONNAISSANCE

    def test_phase_invalid_value_raises(self):
        with pytest.raises(ValueError):
            AttackPhase("nonexistent_phase")

    def test_phase_identity(self):
        assert AttackPhase.IMPACT is AttackPhase.IMPACT

    def test_phase_inequality(self):
        assert AttackPhase.RECONNAISSANCE != AttackPhase.IMPACT


# =====================================================================
# Section 2: ExploitDifficulty enum
# =====================================================================

class TestExploitDifficulty:
    """Tests for the ExploitDifficulty enum — 5 levels."""

    def test_difficulty_count(self):
        assert len(ExploitDifficulty) == 5

    @pytest.mark.parametrize("member,value", [
        ("TRIVIAL", "trivial"),
        ("EASY", "easy"),
        ("MEDIUM", "medium"),
        ("HARD", "hard"),
        ("EXPERT", "expert"),
    ])
    def test_difficulty_values(self, member, value):
        assert ExploitDifficulty[member].value == value

    def test_difficulty_from_value(self):
        assert ExploitDifficulty("easy") == ExploitDifficulty.EASY

    def test_difficulty_invalid_raises(self):
        with pytest.raises(ValueError):
            ExploitDifficulty("impossible")


# =====================================================================
# Section 3: TargetOS enum
# =====================================================================

class TestTargetOS:
    """Tests for the TargetOS enum — 5 types."""

    def test_os_count(self):
        assert len(TargetOS) == 5

    @pytest.mark.parametrize("member,value", [
        ("LINUX", "linux"),
        ("WINDOWS", "windows"),
        ("MACOS", "macos"),
        ("UNIX", "unix"),
        ("UNKNOWN", "unknown"),
    ])
    def test_os_values(self, member, value):
        assert TargetOS[member].value == value

    def test_os_from_value(self):
        assert TargetOS("linux") == TargetOS.LINUX

    def test_os_invalid_raises(self):
        with pytest.raises(ValueError):
            TargetOS("plan9")


# =====================================================================
# Section 4: ExploitTechnique dataclass
# =====================================================================

class TestExploitTechnique:
    """Tests for the ExploitTechnique dataclass."""

    def _make(self, **overrides):
        defaults = dict(
            name="TestExploit",
            mitre_id="T1234",
            description="desc",
            phase=AttackPhase.EXECUTION,
            difficulty=ExploitDifficulty.EASY,
            target_os=[TargetOS.LINUX],
            prerequisites=["shell"],
            commands=["cmd1"],
            indicators=["ind1"],
        )
        defaults.update(overrides)
        return ExploitTechnique(**defaults)

    def test_creation_defaults(self):
        t = self._make()
        assert t.success_rate == 0.7
        assert t.detection_risk == 0.3

    def test_custom_success_rate(self):
        t = self._make(success_rate=0.9)
        assert t.success_rate == 0.9

    def test_custom_detection_risk(self):
        t = self._make(detection_risk=0.8)
        assert t.detection_risk == 0.8

    def test_mutable_list_fields(self):
        t = self._make()
        t.commands.append("extra")
        assert "extra" in t.commands

    def test_fields_assigned(self):
        t = self._make(name="X", mitre_id="T9999")
        assert t.name == "X"
        assert t.mitre_id == "T9999"

    def test_target_os_is_list(self):
        t = self._make(target_os=[TargetOS.LINUX, TargetOS.WINDOWS])
        assert len(t.target_os) == 2


# =====================================================================
# Section 5: PrivilegeEscalation dataclass
# =====================================================================

class TestPrivilegeEscalation:
    """Tests for the PrivilegeEscalation dataclass."""

    def _make(self, **overrides):
        defaults = dict(
            name="TestPrivesc",
            target_os=TargetOS.LINUX,
            from_privilege="user",
            to_privilege="root",
            technique="test",
            commands=["cmd"],
            check_commands=["check"],
            success_indicators=["uid=0"],
            difficulty=ExploitDifficulty.EASY,
        )
        defaults.update(overrides)
        return PrivilegeEscalation(**defaults)

    def test_creation(self):
        p = self._make()
        assert p.name == "TestPrivesc"
        assert p.from_privilege == "user"
        assert p.to_privilege == "root"

    def test_difficulty_attribute(self):
        p = self._make(difficulty=ExploitDifficulty.HARD)
        assert p.difficulty == ExploitDifficulty.HARD

    def test_target_os_attribute(self):
        p = self._make(target_os=TargetOS.WINDOWS)
        assert p.target_os == TargetOS.WINDOWS


# =====================================================================
# Section 6: LateralMoveTechnique dataclass
# =====================================================================

class TestLateralMoveTechnique:
    """Tests for the LateralMoveTechnique dataclass."""

    def _make(self, **overrides):
        defaults = dict(
            name="TestLateral",
            protocol="ssh",
            required_credentials="password",
            commands=["ssh user@host"],
            target_os=TargetOS.LINUX,
            detection_risk=0.3,
        )
        defaults.update(overrides)
        return LateralMoveTechnique(**defaults)

    def test_creation(self):
        t = self._make()
        assert t.name == "TestLateral"
        assert t.protocol == "ssh"
        assert t.detection_risk == 0.3

    def test_protocol_attribute(self):
        t = self._make(protocol="smb")
        assert t.protocol == "smb"


# =====================================================================
# Section 7: PersistenceTechnique dataclass
# =====================================================================

class TestPersistenceTechnique:
    """Tests for the PersistenceTechnique dataclass."""

    def _make(self, **overrides):
        defaults = dict(
            name="TestPersist",
            mitre_id="T1053.003",
            target_os=TargetOS.LINUX,
            method="cron",
            install_commands=["cmd"],
            verify_commands=["verify"],
            remove_commands=["rm"],
            stealth_level=5,
        )
        defaults.update(overrides)
        return PersistenceTechnique(**defaults)

    def test_creation(self):
        p = self._make()
        assert p.stealth_level == 5
        assert p.method == "cron"

    def test_stealth_level(self):
        p = self._make(stealth_level=10)
        assert p.stealth_level == 10


# =====================================================================
# Section 8: AttackChainResult dataclass
# =====================================================================

class TestAttackChainResult:
    """Tests for the AttackChainResult dataclass."""

    def _make(self, **overrides):
        now = datetime.now()
        defaults = dict(
            chain_name="test_chain",
            start_time=now,
            end_time=None,
            phases_completed=["recon"],
            vulnerabilities_found=[],
            exploits_succeeded=[],
            credentials_obtained=[],
            flags_found=[],
            pivot_points=[],
            success=False,
            error=None,
        )
        defaults.update(overrides)
        return AttackChainResult(**defaults)

    def test_creation_defaults(self):
        r = self._make()
        assert r.chain_name == "test_chain"
        assert r.end_time is None
        assert r.success is False
        assert r.error is None

    def test_with_success(self):
        r = self._make(success=True, end_time=datetime.now())
        assert r.success is True
        assert r.end_time is not None

    def test_with_error(self):
        r = self._make(error="connection refused")
        assert r.error == "connection refused"

    def test_flags_list(self):
        r = self._make(flags_found=["flag{abc}", "flag{def}"])
        assert len(r.flags_found) == 2

    def test_mutable_phases_completed(self):
        r = self._make()
        r.phases_completed.append("initial_access")
        assert "initial_access" in r.phases_completed

    def test_mutable_vulnerabilities_found(self):
        r = self._make()
        r.vulnerabilities_found.append({"id": "CVE-2024-1234"})
        assert len(r.vulnerabilities_found) == 1


# =====================================================================
# Section 9: Module-level technique lists
# =====================================================================

class TestLinuxPrivescTechniques:
    """Validate LINUX_PRIVESC_TECHNIQUES list."""

    def test_count(self):
        assert len(LINUX_PRIVESC_TECHNIQUES) == 8

    def test_all_linux_os(self):
        for t in LINUX_PRIVESC_TECHNIQUES:
            assert t.target_os == TargetOS.LINUX

    def test_all_are_privesc_type(self):
        for t in LINUX_PRIVESC_TECHNIQUES:
            assert isinstance(t, PrivilegeEscalation)

    @pytest.mark.parametrize("idx,name", [
        (0, "SUID Binary Exploitation"),
        (1, "Sudo Misconfiguration"),
        (2, "Kernel Exploit"),
        (3, "Cron Job Hijacking"),
        (4, "Writable /etc/passwd"),
        (5, "Capabilities Abuse"),
        (6, "Docker Escape"),
        (7, "NFS Root Squashing Bypass"),
    ])
    def test_technique_names(self, idx, name):
        assert LINUX_PRIVESC_TECHNIQUES[idx].name == name

    def test_all_have_commands(self):
        for t in LINUX_PRIVESC_TECHNIQUES:
            assert len(t.commands) > 0

    def test_all_have_check_commands(self):
        for t in LINUX_PRIVESC_TECHNIQUES:
            assert len(t.check_commands) > 0

    def test_all_have_success_indicators(self):
        for t in LINUX_PRIVESC_TECHNIQUES:
            assert len(t.success_indicators) > 0

    def test_difficulties_are_valid(self):
        for t in LINUX_PRIVESC_TECHNIQUES:
            assert isinstance(t.difficulty, ExploitDifficulty)

    def test_suid_difficulty(self):
        assert LINUX_PRIVESC_TECHNIQUES[0].difficulty == ExploitDifficulty.EASY

    def test_writable_passwd_difficulty(self):
        assert LINUX_PRIVESC_TECHNIQUES[4].difficulty == ExploitDifficulty.TRIVIAL

    def test_docker_escape_difficulty(self):
        assert LINUX_PRIVESC_TECHNIQUES[6].difficulty == ExploitDifficulty.HARD

    def test_docker_escape_from_privilege(self):
        assert LINUX_PRIVESC_TECHNIQUES[6].from_privilege == "container"

    def test_docker_escape_to_privilege(self):
        assert LINUX_PRIVESC_TECHNIQUES[6].to_privilege == "host_root"


class TestWindowsPrivescTechniques:
    """Validate WINDOWS_PRIVESC_TECHNIQUES list."""

    def test_count(self):
        assert len(WINDOWS_PRIVESC_TECHNIQUES) == 7

    def test_all_windows_os(self):
        for t in WINDOWS_PRIVESC_TECHNIQUES:
            assert t.target_os == TargetOS.WINDOWS

    def test_all_are_privesc_type(self):
        for t in WINDOWS_PRIVESC_TECHNIQUES:
            assert isinstance(t, PrivilegeEscalation)

    @pytest.mark.parametrize("idx,name", [
        (0, "Unquoted Service Path"),
        (1, "Always Install Elevated"),
        (2, "Token Impersonation"),
        (3, "JuicyPotato"),
        (4, "PrintSpoofer"),
        (5, "DLL Hijacking"),
        (6, "Scheduled Task Abuse"),
    ])
    def test_technique_names(self, idx, name):
        assert WINDOWS_PRIVESC_TECHNIQUES[idx].name == name

    def test_service_from_privilege(self):
        # Token Impersonation starts from "service"
        assert WINDOWS_PRIVESC_TECHNIQUES[2].from_privilege == "service"

    def test_system_to_privilege(self):
        for t in WINDOWS_PRIVESC_TECHNIQUES:
            assert t.to_privilege == "SYSTEM"


class TestLateralMovementTechniques:
    """Validate LATERAL_MOVEMENT_TECHNIQUES list."""

    def test_count(self):
        assert len(LATERAL_MOVEMENT_TECHNIQUES) == 9

    def test_all_are_lateral_type(self):
        for t in LATERAL_MOVEMENT_TECHNIQUES:
            assert isinstance(t, LateralMoveTechnique)

    @pytest.mark.parametrize("idx,name", [
        (0, "PSExec"),
        (1, "WMIExec"),
        (2, "SMBExec"),
        (3, "Evil-WinRM"),
        (4, "SSH Key"),
        (5, "Pass-the-Hash"),
        (6, "Pass-the-Ticket"),
        (7, "DCOM Execution"),
        (8, "RDP Hijacking"),
    ])
    def test_technique_names(self, idx, name):
        assert LATERAL_MOVEMENT_TECHNIQUES[idx].name == name

    def test_ssh_key_is_linux(self):
        assert LATERAL_MOVEMENT_TECHNIQUES[4].target_os == TargetOS.LINUX

    def test_non_ssh_are_windows(self):
        for t in LATERAL_MOVEMENT_TECHNIQUES:
            if t.protocol != "ssh":
                assert t.target_os == TargetOS.WINDOWS

    def test_detection_risk_range(self):
        for t in LATERAL_MOVEMENT_TECHNIQUES:
            assert 0.0 <= t.detection_risk <= 1.0

    def test_all_have_commands(self):
        for t in LATERAL_MOVEMENT_TECHNIQUES:
            assert len(t.commands) > 0

    def test_protocols_present(self):
        protocols = {t.protocol for t in LATERAL_MOVEMENT_TECHNIQUES}
        assert "smb" in protocols
        assert "ssh" in protocols
        assert "wmi" in protocols
        assert "winrm" in protocols
        assert "kerberos" in protocols
        assert "dcom" in protocols
        assert "rdp" in protocols


class TestPersistenceTechniques:
    """Validate PERSISTENCE_TECHNIQUES list."""

    def test_count(self):
        assert len(PERSISTENCE_TECHNIQUES) == 9

    def test_all_are_persistence_type(self):
        for t in PERSISTENCE_TECHNIQUES:
            assert isinstance(t, PersistenceTechnique)

    @pytest.mark.parametrize("idx,name", [
        (0, "Cron Job"),
        (1, "SSH Authorized Keys"),
        (2, "Systemd Service"),
        (3, "Bashrc Modification"),
        (4, "Registry Run Key"),
        (5, "Scheduled Task"),
        (6, "Windows Service"),
        (7, "WMI Event Subscription"),
        (8, "Golden Ticket"),
    ])
    def test_technique_names(self, idx, name):
        assert PERSISTENCE_TECHNIQUES[idx].name == name

    def test_linux_techniques(self):
        linux_techs = [t for t in PERSISTENCE_TECHNIQUES if t.target_os == TargetOS.LINUX]
        assert len(linux_techs) == 4

    def test_windows_techniques(self):
        windows_techs = [t for t in PERSISTENCE_TECHNIQUES if t.target_os == TargetOS.WINDOWS]
        assert len(windows_techs) == 5

    def test_stealth_range(self):
        for t in PERSISTENCE_TECHNIQUES:
            assert 1 <= t.stealth_level <= 10

    def test_golden_ticket_stealth(self):
        assert PERSISTENCE_TECHNIQUES[8].stealth_level == 9

    def test_all_have_mitre_ids(self):
        for t in PERSISTENCE_TECHNIQUES:
            assert t.mitre_id.startswith("T")

    def test_all_have_install_commands(self):
        for t in PERSISTENCE_TECHNIQUES:
            assert len(t.install_commands) > 0

    def test_all_have_verify_commands(self):
        for t in PERSISTENCE_TECHNIQUES:
            assert len(t.verify_commands) > 0

    def test_all_have_remove_commands(self):
        for t in PERSISTENCE_TECHNIQUES:
            assert len(t.remove_commands) > 0


# =====================================================================
# Section 10: DeepAttackEngine — initialization
# =====================================================================

class TestDeepAttackEngineInit:
    """Tests for DeepAttackEngine.__init__."""

    def test_initial_phase(self):
        e = DeepAttackEngine()
        assert e.current_phase == AttackPhase.RECONNAISSANCE

    def test_empty_attack_history(self):
        e = DeepAttackEngine()
        assert e.attack_history == []

    def test_empty_credentials(self):
        e = DeepAttackEngine()
        assert e.discovered_credentials == []

    def test_empty_pivot_points(self):
        e = DeepAttackEngine()
        assert e.pivot_points == []

    def test_empty_flags(self):
        e = DeepAttackEngine()
        assert e.flags == []

    def test_linux_privesc_loaded(self):
        e = DeepAttackEngine()
        assert e.linux_privesc is LINUX_PRIVESC_TECHNIQUES

    def test_windows_privesc_loaded(self):
        e = DeepAttackEngine()
        assert e.windows_privesc is WINDOWS_PRIVESC_TECHNIQUES

    def test_lateral_loaded(self):
        e = DeepAttackEngine()
        assert e.lateral_techniques is LATERAL_MOVEMENT_TECHNIQUES

    def test_persistence_loaded(self):
        e = DeepAttackEngine()
        assert e.persistence_techniques is PERSISTENCE_TECHNIQUES

    def test_instances_are_independent(self):
        e1 = DeepAttackEngine()
        e2 = DeepAttackEngine()
        e1.flags.append("flag{1}")
        assert "flag{1}" not in e2.flags


# =====================================================================
# Section 11: get_privesc_techniques
# =====================================================================

class TestGetPrivescTechniques:
    """Tests for DeepAttackEngine.get_privesc_techniques."""

    @pytest.fixture
    def engine(self):
        return DeepAttackEngine()

    def test_linux_returns_all(self, engine):
        result = engine.get_privesc_techniques(TargetOS.LINUX)
        assert len(result) == 8

    def test_windows_returns_all(self, engine):
        result = engine.get_privesc_techniques(TargetOS.WINDOWS)
        assert len(result) == 7

    def test_macos_returns_empty(self, engine):
        result = engine.get_privesc_techniques(TargetOS.MACOS)
        assert result == []

    def test_unix_returns_empty(self, engine):
        result = engine.get_privesc_techniques(TargetOS.UNIX)
        assert result == []

    def test_unknown_returns_empty(self, engine):
        result = engine.get_privesc_techniques(TargetOS.UNKNOWN)
        assert result == []

    def test_filter_trivial_linux(self, engine):
        result = engine.get_privesc_techniques(TargetOS.LINUX, ExploitDifficulty.TRIVIAL)
        for t in result:
            assert t.difficulty == ExploitDifficulty.TRIVIAL
        assert len(result) == 1  # Only "Writable /etc/passwd"

    def test_filter_easy_linux(self, engine):
        result = engine.get_privesc_techniques(TargetOS.LINUX, ExploitDifficulty.EASY)
        for t in result:
            assert t.difficulty in (ExploitDifficulty.TRIVIAL, ExploitDifficulty.EASY)

    def test_filter_medium_linux(self, engine):
        result = engine.get_privesc_techniques(TargetOS.LINUX, ExploitDifficulty.MEDIUM)
        allowed = {ExploitDifficulty.TRIVIAL, ExploitDifficulty.EASY, ExploitDifficulty.MEDIUM}
        for t in result:
            assert t.difficulty in allowed

    def test_filter_hard_linux(self, engine):
        result = engine.get_privesc_techniques(TargetOS.LINUX, ExploitDifficulty.HARD)
        # Should include all 8 (TRIVIAL + EASY + MEDIUM + HARD, no EXPERT in list)
        assert len(result) == 8

    def test_filter_expert_linux(self, engine):
        result = engine.get_privesc_techniques(TargetOS.LINUX, ExploitDifficulty.EXPERT)
        assert len(result) == 8

    def test_filter_easy_windows(self, engine):
        result = engine.get_privesc_techniques(TargetOS.WINDOWS, ExploitDifficulty.EASY)
        for t in result:
            assert t.difficulty in (ExploitDifficulty.TRIVIAL, ExploitDifficulty.EASY)
        # Unquoted Service Path, Always Install Elevated, PrintSpoofer
        assert len(result) == 3

    def test_filter_medium_windows(self, engine):
        result = engine.get_privesc_techniques(TargetOS.WINDOWS, ExploitDifficulty.MEDIUM)
        assert len(result) == 7  # All are EASY or MEDIUM

    def test_none_difficulty_returns_all(self, engine):
        result = engine.get_privesc_techniques(TargetOS.LINUX, None)
        assert len(result) == 8

    def test_returned_types(self, engine):
        result = engine.get_privesc_techniques(TargetOS.LINUX)
        for t in result:
            assert isinstance(t, PrivilegeEscalation)


# =====================================================================
# Section 12: get_lateral_techniques
# =====================================================================

class TestGetLateralTechniques:
    """Tests for DeepAttackEngine.get_lateral_techniques."""

    @pytest.fixture
    def engine(self):
        return DeepAttackEngine()

    def test_no_filter_returns_all(self, engine):
        result = engine.get_lateral_techniques()
        assert len(result) == 9

    def test_sorted_by_detection_risk(self, engine):
        result = engine.get_lateral_techniques()
        risks = [t.detection_risk for t in result]
        assert risks == sorted(risks)

    def test_filter_by_smb(self, engine):
        result = engine.get_lateral_techniques(protocol="smb")
        assert all(t.protocol == "smb" for t in result)
        assert len(result) == 3  # PSExec, SMBExec, Pass-the-Hash

    def test_filter_by_ssh(self, engine):
        result = engine.get_lateral_techniques(protocol="ssh")
        assert len(result) == 1
        assert result[0].name == "SSH Key"

    def test_filter_by_wmi(self, engine):
        result = engine.get_lateral_techniques(protocol="wmi")
        assert len(result) == 1
        assert result[0].name == "WMIExec"

    def test_filter_by_winrm(self, engine):
        result = engine.get_lateral_techniques(protocol="winrm")
        assert len(result) == 1

    def test_filter_by_kerberos(self, engine):
        result = engine.get_lateral_techniques(protocol="kerberos")
        assert len(result) == 1
        assert result[0].name == "Pass-the-Ticket"

    def test_filter_by_dcom(self, engine):
        result = engine.get_lateral_techniques(protocol="dcom")
        assert len(result) == 1

    def test_filter_by_rdp(self, engine):
        result = engine.get_lateral_techniques(protocol="rdp")
        assert len(result) == 1
        assert result[0].name == "RDP Hijacking"

    def test_filter_by_nonexistent_protocol(self, engine):
        result = engine.get_lateral_techniques(protocol="telnet")
        assert result == []

    def test_filter_by_os_linux(self, engine):
        result = engine.get_lateral_techniques(target_os=TargetOS.LINUX)
        assert len(result) == 1
        assert result[0].name == "SSH Key"

    def test_filter_by_os_windows(self, engine):
        result = engine.get_lateral_techniques(target_os=TargetOS.WINDOWS)
        assert len(result) == 8

    def test_filter_by_os_macos(self, engine):
        result = engine.get_lateral_techniques(target_os=TargetOS.MACOS)
        assert result == []

    def test_combined_filter_smb_windows(self, engine):
        result = engine.get_lateral_techniques(protocol="smb", target_os=TargetOS.WINDOWS)
        assert len(result) == 3

    def test_combined_filter_smb_linux(self, engine):
        result = engine.get_lateral_techniques(protocol="smb", target_os=TargetOS.LINUX)
        assert result == []

    def test_combined_filter_ssh_linux(self, engine):
        result = engine.get_lateral_techniques(protocol="ssh", target_os=TargetOS.LINUX)
        assert len(result) == 1

    def test_combined_filter_ssh_windows(self, engine):
        result = engine.get_lateral_techniques(protocol="ssh", target_os=TargetOS.WINDOWS)
        assert result == []

    def test_sorted_smb_by_risk(self, engine):
        result = engine.get_lateral_techniques(protocol="smb")
        risks = [t.detection_risk for t in result]
        assert risks == sorted(risks)


# =====================================================================
# Section 13: get_persistence_techniques
# =====================================================================

class TestGetPersistenceTechniques:
    """Tests for DeepAttackEngine.get_persistence_techniques."""

    @pytest.fixture
    def engine(self):
        return DeepAttackEngine()

    def test_linux_returns_four(self, engine):
        result = engine.get_persistence_techniques(TargetOS.LINUX)
        assert len(result) == 4

    def test_windows_returns_five(self, engine):
        result = engine.get_persistence_techniques(TargetOS.WINDOWS)
        assert len(result) == 5

    def test_macos_returns_empty(self, engine):
        result = engine.get_persistence_techniques(TargetOS.MACOS)
        assert result == []

    def test_sorted_by_stealth_descending(self, engine):
        result = engine.get_persistence_techniques(TargetOS.LINUX)
        levels = [t.stealth_level for t in result]
        assert levels == sorted(levels, reverse=True)

    def test_sorted_windows_by_stealth_descending(self, engine):
        result = engine.get_persistence_techniques(TargetOS.WINDOWS)
        levels = [t.stealth_level for t in result]
        assert levels == sorted(levels, reverse=True)

    def test_stealth_min_filters(self, engine):
        result = engine.get_persistence_techniques(TargetOS.LINUX, stealth_min=6)
        for t in result:
            assert t.stealth_level >= 6
        # SSH Keys (7), Bashrc (6) -> 2
        assert len(result) == 2

    def test_stealth_min_filters_windows(self, engine):
        result = engine.get_persistence_techniques(TargetOS.WINDOWS, stealth_min=8)
        for t in result:
            assert t.stealth_level >= 8
        # WMI (8), Golden Ticket (9) -> 2
        assert len(result) == 2

    def test_stealth_min_zero_returns_all(self, engine):
        result = engine.get_persistence_techniques(TargetOS.LINUX, stealth_min=0)
        assert len(result) == 4

    def test_stealth_min_very_high_returns_empty(self, engine):
        result = engine.get_persistence_techniques(TargetOS.LINUX, stealth_min=11)
        assert result == []

    def test_stealth_min_exact_boundary(self, engine):
        # Cron Job has stealth_level=5
        result = engine.get_persistence_techniques(TargetOS.LINUX, stealth_min=5)
        assert any(t.name == "Cron Job" for t in result)

    def test_stealth_min_one_above_boundary(self, engine):
        # Systemd has stealth_level=4
        result = engine.get_persistence_techniques(TargetOS.LINUX, stealth_min=5)
        assert not any(t.name == "Systemd Service" for t in result)


# =====================================================================
# Section 14: suggest_next_phase
# =====================================================================

class TestSuggestNextPhase:
    """Tests for DeepAttackEngine.suggest_next_phase."""

    @pytest.fixture
    def engine(self):
        return DeepAttackEngine()

    def test_no_shell_returns_initial_access(self, engine):
        phase, reasons = engine.suggest_next_phase(
            AttackPhase.RECONNAISSANCE, {"has_shell": False}
        )
        assert phase == AttackPhase.INITIAL_ACCESS
        assert len(reasons) > 0

    def test_shell_no_root_returns_priv_esc(self, engine):
        phase, reasons = engine.suggest_next_phase(
            AttackPhase.INITIAL_ACCESS,
            {"has_shell": True, "is_root": False}
        )
        assert phase == AttackPhase.PRIVILEGE_ESCALATION

    def test_root_no_creds_returns_cred_access(self, engine):
        phase, reasons = engine.suggest_next_phase(
            AttackPhase.PRIVILEGE_ESCALATION,
            {"has_shell": True, "is_root": True, "has_credentials": False}
        )
        assert phase == AttackPhase.CREDENTIAL_ACCESS

    def test_creds_with_network_returns_lateral(self, engine):
        phase, reasons = engine.suggest_next_phase(
            AttackPhase.CREDENTIAL_ACCESS,
            {
                "has_shell": True,
                "is_root": True,
                "has_credentials": True,
                "network_access": True,
            }
        )
        assert phase == AttackPhase.LATERAL_MOVEMENT

    def test_default_next_phase(self, engine):
        # All flags True but no network → falls through to next in order
        phase, reasons = engine.suggest_next_phase(
            AttackPhase.RECONNAISSANCE,
            {
                "has_shell": True,
                "is_root": True,
                "has_credentials": True,
                "network_access": False,
            }
        )
        assert phase == AttackPhase.INITIAL_ACCESS  # next after RECONNAISSANCE

    def test_last_phase_returns_exfiltration(self, engine):
        phase, reasons = engine.suggest_next_phase(
            AttackPhase.EXFILTRATION,
            {
                "has_shell": True,
                "is_root": True,
                "has_credentials": True,
                "network_access": False,
            }
        )
        assert phase == AttackPhase.EXFILTRATION

    def test_no_shell_overrides_all_else(self, engine):
        # Even with is_root=True, no shell → initial access
        phase, _ = engine.suggest_next_phase(
            AttackPhase.DISCOVERY,
            {"has_shell": False, "is_root": True, "has_credentials": True, "network_access": True}
        )
        assert phase == AttackPhase.INITIAL_ACCESS

    def test_empty_context(self, engine):
        # All default to False
        phase, _ = engine.suggest_next_phase(AttackPhase.RECONNAISSANCE, {})
        assert phase == AttackPhase.INITIAL_ACCESS

    def test_reasons_are_strings(self, engine):
        _, reasons = engine.suggest_next_phase(AttackPhase.RECONNAISSANCE, {})
        for r in reasons:
            assert isinstance(r, str)

    def test_progression_from_execution(self, engine):
        phase, _ = engine.suggest_next_phase(
            AttackPhase.EXECUTION,
            {"has_shell": True, "is_root": True, "has_credentials": True, "network_access": False}
        )
        # Next after EXECUTION in phase_order is PRIVILEGE_ESCALATION
        assert phase == AttackPhase.PRIVILEGE_ESCALATION

    def test_progression_from_collection(self, engine):
        phase, _ = engine.suggest_next_phase(
            AttackPhase.COLLECTION,
            {"has_shell": True, "is_root": True, "has_credentials": True, "network_access": False}
        )
        assert phase == AttackPhase.EXFILTRATION


# =====================================================================
# Section 15: generate_attack_plan
# =====================================================================

class TestGenerateAttackPlan:
    """Tests for DeepAttackEngine.generate_attack_plan."""

    @pytest.fixture
    def engine(self):
        return DeepAttackEngine()

    def test_basic_plan_structure(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "10.0.0.1"})
        assert "target" in plan
        assert "phases" in plan
        assert "estimated_time" in plan
        assert "difficulty" in plan

    def test_target_preserved(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "192.168.1.1"})
        assert plan["target"] == "192.168.1.1"

    def test_default_difficulty(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        assert plan["difficulty"] == "medium"

    def test_http_service_creates_web_technique(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": ["http"], "target": "x"})
        initial_phase = plan["phases"][0]
        assert initial_phase["phase"] == "initial_access"
        tech_names = [t["name"] for t in initial_phase["techniques"]]
        assert "Web Application Exploitation" in tech_names

    def test_https_service_creates_web_technique(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": ["https"], "target": "x"})
        initial_phase = plan["phases"][0]
        tech_names = [t["name"] for t in initial_phase["techniques"]]
        assert "Web Application Exploitation" in tech_names

    def test_ssh_service_creates_brute_force(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": ["ssh"], "target": "x"})
        initial_phase = plan["phases"][0]
        tech_names = [t["name"] for t in initial_phase["techniques"]]
        assert "SSH Brute Force" in tech_names

    def test_smb_service_creates_smb_exploit(self, engine):
        plan = engine.generate_attack_plan({"os": "windows", "services": ["smb"], "target": "x"})
        initial_phase = plan["phases"][0]
        tech_names = [t["name"] for t in initial_phase["techniques"]]
        assert "SMB Exploitation" in tech_names

    def test_multiple_services(self, engine):
        plan = engine.generate_attack_plan({
            "os": "linux", "services": ["http", "ssh", "smb"], "target": "x"
        })
        initial_phase = plan["phases"][0]
        assert len(initial_phase["techniques"]) == 3

    def test_no_services_empty_initial(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        initial_phase = plan["phases"][0]
        assert initial_phase["techniques"] == []

    def test_privesc_phase_present(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        phase_names = [p["phase"] for p in plan["phases"]]
        assert "priv_esc" in phase_names

    def test_persistence_phase_present(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        phase_names = [p["phase"] for p in plan["phases"]]
        assert "persistence" in phase_names

    def test_cred_access_phase_present(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        phase_names = [p["phase"] for p in plan["phases"]]
        assert "cred_access" in phase_names

    def test_lateral_movement_not_present_when_not_internal(self, engine):
        plan = engine.generate_attack_plan({
            "os": "linux", "services": [], "target": "x", "is_internal": False
        })
        phase_names = [p["phase"] for p in plan["phases"]]
        assert "lateral_move" not in phase_names

    def test_lateral_movement_present_when_internal(self, engine):
        plan = engine.generate_attack_plan({
            "os": "linux", "services": [], "target": "x", "is_internal": True
        })
        phase_names = [p["phase"] for p in plan["phases"]]
        assert "lateral_move" in phase_names

    def test_phase_count_without_lateral(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        assert len(plan["phases"]) == 4  # initial, privesc, persistence, cred

    def test_phase_count_with_lateral(self, engine):
        plan = engine.generate_attack_plan({
            "os": "linux", "services": [], "target": "x", "is_internal": True
        })
        assert len(plan["phases"]) == 5

    def test_unknown_os(self, engine):
        plan = engine.generate_attack_plan({"os": "unknown", "services": [], "target": "x"})
        # Privesc for unknown OS → empty techniques
        privesc_phase = [p for p in plan["phases"] if p["phase"] == "priv_esc"][0]
        assert privesc_phase["techniques"] == []

    def test_linux_cred_access_uses_shadow(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        cred_phase = [p for p in plan["phases"] if p["phase"] == "cred_access"][0]
        cmd = cred_phase["techniques"][0]["commands"][0]
        assert "shadow" in cmd

    def test_windows_cred_access_uses_mimikatz(self, engine):
        plan = engine.generate_attack_plan({"os": "windows", "services": [], "target": "x"})
        cred_phase = [p for p in plan["phases"] if p["phase"] == "cred_access"][0]
        cmd = cred_phase["techniques"][0]["commands"][0]
        assert "mimikatz" in cmd

    def test_privesc_limited_to_medium(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        privesc_phase = [p for p in plan["phases"] if p["phase"] == "priv_esc"][0]
        for t in privesc_phase["techniques"]:
            assert t["difficulty"] in ("trivial", "easy", "medium")

    def test_privesc_max_five(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        privesc_phase = [p for p in plan["phases"] if p["phase"] == "priv_esc"][0]
        assert len(privesc_phase["techniques"]) <= 5

    def test_persistence_stealth_min_five(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        persist_phase = [p for p in plan["phases"] if p["phase"] == "persistence"][0]
        for t in persist_phase["techniques"]:
            assert t["stealth"] >= 5

    def test_persistence_max_three(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        persist_phase = [p for p in plan["phases"] if p["phase"] == "persistence"][0]
        assert len(persist_phase["techniques"]) <= 3

    def test_missing_os_defaults_unknown(self, engine):
        plan = engine.generate_attack_plan({"services": [], "target": "x"})
        # Should not raise — defaults to "unknown"
        assert plan is not None

    def test_web_technique_has_tools(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": ["http"], "target": "x"})
        web_tech = plan["phases"][0]["techniques"][0]
        assert "tools" in web_tech
        assert len(web_tech["tools"]) > 0


# =====================================================================
# Section 16: log_attack_step
# =====================================================================

class TestLogAttackStep:
    """Tests for DeepAttackEngine.log_attack_step."""

    @pytest.fixture
    def engine(self):
        return DeepAttackEngine()

    def test_appends_to_history(self, engine):
        engine.log_attack_step(AttackPhase.RECONNAISSANCE, "nmap", True)
        assert len(engine.attack_history) == 1

    def test_step_content(self, engine):
        engine.log_attack_step(AttackPhase.EXECUTION, "exploit", False, {"error": "failed"})
        step = engine.attack_history[0]
        assert step["phase"] == "execution"
        assert step["technique"] == "exploit"
        assert step["success"] is False
        assert step["details"]["error"] == "failed"

    def test_default_details_empty(self, engine):
        engine.log_attack_step(AttackPhase.RECONNAISSANCE, "scan", True)
        assert engine.attack_history[0]["details"] == {}

    def test_timestamp_present(self, engine):
        engine.log_attack_step(AttackPhase.RECONNAISSANCE, "scan", True)
        assert "timestamp" in engine.attack_history[0]

    def test_multiple_steps(self, engine):
        engine.log_attack_step(AttackPhase.RECONNAISSANCE, "step1", True)
        engine.log_attack_step(AttackPhase.INITIAL_ACCESS, "step2", False)
        engine.log_attack_step(AttackPhase.EXECUTION, "step3", True)
        assert len(engine.attack_history) == 3


# =====================================================================
# Section 17: add_credential
# =====================================================================

class TestAddCredential:
    """Tests for DeepAttackEngine.add_credential."""

    @pytest.fixture
    def engine(self):
        return DeepAttackEngine()

    def test_appends_credential(self, engine):
        engine.add_credential("password", "admin", "pass123", "shadow")
        assert len(engine.discovered_credentials) == 1

    def test_credential_fields(self, engine):
        engine.add_credential("hash", "root", "aabbccdd", "mimikatz")
        cred = engine.discovered_credentials[0]
        assert cred["type"] == "hash"
        assert cred["username"] == "root"
        assert cred["credential"] == "aabbccdd"
        assert cred["source"] == "mimikatz"
        assert "discovered_at" in cred

    def test_multiple_credentials(self, engine):
        engine.add_credential("password", "user1", "p1", "src1")
        engine.add_credential("key", "user2", "k2", "src2")
        assert len(engine.discovered_credentials) == 2

    def test_duplicate_credentials_allowed(self, engine):
        # Unlike flags, credentials do NOT deduplicate
        engine.add_credential("password", "admin", "pass", "src")
        engine.add_credential("password", "admin", "pass", "src")
        assert len(engine.discovered_credentials) == 2


# =====================================================================
# Section 18: add_pivot_point
# =====================================================================

class TestAddPivotPoint:
    """Tests for DeepAttackEngine.add_pivot_point."""

    @pytest.fixture
    def engine(self):
        return DeepAttackEngine()

    def test_appends_pivot(self, engine):
        engine.add_pivot_point("10.0.0.2", "ssh")
        assert len(engine.pivot_points) == 1

    def test_pivot_fields(self, engine):
        engine.add_pivot_point("192.168.1.5", "smb")
        pivot = engine.pivot_points[0]
        assert pivot["target"] == "192.168.1.5"
        assert pivot["access_method"] == "smb"
        assert "discovered_at" in pivot

    def test_multiple_pivots(self, engine):
        engine.add_pivot_point("10.0.0.2", "ssh")
        engine.add_pivot_point("10.0.0.3", "rdp")
        assert len(engine.pivot_points) == 2


# =====================================================================
# Section 19: add_flag
# =====================================================================

class TestAddFlag:
    """Tests for DeepAttackEngine.add_flag — deduplication."""

    @pytest.fixture
    def engine(self):
        return DeepAttackEngine()

    def test_adds_flag(self, engine):
        engine.add_flag("flag{test123}", "web")
        assert "flag{test123}" in engine.flags

    def test_deduplicates(self, engine):
        engine.add_flag("flag{dup}", "src1")
        engine.add_flag("flag{dup}", "src2")
        assert len(engine.flags) == 1

    def test_different_flags_both_added(self, engine):
        engine.add_flag("flag{a}", "s1")
        engine.add_flag("flag{b}", "s2")
        assert len(engine.flags) == 2

    def test_source_not_stored(self, engine):
        # add_flag ignores source in storage; only deduplicates on flag value
        engine.add_flag("flag{x}", "source_ignored")
        assert engine.flags == ["flag{x}"]


# =====================================================================
# Section 20: get_attack_summary
# =====================================================================

class TestGetAttackSummary:
    """Tests for DeepAttackEngine.get_attack_summary."""

    @pytest.fixture
    def engine(self):
        return DeepAttackEngine()

    def test_empty_summary(self, engine):
        summary = engine.get_attack_summary()
        assert summary["current_phase"] == "reconnaissance"
        assert summary["steps_executed"] == 0
        assert summary["successful_steps"] == 0
        assert summary["credentials_found"] == 0
        assert summary["pivot_points"] == 0
        assert summary["flags_found"] == []
        assert summary["history"] == []

    def test_summary_after_steps(self, engine):
        engine.log_attack_step(AttackPhase.RECONNAISSANCE, "nmap", True)
        engine.log_attack_step(AttackPhase.INITIAL_ACCESS, "exploit", False)
        engine.log_attack_step(AttackPhase.EXECUTION, "cmd", True)
        summary = engine.get_attack_summary()
        assert summary["steps_executed"] == 3
        assert summary["successful_steps"] == 2

    def test_summary_credentials_count(self, engine):
        engine.add_credential("pass", "u", "p", "s")
        engine.add_credential("hash", "u2", "h", "s2")
        assert engine.get_attack_summary()["credentials_found"] == 2

    def test_summary_pivot_count(self, engine):
        engine.add_pivot_point("10.0.0.1", "ssh")
        assert engine.get_attack_summary()["pivot_points"] == 1

    def test_summary_flags(self, engine):
        engine.add_flag("flag{a}", "s")
        engine.add_flag("flag{b}", "s")
        assert engine.get_attack_summary()["flags_found"] == ["flag{a}", "flag{b}"]

    def test_history_limited_to_10(self, engine):
        for i in range(15):
            engine.log_attack_step(AttackPhase.EXECUTION, f"step{i}", True)
        summary = engine.get_attack_summary()
        assert len(summary["history"]) == 10
        # Should be the last 10 steps
        assert summary["history"][0]["technique"] == "step5"
        assert summary["history"][-1]["technique"] == "step14"

    def test_current_phase_reflects_changes(self, engine):
        engine.current_phase = AttackPhase.LATERAL_MOVEMENT
        assert engine.get_attack_summary()["current_phase"] == "lateral_move"


# =====================================================================
# Section 21: get_deep_attack_engine singleton
# =====================================================================

class TestGetDeepAttackEngine:
    """Tests for the global singleton factory."""

    def test_returns_engine(self):
        # Reset the singleton to ensure clean state
        import kali_mcp.core.deep_attack_engine as mod
        mod._deep_attack_engine = None
        engine = get_deep_attack_engine()
        assert isinstance(engine, DeepAttackEngine)

    def test_singleton_returns_same_instance(self):
        import kali_mcp.core.deep_attack_engine as mod
        mod._deep_attack_engine = None
        e1 = get_deep_attack_engine()
        e2 = get_deep_attack_engine()
        assert e1 is e2

    def test_singleton_can_be_reset(self):
        import kali_mcp.core.deep_attack_engine as mod
        mod._deep_attack_engine = None
        e1 = get_deep_attack_engine()
        mod._deep_attack_engine = None
        e2 = get_deep_attack_engine()
        assert e1 is not e2

    def test_singleton_state_persists(self):
        import kali_mcp.core.deep_attack_engine as mod
        mod._deep_attack_engine = None
        engine = get_deep_attack_engine()
        engine.add_flag("flag{singleton}", "test")
        same_engine = get_deep_attack_engine()
        assert "flag{singleton}" in same_engine.flags


# =====================================================================
# Section 22: get_privesc convenience function
# =====================================================================

class TestGetPrivescFunction:
    """Tests for the get_privesc() module-level function."""

    def setup_method(self):
        import kali_mcp.core.deep_attack_engine as mod
        mod._deep_attack_engine = None

    def test_linux_all(self):
        result = get_privesc("linux")
        assert len(result) == 8

    def test_windows_all(self):
        result = get_privesc("windows")
        assert len(result) == 7

    def test_returns_dicts(self):
        result = get_privesc("linux")
        for item in result:
            assert isinstance(item, dict)
            assert "name" in item
            assert "technique" in item
            assert "commands" in item
            assert "difficulty" in item

    def test_with_difficulty_filter(self):
        result = get_privesc("linux", "easy")
        for item in result:
            assert item["difficulty"] in ("trivial", "easy")

    def test_with_trivial_filter(self):
        result = get_privesc("linux", "trivial")
        assert len(result) == 1

    def test_case_insensitive_os(self):
        # The function does os_type.lower()
        result = get_privesc("LINUX")
        assert len(result) == 8

    def test_unknown_os_empty(self):
        result = get_privesc("unknown")
        assert result == []

    def test_invalid_os_raises(self):
        with pytest.raises(ValueError):
            get_privesc("plan9")


# =====================================================================
# Section 23: get_lateral convenience function
# =====================================================================

class TestGetLateralFunction:
    """Tests for the get_lateral() module-level function."""

    def setup_method(self):
        import kali_mcp.core.deep_attack_engine as mod
        mod._deep_attack_engine = None

    def test_all(self):
        result = get_lateral()
        assert len(result) == 9

    def test_returns_dicts(self):
        result = get_lateral()
        for item in result:
            assert isinstance(item, dict)
            assert "name" in item
            assert "protocol" in item
            assert "commands" in item
            assert "detection_risk" in item

    def test_filter_by_protocol(self):
        result = get_lateral(protocol="smb")
        assert len(result) == 3

    def test_filter_by_os(self):
        result = get_lateral(os_type="linux")
        assert len(result) == 1

    def test_filter_combined(self):
        result = get_lateral(protocol="ssh", os_type="linux")
        assert len(result) == 1

    def test_case_insensitive_os(self):
        result = get_lateral(os_type="WINDOWS")
        assert len(result) == 8

    def test_no_os_no_protocol(self):
        result = get_lateral(protocol=None, os_type=None)
        assert len(result) == 9

    def test_sorted_by_risk(self):
        result = get_lateral()
        risks = [r["detection_risk"] for r in result]
        assert risks == sorted(risks)


# =====================================================================
# Section 24: get_persistence convenience function
# =====================================================================

class TestGetPersistenceFunction:
    """Tests for the get_persistence() module-level function."""

    def setup_method(self):
        import kali_mcp.core.deep_attack_engine as mod
        mod._deep_attack_engine = None

    def test_linux_all(self):
        result = get_persistence("linux")
        assert len(result) == 4

    def test_windows_all(self):
        result = get_persistence("windows")
        assert len(result) == 5

    def test_returns_dicts(self):
        result = get_persistence("linux")
        for item in result:
            assert isinstance(item, dict)
            assert "name" in item
            assert "mitre_id" in item
            assert "method" in item
            assert "install_commands" in item
            assert "stealth_level" in item

    def test_with_stealth_filter(self):
        result = get_persistence("linux", min_stealth=7)
        for item in result:
            assert item["stealth_level"] >= 7

    def test_case_insensitive_os(self):
        result = get_persistence("LINUX")
        assert len(result) == 4

    def test_sorted_by_stealth_desc(self):
        result = get_persistence("windows")
        levels = [r["stealth_level"] for r in result]
        assert levels == sorted(levels, reverse=True)


# =====================================================================
# Section 25: generate_plan convenience function
# =====================================================================

class TestGeneratePlanFunction:
    """Tests for the generate_plan() module-level function."""

    def setup_method(self):
        import kali_mcp.core.deep_attack_engine as mod
        mod._deep_attack_engine = None

    def test_basic_call(self):
        plan = generate_plan({"os": "linux", "services": ["http"], "target": "10.0.0.1"})
        assert "phases" in plan
        assert plan["target"] == "10.0.0.1"

    def test_uses_singleton(self):
        import kali_mcp.core.deep_attack_engine as mod
        mod._deep_attack_engine = None
        generate_plan({"os": "linux", "services": [], "target": "x"})
        assert mod._deep_attack_engine is not None


# =====================================================================
# Section 26: Module metadata
# =====================================================================

class TestModuleMetadata:
    """Tests for module-level constants."""

    def test_version(self):
        assert __version__ == "2.0.0"

    def test_description_not_empty(self):
        assert len(__description__) > 0
        assert "Deep Attack Engine" in __description__


# =====================================================================
# Section 27: Edge cases and integration-style unit tests
# =====================================================================

class TestEdgeCases:
    """Edge cases and boundary conditions."""

    @pytest.fixture
    def engine(self):
        return DeepAttackEngine()

    def test_suggest_phase_with_phase_not_in_order(self, engine):
        # RESOURCE_DEVELOPMENT and DEFENSE_EVASION are not in the phase_order list
        # inside suggest_next_phase, so they should raise ValueError
        with pytest.raises(ValueError):
            engine.suggest_next_phase(AttackPhase.RESOURCE_DEVELOPMENT, {})

    def test_suggest_phase_defense_evasion_not_in_order(self, engine):
        with pytest.raises(ValueError):
            engine.suggest_next_phase(AttackPhase.DEFENSE_EVASION, {})

    def test_suggest_phase_impact_not_in_order(self, engine):
        with pytest.raises(ValueError):
            engine.suggest_next_phase(AttackPhase.IMPACT, {})

    def test_generate_plan_missing_target_key(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": []})
        assert plan["target"] is None  # .get("target") returns None

    def test_log_step_preserves_order(self, engine):
        phases = [AttackPhase.RECONNAISSANCE, AttackPhase.INITIAL_ACCESS, AttackPhase.EXECUTION]
        for p in phases:
            engine.log_attack_step(p, p.value, True)
        for i, p in enumerate(phases):
            assert engine.attack_history[i]["phase"] == p.value

    def test_add_flag_empty_string(self, engine):
        engine.add_flag("", "source")
        assert "" in engine.flags

    def test_get_attack_summary_exactly_10_steps(self, engine):
        for i in range(10):
            engine.log_attack_step(AttackPhase.EXECUTION, f"s{i}", True)
        summary = engine.get_attack_summary()
        assert len(summary["history"]) == 10

    def test_get_attack_summary_less_than_10(self, engine):
        for i in range(3):
            engine.log_attack_step(AttackPhase.EXECUTION, f"s{i}", True)
        summary = engine.get_attack_summary()
        assert len(summary["history"]) == 3

    def test_privesc_difficulty_ordering(self):
        """Verify that difficulty_order in get_privesc_techniques is consistent."""
        difficulty_order = [
            ExploitDifficulty.TRIVIAL,
            ExploitDifficulty.EASY,
            ExploitDifficulty.MEDIUM,
            ExploitDifficulty.HARD,
            ExploitDifficulty.EXPERT,
        ]
        for i in range(len(difficulty_order)):
            for j in range(i, len(difficulty_order)):
                assert difficulty_order.index(difficulty_order[i]) <= difficulty_order.index(difficulty_order[j])

    def test_lateral_all_have_required_creds_field(self):
        for t in LATERAL_MOVEMENT_TECHNIQUES:
            assert isinstance(t.required_credentials, str)
            assert len(t.required_credentials) > 0

    def test_persist_methods_unique(self):
        methods = [t.method for t in PERSISTENCE_TECHNIQUES]
        assert len(methods) == len(set(methods))

    def test_linux_privesc_techniques_unique_names(self):
        names = [t.name for t in LINUX_PRIVESC_TECHNIQUES]
        assert len(names) == len(set(names))

    def test_windows_privesc_techniques_unique_names(self):
        names = [t.name for t in WINDOWS_PRIVESC_TECHNIQUES]
        assert len(names) == len(set(names))

    def test_lateral_techniques_unique_names(self):
        names = [t.name for t in LATERAL_MOVEMENT_TECHNIQUES]
        assert len(names) == len(set(names))

    def test_persistence_techniques_unique_names(self):
        names = [t.name for t in PERSISTENCE_TECHNIQUES]
        assert len(names) == len(set(names))

    def test_generate_plan_internal_lateral_sorted_by_risk(self, engine):
        plan = engine.generate_attack_plan({
            "os": "linux", "services": [], "target": "x", "is_internal": True
        })
        lateral_phase = [p for p in plan["phases"] if p["phase"] == "lateral_move"][0]
        if len(lateral_phase["techniques"]) > 1:
            risks = [t["risk"] for t in lateral_phase["techniques"]]
            assert risks == sorted(risks)

    def test_privesc_commands_truncated_in_plan(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        privesc_phase = [p for p in plan["phases"] if p["phase"] == "priv_esc"][0]
        for t in privesc_phase["techniques"]:
            assert len(t["commands"]) <= 2

    def test_persistence_install_truncated_in_plan(self, engine):
        plan = engine.generate_attack_plan({"os": "linux", "services": [], "target": "x"})
        persist_phase = [p for p in plan["phases"] if p["phase"] == "persistence"][0]
        for t in persist_phase["techniques"]:
            assert len(t["commands"]) <= 1

    def test_suggest_next_phase_returns_tuple(self, engine):
        result = engine.suggest_next_phase(AttackPhase.RECONNAISSANCE, {})
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_suggest_next_phase_second_element_is_list(self, engine):
        _, reasons = engine.suggest_next_phase(AttackPhase.RECONNAISSANCE, {})
        assert isinstance(reasons, list)
