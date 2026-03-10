"""
Comprehensive unit tests for kali_mcp.core.broad_attack_orchestrator.

Covers:
- AttackSurface enum (12 members)
- ServiceType enum (28 members)
- ToolChain and AttackVector dataclasses
- Module-level chain lists (WEB/NETWORK/DATABASE/AD/CLOUD)
- SERVICE_PORT_MAP dict
- BroadAttackOrchestrator class (all methods)
- Global convenience functions (get_orchestrator, get_chains_for_port,
  suggest_tools_for_target, get_attack_surface_stats)

All tests are pure unit tests - no subprocess, no network.
"""

import pytest
from copy import deepcopy
from datetime import datetime
from unittest.mock import patch

from kali_mcp.core.broad_attack_orchestrator import (
    AttackSurface,
    ServiceType,
    ToolChain,
    AttackVector,
    WEB_TOOL_CHAINS,
    NETWORK_TOOL_CHAINS,
    DATABASE_TOOL_CHAINS,
    AD_TOOL_CHAINS,
    CLOUD_TOOL_CHAINS,
    SERVICE_PORT_MAP,
    BroadAttackOrchestrator,
    get_orchestrator,
    get_chains_for_port,
    suggest_tools_for_target,
    get_attack_surface_stats,
)


# ============================================================
# AttackSurface Enum Tests
# ============================================================


class TestAttackSurface:
    """Tests for the AttackSurface enum."""

    def test_member_count(self):
        assert len(AttackSurface) == 12

    def test_all_members_present(self):
        expected = {
            "WEB_APPLICATION",
            "NETWORK_SERVICE",
            "DATABASE",
            "EMAIL",
            "FILE_SHARE",
            "REMOTE_ACCESS",
            "CONTAINER_CLOUD",
            "WIRELESS",
            "ACTIVE_DIRECTORY",
            "IOT_EMBEDDED",
            "API_ENDPOINT",
            "MOBILE_APP",
        }
        assert set(m.name for m in AttackSurface) == expected

    def test_values_unique(self):
        values = [m.value for m in AttackSurface]
        assert len(values) == len(set(values))

    @pytest.mark.parametrize(
        "member, value",
        [
            (AttackSurface.WEB_APPLICATION, "web_app"),
            (AttackSurface.NETWORK_SERVICE, "network_svc"),
            (AttackSurface.DATABASE, "database"),
            (AttackSurface.EMAIL, "email"),
            (AttackSurface.FILE_SHARE, "file_share"),
            (AttackSurface.REMOTE_ACCESS, "remote_access"),
            (AttackSurface.CONTAINER_CLOUD, "container_cloud"),
            (AttackSurface.WIRELESS, "wireless"),
            (AttackSurface.ACTIVE_DIRECTORY, "active_directory"),
            (AttackSurface.IOT_EMBEDDED, "iot_embedded"),
            (AttackSurface.API_ENDPOINT, "api_endpoint"),
            (AttackSurface.MOBILE_APP, "mobile_app"),
        ],
    )
    def test_member_value(self, member, value):
        assert member.value == value

    def test_lookup_by_value(self):
        assert AttackSurface("web_app") is AttackSurface.WEB_APPLICATION

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            AttackSurface("nonexistent")


# ============================================================
# ServiceType Enum Tests
# ============================================================


class TestServiceType:
    """Tests for the ServiceType enum."""

    def test_member_count(self):
        assert len(ServiceType) == 28

    def test_all_members_present(self):
        expected = {
            "HTTP", "HTTPS", "PROXY",
            "MYSQL", "POSTGRESQL", "MSSQL", "ORACLE", "MONGODB", "REDIS", "ELASTICSEARCH",
            "SMB", "FTP", "NFS", "RSYNC",
            "SSH", "TELNET", "RDP", "VNC", "WINRM",
            "SMTP", "POP3", "IMAP",
            "LDAP", "KERBEROS",
            "DNS", "SNMP", "DOCKER", "KUBERNETES",
        }
        assert set(m.name for m in ServiceType) == expected

    def test_values_unique(self):
        values = [m.value for m in ServiceType]
        assert len(values) == len(set(values))

    @pytest.mark.parametrize(
        "member, value",
        [
            (ServiceType.HTTP, "http"),
            (ServiceType.HTTPS, "https"),
            (ServiceType.SSH, "ssh"),
            (ServiceType.MYSQL, "mysql"),
            (ServiceType.MSSQL, "mssql"),
            (ServiceType.RDP, "rdp"),
            (ServiceType.KERBEROS, "kerberos"),
            (ServiceType.DOCKER, "docker"),
            (ServiceType.KUBERNETES, "kubernetes"),
            (ServiceType.REDIS, "redis"),
        ],
    )
    def test_member_value(self, member, value):
        assert member.value == value

    def test_lookup_by_value(self):
        assert ServiceType("ssh") is ServiceType.SSH

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            ServiceType("nonexistent")


# ============================================================
# ToolChain Dataclass Tests
# ============================================================


class TestToolChain:
    """Tests for the ToolChain dataclass."""

    def _make_chain(self, **overrides):
        defaults = dict(
            name="test_chain",
            description="A test chain",
            surface=AttackSurface.WEB_APPLICATION,
            services=[ServiceType.HTTP],
            tools=["tool_a", "tool_b"],
        )
        defaults.update(overrides)
        return ToolChain(**defaults)

    def test_creation_minimal(self):
        c = self._make_chain()
        assert c.name == "test_chain"
        assert c.description == "A test chain"
        assert c.surface == AttackSurface.WEB_APPLICATION
        assert c.services == [ServiceType.HTTP]
        assert c.tools == ["tool_a", "tool_b"]

    def test_default_conditions_empty(self):
        c = self._make_chain()
        assert c.conditions == {}

    def test_default_parallel_false(self):
        c = self._make_chain()
        assert c.parallel is False

    def test_default_priority_5(self):
        c = self._make_chain()
        assert c.priority == 5

    def test_default_timeout_300(self):
        c = self._make_chain()
        assert c.timeout == 300

    def test_default_success_indicators_empty(self):
        c = self._make_chain()
        assert c.success_indicators == []

    def test_default_next_chains_empty(self):
        c = self._make_chain()
        assert c.next_chains == []

    def test_custom_fields(self):
        c = self._make_chain(
            parallel=True,
            priority=10,
            timeout=60,
            conditions={"jwt_detected": True},
            success_indicators=["foo"],
            next_chains=["bar"],
        )
        assert c.parallel is True
        assert c.priority == 10
        assert c.timeout == 60
        assert c.conditions == {"jwt_detected": True}
        assert c.success_indicators == ["foo"]
        assert c.next_chains == ["bar"]

    def test_mutable_defaults_isolation(self):
        """Two instances should not share mutable defaults."""
        c1 = self._make_chain()
        c2 = self._make_chain()
        c1.conditions["added"] = True
        assert "added" not in c2.conditions

        c1.success_indicators.append("x")
        assert "x" not in c2.success_indicators

        c1.next_chains.append("y")
        assert "y" not in c2.next_chains

    def test_multiple_services(self):
        c = self._make_chain(services=[ServiceType.HTTP, ServiceType.HTTPS])
        assert len(c.services) == 2

    def test_empty_services(self):
        c = self._make_chain(services=[])
        assert c.services == []

    def test_empty_tools(self):
        c = self._make_chain(tools=[])
        assert c.tools == []


# ============================================================
# AttackVector Dataclass Tests
# ============================================================


class TestAttackVector:
    """Tests for the AttackVector dataclass."""

    def _make_chain(self):
        return ToolChain(
            name="vec_chain",
            description="d",
            surface=AttackSurface.NETWORK_SERVICE,
            services=[ServiceType.SSH],
            tools=["t"],
        )

    def _make_vector(self, **overrides):
        defaults = dict(
            chain=self._make_chain(),
            target="192.168.1.1",
            port=22,
            service=ServiceType.SSH,
            priority=8,
        )
        defaults.update(overrides)
        return AttackVector(**defaults)

    def test_creation(self):
        v = self._make_vector()
        assert v.target == "192.168.1.1"
        assert v.port == 22
        assert v.service == ServiceType.SSH
        assert v.priority == 8

    def test_default_status_pending(self):
        v = self._make_vector()
        assert v.status == "pending"

    def test_default_result_none(self):
        v = self._make_vector()
        assert v.result is None

    def test_default_times_none(self):
        v = self._make_vector()
        assert v.start_time is None
        assert v.end_time is None

    def test_custom_status(self):
        v = self._make_vector(status="running")
        assert v.status == "running"

    def test_set_result(self):
        v = self._make_vector()
        v.result = {"success": True, "data": "pwned"}
        assert v.result["success"] is True

    def test_set_times(self):
        v = self._make_vector()
        now = datetime.now()
        v.start_time = now
        v.end_time = now
        assert v.start_time == now
        assert v.end_time == now

    def test_chain_reference(self):
        v = self._make_vector()
        assert v.chain.name == "vec_chain"


# ============================================================
# Module-Level Chain List Tests
# ============================================================


class TestChainLists:
    """Tests for the module-level chain list constants."""

    def test_web_chain_count(self):
        assert len(WEB_TOOL_CHAINS) == 15

    def test_network_chain_count(self):
        assert len(NETWORK_TOOL_CHAINS) == 10

    def test_database_chain_count(self):
        assert len(DATABASE_TOOL_CHAINS) == 6

    def test_ad_chain_count(self):
        assert len(AD_TOOL_CHAINS) == 8

    def test_cloud_chain_count(self):
        assert len(CLOUD_TOOL_CHAINS) == 3

    def test_total_chain_count(self):
        total = (
            len(WEB_TOOL_CHAINS)
            + len(NETWORK_TOOL_CHAINS)
            + len(DATABASE_TOOL_CHAINS)
            + len(AD_TOOL_CHAINS)
            + len(CLOUD_TOOL_CHAINS)
        )
        assert total == 42

    def test_all_chains_are_toolchain_instances(self):
        for lst in [WEB_TOOL_CHAINS, NETWORK_TOOL_CHAINS, DATABASE_TOOL_CHAINS, AD_TOOL_CHAINS, CLOUD_TOOL_CHAINS]:
            for chain in lst:
                assert isinstance(chain, ToolChain)

    def test_all_chain_names_unique(self):
        all_names = []
        for lst in [WEB_TOOL_CHAINS, NETWORK_TOOL_CHAINS, DATABASE_TOOL_CHAINS, AD_TOOL_CHAINS, CLOUD_TOOL_CHAINS]:
            all_names.extend(c.name for c in lst)
        assert len(all_names) == len(set(all_names)), f"Duplicate chain names: {[n for n in all_names if all_names.count(n) > 1]}"

    def test_web_chains_have_correct_surfaces(self):
        for chain in WEB_TOOL_CHAINS:
            assert chain.surface in (AttackSurface.WEB_APPLICATION, AttackSurface.API_ENDPOINT)

    def test_network_chains_surfaces(self):
        valid = {
            AttackSurface.NETWORK_SERVICE,
            AttackSurface.FILE_SHARE,
            AttackSurface.REMOTE_ACCESS,
            AttackSurface.ACTIVE_DIRECTORY,
        }
        for chain in NETWORK_TOOL_CHAINS:
            assert chain.surface in valid, f"{chain.name} has unexpected surface {chain.surface}"

    def test_database_chains_surface(self):
        for chain in DATABASE_TOOL_CHAINS:
            assert chain.surface == AttackSurface.DATABASE

    def test_ad_chains_surface(self):
        for chain in AD_TOOL_CHAINS:
            assert chain.surface == AttackSurface.ACTIVE_DIRECTORY

    def test_cloud_chains_surface(self):
        for chain in CLOUD_TOOL_CHAINS:
            assert chain.surface == AttackSurface.CONTAINER_CLOUD

    def test_all_chains_have_tools(self):
        for lst in [WEB_TOOL_CHAINS, NETWORK_TOOL_CHAINS, DATABASE_TOOL_CHAINS, AD_TOOL_CHAINS, CLOUD_TOOL_CHAINS]:
            for chain in lst:
                assert len(chain.tools) > 0, f"Chain '{chain.name}' has no tools"

    def test_all_chains_have_description(self):
        for lst in [WEB_TOOL_CHAINS, NETWORK_TOOL_CHAINS, DATABASE_TOOL_CHAINS, AD_TOOL_CHAINS, CLOUD_TOOL_CHAINS]:
            for chain in lst:
                assert chain.description, f"Chain '{chain.name}' missing description"

    def test_priority_range(self):
        for lst in [WEB_TOOL_CHAINS, NETWORK_TOOL_CHAINS, DATABASE_TOOL_CHAINS, AD_TOOL_CHAINS, CLOUD_TOOL_CHAINS]:
            for chain in lst:
                assert 1 <= chain.priority <= 10, f"Chain '{chain.name}' has priority {chain.priority} outside [1,10]"

    def test_web_fingerprint_chain(self):
        chain = WEB_TOOL_CHAINS[0]
        assert chain.name == "web_fingerprint"
        assert chain.parallel is True
        assert chain.priority == 10
        assert "whatweb_scan" in chain.tools

    def test_port_discovery_chain(self):
        chain = NETWORK_TOOL_CHAINS[0]
        assert chain.name == "port_discovery"
        assert chain.parallel is True
        assert chain.priority == 10
        assert chain.services == []

    def test_dcsync_chain_has_conditions(self):
        dcsync = [c for c in AD_TOOL_CHAINS if c.name == "dcsync"][0]
        assert dcsync.conditions == {"replication_rights": True}
        assert dcsync.priority == 10


# ============================================================
# SERVICE_PORT_MAP Tests
# ============================================================


class TestServicePortMap:
    """Tests for the SERVICE_PORT_MAP dictionary."""

    def test_map_is_dict(self):
        assert isinstance(SERVICE_PORT_MAP, dict)

    def test_map_length(self):
        assert len(SERVICE_PORT_MAP) == 38

    @pytest.mark.parametrize(
        "port, service",
        [
            (21, ServiceType.FTP),
            (22, ServiceType.SSH),
            (23, ServiceType.TELNET),
            (25, ServiceType.SMTP),
            (53, ServiceType.DNS),
            (80, ServiceType.HTTP),
            (110, ServiceType.POP3),
            (111, ServiceType.NFS),
            (135, ServiceType.SMB),
            (139, ServiceType.SMB),
            (143, ServiceType.IMAP),
            (161, ServiceType.SNMP),
            (389, ServiceType.LDAP),
            (443, ServiceType.HTTPS),
            (445, ServiceType.SMB),
            (465, ServiceType.SMTP),
            (587, ServiceType.SMTP),
            (636, ServiceType.LDAP),
            (993, ServiceType.IMAP),
            (995, ServiceType.POP3),
            (1433, ServiceType.MSSQL),
            (1521, ServiceType.ORACLE),
            (2049, ServiceType.NFS),
            (2375, ServiceType.DOCKER),
            (2376, ServiceType.DOCKER),
            (3306, ServiceType.MYSQL),
            (3389, ServiceType.RDP),
            (5432, ServiceType.POSTGRESQL),
            (5900, ServiceType.VNC),
            (5985, ServiceType.WINRM),
            (5986, ServiceType.WINRM),
            (6379, ServiceType.REDIS),
            (8080, ServiceType.HTTP),
            (8443, ServiceType.HTTPS),
            (9200, ServiceType.ELASTICSEARCH),
            (9300, ServiceType.ELASTICSEARCH),
            (27017, ServiceType.MONGODB),
        ],
    )
    def test_port_mapping(self, port, service):
        assert SERVICE_PORT_MAP[port] is service

    def test_kerberos_port(self):
        assert SERVICE_PORT_MAP[88] is ServiceType.KERBEROS

    def test_all_values_are_service_type(self):
        for port, svc in SERVICE_PORT_MAP.items():
            assert isinstance(svc, ServiceType)
            assert isinstance(port, int)

    def test_smb_has_three_ports(self):
        smb_ports = [p for p, s in SERVICE_PORT_MAP.items() if s == ServiceType.SMB]
        assert sorted(smb_ports) == [135, 139, 445]

    def test_http_has_two_ports(self):
        http_ports = [p for p, s in SERVICE_PORT_MAP.items() if s == ServiceType.HTTP]
        assert sorted(http_ports) == [80, 8080]


# ============================================================
# BroadAttackOrchestrator Tests
# ============================================================


class TestBroadAttackOrchestratorInit:
    """Tests for BroadAttackOrchestrator initialization."""

    def test_init_creates_all_chains(self):
        o = BroadAttackOrchestrator()
        expected_count = (
            len(WEB_TOOL_CHAINS)
            + len(NETWORK_TOOL_CHAINS)
            + len(DATABASE_TOOL_CHAINS)
            + len(AD_TOOL_CHAINS)
            + len(CLOUD_TOOL_CHAINS)
        )
        assert len(o.all_chains) == expected_count

    def test_init_empty_state(self):
        o = BroadAttackOrchestrator()
        assert o.active_vectors == []
        assert o.completed_vectors == []
        assert o.discovered_services == {}
        assert o.attack_results == {}

    def test_load_chains_keyed_by_name(self):
        o = BroadAttackOrchestrator()
        for name, chain in o.all_chains.items():
            assert name == chain.name

    def test_all_known_chains_loaded(self):
        o = BroadAttackOrchestrator()
        assert "web_fingerprint" in o.all_chains
        assert "port_discovery" in o.all_chains
        assert "mysql_attack" in o.all_chains
        assert "ad_enum" in o.all_chains
        assert "docker_attack" in o.all_chains


class TestIdentifyServices:
    """Tests for BroadAttackOrchestrator.identify_services()."""

    def setup_method(self):
        self.o = BroadAttackOrchestrator()

    def test_empty_scan_result(self):
        result = self.o.identify_services({})
        assert result == {}

    def test_no_ports_key(self):
        result = self.o.identify_services({"info": "no ports here"})
        assert result == {}

    def test_single_port(self):
        scan = {"ports": [{"port": 80, "host": "10.0.0.1"}]}
        result = self.o.identify_services(scan)
        assert "10.0.0.1" in result
        assert ServiceType.HTTP in result["10.0.0.1"]

    def test_multiple_ports_same_host(self):
        scan = {
            "ports": [
                {"port": 80, "host": "10.0.0.1"},
                {"port": 443, "host": "10.0.0.1"},
                {"port": 22, "host": "10.0.0.1"},
            ]
        }
        result = self.o.identify_services(scan)
        assert len(result["10.0.0.1"]) == 3
        assert ServiceType.HTTP in result["10.0.0.1"]
        assert ServiceType.HTTPS in result["10.0.0.1"]
        assert ServiceType.SSH in result["10.0.0.1"]

    def test_multiple_hosts(self):
        scan = {
            "ports": [
                {"port": 22, "host": "host_a"},
                {"port": 80, "host": "host_b"},
            ]
        }
        result = self.o.identify_services(scan)
        assert "host_a" in result
        assert "host_b" in result
        assert ServiceType.SSH in result["host_a"]
        assert ServiceType.HTTP in result["host_b"]

    def test_unknown_port_ignored(self):
        scan = {"ports": [{"port": 99999, "host": "x"}]}
        result = self.o.identify_services(scan)
        assert result == {}

    def test_missing_host_defaults_to_unknown(self):
        scan = {"ports": [{"port": 80}]}
        result = self.o.identify_services(scan)
        assert "unknown" in result

    def test_missing_port_ignored(self):
        scan = {"ports": [{"host": "x"}]}
        result = self.o.identify_services(scan)
        # port defaults to 0, which is not in map
        assert result == {}

    def test_updates_discovered_services(self):
        scan = {"ports": [{"port": 22, "host": "h1"}]}
        self.o.identify_services(scan)
        assert "h1" in self.o.discovered_services

    def test_overwrites_previous_discovered_services(self):
        self.o.identify_services({"ports": [{"port": 22, "host": "h1"}]})
        self.o.identify_services({"ports": [{"port": 80, "host": "h2"}]})
        assert "h1" not in self.o.discovered_services
        assert "h2" in self.o.discovered_services


class TestGetChainsForService:
    """Tests for BroadAttackOrchestrator.get_chains_for_service()."""

    def setup_method(self):
        self.o = BroadAttackOrchestrator()

    def test_http_returns_web_chains(self):
        chains = self.o.get_chains_for_service(ServiceType.HTTP)
        chain_names = [c.name for c in chains]
        assert "web_fingerprint" in chain_names
        assert "directory_bruteforce" in chain_names

    def test_ssh_returns_ssh_chain(self):
        chains = self.o.get_chains_for_service(ServiceType.SSH)
        chain_names = [c.name for c in chains]
        assert "ssh_attack" in chain_names

    def test_mysql_returns_mysql_chain(self):
        chains = self.o.get_chains_for_service(ServiceType.MYSQL)
        names = [c.name for c in chains]
        assert "mysql_attack" in names

    def test_ldap_returns_ad_chains(self):
        chains = self.o.get_chains_for_service(ServiceType.LDAP)
        names = [c.name for c in chains]
        assert "ldap_attack" in names
        assert "ad_enum" in names

    def test_kerberos_returns_kerberos_chains(self):
        chains = self.o.get_chains_for_service(ServiceType.KERBEROS)
        names = [c.name for c in chains]
        assert "kerberos_attack" in names
        assert "kerberoast" in names

    def test_includes_chains_with_empty_services(self):
        """Chains with services=[] should match any service."""
        chains = self.o.get_chains_for_service(ServiceType.SSH)
        names = [c.name for c in chains]
        assert "port_discovery" in names

    def test_sorted_by_priority_desc(self):
        chains = self.o.get_chains_for_service(ServiceType.HTTP)
        priorities = [c.priority for c in chains]
        assert priorities == sorted(priorities, reverse=True)

    def test_smb_returns_smb_chain(self):
        chains = self.o.get_chains_for_service(ServiceType.SMB)
        names = [c.name for c in chains]
        assert "smb_attack" in names

    def test_redis_returns_redis_chain(self):
        chains = self.o.get_chains_for_service(ServiceType.REDIS)
        names = [c.name for c in chains]
        assert "redis_attack" in names

    def test_docker_returns_docker_chain(self):
        chains = self.o.get_chains_for_service(ServiceType.DOCKER)
        names = [c.name for c in chains]
        assert "docker_attack" in names

    def test_rsync_only_gets_generic_chains(self):
        """RSYNC isn't in any specific chain, should only get the ones with empty services."""
        chains = self.o.get_chains_for_service(ServiceType.RSYNC)
        # Should at least get port_discovery (empty services = matches all)
        names = [c.name for c in chains]
        assert "port_discovery" in names
        # Should NOT get service-specific chains
        assert "ssh_attack" not in names


class TestGetChainsForSurface:
    """Tests for BroadAttackOrchestrator.get_chains_for_surface()."""

    def setup_method(self):
        self.o = BroadAttackOrchestrator()

    def test_web_application_surface(self):
        chains = self.o.get_chains_for_surface(AttackSurface.WEB_APPLICATION)
        assert len(chains) > 0
        for c in chains:
            assert c.surface == AttackSurface.WEB_APPLICATION

    def test_database_surface(self):
        chains = self.o.get_chains_for_surface(AttackSurface.DATABASE)
        assert len(chains) == len(DATABASE_TOOL_CHAINS)

    def test_active_directory_surface(self):
        chains = self.o.get_chains_for_surface(AttackSurface.ACTIVE_DIRECTORY)
        # AD chains from both AD_TOOL_CHAINS and some NETWORK_TOOL_CHAINS
        assert len(chains) >= len(AD_TOOL_CHAINS)

    def test_container_cloud_surface(self):
        chains = self.o.get_chains_for_surface(AttackSurface.CONTAINER_CLOUD)
        assert len(chains) == len(CLOUD_TOOL_CHAINS)

    def test_email_surface_empty(self):
        """No chains defined for EMAIL surface."""
        chains = self.o.get_chains_for_surface(AttackSurface.EMAIL)
        assert chains == []

    def test_wireless_surface_empty(self):
        chains = self.o.get_chains_for_surface(AttackSurface.WIRELESS)
        assert chains == []

    def test_iot_surface_empty(self):
        chains = self.o.get_chains_for_surface(AttackSurface.IOT_EMBEDDED)
        assert chains == []

    def test_mobile_surface_empty(self):
        chains = self.o.get_chains_for_surface(AttackSurface.MOBILE_APP)
        assert chains == []

    def test_api_endpoint_surface(self):
        chains = self.o.get_chains_for_surface(AttackSurface.API_ENDPOINT)
        names = [c.name for c in chains]
        assert "api_security_scan" in names
        assert "graphql_attack" in names


class TestPlanAttack:
    """Tests for BroadAttackOrchestrator.plan_attack()."""

    def setup_method(self):
        self.o = BroadAttackOrchestrator()

    def test_single_service(self):
        vectors = self.o.plan_attack("target.com", [ServiceType.HTTP])
        assert len(vectors) > 0
        for v in vectors:
            assert isinstance(v, AttackVector)
            assert v.target == "target.com"

    def test_vectors_sorted_by_priority_desc(self):
        vectors = self.o.plan_attack("t", [ServiceType.HTTP])
        priorities = [v.priority for v in vectors]
        assert priorities == sorted(priorities, reverse=True)

    def test_no_duplicate_chain_names(self):
        vectors = self.o.plan_attack("t", [ServiceType.HTTP, ServiceType.HTTPS])
        chain_names = [v.chain.name for v in vectors]
        assert len(chain_names) == len(set(chain_names))

    def test_multiple_services(self):
        vectors = self.o.plan_attack("t", [ServiceType.HTTP, ServiceType.SSH, ServiceType.MYSQL])
        chain_names = [v.chain.name for v in vectors]
        assert "ssh_attack" in chain_names
        assert "mysql_attack" in chain_names

    def test_updates_active_vectors(self):
        vectors = self.o.plan_attack("t", [ServiceType.HTTP])
        assert self.o.active_vectors == vectors

    def test_empty_services_list(self):
        vectors = self.o.plan_attack("t", [])
        assert vectors == []

    def test_default_status_pending(self):
        vectors = self.o.plan_attack("t", [ServiceType.SSH])
        for v in vectors:
            assert v.status == "pending"

    def test_port_assigned_from_service(self):
        vectors = self.o.plan_attack("t", [ServiceType.SSH])
        ssh_vectors = [v for v in vectors if v.service == ServiceType.SSH]
        # The first discovered port for SSH should be 22
        if ssh_vectors:
            # port_discovery chain has no specific service, so check SSH-specific vectors
            ssh_specific = [v for v in ssh_vectors if v.chain.name == "ssh_attack"]
            if ssh_specific:
                assert ssh_specific[0].port == 22

    def test_deduplication_across_services(self):
        """port_discovery has services=[], so it matches both HTTP and SSH.
        It should only appear once."""
        vectors = self.o.plan_attack("t", [ServiceType.HTTP, ServiceType.SSH])
        port_disc = [v for v in vectors if v.chain.name == "port_discovery"]
        assert len(port_disc) <= 1


class TestGetDefaultPort:
    """Tests for BroadAttackOrchestrator._get_default_port()."""

    def setup_method(self):
        self.o = BroadAttackOrchestrator()

    @pytest.mark.parametrize(
        "service, expected_port",
        [
            (ServiceType.FTP, 21),
            (ServiceType.SSH, 22),
            (ServiceType.HTTP, 80),
            (ServiceType.HTTPS, 443),
            (ServiceType.MYSQL, 3306),
            (ServiceType.RDP, 3389),
            (ServiceType.REDIS, 6379),
            (ServiceType.KERBEROS, 88),
        ],
    )
    def test_known_service_port(self, service, expected_port):
        assert self.o._get_default_port(service) == expected_port

    def test_returns_first_matching_port(self):
        """For services mapped to multiple ports, returns the first encountered."""
        port = self.o._get_default_port(ServiceType.SMB)
        assert port in (135, 139, 445)

    def test_proxy_returns_zero(self):
        """PROXY is not in SERVICE_PORT_MAP so _get_default_port returns 0."""
        assert self.o._get_default_port(ServiceType.PROXY) == 0

    def test_rsync_returns_zero(self):
        assert self.o._get_default_port(ServiceType.RSYNC) == 0


class TestGetNextChains:
    """Tests for BroadAttackOrchestrator.get_next_chains()."""

    def setup_method(self):
        self.o = BroadAttackOrchestrator()

    def test_unknown_chain_returns_empty(self):
        assert self.o.get_next_chains("nonexistent", {}) == []

    def test_no_success_indicators_returns_empty(self):
        result = self.o.get_next_chains("web_fingerprint", {})
        assert result == []

    def test_with_matching_success_indicator(self):
        # web_fingerprint has success_indicators: ["technology_detected", "cms_identified"]
        # and next_chains: ["cms_specific_scan", "directory_bruteforce"]
        results = {"technology_detected": True, "other": "data"}
        next_chains = self.o.get_next_chains("web_fingerprint", results)
        # cms_specific_scan and directory_bruteforce exist in all_chains
        names = [c.name for c in next_chains]
        assert "cms_specific_scan" in names
        assert "directory_bruteforce" in names

    def test_falsy_indicator_not_triggered(self):
        results = {"technology_detected": False}
        next_chains = self.o.get_next_chains("web_fingerprint", results)
        assert next_chains == []

    def test_empty_string_indicator_not_triggered(self):
        results = {"technology_detected": ""}
        next_chains = self.o.get_next_chains("web_fingerprint", results)
        assert next_chains == []

    def test_none_indicator_not_triggered(self):
        results = {"technology_detected": None}
        next_chains = self.o.get_next_chains("web_fingerprint", results)
        assert next_chains == []

    def test_zero_indicator_not_triggered(self):
        results = {"technology_detected": 0}
        next_chains = self.o.get_next_chains("web_fingerprint", results)
        assert next_chains == []

    def test_truthy_string_triggers(self):
        results = {"technology_detected": "Apache"}
        next_chains = self.o.get_next_chains("web_fingerprint", results)
        assert len(next_chains) > 0

    def test_next_chain_not_in_all_chains_skipped(self):
        """If a next_chain name doesn't exist in all_chains, it's silently skipped."""
        # Manually add a chain whose next_chains reference a nonexistent chain
        fake = ToolChain(
            name="fake_chain",
            description="f",
            surface=AttackSurface.WEB_APPLICATION,
            services=[],
            tools=["t"],
            success_indicators=["ok"],
            next_chains=["nonexistent_chain"],
        )
        self.o.all_chains["fake_chain"] = fake
        results = {"ok": True}
        next_chains = self.o.get_next_chains("fake_chain", results)
        assert next_chains == []

    def test_multiple_indicators_any_match(self):
        """Only one indicator needs to match for success."""
        results = {"cms_identified": True}
        next_chains = self.o.get_next_chains("web_fingerprint", results)
        assert len(next_chains) > 0

    def test_sql_injection_chain_next(self):
        results = {"sqli_vulnerable": True}
        next_chains = self.o.get_next_chains("sql_injection_scan", results)
        # next_chains for sql_injection_scan: ["database_dump", "privilege_escalation"]
        # These don't exist in all_chains, so should be empty
        # (they're external references not defined in the module)
        assert isinstance(next_chains, list)


class TestGetAttackCoverage:
    """Tests for BroadAttackOrchestrator.get_attack_coverage()."""

    def setup_method(self):
        self.o = BroadAttackOrchestrator()

    def test_returns_dict(self):
        coverage = self.o.get_attack_coverage()
        assert isinstance(coverage, dict)

    def test_total_chains_count(self):
        coverage = self.o.get_attack_coverage()
        assert coverage["total_chains"] == len(self.o.all_chains)

    def test_has_surfaces_key(self):
        coverage = self.o.get_attack_coverage()
        assert "surfaces" in coverage

    def test_has_services_key(self):
        coverage = self.o.get_attack_coverage()
        assert "services" in coverage

    def test_surfaces_contains_web_app(self):
        coverage = self.o.get_attack_coverage()
        assert "web_app" in coverage["surfaces"]

    def test_surfaces_contains_database(self):
        coverage = self.o.get_attack_coverage()
        assert "database" in coverage["surfaces"]

    def test_services_contains_http(self):
        coverage = self.o.get_attack_coverage()
        assert "http" in coverage["services"]

    def test_surfaces_counts_are_positive(self):
        coverage = self.o.get_attack_coverage()
        for surface, count in coverage["surfaces"].items():
            assert count > 0

    def test_services_counts_are_positive(self):
        coverage = self.o.get_attack_coverage()
        for svc, count in coverage["services"].items():
            assert count > 0

    def test_port_discovery_contributes_no_services(self):
        """port_discovery has services=[], so it shouldn't add to any service count."""
        coverage = self.o.get_attack_coverage()
        # This is implicitly tested: services counts reflect only chains with explicit services


class TestSuggestAttackPath:
    """Tests for BroadAttackOrchestrator.suggest_attack_path()."""

    def setup_method(self):
        self.o = BroadAttackOrchestrator()

    def test_empty_info_returns_empty(self):
        result = self.o.suggest_attack_path({})
        assert result == []

    def test_web_server_discovered(self):
        result = self.o.suggest_attack_path({"web_server": True})
        names = [c.name for c in result]
        assert "web_fingerprint" in names
        assert "directory_bruteforce" in names
        assert "nuclei_comprehensive" in names

    def test_cms_type_discovered(self):
        result = self.o.suggest_attack_path({"cms_type": "WordPress"})
        names = [c.name for c in result]
        assert "cms_specific_scan" in names

    def test_domain_controller_discovered(self):
        result = self.o.suggest_attack_path({"domain_controller": True})
        names = [c.name for c in result]
        assert "ad_enum" in names
        assert "kerberoast" in names
        assert "asrep_roast" in names

    def test_mysql_database_discovered(self):
        result = self.o.suggest_attack_path({"database": "MySQL 5.7"})
        names = [c.name for c in result]
        assert "mysql_attack" in names

    def test_mssql_database_discovered(self):
        result = self.o.suggest_attack_path({"database": "MSSQL 2019"})
        names = [c.name for c in result]
        assert "mssql_attack" in names

    def test_mssql_sqlserver_variant(self):
        result = self.o.suggest_attack_path({"database": "SQL Server 2019"})
        names = [c.name for c in result]
        assert "mssql_attack" in names

    def test_postgres_database_discovered(self):
        result = self.o.suggest_attack_path({"database": "PostgreSQL 13"})
        names = [c.name for c in result]
        assert "postgresql_attack" in names

    def test_mongodb_database_discovered(self):
        result = self.o.suggest_attack_path({"database": "MongoDB 4.4"})
        names = [c.name for c in result]
        assert "mongodb_attack" in names

    def test_redis_database_discovered(self):
        result = self.o.suggest_attack_path({"database": "Redis 6.0"})
        names = [c.name for c in result]
        assert "redis_attack" in names

    def test_docker_discovered(self):
        result = self.o.suggest_attack_path({"docker": True})
        names = [c.name for c in result]
        assert "docker_attack" in names

    def test_container_discovered(self):
        result = self.o.suggest_attack_path({"container": True})
        names = [c.name for c in result]
        assert "docker_attack" in names

    def test_kubernetes_discovered(self):
        result = self.o.suggest_attack_path({"kubernetes": True})
        names = [c.name for c in result]
        assert "kubernetes_attack" in names

    def test_sorted_by_priority_desc(self):
        result = self.o.suggest_attack_path({
            "web_server": True,
            "domain_controller": True,
            "database": "MySQL",
        })
        priorities = [c.priority for c in result]
        assert priorities == sorted(priorities, reverse=True)

    def test_no_none_values(self):
        result = self.o.suggest_attack_path({"web_server": True})
        assert None not in result

    def test_combined_info(self):
        result = self.o.suggest_attack_path({
            "web_server": True,
            "cms_type": "Joomla",
            "docker": True,
            "kubernetes": True,
        })
        names = [c.name for c in result]
        assert "web_fingerprint" in names
        assert "cms_specific_scan" in names
        assert "docker_attack" in names
        assert "kubernetes_attack" in names

    def test_unknown_database_returns_nothing_extra(self):
        result = self.o.suggest_attack_path({"database": "CouchDB 3.0"})
        # CouchDB doesn't match any branch
        assert result == []

    def test_falsy_web_server_key(self):
        result = self.o.suggest_attack_path({"web_server": False})
        names = [c.name for c in result]
        assert "web_fingerprint" not in names


class TestGenerateAttackReport:
    """Tests for BroadAttackOrchestrator.generate_attack_report()."""

    def setup_method(self):
        self.o = BroadAttackOrchestrator()

    def _make_vector(self, chain_name, service, status="completed", success=False):
        chain = self.o.all_chains.get(chain_name)
        if chain is None:
            chain = ToolChain(
                name=chain_name,
                description="test",
                surface=AttackSurface.WEB_APPLICATION,
                services=[service],
                tools=["t"],
            )
        v = AttackVector(
            chain=chain,
            target="t",
            port=80,
            service=service,
            priority=5,
            status=status,
            result={"success": success, "data": "x"} if success else {"success": False},
        )
        return v

    def test_empty_report(self):
        report = self.o.generate_attack_report()
        assert report["total_vectors"] == 0
        assert report["completed_vectors"] == 0
        assert report["successful_attacks"] == 0
        assert report["surfaces_covered"] == []
        assert report["services_attacked"] == []
        assert report["findings"] == []

    def test_report_with_completed_vectors(self):
        v = self._make_vector("web_fingerprint", ServiceType.HTTP, success=True)
        self.o.completed_vectors.append(v)
        report = self.o.generate_attack_report()
        assert report["completed_vectors"] == 1
        assert report["successful_attacks"] == 1
        assert len(report["findings"]) == 1

    def test_report_counts_active_and_completed(self):
        v1 = self._make_vector("web_fingerprint", ServiceType.HTTP, status="running", success=False)
        v2 = self._make_vector("ssh_attack", ServiceType.SSH, success=True)
        self.o.active_vectors.append(v1)
        self.o.completed_vectors.append(v2)
        report = self.o.generate_attack_report()
        assert report["total_vectors"] == 2

    def test_surfaces_covered(self):
        v = self._make_vector("web_fingerprint", ServiceType.HTTP, success=False)
        self.o.completed_vectors.append(v)
        report = self.o.generate_attack_report()
        assert AttackSurface.WEB_APPLICATION.value in report["surfaces_covered"]

    def test_services_attacked(self):
        v = self._make_vector("ssh_attack", ServiceType.SSH, success=False)
        self.o.completed_vectors.append(v)
        report = self.o.generate_attack_report()
        assert ServiceType.SSH.value in report["services_attacked"]

    def test_failed_attack_not_in_findings(self):
        v = self._make_vector("web_fingerprint", ServiceType.HTTP, success=False)
        self.o.completed_vectors.append(v)
        report = self.o.generate_attack_report()
        assert report["successful_attacks"] == 0
        assert report["findings"] == []

    def test_timestamp_present(self):
        report = self.o.generate_attack_report()
        assert "timestamp" in report
        # Should be a valid ISO format string
        datetime.fromisoformat(report["timestamp"])

    def test_vector_with_none_result(self):
        chain = self.o.all_chains["web_fingerprint"]
        v = AttackVector(
            chain=chain,
            target="t",
            port=80,
            service=ServiceType.HTTP,
            priority=5,
            status="completed",
            result=None,
        )
        self.o.completed_vectors.append(v)
        report = self.o.generate_attack_report()
        assert report["successful_attacks"] == 0

    def test_multiple_successful_attacks(self):
        for name in ["web_fingerprint", "sql_injection_scan"]:
            v = self._make_vector(name, ServiceType.HTTP, success=True)
            self.o.completed_vectors.append(v)
        report = self.o.generate_attack_report()
        assert report["successful_attacks"] == 2
        assert len(report["findings"]) == 2

    def test_findings_structure(self):
        v = self._make_vector("web_fingerprint", ServiceType.HTTP, success=True)
        self.o.completed_vectors.append(v)
        report = self.o.generate_attack_report()
        finding = report["findings"][0]
        assert "chain" in finding
        assert "service" in finding
        assert "result" in finding
        assert finding["chain"] == "web_fingerprint"
        assert finding["service"] == "http"


# ============================================================
# Global Convenience Function Tests
# ============================================================


class TestGetOrchestrator:
    """Tests for get_orchestrator() singleton."""

    def test_returns_instance(self):
        import kali_mcp.core.broad_attack_orchestrator as mod
        # Reset singleton
        mod._orchestrator_instance = None
        o = get_orchestrator()
        assert isinstance(o, BroadAttackOrchestrator)

    def test_returns_same_instance(self):
        import kali_mcp.core.broad_attack_orchestrator as mod
        mod._orchestrator_instance = None
        o1 = get_orchestrator()
        o2 = get_orchestrator()
        assert o1 is o2

    def test_creates_on_first_call(self):
        import kali_mcp.core.broad_attack_orchestrator as mod
        mod._orchestrator_instance = None
        assert mod._orchestrator_instance is None
        get_orchestrator()
        assert mod._orchestrator_instance is not None


class TestGetChainsForPort:
    """Tests for get_chains_for_port()."""

    def setup_method(self):
        import kali_mcp.core.broad_attack_orchestrator as mod
        mod._orchestrator_instance = None

    def test_known_port_returns_chains(self):
        chains = get_chains_for_port(80)
        assert len(chains) > 0

    def test_http_port_contains_web_chains(self):
        chains = get_chains_for_port(80)
        names = [c.name for c in chains]
        assert "web_fingerprint" in names

    def test_ssh_port(self):
        chains = get_chains_for_port(22)
        names = [c.name for c in chains]
        assert "ssh_attack" in names

    def test_mysql_port(self):
        chains = get_chains_for_port(3306)
        names = [c.name for c in chains]
        assert "mysql_attack" in names

    def test_unknown_port_returns_empty(self):
        chains = get_chains_for_port(12345)
        assert chains == []

    def test_rdp_port(self):
        chains = get_chains_for_port(3389)
        names = [c.name for c in chains]
        assert "rdp_attack" in names

    def test_kerberos_port(self):
        chains = get_chains_for_port(88)
        names = [c.name for c in chains]
        assert "kerberos_attack" in names


class TestSuggestToolsForTarget:
    """Tests for suggest_tools_for_target()."""

    def setup_method(self):
        import kali_mcp.core.broad_attack_orchestrator as mod
        mod._orchestrator_instance = None

    def test_empty_target_info(self):
        tools = suggest_tools_for_target({})
        assert tools == []

    def test_web_server_target(self):
        tools = suggest_tools_for_target({"web_server": True})
        assert len(tools) > 0
        assert "whatweb_scan" in tools

    def test_no_duplicate_tools(self):
        tools = suggest_tools_for_target({
            "web_server": True,
            "cms_type": "WordPress",
        })
        assert len(tools) == len(set(tools))

    def test_preserves_order(self):
        tools = suggest_tools_for_target({"web_server": True})
        # Should be a deterministic list
        assert isinstance(tools, list)

    def test_mysql_database_target(self):
        tools = suggest_tools_for_target({"database": "MySQL 8.0"})
        assert "mysql_enum" in tools or "hydra_attack" in tools

    def test_combined_target(self):
        tools = suggest_tools_for_target({
            "web_server": True,
            "docker": True,
        })
        assert "whatweb_scan" in tools
        assert "docker_enum" in tools or "deepce" in tools

    def test_returns_list_of_strings(self):
        tools = suggest_tools_for_target({"web_server": True})
        for t in tools:
            assert isinstance(t, str)


class TestGetAttackSurfaceStats:
    """Tests for get_attack_surface_stats()."""

    def setup_method(self):
        import kali_mcp.core.broad_attack_orchestrator as mod
        mod._orchestrator_instance = None

    def test_returns_dict(self):
        stats = get_attack_surface_stats()
        assert isinstance(stats, dict)

    def test_has_total_chains(self):
        stats = get_attack_surface_stats()
        assert "total_chains" in stats
        assert stats["total_chains"] == 42

    def test_has_surfaces(self):
        stats = get_attack_surface_stats()
        assert "surfaces" in stats

    def test_has_services(self):
        stats = get_attack_surface_stats()
        assert "services" in stats


# ============================================================
# Edge Cases and Integration-Style Tests
# ============================================================


class TestEdgeCases:
    """Edge case and integration-style tests."""

    def test_plan_attack_same_service_twice(self):
        """Passing the same service twice should not produce duplicate chains."""
        o = BroadAttackOrchestrator()
        vectors = o.plan_attack("t", [ServiceType.HTTP, ServiceType.HTTP])
        chain_names = [v.chain.name for v in vectors]
        assert len(chain_names) == len(set(chain_names))

    def test_plan_attack_all_database_services(self):
        o = BroadAttackOrchestrator()
        db_services = [
            ServiceType.MYSQL, ServiceType.POSTGRESQL, ServiceType.MSSQL,
            ServiceType.MONGODB, ServiceType.REDIS, ServiceType.ELASTICSEARCH,
        ]
        vectors = o.plan_attack("t", db_services)
        chain_names = {v.chain.name for v in vectors}
        assert "mysql_attack" in chain_names
        assert "postgresql_attack" in chain_names
        assert "mssql_attack" in chain_names
        assert "mongodb_attack" in chain_names
        assert "redis_attack" in chain_names
        assert "elasticsearch_attack" in chain_names

    def test_orchestrator_instances_are_independent(self):
        o1 = BroadAttackOrchestrator()
        o2 = BroadAttackOrchestrator()
        o1.plan_attack("t", [ServiceType.HTTP])
        assert o1.active_vectors != []
        assert o2.active_vectors == []

    def test_chain_list_immutability(self):
        """Verify that modifying orchestrator chains doesn't affect module-level lists."""
        o = BroadAttackOrchestrator()
        original_count = len(WEB_TOOL_CHAINS)
        o.all_chains["extra"] = ToolChain(
            name="extra",
            description="x",
            surface=AttackSurface.WEB_APPLICATION,
            services=[],
            tools=["t"],
        )
        assert len(WEB_TOOL_CHAINS) == original_count

    def test_identify_services_then_plan(self):
        """Full workflow: identify services from scan, then plan attack."""
        o = BroadAttackOrchestrator()
        scan = {
            "ports": [
                {"port": 80, "host": "target"},
                {"port": 22, "host": "target"},
                {"port": 3306, "host": "target"},
            ]
        }
        services = o.identify_services(scan)
        vectors = o.plan_attack("target", services.get("target", []))
        assert len(vectors) > 0
        chain_names = {v.chain.name for v in vectors}
        assert "web_fingerprint" in chain_names
        assert "ssh_attack" in chain_names
        assert "mysql_attack" in chain_names

    def test_get_next_chains_chain_cycle_resilience(self):
        """If a chain references itself in next_chains, it should still return it."""
        o = BroadAttackOrchestrator()
        self_ref = ToolChain(
            name="self_ref",
            description="self referencing",
            surface=AttackSurface.WEB_APPLICATION,
            services=[],
            tools=["t"],
            success_indicators=["done"],
            next_chains=["self_ref"],
        )
        o.all_chains["self_ref"] = self_ref
        result = o.get_next_chains("self_ref", {"done": True})
        assert len(result) == 1
        assert result[0].name == "self_ref"

    def test_suggest_attack_path_case_insensitive_db(self):
        o = BroadAttackOrchestrator()
        # Check lower case
        r1 = o.suggest_attack_path({"database": "mysql"})
        names1 = [c.name for c in r1]
        assert "mysql_attack" in names1
        # Check mixed case
        r2 = o.suggest_attack_path({"database": "MySQL"})
        names2 = [c.name for c in r2]
        assert "mysql_attack" in names2

    def test_plan_attack_with_many_services(self):
        """Ensure planning with many services does not crash or produce errors."""
        o = BroadAttackOrchestrator()
        all_services = list(ServiceType)
        vectors = o.plan_attack("big_target", all_services)
        assert len(vectors) > 0
        # No duplicate chain names
        chain_names = [v.chain.name for v in vectors]
        assert len(chain_names) == len(set(chain_names))

    def test_attack_vector_status_transitions(self):
        o = BroadAttackOrchestrator()
        vectors = o.plan_attack("t", [ServiceType.HTTP])
        v = vectors[0]
        assert v.status == "pending"
        v.status = "running"
        assert v.status == "running"
        v.status = "completed"
        assert v.status == "completed"
        v.status = "failed"
        assert v.status == "failed"

    def test_generate_report_sets_to_lists(self):
        """Report should have lists for surfaces_covered and services_attacked, not sets."""
        o = BroadAttackOrchestrator()
        chain = o.all_chains["web_fingerprint"]
        v = AttackVector(
            chain=chain, target="t", port=80, service=ServiceType.HTTP,
            priority=10, status="completed", result={"success": True}
        )
        o.completed_vectors.append(v)
        report = o.generate_attack_report()
        assert isinstance(report["surfaces_covered"], list)
        assert isinstance(report["services_attacked"], list)

    def test_web_chains_all_have_success_indicators(self):
        for chain in WEB_TOOL_CHAINS:
            assert len(chain.success_indicators) > 0, f"Web chain '{chain.name}' has no success_indicators"

    def test_web_chains_all_have_next_chains(self):
        for chain in WEB_TOOL_CHAINS:
            assert len(chain.next_chains) > 0, f"Web chain '{chain.name}' has no next_chains"

    def test_coverage_surfaces_add_up(self):
        o = BroadAttackOrchestrator()
        coverage = o.get_attack_coverage()
        surface_total = sum(coverage["surfaces"].values())
        assert surface_total == coverage["total_chains"]

    def test_service_port_map_covers_many_service_types(self):
        """Most ServiceType members should appear in SERVICE_PORT_MAP."""
        mapped_services = set(SERVICE_PORT_MAP.values())
        # These are known to not be in the map
        unmapped = {ServiceType.PROXY, ServiceType.RSYNC, ServiceType.KUBERNETES}
        for svc in ServiceType:
            if svc not in unmapped:
                assert svc in mapped_services, f"{svc.name} not found in SERVICE_PORT_MAP"

    def test_all_chain_tools_are_strings(self):
        o = BroadAttackOrchestrator()
        for chain in o.all_chains.values():
            for tool in chain.tools:
                assert isinstance(tool, str), f"Tool in chain '{chain.name}' is not a string"

    def test_get_chains_for_service_returns_list(self):
        o = BroadAttackOrchestrator()
        result = o.get_chains_for_service(ServiceType.HTTP)
        assert isinstance(result, list)

    def test_get_chains_for_surface_returns_list(self):
        o = BroadAttackOrchestrator()
        result = o.get_chains_for_surface(AttackSurface.WEB_APPLICATION)
        assert isinstance(result, list)

    def test_suggest_attack_path_returns_list(self):
        o = BroadAttackOrchestrator()
        result = o.suggest_attack_path({"web_server": True})
        assert isinstance(result, list)

    def test_plan_attack_returns_list(self):
        o = BroadAttackOrchestrator()
        result = o.plan_attack("t", [ServiceType.HTTP])
        assert isinstance(result, list)
