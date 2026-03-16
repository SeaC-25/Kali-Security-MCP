"""
Comprehensive tests for kali_mcp.core.output_parsers

Covers:
- ParsedResult dataclass creation and to_dict()
- smart_truncate with various lengths and edge cases
- detect_flags with various flag formats
- parse_output routing to correct parser
- Each of the 14 registered parsers with realistic sample output
- Edge cases: empty output, None output, unknown tool fallback
- list_parsers returns expected set
"""

import pytest

from kali_mcp.core.output_parsers import (
    ParsedResult,
    smart_truncate,
    detect_flags,
    parse_output,
    list_parsers,
    get_parser,
    register_parser,
    PARSER_REGISTRY,
    NmapParser,
    MasscanParser,
    GobusterParser,
    NucleiParser,
    NiktoParser,
    SqlmapParser,
    SubfinderParser,
    HydraParser,
    WhatwebParser,
    GenericParser,
    _is_trivial_hash,
)


# ============================================================
# 1. ParsedResult dataclass
# ============================================================

class TestParsedResult:

    def test_creation_with_defaults(self):
        r = ParsedResult(
            tool_name="nmap",
            success=True,
            summary="test summary",
            structured_data={"key": "val"},
            raw_output="raw text",
        )
        assert r.tool_name == "nmap"
        assert r.success is True
        assert r.summary == "test summary"
        assert r.structured_data == {"key": "val"}
        assert r.raw_output == "raw text"
        assert r.flags_found == []
        assert r.next_steps == []
        assert r.severity == "info"
        assert r.confidence == 1.0

    def test_creation_with_all_fields(self):
        r = ParsedResult(
            tool_name="sqlmap",
            success=False,
            summary="injection found",
            structured_data={"injectable": True},
            raw_output="raw",
            flags_found=["flag{abc}"],
            next_steps=["next step"],
            severity="critical",
            confidence=0.95,
        )
        assert r.flags_found == ["flag{abc}"]
        assert r.next_steps == ["next step"]
        assert r.severity == "critical"
        assert r.confidence == 0.95

    def test_to_dict_returns_complete_dict(self):
        r = ParsedResult(
            tool_name="test",
            success=True,
            summary="s",
            structured_data={"a": 1},
            raw_output="raw",
            flags_found=["flag{x}"],
            next_steps=["step1"],
            severity="high",
            confidence=0.8,
        )
        d = r.to_dict()
        assert isinstance(d, dict)
        assert d["tool_name"] == "test"
        assert d["success"] is True
        assert d["summary"] == "s"
        assert d["structured_data"] == {"a": 1}
        assert d["raw_output"] == "raw"
        assert d["flags_found"] == ["flag{x}"]
        assert d["next_steps"] == ["step1"]
        assert d["severity"] == "high"
        assert d["confidence"] == 0.8

    def test_to_dict_keys_match_fields(self):
        r = ParsedResult("t", True, "s", {}, "")
        d = r.to_dict()
        expected_keys = {
            "tool_name", "success", "summary", "structured_data",
            "raw_output", "flags_found", "next_steps", "severity", "confidence",
        }
        assert set(d.keys()) == expected_keys

    def test_default_list_fields_are_independent(self):
        """Verify default list fields don't share state across instances."""
        r1 = ParsedResult("a", True, "s", {}, "")
        r2 = ParsedResult("b", True, "s", {}, "")
        r1.flags_found.append("flag{shared?}")
        assert r2.flags_found == []


# ============================================================
# 2. smart_truncate
# ============================================================

class TestSmartTruncate:

    def test_short_text_not_truncated(self):
        text = "short text"
        result, was_truncated = smart_truncate(text, max_length=100)
        assert result == text
        assert was_truncated is False

    def test_exact_length_not_truncated(self):
        text = "x" * 5000
        result, was_truncated = smart_truncate(text, max_length=5000)
        assert result == text
        assert was_truncated is False

    def test_long_text_truncated(self):
        text = "a" * 10000
        result, was_truncated = smart_truncate(text, max_length=5000)
        assert was_truncated is True
        assert len(result) < len(text)
        # Should contain truncation marker
        assert "截断" in result
        # Head preserved (first 60%)
        assert result.startswith("a" * 3000)
        # Tail preserved (last 30%)
        assert result.endswith("a" * 1500)

    def test_empty_string(self):
        result, was_truncated = smart_truncate("", max_length=5000)
        assert result == ""
        assert was_truncated is False

    def test_none_input(self):
        result, was_truncated = smart_truncate(None, max_length=5000)
        assert result == ""
        assert was_truncated is False

    def test_truncation_marker_contains_sizes(self):
        text = "x" * 10000
        result, _ = smart_truncate(text, max_length=5000)
        assert "10000" in result  # original length
        # The omitted chars = 10000 - 3000 - 1500 = 5500
        assert "5500" in result

    def test_custom_max_length(self):
        text = "y" * 200
        result, was_truncated = smart_truncate(text, max_length=100)
        assert was_truncated is True
        head_size = int(100 * 0.6)  # 60
        tail_size = int(100 * 0.3)  # 30
        assert result.startswith("y" * head_size)
        assert result.endswith("y" * tail_size)

    def test_default_max_length_is_5000(self):
        text = "z" * 5001
        _, was_truncated = smart_truncate(text)
        assert was_truncated is True

        text2 = "z" * 5000
        _, was_truncated2 = smart_truncate(text2)
        assert was_truncated2 is False


# ============================================================
# 3. detect_flags
# ============================================================

class TestDetectFlags:

    def test_flag_curly_braces_lowercase(self):
        assert detect_flags("Found: flag{s3cret_v4lue}") == ["flag{s3cret_v4lue}"]

    def test_flag_curly_braces_uppercase(self):
        assert detect_flags("FLAG{UPPER_CASE}") == ["FLAG{UPPER_CASE}"]

    def test_flag_mixed_case(self):
        result = detect_flags("FlAg{MiXeD}")
        assert len(result) == 1
        assert result[0].lower() == "flag{mixed}"

    def test_ctf_format(self):
        result = detect_flags("the answer is ctf{easy_one}")
        assert "ctf{easy_one}" in result

    def test_CTF_uppercase(self):
        result = detect_flags("CTF{UPPER}")
        assert len(result) == 1

    def test_dasctf_format(self):
        result = detect_flags("DASCTF{d4s_fl4g}")
        assert "DASCTF{d4s_fl4g}" in result

    def test_htb_format(self):
        result = detect_flags("htb{hackthebox_flag}")
        assert len(result) == 1
        assert result[0].lower() == "htb{hackthebox_flag}"

    def test_picoctf_format(self):
        result = detect_flags("picoCTF{p1c0_fl4g}")
        assert "picoCTF{p1c0_fl4g}" in result

    def test_iscc_format(self):
        result = detect_flags("ISCC{iscc_flag}")
        assert len(result) == 1

    def test_sctf_format(self):
        result = detect_flags("SCTF{sctf_flag}")
        # The ctf{...} pattern (case-insensitive) also matches as a substring
        assert any("SCTF{sctf_flag}" in f for f in result)
        assert len(result) == 2  # CTF{sctf_flag} + SCTF{sctf_flag}

    def test_buuctf_format(self):
        result = detect_flags("BUUCTF{buu_flag}")
        # The ctf{...} pattern (case-insensitive) also matches as a substring
        assert any("BUUCTF{buu_flag}" in f for f in result)
        assert len(result) == 2  # CTF{buu_flag} + BUUCTF{buu_flag}

    def test_ciscn_format(self):
        result = detect_flags("CISCN{ciscn_flag}")
        assert len(result) == 1

    def test_flag_dash_format(self):
        result = detect_flags("FLAG-abcd-efgh-ijkl")
        assert "FLAG-abcd-efgh-ijkl" in result

    def test_multiple_flags(self):
        text = "flag{one} and also ctf{two} plus DASCTF{three}"
        result = detect_flags(text)
        # DASCTF{three} also matches CTF{three} and SCTF{three} as substrings
        assert len(result) == 5
        assert "flag{one}" in result
        assert "ctf{two}" in result
        assert "DASCTF{three}" in result

    def test_duplicate_flags_deduplicated(self):
        text = "flag{dup} and flag{dup} again"
        result = detect_flags(text)
        assert len(result) == 1

    def test_case_insensitive_deduplication(self):
        text = "flag{same} FLAG{SAME}"
        result = detect_flags(text)
        assert len(result) == 1

    def test_empty_string(self):
        assert detect_flags("") == []

    def test_none_input(self):
        assert detect_flags(None) == []

    def test_no_flags(self):
        assert detect_flags("nothing special here") == []

    def test_md5_with_context_keyword(self):
        text = "flag: 5d41402abc4b2a76b9719d911017c592"
        result = detect_flags(text)
        assert "5d41402abc4b2a76b9719d911017c592" in result

    def test_md5_without_context_keyword_not_detected(self):
        # 'hash' IS a context keyword but requires ':' or '=' after it
        text = "hash is 5d41402abc4b2a76b9719d911017c592"
        result = detect_flags(text)
        assert len(result) == 0  # "hash is" doesn't match "hash[:=]"

    def test_md5_with_hash_colon_keyword(self):
        text = "hash: 5d41402abc4b2a76b9719d911017c592"
        result = detect_flags(text)
        assert "5d41402abc4b2a76b9719d911017c592" in result

    def test_md5_no_keyword_not_detected(self):
        text = "the value 5d41402abc4b2a76b9719d911017c592 appears"
        result = detect_flags(text)
        assert len(result) == 0

    def test_trivial_hash_excluded(self):
        text = "flag: " + "0" * 32
        result = detect_flags(text)
        assert len(result) == 0

    def test_empty_string_md5_excluded(self):
        text = "key: d41d8cd98f00b204e9800998ecf8427e"
        result = detect_flags(text)
        assert len(result) == 0

    def test_low_entropy_hash_excluded(self):
        text = "flag: " + "ab" * 16  # only 2 unique chars
        result = detect_flags(text)
        assert len(result) == 0

    def test_vnctf_format(self):
        result = detect_flags("VNCTF{vn_flag_123}")
        assert any("VNCTF{vn_flag_123}" in f for f in result)
        assert len(result) == 2  # CTF{...} substring + VNCTF{...}

    def test_xyctf_format(self):
        result = detect_flags("XYCTF{xy_flag_123}")
        assert any("XYCTF{xy_flag_123}" in f for f in result)
        assert len(result) == 2  # CTF{...} substring + XYCTF{...}

    def test_moectf_format(self):
        result = detect_flags("MOECTF{moe_flag_123}")
        assert any("MOECTF{moe_flag_123}" in f for f in result)
        assert len(result) == 2  # CTF{...} substring + MOECTF{...}

    def test_rctf_format(self):
        result = detect_flags("RCTF{rctf_flag}")
        assert any("RCTF{rctf_flag}" in f for f in result)
        assert len(result) == 2  # CTF{...} substring + RCTF{...}

    def test_gwctf_format(self):
        result = detect_flags("GWCTF{gw_flag}")
        assert any("GWCTF{gw_flag}" in f for f in result)
        assert len(result) == 2  # CTF{...} substring + GWCTF{...}

    def test_hctf_format(self):
        result = detect_flags("HCTF{h_flag}")
        assert any("HCTF{h_flag}" in f for f in result)
        assert len(result) == 2  # CTF{...} substring + HCTF{...}


# ============================================================
# 3b. _is_trivial_hash
# ============================================================

class TestIsTrivialHash:

    def test_all_zeros(self):
        assert _is_trivial_hash("0" * 32) is True

    def test_all_f(self):
        assert _is_trivial_hash("f" * 32) is True

    def test_empty_string_md5(self):
        assert _is_trivial_hash("d41d8cd98f00b204e9800998ecf8427e") is True

    def test_two_char_variety(self):
        assert _is_trivial_hash("ab" * 16) is True

    def test_real_hash(self):
        assert _is_trivial_hash("5d41402abc4b2a76b9719d911017c592") is False


# ============================================================
# 4. parse_output routing
# ============================================================

class TestParseOutputRouting:

    def test_routes_to_nmap(self):
        r = parse_output("nmap", "", 0)
        assert r.tool_name == "nmap"

    def test_routes_to_masscan(self):
        r = parse_output("masscan", "", 0)
        assert r.tool_name == "masscan"

    def test_routes_to_gobuster(self):
        r = parse_output("gobuster", "", 0)
        assert r.tool_name == "gobuster"

    def test_routes_dirb_to_gobuster_parser(self):
        r = parse_output("dirb", "", 0)
        assert r.tool_name == "gobuster"

    def test_routes_ffuf_to_gobuster_parser(self):
        r = parse_output("ffuf", "", 0)
        assert r.tool_name == "gobuster"

    def test_routes_feroxbuster_to_gobuster_parser(self):
        r = parse_output("feroxbuster", "", 0)
        assert r.tool_name == "gobuster"

    def test_routes_to_nuclei(self):
        r = parse_output("nuclei", "", 0)
        assert r.tool_name == "nuclei"

    def test_routes_to_nikto(self):
        r = parse_output("nikto", "", 0)
        assert r.tool_name == "nikto"

    def test_routes_to_sqlmap(self):
        r = parse_output("sqlmap", "", 0)
        assert r.tool_name == "sqlmap"

    def test_routes_to_subfinder(self):
        r = parse_output("subfinder", "", 0)
        assert r.tool_name == "subfinder"

    def test_routes_sublist3r_to_subfinder_parser(self):
        r = parse_output("sublist3r", "", 0)
        assert r.tool_name == "subfinder"

    def test_routes_amass_to_subfinder_parser(self):
        r = parse_output("amass", "", 0)
        assert r.tool_name == "subfinder"

    def test_routes_to_hydra(self):
        r = parse_output("hydra", "", 0)
        assert r.tool_name == "hydra"

    def test_routes_to_whatweb(self):
        r = parse_output("whatweb", "", 0)
        assert r.tool_name == "whatweb"

    def test_unknown_tool_uses_generic(self):
        r = parse_output("unknown_tool_xyz", "some output", 0)
        # GenericParser sets tool_name from data["_tool_name"]
        assert r.tool_name == "unknown_tool_xyz"

    def test_case_insensitive_routing(self):
        r = parse_output("NMAP", "", 0)
        assert r.tool_name == "nmap"

    def test_whitespace_trimmed(self):
        r = parse_output("  nmap  ", "", 0)
        assert r.tool_name == "nmap"

    def test_none_output_handled(self):
        r = parse_output("nmap", None, 0)
        assert isinstance(r, ParsedResult)

    def test_empty_output_handled(self):
        r = parse_output("nmap", "", 0)
        assert isinstance(r, ParsedResult)

    def test_flag_detection_runs_on_all_parsers(self):
        r = parse_output("nmap", "flag{found_in_nmap}", 0)
        assert "flag{found_in_nmap}" in r.flags_found


# ============================================================
# 5. Nmap parser
# ============================================================

NMAP_OUTPUT = """Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-01 12:00 UTC
Nmap scan report for 10.0.0.1
Host is up (0.0010s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
80/tcp   open  http        Apache httpd 2.4.52 ((Ubuntu))
443/tcp  open  https       Apache httpd 2.4.52
3306/tcp open  mysql       MySQL 5.7.40
8080/tcp closed http-proxy

OS details: Ubuntu Linux 22.04

Nmap done: 1 IP address (1 host up) scanned in 5.23 seconds
"""


class TestNmapParser:

    def test_open_ports_parsed(self):
        r = parse_output("nmap", NMAP_OUTPUT, 0, {"target": "10.0.0.1"})
        ports = r.structured_data["ports"]
        open_ports = [p for p in ports if p["state"] == "open"]
        assert len(open_ports) == 4
        port_nums = {p["port"] for p in open_ports}
        assert port_nums == {22, 80, 443, 3306}

    def test_closed_port_included(self):
        r = parse_output("nmap", NMAP_OUTPUT, 0)
        ports = r.structured_data["ports"]
        closed = [p for p in ports if p["state"] == "closed"]
        assert len(closed) == 1
        assert closed[0]["port"] == 8080

    def test_os_detected(self):
        r = parse_output("nmap", NMAP_OUTPUT, 0)
        assert "Ubuntu" in r.structured_data["os"]

    def test_hostname_parsed(self):
        r = parse_output("nmap", NMAP_OUTPUT, 0)
        assert r.structured_data["hostname"] == "10.0.0.1"

    def test_host_up(self):
        r = parse_output("nmap", NMAP_OUTPUT, 0)
        assert r.structured_data["host_up"] is True

    def test_summary_contains_port_count(self):
        r = parse_output("nmap", NMAP_OUTPUT, 0, {"target": "10.0.0.1"})
        assert "4" in r.summary  # 4 open ports

    def test_next_steps_generated(self):
        r = parse_output("nmap", NMAP_OUTPUT, 0, {"target": "10.0.0.1"})
        assert len(r.next_steps) > 0

    def test_ssh_next_step(self):
        r = parse_output("nmap", NMAP_OUTPUT, 0)
        ssh_steps = [s for s in r.next_steps if "SSH" in s or "ssh" in s.lower()]
        assert len(ssh_steps) > 0

    def test_empty_output(self):
        r = parse_output("nmap", "", 0)
        assert r.structured_data["ports"] == []
        assert r.structured_data["host_up"] is False

    def test_host_down(self):
        output = """Starting Nmap 7.94
Nmap scan report for 10.0.0.99
Host seems down.
Nmap done: 1 IP address (0 hosts up)
"""
        r = parse_output("nmap", output, 0)
        assert r.structured_data["host_up"] is False

    def test_service_version_extraction(self):
        r = parse_output("nmap", NMAP_OUTPUT, 0)
        ports = r.structured_data["ports"]
        ssh_port = [p for p in ports if p["port"] == 22][0]
        assert ssh_port["service"] == "ssh"
        # version should have been extracted
        assert ssh_port["version"]

    def test_open_port_count_field(self):
        r = parse_output("nmap", NMAP_OUTPUT, 0)
        assert r.structured_data["open_port_count"] == 4

    def test_severity_for_insecure_services(self):
        output = """Nmap scan report for 10.0.0.1
Host is up.

PORT   STATE SERVICE
21/tcp open  ftp
23/tcp open  telnet
"""
        r = parse_output("nmap", output, 0)
        assert r.severity in ("medium", "high")

    def test_confidence_with_open_ports(self):
        r = parse_output("nmap", NMAP_OUTPUT, 0)
        assert r.confidence == 0.95

    def test_confidence_without_open_ports(self):
        output = """Nmap scan report for 10.0.0.1
Host is up.

All 1000 scanned ports on 10.0.0.1 are filtered
"""
        r = parse_output("nmap", output, 0)
        assert r.confidence == 0.7

    def test_web_port_nuclei_suggestion(self):
        r = parse_output("nmap", NMAP_OUTPUT, 0)
        nuclei_steps = [s for s in r.next_steps if "nuclei" in s.lower()]
        assert len(nuclei_steps) > 0


# ============================================================
# 5b. Masscan parser
# ============================================================

MASSCAN_OUTPUT = """Starting masscan 1.3.2
Discovered open port 80/tcp on 192.168.1.1
Discovered open port 443/tcp on 192.168.1.1
Discovered open port 22/tcp on 192.168.1.2
Discovered open port 8080/tcp on 192.168.1.1
"""


class TestMasscanParser:

    def test_ports_parsed(self):
        r = parse_output("masscan", MASSCAN_OUTPUT, 0, {"target": "192.168.1.0/24"})
        ports = r.structured_data["ports"]
        assert len(ports) == 4

    def test_hosts_collected(self):
        r = parse_output("masscan", MASSCAN_OUTPUT, 0)
        hosts = r.structured_data["hosts"]
        assert "192.168.1.1" in hosts
        assert "192.168.1.2" in hosts

    def test_open_port_count(self):
        r = parse_output("masscan", MASSCAN_OUTPUT, 0)
        assert r.structured_data["open_port_count"] == 4

    def test_summary(self):
        r = parse_output("masscan", MASSCAN_OUTPUT, 0, {"target": "192.168.1.0/24"})
        assert "4" in r.summary
        assert "2" in r.summary  # 2 hosts

    def test_next_steps_include_nmap(self):
        r = parse_output("masscan", MASSCAN_OUTPUT, 0)
        nmap_steps = [s for s in r.next_steps if "nmap" in s.lower()]
        assert len(nmap_steps) > 0

    def test_web_port_suggestion(self):
        r = parse_output("masscan", MASSCAN_OUTPUT, 0)
        web_steps = [s for s in r.next_steps if "Web" in s or "whatweb" in s.lower()]
        assert len(web_steps) > 0

    def test_empty_output(self):
        r = parse_output("masscan", "", 0)
        assert r.structured_data["ports"] == []
        assert r.structured_data["hosts"] == []
        assert r.structured_data["open_port_count"] == 0


# ============================================================
# 5c. Gobuster parser (also dirb, ffuf, feroxbuster)
# ============================================================

GOBUSTER_OUTPUT = """/admin                (Status: 200) [Size: 1234]
/login                (Status: 302) [Size: 0] [--> /auth/login]
/api                  (Status: 200) [Size: 567]
/uploads              (Status: 403) [Size: 0]
/.git                 (Status: 200) [Size: 23]
/backup               (Status: 200) [Size: 9999]
/index.php            (Status: 200) [Size: 5000]
/style.css            (Status: 200) [Size: 300]
"""


class TestGobusterParser:

    def test_paths_parsed(self):
        r = parse_output("gobuster", GOBUSTER_OUTPUT, 0, {"url": "http://target.com"})
        paths = r.structured_data["paths"]
        assert len(paths) == 8

    def test_status_codes(self):
        r = parse_output("gobuster", GOBUSTER_OUTPUT, 0)
        paths = r.structured_data["paths"]
        admin_path = [p for p in paths if p["path"] == "/admin"][0]
        assert admin_path["status"] == 200
        assert admin_path["size"] == 1234

    def test_redirect_parsed(self):
        r = parse_output("gobuster", GOBUSTER_OUTPUT, 0)
        paths = r.structured_data["paths"]
        login_path = [p for p in paths if p["path"] == "/login"][0]
        assert login_path["redirect"] == "/auth/login"

    def test_interesting_paths_found(self):
        r = parse_output("gobuster", GOBUSTER_OUTPUT, 0)
        interesting = r.structured_data["interesting"]
        assert "/admin" in interesting
        assert "/.git" in interesting
        assert "/backup" in interesting

    def test_total_found(self):
        r = parse_output("gobuster", GOBUSTER_OUTPUT, 0)
        assert r.structured_data["total_found"] == 8

    def test_high_severity_for_git(self):
        r = parse_output("gobuster", GOBUSTER_OUTPUT, 0)
        assert r.severity == "high"

    def test_git_next_step(self):
        r = parse_output("gobuster", GOBUSTER_OUTPUT, 0)
        git_steps = [s for s in r.next_steps if ".git" in s.lower()]
        assert len(git_steps) > 0

    def test_admin_next_step(self):
        r = parse_output("gobuster", GOBUSTER_OUTPUT, 0)
        admin_steps = [s for s in r.next_steps if "管理后台" in s or "admin" in s.lower()]
        assert len(admin_steps) > 0

    def test_empty_output(self):
        r = parse_output("gobuster", "", 0, {"url": "http://target.com"})
        assert r.structured_data["paths"] == []
        assert r.structured_data["total_found"] == 0

    def test_dirb_uses_same_parser(self):
        r = parse_output("dirb", GOBUSTER_OUTPUT, 0)
        assert len(r.structured_data["paths"]) == 8

    def test_ffuf_uses_same_parser(self):
        r = parse_output("ffuf", GOBUSTER_OUTPUT, 0)
        assert len(r.structured_data["paths"]) == 8

    def test_feroxbuster_format(self):
        ferox_output = "200 GET 100l 200w 5000c http://target.com/admin\n"
        r = parse_output("feroxbuster", ferox_output, 0)
        paths = r.structured_data["paths"]
        assert len(paths) == 1
        assert paths[0]["status"] == 200
        assert paths[0]["size"] == 5000

    def test_php_pages_suggestion(self):
        php_output = "/login.php            (Status: 200) [Size: 5000]\n/test.php            (Status: 200) [Size: 1000]\n"
        r = parse_output("gobuster", php_output, 0)
        sqlmap_steps = [s for s in r.next_steps if "sqlmap" in s.lower()]
        assert len(sqlmap_steps) > 0

    def test_summary_contains_status_200_count(self):
        r = parse_output("gobuster", GOBUSTER_OUTPUT, 0, {"url": "http://target.com"})
        assert "200" in r.summary


# ============================================================
# 5d. Nuclei parser
# ============================================================

NUCLEI_TEXT_OUTPUT = """[critical] [CVE-2021-44228] [http] http://target.com/api [log4shell]
[high] [CVE-2023-1234] [http] http://target.com/admin
[medium] [xss-reflected] [http] http://target.com/search
[info] [tech-detect:apache] [http] http://target.com
"""

NUCLEI_JSON_OUTPUT = '{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell","severity":"critical","classification":{"cve-id":["CVE-2021-44228"]}},"matched-at":"http://target.com/api","matcher-name":"log4shell"}\n'


class TestNucleiParser:

    def test_text_format_parsed(self):
        r = parse_output("nuclei", NUCLEI_TEXT_OUTPUT, 0, {"target": "http://target.com"})
        vulns = r.structured_data["vulnerabilities"]
        assert len(vulns) == 4

    def test_severity_stats(self):
        r = parse_output("nuclei", NUCLEI_TEXT_OUTPUT, 0)
        stats = r.structured_data["stats"]
        assert stats["critical"] == 1
        assert stats["high"] == 1
        assert stats["medium"] == 1
        assert stats["info"] == 1

    def test_max_severity(self):
        r = parse_output("nuclei", NUCLEI_TEXT_OUTPUT, 0)
        assert r.severity == "critical"

    def test_cve_extraction(self):
        r = parse_output("nuclei", NUCLEI_TEXT_OUTPUT, 0)
        vulns = r.structured_data["vulnerabilities"]
        cve_vuln = [v for v in vulns if v["cve_id"] == "CVE-2021-44228"]
        assert len(cve_vuln) == 1

    def test_json_format_parsed(self):
        r = parse_output("nuclei", NUCLEI_JSON_OUTPUT, 0)
        vulns = r.structured_data["vulnerabilities"]
        assert len(vulns) == 1
        assert vulns[0]["name"] == "Log4Shell"
        assert vulns[0]["severity"] == "critical"
        assert vulns[0]["cve_id"] == "CVE-2021-44228"

    def test_critical_vuln_next_steps(self):
        r = parse_output("nuclei", NUCLEI_TEXT_OUTPUT, 0)
        critical_steps = [s for s in r.next_steps if "严重" in s or "critical" in s.lower()]
        assert len(critical_steps) > 0

    def test_xss_next_step(self):
        xss_output = "[medium] [xss-reflected] [http] http://target.com/search\n"
        r = parse_output("nuclei", xss_output, 0)
        xss_steps = [s for s in r.next_steps if "XSS" in s or "xss" in s.lower()]
        assert len(xss_steps) > 0

    def test_sql_next_step(self):
        sql_output = "[high] [sqli-error-based] [http] http://target.com/api\n"
        r = parse_output("nuclei", sql_output, 0)
        sql_steps = [s for s in r.next_steps if "SQL" in s or "sqlmap" in s.lower()]
        assert len(sql_steps) > 0

    def test_empty_output(self):
        r = parse_output("nuclei", "", 0, {"target": "http://target.com"})
        assert r.structured_data["vulnerabilities"] == []
        assert r.severity == "info"

    def test_confidence_with_vulns(self):
        r = parse_output("nuclei", NUCLEI_TEXT_OUTPUT, 0)
        assert r.confidence == 0.95

    def test_confidence_without_vulns(self):
        r = parse_output("nuclei", "", 0)
        assert r.confidence == 0.7

    def test_info_only_severity(self):
        output = "[info] [tech-detect:apache] [http] http://target.com\n"
        r = parse_output("nuclei", output, 0)
        assert r.severity == "info"


# ============================================================
# 5e. Nikto parser
# ============================================================

NIKTO_OUTPUT = """- Nikto v2.5.0
+ Target IP:          10.0.0.1
+ Target Hostname:    target.com
+ Target Port:        80
+ Server: Apache/2.4.52 (Ubuntu)
+ OSVDB-3092: /admin/: This might be interesting...
+ /login.php: Admin login page/section found.
+ CVE-2021-41773: /cgi-bin/.%2e/: Apache 2.4.49-50 Path Traversal
+ /uploads/: Directory indexing found.
"""


class TestNiktoParser:

    def test_findings_parsed(self):
        r = parse_output("nikto", NIKTO_OUTPUT, 0, {"target": "target.com"})
        findings = r.structured_data["findings"]
        assert len(findings) >= 3

    def test_server_detected(self):
        r = parse_output("nikto", NIKTO_OUTPUT, 0)
        assert "Apache" in r.structured_data["server"]

    def test_osvdb_id_parsed(self):
        r = parse_output("nikto", NIKTO_OUTPUT, 0)
        findings = r.structured_data["findings"]
        osvdb = [f for f in findings if f["id"] == "OSVDB-3092"]
        assert len(osvdb) == 1

    def test_cve_id_parsed(self):
        r = parse_output("nikto", NIKTO_OUTPUT, 0)
        findings = r.structured_data["findings"]
        cve = [f for f in findings if "CVE" in f.get("id", "")]
        assert len(cve) == 1

    def test_severity_high_for_cve(self):
        r = parse_output("nikto", NIKTO_OUTPUT, 0)
        assert r.severity == "high"

    def test_interesting_count(self):
        r = parse_output("nikto", NIKTO_OUTPUT, 0)
        assert r.structured_data["interesting_findings"] > 0

    def test_next_steps(self):
        r = parse_output("nikto", NIKTO_OUTPUT, 0)
        assert len(r.next_steps) > 0

    def test_server_next_step(self):
        r = parse_output("nikto", NIKTO_OUTPUT, 0)
        server_steps = [s for s in r.next_steps if "Apache" in s or "searchsploit" in s.lower()]
        assert len(server_steps) > 0

    def test_empty_output(self):
        r = parse_output("nikto", "", 0)
        assert r.structured_data["findings"] == []
        assert r.structured_data["total_findings"] == 0

    def test_summary(self):
        r = parse_output("nikto", NIKTO_OUTPUT, 0, {"target": "target.com"})
        assert "target.com" in r.summary
        assert "Apache" in r.summary


# ============================================================
# 5f. SQLMap parser
# ============================================================

SQLMAP_OUTPUT = """[*] starting @ 12:00:00

[12:00:01] [INFO] testing connection to the target URL
[12:00:02] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:00:03] [INFO] Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
    Payload: id=1 AND 1=1

    Type: time-based blind
    Title: MySQL >= 5.0 time-based blind
    Payload: id=1 AND SLEEP(5)

[12:00:04] [INFO] the back-end DBMS is MySQL
[12:00:05] [INFO] banner: '5.7.40-0ubuntu0.18.04.1'
web server operating system: Linux Ubuntu
web application technology: PHP 7.2, Apache 2.4.29
back-end DBMS: MySQL >= 5.0

[12:00:06] [INFO] Parameter 'id' is vulnerable
available databases [3]:
[*] information_schema
[*] mysql
[*] webapp

Database: webapp
[*] users
[*] posts
"""


class TestSqlmapParser:

    def test_injectable_detected(self):
        r = parse_output("sqlmap", SQLMAP_OUTPUT, 0, {"url": "http://target.com/page?id=1"})
        assert r.structured_data["injectable"] is True

    def test_parameter_detected(self):
        r = parse_output("sqlmap", SQLMAP_OUTPUT, 0)
        assert r.structured_data["parameter"] == "id"

    def test_db_type_detected(self):
        r = parse_output("sqlmap", SQLMAP_OUTPUT, 0)
        assert "MySQL" in r.structured_data["db_type"]

    def test_injection_types(self):
        r = parse_output("sqlmap", SQLMAP_OUTPUT, 0)
        types = r.structured_data["injection_types"]
        assert "boolean-based" in types
        assert "time-based" in types

    def test_databases_listed(self):
        r = parse_output("sqlmap", SQLMAP_OUTPUT, 0)
        dbs = r.structured_data["databases"]
        assert "information_schema" in dbs
        assert "mysql" in dbs
        assert "webapp" in dbs

    def test_tables_listed(self):
        r = parse_output("sqlmap", SQLMAP_OUTPUT, 0)
        tables = r.structured_data["tables"]
        assert "webapp" in tables
        assert "users" in tables["webapp"]
        assert "posts" in tables["webapp"]

    def test_banner_parsed(self):
        r = parse_output("sqlmap", SQLMAP_OUTPUT, 0)
        assert "5.7.40" in r.structured_data["banner"]

    def test_severity_critical(self):
        r = parse_output("sqlmap", SQLMAP_OUTPUT, 0)
        assert r.severity == "critical"

    def test_summary_contains_injection_info(self):
        r = parse_output("sqlmap", SQLMAP_OUTPUT, 0, {"url": "http://target.com"})
        assert "SQL注入" in r.summary
        assert "id" in r.summary

    def test_next_steps_for_tables(self):
        r = parse_output("sqlmap", SQLMAP_OUTPUT, 0)
        dump_steps = [s for s in r.next_steps if "--dump" in s]
        assert len(dump_steps) > 0

    def test_mysql_os_shell_suggestion(self):
        r = parse_output("sqlmap", SQLMAP_OUTPUT, 0)
        os_steps = [s for s in r.next_steps if "os-shell" in s.lower()]
        assert len(os_steps) > 0

    def test_not_injectable(self):
        output = """[*] starting @ 12:00:00
[12:00:01] [WARNING] parameter 'id' does not seem to be injectable
[12:00:02] [CRITICAL] all tested parameters do not appear to be injectable
"""
        r = parse_output("sqlmap", output, 1)
        assert r.structured_data["injectable"] is False
        assert r.severity == "info"

    def test_empty_output(self):
        r = parse_output("sqlmap", "", 0, {"url": "http://target.com"})
        assert r.structured_data["injectable"] is False


# ============================================================
# 5g. Subfinder parser (also sublist3r, amass)
# ============================================================

SUBFINDER_OUTPUT = """api.example.com
www.example.com
mail.example.com
dev.example.com
staging.example.com
*.example.com
"""


class TestSubfinderParser:

    def test_subdomains_parsed(self):
        r = parse_output("subfinder", SUBFINDER_OUTPUT, 0, {"domain": "example.com"})
        subs = r.structured_data["subdomains"]
        assert len(subs) >= 5

    def test_count_matches(self):
        r = parse_output("subfinder", SUBFINDER_OUTPUT, 0, {"domain": "example.com"})
        assert r.structured_data["count"] == len(r.structured_data["subdomains"])

    def test_wildcard_detected(self):
        r = parse_output("subfinder", SUBFINDER_OUTPUT, 0, {"domain": "example.com"})
        assert r.structured_data["wildcard_detected"] is True

    def test_unique_prefixes(self):
        r = parse_output("subfinder", SUBFINDER_OUTPUT, 0, {"domain": "example.com"})
        prefixes = r.structured_data["unique_prefixes"]
        assert "api" in prefixes
        assert "www" in prefixes
        assert "dev" in prefixes

    def test_deduplication(self):
        output = "api.example.com\napi.example.com\nwww.example.com\n"
        r = parse_output("subfinder", output, 0)
        subs = r.structured_data["subdomains"]
        assert len(subs) == 2

    def test_next_steps(self):
        r = parse_output("subfinder", SUBFINDER_OUTPUT, 0)
        assert len(r.next_steps) > 0
        httpx_steps = [s for s in r.next_steps if "httpx" in s.lower()]
        assert len(httpx_steps) > 0

    def test_wildcard_warning(self):
        r = parse_output("subfinder", SUBFINDER_OUTPUT, 0)
        wildcard_steps = [s for s in r.next_steps if "通配符" in s]
        assert len(wildcard_steps) > 0

    def test_empty_output(self):
        r = parse_output("subfinder", "", 0, {"domain": "example.com"})
        assert r.structured_data["subdomains"] == []
        assert r.structured_data["count"] == 0

    def test_sublist3r_uses_same_parser(self):
        r = parse_output("sublist3r", SUBFINDER_OUTPUT, 0, {"domain": "example.com"})
        assert len(r.structured_data["subdomains"]) >= 5

    def test_amass_uses_same_parser(self):
        r = parse_output("amass", SUBFINDER_OUTPUT, 0, {"domain": "example.com"})
        assert len(r.structured_data["subdomains"]) >= 5

    def test_non_domain_lines_skipped(self):
        output = "api.example.com\n[INFO] scanning...\nwww.example.com\n"
        r = parse_output("subfinder", output, 0)
        subs = r.structured_data["subdomains"]
        assert len(subs) == 2

    def test_summary_contains_count(self):
        r = parse_output("subfinder", SUBFINDER_OUTPUT, 0, {"domain": "example.com"})
        # Count should be in summary
        count = str(r.structured_data["count"])
        assert count in r.summary


# ============================================================
# 5h. Hydra parser
# ============================================================

HYDRA_OUTPUT = """Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-01 12:00:00
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries
[DATA] attacking ssh://10.0.0.1:22/
[22][ssh] host: 10.0.0.1   login: admin   password: password123
[22][ssh] host: 10.0.0.1   login: root   password: toor
1 of 14344399 complete, 2 valid passwords found
"""


class TestHydraParser:

    def test_credentials_found(self):
        r = parse_output("hydra", HYDRA_OUTPUT, 0, {"target": "10.0.0.1", "service": "ssh"})
        creds = r.structured_data["credentials"]
        assert len(creds) == 2

    def test_credential_details(self):
        r = parse_output("hydra", HYDRA_OUTPUT, 0)
        creds = r.structured_data["credentials"]
        admin_cred = [c for c in creds if c["login"] == "admin"][0]
        assert admin_cred["password"] == "password123"
        assert admin_cred["port"] == 22
        assert admin_cred["service"] == "ssh"
        assert admin_cred["host"] == "10.0.0.1"

    def test_found_flag(self):
        r = parse_output("hydra", HYDRA_OUTPUT, 0)
        assert r.structured_data["found"] is True

    def test_severity_critical(self):
        r = parse_output("hydra", HYDRA_OUTPUT, 0)
        assert r.severity == "critical"

    def test_confidence_high(self):
        r = parse_output("hydra", HYDRA_OUTPUT, 0)
        assert r.confidence == 0.99

    def test_ssh_next_step(self):
        r = parse_output("hydra", HYDRA_OUTPUT, 0)
        ssh_steps = [s for s in r.next_steps if "SSH" in s]
        assert len(ssh_steps) > 0

    def test_summary_contains_creds(self):
        r = parse_output("hydra", HYDRA_OUTPUT, 0, {"target": "10.0.0.1"})
        assert "admin" in r.summary
        assert "password123" in r.summary

    def test_no_creds_found(self):
        output = """Hydra v9.5
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries
[DATA] attacking ssh://10.0.0.1:22/
0 of 14344399 complete, 0 valid passwords found
"""
        r = parse_output("hydra", output, 1, {"target": "10.0.0.1", "service": "ssh"})
        assert r.structured_data["found"] is False
        assert r.severity == "info"
        assert r.confidence == 0.6

    def test_attempts_parsed(self):
        r = parse_output("hydra", HYDRA_OUTPUT, 0)
        assert r.structured_data["attempts"] == 14344399

    def test_empty_output(self):
        r = parse_output("hydra", "", 0, {"target": "10.0.0.1"})
        assert r.structured_data["credentials"] == []
        assert r.structured_data["found"] is False

    def test_ftp_next_step(self):
        output = "[21][ftp] host: 10.0.0.1   login: anonymous   password: anonymous@\n"
        r = parse_output("hydra", output, 0)
        ftp_steps = [s for s in r.next_steps if "FTP" in s]
        assert len(ftp_steps) > 0

    def test_http_next_step(self):
        output = "[80][http-get] host: 10.0.0.1   login: admin   password: admin\n"
        r = parse_output("hydra", output, 0)
        web_steps = [s for s in r.next_steps if "Web" in s or "后台" in s]
        assert len(web_steps) > 0

    def test_mysql_next_step(self):
        output = "[3306][mysql] host: 10.0.0.1   login: root   password: root\n"
        r = parse_output("hydra", output, 0)
        db_steps = [s for s in r.next_steps if "数据库" in s]
        assert len(db_steps) > 0


# ============================================================
# 5i. WhatWeb parser
# ============================================================

WHATWEB_OUTPUT = """http://target.com [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.0.0.1], JQuery[3.6.0], PHP[7.4.3], Title[Welcome], WordPress[6.4.2]
"""


class TestWhatwebParser:

    def test_technologies_parsed(self):
        r = parse_output("whatweb", WHATWEB_OUTPUT, 0, {"target": "http://target.com"})
        techs = r.structured_data["technologies"]
        assert len(techs) > 0

    def test_server_detected(self):
        r = parse_output("whatweb", WHATWEB_OUTPUT, 0)
        assert "Apache" in r.structured_data["server"]

    def test_cms_detected(self):
        r = parse_output("whatweb", WHATWEB_OUTPUT, 0)
        assert r.structured_data["cms"] == "WordPress"

    def test_language_detected(self):
        r = parse_output("whatweb", WHATWEB_OUTPUT, 0)
        assert r.structured_data["language"] == "PHP"

    def test_wordpress_next_step(self):
        r = parse_output("whatweb", WHATWEB_OUTPUT, 0)
        wp_steps = [s for s in r.next_steps if "wpscan" in s.lower() or "WordPress" in s]
        assert len(wp_steps) > 0

    def test_php_next_step(self):
        r = parse_output("whatweb", WHATWEB_OUTPUT, 0)
        php_steps = [s for s in r.next_steps if "PHP" in s or "LFI" in s]
        assert len(php_steps) > 0

    def test_server_searchsploit_suggestion(self):
        r = parse_output("whatweb", WHATWEB_OUTPUT, 0)
        ss_steps = [s for s in r.next_steps if "searchsploit" in s.lower()]
        assert len(ss_steps) > 0

    def test_summary_includes_server(self):
        r = parse_output("whatweb", WHATWEB_OUTPUT, 0, {"target": "http://target.com"})
        assert "Apache" in r.summary

    def test_summary_includes_cms(self):
        r = parse_output("whatweb", WHATWEB_OUTPUT, 0, {"target": "http://target.com"})
        assert "WordPress" in r.summary

    def test_empty_output(self):
        r = parse_output("whatweb", "", 0, {"target": "http://target.com"})
        assert r.structured_data["technologies"] == []
        assert r.structured_data["server"] == ""
        assert r.structured_data["cms"] == ""

    def test_joomla_next_step(self):
        output = "http://target.com [200 OK] Joomla[3.9.28], PHP[7.4]\n"
        r = parse_output("whatweb", output, 0)
        joomla_steps = [s for s in r.next_steps if "joomscan" in s.lower()]
        assert len(joomla_steps) > 0

    def test_thinkphp_next_step(self):
        output = "http://target.com [200 OK] ThinkPHP[5.0], PHP[7.4]\n"
        r = parse_output("whatweb", output, 0)
        tp_steps = [s for s in r.next_steps if "ThinkPHP" in s]
        assert len(tp_steps) > 0


# ============================================================
# 6. Edge cases
# ============================================================

class TestEdgeCases:

    def test_none_output(self):
        r = parse_output("nmap", None, 0)
        assert isinstance(r, ParsedResult)
        assert r.raw_output == ""

    def test_empty_output_all_parsers(self):
        """Every registered parser should handle empty output gracefully."""
        for name in PARSER_REGISTRY:
            r = parse_output(name, "", 0)
            assert isinstance(r, ParsedResult)
            assert isinstance(r.summary, str)

    def test_none_output_all_parsers(self):
        """Every registered parser should handle None output gracefully."""
        for name in PARSER_REGISTRY:
            r = parse_output(name, None, 0)
            assert isinstance(r, ParsedResult)

    def test_unknown_tool_fallback(self):
        r = parse_output("some_completely_unknown_tool", "output line1\noutput line2\n", 0)
        assert isinstance(r, ParsedResult)
        assert r.tool_name == "some_completely_unknown_tool"
        assert r.structured_data["line_count"] == 3  # 2 lines + trailing empty

    def test_generic_parser_error_lines(self):
        output = "OK line\nERROR: something failed\nWARNING: deprecated feature\nOK again\n"
        r = parse_output("unknown", output, 1)
        assert len(r.structured_data["error_lines"]) >= 1
        # "WARNING: deprecated" matches warning regex (not error regex)
        assert len(r.structured_data["warning_lines"]) >= 1
        assert r.success is False

    def test_generic_parser_success(self):
        output = "result line 1\nresult line 2\n"
        r = parse_output("unknown", output, 0)
        assert r.success is True
        assert "执行成功" in r.summary

    def test_generic_parser_failure_summary(self):
        output = "ERROR: connection refused\n"
        r = parse_output("unknown", output, 1)
        assert "执行失败" in r.summary

    def test_flag_in_output_appends_to_summary(self):
        """If flag is detected, summary should mention it."""
        output = "80/tcp   open  http    Apache\nflag{test_flag_in_nmap}\n"
        r = parse_output("nmap", output, 0)
        assert "flag{test_flag_in_nmap}" in r.flags_found
        assert "Flag" in r.summary or "flag" in r.summary.lower()

    def test_nonzero_return_code(self):
        r = parse_output("nmap", "some output", 1)
        assert r.success is False

    def test_very_large_output_truncated(self):
        output = "x" * 20000
        r = parse_output("unknown", output, 0)
        # raw_output should be truncated by smart_truncate
        assert len(r.raw_output) < 20000
        assert "截断" in r.raw_output

    def test_return_code_zero_is_success(self):
        r = parse_output("nmap", "Nmap scan report for 10.0.0.1\nHost is up.\n", 0)
        assert r.success is True


# ============================================================
# 7. list_parsers
# ============================================================

class TestListParsers:

    def test_returns_dict(self):
        result = list_parsers()
        assert isinstance(result, dict)

    def test_contains_all_14_registered(self):
        result = list_parsers()
        expected_names = {
            "nmap", "masscan",
            "gobuster", "dirb", "ffuf", "feroxbuster",
            "nuclei", "nikto",
            "sqlmap",
            "subfinder", "sublist3r", "amass",
            "hydra",
            "whatweb",
        }
        assert expected_names == set(result.keys())

    def test_parser_class_names(self):
        result = list_parsers()
        assert result["nmap"] == "NmapParser"
        assert result["masscan"] == "MasscanParser"
        assert result["gobuster"] == "GobusterParser"
        assert result["dirb"] == "GobusterParser"
        assert result["ffuf"] == "GobusterParser"
        assert result["feroxbuster"] == "GobusterParser"
        assert result["nuclei"] == "NucleiParser"
        assert result["nikto"] == "NiktoParser"
        assert result["sqlmap"] == "SqlmapParser"
        assert result["subfinder"] == "SubfinderParser"
        assert result["sublist3r"] == "SubfinderParser"
        assert result["amass"] == "SubfinderParser"
        assert result["hydra"] == "HydraParser"
        assert result["whatweb"] == "WhatwebParser"


# ============================================================
# 8. get_parser and register_parser
# ============================================================

class TestGetAndRegisterParser:

    def test_get_known_parser(self):
        p = get_parser("nmap")
        assert isinstance(p, NmapParser)

    def test_get_unknown_parser_returns_generic(self):
        p = get_parser("unknown_tool")
        assert isinstance(p, GenericParser)

    def test_get_parser_case_insensitive(self):
        p = get_parser("NMAP")
        assert isinstance(p, NmapParser)

    def test_register_custom_parser(self):
        """Register a parser and verify it's used."""

        class CustomParser(GenericParser):
            tool_name = "custom_tool"

        register_parser("custom_tool", CustomParser())
        p = get_parser("custom_tool")
        assert isinstance(p, CustomParser)

        # Cleanup
        if "custom_tool" in PARSER_REGISTRY:
            del PARSER_REGISTRY["custom_tool"]


# ============================================================
# 9. Integration: flag detection across parsers
# ============================================================

class TestFlagIntegration:

    def test_flag_in_nmap_output(self):
        output = """Nmap scan report for 10.0.0.1
80/tcp open http
flag{n0t_s0_h1dd3n}
"""
        r = parse_output("nmap", output, 0)
        assert "flag{n0t_s0_h1dd3n}" in r.flags_found

    def test_flag_in_gobuster_output(self):
        output = "/secret (Status: 200) [Size: 100]\nflag{d1r_bust3d}\n"
        r = parse_output("gobuster", output, 0)
        assert "flag{d1r_bust3d}" in r.flags_found

    def test_flag_in_nuclei_output(self):
        output = "[info] [tech-detect] [http] http://target.com flag{nucl31}\n"
        r = parse_output("nuclei", output, 0)
        assert "flag{nucl31}" in r.flags_found

    def test_flag_in_sqlmap_output(self):
        output = "flag{sql_1nj3ct3d}\nParameter: id is vulnerable\n"
        r = parse_output("sqlmap", output, 0)
        assert "flag{sql_1nj3ct3d}" in r.flags_found

    def test_flag_in_hydra_output(self):
        output = "[22][ssh] host: 10.0.0.1 login: flag password: flag{hydr4_cr4ck3d}\n"
        r = parse_output("hydra", output, 0)
        assert "flag{hydr4_cr4ck3d}" in r.flags_found

    def test_multiple_flag_formats_in_one_output(self):
        # Use unique prefixes that won't create substring matches
        output = "flag{one} picoCTF{two} DASCTF{three} htb{four}\n"
        r = parse_output("unknown", output, 0)
        assert "flag{one}" in r.flags_found
        assert "picoCTF{two}" in r.flags_found
        assert "DASCTF{three}" in r.flags_found
        assert "htb{four}" in r.flags_found
        assert len(r.flags_found) >= 4

    def test_flag_summary_enhancement(self):
        """When flags are found, summary should mention it."""
        output = "80/tcp open http\nflag{enhanced_summary}\n"
        r = parse_output("nmap", output, 0)
        # The base parser adds flag mention if not already in summary
        assert any("Flag" in r.summary or "flag" in r.summary.lower() for _ in [1])
