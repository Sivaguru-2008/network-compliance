"""The parser must produce the right baseline for both samples.

These tests pin the *normalization contract*: the value, whether it counts as
detected, and the evidence line behind it.  Everything downstream is derived
from these three things, so if they are right the report is right.
"""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.parsers import CiscoIOSParser, ParserError, registry


# ---------------------------------------------------------------------------
# hardened sample
# ---------------------------------------------------------------------------


def test_hardened_identity(hardened: SecurityBaselineModel):
    assert hardened.hostname.value == "CORE-RTR-01"
    assert hardened.provenance.vendor == "cisco"
    assert hardened.provenance.os_family == "ios"
    assert hardened.source_sha256 and len(hardened.source_sha256) == 64


@pytest.mark.parametrize(
    "field, expected_value",
    [
        ("telnet_enabled", False),
        ("vty_transport_input", ["ssh"]),
        ("vty_exec_timeout_seconds", 300),
        ("ssh_version", 2),
        ("http_server_enabled", False),
        ("https_server_enabled", False),
        ("enable_secret_set", True),
        ("enable_password_present", False),
        ("password_encryption", True),
        ("aaa_enabled", True),
        ("logging_enabled", True),
        ("logging_buffered", True),
        ("logging_hosts", ["10.20.30.40"]),
        ("management_acl_applied", True),
        ("login_banner_present", True),
        ("password_min_length", 8),
        ("ntp_servers", ["10.20.30.41"]),
    ],
)
def test_hardened_values(hardened: SecurityBaselineModel, field: str, expected_value):
    observation = getattr(hardened, field)
    assert observation.detected is True, f"{field} should be conclusively determined"
    assert observation.value == expected_value


def test_hardened_snmp_community_is_not_default(hardened: SecurityBaselineModel):
    communities = hardened.snmp_communities.value
    assert hardened.snmp_communities.detected is True
    assert [c.name for c in communities] == ["Str0ng-R0-C0mmun1ty"]
    assert communities[0].access == "ro"
    assert communities[0].acl == "99"


def test_hardened_has_no_parser_warnings(hardened: SecurityBaselineModel):
    assert hardened.provenance.warnings == []


# ---------------------------------------------------------------------------
# insecure sample
# ---------------------------------------------------------------------------


def test_insecure_identity(insecure: SecurityBaselineModel):
    assert insecure.hostname.value == "BRANCH-SW-07"


@pytest.mark.parametrize(
    "field, expected_value",
    [
        ("telnet_enabled", True),
        ("vty_exec_timeout_seconds", 0),
        ("http_server_enabled", True),
        ("https_server_enabled", True),
        ("enable_secret_set", False),
        ("enable_password_present", True),
        ("password_encryption", False),
        ("aaa_enabled", False),
        ("logging_enabled", False),
        ("logging_buffered", False),
        ("logging_hosts", []),
        ("management_acl_applied", False),
        ("login_banner_present", False),
        ("password_min_length", 0),
        ("ntp_servers", []),
    ],
)
def test_insecure_values(insecure: SecurityBaselineModel, field: str, expected_value):
    observation = getattr(insecure, field)
    assert observation.detected is True, f"{field} should be conclusively determined"
    assert observation.value == expected_value


def test_insecure_transport_all_expands_to_include_telnet(insecure: SecurityBaselineModel):
    """`transport input all` must be understood as permitting cleartext."""
    transports = insecure.vty_transport_input.value
    assert "telnet" in transports
    assert "ssh" in transports


def test_insecure_snmp_communities_are_defaults(insecure: SecurityBaselineModel):
    communities = insecure.snmp_communities.value
    assert [c.name for c in communities] == ["public", "private"]
    assert [c.access for c in communities] == ["ro", "rw"]


def test_insecure_ssh_version_is_undetected(insecure: SecurityBaselineModel):
    """No `ip ssh version` line: unknown, never assumed secure."""
    assert insecure.ssh_version.detected is False
    assert insecure.ssh_version.value is None
    assert "ip ssh version" in insecure.ssh_version.note


# ---------------------------------------------------------------------------
# evidence integrity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sample", ["hardened", "insecure"])
def test_reported_line_numbers_match_the_source_file(request, sample):
    """Every cited line number must actually contain the cited text."""
    baseline = request.getfixturevalue(sample)
    raw_lines = request.getfixturevalue(f"{sample}_text").splitlines()

    checked = 0
    for field in SecurityBaselineModel.observable_fields():
        observation = getattr(baseline, field)
        if observation.line_number is None:
            continue
        actual = raw_lines[observation.line_number - 1].strip()
        assert actual == observation.source_line, f"{field} cites line {observation.line_number}"
        checked += 1
    assert checked >= 5, "expected several fields to carry a concrete evidence line"


@pytest.mark.parametrize("sample", ["hardened", "insecure"])
def test_every_field_is_either_detected_with_evidence_or_explicitly_unknown(request, sample):
    """No field may be silently populated without evidence or a stated reason."""
    baseline = request.getfixturevalue(sample)
    for field in SecurityBaselineModel.observable_fields():
        observation = getattr(baseline, field)
        if observation.detected:
            assert observation.source_line or observation.note, (
                f"{field} is detected but carries neither a source line nor a justification"
            )
        else:
            assert observation.value is None
            assert observation.note, f"{field} is undetected but does not say why"


# ---------------------------------------------------------------------------
# absence policy: ambiguous vs conclusive
# ---------------------------------------------------------------------------

MINIMAL_CONFIG = "hostname EDGE-01\n!\nline vty 0 4\n!\nend\n"


@pytest.fixture(scope="module")
def minimal() -> SecurityBaselineModel:
    return CiscoIOSParser().parse(MINIMAL_CONFIG)


@pytest.mark.parametrize(
    "field",
    ["http_server_enabled", "ssh_version", "telnet_enabled", "vty_transport_input", "vty_exec_timeout_seconds"],
)
def test_ambiguous_absence_is_undetected(minimal: SecurityBaselineModel, field: str):
    """Settings whose IOS default varies by release must never be guessed."""
    assert getattr(minimal, field).detected is False


@pytest.mark.parametrize(
    "field, expected",
    [
        ("enable_secret_set", False),
        ("password_encryption", False),
        ("aaa_enabled", False),
        ("logging_enabled", False),
        ("management_acl_applied", False),
        ("login_banner_present", False),
        ("password_min_length", 0),
        ("ntp_servers", []),
    ],
)
def test_conclusive_absence_is_detected_as_insecure(minimal: SecurityBaselineModel, field: str, expected):
    """Commands that always appear when configured: absence *is* the evidence."""
    observation = getattr(minimal, field)
    assert observation.detected is True
    assert observation.value == expected
    assert observation.source_line is None
    assert observation.note


def test_no_vty_block_leaves_remote_access_undetermined():
    baseline = CiscoIOSParser().parse("hostname EDGE-02\n!\nend\n")
    assert baseline.telnet_enabled.detected is False
    assert "line vty" in baseline.telnet_enabled.note
    assert baseline.management_acl_applied.detected is False


# ---------------------------------------------------------------------------
# management reachability, banner, password policy, time
# ---------------------------------------------------------------------------


def test_one_unrestricted_vty_block_defeats_the_others():
    """Worst case: the block without an access-class is the way in."""
    baseline = CiscoIOSParser().parse(
        "hostname EDGE-03\n"
        "!\n"
        "line vty 0 4\n"
        " access-class 99 in\n"
        " transport input ssh\n"
        "line vty 5 15\n"
        " transport input ssh\n"
        "!\nend\n"
    )

    assert baseline.management_acl_applied.value is False
    assert "1 'line vty' block(s) have no inbound" in baseline.management_acl_applied.note
    assert any("access-class" in w for w in baseline.provenance.warnings)


def test_every_vty_block_restricted_is_a_pass():
    baseline = CiscoIOSParser().parse(
        "hostname EDGE-04\n"
        "!\n"
        "line vty 0 4\n"
        " access-class 99 in\n"
        "line vty 5 15\n"
        " access-class 99 in\n"
        "!\nend\n"
    )

    assert baseline.management_acl_applied.value is True
    assert baseline.management_acl_applied.source_line == "access-class 99 in"


def test_an_outbound_access_class_does_not_restrict_who_may_connect():
    """`access-class N out` governs outbound sessions; direction is the control."""
    baseline = CiscoIOSParser().parse(
        "hostname EDGE-05\n!\nline vty 0 4\n access-class 99 out\n!\nend\n"
    )

    assert baseline.management_acl_applied.value is False


@pytest.mark.parametrize("banner", ["banner login ^C", "banner motd ^C", "banner exec ^C"])
def test_any_banner_kind_counts(banner: str):
    baseline = CiscoIOSParser().parse(f"hostname EDGE-06\n!\n{banner}\nNotice.\n^C\n!\nend\n")

    assert baseline.login_banner_present.value is True
    assert baseline.login_banner_present.source_line == banner


def test_ntp_servers_are_deduplicated_and_vrf_qualified_forms_are_read():
    baseline = CiscoIOSParser().parse(
        "hostname EDGE-07\n"
        "!\n"
        "ntp server 10.20.30.41\n"
        "ntp server 10.20.30.41 prefer\n"
        "ntp server vrf MGMT 10.20.30.42 key 1\n"
        "ntp peer 10.20.30.99\n"
        "!\nend\n"
    )

    assert baseline.ntp_servers.value == ["10.20.30.41", "10.20.30.42"], "a peer is not an authority"


def test_password_min_length_is_read_as_a_number():
    baseline = CiscoIOSParser().parse(
        "hostname EDGE-08\n!\nsecurity passwords min-length 12\n!\nend\n"
    )

    assert baseline.password_min_length.value == 12


# ---------------------------------------------------------------------------
# aggregation, detection, error handling
# ---------------------------------------------------------------------------


def test_worst_case_aggregation_across_vty_blocks():
    """One weak VTY block condemns the device, regardless of the others."""
    config = (
        "hostname MIXED\n"
        "line vty 0 4\n"
        " exec-timeout 5 0\n"
        " transport input ssh\n"
        "line vty 5 15\n"
        " exec-timeout 30 0\n"
        " transport input telnet ssh\n"
        "end\n"
    )
    baseline = CiscoIOSParser().parse(config)
    assert baseline.telnet_enabled.value is True
    assert baseline.telnet_enabled.source_line == "transport input telnet ssh"
    assert baseline.vty_exec_timeout_seconds.value == 1800  # the longest, not the shortest


def test_partially_specified_vty_transport_is_undetected():
    """Clean-looking but incomplete evidence is not proof of a clean device."""
    config = "hostname PARTIAL\nline vty 0 4\n transport input ssh\nline vty 5 15\n exec-timeout 5 0\nend\n"
    baseline = CiscoIOSParser().parse(config)
    assert baseline.telnet_enabled.detected is False


def test_exec_timeout_zero_beats_a_longer_configured_timeout():
    config = (
        "hostname ZERO\n"
        "line vty 0 4\n"
        " exec-timeout 9 0\n"
        " transport input ssh\n"
        "line vty 5 15\n"
        " exec-timeout 0 0\n"
        " transport input ssh\n"
        "end\n"
    )
    baseline = CiscoIOSParser().parse(config)
    assert baseline.vty_exec_timeout_seconds.value == 0


def test_exec_timeout_seconds_component_is_included():
    config = "hostname SEC\nline vty 0 4\n exec-timeout 2 30\n transport input ssh\nend\n"
    baseline = CiscoIOSParser().parse(config)
    assert baseline.vty_exec_timeout_seconds.value == 150


def test_explicitly_disabled_logging_is_a_detected_false():
    config = "hostname NOLOG\nno logging on\nlogging host 10.0.0.1\nend\n"
    baseline = CiscoIOSParser().parse(config)
    assert baseline.logging_enabled.detected is True
    assert baseline.logging_enabled.value is False
    assert baseline.logging_enabled.source_line == "no logging on"


def test_logging_settings_are_not_mistaken_for_syslog_hosts():
    config = "hostname L\nlogging trap informational\nlogging console critical\nend\n"
    baseline = CiscoIOSParser().parse(config)
    assert baseline.logging_hosts.value == []


def test_snmpv3_only_config_has_no_communities():
    config = "hostname V3\nsnmp-server group SECURE v3 priv\nsnmp-server host 10.0.0.9 version 3 priv admin\nend\n"
    baseline = CiscoIOSParser().parse(config)
    assert baseline.snmp_communities.detected is True
    assert baseline.snmp_communities.value == []


def test_detection_scores_ios_high_and_other_vendors_low(hardened_text: str):
    assert CiscoIOSParser.detect(hardened_text) >= 0.8
    assert CiscoIOSParser.detect("set system host-name fw01\nset system services ssh\n") < 0.3
    assert CiscoIOSParser.detect("config system global\n set hostname FGT\nend\n") < 0.3
    assert CiscoIOSParser.detect("") == 0.0


def test_registry_auto_detects_the_cisco_parser(hardened_text: str):
    parser_cls, score = registry.detect(hardened_text)
    assert parser_cls is CiscoIOSParser
    assert score >= 0.8


def test_registry_refuses_to_guess_on_an_unrecognised_vendor():
    """Allied Telesis/unrecognized: Junos, FortiOS and VRP both have deterministic parsers now."""
    with pytest.raises(ParserError, match="Could not confidently identify"):
        registry.detect("create config=test.cfg\nadd ip interface=vlan1\n")


def test_empty_config_is_an_error_not_a_clean_bill_of_health():
    with pytest.raises(ParserError):
        CiscoIOSParser().parse("   \n\n")
