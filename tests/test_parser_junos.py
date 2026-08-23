"""The Juniper Junos parser — the second deterministic vendor.

This file carries more weight than a parser test usually would, because it is
the first evidence that the baseline is genuinely vendor-neutral rather than
Cisco-shaped. Two properties are worth more than field coverage:

* the **same device** in set format and in braces format must produce the same
  baseline, and both must cite lines that really exist in the file they were
  given — the braces walker is ours precisely so line numbers survive;
* Junos absence semantics differ from IOS. A service that is not written is not
  offered, so most absences are conclusive here where the equivalent IOS
  absence is ambiguous. The two parsers must disagree about *absence policy*
  while agreeing about what each field means.
"""

from pathlib import Path

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.observation import Origin
from auditor.models.result import Status
from auditor.engine import ComplianceEngine
from auditor.parsers import CiscoIOSParser, JunosParser, ParserError, registry
from auditor.parsers.junos import JunosStatement
from auditor.rules import load_framework

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
SRX_TEXT = (SAMPLES / "junos_srx.conf").read_text(encoding="utf-8")
FORTIOS_TEXT = (SAMPLES / "fortios_unknown.conf").read_text(encoding="utf-8")

# The same device as samples/junos_srx.conf, as `show configuration` renders it.
BRACES_TEXT = """\
system {
    host-name BRANCH-FW-02;
    domain-name branch.example.net;
    root-authentication {
        encrypted-password "$6$mR7vQpLb$8rTfYh1WqZd6JsEuA4iKmPnVxCbGyRt3pLhBc7YrUeIoAtFgNjW";
    }
    login {
        message "Authorised access only. Activity is logged and monitored.";
        idle-timeout 0;
        user netops {
            class super-user;
        }
    }
    services {
        telnet;
        ssh {
            protocol-version v2;
            root-login deny;
        }
        web-management {
            http {
                interface ge-0/0/0.0;
            }
            https {
                system-generated-certificate;
            }
        }
    }
    ntp {
        server 10.20.30.41;
    }
    syslog {
        host 10.20.30.40 {
            any notice;
        }
        file messages {
            any notice;
        }
    }
}
snmp {
    community public {
        authorization read-only;
    }
    community private {
        authorization read-write;
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.10.0.1/30;
            }
        }
    }
}
"""


@pytest.fixture(scope="module")
def srx() -> SecurityBaselineModel:
    return JunosParser().parse(SRX_TEXT, source_file="samples/junos_srx.conf")


@pytest.fixture(scope="module")
def braces() -> SecurityBaselineModel:
    return JunosParser().parse(BRACES_TEXT, source_file="braces.conf")


@pytest.fixture(scope="module")
def junos_results(srx):
    engine = ComplianceEngine(load_framework("CIS", "juniper_junos"))
    return {result.rule_id: result for result in engine.evaluate(srx)}


def parse(text: str) -> SecurityBaselineModel:
    return JunosParser().parse(text)


# ---------------------------------------------------------------------------
# identity and detection
# ---------------------------------------------------------------------------


def test_identity(srx: SecurityBaselineModel):
    assert srx.provenance.parser_name == "juniper_junos"
    assert srx.provenance.vendor == "juniper"
    assert srx.provenance.os_family == "junos"
    assert srx.hostname.value == "BRANCH-FW-02"
    assert srx.config_line_count == len(SRX_TEXT.splitlines())


def test_each_parser_claims_only_its_own_vendor(hardened_text):
    assert JunosParser.detect(SRX_TEXT) >= 0.8
    assert JunosParser.detect(BRACES_TEXT) >= 0.5
    assert JunosParser.detect(hardened_text) < 0.3
    assert JunosParser.detect(FORTIOS_TEXT) < 0.3
    assert CiscoIOSParser.detect(SRX_TEXT) < 0.3
    assert JunosParser.detect("") == 0.0


def test_the_registry_routes_a_junos_config_to_the_junos_parser():
    parser_cls, score = registry.detect(SRX_TEXT)
    assert parser_cls is JunosParser
    assert score >= 0.8


def test_empty_config_is_an_error_not_a_clean_bill_of_health():
    with pytest.raises(ParserError, match="empty"):
        parse("   \n\n")


def test_a_file_with_no_junos_statements_is_refused():
    with pytest.raises(ParserError, match="No Junos statements"):
        parse("just some prose\nand another line\n")


# ---------------------------------------------------------------------------
# the sample, field by field
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field, expected_value",
    [
        ("hostname", "BRANCH-FW-02"),
        ("telnet_enabled", True),
        ("vty_transport_input", ["ssh", "telnet"]),
        ("vty_exec_timeout_seconds", 0),
        ("ssh_enabled", True),
        ("ssh_version", 2),
        ("http_server_enabled", True),
        ("https_server_enabled", True),
        ("enable_secret_set", True),
        ("enable_password_present", False),
        ("password_encryption", True),
        ("aaa_enabled", False),
        ("logging_enabled", True),
        ("logging_hosts", ["10.20.30.40"]),
        ("logging_buffered", True),
        ("login_banner_present", True),
        ("management_acl_applied", False),
        ("ntp_servers", ["10.20.30.41"]),
    ],
)
def test_sample_values(srx: SecurityBaselineModel, field: str, expected_value):
    observation = getattr(srx, field)
    assert observation.detected is True, f"{field} should be conclusive on this config"
    assert observation.value == expected_value


def test_sample_snmp_communities_are_the_defaults(srx: SecurityBaselineModel):
    communities = srx.snmp_communities.value
    assert [(c.name, c.access) for c in communities] == [("public", "ro"), ("private", "rw")]


def test_only_the_release_dependent_default_escalates(srx: SecurityBaselineModel):
    """A Junos config is a complete document, so almost nothing should escalate.

    The exception is the one setting whose effective value comes from a default
    rather than from the text - which is exactly the case the IOS parser also
    refuses to guess at.
    """
    undetected = [f for f in SecurityBaselineModel.observable_fields() if not getattr(srx, f).detected]
    assert undetected == ["password_min_length"]


def test_reported_line_numbers_match_the_source_file(srx: SecurityBaselineModel):
    """Every cited line number must actually contain the cited text."""
    raw_lines = SRX_TEXT.splitlines()
    checked = 0
    for field in SecurityBaselineModel.observable_fields():
        observation = getattr(srx, field)
        if observation.line_number is None:
            continue
        assert raw_lines[observation.line_number - 1].strip() == observation.source_line, field
        checked += 1
    assert checked >= 10


def test_every_field_is_either_detected_with_evidence_or_explicitly_unknown(srx: SecurityBaselineModel):
    for field in SecurityBaselineModel.observable_fields():
        observation = getattr(srx, field)
        assert observation.origin is Origin.DETERMINISTIC
        if observation.detected:
            assert observation.source_line or observation.note, f"{field} detected with no evidence"
        else:
            assert observation.note, f"{field} unknown with no stated reason"


# ---------------------------------------------------------------------------
# both formats, one baseline
# ---------------------------------------------------------------------------


def test_braces_format_produces_the_same_reading_as_set_format(srx, braces):
    """The same device, rendered two ways, must audit identically.

    Values must match; evidence must not. An SNMP community carries the line it
    was read from, so those are compared on their semantic content alone.
    """
    for field in SecurityBaselineModel.observable_fields():
        left, right = getattr(braces, field), getattr(srx, field)
        assert left.detected == right.detected, field
        if field == "snmp_communities":
            assert [(c.name, c.access) for c in left.value] == [(c.name, c.access) for c in right.value]
            continue
        assert left.value == right.value, field

    assert braces.ssh_version.source_line != srx.ssh_version.source_line


def test_braces_format_cites_lines_from_the_braces_file(braces):
    """The whole reason the brace walker is ours: line numbers must survive."""
    raw_lines = BRACES_TEXT.splitlines()
    checked = 0
    for field in SecurityBaselineModel.observable_fields():
        observation = getattr(braces, field)
        if observation.line_number is None:
            continue
        assert raw_lines[observation.line_number - 1].strip() == observation.source_line, field
        checked += 1
    assert checked >= 10


def test_a_nested_leaf_cites_itself_not_the_block_that_contains_it(braces):
    """`protocol-version v2;` is the evidence, not `ssh {`."""
    assert braces.ssh_version.source_line == "protocol-version v2;"
    assert BRACES_TEXT.splitlines()[braces.ssh_version.line_number - 1].strip() == "protocol-version v2;"


def test_a_statements_meaning_is_its_full_path_not_its_last_word():
    """`ssh` under netconf is an API over SSH, not the interactive SSH server."""
    baseline = parse("set system host-name FW\nset system services netconf ssh\n")

    assert baseline.ssh_enabled.value is False
    assert baseline.vty_transport_input.value == []


# ---------------------------------------------------------------------------
# deactivated statements are configured but not in effect
# ---------------------------------------------------------------------------


def test_a_deactivated_service_is_not_offered():
    baseline = parse(
        "set system host-name FW\n"
        "set system services telnet\n"
        "deactivate system services telnet\n"
        "set system services ssh protocol-version v2\n"
    )

    assert baseline.telnet_enabled.value is False
    assert baseline.vty_transport_input.value == ["ssh"]
    assert any("Deactivated" in warning for warning in baseline.provenance.warnings)


def test_an_inactive_block_in_braces_format_is_not_in_effect():
    baseline = parse(
        "system {\n"
        "    host-name FW;\n"
        "    services {\n"
        "        inactive: telnet;\n"
        "        ssh {\n"
        "            protocol-version v2;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

    assert baseline.telnet_enabled.value is False
    assert baseline.vty_transport_input.value == ["ssh"]


def test_deactivating_a_parent_deactivates_what_it_contains():
    baseline = parse(
        "set system host-name FW\n"
        "set system services web-management http interface ge-0/0/0.0\n"
        "deactivate system services web-management\n"
    )

    assert baseline.http_server_enabled.value is False


# ---------------------------------------------------------------------------
# absence policy: conclusive on Junos where IOS must escalate
# ---------------------------------------------------------------------------


MINIMAL = "set system host-name FW\nset system services ssh protocol-version v2\n"


@pytest.mark.parametrize(
    "field, expected",
    [
        ("http_server_enabled", False),
        ("https_server_enabled", False),
        ("enable_secret_set", False),
        ("enable_password_present", False),
        ("aaa_enabled", False),
        ("logging_enabled", False),
        ("logging_buffered", False),
        ("vty_exec_timeout_seconds", 0),
    ],
)
def test_conclusive_absence_is_detected_as_insecure(field: str, expected):
    """A service Junos does not write is a service the device does not offer."""
    observation = getattr(parse(MINIMAL), field)

    assert observation.detected is True
    assert observation.value == expected
    assert observation.source_line is None, "absence has no line to cite"
    assert observation.note


def test_cleartext_is_ruled_out_by_reading_the_services_block_not_by_absence():
    """With services configured, telnet=False is positive evidence, and cites it."""
    observation = parse(MINIMAL).telnet_enabled

    assert observation.detected is True
    assert observation.value is False
    assert observation.source_line == "set system services ssh protocol-version v2"


def test_a_device_offering_no_management_service_at_all_is_conclusive_too():
    observation = parse("set system host-name FW\nset system syslog file messages any notice\n").telnet_enabled

    assert observation.detected is True
    assert observation.value is False
    assert observation.source_line is None
    assert "no remote-access service" in observation.note


def test_a_missing_ssh_protocol_version_is_the_one_ambiguous_absence():
    baseline = parse("set system host-name FW\nset system services ssh root-login deny\n")

    assert baseline.ssh_enabled.value is True
    assert baseline.ssh_version.detected is False
    assert "release default" in baseline.ssh_version.note
    assert any("protocol-version" in warning for warning in baseline.provenance.warnings)


def test_an_unparseable_protocol_version_escalates_rather_than_guessing():
    baseline = parse("set system host-name FW\nset system services ssh protocol-version both\n")

    assert baseline.ssh_version.detected is False
    assert "Unrecognised" in baseline.ssh_version.note


def test_the_two_parsers_disagree_about_absence_but_agree_about_meaning(insecure_text):
    """IOS cannot know its HTTP default; Junos can. Same field, different evidence."""
    ios = CiscoIOSParser().parse(
        "\n".join(line for line in insecure_text.splitlines() if "ip http server" not in line)
    )
    junos = parse(MINIMAL)

    assert ios.http_server_enabled.detected is False, "IOS default varies by train"
    assert junos.http_server_enabled.detected is True
    assert junos.http_server_enabled.value is False


# ---------------------------------------------------------------------------
# individual settings that need their own reasoning
# ---------------------------------------------------------------------------


def test_idle_timeout_is_minutes_on_the_device_and_seconds_in_the_baseline():
    baseline = parse("set system host-name FW\nset system login class ops idle-timeout 10\n")

    assert baseline.vty_exec_timeout_seconds.value == 600


def test_the_longest_idle_timeout_across_login_classes_wins():
    baseline = parse(
        "set system host-name FW\n"
        "set system login class ops idle-timeout 5\n"
        "set system login class admins idle-timeout 30\n"
    )

    assert baseline.vty_exec_timeout_seconds.value == 1800


def test_a_class_that_never_times_out_beats_every_configured_timeout():
    baseline = parse(
        "set system host-name FW\n"
        "set system login class ops idle-timeout 5\n"
        "set system login class legacy idle-timeout 0\n"
    )

    assert baseline.vty_exec_timeout_seconds.value == 0
    assert "disables the idle timeout" in baseline.vty_exec_timeout_seconds.note


def test_the_loopback_filter_is_what_restricts_management_access():
    """Junos has no per-line access-class: lo0 is where the control plane is guarded."""
    guarded = parse(
        "set system host-name FW\n"
        "set firewall family inet filter PROTECT-RE term MGMT then accept\n"
        "set interfaces lo0 unit 0 family inet filter input PROTECT-RE\n"
    )
    assert guarded.management_acl_applied.value is True
    assert "lo0" in guarded.management_acl_applied.note

    unguarded = parse(
        "set system host-name FW\nset interfaces ge-0/0/0 unit 0 family inet filter input EDGE\n"
    )
    assert unguarded.management_acl_applied.value is False, "a filter on a data port is not RE protection"


def test_an_output_only_loopback_filter_does_not_restrict_who_may_connect():
    baseline = parse(
        "set system host-name FW\nset interfaces lo0 unit 0 family inet filter output ACCOUNTING\n"
    )

    assert baseline.management_acl_applied.value is False


@pytest.mark.parametrize("statement", ["message", "announcement"])
def test_either_banner_statement_counts(statement: str):
    baseline = parse(f'set system host-name FW\nset system login {statement} "Notice."\n')

    assert baseline.login_banner_present.value is True


def test_ntp_servers_are_collected_and_deduplicated():
    baseline = parse(
        "set system host-name FW\n"
        "set system ntp server 10.20.30.41\n"
        "set system ntp server 10.20.30.41 prefer\n"
        "set system ntp server 10.20.30.42\n"
    )

    assert baseline.ntp_servers.value == ["10.20.30.41", "10.20.30.42"]


def test_an_explicit_password_minimum_is_read_rather_than_escalated():
    baseline = parse("set system host-name FW\nset system login password minimum-length 12\n")

    assert baseline.password_min_length.detected is True
    assert baseline.password_min_length.value == 12
    assert baseline.provenance.warnings == []


def test_a_plain_text_password_is_a_stored_credential_failure():
    baseline = parse(
        "set system host-name FW\nset system root-authentication plain-text-password\n"
    )

    assert baseline.enable_password_present.value is True
    assert baseline.password_encryption.value is False
    assert baseline.password_encryption.detected is True


def test_centralised_authentication_needs_both_an_order_and_a_server():
    both = parse(
        "set system host-name FW\n"
        "set system authentication-order [ tacplus password ]\n"
        "set system tacplus-server 10.20.30.45 secret abc\n"
    )
    assert both.aaa_enabled.value is True
    assert not any("authentication-order" in w for w in both.provenance.warnings)

    server_only = parse("set system host-name FW\nset system radius-server 10.20.30.46 secret abc\n")
    assert server_only.aaa_enabled.value is True
    assert any("authentication-order" in w for w in server_only.provenance.warnings)

    order_only = parse("set system host-name FW\nset system authentication-order [ radius password ]\n")
    assert order_only.aaa_enabled.value is True
    assert any("no radius-server" in w for w in order_only.provenance.warnings)


def test_an_snmpv3_only_device_has_no_communities():
    baseline = parse("set system host-name FW\nset snmp v3 usm local-engine user netops\n")

    assert baseline.snmp_communities.detected is True
    assert baseline.snmp_communities.value == []
    assert "SNMPv3-only" in baseline.snmp_communities.note


def test_community_attributes_spread_across_statements_are_collected():
    baseline = parse(
        "set system host-name FW\n"
        "set snmp community corpRO authorization read-only\n"
        "set snmp community corpRO clients 10.20.30.0/24\n"
        "set snmp community corpRO view corpView\n"
    )

    community = baseline.snmp_communities.value[0]
    assert (community.name, community.access) == ("corpRO", "ro")
    assert community.acl == "10.20.30.0/24"
    assert community.view == "corpView"


def test_a_quoted_password_hash_survives_tokenising():
    baseline = parse(
        'set system host-name FW\n'
        'set system root-authentication encrypted-password "$6$abc def$xyz"\n'
    )

    assert baseline.enable_secret_set.value is True


# ---------------------------------------------------------------------------
# statements
# ---------------------------------------------------------------------------


def test_statement_paths_are_matched_by_prefix_not_substring():
    statement = JunosStatement(
        path=("system", "services", "ssh", "protocol-version", "v2"),
        source_line="set system services ssh protocol-version v2",
        line_number=1,
    )

    assert statement.starts_with("system", "services", "ssh") is True
    assert statement.starts_with("system", "services", "ssh", "root-login") is False
    assert statement.text == "system services ssh protocol-version v2"


# ---------------------------------------------------------------------------
# verdicts against the Junos rule pack
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule_id, expected",
    [
        ("CIS-JUNOS-NO-CLEARTEXT-SERVICES", Status.FAIL),
        ("CIS-JUNOS-SNMP-NO-DEFAULT-COMMUNITY", Status.FAIL),
        ("CIS-JUNOS-AAA-CENTRALISED", Status.FAIL),
        ("CIS-JUNOS-IDLE-TIMEOUT", Status.FAIL),
        ("CIS-JUNOS-NO-JWEB-HTTP", Status.FAIL),
        ("CIS-JUNOS-ROOT-AUTH-HASHED", Status.PASS),
        ("CIS-JUNOS-SSH-V2", Status.PASS),
        ("CIS-JUNOS-SYSLOG-DESTINATION", Status.PASS),
        ("CIS-JUNOS-MGMT-FILTER", Status.FAIL),
        ("CIS-JUNOS-SNMP-NO-WRITE", Status.FAIL),
        ("CIS-JUNOS-LOGIN-BANNER", Status.PASS),
        ("CIS-JUNOS-NTP-CONFIGURED", Status.PASS),
        # The one control on this device the configuration text cannot settle.
        ("CIS-JUNOS-PASSWORD-MIN-LENGTH", Status.NEEDS_REVIEW),
    ],
)
def test_sample_verdicts(junos_results, rule_id: str, expected: Status):
    assert junos_results[rule_id].status is expected


def test_remediating_the_sample_turns_every_control_green():
    """No verdict is hardcoded: fix the config and the report must follow."""
    remediated = (
        SRX_TEXT.replace("set system services telnet\n", "")
        .replace("set system services web-management http interface ge-0/0/0.0\n", "")
        .replace("set snmp community public authorization read-only\n", "")
        .replace("set snmp community private authorization read-write\n", "")
        .replace("set system login idle-timeout 0", "set system login class ops idle-timeout 10")
        + "set system authentication-order [ tacplus password ]\n"
        + "set system tacplus-server 10.20.30.45 secret abc\n"
        + "set system login password minimum-length 8\n"
        + "set interfaces lo0 unit 0 family inet filter input PROTECT-RE\n"
    )
    engine = ComplianceEngine(load_framework("CIS", "juniper_junos"))
    results = engine.evaluate(JunosParser().parse(remediated))

    assert [r.status for r in results] == [Status.PASS] * 13, {
        r.rule_id: (r.status, r.reason) for r in results if r.status is not Status.PASS
    }


def test_the_junos_pack_reuses_the_cisco_packs_conditions():
    """Same conditions, different remediation — the baseline is the seam."""
    junos = {rule.id: rule for rule in load_framework("CIS", "juniper_junos").rules}
    cisco = {rule.id: rule for rule in load_framework("CIS", "cisco_ios").rules}

    junos_conditions = sorted(
        rule.condition.model_dump_json() for rule in junos.values()
    )
    cisco_conditions = sorted(
        rule.condition.model_dump_json() for rule in cisco.values()
    )
    assert junos_conditions == cisco_conditions

    for rule in junos.values():
        assert rule.remediation.cli, rule.id
        assert not any("configure terminal" in line for line in rule.remediation.cli), rule.id
