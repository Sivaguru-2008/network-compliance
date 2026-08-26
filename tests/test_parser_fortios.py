"""The Fortinet FortiOS parser — the third deterministic vendor.

Cisco proved the pipeline. Junos proved the baseline was not Cisco-shaped.
FortiOS is here to prove something narrower: that a *setting* in this tool means
the effective state of the device rather than a line that appears in a file.

So the tests that carry the most weight in this file are not the field-coverage
ones. They are:

* **evidence integrity** — the configuration is walked, never rewritten, so a
  cited line number must survive arbitrary text being inserted above it. Two
  tests insert padding and require the citation to move with it.
* **scope isolation** — `allowaccess` under `port1` says nothing about `port2`,
  and an `unset` inside one `edit` block must not reach into another.
* **configured versus effective** — FortiOS has four separate ways to write a
  setting down and leave it out of force (`unset`, `delete`, `set status
  disable`, and the wrong `edit` context), and each one has a test.
* **absence** — FortiOS `show` prints only what differs from the factory
  default, so absence proves a great deal less here than it does on Junos. The
  fields where it proves nothing must escalate rather than pass.
"""

from pathlib import Path

import pytest

from auditor.engine import ComplianceEngine
from auditor.models.baseline import SecurityBaselineModel
from auditor.models.observation import Origin
from auditor.models.result import Status
from auditor.parsers import CiscoIOSParser, FortiosParser, JunosParser, ParserError, registry
from auditor.rules import load_framework

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
FGT_TEXT = (SAMPLES / "fortios_fgt.conf").read_text(encoding="utf-8")
JUNOS_TEXT = (SAMPLES / "junos_srx.conf").read_text(encoding="utf-8")
UNKNOWN_TEXT = (SAMPLES / "unknown_vendor.conf").read_text(encoding="utf-8")

# The smallest configuration that exercises the whole grammar: a global block,
# a table with two entries, and a `config` nested inside an `edit`.
MINIMAL = """\
config system global
    set hostname "FGT-TEST"
    set admintimeout 10
end
config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping https ssh
    next
    edit "port2"
        set ip 10.0.1.1 255.255.255.0
        set allowaccess ping
    next
end
"""


def parse(text: str) -> SecurityBaselineModel:
    return FortiosParser().parse(text)


def interfaces(*blocks: str) -> str:
    """A `config system interface` table built from the given `edit` bodies."""
    return "config system interface\n" + "".join(blocks) + "end\n"


def port(name: str, *lines: str) -> str:
    body = "".join(f"        {line}\n" for line in lines)
    return f'    edit "{name}"\n{body}    next\n'


@pytest.fixture(scope="module")
def fgt() -> SecurityBaselineModel:
    return FortiosParser().parse(FGT_TEXT, source_file="samples/fortios_fgt.conf")


@pytest.fixture(scope="module")
def fortios_results(fgt):
    engine = ComplianceEngine(load_framework("CIS", "fortinet_fortios"))
    return {result.rule_id: result for result in engine.evaluate(fgt)}


# ---------------------------------------------------------------------------
# identity and detection
# ---------------------------------------------------------------------------


def test_identity(fgt: SecurityBaselineModel):
    assert fgt.provenance.parser_name == "fortinet_fortios"
    assert fgt.provenance.vendor == "fortinet"
    assert fgt.provenance.os_family == "fortios"
    assert fgt.hostname.value == "BRANCH-FGT-11"
    assert fgt.config_line_count == len(FGT_TEXT.splitlines())


def test_each_parser_claims_only_its_own_vendor(hardened_text):
    assert FortiosParser.detect(FGT_TEXT) >= 0.8
    assert FortiosParser.detect(MINIMAL) >= 0.5
    assert FortiosParser.detect(hardened_text) < 0.3
    assert FortiosParser.detect(JUNOS_TEXT) < 0.3
    assert FortiosParser.detect(UNKNOWN_TEXT) < 0.3
    assert FortiosParser.detect("") == 0.0


def test_adding_fortios_did_not_disturb_the_other_two_vendors(hardened_text):
    """Detection stays mutually exclusive: nobody's score moved."""
    assert CiscoIOSParser.detect(FGT_TEXT) < 0.3
    assert JunosParser.detect(FGT_TEXT) < 0.3
    assert CiscoIOSParser.detect(hardened_text) >= 0.8
    assert JunosParser.detect(JUNOS_TEXT) >= 0.8


def test_the_registry_routes_a_fortios_config_to_the_fortios_parser():
    parser_cls, score = registry.detect(FGT_TEXT)
    assert parser_cls is FortiosParser
    assert score >= 0.8, "FortiOS should be identified with high confidence"


def test_the_registry_still_refuses_a_vendor_nobody_claims():
    with pytest.raises(ParserError, match="Could not confidently identify"):
        registry.detect(UNKNOWN_TEXT)


def test_empty_config_is_an_error_not_a_clean_bill_of_health():
    for text in ("", "   \n\n", "\t\n"):
        with pytest.raises(ParserError, match="empty"):
            parse(text)


def test_a_file_with_no_fortios_statements_is_refused():
    with pytest.raises(ParserError, match="No FortiOS statements"):
        parse("# a comment\n# and another\n")


# ---------------------------------------------------------------------------
# the sample, field by field
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field, expected_value",
    [
        ("hostname", "BRANCH-FGT-11"),
        ("telnet_enabled", True),
        ("vty_transport_input", ["ssh", "telnet"]),
        ("vty_exec_timeout_seconds", 28800),
        ("ssh_enabled", True),
        ("http_server_enabled", True),
        ("https_server_enabled", True),
        ("management_acl_applied", False),
        ("login_banner_present", False),
        ("enable_secret_set", True),
        ("enable_password_present", False),
        ("password_encryption", True),
        ("password_min_length", 0),
        ("aaa_enabled", False),
        ("logging_enabled", True),
        ("logging_hosts", ["192.168.20.40"]),
    ],
)
def test_sample_values(fgt: SecurityBaselineModel, field: str, expected_value):
    observation = getattr(fgt, field)
    assert observation.detected is True, f"{field} should be conclusive on this config"
    assert observation.value == expected_value


def test_sample_snmp_community_is_a_default_name(fgt: SecurityBaselineModel):
    communities = fgt.snmp_communities.value
    assert [(c.name, c.access) for c in communities] == [("public", "ro")]
    # The host list comes from `config hosts` nested inside the community's edit.
    assert communities[0].acl == "192.168.20.50"


def test_only_the_unstated_defaults_escalate(fgt: SecurityBaselineModel):
    """Everything undetected here is a FortiOS default the text does not state.

    Not a coverage gap: each of these three is a value the device has and the
    configuration declines to write down, which is exactly the case the
    architecture answers with NEEDS_REVIEW rather than a guess.
    """
    original_fields = {
        "hostname", "telnet_enabled", "vty_transport_input", "vty_exec_timeout_seconds",
        "ssh_enabled", "ssh_version", "http_server_enabled", "https_server_enabled",
        "management_acl_applied", "login_banner_present", "enable_secret_set",
        "enable_password_present", "password_encryption", "password_min_length",
        "aaa_enabled", "snmp_communities", "logging_enabled", "logging_hosts",
        "logging_buffered", "ntp_servers"
    }
    undetected = [f for f in SecurityBaselineModel.observable_fields() if not getattr(fgt, f).detected]
    undetected_original = [f for f in undetected if f in original_fields]
    assert undetected_original == ["ssh_version", "logging_buffered", "ntp_servers"]


def test_every_field_is_either_detected_with_evidence_or_explicitly_unknown(fgt):
    for field in SecurityBaselineModel.observable_fields():
        observation = getattr(fgt, field)
        assert observation.origin is Origin.DETERMINISTIC
        if observation.detected:
            assert observation.source_line or observation.note, f"{field} detected with no evidence"
        else:
            assert observation.note, f"{field} unknown with no stated reason"


def test_the_parser_never_calls_a_model(fgt: SecurityBaselineModel):
    """Deterministic means deterministic: no origin here may be LLM or HYBRID."""
    origins = {getattr(fgt, f).origin for f in SecurityBaselineModel.observable_fields()}
    assert origins == {Origin.DETERMINISTIC}
    assert FortiosParser.is_fallback is False
    assert FortiosParser.base_confidence == 1.0


# ---------------------------------------------------------------------------
# evidence integrity: the file the operator handed us, not a rewritten copy
# ---------------------------------------------------------------------------


def test_reported_line_numbers_match_the_source_file(fgt: SecurityBaselineModel):
    """Every cited line number must actually contain the cited text."""
    raw_lines = FGT_TEXT.splitlines()
    checked = 0
    for field in SecurityBaselineModel.observable_fields():
        observation = getattr(fgt, field)
        if observation.line_number is None:
            continue
        assert raw_lines[observation.line_number - 1].strip() == observation.source_line, field
        checked += 1
    assert checked >= 10


def test_snmp_community_evidence_also_points_at_a_real_line(fgt: SecurityBaselineModel):
    raw_lines = FGT_TEXT.splitlines()
    for community in fgt.snmp_communities.value:
        assert raw_lines[community.line_number - 1].strip() == community.source_line


def test_inserting_lines_before_a_finding_moves_the_line_it_cites():
    """The whole reason the block walk is ours: no renumbering, ever.

    Nothing about the configuration changes except how far down the file it
    starts. Every citation must move by exactly that much, and must still land
    on the line it names.
    """
    config = interfaces(port("port1", "set allowaccess ping https ssh telnet"))
    padded = "# an irrelevant comment\n\n# and another\n" * 4 + config

    before, after = parse(config), parse(padded)
    offset = len(padded.splitlines()) - len(config.splitlines())
    assert offset == 12

    for field in ("telnet_enabled", "ssh_enabled", "https_server_enabled", "vty_transport_input"):
        original, shifted = getattr(before, field), getattr(after, field)
        assert shifted.value == original.value, field
        assert shifted.source_line == original.source_line, field
        assert shifted.line_number == original.line_number + offset, field
        assert (
            padded.splitlines()[shifted.line_number - 1].strip() == shifted.source_line
        ), field


def test_every_citation_survives_padding_of_the_whole_sample():
    """The same property across every field of a real configuration."""
    padded = "#\n# padding that means nothing\n#\n" + FGT_TEXT
    before, after = parse(FGT_TEXT), parse(padded)

    checked = 0
    for field in SecurityBaselineModel.observable_fields():
        original, shifted = getattr(before, field), getattr(after, field)
        if original.line_number is None:
            assert shifted.line_number is None, field
            continue
        assert shifted.line_number == original.line_number + 3, field
        assert padded.splitlines()[shifted.line_number - 1].strip() == shifted.source_line
        checked += 1
    assert checked >= 10


def test_evidence_is_the_original_line_not_a_reconstruction():
    """Odd but legal spacing is reported back exactly as the operator wrote it."""
    config = "config system global\n\t  set    admintimeout   15\nend\n"
    baseline = parse(config)

    assert baseline.vty_exec_timeout_seconds.value == 900
    assert baseline.vty_exec_timeout_seconds.source_line == "set    admintimeout   15"
    assert config.splitlines()[1].strip() == baseline.vty_exec_timeout_seconds.source_line


def test_a_nested_setting_cites_itself_not_the_block_that_contains_it():
    """`set allowaccess …` is the evidence, not `config system interface`."""
    baseline = parse(interfaces(port("port1", "set allowaccess ping telnet")))

    assert baseline.telnet_enabled.source_line == "set allowaccess ping telnet"
    assert baseline.telnet_enabled.line_number == 3


def test_comments_and_blank_lines_are_skipped_without_shifting_anything():
    config = (
        "# a header comment\n"
        "\n"
        "config system global\n"
        "\n"
        "    # why this timeout was chosen\n"
        "    set admintimeout 7\n"
        "\n"
        "end\n"
    )
    baseline = parse(config)

    assert baseline.vty_exec_timeout_seconds.value == 420
    assert baseline.vty_exec_timeout_seconds.line_number == 6
    assert config.splitlines()[5].strip() == "set admintimeout 7"


# ---------------------------------------------------------------------------
# block structure: config / edit / set / next / end
# ---------------------------------------------------------------------------


def test_a_basic_config_edit_set_end_block_reads_through():
    baseline = parse(MINIMAL)

    assert baseline.hostname.value == "FGT-TEST"
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.ssh_enabled.value is True
    assert baseline.telnet_enabled.value is False
    structural = ("Unmatched", "never closed", "not a FortiOS statement")
    assert not [
        w for w in baseline.provenance.warnings if any(k in w for k in structural)
    ], "a well-formed config must raise no structural complaint"


def test_multiple_edit_blocks_do_not_leak_into_one_another():
    """port2's reading must not be contaminated by port1's, or the reverse."""
    parser = FortiosParser()
    parser.parse(
        interfaces(
            port("port1", "set allowaccess ping https ssh telnet"),
            port("port2", "set allowaccess ping"),
        )
    )
    port1 = parser.first("system", "interface", "port1", "allowaccess")
    port2 = parser.first("system", "interface", "port2", "allowaccess")

    assert port1.values == ("ping", "https", "ssh", "telnet")
    assert port2.values == ("ping",)


def test_the_worst_interface_decides_and_the_evidence_names_it():
    baseline = parse(
        interfaces(
            port("port1", "set allowaccess ping https ssh"),
            port("port2", "set allowaccess ping telnet"),
        )
    )

    assert baseline.telnet_enabled.value is True
    assert baseline.telnet_enabled.source_line == "set allowaccess ping telnet"
    assert baseline.vty_transport_input.value == ["ssh", "telnet"]


def test_a_config_nested_inside_an_edit_nests_in_the_path_too():
    """`config hosts` under an SNMP community is a table inside a table entry."""
    parser = FortiosParser()
    parser.parse(
        "config system snmp community\n"
        "    edit 1\n"
        '        set name "netops"\n'
        "        config hosts\n"
        "            edit 1\n"
        "                set ip 10.0.0.5 255.255.255.255\n"
        "            next\n"
        "        end\n"
        "    next\n"
        "end\n"
    )
    host_ip = parser.first("system", "snmp", "community", "1", "hosts", "1", "ip")

    assert host_ip is not None
    assert host_ip.values == ("10.0.0.5", "255.255.255.255")
    assert host_ip.line_number == 6


def test_two_tables_may_both_have_an_entry_named_one():
    """The nested `edit 1` and the outer `edit 1` are different objects."""
    parser = FortiosParser()
    parser.parse(
        "config system snmp community\n"
        "    edit 1\n"
        '        set name "outer"\n'
        "        config hosts\n"
        "            edit 1\n"
        "                set ip 10.0.0.5 255.255.255.255\n"
        "            next\n"
        "        end\n"
        "    next\n"
        "end\n"
    )
    assert parser.first("system", "snmp", "community", "1", "name").value == "outer"
    assert parser.first("system", "snmp", "community", "1", "hosts", "1", "name") is None


def test_a_settings_meaning_is_its_full_path_not_its_attribute_name():
    """A `hostname` in the DNS database is not the device's hostname."""
    baseline = parse(
        "config system dns-database\n"
        '    edit "example.net"\n'
        "        config dns-entry\n"
        "            edit 1\n"
        '                set hostname "www"\n'
        "            next\n"
        "        end\n"
        "    next\n"
        "end\n"
    )
    assert baseline.hostname.detected is False


# ---------------------------------------------------------------------------
# unset and delete: written down, not in force
# ---------------------------------------------------------------------------


def test_unset_clears_a_setting_made_earlier_in_the_same_block():
    parser = FortiosParser()
    parser.parse(
        interfaces(port("port1", "set allowaccess ping https ssh telnet", "unset allowaccess"))
    )
    assert parser.first("system", "interface", "port1", "allowaccess") is None
    assert [s.values for s in parser.cleared("system", "interface")] == [
        ("ping", "https", "ssh", "telnet")
    ]


def test_unset_is_not_the_same_as_denying_everything():
    """`unset` returns the attribute to a factory default the text never states.

    Reading it as "no access permitted" would hand a clean pass to a device
    whose real allowaccess is whatever its interface role defaults to.
    """
    unset = parse(interfaces(port("port1", "set allowaccess ping https ssh", "unset allowaccess")))
    written = parse(interfaces(port("port1", "set allowaccess ping https ssh")))

    assert unset.telnet_enabled.detected is False
    assert unset.vty_transport_input.detected is False
    assert "factory default" in unset.telnet_enabled.note

    assert written.telnet_enabled.detected is True
    assert written.telnet_enabled.value is False
    assert written.vty_transport_input.value == ["ssh"]


def test_an_unset_in_one_edit_block_does_not_reach_into_another():
    parser = FortiosParser()
    baseline = parser.parse(
        interfaces(
            port("port1", "set allowaccess ping https ssh telnet"),
            port("port2", "set allowaccess ping https ssh", "unset allowaccess"),
        )
    )
    assert parser.first("system", "interface", "port1", "allowaccess").values == (
        "ping",
        "https",
        "ssh",
        "telnet",
    )
    assert parser.first("system", "interface", "port2", "allowaccess") is None
    # port1 still proves the violation, even though port2 is now unknown.
    assert baseline.telnet_enabled.value is True


def test_delete_removes_a_table_entry_and_everything_under_it():
    parser = FortiosParser()
    parser.parse(
        "config system snmp community\n"
        "    edit 1\n"
        '        set name "public"\n'
        "    next\n"
        "    delete 1\n"
        "end\n"
    )
    assert parser.entries("system", "snmp", "community") == []
    assert parser.first("system", "snmp", "community", "1", "name") is None


def test_delete_leaves_the_other_entries_alone():
    parser = FortiosParser()
    baseline = parser.parse(
        "config system snmp sysinfo\n"
        "    set status enable\n"
        "end\n"
        "config system snmp community\n"
        "    edit 1\n"
        '        set name "public"\n'
        "    next\n"
        "    edit 2\n"
        '        set name "netops-ro"\n'
        "    next\n"
        "    delete 1\n"
        "end\n"
    )
    assert [e.name for e in parser.entries("system", "snmp", "community")] == ["2"]
    assert [c.name for c in baseline.snmp_communities.value] == ["netops-ro"]


def test_deleting_an_interface_removes_its_allowaccess_from_the_reading():
    baseline = parse(
        interfaces(
            port("port1", "set allowaccess ping https ssh"),
            port("port2", "set allowaccess ping https ssh telnet"),
        ).replace("end\n", "    delete port2\nend\n")
    )
    assert baseline.telnet_enabled.value is False
    assert baseline.vty_transport_input.value == ["ssh"]


# ---------------------------------------------------------------------------
# configured versus effective
# ---------------------------------------------------------------------------


def test_a_disabled_snmp_community_is_not_reachable():
    baseline = parse(
        "config system snmp sysinfo\n"
        "    set status enable\n"
        "end\n"
        "config system snmp community\n"
        "    edit 1\n"
        '        set name "public"\n'
        "        set status disable\n"
        "    next\n"
        "end\n"
    )
    assert baseline.snmp_communities.value == []
    assert any("disabled" in w for w in baseline.provenance.warnings)


def test_a_disabled_snmp_agent_hides_every_community():
    baseline = parse(
        "config system snmp sysinfo\n"
        "    set status disable\n"
        "end\n"
        "config system snmp community\n"
        "    edit 1\n"
        '        set name "public"\n'
        "    next\n"
        "end\n"
    )
    assert baseline.snmp_communities.value == []
    assert baseline.snmp_communities.source_line == "set status disable"


def test_an_enabled_community_is_still_reported():
    """The gate must not swallow the live case it exists to distinguish."""
    baseline = parse(
        "config system snmp sysinfo\n"
        "    set status enable\n"
        "end\n"
        "config system snmp community\n"
        "    edit 1\n"
        '        set name "public"\n'
        "        set status enable\n"
        "    next\n"
        "end\n"
    )
    assert [c.name for c in baseline.snmp_communities.value] == ["public"]


def test_a_disabled_password_policy_enforces_nothing():
    """A minimum-length that is switched off is not a minimum length."""
    baseline = parse(
        "config system password-policy\n"
        "    set status disable\n"
        "    set minimum-length 16\n"
        "end\n"
    )
    assert baseline.password_min_length.detected is True
    assert baseline.password_min_length.value == 0
    assert baseline.password_min_length.source_line == "set status disable"


def test_an_enabled_password_policy_is_read():
    baseline = parse(
        "config system password-policy\n"
        "    set status enable\n"
        "    set minimum-length 12\n"
        "end\n"
    )
    assert baseline.password_min_length.value == 12
    assert baseline.password_min_length.source_line == "set minimum-length 12"


def test_a_password_policy_that_states_no_status_escalates():
    baseline = parse("config system password-policy\n    set minimum-length 12\nend\n")

    assert baseline.password_min_length.detected is False
    assert "factory default" in baseline.password_min_length.note


def test_a_disabled_syslog_server_ships_nothing():
    baseline = parse(
        "config log syslogd setting\n"
        "    set status disable\n"
        '    set server "10.0.0.9"\n'
        "end\n"
    )
    assert baseline.logging_hosts.value == []
    assert any("disabled" in w for w in baseline.provenance.warnings)


def test_an_enabled_syslog_server_is_a_destination():
    baseline = parse(
        "config log syslogd setting\n"
        "    set status enable\n"
        '    set server "10.0.0.9"\n'
        "end\n"
    )
    assert baseline.logging_hosts.value == ["10.0.0.9"]
    assert baseline.logging_enabled.value is True


def test_several_syslog_slots_are_collected():
    baseline = parse(
        "config log syslogd setting\n"
        "    set status enable\n"
        '    set server "10.0.0.9"\n'
        "end\n"
        "config log syslogd2 setting\n"
        "    set status enable\n"
        '    set server "10.0.0.10"\n'
        "end\n"
    )
    assert baseline.logging_hosts.value == ["10.0.0.10", "10.0.0.9"]


# ---------------------------------------------------------------------------
# management access: one `allowaccess` statement, five fields
# ---------------------------------------------------------------------------


def test_one_allowaccess_statement_feeds_five_fields():
    baseline = parse(interfaces(port("wan", "set allowaccess ping https http ssh telnet snmp")))

    assert baseline.telnet_enabled.value is True
    assert baseline.ssh_enabled.value is True
    assert baseline.http_server_enabled.value is True
    assert baseline.https_server_enabled.value is True
    assert baseline.vty_transport_input.value == ["ssh", "telnet"]


def test_ping_and_snmp_are_not_login_transports():
    """`allowaccess` is not a transport list; only two of its keywords are logins."""
    baseline = parse(interfaces(port("port1", "set allowaccess ping snmp fgfm probe-response")))

    assert baseline.vty_transport_input.value == []
    assert baseline.telnet_enabled.value is False
    assert baseline.ssh_enabled.value is False


def test_http_and_https_are_read_separately():
    baseline = parse(interfaces(port("port1", "set allowaccess ping https ssh")))

    assert baseline.https_server_enabled.value is True
    assert baseline.http_server_enabled.value is False


def test_an_interface_with_no_allowaccess_prevents_a_clean_pass():
    """Clean-but-incomplete evidence is not proof, exactly as on IOS."""
    baseline = parse(
        interfaces(
            port("port1", "set allowaccess ping https ssh"),
            port("port2", "set ip 10.0.1.1 255.255.255.0"),
        )
    )
    assert baseline.telnet_enabled.detected is False
    assert baseline.vty_transport_input.detected is False
    assert "factory default" in baseline.telnet_enabled.note


def test_positive_evidence_outweighs_incomplete_evidence():
    """One interface offering telnet condemns the device whatever the rest say."""
    baseline = parse(
        interfaces(
            port("port1", "set allowaccess ping https ssh telnet"),
            port("port2", "set ip 10.0.1.1 255.255.255.0"),
        )
    )
    assert baseline.telnet_enabled.detected is True
    assert baseline.telnet_enabled.value is True


def test_a_config_with_no_interface_table_cannot_be_read_as_locked_down():
    baseline = parse("config system global\n    set hostname \"FGT\"\nend\n")

    for field in ("telnet_enabled", "ssh_enabled", "http_server_enabled", "https_server_enabled"):
        assert getattr(baseline, field).detected is False, field
    assert baseline.vty_transport_input.detected is False


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------


def test_ssh_v1_compatibility_enabled_is_protocol_version_one():
    baseline = parse(
        "config system global\n    set admin-ssh-v1 enable\nend\n"
        + interfaces(port("port1", "set allowaccess ssh"))
    )
    assert baseline.ssh_version.value == 1
    assert baseline.ssh_version.source_line == "set admin-ssh-v1 enable"


def test_ssh_v1_compatibility_disabled_is_protocol_version_two():
    baseline = parse(
        "config system global\n    set admin-ssh-v1 disable\nend\n"
        + interfaces(port("port1", "set allowaccess ssh"))
    )
    assert baseline.ssh_version.value == 2


def test_a_missing_admin_ssh_v1_escalates_rather_than_assuming_two():
    baseline = parse(interfaces(port("port1", "set allowaccess ssh")))

    assert baseline.ssh_enabled.value is True
    assert baseline.ssh_version.detected is False
    assert "release default" in baseline.ssh_version.note


def test_no_ssh_anywhere_means_no_version_is_enforced():
    baseline = parse(interfaces(port("port1", "set allowaccess ping https")))

    assert baseline.ssh_enabled.value is False
    assert baseline.ssh_version.detected is False
    assert "no protocol version is enforced" in baseline.ssh_version.note


# ---------------------------------------------------------------------------
# trusthosts: FortiOS has no access-class and no loopback filter
# ---------------------------------------------------------------------------


def admins(*bodies: str) -> str:
    return "config system admin\n" + "".join(bodies) + "end\n"


def test_a_trusthost_restricts_an_account():
    baseline = parse(admins(port("admin", "set trusthost1 10.20.30.0 255.255.255.0")))

    assert baseline.management_acl_applied.value is True
    assert baseline.management_acl_applied.source_line == "set trusthost1 10.20.30.0 255.255.255.0"


def test_the_factory_trusthost_restricts_nothing():
    """`0.0.0.0 0.0.0.0` is every source address, which is not a restriction."""
    baseline = parse(admins(port("admin", "set trusthost1 0.0.0.0 0.0.0.0")))

    assert baseline.management_acl_applied.value is False


def test_an_account_with_no_trusthost_is_reachable_from_anywhere():
    baseline = parse(admins(port("admin", 'set accprofile "super_admin"')))

    assert baseline.management_acl_applied.detected is True
    assert baseline.management_acl_applied.value is False


def test_one_unrestricted_account_condemns_the_device():
    baseline = parse(
        admins(
            port("netops", "set trusthost1 10.20.30.0 255.255.255.0"),
            port("backup-admin", 'set accprofile "super_admin"'),
        )
    )
    assert baseline.management_acl_applied.value is False
    assert "backup-admin" in baseline.management_acl_applied.note


def test_a_later_trusthost_slot_counts_just_as_much():
    baseline = parse(
        admins(port("admin", "set trusthost1 0.0.0.0 0.0.0.0", "set trusthost3 10.0.0.0 255.0.0.0"))
    )
    assert baseline.management_acl_applied.value is True


def test_no_admin_table_at_all_cannot_be_ruled_on():
    baseline = parse(MINIMAL)

    assert baseline.management_acl_applied.detected is False


# ---------------------------------------------------------------------------
# credentials
# ---------------------------------------------------------------------------


def test_enc_marks_a_stored_hash():
    baseline = parse(admins(port("admin", "set password ENC AK1abcdef0123456789")))

    assert baseline.enable_secret_set.value is True
    assert baseline.enable_password_present.value is False
    assert baseline.password_encryption.value is True


def test_a_password_without_enc_is_a_cleartext_credential():
    baseline = parse(admins(port("admin", "set password Summer2024!")))

    assert baseline.enable_password_present.value is True
    assert baseline.password_encryption.value is False
    assert baseline.enable_secret_set.value is False


def test_an_admin_account_with_no_password_is_a_conclusive_absence():
    baseline = parse(admins(port("admin", 'set accprofile "super_admin"')))

    assert baseline.enable_secret_set.detected is True
    assert baseline.enable_secret_set.value is False


# ---------------------------------------------------------------------------
# centralised authentication
# ---------------------------------------------------------------------------


def test_centralised_authentication_needs_a_server_and_an_account_using_it():
    both = parse(
        'config user radius\n    edit "AUTH"\n        set server "10.0.0.9"\n    next\nend\n'
        + admins(port("netops", "set remote-auth enable"))
    )
    assert both.aaa_enabled.value is True
    assert not [w for w in both.provenance.warnings if "authentication" in w or "remote-auth" in w]


def test_a_server_nobody_authenticates_against_is_warned_about():
    baseline = parse('config user radius\n    edit "AUTH"\n        set server "10.0.0.9"\n    next\nend\n')

    assert baseline.aaa_enabled.value is True
    assert any("still local" in w for w in baseline.provenance.warnings)


def test_an_account_pointed_at_a_server_that_does_not_exist_is_warned_about():
    baseline = parse(admins(port("netops", "set remote-auth enable")))

    assert baseline.aaa_enabled.value is True
    assert any("fall back" in w for w in baseline.provenance.warnings)


def test_neither_means_local_only_and_that_is_conclusive():
    baseline = parse(MINIMAL)

    assert baseline.aaa_enabled.detected is True
    assert baseline.aaa_enabled.value is False


# ---------------------------------------------------------------------------
# banner, NTP
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("attribute", ["pre-login-banner", "post-login-banner"])
def test_either_banner_counts(attribute: str):
    baseline = parse(f"config system global\n    set {attribute} enable\nend\n")

    assert baseline.login_banner_present.value is True


def test_a_banner_explicitly_disabled_is_no_banner():
    baseline = parse("config system global\n    set pre-login-banner disable\nend\n")

    assert baseline.login_banner_present.detected is True
    assert baseline.login_banner_present.value is False


def test_named_ntp_servers_are_collected():
    baseline = parse(
        "config system ntp\n"
        "    set ntpsync enable\n"
        "    set type custom\n"
        "    config ntpserver\n"
        "        edit 1\n"
        '            set server "10.0.0.1"\n'
        "        next\n"
        "        edit 2\n"
        '            set server "10.0.0.2"\n'
        "        next\n"
        "    end\n"
        "end\n"
    )
    assert baseline.ntp_servers.value == ["10.0.0.1", "10.0.0.2"]


def test_ntpsync_disabled_is_a_conclusive_absence_of_time_sync():
    baseline = parse("config system ntp\n    set ntpsync disable\nend\n")

    assert baseline.ntp_servers.detected is True
    assert baseline.ntp_servers.value == []


def test_the_fortiguard_default_is_synchronised_but_names_no_address():
    """Neither a pass nor a fail: the device has a time source it will not name."""
    baseline = parse("config system ntp\n    set ntpsync enable\nend\n")

    assert baseline.ntp_servers.detected is False
    assert "FortiGuard" in baseline.ntp_servers.note


def test_no_ntp_block_at_all_escalates():
    baseline = parse(MINIMAL)

    assert baseline.ntp_servers.detected is False


# ---------------------------------------------------------------------------
# absence policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field, expected",
    [
        ("login_banner_present", False),
        ("password_min_length", 0),
        ("aaa_enabled", False),
        ("logging_hosts", []),
    ],
)
def test_conclusive_absence_is_detected_as_insecure(field: str, expected):
    """These features are off in every release until configured, and configuring
    them writes the block, so silence really is evidence."""
    observation = getattr(parse(MINIMAL), field)

    assert observation.detected is True
    assert observation.value == expected
    assert observation.source_line is None
    assert observation.note


@pytest.mark.parametrize(
    "field",
    ["ssh_version", "logging_buffered", "ntp_servers", "management_acl_applied"],
)
def test_ambiguous_absence_escalates_rather_than_guessing(field: str):
    """Each of these has a FortiOS default the configuration text does not state."""
    observation = getattr(parse(MINIMAL), field)

    assert observation.detected is False
    assert observation.value is None
    assert observation.note


def test_a_missing_admintimeout_escalates():
    """A `show` omits a setting left at its default, so absence proves nothing."""
    baseline = parse('config system global\n    set hostname "FGT"\nend\n')

    assert baseline.vty_exec_timeout_seconds.detected is False
    assert "factory idle timeout" in baseline.vty_exec_timeout_seconds.note


def test_admintimeout_zero_is_never():
    baseline = parse("config system global\n    set admintimeout 0\nend\n")

    assert baseline.vty_exec_timeout_seconds.value == 0
    assert "disables" in baseline.vty_exec_timeout_seconds.note


def test_the_three_vendors_disagree_about_absence_but_agree_about_meaning(insecure_text):
    """`ntp_servers` on a config that mentions no NTP at all.

    IOS writes `ntp server` when configured, so absence is conclusive. FortiOS
    synchronises against FortiGuard out of the box and a `show` prints nothing,
    so the same silence settles nothing. Same field, same meaning, two honest
    and different readings.
    """
    ios = CiscoIOSParser().parse(insecure_text)
    fortios = parse(MINIMAL)

    assert ios.ntp_servers.detected is True and ios.ntp_servers.value == []
    assert fortios.ntp_servers.detected is False


# ---------------------------------------------------------------------------
# similarly named settings must not be confused
# ---------------------------------------------------------------------------


def test_admin_console_timeout_is_not_admintimeout():
    """Prefix matching is on whole path segments, not on string prefixes."""
    baseline = parse("config system global\n    set admin-console-timeout 0\nend\n")

    assert baseline.vty_exec_timeout_seconds.detected is False


def test_a_fortianalyzer_server_is_not_a_syslog_server():
    baseline = parse(
        "config log fortianalyzer setting\n"
        "    set status enable\n"
        '    set server "10.0.0.9"\n'
        "end\n"
    )
    assert baseline.logging_hosts.value == []


def test_a_dns_server_is_not_a_syslog_server():
    baseline = parse('config system dns\n    set primary 10.0.0.53\nend\n')

    assert baseline.logging_hosts.value == []


def test_a_local_user_password_is_not_an_administrator_password():
    """`config user local` holds VPN users, not administrators."""
    baseline = parse(
        'config user local\n    edit "vpnuser"\n        set passwd ENC AK1xyz\n    next\nend\n'
        + admins(port("admin", 'set accprofile "super_admin"'))
    )
    assert baseline.enable_secret_set.value is False


def test_an_allowaccess_outside_the_interface_table_is_ignored():
    baseline = parse(
        "config system sdwan\n"
        "    config zone\n"
        "        edit 1\n"
        "            set allowaccess telnet\n"
        "        next\n"
        "    end\n"
        "end\n"
        + interfaces(port("port1", "set allowaccess ping https ssh"))
    )
    assert baseline.telnet_enabled.value is False


def test_an_snmp_user_is_not_an_snmp_community():
    baseline = parse(
        "config system snmp sysinfo\n"
        "    set status enable\n"
        "end\n"
        'config system snmp user\n    edit "public"\n        set queries enable\n    next\nend\n'
    )
    assert baseline.snmp_communities.detected is True
    assert baseline.snmp_communities.value == []


# ---------------------------------------------------------------------------
# malformed and incomplete configuration
# ---------------------------------------------------------------------------


def test_a_truncated_block_still_yields_a_baseline_and_a_warning():
    baseline = parse('config system global\n    set hostname "FGT"\n')

    assert baseline.hostname.value == "FGT"
    assert any("never closed" in w for w in baseline.provenance.warnings)


def test_an_unmatched_end_is_reported_not_crashed_on():
    baseline = parse('config system global\n    set hostname "FGT"\nend\nend\n')

    assert baseline.hostname.value == "FGT"
    assert any("Unmatched 'end'" in w for w in baseline.provenance.warnings)


def test_an_unmatched_next_is_reported():
    baseline = parse('config system global\n    set hostname "FGT"\n    next\nend\n')

    assert baseline.hostname.value == "FGT"
    assert any("Unmatched 'next'" in w for w in baseline.provenance.warnings)


def test_an_edit_left_open_does_not_swallow_the_next_table():
    """`end` closes back to the innermost `config`, discarding a dangling `edit`."""
    baseline = parse(
        "config system interface\n"
        '    edit "port1"\n'
        "        set allowaccess ping https ssh telnet\n"
        "end\n"
        + "config system global\n    set hostname \"FGT\"\nend\n"
    )
    assert baseline.hostname.value == "FGT"
    assert baseline.telnet_enabled.value is True


def test_prose_is_ignored_rather_than_parsed_into_a_fictional_baseline():
    baseline = parse(
        "config system global\n"
        "    The firewall should really have a shorter timeout.\n"
        '    set hostname "FGT"\n'
        "end\n"
    )
    assert baseline.hostname.value == "FGT"
    assert baseline.vty_exec_timeout_seconds.detected is False
    assert any("not a FortiOS statement" in w for w in baseline.provenance.warnings)


def test_a_set_with_no_attribute_is_skipped():
    baseline = parse('config system global\n    set\n    set hostname "FGT"\nend\n')

    assert baseline.hostname.value == "FGT"


def test_an_unparseable_admintimeout_escalates_rather_than_guessing():
    baseline = parse("config system global\n    set admintimeout never\nend\n")

    assert baseline.vty_exec_timeout_seconds.detected is False
    assert "Unrecognised" in baseline.vty_exec_timeout_seconds.note


def test_a_multi_line_value_does_not_close_the_block_that_contains_it():
    """A certificate body contains words; none of them may act as syntax.

    Regression: an `end` on its own line inside a quoted blob used to close the
    real block, so every setting after it landed at the wrong path.
    """
    baseline = parse(
        "config system global\n"
        '    set certificate "-----BEGIN CERTIFICATE-----\n'
        "end\n"
        "next\n"
        '-----END CERTIFICATE-----"\n'
        "    set hostname \"FGT\"\n"
        "    set admintimeout 10\n"
        "end\n"
    )
    assert baseline.hostname.value == "FGT"
    assert baseline.vty_exec_timeout_seconds.value == 600


def test_a_quoted_value_keeps_its_spaces():
    baseline = parse('config system global\n    set hostname "BRANCH FGT 11"\nend\n')

    assert baseline.hostname.value == "BRANCH FGT 11"


def test_a_multi_vdom_configuration_reads_the_global_block_and_says_so():
    baseline = parse(
        "config global\n"
        "config system global\n"
        '    set hostname "FGT-VDOM"\n'
        "    set admintimeout 10\n"
        "end\n"
        "end\n"
    )
    assert baseline.hostname.value == "FGT-VDOM"
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert any("Multi-VDOM" in w for w in baseline.provenance.warnings)


# ---------------------------------------------------------------------------
# verdicts against the FortiOS rule pack
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule_id, expected",
    [
        ("CIS-FORTIOS-2.4.5", Status.FAIL),
        ("CIS-FORTIOS-2.4.2", Status.FAIL),
        ("CIS-FORTIOS-2.3.1", Status.FAIL),
        ("CIS-FORTIOS-AAA-CENTRALISED", Status.FAIL),
        ("CIS-FORTIOS-2.4.4", Status.FAIL),
        ("CIS-FORTIOS-2.4.5-HTTP", Status.FAIL),
        ("CIS-FORTIOS-2.2.1", Status.FAIL),
        ("CIS-FORTIOS-2.1.1", Status.FAIL),
        ("CIS-FORTIOS-2.4.1", Status.PASS),
        ("CIS-FORTIOS-2.3.1-WRITE", Status.PASS),
        ("CIS-FORTIOS-7.1.1", Status.PASS),
        # The two settings on this device the configuration text cannot settle.
        ("CIS-FORTIOS-SSH-V2", Status.NEEDS_REVIEW),
        ("CIS-FORTIOS-2.1.4", Status.NEEDS_REVIEW),
    ],
)
def test_sample_verdicts(fortios_results, rule_id: str, expected: Status):
    assert fortios_results[rule_id].status is expected


def test_remediating_the_sample_turns_every_control_green():
    """No verdict is hardcoded: fix the config and the report must follow."""
    remediated = (
        FGT_TEXT.replace(
            "set allowaccess ping https http ssh telnet", "set allowaccess ping https ssh"
        )
        .replace("set admintimeout 480", "set admintimeout 10")
        .replace(
            '    set timezone "Asia/Kolkata"',
            "    set timezone \"Asia/Kolkata\"\n"
            "    set admin-ssh-v1 disable\n"
            "    set pre-login-banner enable",
        )
        .replace(
            '        set accprofile "super_admin"',
            '        set accprofile "super_admin"\n'
            "        set trusthost1 192.168.20.0 255.255.255.0\n"
            "        set remote-auth enable",
        )
        .replace('        set name "public"', '        set name "netops-ro-9f2c"')
        .replace("    set ntpsync enable", "    set ntpsync enable\n    set type custom")
        + "config system password-policy\n"
        "    set status enable\n"
        "    set minimum-length 8\n"
        "end\n"
        'config user radius\n    edit "AUTH-RADIUS"\n        set server "192.168.20.45"\n    next\nend\n'
        "config system ntp\n"
        "    config ntpserver\n"
        "        edit 1\n"
        '            set server "192.168.20.41"\n'
        "        next\n"
        "    end\n"
        "end\n"
    )
    engine = ComplianceEngine(load_framework("CIS", "fortinet_fortios"))
    results = engine.evaluate(parse(remediated))

    assert [r.status for r in results] == [Status.PASS] * 13, {
        r.rule_id: (r.status, r.message) for r in results if r.status is not Status.PASS
    }


def test_the_fortios_pack_reuses_the_other_packs_conditions():
    """Same conditions, different remediation — the baseline is the seam."""
    fortios = load_framework("CIS", "fortinet_fortios")
    cisco = load_framework("CIS", "cisco_ios")

    assert sorted(rule.condition.model_dump_json() for rule in fortios.rules) == sorted(
        rule.condition.model_dump_json() for rule in cisco.rules
    )

    for rule in fortios.rules:
        assert rule.remediation.cli, rule.id
        assert not any("configure terminal" in line for line in rule.remediation.cli), rule.id
        assert not any(line.strip().startswith("set system ") for line in rule.remediation.cli), rule.id


def test_the_fortios_pack_asserts_clause_numbers():
    """Verify that FortiOS pack has clause numbers verified from PDF."""
    ruleset = load_framework("CIS", "fortinet_fortios")

    assert any(rule.control_ref is not None for rule in ruleset.rules)
    assert "clause numbers verified from PDF" in ruleset.framework_version
    assert "Clause numbers verified" in ruleset.source_note


# ── New Priority 1 Automation tests ──────────────────────────────────────────

def test_ha_parsing():
    # 1. Compliant
    config_compliant = """config system ha
        set mode a-p
        set monitor port1 port2
    end"""
    b = parse(config_compliant)
    assert b.ha_enabled.value is True
    assert b.ha_enabled.line_number == 2
    assert b.ha_enabled.source_line == "set mode a-p"
    assert b.ha_monitor_interfaces.value == ["port1", "port2"]
    assert b.ha_monitor_interfaces.line_number == 3
    assert b.ha_monitor_interfaces.source_line == "set monitor port1 port2"

    # 2. Non-compliant (explicit standalone)
    config_non_compliant = """config system ha
        set mode standalone
    end"""
    b = parse(config_non_compliant)
    assert b.ha_enabled.value is False
    assert b.ha_enabled.source_line == "set mode standalone"
    assert b.ha_monitor_interfaces.value == []

    # 3. Absent
    config_absent = """config system global
        set hostname FGT
    end"""
    b = parse(config_absent)
    assert b.ha_enabled.detected is True
    assert b.ha_enabled.value is False
    assert b.ha_enabled.source_line is None
    assert b.ha_monitor_interfaces.value == []
    assert b.ha_monitor_interfaces.source_line is None


def test_av_push_parsing():
    # 1. Compliant — status enable + frequency automatic (explicit)
    config_compliant = """config system autoupdate schedule
        set status enable
        set frequency automatic
    end"""
    b = parse(config_compliant)
    assert b.av_push_updates_enabled.value is True
    assert b.av_push_updates_enabled.source_line == "set frequency automatic"

    # 2. Compliant — status enable, frequency absent (default automatic)
    config_default_freq = """config system autoupdate schedule
        set status enable
    end"""
    b = parse(config_default_freq)
    assert b.av_push_updates_enabled.value is True
    assert b.av_push_updates_enabled.source_line == "set status enable"

    # 3. Non-compliant — status disable
    config_disabled = """config system autoupdate schedule
        set status disable
    end"""
    b = parse(config_disabled)
    assert b.av_push_updates_enabled.value is False
    assert b.av_push_updates_enabled.source_line == "set status disable"

    # 4. Non-compliant — status enable but frequency not automatic
    config_daily = """config system autoupdate schedule
        set status enable
        set frequency daily
    end"""
    b = parse(config_daily)
    assert b.av_push_updates_enabled.value is False

    # 5. Absent
    config_absent = """config system global
        set hostname FGT
    end"""
    b = parse(config_absent)
    assert b.av_push_updates_enabled.detected is True
    assert b.av_push_updates_enabled.value is False

    # 6. Block present but no status — non-compliant
    config_no_status = """config system autoupdate schedule
    end"""
    b = parse(config_no_status)
    assert b.av_push_updates_enabled.value is False


def test_security_fabric_parsing():
    # 1. Compliant
    config_compliant = """config system csf
        set status enable
    end"""
    b = parse(config_compliant)
    assert b.security_fabric_enabled.value is True
    assert b.security_fabric_enabled.line_number == 2
    assert b.security_fabric_enabled.source_line == "set status enable"

    # 2. Non-compliant
    config_non_compliant = """config system csf
        set status disable
    end"""
    b = parse(config_non_compliant)
    assert b.security_fabric_enabled.value is False
    assert b.security_fabric_enabled.source_line == "set status disable"

    # 3. Absent
    config_absent = """config system global
        set hostname FGT
    end"""
    b = parse(config_absent)
    assert b.security_fabric_enabled.detected is True
    assert b.security_fabric_enabled.value is False


def test_av_ai_detection_parsing():
    # 1. Compliant — machine-learning-detection enable
    config_compliant = """config antivirus settings
        set machine-learning-detection enable
    end"""
    b = parse(config_compliant)
    assert b.av_ai_detection_enabled.value is True
    assert b.av_ai_detection_enabled.source_line == "set machine-learning-detection enable"

    # 2. Non-compliant — machine-learning-detection disable
    config_disabled = """config antivirus settings
        set machine-learning-detection disable
    end"""
    b = parse(config_disabled)
    assert b.av_ai_detection_enabled.value is False
    assert b.av_ai_detection_enabled.source_line == "set machine-learning-detection disable"

    # 3. Absent — no antivirus settings block
    config_absent = """config system global
        set hostname FGT
    end"""
    b = parse(config_absent)
    assert b.av_ai_detection_enabled.detected is True
    assert b.av_ai_detection_enabled.value is False

    # 4. Block present but setting absent — non-compliant
    config_no_setting = """config antivirus settings
        set default-db extended
    end"""
    b = parse(config_no_setting)
    assert b.av_ai_detection_enabled.value is False


def test_av_grayware_parsing():
    # 1. Compliant — grayware enable
    config_compliant = """config antivirus settings
        set grayware enable
    end"""
    b = parse(config_compliant)
    assert b.av_grayware_enabled.value is True
    assert b.av_grayware_enabled.source_line == "set grayware enable"

    # 2. Non-compliant — grayware disable
    config_disabled = """config antivirus settings
        set grayware disable
    end"""
    b = parse(config_disabled)
    assert b.av_grayware_enabled.value is False
    assert b.av_grayware_enabled.source_line == "set grayware disable"

    # 3. Absent — no antivirus settings block
    config_absent = """config system global
        set hostname FGT
    end"""
    b = parse(config_absent)
    assert b.av_grayware_enabled.detected is True
    assert b.av_grayware_enabled.value is False

    # 4. Block present but setting absent — non-compliant (default disabled)
    config_no_setting = """config antivirus settings
        set default-db extended
    end"""
    b = parse(config_no_setting)
    assert b.av_grayware_enabled.value is False


def test_av_settings_combined():
    """Both AI detection and grayware from the same config block."""
    config = """config antivirus settings
        set machine-learning-detection enable
        set grayware enable
    end"""
    b = parse(config)
    assert b.av_ai_detection_enabled.value is True
    assert b.av_grayware_enabled.value is True

    config_mixed = """config antivirus settings
        set machine-learning-detection enable
        set grayware disable
    end"""
    b = parse(config_mixed)
    assert b.av_ai_detection_enabled.value is True
    assert b.av_grayware_enabled.value is False


def test_log_encryption_parsing():
    # 1. Compliant — enc-algorithm high + reliable enable
    config_compliant = """config log fortianalyzer setting
        set enc-algorithm high
        set reliable enable
    end"""
    b = parse(config_compliant)
    assert b.log_encryption_enabled.value is True

    # 2. Non-compliant — enc-algorithm not high
    config_low_enc = """config log fortianalyzer setting
        set enc-algorithm low
        set reliable enable
    end"""
    b = parse(config_low_enc)
    assert b.log_encryption_enabled.value is False

    # 3. Non-compliant — reliable not enable
    config_no_reliable = """config log fortianalyzer setting
        set enc-algorithm high
        set reliable disable
    end"""
    b = parse(config_no_reliable)
    assert b.log_encryption_enabled.value is False

    # 4. Non-compliant — enc-algorithm only, no reliable
    config_enc_only = """config log fortianalyzer setting
        set enc-algorithm high
    end"""
    b = parse(config_enc_only)
    assert b.log_encryption_enabled.value is False

    # 5. Non-compliant — reliable only, no enc-algorithm
    config_rel_only = """config log fortianalyzer setting
        set reliable enable
    end"""
    b = parse(config_rel_only)
    assert b.log_encryption_enabled.value is False

    # 6. Absent — no fortianalyzer setting block
    config_absent = """config system global
        set hostname FGT
    end"""
    b = parse(config_absent)
    assert b.log_encryption_enabled.detected is True
    assert b.log_encryption_enabled.value is False

    # 7. Block present but empty — non-compliant
    config_empty = """config log fortianalyzer setting
    end"""
    b = parse(config_empty)
    assert b.log_encryption_enabled.value is False

    # 8. False-PASS guard — non-compliant config must not pass
    config_wrong = """config log fortianalyzer setting
        set enc-algorithm default
        set reliable enable
    end"""
    b = parse(config_wrong)
    assert b.log_encryption_enabled.value is False

    # 9. False-FAIL guard — fully compliant config must pass
    config_correct = """config log fortianalyzer setting
        set reliable enable
        set enc-algorithm high
        set status enable
    end"""
    b = parse(config_correct)
    assert b.log_encryption_enabled.value is True

