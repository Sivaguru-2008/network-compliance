"""One contract, three vendors.

Cisco IOS, Junos and FortiOS share nothing at the level of syntax. IOS is
indented command lines, Junos is braces or `set` paths, FortiOS is
`config`/`edit`/`next`/`end` blocks. Three parsers exist precisely because no
single grammar could read all three.

What they do share is everything downstream of parsing::

    vendor-specific syntax
            |
            v
    vendor-specific deterministic parser     <- three of these
            |
            v
    SecurityBaselineModel                    <- one of these
            |
            v
    ComplianceEngine                         <- one of these
            |
            v
    AuditReport                              <- one of these

This file asserts the joints. It is deliberately not a fourth copy of any
vendor's field tests: it never checks what a parser read, only that all three
can be driven through the identical pipeline, produce the identical shape, and
obey the identical rules about evidence. If a fourth vendor is added and these
tests pass, the engine, the packs and the report layer did not have to change —
which is the claim the architecture makes and this file is here to check.
"""

from pathlib import Path
from typing import List

import pytest

from auditor.engine import ComplianceEngine
from auditor.models.baseline import SecurityBaselineModel
from auditor.models.observation import Observation, Origin
from auditor.models.result import AuditReport, Status
from auditor.parsers import CiscoIOSParser, FortiosParser, JunosParser, ParserError
from auditor.parsers.base import VendorParser
from auditor.report import render_report
from auditor.rules import load_framework

SAMPLES = Path(__file__).resolve().parents[1] / "samples"

#: (parser class, sample file, rule-pack platform key) for every deterministic
#: vendor. Adding a fourth vendor means adding one row, and nothing else.
VENDORS = [
    pytest.param(CiscoIOSParser, "insecure_ios.conf", "cisco_ios", id="cisco_ios"),
    pytest.param(JunosParser, "junos_srx.conf", "juniper_junos", id="juniper_junos"),
    pytest.param(FortiosParser, "fortios_fgt.conf", "fortinet_fortios", id="fortinet_fortios"),
]

ALL_PARSERS = [CiscoIOSParser, JunosParser, FortiosParser]


def read(sample: str) -> str:
    return (SAMPLES / sample).read_text(encoding="utf-8")


def audit(parser_cls, sample: str, platform_key: str) -> AuditReport:
    """The whole pipeline, written once and driven by every vendor in turn."""
    text = read(sample)
    baseline = parser_cls().parse(text, source_file=f"samples/{sample}")
    engine = ComplianceEngine(load_framework("CIS", platform_key))
    return engine.build_report(baseline, tool_name="netaudit", tool_version="test")


# ---------------------------------------------------------------------------
# the parser interface
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("parser_cls", ALL_PARSERS, ids=lambda c: c.name)
def test_every_parser_implements_the_same_interface(parser_cls):
    assert issubclass(parser_cls, VendorParser)
    assert isinstance(parser_cls.name, str) and parser_cls.name
    assert isinstance(parser_cls.vendor, str) and parser_cls.vendor
    assert isinstance(parser_cls.os_family, str) and parser_cls.os_family
    assert parser_cls.version.count(".") == 2
    assert parser_cls.base_confidence == 1.0, "a grammar-based parse is not probabilistic"
    assert parser_cls.is_fallback is False, "a deterministic parser is never the fallback"


@pytest.mark.parametrize("parser_cls", ALL_PARSERS, ids=lambda c: c.name)
def test_detect_is_a_classmethod_returning_a_probability(parser_cls):
    """The registry ranks parsers before instantiating any of them."""
    for sample in ("insecure_ios.conf", "junos_srx.conf", "fortios_fgt.conf"):
        score = parser_cls.detect(read(sample))
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0
    assert parser_cls.detect("") == 0.0


@pytest.mark.parametrize("parser_cls", ALL_PARSERS, ids=lambda c: c.name)
def test_every_parser_refuses_an_empty_configuration(parser_cls):
    """An empty file is an error, never a device with nothing wrong with it."""
    with pytest.raises(ParserError):
        parser_cls().parse("   \n\n")


def test_each_sample_is_claimed_by_exactly_one_parser():
    """Three grammars, no overlap: detection is a partition, not a contest."""
    for parser_cls, sample, _ in [(p.values[0], p.values[1], p.values[2]) for p in VENDORS]:
        claimants = [other for other in ALL_PARSERS if other.detect(read(sample)) >= 0.3]
        assert claimants == [parser_cls], f"{sample} claimed by {[c.name for c in claimants]}"


# ---------------------------------------------------------------------------
# the common model
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("parser_cls, sample, platform_key", VENDORS)
def test_every_parser_produces_the_same_model(parser_cls, sample, platform_key):
    baseline = parser_cls().parse(read(sample))

    assert isinstance(baseline, SecurityBaselineModel)
    assert baseline.provenance.vendor and baseline.provenance.os_family
    assert baseline.source_sha256 and len(baseline.source_sha256) == 64
    assert baseline.config_line_count == len(read(sample).splitlines())


@pytest.mark.parametrize("parser_cls, sample, platform_key", VENDORS)
def test_every_field_of_the_vocabulary_is_answered(parser_cls, sample, platform_key):
    """No parser may leave a field at its factory 'nobody looked' default.

    Either the parser settled the field, or it said in writing why it could
    not. A field nobody evaluated is indistinguishable in a report from a field
    that genuinely cannot be read, and the difference matters.
    """
    baseline = parser_cls().parse(read(sample))

    for field in SecurityBaselineModel.observable_fields():
        observation = getattr(baseline, field)
        assert isinstance(observation, Observation), field
        assert observation.origin is Origin.DETERMINISTIC, field
        assert observation.note or observation.source_line, field
        assert observation.note != "Parser did not evaluate this field.", field


@pytest.mark.parametrize("parser_cls, sample, platform_key", VENDORS)
def test_no_parser_invents_evidence(parser_cls, sample, platform_key):
    """The single property every vendor must obey identically.

    A cited line number has to name a line that exists in the file the operator
    supplied, and the cited text has to be what is on it. This is what stops a
    parser from citing a line it synthesised, and it is checked the same way for
    a converter-free grammar walk (Junos, FortiOS) and for one built on a third
    party's parse tree (IOS).
    """
    text = read(sample)
    raw_lines = text.splitlines()
    baseline = parser_cls().parse(text)

    cited = 0
    for field in SecurityBaselineModel.observable_fields():
        observation = getattr(baseline, field)
        if observation.line_number is None:
            assert observation.source_line is None or observation.detected, field
            continue
        assert 1 <= observation.line_number <= len(raw_lines), field
        assert raw_lines[observation.line_number - 1].strip() == observation.source_line, field
        cited += 1

    assert cited >= 8, "a real device configuration should produce cited evidence"


@pytest.mark.parametrize("parser_cls, sample, platform_key", VENDORS)
def test_an_undetected_field_never_carries_a_value(parser_cls, sample, platform_key):
    """`detected=False` means unknown, and unknown is never quietly 'secure'."""
    baseline = parser_cls().parse(read(sample))

    for field in SecurityBaselineModel.observable_fields():
        observation = getattr(baseline, field)
        if not observation.detected:
            assert observation.value is None, field
            assert observation.confidence == 0.0, field


# ---------------------------------------------------------------------------
# one engine, one report
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("parser_cls, sample, platform_key", VENDORS)
def test_one_engine_evaluates_every_vendor(parser_cls, sample, platform_key):
    """The same ComplianceEngine class, unmodified, for all three."""
    report = audit(parser_cls, sample, platform_key)

    assert isinstance(report, AuditReport)
    assert report.framework.name == "CIS"
    assert report.framework.rules_evaluated == 13
    assert len(report.results) == 13
    assert report.target.vendor == parser_cls.vendor
    assert report.target.os_family == parser_cls.os_family
    assert report.target.parser == parser_cls.name


@pytest.mark.parametrize("parser_cls, sample, platform_key", VENDORS)
def test_every_verdict_is_one_of_three_and_carries_its_evidence(parser_cls, sample, platform_key):
    report = audit(parser_cls, sample, platform_key)

    for result in report.results:
        assert result.status in (Status.PASS, Status.FAIL, Status.NEEDS_REVIEW)
        assert result.message
        assert result.evidence, result.rule_id
        assert all(item.field and (item.source_line or item.note) for item in result.evidence), (
            result.rule_id
        )
        if result.status is not Status.PASS:
            assert result.remediation and result.remediation.cli, result.rule_id


@pytest.mark.parametrize("parser_cls, sample, platform_key", VENDORS)
def test_every_vendor_renders_through_the_same_report_layer(parser_cls, sample, platform_key):
    rendered = render_report(audit(parser_cls, sample, platform_key), color=False)

    assert "NETWORK SECURITY COMPLIANCE AUDIT" in rendered
    assert parser_cls.vendor in rendered
    assert "REMEDIATION" in rendered.upper()


def test_the_three_samples_are_three_different_devices():
    """Guards against the pipeline quietly reading the same file three times."""
    reports = [audit(*[p.values[0], p.values[1], p.values[2]]) for p in VENDORS]
    fingerprints = {r.target.source_sha256 for r in reports}
    vendors = {r.target.vendor for r in reports}

    assert len(fingerprints) == 3
    assert vendors == {"cisco", "juniper", "fortinet"}


# ---------------------------------------------------------------------------
# the seam: rule packs differ only where they must
# ---------------------------------------------------------------------------


def test_all_three_packs_ask_the_same_questions():
    """Conditions are vendor-neutral because they read the baseline, not syntax."""
    conditions = {
        key: sorted(rule.condition.model_dump_json() for rule in load_framework("CIS", key).rules)
        for key in ("cisco_ios", "juniper_junos", "fortinet_fortios")
    }
    assert conditions["cisco_ios"] == conditions["juniper_junos"] == conditions["fortinet_fortios"]


def test_all_three_packs_answer_them_in_their_own_cli():
    """What is vendor-specific is the fix, and only the fix."""
    remediations = {
        key: "\n".join(
            line for rule in load_framework("CIS", key).rules for line in rule.remediation.cli
        )
        for key in ("cisco_ios", "juniper_junos", "fortinet_fortios")
    }
    assert len(set(remediations.values())) == 3

    assert "configure terminal" in remediations["cisco_ios"]
    assert "commit and-quit" in remediations["juniper_junos"]
    assert "config system global" in remediations["fortinet_fortios"]

    # ...and no pack leaks another vendor's syntax into its own instructions.
    assert "configure terminal" not in remediations["juniper_junos"]
    assert "configure terminal" not in remediations["fortinet_fortios"]
    assert "commit and-quit" not in remediations["fortinet_fortios"]


def test_a_clause_number_is_either_verified_or_omitted():
    """No pack may carry a citation nobody can check.

    The Cisco pack asserts clause numbers because they were read off the CIS
    Cisco IOS Benchmark. The Junos and FortiOS packs assert none at all, because
    their numbering could not be verified against a licensed copy — and a
    plausible-looking invented clause number is worse than no clause number,
    since it would survive into an audit report as a citation.
    """
    cisco = load_framework("CIS", "cisco_ios")
    assert all(rule.control_ref for rule in cisco.rules)

    for key in ("juniper_junos", "fortinet_fortios"):
        ruleset = load_framework("CIS", key)
        assert all(rule.control_ref is None for rule in ruleset.rules), key
        assert "clause numbers not asserted" in ruleset.framework_version, key


def test_every_rule_in_every_pack_reads_a_field_the_baseline_defines():
    """The engine validates this at construction; here it is asserted for all three."""
    known = set(SecurityBaselineModel.observable_fields())
    for key in ("cisco_ios", "juniper_junos", "fortinet_fortios"):
        ruleset = load_framework("CIS", key)
        for rule in ruleset.rules:
            assert set(rule.baseline_fields) <= known, f"{key}/{rule.id}"
        # Constructing the engine is itself the check that nothing is misnamed.
        assert ComplianceEngine(ruleset).ruleset is ruleset


def test_a_pack_written_for_one_vendor_still_evaluates_another():
    """The conditions are portable; only the remediation is not, and it says so.

    This is the property that lets a new vendor be audited the day its parser
    lands, before anyone has written the pack of remediation commands for it.
    """
    from auditor.rules import platform_mismatch_note

    fortios_baseline = FortiosParser().parse(read("fortios_fgt.conf"))
    cisco_pack = load_framework("CIS", "cisco_ios")
    results: List = ComplianceEngine(cisco_pack).evaluate(fortios_baseline)

    assert len(results) == 13
    note = platform_mismatch_note(cisco_pack, "fortinet", "fortios")
    assert note and "must be translated" in note
