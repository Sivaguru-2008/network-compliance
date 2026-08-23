"""The hybrid parser: deterministic first, model only for the gaps.

Three properties matter here, and each is worth more than coverage of the
mechanics:

* a deterministic reading is **never** overruled by a model, even when the model
  is confident and contradicts it;
* the model is only asked when there is actually a gap, because the call costs
  money and sends the configuration off-box;
* what the model fills is stamped ``HYBRID``, so a reader - and the training
  loop - can tell the two reliability classes apart in the same report.
"""

from pathlib import Path

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.observation import Origin
from auditor.models.result import Status
from auditor.parsers import CiscoIOSParser, HybridParser, LLMParser, ParserError, registry
from llm_stub import StubClient, found, make_extraction

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
UNKNOWN_VENDOR = (SAMPLES / "unknown_vendor.conf").read_text(encoding="utf-8")

# The gap under test is real, not contrived: IOS accepts abbreviated commands,
# and `ip ssh ver 2` is a line the regex grammar does not match but a model
# reads without difficulty. That is precisely the case a hybrid parse is for.
GAP_FIELD = "ssh_version"
SSH_VERSION_RULE = "CIS-IOS-2.1.1.6"
ABBREVIATED_SSH = "ip ssh ver 2"


@pytest.fixture
def gapped_text(hardened_text):
    """A hardened config the deterministic parser cannot fully read."""
    return hardened_text.replace("ip ssh version 2", ABBREVIATED_SSH)


def hybrid_with(extraction, **kwargs):
    client = StubClient(extraction)
    return HybridParser(llm=LLMParser(client, **kwargs)), client


def parse_with(config_text, extraction, **kwargs):
    parser, client = hybrid_with(extraction, **kwargs)
    baseline = parser.parse(config_text, source_file="device.conf")
    return parser, client, baseline


def parse_insecure(insecure_text, extraction, **kwargs):
    return parse_with(insecure_text, extraction, **kwargs)


# ---------------------------------------------------------------------------
# selection: it must be asked for
# ---------------------------------------------------------------------------


def test_hybrid_is_registered_but_never_auto_selected(hardened_text):
    assert registry.get("hybrid") is HybridParser
    assert HybridParser.detect(hardened_text) == 0.0
    assert HybridParser.detect(UNKNOWN_VENDOR) == 0.0

    chosen, _ = registry.detect(hardened_text, allow_fallback=True)
    assert chosen is CiscoIOSParser


def test_hybrid_is_not_a_fallback_either():
    """The fallback slot belongs to the LLM parser; hybrid needs --vendor."""
    assert HybridParser.is_fallback is False
    assert HybridParser not in registry.fallbacks()


def test_hybrid_refuses_a_config_no_deterministic_parser_recognises():
    parser, client = hybrid_with(make_extraction())
    with pytest.raises(ParserError, match="--vendor llm"):
        parser.parse(UNKNOWN_VENDOR)
    assert client.calls == 0, "an unrecognised vendor must cost nothing"


def test_empty_config_is_rejected_before_anything_is_sent():
    parser, client = hybrid_with(make_extraction())
    with pytest.raises(ParserError, match="empty"):
        parser.parse("   \n")
    assert client.calls == 0


# ---------------------------------------------------------------------------
# the model is only consulted about gaps
# ---------------------------------------------------------------------------


def test_no_model_call_when_the_deterministic_parser_settled_everything(hardened_text):
    parser, client = hybrid_with(make_extraction())
    baseline = parser.parse(hardened_text, source_file="samples/hardened_ios.conf")

    assert client.calls == 0
    assert baseline.provenance.parser_name == "hybrid"
    assert any("no model call was needed" in w for w in baseline.provenance.warnings)
    assert all(
        getattr(baseline, field).origin is Origin.DETERMINISTIC
        for field in SecurityBaselineModel.observable_fields()
    )


def test_a_gap_is_filled_and_stamped_hybrid(gapped_text):
    deterministic = CiscoIOSParser().parse(gapped_text)
    assert not getattr(deterministic, GAP_FIELD).detected, "the grammar now reads the gap line"

    parser, client, baseline = parse_with(
        gapped_text,
        make_extraction(ssh_version=found(2, ABBREVIATED_SSH, confidence=0.9)),
    )

    assert client.calls == 1
    observation = getattr(baseline, GAP_FIELD)
    assert observation.detected is True
    assert observation.value == 2
    assert observation.origin is Origin.HYBRID
    assert observation.source_line == ABBREVIATED_SSH
    assert parser.filled_fields == [GAP_FIELD]


def test_a_gap_the_model_also_cannot_settle_stays_unknown(gapped_text):
    parser, _, baseline = parse_with(gapped_text, make_extraction())

    assert getattr(baseline, GAP_FIELD).detected is False
    assert parser.filled_fields == []


def test_an_ungrounded_claim_does_not_become_a_hybrid_finding(gapped_text):
    """Grounding still applies: a line the device does not have fills nothing."""
    parser, _, baseline = parse_with(
        gapped_text,
        make_extraction(ssh_version=found(2, "ip ssh version 2", confidence=0.99)),
    )

    assert getattr(baseline, GAP_FIELD).detected is False
    assert parser.filled_fields == []


def test_a_low_confidence_claim_does_not_become_a_hybrid_finding(gapped_text):
    parser, _, baseline = parse_with(
        gapped_text,
        make_extraction(ssh_version=found(2, ABBREVIATED_SSH, confidence=0.2)),
        min_confidence=0.6,
    )

    assert getattr(baseline, GAP_FIELD).detected is False
    assert parser.filled_fields == []


# ---------------------------------------------------------------------------
# the deterministic reading wins, always
# ---------------------------------------------------------------------------


def test_a_confident_model_never_overrules_a_deterministic_finding(insecure_text):
    """The insecure sample proves telnet is on. The model says otherwise, loudly."""
    truth = CiscoIOSParser().parse(insecure_text)
    assert truth.telnet_enabled.detected and truth.telnet_enabled.value is True

    _, _, baseline = parse_insecure(
        insecure_text,
        make_extraction(
            telnet_enabled=found(False, "transport input ssh", confidence=1.0),
            http_server_enabled=found(False, "no ip http server", confidence=1.0),
            aaa_enabled=found(True, "aaa new-model", confidence=1.0),
        ),
    )

    assert baseline.telnet_enabled.value is True
    assert baseline.telnet_enabled.origin is Origin.DETERMINISTIC
    assert baseline.http_server_enabled.value is True
    assert baseline.aaa_enabled.value is False


def test_absence_conclusions_are_deterministic_findings_and_are_kept(insecure_text):
    """``aaa_enabled`` is decided by absence, so it is settled - not a gap."""
    _, _, baseline = parse_insecure(
        insecure_text,
        make_extraction(aaa_enabled=found(True, "aaa new-model", confidence=1.0)),
    )

    assert baseline.aaa_enabled.detected is True
    assert baseline.aaa_enabled.value is False
    assert baseline.aaa_enabled.origin is Origin.DETERMINISTIC


# ---------------------------------------------------------------------------
# provenance, verdicts, and what the training loop harvests
# ---------------------------------------------------------------------------


def test_provenance_names_both_parsers_and_says_what_was_filled(gapped_text):
    _, _, baseline = parse_with(
        gapped_text,
        make_extraction(ssh_version=found(2, ABBREVIATED_SSH, confidence=0.9)),
    )

    assert baseline.provenance.parser_name == "hybrid"
    assert "cisco_ios" in baseline.provenance.parser_version
    assert "llm" in baseline.provenance.parser_version
    filled = [w for w in baseline.provenance.warnings if "Hybrid parse" in w]
    assert filled and GAP_FIELD in filled[0]
    assert "never overruled" in filled[0]


def test_the_full_model_reading_is_kept_for_the_training_loop(insecure_text):
    """Every hybrid parse yields free comparison data on the settled fields too."""
    parser, _, _ = parse_insecure(
        insecure_text,
        make_extraction(telnet_enabled=found(True, "transport input telnet", confidence=0.9)),
    )

    llm_baseline = parser.last_llm_baseline
    assert llm_baseline is not None
    assert llm_baseline.telnet_enabled.detected is True
    assert llm_baseline.telnet_enabled.origin is Origin.LLM


def test_filling_a_gap_turns_needs_review_into_a_verdict(engine, gapped_text):
    """The point of the hybrid parse: coverage bought back, without guessing."""
    before = {r.rule_id: r for r in engine.evaluate(CiscoIOSParser().parse(gapped_text))}
    assert before[SSH_VERSION_RULE].status is Status.NEEDS_REVIEW

    _, _, baseline = parse_with(
        gapped_text,
        make_extraction(ssh_version=found(2, ABBREVIATED_SSH, confidence=0.9)),
    )
    after = {r.rule_id: r for r in engine.evaluate(baseline)}
    assert after[SSH_VERSION_RULE].status is Status.PASS


def test_hybrid_satisfies_the_vendor_parser_contract(insecure_text):
    from auditor.parsers.base import VendorParser

    assert issubclass(HybridParser, VendorParser)
    _, _, baseline = parse_insecure(insecure_text, make_extraction())
    assert isinstance(baseline, SecurityBaselineModel)


def test_cli_builds_a_hybrid_parser_without_touching_the_network(monkeypatch, tmp_path, insecure_text):
    from auditor import cli

    client = StubClient(make_extraction(ssh_version=found(1, "ip ssh version 1", confidence=0.9)))
    monkeypatch.setattr(cli, "_llm_client", lambda args: client)

    config = tmp_path / "device.conf"
    config.write_text(insecure_text, encoding="utf-8")
    report_path = tmp_path / "device.json"

    code = cli.run([str(config), "--vendor", "hybrid", "--quiet", "--json", str(report_path)])

    assert code == cli.EXIT_OK
    assert client.calls == 1
    assert report_path.is_file()
