"""Device identity: what the file says, and null for everything it does not.

The tests that matter most here are the negative ones. Any extractor can find a
hostname; the property worth pinning is that a serial number nobody captured
comes back as ``None`` on every vendor, every time, with no placeholder and no
value inferred from an image filename.
"""

import inspect
import re
from pathlib import Path

import pytest

from auditor.identity import companion, extractors
from auditor.identity import companion_path, enrich_from_companion, extract_identity, is_companion_file
from auditor.models.identity import UNKNOWN_VENDOR, DeviceIdentity
from auditor.parsers import CiscoIOSParser, FortiosParser, JunosParser

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / "samples"

VENDOR_SAMPLES = {
    "cisco_ios": ("hardened_ios.conf", CiscoIOSParser, "CORE-RTR-01"),
    "juniper_junos": ("junos_srx.conf", JunosParser, "BRANCH-FW-02"),
    "fortinet_fortios": ("fortios_fgt.conf", FortiosParser, "BRANCH-FGT-11"),
}


def _identity_for(vendor: str) -> tuple:
    """Parse a vendor sample the way the pipeline does, then extract identity."""
    filename, parser_cls, _ = VENDOR_SAMPLES[vendor]
    text = (SAMPLES / filename).read_text(encoding="utf-8")
    baseline = parser_cls().parse(text, source_file=f"samples/{filename}")
    return extract_identity(text, baseline), text


def _line(text: str, number: int) -> str:
    return text.splitlines()[number - 1]


# ---------------------------------------------------------------------------
# hostname, with the evidence line it came from
# ---------------------------------------------------------------------------


def test_cisco_hostname_is_extracted_with_its_evidence_line():
    identity, text = _identity_for("cisco_ios")

    assert identity.vendor == "cisco_ios"
    assert identity.os_family == "ios"
    assert identity.hostname.value == "CORE-RTR-01"
    assert identity.hostname.detected is True
    assert identity.hostname.source_line == "hostname CORE-RTR-01"
    # The cited line number must actually contain the cited text.
    assert "CORE-RTR-01" in _line(text, identity.hostname.line_number)


def test_junos_hostname_is_extracted_with_its_evidence_line():
    identity, text = _identity_for("juniper_junos")

    assert identity.vendor == "juniper_junos"
    assert identity.hostname.value == "BRANCH-FW-02"
    assert identity.hostname.detected is True
    assert "BRANCH-FW-02" in _line(text, identity.hostname.line_number)


def test_fortios_hostname_is_extracted_with_its_evidence_line():
    identity, text = _identity_for("fortinet_fortios")

    assert identity.vendor == "fortinet_fortios"
    assert identity.hostname.value == "BRANCH-FGT-11"
    assert identity.hostname.detected is True
    assert "BRANCH-FGT-11" in _line(text, identity.hostname.line_number)


def test_hostname_comes_from_the_parse_rather_than_a_second_reading():
    """Identity reuses the baseline's observation object, evidence and all."""
    filename, parser_cls, expected = VENDOR_SAMPLES["cisco_ios"]
    text = (SAMPLES / filename).read_text(encoding="utf-8")
    baseline = parser_cls().parse(text)

    identity = extract_identity(text, baseline)

    assert identity.hostname == baseline.hostname
    assert identity.hostname.value == expected


# ---------------------------------------------------------------------------
# the honesty constraint: absent hardware facts are null, never invented
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vendor", sorted(VENDOR_SAMPLES))
def test_serial_is_null_for_a_config_only_ingest(vendor: str):
    """A running-config does not carry the serial, so the answer is None.

    This is the constraint the whole identity model exists to hold: a null
    serial is a correct result for a config-only ingest, and any non-null value
    here would be fabricated.
    """
    identity, _ = _identity_for(vendor)

    assert identity.serial_number.value is None
    assert identity.serial_number.detected is False
    assert identity.field_value("serial_number") is None


@pytest.mark.parametrize("vendor", sorted(VENDOR_SAMPLES))
def test_a_null_serial_says_where_the_serial_would_come_from(vendor: str):
    note = identity_note = _identity_for(vendor)[0].serial_number.note
    assert note, "a null field must explain itself"
    assert "show" in identity_note.lower() or "get system status" in identity_note.lower()


@pytest.mark.parametrize("vendor", ["cisco_ios", "juniper_junos"])
def test_model_is_null_when_the_configuration_does_not_state_it(vendor: str):
    identity, _ = _identity_for(vendor)

    assert identity.model.value is None
    assert identity.model.detected is False


def test_a_cisco_boot_system_image_name_is_not_turned_into_a_version():
    """`c2900-...157-3.M2.bin` implies 15.7(3)M2 only after a transformation.

    The file never states that version, so the extractor must not report one.
    """
    text = "\n".join(
        [
            "hostname EDGE-RTR-09",
            "boot system flash:c2900-universalk9-mz.SPA.157-3.M2.bin",
            "line vty 0 4",
            " transport input ssh",
            "end",
        ]
    )

    identity = extract_identity(text, vendor="cisco_ios")

    assert identity.os_version.value is None
    assert identity.os_version.detected is False
    assert "boot system" in identity.os_version.note


def test_identity_never_references_a_compliance_framework():
    """Identity says which device this is; it must not know CIS from NIST."""
    frameworks = re.compile(r"\b(cis|nist|stig|iso[ _-]?27001|800[ _-]?53)\b", re.IGNORECASE)

    for vendor in VENDOR_SAMPLES:
        payload = _identity_for(vendor)[0].model_dump_json()
        assert frameworks.search(payload) is None, f"{vendor} identity mentions a framework"


def test_the_identity_layer_does_not_depend_on_the_rules_layer():
    """Structural, not textual: identity cannot import what it must not know about."""
    sources = [
        (Path(extractors.__file__)).read_text(encoding="utf-8"),
        (Path(companion.__file__)).read_text(encoding="utf-8"),
    ]
    for source in sources:
        assert "from ..rules" not in source
        assert "from ..engine" not in source
        assert "import auditor.rules" not in source


def test_identity_extraction_takes_no_framework_argument():
    """The signature is the guarantee: frameworks cannot influence identity."""
    parameters = set(inspect.signature(extract_identity).parameters)

    assert parameters == {"config_text", "baseline", "vendor"}


def test_identity_extraction_never_needs_a_language_model():
    """Deterministic-first: identity must not depend on the LLM layer at all."""
    for module in (extractors, companion):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "llm" not in source.lower().replace("all", "")
        assert "anthropic" not in source.lower()


# ---------------------------------------------------------------------------
# version: present when stated, null when not
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vendor,expected",
    [("cisco_ios", "15.7"), ("juniper_junos", "21.4R3-S4.9"), ("fortinet_fortios", "7.2.5")],
)
def test_version_is_extracted_verbatim_when_the_configuration_states_it(vendor, expected):
    identity, text = _identity_for(vendor)

    assert identity.os_version.value == expected
    assert identity.os_version.detected is True
    assert expected in _line(text, identity.os_version.line_number)


def test_version_is_null_when_the_configuration_omits_it():
    text = (SAMPLES / "hardened_ios.conf").read_text(encoding="utf-8")
    without_version = "\n".join(
        line for line in text.splitlines() if not line.strip().startswith("version ")
    )
    baseline = CiscoIOSParser().parse(without_version)

    identity = extract_identity(without_version, baseline)

    assert identity.os_version.value is None
    assert identity.os_version.detected is False
    assert identity.hostname.value == "CORE-RTR-01", "removing the version must not disturb the rest"


def test_ssh_version_is_not_mistaken_for_an_os_version():
    text = "\n".join(["hostname SW-1", "ip ssh version 2", "end"])

    identity = extract_identity(text, vendor="cisco_ios")

    assert identity.os_version.value is None


def test_fortios_reads_model_and_version_from_the_config_version_header():
    """FortiOS writes the platform into the file, so reading it is not guessing."""
    identity, text = _identity_for("fortinet_fortios")

    assert identity.model.value == "FGT60F"
    assert identity.model.detected is True
    assert identity.model.line_number == 1
    assert "FGT60F" in _line(text, identity.model.line_number)
    # ...but the header carries no serial, and none is invented from it.
    assert identity.serial_number.value is None


def test_cisco_license_udi_is_read_because_it_is_in_the_configuration():
    """`license udi` genuinely appears in some running-configs. Reading it is reporting."""
    text = (SAMPLES / "hardened_ios.conf").read_text(encoding="utf-8")
    lines = text.splitlines()
    lines.insert(len(lines) - 1, "license udi pid ISR4331/K9 sn FDO21520ABC")
    with_udi = "\n".join(lines)
    baseline = CiscoIOSParser().parse(with_udi)

    identity = extract_identity(with_udi, baseline)

    assert identity.serial_number.value == "FDO21520ABC"
    assert identity.model.value == "ISR4331/K9"
    assert "license udi" in identity.serial_number.source_line
    assert "license udi" in _line(with_udi, identity.serial_number.line_number)


# ---------------------------------------------------------------------------
# unknown vendor
# ---------------------------------------------------------------------------


def test_unknown_vendor_yields_an_identity_rather_than_a_crash():
    text = (SAMPLES / "unknown_vendor.conf").read_text(encoding="utf-8")

    identity = extract_identity(text)

    assert identity.vendor == UNKNOWN_VENDOR
    assert identity.os_family == UNKNOWN_VENDOR
    assert identity.is_identified is False
    assert identity.serial_number.value is None
    assert identity.model.value is None
    assert identity.os_version.value is None


def test_unknown_vendor_still_reports_a_clear_hostname():
    """A wrong hostname is visible and cheap; a wrong serial is an asset-management lie."""
    text = (SAMPLES / "unknown_vendor.conf").read_text(encoding="utf-8")

    identity = extract_identity(text)

    assert identity.hostname.value == "BRANCH-SW-03"
    assert "sysname" in identity.hostname.note
    assert "BRANCH-SW-03" in _line(text, identity.hostname.line_number)


def test_an_unrecognisable_file_reports_nothing_at_all():
    identity = extract_identity("\x00\x01 binary rubbish \xff")

    assert identity.vendor == UNKNOWN_VENDOR
    assert identity.hostname.value is None
    assert identity.display_name == "(hostname not found)"


def test_empty_text_does_not_crash_the_extractor():
    identity = extract_identity("")

    assert identity == DeviceIdentity(
        hostname=identity.hostname,
        os_version=identity.os_version,
        model=identity.model,
        serial_number=identity.serial_number,
    )
    assert identity.hostname.detected is False


# ---------------------------------------------------------------------------
# the optional companion capture
# ---------------------------------------------------------------------------

CISCO_SHOW_VERSION = """\
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.7(3)M2, RELEASE SOFTWARE (fc2)

Cisco CISCO2911/K9 (revision 1.0) with 483328K/40960K bytes of memory.
Processor board ID FTX1840ALCK
"""

JUNOS_SHOW_CHASSIS = """\
Hostname: BRANCH-FW-02
Model: srx340
Junos: 21.4R3-S4.9
Item             Version  Part number  Serial number     Description
Chassis                                JN123456789       SRX340
"""

FORTIOS_GET_STATUS = """\
Version: FortiGate-60F v7.2.5,build1517,230606 (GA.F)
Serial-Number: FGT60FTK20012345
"""


def test_companion_show_output_populates_the_serial():
    identity, _ = _identity_for("cisco_ios")
    assert identity.serial_number.value is None

    enriched = enrich_from_companion(
        identity, CISCO_SHOW_VERSION, companion_file="core-rtr-01.show_version.txt"
    )

    assert enriched.serial_number.value == "FTX1840ALCK"
    assert enriched.serial_number.detected is True
    assert enriched.model.value == "CISCO2911/K9"
    assert enriched.companion_file == "core-rtr-01.show_version.txt"


def test_companion_evidence_says_it_came_from_the_companion():
    """A serial cited against a config line number would be a lie about its source."""
    identity, _ = _identity_for("cisco_ios")

    enriched = enrich_from_companion(identity, CISCO_SHOW_VERSION, companion_file="cap.txt")

    note = enriched.serial_number.note
    assert "companion" in note.lower()
    assert "not from the configuration" in note
    assert enriched.serial_number.line_number == 4
    assert CISCO_SHOW_VERSION.splitlines()[3].strip() == enriched.serial_number.source_line


@pytest.mark.parametrize(
    "vendor,capture,serial",
    [
        ("cisco_ios", CISCO_SHOW_VERSION, "FTX1840ALCK"),
        ("juniper_junos", JUNOS_SHOW_CHASSIS, "JN123456789"),
        ("fortinet_fortios", FORTIOS_GET_STATUS, "FGT60FTK20012345"),
    ],
)
def test_every_vendor_can_be_enriched_from_its_own_show_command(vendor, capture, serial):
    identity, _ = _identity_for(vendor)

    enriched = enrich_from_companion(identity, capture, companion_file="capture.txt")

    assert enriched.serial_number.value == serial


def test_absent_companion_leaves_every_hardware_field_null():
    identity, _ = _identity_for("cisco_ios")

    unchanged = enrich_from_companion(identity, "", companion_file=None)

    assert unchanged.serial_number.value is None
    assert unchanged.model.value is None
    assert unchanged == identity


def test_companion_does_not_overwrite_what_the_configuration_established():
    """The config is the artefact under audit, so it wins on version."""
    identity, _ = _identity_for("cisco_ios")
    assert identity.os_version.value == "15.7"

    enriched = enrich_from_companion(identity, CISCO_SHOW_VERSION, companion_file="cap.txt")

    assert enriched.os_version.value == "15.7"
    assert enriched.os_version.note is None


def test_companion_is_located_by_filename_convention(tmp_path):
    config = tmp_path / "core-rtr-01.conf"
    config.write_text("hostname CORE-RTR-01\n", encoding="utf-8")
    capture = tmp_path / "core-rtr-01.show_version.txt"
    capture.write_text(CISCO_SHOW_VERSION, encoding="utf-8")

    assert companion_path(config) == capture
    assert is_companion_file(capture) is True
    assert is_companion_file(config) is False


def test_no_companion_file_is_not_an_error(tmp_path):
    config = tmp_path / "lonely.conf"
    config.write_text("hostname LONELY\n", encoding="utf-8")

    assert companion_path(config) is None
