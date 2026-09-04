"""Regression tests for failures discovered during REAL_PRODUCTION E2E evaluation.

Every test in this file guards a specific bug that was found and fixed by running
the 26 REAL_PRODUCTION configs (16 Cisco IOS + 10 Juniper Junos) through the
full auditor pipeline.
"""

import json
import sys
from pathlib import Path
from typing import List

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from auditor.parsers.base import ParserRegistry, registry
from auditor.parsers.junos import JunosParser
from auditor.parsers.ubiquiti_edgeos import UbiquitiEdgeOSParser
from auditor.models.result import Status
from auditor.pipeline import evaluate, parse_config, platform_key_for, select_parser

MANIFEST_PATH = PROJECT_ROOT / "dataset" / "manifest.json"


def _real_production_entries():
    """Load REAL_PRODUCTION entries from the dataset manifest."""
    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)
    entries = []
    for cat_key, cat_list in manifest["categories"].items():
        for entry in cat_list:
            if entry.get("provenance_class") == "REAL_PRODUCTION":
                entries.append(entry)
    return entries


def _load_config(local_path: str) -> str:
    full = PROJECT_ROOT / local_path
    return full.read_text(encoding="utf-8", errors="replace")


# =========================================================================== #
#  Regression: Ubiquiti EdgeOS false-positive detection on Juniper configs     #
# =========================================================================== #

JUNOS_BRACES_SNIPPET = """\
system {
    host-name test-router;
    services {
        ssh {
            protocol-version v2;
        }
    }
    root-authentication {
        encrypted-password "$6$abc123";
    }
    syslog {
        host 10.0.0.1;
    }
    ntp {
        server 10.0.0.2;
    }
}
interfaces {
    lo0 {
        unit 0 {
            family inet {
                filter {
                    input protect-re;
                }
                address 10.10.10.1/32;
            }
        }
    }
}
"""


class TestEdgeOSFalsePositiveOnJunos:
    """EdgeOS detect() must return 0.0 for Junos braces-format configs.

    Bug: EdgeOS had a broad pattern matching any config with both "system {"
    and "services {", which caught all Junos braces-format configs.
    """

    def test_edgeos_rejects_junos_braces_snippet(self):
        score = UbiquitiEdgeOSParser.detect(JUNOS_BRACES_SNIPPET)
        assert score == 0.0, f"EdgeOS should reject Junos config, got {score}"

    def test_junos_accepts_junos_braces_snippet(self):
        score = JunosParser.detect(JUNOS_BRACES_SNIPPET)
        assert score > 0.3, f"Junos should accept its own config, got {score}"

    def test_edgeos_rejects_all_real_juniper_configs(self):
        entries = _real_production_entries()
        junos_entries = [e for e in entries if e["platform"] == "juniper_junos"]
        assert len(junos_entries) == 10, "Expected 10 Juniper REAL_PRODUCTION configs"
        for entry in junos_entries:
            config = _load_config(entry["local_path"])
            score = UbiquitiEdgeOSParser.detect(config)
            assert score == 0.0, (
                f"EdgeOS should reject {Path(entry['local_path']).name}, got {score}"
            )

    def test_junos_wins_detection_for_all_real_juniper_configs(self):
        entries = _real_production_entries()
        junos_entries = [e for e in entries if e["platform"] == "juniper_junos"]
        for entry in junos_entries:
            config = _load_config(entry["local_path"])
            parser_cls, score = registry.detect(config)
            assert parser_cls.name == "juniper_junos", (
                f"Expected juniper_junos for {Path(entry['local_path']).name}, "
                f"got {parser_cls.name} ({score})"
            )


# =========================================================================== #
#  Regression: Junos inactive-depth tracking affecting sibling blocks          #
# =========================================================================== #

INACTIVE_SIBLING_CONFIG = """\
system {
    host-name inactive-depth-test;
    services {
        ssh;
    }
    syslog {
        host 10.0.0.1;
    }
    ntp {
        server 10.0.0.2;
    }
}
interfaces {
    inactive: fxp0 {
        unit 0 {
            family inet {
                address 192.168.1.1/24;
            }
        }
    }
    lo0 {
        unit 0 {
            family inet {
                filter {
                    input protect-re;
                }
                address 10.10.10.1/32;
            }
        }
    }
}
"""


class TestJunosInactiveDepthTracking:
    """Braces-format parser must clear inactive flag when returning to sibling depth.

    Bug: `_read_braces_format` used `len(stack) < inactive_depth` instead of
    `<=` to clear inactive_depth when popping. When `inactive: fxp0 {` was
    followed by `lo0 {` at the same depth, lo0 was incorrectly marked inactive.
    This caused management_acl (lo0 filter) to be missed on 3 Juniper configs.
    """

    def test_lo0_filter_active_after_inactive_fxp0(self):
        parser = JunosParser()
        baseline = parser.parse(INACTIVE_SIBLING_CONFIG)
        obs = baseline.management_acl_applied
        assert obs.detected, "lo0 filter should be detected"
        assert obs.value is True, "lo0 filter should be present (management ACL applied)"

    def test_fxp0_content_inactive(self):
        parser = JunosParser()
        parser.parse(INACTIVE_SIBLING_CONFIG)
        active_fxp0 = parser.find("interfaces", "fxp0")
        inactive_fxp0 = parser.inactive("interfaces", "fxp0")
        assert len(active_fxp0) == 0, "fxp0 should have no active statements"
        assert len(inactive_fxp0) > 0, "fxp0 should have inactive statements"

    def test_lo0_content_active(self):
        parser = JunosParser()
        parser.parse(INACTIVE_SIBLING_CONFIG)
        active_lo0 = parser.find("interfaces", "lo0")
        assert len(active_lo0) > 0, "lo0 should have active statements"

    @pytest.mark.parametrize("config_name", ["clev.conf", "hous.conf", "kans.conf"])
    def test_real_configs_management_acl_pass(self, config_name):
        """The 3 configs that had FP=3 for management_acl must now PASS."""
        entries = _real_production_entries()
        entry = next(
            e for e in entries
            if Path(e["local_path"]).name == config_name
        )
        config = _load_config(entry["local_path"])
        parser = JunosParser()
        baseline = parser.parse(config, source_file=config_name)
        assert baseline.management_acl_applied.detected, (
            f"{config_name}: management_acl should be detected"
        )
        assert baseline.management_acl_applied.value is True, (
            f"{config_name}: management_acl should be True (lo0 filter present)"
        )


# =========================================================================== #
#  Regression: Vendor detection accuracy for all 26 REAL_PRODUCTION configs    #
# =========================================================================== #


class TestVendorDetectionAllRealProduction:
    """Every REAL_PRODUCTION config must be detected as its expected vendor."""

    def test_all_26_configs_detected_correctly(self):
        entries = _real_production_entries()
        assert len(entries) == 26
        expected_parser_name = {
            "cisco_ios": "cisco_ios",
            "juniper_junos": "juniper_junos",
        }
        failures = []
        for entry in entries:
            config = _load_config(entry["local_path"])
            parser_cls, score = registry.detect(config)
            expected = expected_parser_name[entry["platform"]]
            if parser_cls.name != expected:
                failures.append(
                    f"{Path(entry['local_path']).name}: "
                    f"expected {expected}, got {parser_cls.name}"
                )
        assert not failures, f"Vendor detection failures:\n" + "\n".join(failures)


# =========================================================================== #
#  Regression: Parser success for all 26 REAL_PRODUCTION configs               #
# =========================================================================== #


class TestParserSuccessAllRealProduction:
    """Every REAL_PRODUCTION config must parse without error."""

    def test_all_26_configs_parse_successfully(self):
        entries = _real_production_entries()
        assert len(entries) == 26
        failures = []
        for entry in entries:
            config = _load_config(entry["local_path"])
            try:
                parser_cls, _score = select_parser(config)
                parser = parser_cls()
                baseline = parser.parse(config, source_file=entry["local_path"])
                assert baseline is not None
            except Exception as exc:
                failures.append(f"{Path(entry['local_path']).name}: {exc}")
        assert not failures, f"Parse failures:\n" + "\n".join(failures)


# =========================================================================== #
#  Regression: Compliance evaluation accuracy (zero FP/FN)                     #
# =========================================================================== #


_CISCO_GROUND_TRUTH = {
    "aaa_enabled": "FAIL",
    "secure_vty_transport": "NEEDS_REVIEW",
    "vty_idle_timeout": "NEEDS_REVIEW",
    "enable_secret_encrypted": "FAIL",
    "no_default_snmp_community": "PASS",
    "http_server_disabled": "NEEDS_REVIEW",
    "ssh_version_2": "NEEDS_REVIEW",
    "logging_enabled": "FAIL",
    "management_acl": "NEEDS_REVIEW",
    "login_banner": "FAIL",
    "password_min_length": "FAIL",
    "ntp_configured": "FAIL",
    "no_write_snmp_community": "PASS",
}

_JUNOS_WITH_SSH_V2 = {"atla.conf", "hous.conf", "clev.conf", "kans.conf",
                       "losa.conf", "salt.conf", "seat.conf"}


def _junos_ground_truth(filename: str):
    base = {
        "aaa_enabled": "PASS",
        "secure_vty_transport": "PASS",
        "vty_idle_timeout": "FAIL",
        "enable_secret_encrypted": "FAIL",
        "no_default_snmp_community": "PASS",
        "http_server_disabled": "PASS",
        "logging_enabled": "PASS",
        "management_acl": "PASS",
        "login_banner": "FAIL",
        "password_min_length": "NEEDS_REVIEW",
        "ntp_configured": "PASS",
        "no_write_snmp_community": "PASS",
    }
    base["ssh_version_2"] = "PASS" if filename in _JUNOS_WITH_SSH_V2 else "NEEDS_REVIEW"
    return base


_RULE_TO_CONTROL = {
    "aaa_enabled": "aaa_enabled",
    "secure_vty_transport": "secure_vty_transport",
    "vty_idle_timeout": "vty_idle_timeout",
    "enable_secret_encrypted": "enable_secret_encrypted",
    "no_default_snmp_community": "no_default_snmp_community",
    "http_server_disabled": "http_server_disabled",
    "ssh_version_2": "ssh_version_2",
    "logging_enabled": "logging_enabled",
    "management_acl": "management_acl",
    "login_banner": "login_banner",
    "password_min_length": "password_min_length",
    "ntp_configured": "ntp_configured",
    "no_write_snmp_community": "no_write_snmp_community",
}


class TestComplianceAccuracyAllRealProduction:
    """Full compliance evaluation must match ground truth for all configs."""

    def test_zero_fp_fn_across_all_rules(self):
        entries = _real_production_entries()
        assert len(entries) == 26
        mismatches = []

        for entry in entries:
            config = _load_config(entry["local_path"])
            filename = Path(entry["local_path"]).name

            if entry["platform"] == "cisco_ios":
                gt = _CISCO_GROUND_TRUTH
            else:
                gt = _junos_ground_truth(filename)

            parser_cls, _ = select_parser(config)
            parser = parser_cls()
            baseline = parser.parse(config, source_file=filename)
            outcome = evaluate(baseline, ["CIS"])
            result_map = {}
            for cr in outcome.results:
                control = cr.internal_control_id or cr.rule_id
                result_map[control] = cr.status.value

            for control_id, expected_status in gt.items():
                actual = result_map.get(control_id, "MISSING")
                if actual != expected_status:
                    mismatches.append(
                        f"{filename} | {control_id}: expected={expected_status}, got={actual}"
                    )

        assert not mismatches, (
            f"{len(mismatches)} compliance mismatches:\n" + "\n".join(mismatches)
        )
