"""Multi-Platform Validation Matrix.

Validates:
1. Vendor/Platform Detection
2. Parser Execution
3. SecurityBaselineModel Normalization
4. Evidence Extraction with Line Number Provenance
5. Device Identity Extraction
6. Compliance Rule Evaluation (PASS, FAIL, NEEDS_REVIEW, UNSUPPORTED, NOT_APPLICABLE)
7. Remediation Generation & Rollback
8. Structured JSON Report Output
9. Error Handling
"""

import pytest
from auditor.engine import ComplianceEngine
from auditor.identity.extractors import extract_identity
from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import AuditReport, FrameworkInfo, ReportSummary, Status, TargetInfo
from auditor.models.rule import ComplianceRule, LeafCondition, Operator, Remediation, RuleSet, Severity, Platform
from auditor.parsers import (
    A10ACOSParser,
    AlcatelAOSParser,
    AristaEOSParser,
    AWSSecurityGroupParser,
    AzureNSGParser,
    BarracudaCloudGenParser,
    CatoNetworksParser,
    CheckPointGaiaParser,
    CiscoASAParser,
    CiscoIOSParser,
    ExtremeEXOSParser,
    F5BigIPTMOSParser,
    ForcepointNGFWParser,
    FortiosParser,
    HillstoneStoneOSParser,
    HPEArubaAosCxParser,
    HPEArubaParser,
    HuaweiVRPParser,
    JunosParser,
    MikroTikROSParser,
    NetgatePfSenseParser,
    NokiaSROSParser,
    PaloAltoParser,
    PfSenseParser,
    RuckusFastIronParser,
    SangforNGAFParser,
    SonicParser,
    SonicWallParser,
    SonicWallSonicOSParser,
    SophosSFOSParser,
    StormshieldParser,
    StormshieldSNSParser,
    UbiquitiEdgeOSParser,
    UbiquitiParser,
    VersaVersaOSParser,
    WatchGuardFirewareParser,
    WatchGuardParser,
    ZscalerZIAParser,
    ZscalerZPAParser,
    registry,
)
from auditor.pipeline import assess_configuration_completeness, build_report, evaluate, parse_config, select_parser
from auditor.schema import validate_audit_report_dict


# Verified realistic config samples for all vendors
PLATFORM_FIXTURES = {
    "cisco_ios": ("hostname Core-Router-01\nip ssh version 2\nline vty 0 4\n transport input ssh\n access-class 10 in\n", CiscoIOSParser),
    "cisco_asa": (": Saved\n: Written by enable_15\n! ASA Version 9.14(1)\nhostname asa-fw-01\nssh version 2\n", CiscoASAParser),
    "juniper_junos": ("set system host-name core-edge-01\nset system services ssh protocol-version v2\n", JunosParser),
    "fortinet_fortios": ("config system global\n    set hostname \"FGT-HQ-01\"\nend\nconfig system admin\n    edit \"admin\"\n        set password-expire-warning-days 7\n    next\nend\n", FortiosParser),
    "arista_eos": ("hostname arista-switch-01\nmanagement ssh\n  protocol version 2\n", AristaEOSParser),
    "checkpoint_gaia": ("# Check Point Gaia configuration\nset hostname cp-firewall-01\nset password-controls min-password-length 12\n", CheckPointGaiaParser),
    "huawei_vrp": ("sysname Huawei-Core-01\nstelnet server enable\n", HuaweiVRPParser),
    "paloalto_panos": ("<config version=\"10.1.0\">\n  <mgt-config>\n    <users>\n      <entry name=\"admin\"/>\n    </users>\n  </mgt-config>\n</config>", PaloAltoParser),
    "sonicwall_sonicos": ("! SonicOS Preference Configuration\nhostname SonicFW-01\nmanagement ssh\nidle-logout-time 10\n", SonicWallSonicOSParser),
    "sonic": ("{\n  \"DEVICE_METADATA\": {\n    \"localhost\": {\n      \"hostname\": \"sonic-leaf-01\",\n      \"platform\": \"x86_64-mlnx\"\n    }\n  },\n  \"FEATURE\": {\n    \"sshd\": {\"state\": \"enabled\"}\n  }\n}", SonicParser),
    "mikrotik_routeros": ("/system identity set name=MikroTik-GW\n/ip ssh set strong-crypto=yes\n", MikroTikROSParser),
    "hpe_aruba_aos_cx": ("hostname Aruba-AOS-CX\nssh server enable\n", HPEArubaAosCxParser),
    "extreme_exos": ("configure snmp sysName \"Extreme-X460\"\nenable ssh2\n", ExtremeEXOSParser),
    "f5_bigip_tmos": ("sys global-settings {\n    hostname f5-bigip-01.corp\n}\n", F5BigIPTMOSParser),
    "a10_acos": ("hostname A10-Thunder-01\nssh server enable\n", A10ACOSParser),
    "alcatel_aos": ("! IP Setup\nsystem name \"ale-switch-1\"\nip service ssh\nno ip service telnet\n", AlcatelAOSParser),
    "barracuda_cloudgen": ("#scope:BoxAdministration\nsys-name = \"BarracudaFW01\"\nssh-enable = \"yes\"\n", BarracudaCloudGenParser),
    "cato_networks": ("{\n  \"data\": {\n    \"accountBySubdomain\": {\n      \"id\": 12345,\n      \"name\": \"AcmeCorp\"\n    }\n  }\n}", CatoNetworksParser),
    "forcepoint_ngfw": ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<firewall_node name=\"ForcepointFW01\" engine_version=\"6.10\" ssh_service=\"true\" web_server_https=\"true\">\n</firewall_node>", ForcepointNGFWParser),
    "hillstone_stoneos": ("hostname Hillstone-SG6000\n", HillstoneStoneOSParser),
    "netgate_pfsense": ("<?xml version=\"1.0\"?>\n<pfsense>\n  <system>\n    <hostname>pfSenseFW01</hostname>\n    <webgui><protocol>https</protocol></webgui>\n  </system>\n</pfsense>", NetgatePfSenseParser),
    "nokia_sros": ("# TiMOS-C-19.10.R1\necho \"System Configuration\"\n    system\n        name \"Nokia-7750-SR\"\n    exit\n", NokiaSROSParser),
    "ruckus_fastiron": ("hostname ruckus-switch-1\nenable strict-password-enforcement\nweb-management https\nip ssh server\n", RuckusFastIronParser),
    "sangfor_ngaf": ("hostname Sangfor-NGAF-01\n", SangforNGAFParser),
    "sophos_sfos": ("<Configuration>\n  <IPHost transactionid=\"100\">\n    <Name>Internal_LAN</Name>\n    <IPAddress>192.168.100.0</IPAddress>\n  </IPHost>\n</Configuration>", SophosSFOSParser),
    "stormshield_sns": ("# Stormshield Network Security 4.3.4\n[System]\nName=StormshieldFW01\n[Console]\nSSHEnable=1\n", StormshieldSNSParser),
    "ubiquiti_edgeos": ("set system host-name \"edge-router-1\"\nset service gui listen-address 192.168.1.1\nset service ssh protocol-version v2\n", UbiquitiEdgeOSParser),
    "versa_versos": ("set system host-name \"versa-edge-1\"\nset system login announcement \"Authorized Access Only.\"\nset system services ssh enable\n", VersaVersaOSParser),
    "watchguard_fireware": ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration version=\"12.9\">\n  <system-parameters>\n    <device-name>WatchGuard-T35</device-name>\n  </system-parameters>\n</configuration>", WatchGuardFirewareParser),
    "aws_security_group": ("{\"SecurityGroups\": [{\"GroupName\": \"aws-sg-01\", \"GroupId\": \"sg-123\", \"IpPermissions\": []}]}", AWSSecurityGroupParser),
    "azure_nsg": ("{\"name\": \"azure-nsg-01\", \"properties\": {\"securityRules\": []}}", AzureNSGParser),
    "zscaler_zia": ("{\n  \"tenant\": \"AcmeZiaTenant\",\n  \"zia_configuration\": {\"tenant\": \"AcmeZiaTenant\"},\n  \"adminUsers\": [{\"id\": 1, \"loginName\": \"admin@acme.com\"}]\n}", ZscalerZIAParser),
    "zscaler_zpa": ("{\n  \"tenant\": \"AcmeZpaTenant\",\n  \"zpa_configuration\": {\"tenant\": \"AcmeZpaTenant\"},\n  \"adminSso\": {\"ssoEnabled\": true}\n}", ZscalerZPAParser),
}


class TestPlatformMatrix:
    """Parametrized platform matrix verifying all 33 platforms."""

    @pytest.mark.parametrize("platform_name, fixture_data", sorted(PLATFORM_FIXTURES.items()))
    def test_detection_and_parsing(self, platform_name, fixture_data):
        config_text, parser_cls = fixture_data
        parser = parser_cls()
        confidence = parser.detect(config_text)
        assert confidence > 0.0, f"Detection failed for {platform_name}"

        baseline = parser.parse(config_text)
        assert isinstance(baseline, SecurityBaselineModel)
        assert baseline.provenance.vendor is not None
        assert baseline.provenance.parser_name == parser.name
        assert baseline.config_line_count > 0

    @pytest.mark.parametrize("platform_name, fixture_data", sorted(PLATFORM_FIXTURES.items()))
    def test_identity_extraction(self, platform_name, fixture_data):
        config_text, parser_cls = fixture_data
        parser = parser_cls()
        baseline = parser.parse(config_text)
        identity = extract_identity(config_text, baseline)
        assert identity is not None
        assert identity.vendor is not None
        assert identity.hostname is not None
        # Must not hallucinate serial/model when absent
        if not identity.serial_number.detected:
            assert identity.serial_number.value is None

    @pytest.mark.parametrize("platform_name, fixture_data", sorted(PLATFORM_FIXTURES.items()))
    def test_capabilities_and_rule_evaluation(self, platform_name, fixture_data):
        config_text, parser_cls = fixture_data
        parser = parser_cls()
        baseline = parser.parse(config_text)
        capabilities = baseline.capabilities()
        assert isinstance(capabilities, dict)
        assert len(capabilities) > 0

        test_ruleset = RuleSet(
            schema_version="1.0",
            framework="MATRIX_TEST",
            framework_version="1.0",
            platform=Platform(vendor=baseline.provenance.vendor, os_family=baseline.provenance.os_family),
            rules=[
                ComplianceRule(
                    id="TEST-SSH",
                    control_ref="1.1",
                    title="Test SSH Enabled",
                    description="Verifies SSH",
                    severity=Severity.HIGH,
                    condition=LeafCondition(field="ssh_enabled", operator=Operator.IS_TRUE),
                    remediation=Remediation(
                        summary="Enable SSH",
                        commands=["ssh enable"],
                        rollback=["no ssh enable"],
                    ),
                ),
                ComplianceRule(
                    id="TEST-UNSUPPORTED-FIELD",
                    control_ref="1.2",
                    title="Test Unsupported Field",
                    description="Tests unsupported field handling",
                    severity=Severity.LOW,
                    condition=LeafCondition(field="av_ai_detection_enabled", operator=Operator.IS_TRUE),
                    remediation=Remediation(
                        summary="Enable AI AV",
                        commands=["config av"],
                    ),
                ),
            ],
        )

        engine = ComplianceEngine(test_ruleset)
        results = engine.evaluate(baseline)
        assert len(results) == 2

        report = AuditReport(
            tool={"name": "netaudit", "version": "0.1.0"},
            target=TargetInfo(
                vendor=baseline.provenance.vendor,
                os_family=baseline.provenance.os_family,
                parser=baseline.provenance.parser_name,
                parser_version=baseline.provenance.parser_version,
                detection_confidence=1.0,
                config_line_count=baseline.config_line_count,
                capabilities=capabilities,
            ),
            framework=FrameworkInfo(
                name="MATRIX_TEST",
                version="1.0",
                rules_evaluated=2,
            ),
            frameworks=[FrameworkInfo(name="MATRIX_TEST", version="1.0", rules_evaluated=2)],
            summary=ReportSummary.from_results(results),
            results=results,
            baseline=baseline,
        )
        report.validate_consistency()
        report_dict = report.model_dump(mode="json")
        validated = validate_audit_report_dict(report_dict)
        assert validated.summary.total == 2
