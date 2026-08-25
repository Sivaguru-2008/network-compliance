import sys
from pathlib import Path
import pytest

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parents[1]))

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers.paloalto import PaloAltoParser
from auditor.pipeline import evaluate_cis_paloalto


COMPLIANT_XML = """<configuration>
  <deviceconfig>
    <system>
      <hostname>PA-VM</hostname>
      <login-banner>Warning: Authorized Access Only!</login-banner>
      <log-high-dp-load>yes</log-high-dp-load>
      <login-timeout>10</login-timeout>
      <verify-update-server-identity>yes</verify-update-server-identity>
      <service>
        <http>no</http>
        <telnet>no</telnet>
      </service>
      <ntp-servers>
        <primary-ntp>
          <ntp-server-address>1.1.1.1</ntp-server-address>
        </primary-ntp>
        <secondary-ntp>
          <ntp-server-address>2.2.2.2</ntp-server-address>
        </secondary-ntp>
      </ntp-servers>
    </system>
  </deviceconfig>
  <mgt-config>
    <password-complexity>
      <minimum-length>12</minimum-length>
      <block-prevent>3</block-prevent>
      <block-time>15</block-time>
    </password-complexity>
  </mgt-config>
  <shared>
    <log-settings>
      <syslog>
        <entry name="syslog-1">
          <server>10.0.0.1</server>
        </entry>
      </syslog>
    </log-settings>
  </shared>
</configuration>"""


NON_COMPLIANT_XML = """<configuration>
  <deviceconfig>
    <system>
      <hostname>PA-VM</hostname>
      <login-banner></login-banner>
      <log-high-dp-load>no</log-high-dp-load>
      <login-timeout>15</login-timeout>
      <verify-update-server-identity>no</verify-update-server-identity>
      <service>
        <http>yes</http>
        <telnet>yes</telnet>
      </service>
      <ntp-servers>
        <primary-ntp>
          <ntp-server-address>1.1.1.1</ntp-server-address>
        </primary-ntp>
      </ntp-servers>
      <snmp-setting>
        <v2c>
          <community>public</community>
        </v2c>
      </snmp-setting>
    </system>
  </deviceconfig>
  <mgt-config>
    <password-complexity>
      <minimum-length>8</minimum-length>
      <block-prevent>0</block-prevent>
      <block-time>0</block-time>
    </password-complexity>
  </mgt-config>
</configuration>"""


MINIMAL_XML = """<configuration>
</configuration>"""


class TestPaloAltoPipeline:
    @pytest.fixture
    def parser(self):
        return PaloAltoParser()

    def test_compliant_configuration(self, parser):
        baseline = parser.parse(COMPLIANT_XML)
        report = evaluate_cis_paloalto(baseline)
        
        assert report.summary.total == 67
        results_by_ref = {r.control_ref: r for r in report.results}
        
        # All 10 deterministic controls should pass
        assert results_by_ref["1.1.1.1"].status == Status.PASS
        assert results_by_ref["1.1.2"].status == Status.PASS
        assert results_by_ref["1.1.3"].status == Status.PASS
        assert results_by_ref["1.2.3"].status == Status.PASS
        assert results_by_ref["1.3.2"].status == Status.PASS
        assert results_by_ref["1.4.1"].status == Status.PASS
        assert results_by_ref["1.4.2"].status == Status.PASS
        assert results_by_ref["1.5.1"].status == Status.PASS
        assert results_by_ref["1.6.1"].status == Status.PASS
        assert results_by_ref["1.6.2"].status == Status.PASS

        # Provenance checks
        ev = results_by_ref["1.1.2"].evidence[0]
        assert ev.line_number == 5
        assert ev.source_line == "<login-banner>Warning: Authorized Access Only!</login-banner>"
        assert "Path: /configuration/deviceconfig/system/login-banner" in ev.note

    def test_non_compliant_configuration(self, parser):
        baseline = parser.parse(NON_COMPLIANT_XML)
        report = evaluate_cis_paloalto(baseline)
        
        assert report.summary.total == 67
        results_by_ref = {r.control_ref: r for r in report.results}
        
        # All 10 deterministic controls should fail
        assert results_by_ref["1.1.1.1"].status == Status.FAIL
        assert results_by_ref["1.1.2"].status == Status.FAIL
        assert results_by_ref["1.1.3"].status == Status.FAIL
        assert results_by_ref["1.2.3"].status == Status.FAIL
        assert results_by_ref["1.3.2"].status == Status.FAIL
        assert results_by_ref["1.4.1"].status == Status.FAIL
        assert results_by_ref["1.4.2"].status == Status.FAIL
        assert results_by_ref["1.5.1"].status == Status.FAIL
        assert results_by_ref["1.6.1"].status == Status.FAIL
        assert results_by_ref["1.6.2"].status == Status.FAIL

    def test_minimal_configuration_defaults(self, parser):
        baseline = parser.parse(MINIMAL_XML)
        report = evaluate_cis_paloalto(baseline)
        
        results_by_ref = {r.control_ref: r for r in report.results}
        
        # Absent values default behavior verification
        # Banner is absent -> FAIL
        assert results_by_ref["1.1.2"].status == Status.FAIL
        
        # Telnet/HTTP absent -> defaults to disabled -> PASS
        assert results_by_ref["1.2.3"].status == Status.PASS
        
        # Password min length absent -> defaults to 0 -> FAIL
        assert results_by_ref["1.3.2"].status == Status.FAIL
        
        # Login timeout absent -> defaults to 0 (never) -> FAIL
        assert results_by_ref["1.4.1"].status == Status.FAIL
        
        # Lockout absent -> defaults to 0 -> FAIL
        assert results_by_ref["1.4.2"].status == Status.FAIL
        
        # SNMP absent -> defaults to disabled (no communities) -> PASS
        assert results_by_ref["1.5.1"].status == Status.PASS
        
        # NTP absent -> defaults to none -> FAIL
        assert results_by_ref["1.6.2"].status == Status.FAIL
        
        # Verify Update Server absent -> defaults to True (Authoritative Default) -> PASS
        assert results_by_ref["1.6.1"].status == Status.PASS

    @pytest.mark.parametrize(
        "length,expected_status",
        [
            (12, Status.PASS),
            (13, Status.PASS),
            (11, Status.FAIL),
            (0, Status.FAIL),
            (20, Status.PASS),
        ]
    )
    def test_password_length_boundary_values(self, parser, length, expected_status):
        xml = f"""<configuration>
          <mgt-config>
            <password-complexity>
              <minimum-length>{length}</minimum-length>
            </password-complexity>
          </mgt-config>
        </configuration>"""
        baseline = parser.parse(xml)
        report = evaluate_cis_paloalto(baseline)
        results_by_ref = {r.control_ref: r for r in report.results}
        assert results_by_ref["1.3.2"].status == expected_status

    @pytest.mark.parametrize(
        "timeout,expected_status",
        [
            (10, Status.PASS),
            (9, Status.PASS),
            (11, Status.FAIL),
            (0, Status.FAIL),
            (1, Status.PASS),
            (100, Status.FAIL),
        ]
    )
    def test_idle_timeout_boundary_values(self, parser, timeout, expected_status):
        xml = f"""<configuration>
          <deviceconfig>
            <system>
              <login-timeout>{timeout}</login-timeout>
            </system>
          </deviceconfig>
        </configuration>"""
        baseline = parser.parse(xml)
        report = evaluate_cis_paloalto(baseline)
        results_by_ref = {r.control_ref: r for r in report.results}
        assert results_by_ref["1.4.1"].status == expected_status

    def test_ordering_and_whitespace(self, parser):
        # XML format allows elements in different order
        xml_reordered = """<configuration>
          <mgt-config>
            <password-complexity>
              <block-time>15</block-time>
              <minimum-length>12</minimum-length>
              <block-prevent>3</block-prevent>
            </password-complexity>
          </mgt-config>
          <deviceconfig>
            <system>
              <login-timeout>10</login-timeout>
              <log-high-dp-load>yes</log-high-dp-load>
            </system>
          </deviceconfig>
        </configuration>"""
        baseline = parser.parse(xml_reordered)
        report = evaluate_cis_paloalto(baseline)
        results_by_ref = {r.control_ref: r for r in report.results}
        
        assert results_by_ref["1.3.2"].status == Status.PASS
        assert results_by_ref["1.4.1"].status == Status.PASS
        assert results_by_ref["1.4.2"].status == Status.PASS
        assert results_by_ref["1.1.3"].status == Status.PASS
