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
      <enabled>yes</enabled>
      <minimum-length>12</minimum-length>
      <minimum-uppercase-letters>1</minimum-uppercase-letters>
      <minimum-lowercase-letters>1</minimum-lowercase-letters>
      <minimum-numeric-letters>1</minimum-numeric-letters>
      <minimum-special-characters>1</minimum-special-characters>
      <new-password-differs-by-characters>3</new-password-differs-by-characters>
      <password-history-count>24</password-history-count>
      <block-prevent>3</block-prevent>
      <block-time>15</block-time>
    </password-complexity>
    <password-profile>
      <entry name="admin-profile">
        <password-change>
          <expiration-period>90</expiration-period>
        </password-change>
      </entry>
    </password-profile>
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


REAL_COMPLIANT_XML = """<config version="11.0.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>PA-VM</hostname>
          <login-banner>Warning: Authorized Access Only!</login-banner>
          <server-verification>yes</server-verification>
          <service>
            <disable-http>yes</disable-http>
            <disable-telnet>yes</disable-telnet>
          </service>
          <ntp-servers>
            <primary-ntp-server>
              <ntp-server-address>1.1.1.1</ntp-server-address>
            </primary-ntp-server>
            <secondary-ntp-server>
              <ntp-server-address>2.2.2.2</ntp-server-address>
            </secondary-ntp-server>
          </ntp-servers>
        </system>
        <setting>
          <management>
            <enable-log-high-dp-load>yes</enable-log-high-dp-load>
            <idle-timeout>10</idle-timeout>
            <admin-lockout>
              <failed-attempts>3</failed-attempts>
              <lockout-time>15</lockout-time>
            </admin-lockout>
          </management>
        </setting>
      </deviceconfig>
      <mgt-config>
        <password-complexity>
          <enabled>yes</enabled>
          <minimum-length>12</minimum-length>
          <minimum-uppercase-letters>1</minimum-uppercase-letters>
          <minimum-lowercase-letters>1</minimum-lowercase-letters>
          <minimum-numeric-letters>1</minimum-numeric-letters>
          <minimum-special-characters>1</minimum-special-characters>
          <new-password-differs-by-characters>3</new-password-differs-by-characters>
          <password-history-count>24</password-history-count>
        </password-complexity>
        <password-profile>
          <entry name="admin-profile">
            <password-change>
              <expiration-period>90</expiration-period>
            </password-change>
          </entry>
        </password-profile>
      </mgt-config>
    </entry>
  </devices>
  <shared>
    <log-settings>
      <syslog>
        <entry name="syslog-1">
          <server>10.0.0.1</server>
        </entry>
      </syslog>
    </log-settings>
  </shared>
</config>"""


REAL_NON_COMPLIANT_XML = """<config version="11.0.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>PA-VM</hostname>
          <login-banner></login-banner>
          <server-verification>no</server-verification>
          <service>
            <disable-http>no</disable-http>
            <disable-telnet>no</disable-telnet>
          </service>
          <ntp-servers>
            <primary-ntp-server>
              <ntp-server-address>1.1.1.1</ntp-server-address>
            </primary-ntp-server>
          </ntp-servers>
          <snmp-setting>
            <v2c>
              <community>public</community>
            </v2c>
          </snmp-setting>
        </system>
        <setting>
          <management>
            <enable-log-high-dp-load>no</enable-log-high-dp-load>
            <idle-timeout>15</idle-timeout>
            <admin-lockout>
              <failed-attempts>0</failed-attempts>
              <lockout-time>0</lockout-time>
            </admin-lockout>
          </management>
        </setting>
      </deviceconfig>
      <mgt-config>
        <password-complexity>
          <minimum-length>8</minimum-length>
        </password-complexity>
      </mgt-config>
    </entry>
  </devices>
</config>"""


class TestPaloAltoPipeline:
    @pytest.fixture
    def parser(self):
        return PaloAltoParser()

    def test_compliant_configuration(self, parser):
        baseline = parser.parse(COMPLIANT_XML)
        report = evaluate_cis_paloalto(baseline)
        
        assert report.summary.total == 80
        results_by_ref = {r.control_ref: r for r in report.results}
        
        # All 17 deterministic controls should pass
        assert results_by_ref["1.1.1.1"].status == Status.PASS
        assert results_by_ref["1.1.2"].status == Status.PASS
        assert results_by_ref["1.1.3"].status == Status.PASS
        assert results_by_ref["1.2.3"].status == Status.PASS
        assert results_by_ref["1.3.2"].status == Status.PASS
        assert results_by_ref["1.3.3"].status == Status.PASS
        assert results_by_ref["1.3.4"].status == Status.PASS
        assert results_by_ref["1.3.5"].status == Status.PASS
        assert results_by_ref["1.3.6"].status == Status.PASS
        assert results_by_ref["1.3.7"].status == Status.PASS
        assert results_by_ref["1.3.8"].status == Status.PASS
        assert results_by_ref["1.3.9"].status == Status.PASS
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
        
        assert report.summary.total == 80
        results_by_ref = {r.control_ref: r for r in report.results}
        
        # All 17 deterministic controls should fail
        assert results_by_ref["1.1.1.1"].status == Status.FAIL
        assert results_by_ref["1.1.2"].status == Status.FAIL
        assert results_by_ref["1.1.3"].status == Status.FAIL
        assert results_by_ref["1.2.3"].status == Status.FAIL
        assert results_by_ref["1.3.2"].status == Status.FAIL
        assert results_by_ref["1.3.3"].status == Status.FAIL
        assert results_by_ref["1.3.4"].status == Status.FAIL
        assert results_by_ref["1.3.5"].status == Status.FAIL
        assert results_by_ref["1.3.6"].status == Status.FAIL
        assert results_by_ref["1.3.7"].status == Status.FAIL
        assert results_by_ref["1.3.8"].status == Status.FAIL
        assert results_by_ref["1.3.9"].status == Status.FAIL
        assert results_by_ref["1.4.1"].status == Status.FAIL
        assert results_by_ref["1.4.2"].status == Status.FAIL
        assert results_by_ref["1.5.1"].status == Status.FAIL
        assert results_by_ref["1.6.1"].status == Status.FAIL
        assert results_by_ref["1.6.2"].status == Status.FAIL

    def test_real_compliant_configuration(self, parser):
        baseline = parser.parse(REAL_COMPLIANT_XML)
        report = evaluate_cis_paloalto(baseline)
        
        assert report.summary.total == 80
        results_by_ref = {r.control_ref: r for r in report.results}
        
        # All 17 deterministic controls should pass
        assert results_by_ref["1.1.1.1"].status == Status.PASS
        assert results_by_ref["1.1.2"].status == Status.PASS
        assert results_by_ref["1.1.3"].status == Status.PASS
        assert results_by_ref["1.2.3"].status == Status.PASS
        assert results_by_ref["1.3.2"].status == Status.PASS
        assert results_by_ref["1.3.3"].status == Status.PASS
        assert results_by_ref["1.3.4"].status == Status.PASS
        assert results_by_ref["1.3.5"].status == Status.PASS
        assert results_by_ref["1.3.6"].status == Status.PASS
        assert results_by_ref["1.3.7"].status == Status.PASS
        assert results_by_ref["1.3.8"].status == Status.PASS
        assert results_by_ref["1.3.9"].status == Status.PASS
        assert results_by_ref["1.4.1"].status == Status.PASS
        assert results_by_ref["1.4.2"].status == Status.PASS
        assert results_by_ref["1.5.1"].status == Status.PASS
        assert results_by_ref["1.6.1"].status == Status.PASS
        assert results_by_ref["1.6.2"].status == Status.PASS

        # Real path provenance check
        ev = results_by_ref["1.1.2"].evidence[0]
        assert ev.line_number == 7
        assert ev.source_line == "<login-banner>Warning: Authorized Access Only!</login-banner>"
        assert "Path: /config/devices/entry/deviceconfig/system/login-banner" in ev.note

    def test_real_non_compliant_configuration(self, parser):
        baseline = parser.parse(REAL_NON_COMPLIANT_XML)
        report = evaluate_cis_paloalto(baseline)
        
        assert report.summary.total == 80
        results_by_ref = {r.control_ref: r for r in report.results}
        
        # All 17 deterministic controls should fail
        assert results_by_ref["1.1.1.1"].status == Status.FAIL
        assert results_by_ref["1.1.2"].status == Status.FAIL
        assert results_by_ref["1.1.3"].status == Status.FAIL
        assert results_by_ref["1.2.3"].status == Status.FAIL
        assert results_by_ref["1.3.2"].status == Status.FAIL
        assert results_by_ref["1.3.3"].status == Status.FAIL
        assert results_by_ref["1.3.4"].status == Status.FAIL
        assert results_by_ref["1.3.5"].status == Status.FAIL
        assert results_by_ref["1.3.6"].status == Status.FAIL
        assert results_by_ref["1.3.7"].status == Status.FAIL
        assert results_by_ref["1.3.8"].status == Status.FAIL
        assert results_by_ref["1.3.9"].status == Status.FAIL
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
        
        # New password requirements default to 0 -> FAIL
        assert results_by_ref["1.3.3"].status == Status.FAIL
        assert results_by_ref["1.3.4"].status == Status.FAIL
        assert results_by_ref["1.3.5"].status == Status.FAIL
        assert results_by_ref["1.3.6"].status == Status.FAIL
        assert results_by_ref["1.3.7"].status == Status.FAIL
        assert results_by_ref["1.3.8"].status == Status.FAIL
        assert results_by_ref["1.3.9"].status == Status.FAIL

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

    def test_false_pass_regressions(self, parser):
        # 1. Syslog server profile without log forwarding must FAIL
        xml_syslog_profile_only = """<configuration>
          <shared>
            <server-profile>
              <syslog>
                <entry name="my-syslog-profile">
                  <server>
                    <entry name="my-srv">
                      <server>192.168.1.1</server>
                    </entry>
                  </server>
                </entry>
              </syslog>
            </server-profile>
          </shared>
        </configuration>"""
        baseline = parser.parse(xml_syslog_profile_only)
        report = evaluate_cis_paloalto(baseline)
        results_by_ref = {r.control_ref: r for r in report.results}
        assert results_by_ref["1.1.1.1"].status == Status.FAIL
        assert baseline.logging_enabled.value is False

        # 2. Authentication Profile without lockout must FAIL
        xml_auth_profile_no_lockout = """<configuration>
          <mgt-config>
            <password-complexity>
              <block-prevent>3</block-prevent>
              <block-time>15</block-time>
            </password-complexity>
          </mgt-config>
          <shared>
            <authentication-profile>
              <entry name="ldap-auth">
                <type>ldap</type>
              </entry>
            </authentication-profile>
          </shared>
        </configuration>"""
        baseline2 = parser.parse(xml_auth_profile_no_lockout)
        report2 = evaluate_cis_paloalto(baseline2)
        results_by_ref2 = {r.control_ref: r for r in report2.results}
        assert results_by_ref2["1.4.2"].status == Status.FAIL
        assert baseline2.admin_lockout_threshold.value == 0
        assert baseline2.admin_lockout_duration.value == 0

    @pytest.mark.parametrize(
        "uppercase,expected_status",
        [
            (1, Status.PASS),
            (2, Status.PASS),
            (0, Status.FAIL),
        ]
    )
    def test_password_uppercase_boundary(self, parser, uppercase, expected_status):
        xml = f"""<configuration>
          <mgt-config>
            <password-complexity>
              <enabled>yes</enabled>
              <minimum-uppercase-letters>{uppercase}</minimum-uppercase-letters>
            </password-complexity>
          </mgt-config>
        </configuration>"""
        baseline = parser.parse(xml)
        report = evaluate_cis_paloalto(baseline)
        results_by_ref = {r.control_ref: r for r in report.results}
        assert results_by_ref["1.3.3"].status == expected_status

    @pytest.mark.parametrize(
        "lowercase,expected_status",
        [
            (1, Status.PASS),
            (2, Status.PASS),
            (0, Status.FAIL),
        ]
    )
    def test_password_lowercase_boundary(self, parser, lowercase, expected_status):
        xml = f"""<configuration>
          <mgt-config>
            <password-complexity>
              <enabled>yes</enabled>
              <minimum-lowercase-letters>{lowercase}</minimum-lowercase-letters>
            </password-complexity>
          </mgt-config>
        </configuration>"""
        baseline = parser.parse(xml)
        report = evaluate_cis_paloalto(baseline)
        results_by_ref = {r.control_ref: r for r in report.results}
        assert results_by_ref["1.3.4"].status == expected_status

    @pytest.mark.parametrize(
        "numeric,expected_status",
        [
            (1, Status.PASS),
            (2, Status.PASS),
            (0, Status.FAIL),
        ]
    )
    def test_password_numeric_boundary(self, parser, numeric, expected_status):
        xml = f"""<configuration>
          <mgt-config>
            <password-complexity>
              <enabled>yes</enabled>
              <minimum-numeric-letters>{numeric}</minimum-numeric-letters>
            </password-complexity>
          </mgt-config>
        </configuration>"""
        baseline = parser.parse(xml)
        report = evaluate_cis_paloalto(baseline)
        results_by_ref = {r.control_ref: r for r in report.results}
        assert results_by_ref["1.3.5"].status == expected_status

    @pytest.mark.parametrize(
        "special,expected_status",
        [
            (1, Status.PASS),
            (2, Status.PASS),
            (0, Status.FAIL),
        ]
    )
    def test_password_special_boundary(self, parser, special, expected_status):
        xml = f"""<configuration>
          <mgt-config>
            <password-complexity>
              <enabled>yes</enabled>
              <minimum-special-characters>{special}</minimum-special-characters>
            </password-complexity>
          </mgt-config>
        </configuration>"""
        baseline = parser.parse(xml)
        report = evaluate_cis_paloalto(baseline)
        results_by_ref = {r.control_ref: r for r in report.results}
        assert results_by_ref["1.3.6"].status == expected_status

    @pytest.mark.parametrize(
        "expiry,expected_status",
        [
            (90, Status.PASS),
            (89, Status.PASS),
            (91, Status.FAIL),
            (0, Status.FAIL),
        ]
    )
    def test_password_expiry_boundary(self, parser, expiry, expected_status):
        xml = f"""<configuration>
          <mgt-config>
            <password-profile>
              <entry name="admin-profile">
                <password-change>
                  <expiration-period>{expiry}</expiration-period>
                </password-change>
              </entry>
            </password-profile>
          </mgt-config>
        </configuration>"""
        baseline = parser.parse(xml)
        report = evaluate_cis_paloalto(baseline)
        results_by_ref = {r.control_ref: r for r in report.results}
        assert results_by_ref["1.3.7"].status == expected_status

    @pytest.mark.parametrize(
        "diff_chars,expected_status",
        [
            (3, Status.PASS),
            (2, Status.FAIL),
            (4, Status.PASS),
        ]
    )
    def test_password_diff_chars_boundary(self, parser, diff_chars, expected_status):
        xml = f"""<configuration>
          <mgt-config>
            <password-complexity>
              <enabled>yes</enabled>
              <new-password-differs-by-characters>{diff_chars}</new-password-differs-by-characters>
            </password-complexity>
          </mgt-config>
        </configuration>"""
        baseline = parser.parse(xml)
        report = evaluate_cis_paloalto(baseline)
        results_by_ref = {r.control_ref: r for r in report.results}
        assert results_by_ref["1.3.8"].status == expected_status

    @pytest.mark.parametrize(
        "reuse_limit,expected_status",
        [
            (24, Status.PASS),
            (23, Status.FAIL),
            (25, Status.PASS),
        ]
    )
    def test_password_reuse_limit_boundary(self, parser, reuse_limit, expected_status):
        xml = f"""<configuration>
          <mgt-config>
            <password-complexity>
              <enabled>yes</enabled>
              <password-history-count>{reuse_limit}</password-history-count>
            </password-complexity>
          </mgt-config>
        </configuration>"""
        baseline = parser.parse(xml)
        report = evaluate_cis_paloalto(baseline)
        results_by_ref = {r.control_ref: r for r in report.results}
        assert results_by_ref["1.3.9"].status == expected_status

