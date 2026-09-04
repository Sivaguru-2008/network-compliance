"""Tests for Cloud-Native and Extended Vendor Parsers, plus Excerpt Detection."""

import pytest
from auditor.models.excerpt import assess_configuration_completeness
from auditor.parsers.aws_security_group import AWSSecurityGroupParser
from auditor.parsers.azure_nsg import AzureNSGParser
from auditor.parsers.cisco_asa import CiscoASAParser
from auditor.parsers.hpe_aruba import HPEArubaParser
from auditor.parsers.pfsense import PfSenseParser
from auditor.parsers.ubiquiti import UbiquitiParser


SAMPLE_AWS_SG = """{
  "SecurityGroups": [
    {
      "GroupName": "web-tier-sg",
      "GroupId": "sg-0123456789abcdef0",
      "IpPermissions": [
        {
          "IpProtocol": "tcp",
          "FromPort": 22,
          "ToPort": 22,
          "IpRanges": [{"CidrIp": "192.168.1.0/24"}]
        },
        {
          "IpProtocol": "tcp",
          "FromPort": 80,
          "ToPort": 80,
          "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        },
        {
          "IpProtocol": "tcp",
          "FromPort": 443,
          "ToPort": 443,
          "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }
      ]
    }
  ]
}"""

SAMPLE_AZURE_NSG = """{
  "name": "app-nsg",
  "type": "Microsoft.Network/networkSecurityGroups",
  "properties": {
    "securityRules": [
      {
        "name": "AllowSSHFromBastion",
        "properties": {
          "protocol": "Tcp",
          "sourcePortRange": "*",
          "destinationPortRange": "22",
          "sourceAddressPrefix": "10.0.0.5/32",
          "access": "Allow",
          "direction": "Inbound"
        }
      },
      {
        "name": "AllowHTTPS",
        "properties": {
          "protocol": "Tcp",
          "sourcePortRange": "*",
          "destinationPortRange": "443",
          "sourceAddressPrefix": "Internet",
          "access": "Allow",
          "direction": "Inbound"
        }
      }
    ]
  }
}"""

SAMPLE_PFSENSE = """<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>fw-core-01</hostname>
    <webgui>
      <protocol>https</protocol>
      <port>443</port>
    </webgui>
    <ssh>
      <enable>enabled</enable>
    </ssh>
    <timeservers>0.pool.ntp.org 1.pool.ntp.org</timeservers>
    <syslog>
      <remoteserver>192.168.10.50</remoteserver>
    </syslog>
  </system>
  <snmpd>
    <enable>enabled</enable>
    <community>secure-community</community>
  </snmpd>
</pfsense>"""

SAMPLE_CISCO_ASA = """
: Saved
ASA Version 9.16(1)
!
hostname asa-edge-5525
names
!
http server enable
http 192.168.1.0 255.255.255.0 inside
ssh 192.168.1.0 255.255.255.0 inside
ssh timeout 10
ssh version 2
!
logging enable
logging host inside 192.168.10.50
ntp server 192.168.10.1
banner motd # AUTHORIZED ACCESS ONLY #
enable password PBKDF2_HASH_SECRET
passwd LOCAL_ADMIN_HASH
"""

SAMPLE_HPE_ARUBA = """
; J9773A Configuration Editor; Created on release #YA.16.05.0007
; Provision switch configuration
hostname "Aruba-2930F"
module 1 type j9773a
ip ssh
no telnet-server
web-management ssl
no web-management plaintext
console inactivity-timer 10
logging 192.168.10.50
timesync sntp
sntp server priority 1 192.168.10.1
banner motd "AUTHORIZED ACCESS ONLY"
snmp-server community "corp-read" operator
password manager user-name "admin" sha256 "$6$xyz123"
"""

SAMPLE_UBIQUITI = """
system {
    host-name EdgeRouter-Pro
    login {
        user admin {
            authentication {
                encrypted-password "$6$rounds=5000$salt$hash123"
            }
        }
    }
    ntp {
        server time1.google.com
    }
    syslog {
        global {
            facility all {
                level notice
            }
        }
        host 192.168.10.50 {
            facility all {
                level info
            }
        }
    }
}
service {
    gui {
        https-port 443
    }
    ssh {
        port 22
        protocol-version v2
    }
}
"""


def test_aws_security_group_parser():
    parser = AWSSecurityGroupParser()
    assert parser.detect(SAMPLE_AWS_SG) >= 0.8
    baseline = parser.parse(SAMPLE_AWS_SG)
    assert baseline.hostname.value == "web-tier-sg"
    assert baseline.telnet_enabled.value is False
    assert baseline.ssh_enabled.value is True
    assert baseline.http_server_enabled.value is True
    assert baseline.https_server_enabled.value is True
    assert baseline.management_acl_applied.value is True


def test_azure_nsg_parser():
    parser = AzureNSGParser()
    assert parser.detect(SAMPLE_AZURE_NSG) >= 0.8
    baseline = parser.parse(SAMPLE_AZURE_NSG)
    assert baseline.hostname.value == "app-nsg"
    assert baseline.telnet_enabled.value is False
    assert baseline.ssh_enabled.value is True
    assert baseline.https_server_enabled.value is True
    assert baseline.management_acl_applied.value is True


def test_pfsense_parser():
    parser = PfSenseParser()
    assert parser.detect(SAMPLE_PFSENSE) >= 0.8
    baseline = parser.parse(SAMPLE_PFSENSE)
    assert baseline.hostname.value == "fw-core-01"
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.ssh_enabled.value is True
    assert baseline.logging_enabled.value is True
    assert len(baseline.logging_hosts.value) == 1
    assert baseline.snmp_communities.value[0].name == "secure-community"


def test_cisco_asa_parser():
    parser = CiscoASAParser()
    assert parser.detect(SAMPLE_CISCO_ASA) >= 0.7
    baseline = parser.parse(SAMPLE_CISCO_ASA)
    assert baseline.hostname.value == "asa-edge-5525"
    assert baseline.ssh_enabled.value is True
    assert baseline.ssh_version.value == 2
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.login_banner_present.value is True
    assert baseline.logging_enabled.value is True


def test_hpe_aruba_parser():
    parser = HPEArubaParser()
    assert parser.detect(SAMPLE_HPE_ARUBA) >= 0.7
    baseline = parser.parse(SAMPLE_HPE_ARUBA)
    assert baseline.hostname.value == "Aruba-2930F"
    assert baseline.ssh_enabled.value is True
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.snmp_communities.value[0].name == "corp-read"


def test_ubiquiti_parser():
    parser = UbiquitiParser()
    assert parser.detect(SAMPLE_UBIQUITI) >= 0.7
    baseline = parser.parse(SAMPLE_UBIQUITI)
    assert baseline.hostname.value == "EdgeRouter-Pro"
    assert baseline.ssh_enabled.value is True
    assert baseline.telnet_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.enable_secret_set.value is True


def test_excerpt_completeness_assessment():
    full_assessment = assess_configuration_completeness(SAMPLE_CISCO_ASA)
    assert full_assessment.completeness_score >= 0.6
    assert full_assessment.is_partial is False

    partial_snippet = """
    interface GigabitEthernet0/1
     description Uplink to Core
     ip address 10.1.1.1 255.255.255.0
     ...
    """
    partial_assessment = assess_configuration_completeness(partial_snippet)
    assert partial_assessment.is_partial is True
    assert partial_assessment.disclaimer() is not None
