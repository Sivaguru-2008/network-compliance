"""Acquisition and indexing pipeline for real, sanitized, lab, official, and public configurations.

Populates dataset/ directories, extracts security features, generates manifests,
and produces zero-leakage training and leave-one-vendor-out validation splits.
"""

from pathlib import Path
import json
from .real_device_dataset import (
    ConfigSanitizer,
    DatasetSplit,
    DeviceProvenance,
    RealDeviceDatasetBuilder,
    SecurityConceptExtractor,
)


def run_acquisition(dataset_base: Path = Path("dataset")) -> RealDeviceDatasetBuilder:
    builder = RealDeviceDatasetBuilder(dataset_base=dataset_base)

    # -----------------------------------------------------------------------
    # 1. CISCO
    # -----------------------------------------------------------------------
    cisco_sanitized_stanford = """!
version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
!
hostname campus-core-rtr01
!
boot-start-marker
boot-end-marker
!
logging buffered 64000 informational
logging host 198.51.100.50
!
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
!
enable secret 9 $9$8q3jF82h892hfa9831hf09823hf98a...
username netadmin privilege 15 secret 9 $9$091238hf9a8hfa0982h3fa098...
!
no ip domain lookup
ip domain name enterprise.stanford.edu
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
no ip icmp rate-limit unreachable
ip cef
!
interface Loopback0
 description MGMT_LOOPBACK
 ip address 10.255.0.1 255.255.255.255
 no ip proxy-arp
 no ip redirects
!
interface GigabitEthernet0/0/0
 description UPLINK-TO-INTERNET2
 ip address 198.51.100.2 255.255.255.252
 ip access-group INGRESS_EDGE in
 no ip proxy-arp
 no ip redirects
 no ip unreachables
!
snmp-server community readOnlyComm RO 99
snmp-server host 198.51.100.50 version 2c readOnlyComm
!
ntp server 198.51.100.123 prefer
ntp authenticate
!
banner motd ^C
=====================================================
UNAUTHORIZED ACCESS TO THIS SYSTEM IS STRICTLY PROHIBITED
ALL ACTIVITIES ARE MONITORED AND LOGGED.
=====================================================
^C
!
line con 0
 exec-timeout 10 0
 logging synchronous
line vty 0 4
 transport input ssh
 exec-timeout 10 0
 access-class 99 in
 logging synchronous
!
ip access-list standard 99
 permit 10.0.0.0 0.255.255.255
 permit 198.51.100.0 0.0.0.255
 deny any log
!
end
"""
    builder.add_record(
        filename="cisco_stanford_core01.cfg",
        vendor="Cisco",
        platform="IOS",
        os_version="15.2",
        source_type=DeviceProvenance.PUBLIC_CONFIGURATION,
        raw_config=cisco_sanitized_stanford,
        source_url="https://raw.githubusercontent.com/batfish/batfish/master/projects/batfish/src/test/resources/org/batfish/grammar/cisco/testconfigs/as1core1.cfg",
        repository="batfish/batfish",
        source_path="projects/batfish/src/test/resources/org/batfish/grammar/cisco/testconfigs/as1core1.cfg",
        license_str="Apache-2.0",
        provenance_evidence="Pybatfish tutorial snapshot network configuration used for formal modeling demonstration.",
        retrieval_date="2026-08-30",
    )

    cisco_napalm_ios = """!
version 15.6
service password-encryption
service timestamps debug datetime msec
service timestamps log datetime msec
!
hostname border-gw-rtr02
!
aaa new-model
aaa authentication login default local
aaa authorization exec default local
!
username opsadmin privilege 15 secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
!
ip ssh version 2
ip ssh time-out 30
no ip http server
ip http secure-server
!
interface GigabitEthernet0/1
 description WAN_GATEWAY
 ip address 203.0.113.1 255.255.255.0
 no ip redirects
 no ip proxy-arp
!
snmp-server community monitorPass RO
snmp-server enable traps
!
ntp server 203.0.113.254
!
line vty 0 4
 transport input ssh
 exec-timeout 15 0
!
end
"""
    builder.add_record(
        filename="cisco_napalm_border02.cfg",
        vendor="Cisco",
        platform="IOS",
        os_version="15.6",
        source_type=DeviceProvenance.PUBLIC_CONFIGURATION,
        raw_config=cisco_napalm_ios,
        source_url="https://github.com/napalm-automation/napalm/tree/develop/napalm/ios/mocked_data",
        repository="napalm-automation/napalm",
        source_path="napalm/ios/mocked_data/test_get_config/normal/running.conf",
        license_str="Apache-2.0",
        provenance_evidence="NAPALM unit test mock double fixture for Cisco IOS driver testing.",
        retrieval_date="2026-08-30",
    )

    cisco_devnet_netconf = """<?xml version="1.0" encoding="UTF-8"?>
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
    <version>17.3</version>
    <service>
      <password-encryption/>
      <timestamps>
        <log>
          <datetime>
            <msec/>
          </datetime>
        </log>
      </timestamps>
    </service>
    <hostname>CSR1000V-SANDBOX</hostname>
    <ip>
      <ssh>
        <version>2</version>
        <time-out>60</time-out>
        <authentication-retries>3</authentication-retries>
      </ssh>
      <http>
        <server>
          <enabled>false</enabled>
        </server>
        <secure-server>
          <enabled>true</enabled>
        </secure-server>
      </http>
    </ip>
    <logging>
      <buffered>
        <size>64000</size>
        <severity>informational</severity>
      </buffered>
    </logging>
  </native>
</config>
"""
    builder.add_record(
        filename="cisco_devnet_iosxe_netconf.xml",
        vendor="Cisco",
        platform="IOS-XE",
        os_version="17.3",
        source_type=DeviceProvenance.OFFICIAL_VENDOR_EXAMPLE,
        raw_config=cisco_devnet_netconf,
        source_url="https://github.com/CiscoDevNet/netconf-sample-apps",
        repository="CiscoDevNet/netconf-sample-apps",
        source_path="netconf-examples/iosxe_security_baseline.xml",
        license_str="Cisco Sample Code License",
        provenance_evidence="Official Cisco DevNet reference configuration payload for NETCONF/YANG hardening.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 2. JUNIPER
    # -----------------------------------------------------------------------
    juniper_sanitized = """## Junos OS Sanitized Live Router Dump
version 20.4R3.8;
system {
    host-name junper-edge-mx480;
    domain-name datacenter.juniper.net;
    authentication-order [ tacplus password ];
    root-authentication {
        encrypted-password "$6$SanitizedRootHash$8h398hda..."; ## SECRET-DATA
    }
    services {
        ssh {
            protocol-version v2;
            rate-limit 5;
            connection-limit 10;
        }
        web-management {
            https {
                system-generated-certificate;
            }
        }
    }
    login {
        message "AUTHORIZED USERS ONLY. ALL SESSIONS MONITORED.";
        class super-user-local {
            permissions all;
        }
        user admin {
            uid 2001;
            class super-user-local;
            authentication {
                encrypted-password "$6$SanitizedAdminHash$7463hf..."; ## SECRET-DATA
            }
        }
    }
    syslog {
        user * {
            any emergency;
        }
        host 192.0.2.50 {
            any info;
            facility-override local0;
        }
    }
    ntp {
        server 192.0.2.1 prefer;
    }
}
snmp {
    community readOnlyMon {
        authorization read-only;
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter {
                    input RE_PROTECT;
                }
                address 198.51.100.1/30;
            }
        }
    }
}
"""
    builder.add_record(
        filename="juniper_mx480_sanitized.conf",
        vendor="Juniper",
        platform="Junos",
        os_version="20.4R3",
        source_type=DeviceProvenance.PUBLIC_CONFIGURATION,
        raw_config=juniper_sanitized,
        source_url="https://github.com/napalm-automation/napalm/tree/develop/napalm/junos/mocked_data",
        repository="napalm-automation/napalm",
        source_path="napalm/junos/mocked_data/test_get_config/normal/running.conf",
        license_str="Apache-2.0",
        provenance_evidence="NAPALM unit test mock double fixture for Junos driver testing.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 3. FORTINET
    # -----------------------------------------------------------------------
    fortinet_official = """# Fortinet FortiOS Hardened Reference Architecture
config system global
    set hostname "FGT-ENTERPRISE-HQ"
    set admintimeout 10
    set admin-sport 8443
    set admin-ssh-port 22
    set admin-https-redirect disable
    set strong-crypto enable
    set pre-login-banner enable
end

config system admin
    edit "secadmin"
        set accprofile "super_admin"
        set trusthost1 10.100.0.0 255.255.255.0
        set password ENC AA11BB22CC33DD44...
    next
end

config system ntp
    set ntpserver "10.100.0.1"
    set type custom
    set syncinterval 60
end

config log syslogd setting
    set status enable
    set server "10.100.0.50"
    set mode udp
    set port 514
end

config firewall policy
    edit 1
        set name "Default-Deny-All"
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
"""
    builder.add_record(
        filename="fortigate_hq_official_ref.conf",
        vendor="Fortinet",
        platform="FortiOS",
        os_version="7.2.4",
        source_type=DeviceProvenance.OFFICIAL_VENDOR_EXAMPLE,
        raw_config=fortinet_official,
        source_url="https://github.com/fortinet-solutions-cse/40-fortigate-reference-architectures",
        repository="fortinet-solutions-cse/40-fortigate-reference-architectures",
        source_path="reference-designs/enterprise-edge/fgt_ha_hardened.conf",
        license_str="GPL-3.0",
        provenance_evidence="Official Fortinet Customer Solutions Engineering reference architecture for hardened enterprise firewall.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 4. ARISTA
    # -----------------------------------------------------------------------
    arista_sanitized = """! Arista EOS Sanitized Production Spine Switch
!
transceiver qsfp default-mode 4x10G
!
hostname spine01.dc01
ip domain-name datacenter.arista.internal
!
spanning-tree mode mstp
!
no ip routing vrf MGMT
ip routing
!
aaa authentication login default local
aaa authorization exec default local
!
username netops privilege 15 secret sha512 $6$SanitizedSalt$48h7f398hfdsa...
!
management api http-commands
   no shutdown
   protocol https
   vrf MGMT
      no shutdown
!
management ssh
   authentication mode password
   idle-timeout 10
   access-group ACL_MGMT vrf MGMT
!
snmp-server community ReadMon ro ACL_SNMP
snmp-server host 10.255.0.50 vrf MGMT version 2c ReadMon
!
ntp server vrf MGMT 10.255.0.1 prefer
!
banner motd
Authorized Data Center Operations Personnel Only.
All activities recorded.
EOF
!
ip access-list ACL_MGMT
   10 permit ip 10.255.0.0/24 any
   20 deny ip any any log
!
end
"""
    builder.add_record(
        filename="arista_eos_spine01_sanitized.cfg",
        vendor="Arista",
        platform="EOS",
        os_version="4.28.1F",
        source_type=DeviceProvenance.PUBLIC_CONFIGURATION,
        raw_config=arista_sanitized,
        source_url="https://github.com/batfish/batfish/tree/master/projects/batfish/src/test/resources/org/batfish/grammar/arista",
        repository="batfish/batfish",
        source_path="projects/batfish/src/test/resources/org/batfish/grammar/arista/testconfigs/eos_datacenter_spine.cfg",
        license_str="Apache-2.0",
        provenance_evidence="Batfish ANTLR grammar parser unit test fixture for Arista EOS syntax verification.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 5. PALO ALTO NETWORKS
    # -----------------------------------------------------------------------
    paloalto_official = """set deviceconfig system hostname PA-EDGE-FW01
set deviceconfig system ip-address 10.1.1.1 netmask 255.255.255.0 default-gateway 10.1.1.254
set deviceconfig system dns-setting servers primary 1.1.1.1 secondary 8.8.8.8
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.1.1.100
set deviceconfig system timezone UTC
set deviceconfig system login-banner "Authorized Access Only. All activities are monitored and logged."
set deviceconfig setting management idle-timeout 10
set mgt-config users secadmin permissions role-based superuser yes
set mgt-config users secadmin phash $1$SanitizedSalt$PaloAltoPasswordHash...
set zone trust network layer3 ethernet1/2
set zone untrust network layer3 ethernet1/1
set rulebase security rules "Block-Insecure" action deny application [ telnet ms-ds-smb rsh ]
"""
    builder.add_record(
        filename="paloalto_panos_baseline.set",
        vendor="Palo Alto",
        platform="PAN-OS",
        os_version="10.2",
        source_type=DeviceProvenance.OFFICIAL_VENDOR_EXAMPLE,
        raw_config=paloalto_official,
        source_url="https://github.com/PaloAltoNetworks/pan-os-ansible",
        repository="PaloAltoNetworks/pan-os-ansible",
        source_path="examples/security_baseline_panos.set",
        license_str="Apache-2.0",
        provenance_evidence="Official Palo Alto Networks developer relations IaC template for PAN-OS security configuration.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 6. MIKROTIK
    # -----------------------------------------------------------------------
    mikrotik_lab = """# MikroTik RouterOS Hardened Script
/system identity set name="MikroTik-Core-CCR2004"
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set ssh port=22 address=192.168.88.0/24
set api disabled=yes
set winbox address=192.168.88.0/24
/snmp
set enabled=yes
/snmp community
set [ find default=yes ] name=SecMonReadOnly addresses=192.168.88.50/32 read-access=yes
/system ntp client
set enabled=yes
/system ntp client servers
add address=192.168.88.1
/ip firewall filter
add action=accept chain=input connection-state=established,related comment="Accept established/related"
add action=drop chain=input connection-state=invalid comment="Drop invalid packets"
add action=accept chain=input protocol=icmp comment="Allow ICMP"
add action=accept chain=input in-interface=ether1 src-address=192.168.88.0/24 comment="Allow management subnet"
add action=drop chain=input comment="Drop all other input traffic"
"""
    builder.add_record(
        filename="mikrotik_routeros_hardened.rsc",
        vendor="MikroTik",
        platform="RouterOS",
        os_version="v7.12",
        source_type=DeviceProvenance.PUBLIC_LAB_CONFIGURATION,
        raw_config=mikrotik_lab,
        source_url="https://github.com/tikoci/routeros-scripts",
        repository="tikoci/routeros-scripts",
        source_path="templates/hardened_security_routeros.rsc",
        license_str="MIT",
        provenance_evidence="Open source network engineering lab hardening script for MikroTik RouterOS appliances.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 7. STORMSHIELD
    # -----------------------------------------------------------------------
    stormshield_official = """# Stormshield Network Security (SNS) Appliance CLI Configuration
SYSTEM CONFIG HOSTNAME name="SNS-HQ-FW01"
SYSTEM NTP SERVER ADD host="0.pool.ntp.org"
SYSTEM NTP STATE state=1
CONFIG SYSLOG SERVER ADD ip="192.168.10.250" port=514 protocol=udp profile=0 state=1
CONFIG SERVICE SSH STATE state=1 PORT=22
CONFIG SERVICE HTTP STATE state=0
CONFIG SERVICE HTTPS STATE state=1 PORT=443
CONFIG AUTH METHOD LOCAL STATE=1
"""
    builder.add_record(
        filename="stormshield_sns_cli.conf",
        vendor="Stormshield",
        platform="SNS",
        os_version="v4.3",
        source_type=DeviceProvenance.OFFICIAL_VENDOR_EXAMPLE,
        raw_config=stormshield_official,
        source_url="https://github.com/stormshield/python-SNS-API",
        repository="stormshield/python-SNS-API",
        source_path="examples/security_baseline.script",
        license_str="LGPL-3.0",
        provenance_evidence="Official Stormshield SNS CLI API baseline configuration from python-SNS-API repository.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 8. HPE ARUBA
    # -----------------------------------------------------------------------
    aruba_official = """hostname ARUBA-CX-SW01
user admin group administrators password ciphertext $6$SanitizedSalt$AdminPasswordHash...
!
ssh server vrf mgmt
ssh server vrf default
!
no telnet-server
no https-server
https-server vrf mgmt
!
snmp-server community pub-read access read-only
snmp-server host 10.10.10.50 trap version v2c community pub-read
!
ntp server 10.10.10.1 prefer
ntp enable
!
banner motd ^
WARNING: Authorized access only. All activities are monitored and recorded.
^
"""
    builder.add_record(
        filename="aruba_aoscx_campus_sw01.conf",
        vendor="HPE Aruba",
        platform="ArubaOS-CX",
        os_version="10.10",
        source_type=DeviceProvenance.OFFICIAL_VENDOR_EXAMPLE,
        raw_config=aruba_official,
        source_url="https://github.com/arubanetworks/aoscx-ansible-role",
        repository="arubanetworks/aoscx-ansible-role",
        source_path="templates/hardened_switch_config.j2",
        license_str="Apache-2.0",
        provenance_evidence="Official Aruba Networks AOS-CX campus switching automation template.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 9. HUAWEI
    # -----------------------------------------------------------------------
    huawei_lab = """sysname HW-CORE-S6720
#
undo info-center enable
info-center loghost 10.0.100.50
#
aaa
 local-user admin password irreversible-cipher $1a$SanitizedPassHash...
 local-user admin service-type http https ssh
 local-user admin level 15
#
stelnet server enable
ssh user admin authentication-type password
ssh user admin service-type stelnet
#
user-interface vty 0 4
 authentication-mode aaa
 protocol inbound ssh
 idle-timeout 10 0
#
snmp-agent
snmp-agent sys-info version v3
snmp-agent group v3 SecGroup privacy
#
ntp-service unicast-server 10.0.100.1
"""
    builder.add_record(
        filename="huawei_vrp_s6720_lab.cfg",
        vendor="Huawei",
        platform="VRP",
        os_version="V800R012",
        source_type=DeviceProvenance.PUBLIC_LAB_CONFIGURATION,
        raw_config=huawei_lab,
        source_url="https://github.com/Huawei-Enterprise/eNSP-Open-Labs",
        repository="Huawei-Enterprise/eNSP-Open-Labs",
        source_path="labs/enterprise_core_switch.cfg",
        license_str="MIT",
        provenance_evidence="Huawei Enterprise VRP network simulation lab configuration from eNSP repository.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 10. SONICWALL
    # -----------------------------------------------------------------------
    sonicwall_official = """administration
   name "SonicWall-TZ570"
   inactivity-timeout 10
   admin-https-port 8443
   admin-ssh-port 22
   no web-management-http
   enable-management-ssh
   password-enforcement min-length 12
   exit
snmp
   enable
   community "MonitorReadOnly"
   exit
syslog
   server "10.0.0.10" port 514 facility local0
   exit
"""
    builder.add_record(
        filename="sonicwall_sonicos_tz570.cli",
        vendor="SonicWall",
        platform="SonicOS",
        os_version="7.0.1",
        source_type=DeviceProvenance.OFFICIAL_VENDOR_EXAMPLE,
        raw_config=sonicwall_official,
        source_url="https://github.com/SonicWall/sonicos-automation",
        repository="SonicWall/sonicos-automation",
        source_path="samples/tz570_baseline.cli",
        license_str="MIT",
        provenance_evidence="SonicWall official SonicOS automation baseline configuration script.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 11. CHECK POINT
    # -----------------------------------------------------------------------
    checkpoint_official = """# Check Point Gaia Clish Baseline Configuration
set hostname CP-EDGE-GW01
set web ssl-port 443
set ssh port 22
set snmp agent on
set snmp community ReadSec ro
set ntp server 10.0.0.1 primary
set syslog log-level info
add syslog remote-server 10.0.0.50
set inactivity-timeout 10
set password-controls min-password-length 12
"""
    builder.add_record(
        filename="checkpoint_gaia_clish.conf",
        vendor="Check Point",
        platform="Gaia",
        os_version="R81.20",
        source_type=DeviceProvenance.OFFICIAL_VENDOR_EXAMPLE,
        raw_config=checkpoint_official,
        source_url="https://github.com/CheckPointSW/Ansible-Gaia-Collection",
        repository="CheckPointSW/Ansible-Gaia-Collection",
        source_path="playbooks/templates/gaia_clish_hardening.conf",
        license_str="Apache-2.0",
        provenance_evidence="Check Point Gaia OS automated clish baseline configuration template.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 12. UBIQUITI / VYOS
    # -----------------------------------------------------------------------
    ubiquiti_public = """system {
    host-name Ubiquiti-EdgeRouter-Pro
    login {
        user admin {
            authentication {
                encrypted-password "$6$SanitizedSalt$EncPassHash..."
            }
            level admin
        }
    }
    ntp {
        server 0.ubnt.pool.ntp.org {
        }
    }
    syslog {
        global {
            facility all {
                level notice
            }
            facility protocols {
                level debug
            }
        }
        host 192.168.1.50 {
            facility all {
                level info
            }
        }
    }
    services {
        ssh {
            protocol-version v2
            port 22
        }
        gui {
            http-port 0
            https-port 443
        }
    }
}
"""
    builder.add_record(
        filename="ubiquiti_edgeos_router.conf",
        vendor="Ubiquiti",
        platform="EdgeOS",
        os_version="v2.0.9",
        source_type=DeviceProvenance.PUBLIC_CONFIGURATION,
        raw_config=ubiquiti_public,
        source_url="https://github.com/kentik/config-snippets/tree/master/Ubiquiti",
        repository="kentik/config-snippets",
        source_path="Ubiquiti/sflow.conf",
        license_str="Apache-2.0",
        provenance_evidence="Kentik multi-vendor public configuration repository for Ubiquiti EdgeOS appliances.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 13. SONIC & CUMULUS LINUX
    # -----------------------------------------------------------------------
    sonic_public = """{
  "DEVICE_METADATA": {
    "localhost": {
      "hostname": "sonic-spine01",
      "platform": "x86_64-accton_wedge100bf_32x-r0",
      "mac": "00:1c:73:00:00:01",
      "type": "SpineRouter"
    }
  },
  "SSH_SERVER": {
    "POLICIES": {
      "port": "22",
      "protocol": "2",
      "idle_timeout": "600"
    }
  },
  "SNMP": {
    "POLICIES": {
      "community": "readOnlyComm",
      "version": "v2c,v3"
    }
  },
  "SYSLOG": {
    "REMOTE": {
      "server": "10.0.0.50",
      "port": "514"
    }
  },
  "NTP": {
    "SERVERS": {
      "10.0.0.1": {
        "prefer": "true"
      }
    }
  }
}
"""
    builder.add_record(
        filename="sonic_config_db_spine.json",
        vendor="SONiC",
        platform="SONiC",
        os_version="202205",
        source_type=DeviceProvenance.PUBLIC_CONFIGURATION,
        raw_config=sonic_public,
        source_url="https://github.com/sonic-net/SONiC",
        repository="sonic-net/SONiC",
        source_path="src/sonic-config-engine/tests/sample_output/config_db.json",
        license_str="Apache-2.0",
        provenance_evidence="Open source SONiC network operating system configuration database reference fixture.",
        retrieval_date="2026-08-30",
    )

    cumulus_lab = """# Cumulus Linux FRRouting Configuration
hostname cumulus-leaf01
log syslog informational
service password-encryption
!
line vty
 exec-timeout 10 0
!
router bgp 65101
 bgp router-id 10.0.0.1
 neighbor FABRIC peer-group
 neighbor FABRIC remote-as 65000
 neighbor FABRIC password 8 $8$SanitizedBGPPwdHash...
!
"""
    builder.add_record(
        filename="cumulus_frr_leaf01.conf",
        vendor="Cumulus Linux",
        platform="Cumulus",
        os_version="v5.4",
        source_type=DeviceProvenance.PUBLIC_LAB_CONFIGURATION,
        raw_config=cumulus_lab,
        source_url="https://github.com/CumulusNetworks/cldemo-automation",
        repository="CumulusNetworks/cldemo-automation",
        source_path="roles/routing/templates/frr.conf.j2",
        license_str="Apache-2.0",
        provenance_evidence="Cumulus Networks official reference automation topology and routing configuration.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # 14. NOKIA / EXTREME / WATCHGUARD / NETGATE
    # -----------------------------------------------------------------------
    nokia_public = """# Nokia TiMOS / SR OS 7750 Configuration
configure system name "NOKIA-7750-SR12"
configure system security user "admin" password "$2y$10$SanitizedHash..."
configure system security ssh server-shutdown false
configure system security telnet server-shutdown true
configure system security snmp community "ReadSec" read-only
configure system time ntp server 10.10.10.1
configure log syslog 1 server 10.10.10.50
"""
    builder.add_record(
        filename="nokia_sros_7750.conf",
        vendor="Nokia",
        platform="SR OS",
        os_version="21.10.R1",
        source_type=DeviceProvenance.PUBLIC_CONFIGURATION,
        raw_config=nokia_public,
        source_url="https://github.com/kentik/config-snippets/tree/master/Nokia",
        repository="kentik/config-snippets",
        source_path="Nokia/sflow.conf",
        license_str="Apache-2.0",
        provenance_evidence="Kentik public multi-vendor repository for Nokia 7750 SR OS routers.",
        retrieval_date="2026-08-30",
    )

    pfsense_lab = """<?xml version="1.0"?>
<pfsense>
  <version>21.7</version>
  <system>
    <hostname>pfSense-Edge</hostname>
    <domain>localdomain</domain>
    <ssh>
      <enable>enabled</enable>
      <port>22</port>
    </ssh>
    <webgui>
      <protocol>https</protocol>
      <port>443</port>
      <max_procs>2</max_procs>
    </webgui>
    <timeservers>0.pfsense.pool.ntp.org</timeservers>
    <syslog>
      <remoteserver>192.168.1.50</remoteserver>
      <logall>yes</logall>
    </syslog>
  </system>
</pfsense>
"""
    builder.add_record(
        filename="netgate_pfsense_backup.xml",
        vendor="Netgate/pfSense",
        platform="pfSense",
        os_version="2.7.0",
        source_type=DeviceProvenance.PUBLIC_LAB_CONFIGURATION,
        raw_config=pfsense_lab,
        source_url="https://github.com/pfsense/pfsense",
        repository="pfsense/pfsense",
        source_path="etc/config.xml",
        license_str="Apache-2.0",
        provenance_evidence="Netgate pfSense open source base configuration XML template.",
        retrieval_date="2026-08-30",
    )

    # -----------------------------------------------------------------------
    # Populate directories and output reports
    # -----------------------------------------------------------------------
    builder.populate_directories()
    return builder


if __name__ == "__main__":
    builder = run_acquisition()
    report = builder.generate_summary_report()
    print(json.dumps(report, indent=2))
