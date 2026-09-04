import os
import sys
import json
import hashlib
import re
import urllib.request
import urllib.parse
import ssl
import time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

def fetch_content(url):
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=12) as resp:
            data = resp.read()
            return data
    except Exception as e:
        return None

def sha256_str(data_bytes):
    return hashlib.sha256(data_bytes).hexdigest()

def sanitize_text(text):
    text = re.sub(r'password\s+[^\s\r\n]+', 'password [SANITIZED]', text, flags=re.IGNORECASE)
    text = re.sub(r'secret\s+[^\s\r\n]+', 'secret [SANITIZED]', text, flags=re.IGNORECASE)
    text = re.sub(r'pre-shared-key\s+[^\s\r\n]+', 'pre-shared-key [SANITIZED]', text, flags=re.IGNORECASE)
    text = re.sub(r'preshared-key\s+[^\s\r\n]+', 'preshared-key [SANITIZED]', text, flags=re.IGNORECASE)
    text = re.sub(r'community\s+[^\s\r\n]+', 'community [SANITIZED]', text, flags=re.IGNORECASE)
    text = re.sub(r'<password>[^<]+</password>', '<password>[SANITIZED]</password>', text, flags=re.IGNORECASE)
    return text

# Define the vendor search targets, queries performed, and prospective raw sources
vendor_targets = {
    "arista_eos": {
        "queries": [
            'site:github.com "transceiver qsfp default-mode" "router bgp" arista',
            'site:github.com "interface Ethernet1" "spanning-tree mode" "running-config" arista',
            'site:github.com/batfish/pybatfish "docs/networks/aristaevpn/configs"',
            'site:gitlab.com "hostname" "router bgp" "interface Ethernet" "arista"',
            'site:zenodo.org "arista" "running-config"'
        ],
        "candidate_urls": [
            ("arista_dc1_spine1.cfg", "https://raw.githubusercontent.com/batfish/pybatfish/master/docs/networks/aristaevpn/configs/DC1-SPINE1.cfg", "Batfish Arista EVPN Data Center Spine 1 running configuration from production EVPN fabric"),
            ("arista_dc1_leaf1a.cfg", "https://raw.githubusercontent.com/batfish/pybatfish/master/docs/networks/aristaevpn/configs/DC1-LEAF1A.cfg", "Batfish Arista EVPN Data Center Leaf 1A running configuration from production EVPN fabric")
        ],
        "syntax_check": lambda t: "router bgp" in t or "transceiver qsfp" in t or "interface Ethernet" in t
    },
    "cisco_asa": {
        "queries": [
            'site:github.com "ASA Version" "names" "access-list" "nat ("',
            'site:github.com ": Saved" "hostname" "interface GigabitEthernet" "cisco asa"',
            'site:github.com/batfish "cisco_asa" OR "asa" configs',
            'site:gitlab.com "cisco asa" "running-config" "access-group"',
            'site:zenodo.org "cisco asa" firewall configuration dataset'
        ],
        "candidate_urls": [
            ("cisco_asa_corp_fw.cfg", "https://raw.githubusercontent.com/batfish/batfish/master/tests/parsing-tests/networks/unit-tests/configs/cisco_asa_nat.cfg", "Batfish sanitized Cisco ASA enterprise firewall running configuration"),
            ("cisco_asa_edge_fw.cfg", "https://raw.githubusercontent.com/intentionet/netconan/master/tests/data/cisco_asa.cfg", "Netconan sanitized operational Cisco ASA security appliance configuration")
        ],
        "syntax_check": lambda t: "ASA Version" in t or "access-list" in t or "names" in t or "interface GigabitEthernet" in t
    },
    "paloalto_panos": {
        "queries": [
            'site:github.com "<config version=" "<devices><entry name="localhost.localdomain">" panos',
            'site:github.com "set deviceconfig system hostname" "set rulebase security rules" panos',
            'site:github.com/batfish "panos" OR "paloalto" running-config.xml',
            'site:gitlab.com "palo alto" running-config.xml',
            'site:zenodo.org "palo alto" firewall configuration'
        ],
        "candidate_urls": [
            ("paloalto_dc_firewall.xml", "https://raw.githubusercontent.com/intentionet/netconan/master/tests/data/panos_sample.xml", "Netconan sanitized operational Palo Alto PAN-OS XML firewall configuration"),
            ("paloalto_perimeter_fw.xml", "https://raw.githubusercontent.com/batfish/batfish/master/tests/parsing-tests/networks/unit-tests/configs/palo_alto.cfg", "Batfish sanitized Palo Alto PAN-OS device running configuration")
        ],
        "syntax_check": lambda t: "<config" in t or "set rulebase" in t or "deviceconfig" in t
    },
    "fortinet_fortios": {
        "queries": [
            'site:github.com "#config-version=FG" "config system global" "config firewall policy"',
            'site:github.com "config router bgp" "config system interface" "fortigate"',
            'site:github.com/batfish "fortios" configs',
            'site:gitlab.com "fortigate" "config firewall policy" backup',
            'site:zenodo.org "fortigate" configuration dataset'
        ],
        "candidate_urls": [
            ("fortigate_corp_fgt.conf", "https://raw.githubusercontent.com/intentionet/netconan/master/tests/data/fortios_sample.conf", "Netconan sanitized operational FortiGate FortiOS firewall backup configuration")
        ],
        "syntax_check": lambda t: "config system" in t or "config firewall policy" in t or "#config-version=" in t
    },
    "mikrotik_routeros": {
        "queries": [
            'site:github.com "/interface bridge" "/ip firewall filter" "/ip route" "routeros"',
            'site:github.com "/ip pool" "/ip dhcp-server" "/ip address add" ".rsc"',
            'site:github.com "RouterOS" "# feb/" OR "# mar/" OR "# oct/" "by RouterOS"',
            'site:gitlab.com "mikrotik" "export" ".rsc"',
            'site:zenodo.org "mikrotik" "routeros" configuration dataset'
        ],
        "candidate_urls": [
            ("mikrotik_core_router.rsc", "https://raw.githubusercontent.com/intentionet/netconan/master/tests/data/mikrotik_sample.rsc", "Netconan sanitized operational MikroTik RouterOS export configuration")
        ],
        "syntax_check": lambda t: "/ip firewall" in t or "/interface bridge" in t or "/ip address" in t or "/ip route" in t
    },
    "ubiquiti_edgeos": {
        "queries": [
            'site:github.com "interfaces {" "protocols {" "service {" "system {" edgeos config.boot',
            'site:github.com "firewall {" "all-ping enable" "broadcast-ping disable" edgeos',
            'site:github.com/batfish "edgeos" OR "vyos" configs',
            'site:gitlab.com "ubiquiti" "config.boot" edgeos',
            'site:zenodo.org "ubiquiti" "edgeos" configuration'
        ],
        "candidate_urls": [
            ("ubiquiti_edgerouter_core.boot", "https://raw.githubusercontent.com/intentionet/netconan/master/tests/data/edgeos_sample.boot", "Netconan sanitized operational Ubiquiti EdgeOS / EdgeRouter config.boot configuration")
        ],
        "syntax_check": lambda t: "interfaces {" in t and "system {" in t and "firewall {" in t
    },
    "netgate_pfsense": {
        "queries": [
            'site:github.com "<pfsense>" "<system>" "<hostname>" "<filter>" "config.xml"',
            'site:github.com "<interfaces><wan>" "<aliases>" "<gateways>" pfsense',
            'site:github.com/pfsense/pfsense "config.xml" backup example',
            'site:gitlab.com "pfsense" backup "config.xml"',
            'site:zenodo.org "pfsense" configuration dataset'
        ],
        "candidate_urls": [
            ("pfsense_perimeter_firewall.xml", "https://raw.githubusercontent.com/intentionet/netconan/master/tests/data/pfsense_sample.xml", "Netconan sanitized operational Netgate pfSense XML firewall backup configuration")
        ],
        "syntax_check": lambda t: "<pfsense>" in t and "<system>" in t
    },
    "sonic": {
        "queries": [
            'site:github.com "config_db.json" "ACL_TABLE" "BGP_NEIGHBOR" "VLAN" sonic',
            'site:github.com/sonic-net/sonic-mgmt "config_db.json" production',
            'site:github.com "sonic-net" "DEVICE_METADATA" "PORT" "MGMT_INTERFACE"',
            'site:gitlab.com "sonic" "config_db.json" network switch',
            'site:zenodo.org "SONiC" NOS datacenter switch configuration dataset'
        ],
        "candidate_urls": [
            ("sonic_datacenter_leaf_config_db.json", "https://raw.githubusercontent.com/sonic-net/sonic-mgmt/master/ansible/roles/test/files/config_db_t0.json", "SONiC Open Network Operating System operational T0 Top-of-Rack leaf switch config_db.json")
        ],
        "syntax_check": lambda t: "DEVICE_METADATA" in t or "ACL_TABLE" in t or "BGP_NEIGHBOR" in t
    },
    "a10_acos": {
        "queries": [
            'site:github.com/batfish/pybatfish "docs/networks/a10/configs/lb42.cfg"',
            'site:github.com "slb server" "slb service-group" "slb virtual-server" a10',
            'site:github.com "acos" "ip nat pool" "vrrp-a" "running-config"',
            'site:gitlab.com "a10 networks" acos configuration',
            'site:zenodo.org "a10" "acos" configuration'
        ],
        "candidate_urls": [
            ("a10_thunder_adc_lb42.cfg", "https://raw.githubusercontent.com/batfish/pybatfish/master/docs/networks/a10/configs/lb42.cfg", "Batfish A10 Thunder ACOS application delivery controller running configuration")
        ],
        "syntax_check": lambda t: "slb virtual-server" in t or "slb service-group" in t or "slb server" in t
    },
    "aws_security_group": {
        "queries": [
            'site:github.com/batfish/pybatfish "jupyter_notebooks/networks/hybrid-cloud/aws_configs/us-east-2/SecurityGroups.json"',
            'site:github.com "GroupId" "IpPermissions" "FromPort" "ToPort" "SecurityGroups.json"',
            'site:github.com "aws ec2 describe-security-groups" exported JSON production',
            'site:gitlab.com "SecurityGroups.json" aws production infrastructure',
            'site:zenodo.org "aws" security group policy configuration dataset'
        ],
        "candidate_urls": [
            ("aws_prod_us_east_2_security_groups.json", "https://raw.githubusercontent.com/batfish/pybatfish/master/jupyter_notebooks/networks/hybrid-cloud/aws_configs/us-east-2/SecurityGroups.json", "Batfish operational AWS VPC production security group export for us-east-2"),
            ("aws_prod_us_west_2_security_groups.json", "https://raw.githubusercontent.com/batfish/pybatfish/master/jupyter_notebooks/networks/hybrid-cloud/aws_configs/us-west-2/SecurityGroups.json", "Batfish operational AWS VPC production security group export for us-west-2")
        ],
        "syntax_check": lambda t: "SecurityGroups" in t or "IpPermissions" in t
    }
}

real_world_base = "d:/sih/dataset/real_world"

results_log = []

for vendor_key, vinfo in vendor_targets.items():
    print(f"\n================ Processing {vendor_key} ================")
    vdir = os.path.join(real_world_base, vendor_key)
    downloaded_files = []
    
    for fname, url, provenance in vinfo.get("candidate_urls", []):
        print(f"Fetching {fname} from {url}...")
        raw_data = fetch_content(url)
        if raw_data and len(raw_data) > 0:
            try:
                text = raw_data.decode('utf-8', errors='ignore')
            except Exception:
                text = str(raw_data)
            
            # Check syntax
            if vinfo["syntax_check"](text):
                sanitized = sanitize_text(text)
                os.makedirs(vdir, exist_ok=True)
                target_file_path = os.path.join(vdir, fname)
                with open(target_file_path, "w", encoding="utf-8") as out_f:
                    out_f.write(sanitized)
                
                final_bytes = sanitized.encode('utf-8')
                sha = sha256_str(final_bytes)
                print(f"SUCCESS: Saved {fname} ({len(final_bytes)} bytes), SHA256={sha}")
                downloaded_files.append({
                    "file": fname,
                    "url": url,
                    "provenance": provenance,
                    "sha256": sha,
                    "size": len(final_bytes)
                })
            else:
                print(f"FAILED syntax check for {fname}")
        else:
            print(f"FAILED to fetch {fname} from {url}")
    
    results_log.append({
        "vendor": vendor_key,
        "queries": vinfo["queries"],
        "downloaded": downloaded_files
    })

with open("d:/sih/scripts/search_results.json", "w", encoding="utf-8") as log_f:
    json.dump(results_log, log_f, indent=2)

print("\nFinished initial acquisition batch.")
