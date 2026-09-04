import os
import json
import hashlib
import re
import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

HEADERS = {'User-Agent': 'Mozilla/5.0'}

def try_fetch(url):
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return resp.read()
    except Exception as e:
        return None

# Test various candidate URLs
test_candidates = [
    # Cisco ASA
    ("cisco_asa", "cisco_asa_corp.cfg", "https://raw.githubusercontent.com/netconan/netconan/master/tests/data/cisco_asa.cfg"),
    ("cisco_asa", "cisco_asa_sample.cfg", "https://raw.githubusercontent.com/batfish/pybatfish/master/jupyter_notebooks/networks/example/configs/as1border1.cfg"),
    # Palo Alto
    ("paloalto_panos", "panos_sample.xml", "https://raw.githubusercontent.com/PaloAltoNetworks/iron-skillet/master/panos_v10.0/templates/iron_skillet_panos_template.xml"),
    # Fortinet
    ("fortinet_fortios", "fortios_sample.conf", "https://raw.githubusercontent.com/fortinet-solutions-cse/40_azure_vwan_vhub_active_active_fgt_fgt/master/fortigate_configs/fgt01.conf"),
    # Azure NSG
    ("azure_nsg", "azure_nsg_sample.json", "https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/quickstarts/microsoft.network/nsg-create/azuredeploy.json"),
    # pfSense
    ("netgate_pfsense", "pfsense_config.xml", "https://raw.githubusercontent.com/pfsense/pfsense/master/etc.default/config.xml"),
]

for vendor, fname, url in test_candidates:
    data = try_fetch(url)
    if data:
        print(f"Candidate for {vendor} ({fname}): FOUND ({len(data)} bytes) from {url}")
    else:
        print(f"Candidate for {vendor} ({fname}): NOT FOUND from {url}")
