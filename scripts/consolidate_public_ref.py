import os
import shutil
import hashlib
import json

pub_ref_dir = "d:/sih/dataset/public_reference"

# Mapping shorthand names to canonical names
canonical_map = {
    "a10": "a10_acos",
    "alcatel": "alcatel_aos",
    "arista": "arista_eos",
    "aws": "aws_security_group",
    "azure": "azure_nsg",
    "barracuda": "barracuda_cloudgen",
    "cato": "cato_networks",
    "check_point": "checkpoint_gaia",
    "cisco": "cisco_ios",
    "extreme": "extreme_exos",
    "f5": "f5_bigip_tmos",
    "forcepoint": "forcepoint_ngfw",
    "fortinet": "fortinet_fortios",
    "hillstone": "hillstone_stoneos",
    "hpe_aruba": "hpe_aruba_aos_switch",
    "huawei": "huawei_vrp",
    "juniper": "juniper_junos",
    "mikrotik": "mikrotik_routeros",
    "netgate": "netgate_pfsense",
    "nokia": "nokia_sros",
    "palo_alto": "paloalto_panos",
    "ruckus": "ruckus_fastiron",
    "sangfor": "sangfor_ngaf",
    "sonicwall": "sonicwall_sonicos",
    "sophos": "sophos_sfos",
    "stormshield": "stormshield_sns",
    "ubiquiti": "ubiquiti_edgeos",
    "versa": "versa_versos",
    "watchguard": "watchguard_fireware"
}

# Move shorthand folders into canonical folders in public_reference
for src_name, dst_name in canonical_map.items():
    src_path = os.path.join(pub_ref_dir, src_name)
    dst_path = os.path.join(pub_ref_dir, dst_name)
    if os.path.exists(src_path) and os.path.isdir(src_path):
        os.makedirs(dst_path, exist_ok=True)
        for f in os.listdir(src_path):
            src_f = os.path.join(src_path, f)
            dst_f = os.path.join(dst_path, f)
            if not os.path.exists(dst_f):
                shutil.move(src_f, dst_f)
            else:
                os.remove(src_f)
        shutil.rmtree(src_path)

print("Consolidated public_reference directories.")
