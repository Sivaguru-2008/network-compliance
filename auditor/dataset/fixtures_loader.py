"""Sync and sanitize vendor configuration fixtures across all supported vendors."""

import json
import shutil
from pathlib import Path
from typing import Dict, List

from .sanitizer import SecretSanitizer

FIXTURE_MAPPINGS = {
    "cisco_ios": [
        ("samples/cisco/hardened_ios.conf", "cisco_ios_hardened.conf", "synthetic"),
        ("samples/cisco/insecure_ios.conf", "cisco_ios_insecure.conf", "synthetic"),
        ("dataset/official_vendor_examples/cisco/cisco_devnet_iosxe_netconf.xml", "cisco_iosxe_devnet.xml", "real"),
    ],
    "juniper_junos": [
        ("samples/junos/sample.conf", "junos_sample.conf", "synthetic"),
        ("samples/junos_srx.conf", "junos_srx_baseline.conf", "synthetic"),
    ],
    "fortinet_fortios": [
        ("samples/fortios/sample.conf", "fortios_sample.conf", "synthetic"),
        ("samples/fortios_fgt.conf", "fortios_fgt_baseline.conf", "synthetic"),
        ("dataset/official_vendor_examples/fortinet/fortigate_hq_official_ref.conf", "fortigate_hq_official.conf", "real"),
    ],
    "arista_eos": [
        ("samples/arista/secure.conf", "arista_eos_secure.conf", "synthetic"),
        ("samples/arista/insecure.conf", "arista_eos_insecure.conf", "synthetic"),
    ],
    "sonic": [
        ("samples/sonic/sample.conf", "sonic_config_db_sample.json", "synthetic"),
        ("samples/sonic/insecure.conf", "sonic_config_db_insecure.json", "synthetic"),
    ],
    "paloalto_panos": [
        ("samples/paloalto_panos.xml", "panos_sample.xml", "synthetic"),
        ("dataset/official_vendor_examples/palo_alto/paloalto_panos_baseline.set", "panos_baseline.set", "real"),
    ],
    "huawei_vrp": [
        ("samples/huawei_vrp/secure.conf", "huawei_vrp_secure.cfg", "synthetic"),
        ("dataset/lab_configuration/huawei/huawei_vrp_s6720_lab.cfg", "huawei_vrp_s6720_lab.cfg", "real"),
    ],
    "checkpoint_gaia": [
        ("samples/checkpoint_gaia/secure.conf", "checkpoint_gaia_secure.conf", "synthetic"),
        ("dataset/official_vendor_examples/check_point/checkpoint_gaia_clish.conf", "checkpoint_gaia_clish.conf", "real"),
    ],
    "mikrotik_routeros": [
        ("samples/mikrotik_routeros/secure.conf", "mikrotik_routeros_secure.rsc", "synthetic"),
        ("dataset/lab_configuration/mikrotik/mikrotik_routeros_hardened.rsc", "mikrotik_routeros_hardened.rsc", "real"),
    ],
    "sonicwall": [
        ("samples/sonicwall/secure.conf", "sonicwall_secure.cli", "synthetic"),
        ("dataset/official_vendor_examples/sonicwall/sonicwall_sonicos_tz570.cli", "sonicwall_sonicos_tz570.cli", "real"),
    ],
    "stormshield": [
        ("samples/stormshield/secure.conf", "stormshield_secure.conf", "synthetic"),
        ("dataset/official_vendor_examples/stormshield/stormshield_sns_cli.conf", "stormshield_sns_cli.conf", "real"),
    ],
    "watchguard_fireware": [
        ("samples/watchguard/secure.xml", "watchguard_fireware_secure.xml", "synthetic"),
        ("samples/watchguard/official_example.xml", "watchguard_fireware_official.xml", "real"),
    ],
    "a10_acos": [
        ("samples/a10/secure.conf", "a10_acos_secure.conf", "synthetic"),
        ("samples/a10/insecure.conf", "a10_acos_insecure.conf", "synthetic"),
    ],
    "alcatel_aos": [
        ("samples/alcatel/secure.conf", "alcatel_aos_secure.conf", "synthetic"),
        ("samples/alcatel/insecure.conf", "alcatel_aos_insecure.conf", "synthetic"),
    ],
    "aws_security_group": [
        ("samples/aws_security_group/sample.json", "aws_security_group_sample.json", "synthetic"),
        ("samples/aws_security_group/insecure.json", "aws_security_group_insecure.json", "synthetic"),
    ],
    "azure_nsg": [
        ("samples/azure_nsg/sample.json", "azure_nsg_sample.json", "synthetic"),
        ("samples/azure_nsg/insecure.json", "azure_nsg_insecure.json", "synthetic"),
    ],
    "barracuda_cloudgen": [
        ("samples/barracuda/secure.conf", "barracuda_cloudgen_secure.conf", "synthetic"),
        ("samples/barracuda/insecure.conf", "barracuda_cloudgen_insecure.conf", "synthetic"),
    ],
    "cato_networks": [
        ("samples/cato/sample.json", "cato_networks_sample.json", "synthetic"),
        ("samples/cato/insecure.json", "cato_networks_insecure.json", "synthetic"),
    ],
    "cisco_asa": [
        ("samples/cisco_asa/secure.conf", "cisco_asa_secure.conf", "synthetic"),
        ("samples/cisco_asa/insecure.conf", "cisco_asa_insecure.conf", "synthetic"),
    ],
    "extreme_exos": [
        ("samples/extreme/secure.conf", "extreme_exos_secure.conf", "synthetic"),
        ("samples/extreme/insecure.conf", "extreme_exos_insecure.conf", "synthetic"),
    ],
    "f5_bigip_tmos": [
        ("samples/f5/secure.conf", "f5_bigip_tmos_secure.conf", "synthetic"),
        ("samples/f5/insecure.conf", "f5_bigip_tmos_insecure.conf", "synthetic"),
    ],
    "forcepoint_ngfw": [
        ("samples/forcepoint/secure.conf", "forcepoint_ngfw_secure.conf", "synthetic"),
        ("samples/forcepoint/insecure.conf", "forcepoint_ngfw_insecure.conf", "synthetic"),
    ],
    "hillstone_stoneos": [
        ("samples/hillstone/secure.conf", "hillstone_stoneos_secure.conf", "synthetic"),
        ("samples/hillstone/insecure.conf", "hillstone_stoneos_insecure.conf", "synthetic"),
    ],
    "hpe_aruba": [
        ("samples/hpe_aruba/secure.conf", "hpe_aruba_secure.conf", "synthetic"),
        ("samples/hpe_aruba/insecure.conf", "hpe_aruba_insecure.conf", "synthetic"),
    ],
    "hpe_aruba_aos_cx": [
        ("samples/hpe_aruba_aos_cx/secure.conf", "hpe_aruba_aos_cx_secure.conf", "synthetic"),
        ("samples/hpe_aruba_aos_cx/insecure.conf", "hpe_aruba_aos_cx_insecure.conf", "synthetic"),
        ("dataset/official_vendor_examples/hpe_aruba/aruba_aoscx_campus_sw01.conf", "aruba_aoscx_campus_sw01.conf", "real"),
    ],
    "netgate_pfsense": [
        ("samples/netgate_pfsense/sample.xml", "netgate_pfsense_sample.xml", "synthetic"),
        ("samples/netgate_pfsense/insecure.xml", "netgate_pfsense_insecure.xml", "synthetic"),
        ("dataset/lab_configuration/netgate_pfsense/netgate_pfsense_backup.xml", "netgate_pfsense_lab_backup.xml", "real"),
    ],
    "nokia_sros": [
        ("samples/nokia_sros/secure.conf", "nokia_sros_secure.conf", "synthetic"),
        ("samples/nokia_sros/insecure.conf", "nokia_sros_insecure.conf", "synthetic"),
        ("dataset/public_configuration/nokia/nokia_sros_7750.conf", "nokia_sros_7750.conf", "real"),
    ],
    "ruckus_fastiron": [
        ("samples/ruckus/secure.conf", "ruckus_fastiron_secure.conf", "synthetic"),
        ("samples/ruckus/insecure.conf", "ruckus_fastiron_insecure.conf", "synthetic"),
    ],
    "sangfor_ngaf": [
        ("samples/sangfor/secure.conf", "sangfor_ngaf_secure.conf", "synthetic"),
        ("samples/sangfor/insecure.conf", "sangfor_ngaf_insecure.conf", "synthetic"),
    ],
    "sophos_sfos": [
        ("samples/sophos/secure.conf", "sophos_sfos_secure.conf", "synthetic"),
        ("samples/sophos/insecure.conf", "sophos_sfos_insecure.conf", "synthetic"),
    ],
    "stormshield_sns": [
        ("dataset/official_vendor_examples/stormshield/stormshield_sns_cli.conf", "stormshield_sns_cli.conf", "real"),
    ],
    "ubiquiti_edgeos": [
        ("samples/ubiquiti/secure.conf", "ubiquiti_edgeos_secure.conf", "synthetic"),
        ("samples/ubiquiti/insecure.conf", "ubiquiti_edgeos_insecure.conf", "synthetic"),
        ("dataset/public_configuration/ubiquiti/ubiquiti_edgeos_router.conf", "ubiquiti_edgeos_router.conf", "real"),
    ],
    "versa_versos": [
        ("samples/versa/secure.conf", "versa_versos_secure.conf", "synthetic"),
        ("samples/versa/insecure.conf", "versa_versos_insecure.conf", "synthetic"),
    ],
    "zscaler_zia": [
        ("samples/zscaler_zia/sample.json", "zscaler_zia_sample.json", "synthetic"),
        ("samples/zscaler_zia/insecure.json", "zscaler_zia_insecure.json", "synthetic"),
    ],
    "zscaler_zpa": [
        ("samples/zscaler_zpa/sample.json", "zscaler_zpa_sample.json", "synthetic"),
        ("samples/zscaler_zpa/insecure.json", "zscaler_zpa_insecure.json", "synthetic"),
    ],
}


def load_or_sync_fixtures(base_dir: Path = Path(".")) -> Dict[str, int]:
    """Copy and sanitize fixtures to dataset/vendor_references/<vendor>/config_fixtures/."""
    dataset_base = base_dir / "dataset"
    vendor_ref_base = dataset_base / "vendor_references"
    counts = {}

    for vendor_key, fixture_list in FIXTURE_MAPPINGS.items():
        fix_dir = vendor_ref_base / vendor_key / "config_fixtures"
        fix_dir.mkdir(parents=True, exist_ok=True)
        count = 0

        for src_rel, dest_filename, provenance_type in fixture_list:
            src_path = base_dir / src_rel
            if src_path.exists():
                dest_path = fix_dir / dest_filename
                # Run secret sanitizer
                SecretSanitizer.sanitize_file(src_path, dest_path)
                count += 1

        counts[vendor_key] = count

    return counts
