
import urllib.request
import json
import os
import re

candidates = {
    'cisco_ios': [
        ('bbra_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/bbra_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone (NSDI 12/13)'),
        ('bbrb_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/bbrb_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('boza_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/boza_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('bozb_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/bozb_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('coza_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/coza_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('cozb_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/cozb_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('goza_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/goza_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('gozb_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/gozb_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('poza_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/poza_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('pozb_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/pozb_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('roza_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/roza_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('rozb_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/rozb_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('soza_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/soza_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('sozb_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/sozb_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('yoza_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/yoza_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
        ('yozb_rtr.cfg', 'https://raw.githubusercontent.com/cllorenz/hassel-reproduction/master/benchmarks/stanford_orig/yozb_rtr_config.txt', 'REAL_PRODUCTION', 'Stanford University Campus Backbone'),
    ],
    'juniper_junos': [
        ('atla.conf', 'https://raw.githubusercontent.com/nsg-ethz/config2spec/master/scenarios/internet2/configs/atla.conf', 'REAL_PRODUCTION', 'Internet2 Nationwide Backbone PoP Router (NSDI 20)'),
        ('chic.conf', 'https://raw.githubusercontent.com/nsg-ethz/config2spec/master/scenarios/internet2/configs/chic.conf', 'REAL_PRODUCTION', 'Internet2 Nationwide Backbone PoP Router'),
        ('clev.conf', 'https://raw.githubusercontent.com/nsg-ethz/config2spec/master/scenarios/internet2/configs/clev.conf', 'REAL_PRODUCTION', 'Internet2 Nationwide Backbone PoP Router'),
        ('hous.conf', 'https://raw.githubusercontent.com/nsg-ethz/config2spec/master/scenarios/internet2/configs/hous.conf', 'REAL_PRODUCTION', 'Internet2 Nationwide Backbone PoP Router'),
        ('kans.conf', 'https://raw.githubusercontent.com/nsg-ethz/config2spec/master/scenarios/internet2/configs/kans.conf', 'REAL_PRODUCTION', 'Internet2 Nationwide Backbone PoP Router'),
        ('losa.conf', 'https://raw.githubusercontent.com/nsg-ethz/config2spec/master/scenarios/internet2/configs/losa.conf', 'REAL_PRODUCTION', 'Internet2 Nationwide Backbone PoP Router'),
        ('newy32aoa.conf', 'https://raw.githubusercontent.com/nsg-ethz/config2spec/master/scenarios/internet2/configs/newy32aoa.conf', 'REAL_PRODUCTION', 'Internet2 Nationwide Backbone PoP Router'),
        ('salt.conf', 'https://raw.githubusercontent.com/nsg-ethz/config2spec/master/scenarios/internet2/configs/salt.conf', 'REAL_PRODUCTION', 'Internet2 Nationwide Backbone PoP Router'),
        ('seat.conf', 'https://raw.githubusercontent.com/nsg-ethz/config2spec/master/scenarios/internet2/configs/seat.conf', 'REAL_PRODUCTION', 'Internet2 Nationwide Backbone PoP Router'),
        ('wash.conf', 'https://raw.githubusercontent.com/nsg-ethz/config2spec/master/scenarios/internet2/configs/wash.conf', 'REAL_PRODUCTION', 'Internet2 Nationwide Backbone PoP Router'),
    ],
    'cisco_asa': [
        ('cisco_asa_vpn.cfg', 'https://raw.githubusercontent.com/Azure/Azure-vpn-config-samples/master/Cisco/ASA/Cisco-ASA-SampleConfig.txt', 'PUBLIC_REFERENCE', 'Azure VPN Gateway Reference Architecture for Cisco ASA'),
        ('cisco_asa_batfish.cfg', 'https://raw.githubusercontent.com/batfish/batfish/master/tests/java/org/batfish/grammar/cisco/testrigs/cisco_asa/configs/cisco_asa.cfg', 'PUBLIC_REFERENCE', 'Batfish Cisco ASA native grammar reference testbed'),
    ],
    'fortinet_fortios': [
        ('fortios_fgt_initial.conf', 'https://raw.githubusercontent.com/napalm-automation-community/napalm-fortios/develop/test/unit/fortios/initial.conf', 'PUBLIC_REFERENCE', 'NAPALM FortiOS driver full testbed export'),
        ('fortios_fgt_new.conf', 'https://raw.githubusercontent.com/napalm-automation-community/napalm-fortios/develop/test/unit/fortios/new_good.conf', 'PUBLIC_REFERENCE', 'NAPALM FortiOS updated security policy snapshot'),
        ('fortios_azure_vpn.conf', 'https://raw.githubusercontent.com/Azure/Azure-vpn-config-samples/master/Fortinet/FortiGate/Fortinet-FortiGate-SampleConfig.txt', 'PUBLIC_REFERENCE', 'Azure VPN Gateway Reference Architecture for Fortinet FortiGate'),
    ],
    'f5_bigip_tmos': [
        ('f5_bigip_initial.conf', 'https://raw.githubusercontent.com/napalm-automation-community/napalm-f5/master/test/unit/f5/initial.conf', 'PUBLIC_REFERENCE', 'NAPALM F5 TMOS driver full testbed export'),
        ('f5_bigip_new.conf', 'https://raw.githubusercontent.com/napalm-automation-community/napalm-f5/master/test/unit/f5/new_good.conf', 'PUBLIC_REFERENCE', 'NAPALM F5 TMOS updated virtual server & policy snapshot'),
    ],
    'paloalto_panos': [
        ('iron_skillet_panos_static.xml', 'https://raw.githubusercontent.com/PaloAltoNetworks/iron-skillet/panos_v10.1/loadable_configs/sample-mgmt-static/panos/iron_skillet_panos_full.xml', 'PUBLIC_REFERENCE', 'Palo Alto Networks IronSkillet Official Baseline Template'),
        ('iron_skillet_panos_aws.xml', 'https://raw.githubusercontent.com/PaloAltoNetworks/iron-skillet/panos_v10.1/loadable_configs/sample-cloud-AWS/panos/iron_skillet_panos_full.xml', 'PUBLIC_REFERENCE', 'Palo Alto Networks IronSkillet AWS Cloud Reference'),
        ('panos_napalm_running.xml', 'https://raw.githubusercontent.com/napalm-automation-community/napalm-panos/develop/test/unit/mocked_data/test_get_config/normal/running_config.xml', 'PUBLIC_REFERENCE', 'NAPALM PAN-OS PA-Series physical device export'),
    ],
    'arista_eos': [
        ('arista_avd_spine1.cfg', 'https://raw.githubusercontent.com/aristanetworks/ansible-avd/devel/ansible_collections/arista/avd/examples/campus-fabric/intended/configs/SPINE1.cfg', 'PUBLIC_REFERENCE', 'Arista Validated Design Campus Fabric Spine 1'),
        ('arista_avd_spine2.cfg', 'https://raw.githubusercontent.com/aristanetworks/ansible-avd/devel/ansible_collections/arista/avd/examples/campus-fabric/intended/configs/SPINE2.cfg', 'PUBLIC_REFERENCE', 'Arista Validated Design Campus Fabric Spine 2'),
        ('arista_avd_leaf1a.cfg', 'https://raw.githubusercontent.com/aristanetworks/ansible-avd/devel/ansible_collections/arista/avd/examples/campus-fabric/intended/configs/LEAF1A.cfg', 'PUBLIC_REFERENCE', 'Arista Validated Design Campus Fabric Leaf 1A'),
        ('arista_napalm_running.cfg', 'https://raw.githubusercontent.com/napalm-automation/napalm/develop/test/eos/mocked_data/test_get_config/normal/show_running_config.text', 'PUBLIC_REFERENCE', 'NAPALM EOS live testbed export'),
    ],
    'mikrotik_routeros': [
        ('routeros_base.rsc', 'https://raw.githubusercontent.com/floeff/routeros-configuration/main/03-base.rsc', 'PUBLIC_REFERENCE', 'MikroTik RouterOS production baseline export'),
        ('mikrotik_napalm.rsc', 'https://raw.githubusercontent.com/napalm-automation-community/napalm-ros/develop/test/unit/ros/show_running_config.text', 'PUBLIC_REFERENCE', 'NAPALM RouterOS testbed export'),
    ],
    'netgate_pfsense': [
        ('pfsense_backup_config.xml', 'https://raw.githubusercontent.com/pfsense/pfsense/master/src/etc/config.xml', 'PUBLIC_REFERENCE', 'Netgate pfSense official default/base configuration schema'),
        ('pfsense_bm_backup.xml', 'https://raw.githubusercontent.com/blogmotion/bm-backup-pfsense/master/config.sample.xml', 'PUBLIC_REFERENCE', 'pfSense community operational backup XML export'),
    ],
    'sonic': [
        ('sonic_config_db_spine.json', 'https://raw.githubusercontent.com/sonic-net/sonic-buildimage/master/dockers/docker-orchagent/sonic_config_db.json', 'PUBLIC_REFERENCE', 'SONiC NOS OCP official config_db.json schema & reference configuration'),
    ],
    'hpe_aruba': [
        ('hpe_procurve_napalm.cfg', 'https://raw.githubusercontent.com/napalm-automation-community/napalm-procurve/master/test/unit/procurve/show_running_config.text', 'PUBLIC_REFERENCE', 'NAPALM HPE Provision/ProCurve testbed running-config export'),
    ],
    'hpe_aruba_aos_cx': [
        ('aruba_aoscx_campus_sw01.conf', 'https://raw.githubusercontent.com/aruba/aoscx-ansible-collection/master/tests/unit/fixtures/show_running_config.txt', 'PUBLIC_REFERENCE', 'HPE Aruba AOS-CX campus switch running configuration reference'),
    ],
    'huawei_vrp': [
        ('huawei_vrp_napalm.cfg', 'https://raw.githubusercontent.com/napalm-automation-community/napalm-huawei-vrp/master/test/unit/huawei_vrp/show_current_configuration.text', 'PUBLIC_REFERENCE', 'NAPALM Huawei VRP operational display current-configuration export'),
    ],
    'nokia_sros': [
        ('nokia_sros_napalm.cfg', 'https://raw.githubusercontent.com/napalm-automation-community/napalm-sros/master/test/unit/sros/show_running_config.text', 'PUBLIC_REFERENCE', 'NAPALM Nokia SR OS admin display-config operational export'),
    ],
    'checkpoint_gaia': [
        ('checkpoint_gaia_napalm.cfg', 'https://raw.githubusercontent.com/napalm-automation-community/napalm-gaia/master/test/unit/gaia/show_configuration.text', 'PUBLIC_REFERENCE', 'NAPALM Check Point Gaia OS Clish configuration export'),
    ],
    'ubiquiti_edgeos': [
        ('ubiquiti_edgeos_config.boot', 'https://raw.githubusercontent.com/open-traffic-generator/snappi-tests/main/models/edgeos/config.boot', 'PUBLIC_REFERENCE', 'Ubiquiti EdgeOS / VyOS native tree config.boot export'),
    ],
}

headers = {'User-Agent': 'Mozilla/5.0'}
for vendor, items in candidates.items():
    print(f'=== Testing vendor: {vendor} ({len(items)} items) ===')
    for fname, url, pclass, desc in items:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                content = r.read().decode('utf-8', errors='ignore')
                print(f'  [OK] {fname}: {len(content)} bytes, {len(content.splitlines())} lines')
        except Exception as e:
            print(f'  [FAIL] {fname} ({url}): {e}')
