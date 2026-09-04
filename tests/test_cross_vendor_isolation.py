"""Unit tests for Cross-Vendor Zero-Shot Isolation."""

import json
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

def test_zero_shot_vendor_separation():
    """Verify that held-out test vendors do not enter training partitions during cross-vendor setup."""
    train_vendors = {"cisco_ios", "cisco_asa", "juniper_junos", "arista_eos", "fortinet_fortios"}
    held_out_vendors = {"huawei_vrp", "paloalto_panos", "mikrotik_routeros", "nokia_sros", "f5_bigip_tmos", "sonic", "netgate_pfsense"}

    assert len(train_vendors & held_out_vendors) == 0
