"""Forensic investigation script for deep provenance audit."""

import hashlib
import json
import os
import re
from pathlib import Path
import urllib.request
import urllib.error

REPO_ROOT = Path(__file__).resolve().parent.parent

def sha256_of_file(path: Path) -> str:
    if not path.exists():
        return "MISSING"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def sha256_of_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

def inspect_manifest():
    manifest_path = REPO_ROOT / "dataset" / "real_world" / "manifest.json"
    if not manifest_path.exists():
        print("Manifest not found")
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    print(f"Total manifest entries: {len(manifest)}")
    
    target_keys = ['fortinet_fortios', 'paloalto_panos', 'f5_bigip_tmos', 'cisco_ios', 'juniper_junos',
                   'cato_networks', 'forcepoint_ngfw', 'sophos_sfos', 'zscaler_zia', 'zscaler_zpa', 'sangfor_ngaf']
    
    print("\n--- TARGET PLATFORMS IN REAL_WORLD MANIFEST ---")
    for item in manifest:
        pk = item.get('platform_key')
        if pk in target_keys:
            print(f"[{pk}] file: {item.get('filename')} | prov: {item.get('provenance_classification')} | org: {item.get('source_organization')} | url: {item.get('source_url')}")

if __name__ == "__main__":
    inspect_manifest()
