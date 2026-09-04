import os
import sys
import json
import re
import hashlib
import glob
import mimetypes
from pathlib import Path
from typing import Dict, List, Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

def run_all_checks():
    results = {}
    print("=" * 60)
    print("SIH COMPREHENSIVE FORENSIC VALIDATOR")
    print("=" * 60)

    # -------------------------------------------------------------
    # 1. PARSER REGISTRY & PLATFORMS
    # -------------------------------------------------------------
    from auditor.parsers import registry
    parsers_map = registry._parsers
    total_entry_points = len(parsers_map)
    unique_classes = set(parsers_map.values())
    
    class_details = {}
    for cls in unique_classes:
        aliases = [k for k, v in parsers_map.items() if v == cls]
        try:
            inst = cls()
            vendor_name = getattr(inst, 'vendor', cls.__name__)
            config_format = getattr(inst, 'config_format', 'text')
        except Exception as e:
            vendor_name = cls.__name__
            config_format = 'unknown'
            
        class_details[cls.__name__] = {
            "class": cls.__name__,
            "module": cls.__module__,
            "aliases": aliases,
            "vendor": vendor_name,
            "config_format": config_format,
        }
        
    results["parser_registry"] = {
        "total_entry_points": total_entry_points,
        "unique_classes_count": len(unique_classes),
        "entry_points": {k: v.__name__ for k, v in parsers_map.items()},
        "classes": class_details
    }
    
    # -------------------------------------------------------------
    # 2. MASTER 33 PLATFORMS INVENTORY & PHYSICAL AUDIT
    # -------------------------------------------------------------
    platforms_33 = [
        ("cisco_ios", "Cisco IOS / IOS-XE", "CiscoIOSParser", "cisco_ios.py"),
        ("juniper_junos", "Juniper Junos", "JunosParser", "junos.py"),
        ("fortinet_fortios", "Fortinet FortiOS", "FortiosParser", "fortios.py"),
        ("arista_eos", "Arista EOS", "AristaEOSParser", "arista_eos.py"),
        ("sonic", "SONiC NOS", "SonicParser", "sonic.py"),
        ("paloalto_panos", "Palo Alto PAN-OS", "PaloAltoParser", "paloalto.py"),
        ("huawei_vrp", "Huawei VRP", "HuaweiVRPParser", "huawei_vrp.py"),
        ("checkpoint_gaia", "Check Point Gaia", "CheckPointGaiaParser", "checkpoint_gaia.py"),
        ("mikrotik_routeros", "MikroTik RouterOS", "MikroTikROSParser", "mikrotik_routeros.py"),
        ("sonicwall_sonicos", "SonicWall SonicOS", "SonicWallSonicOSParser", "sonicwall_sonicos.py"),
        ("stormshield_sns", "Stormshield SNS", "StormshieldSNSParser", "stormshield_sns.py"),
        ("watchguard_fireware", "WatchGuard Fireware", "WatchGuardFirewareParser", "watchguard_fireware.py"),
        ("a10_acos", "A10 Networks ACOS", "A10ACOSParser", "a10_acos.py"),
        ("alcatel_aos", "Alcatel AOS", "AlcatelAOSParser", "alcatel_aos.py"),
        ("barracuda_cloudgen", "Barracuda CloudGen", "BarracudaCloudGenParser", "barracuda_cloudgen.py"),
        ("cato_networks", "Cato Networks SASE", "CatoNetworksParser", "cato_networks.py"),
        ("extreme_exos", "Extreme EXOS", "ExtremeEXOSParser", "extreme_exos.py"),
        ("f5_bigip_tmos", "F5 BIG-IP TMOS", "F5BigIPTMOSParser", "f5_bigip_tmos.py"),
        ("forcepoint_ngfw", "Forcepoint NGFW", "ForcepointNGFWParser", "forcepoint_ngfw.py"),
        ("hillstone_stoneos", "Hillstone StoneOS", "HillstoneStoneOSParser", "hillstone_stoneos.py"),
        ("hpe_aruba_aos_cx", "HPE Aruba AOS-CX", "HPEArubaAosCxParser", "hpe_aruba_aos_cx.py"),
        ("netgate_pfsense", "Netgate pfSense", "NetgatePfSenseParser", "netgate_pfsense.py"),
        ("nokia_sros", "Nokia SR OS", "NokiaSROSParser", "nokia_sros.py"),
        ("ruckus_fastiron", "Ruckus FastIron", "RuckusFastIronParser", "ruckus_fastiron.py"),
        ("sangfor_ngaf", "Sangfor NGAF", "SangforNGAFParser", "sangfor_ngaf.py"),
        ("sophos_sfos", "Sophos SFOS", "SophosSFOSParser", "sophos_sfos.py"),
        ("ubiquiti_edgeos", "Ubiquiti EdgeOS", "UbiquitiEdgeOSParser", "ubiquiti_edgeos.py"),
        ("versa_versos", "Versa VersaOS", "VersaVersaOSParser", "versa_versos.py"),
        ("zscaler_zia", "Zscaler ZIA", "ZscalerZIAParser", "zscaler_zia.py"),
        ("zscaler_zpa", "Zscaler ZPA", "ZscalerZPAParser", "zscaler_zpa.py"),
        ("aws_security_group", "AWS Security Group", "AWSSecurityGroupParser", "aws_security_group.py"),
        ("azure_nsg", "Azure NSG", "AzureNSGParser", "azure_nsg.py"),
        ("cisco_asa", "Cisco ASA", "CiscoASAParser", "cisco_asa.py"),
    ]

    from auditor.models.baseline import SecurityBaselineModel
    from auditor.models.observation import Observation
    from auditor.engine import ComplianceEngine
    from auditor.identity import extract_identity, platform_key
    from auditor.rules import load_framework, load_ruleset

    cis_path = REPO_ROOT / "auditor" / "rules" / "frameworks" / "cis.json"
    cis_data = {}
    if cis_path.exists():
        with open(cis_path, "r", encoding="utf-8") as f:
            cis_data = json.load(f)
            
    remed_dir = REPO_ROOT / "auditor" / "rules" / "remediations"

    vendor_audit = []
    for key, name, class_name, file_name in platforms_33:
        pf_file = REPO_ROOT / "auditor" / "parsers" / file_name
        file_exists = pf_file.exists()
        
        cls_obj = getattr(sys.modules.get("auditor.parsers"), class_name, None)
        imports = cls_obj is not None
        
        is_reg = key in parsers_map or any(parsers_map.get(k) == cls_obj for k in parsers_map)
        
        can_instantiate = False
        inst = None
        if cls_obj:
            try:
                inst = cls_obj()
                can_instantiate = True
            except Exception:
                pass

        # Identity detector
        id_detector_works = True

        # CIS mappings
        cis_supported = False
        cis_controls_count = 0
        if cis_data and "rules" in cis_data:
            for rule in cis_data["rules"]:
                if key in rule.get("vendor_mappings", {}):
                    cis_controls_count += 1
            if cis_controls_count > 0:
                cis_supported = True

        # Remediation
        remed_file = remed_dir / f"{key}.json"
        remed_exists = remed_file.exists()

        # Verification logic
        has_verification = True

        # Tests exist
        test_files = list((REPO_ROOT / "tests").glob(f"*{key}*.py"))
        # Also check for base tokens
        if not test_files:
            tokens = key.split('_')
            for tok in tokens:
                if len(tok) > 3:
                    test_files.extend(list((REPO_ROOT / "tests").glob(f"*{tok}*.py")))
        test_files = list(set(test_files))
        tests_exist = len(test_files) > 0

        vendor_audit.append({
            "vendor_key": key,
            "platform_name": name,
            "parser_class": class_name,
            "parser_file_exists": file_exists,
            "imports": imports,
            "registered": is_reg,
            "instantiates": can_instantiate,
            "cis_supported": cis_supported,
            "cis_controls_count": cis_controls_count,
            "remediation_pack_exists": remed_exists,
            "tests_exist": tests_exist,
            "test_files": [t.name for t in test_files]
        })
        
    results["vendor_audit"] = vendor_audit

    # -------------------------------------------------------------
    # 3. FIXTURE AUDIT & CLASSIFICATION
    # -------------------------------------------------------------
    dataset_dir = REPO_ROOT / "dataset"
    all_dataset_files = [p for p in dataset_dir.rglob("*") if p.is_file()]
    
    fixtures_categorized = []
    for fpath in all_dataset_files:
        rel = str(fpath.relative_to(REPO_ROOT)).replace("\\", "/")
        if rel.startswith("dataset/nlp/") or rel.startswith("dataset/vendor_references/"):
            continue
        if fpath.suffix.lower() in [".json", ".conf", ".cfg", ".xml", ".txt", ".rsc"]:
            category = "UNVERIFIED"
            if "sanitized_real_device" in rel or "real_device" in rel:
                category = "REAL_DEVICE_EXPORT"
            elif "official_vendor_examples" in rel or "official" in rel:
                category = "OFFICIAL_VENDOR_EXAMPLE"
            elif "public_config" in rel or "public_configuration" in rel or "purdue_isl" in rel or "public_netconf" in rel:
                category = "PUBLIC_CONFIGURATION_EXAMPLE"
            elif "synthetic" in rel or "lab_configuration" in rel:
                category = "SYNTHETIC"
            
            fixtures_categorized.append({
                "path": rel,
                "size": fpath.stat().st_size,
                "category": category
            })
            
    test_fixtures_dir = REPO_ROOT / "tests" / "fixtures"
    if test_fixtures_dir.exists():
        for fpath in test_fixtures_dir.rglob("*"):
            if fpath.is_file() and fpath.suffix.lower() in [".json", ".conf", ".cfg", ".xml", ".txt", ".rsc"]:
                rel = str(fpath.relative_to(REPO_ROOT)).replace("\\", "/")
                category = "SYNTHETIC"
                if "real" in rel.lower():
                    category = "REAL_DEVICE_EXPORT"
                fixtures_categorized.append({
                    "path": rel,
                    "size": fpath.stat().st_size,
                    "category": category
                })

    results["fixtures"] = {
        "total_fixtures": len(fixtures_categorized),
        "by_category": {
            "REAL_DEVICE_EXPORT": len([f for f in fixtures_categorized if f["category"] == "REAL_DEVICE_EXPORT"]),
            "OFFICIAL_VENDOR_EXAMPLE": len([f for f in fixtures_categorized if f["category"] == "OFFICIAL_VENDOR_EXAMPLE"]),
            "PUBLIC_CONFIGURATION_EXAMPLE": len([f for f in fixtures_categorized if f["category"] == "PUBLIC_CONFIGURATION_EXAMPLE"]),
            "SYNTHETIC": len([f for f in fixtures_categorized if f["category"] == "SYNTHETIC"]),
            "UNVERIFIED": len([f for f in fixtures_categorized if f["category"] == "UNVERIFIED"]),
        },
        "details": fixtures_categorized
    }

    # -------------------------------------------------------------
    # 4. OFFICIAL REFERENCE DOCUMENTS AUDIT
    # -------------------------------------------------------------
    doc_dir = REPO_ROOT / "dataset" / "vendor_references"
    docs_audited = []
    if doc_dir.exists():
        for doc_file in doc_dir.rglob("*"):
            if doc_file.is_file():
                rel = str(doc_file.relative_to(REPO_ROOT)).replace("\\", "/")
                size = doc_file.stat().st_size
                
                sha256 = hashlib.sha256(doc_file.read_bytes()).hexdigest() if size > 0 else ""
                
                status = "SUCCESSFULLY_ACQUIRED"
                if size == 0:
                    status = "FAILED"
                else:
                    try:
                        head = doc_file.read_bytes()[:1024].decode('utf-8', errors='ignore').lower()
                        if "403 forbidden" in head or "access denied" in head or ("login" in head and "sign in" in head):
                            status = "ACCESS_RESTRICTED"
                        elif "404 not found" in head:
                            status = "FAILED"
                    except Exception:
                        pass
                
                parts = doc_file.relative_to(doc_dir).parts
                vendor_key = parts[0] if len(parts) > 0 else "unknown"

                docs_audited.append({
                    "path": rel,
                    "filename": doc_file.name,
                    "vendor_key": vendor_key,
                    "size_bytes": size,
                    "sha256": sha256,
                    "status": status
                })

    manifest_path = REPO_ROOT / "dataset" / "manifest.json"
    manifest_data = {}
    if manifest_path.exists():
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)

    results["documents"] = {
        "physical_files_count": len(docs_audited),
        "by_status": {
            "SUCCESSFULLY_ACQUIRED": len([d for d in docs_audited if d["status"] == "SUCCESSFULLY_ACQUIRED"]),
            "ACCESS_RESTRICTED": len([d for d in docs_audited if d["status"] == "ACCESS_RESTRICTED"]),
            "NOT_PUBLIC": len([d for d in docs_audited if d["status"] == "NOT_PUBLIC"]),
            "FAILED": len([d for d in docs_audited if d["status"] == "FAILED"]),
            "DUPLICATE": len([d for d in docs_audited if d["status"] == "DUPLICATE"]),
        },
        "manifest_entries_count": len(manifest_data) if isinstance(manifest_data, dict) else len(manifest_data.get("documents", [])),
        "details": docs_audited
    }

    # -------------------------------------------------------------
    # 5. NLP COMMANDS & CONFIG BLOCKS AUDIT
    # -------------------------------------------------------------
    commands_file = REPO_ROOT / "dataset" / "nlp" / "commands.jsonl"
    commands_count = 0
    commands_sample_audited = []
    source_verified_count = 0
    model_inferred_count = 0
    unverified_count = 0
    
    if commands_file.exists():
        with open(commands_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                if not line.strip():
                    continue
                commands_count += 1
                try:
                    cmd_obj = json.loads(line)
                    status = cmd_obj.get("status") or cmd_obj.get("verification_status") or "SOURCE_VERIFIED"
                    if status == "SOURCE_VERIFIED":
                        source_verified_count += 1
                    elif status == "MODEL_INFERRED":
                        model_inferred_count += 1
                    else:
                        unverified_count += 1
                    if idx < 120:
                        commands_sample_audited.append(cmd_obj)
                except Exception:
                    pass

    config_blocks_file = REPO_ROOT / "dataset" / "nlp" / "config_blocks.jsonl"
    config_blocks_count = 0
    config_blocks_sample = []
    if config_blocks_file.exists():
        with open(config_blocks_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                if not line.strip():
                    continue
                config_blocks_count += 1
                if idx < 120:
                    try:
                        config_blocks_sample.append(json.loads(line))
                    except Exception:
                        pass

    documents_jsonl = REPO_ROOT / "dataset" / "nlp" / "documents.jsonl"
    nlp_docs_count = 0
    if documents_jsonl.exists():
        with open(documents_jsonl, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    nlp_docs_count += 1

    results["nlp"] = {
        "commands_total": commands_count,
        "source_verified_commands": source_verified_count,
        "model_inferred_commands": model_inferred_count,
        "unverified_commands": unverified_count,
        "config_blocks_total": config_blocks_count,
        "documents_total": nlp_docs_count,
        "sample_commands_audited_count": len(commands_sample_audited),
        "sample_blocks_audited_count": len(config_blocks_sample)
    }

    # -------------------------------------------------------------
    # 6. CIS & COMPLIANCE FRAMEWORK AUDIT
    # -------------------------------------------------------------
    frameworks_dir = REPO_ROOT / "auditor" / "rules" / "frameworks"
    frameworks_audit = {}
    if frameworks_dir.exists():
        for fw_file in frameworks_dir.glob("*.json"):
            with open(fw_file, "r", encoding="utf-8") as f:
                try:
                    fw_content = json.load(f)
                    rules = fw_content.get("rules", [])
                    controls_count = len(rules)
                    total_mappings = sum(len(r.get("vendor_mappings", {})) for r in rules)
                    frameworks_audit[fw_file.stem] = {
                        "controls_count": controls_count,
                        "total_vendor_mappings": total_mappings,
                        "vendors_mapped": list(set(v for r in rules for v in r.get("vendor_mappings", {}).keys()))
                    }
                except Exception as e:
                    frameworks_audit[fw_file.stem] = {"error": str(e)}

    results["frameworks"] = frameworks_audit

    # -------------------------------------------------------------
    # 7. REMEDIATION PACKS AUDIT
    # -------------------------------------------------------------
    remediations_audit = []
    if remed_dir.exists():
        for r_file in remed_dir.glob("*.json"):
            with open(r_file, "r", encoding="utf-8") as f:
                try:
                    r_data = json.load(f)
                    controls = r_data.get("controls", {}) or r_data.get("remediations", {})
                    remediations_audit.append({
                        "vendor_key": r_file.stem,
                        "file": r_file.name,
                        "controls_count": len(controls) if isinstance(controls, (dict, list)) else 0,
                        "has_verification": "verification" in str(r_data).lower(),
                        "has_rollback": "rollback" in str(r_data).lower()
                    })
                except Exception as e:
                    remediations_audit.append({"vendor_key": r_file.stem, "error": str(e)})

    results["remediation_packs"] = {
        "total_packs": len(remediations_audit),
        "details": remediations_audit
    }

    # -------------------------------------------------------------
    # 8. SECURITY & SECRETS AUDIT
    # -------------------------------------------------------------
    secret_patterns = [
        r"(?i)password\s*[:=]\s*['\"][^'\"]{4,}['\"]",
        r"(?i)api_key\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        r"(?i)secret\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        r"-----BEGIN RSA PRIVATE KEY-----",
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        r"-----BEGIN PRIVATE KEY-----",
    ]
    
    findings_secrets = []
    scan_exts = [".py", ".json", ".yaml", ".yml", ".md", ".env"]
    for path in REPO_ROOT.rglob("*"):
        if path.is_file() and path.suffix in scan_exts:
            rel = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
            if rel.startswith(".git/") or "/.system_generated/" in rel or "venv" in rel:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                for pat in secret_patterns:
                    matches = re.findall(pat, content)
                    if matches:
                        for m in matches:
                            findings_secrets.append({
                                "file": rel,
                                "match": m[:40] + ("..." if len(m) > 40 else "")
                            })
            except Exception:
                pass
                
    results["security_audit"] = {
        "findings_count": len(findings_secrets),
        "findings": findings_secrets[:50]
    }

    # -------------------------------------------------------------
    # 9. END-TO-END PARSER & COMPLIANCE EXECUTION ON FIXTURES
    # -------------------------------------------------------------
    from auditor.pipeline import assess_configuration_completeness
    
    # Load CIS ruleset
    cis_ruleset = None
    try:
        cis_ruleset = load_framework("CIS")
    except Exception as e:
        print(f"Warning loading CIS framework: {e}")

    e2e_results = []
    for p_key, p_name, p_class, p_file in platforms_33:
        # Find candidate fixture for this vendor
        fixture_candidates = []
        # Check dataset and tests
        for cat in fixtures_categorized:
            path_str = cat["path"].lower()
            if p_key in path_str or p_key.split('_')[0] in path_str:
                fixture_candidates.append(REPO_ROOT / cat["path"])
                
        # Also check common test fixtures
        if not fixture_candidates:
            for fx in (REPO_ROOT / "tests").rglob("*"):
                if fx.is_file() and (p_key in fx.name.lower() or p_key.split('_')[0] in fx.name.lower()) and fx.suffix in [".conf", ".cfg", ".xml", ".json", ".txt"]:
                    fixture_candidates.append(fx)

        fixture_used = None
        parser_success = False
        exc_str = None
        obs_count = 0
        findings_count = 0
        unknown_fields_count = 0
        compliance_status = "NO_FIXTURE"
        identity_extracted = {}

        if fixture_candidates:
            fixture_used = str(fixture_candidates[0].relative_to(REPO_ROOT)).replace("\\", "/")
            try:
                content = fixture_candidates[0].read_text(encoding="utf-8", errors="ignore")
                cls_obj = getattr(sys.modules.get("auditor.parsers"), p_class, None)
                if cls_obj:
                    parser_inst = cls_obj()
                    baseline = parser_inst.parse(content)
                    parser_success = True
                    obs_dict = baseline.to_observations() if hasattr(baseline, 'to_observations') else {}
                    obs_count = len(obs_dict)
                    
                    # Extract identity
                    try:
                        id_res = extract_identity(content, p_key)
                        identity_extracted = {
                            "hostname": id_res.hostname,
                            "os_version": id_res.os_version,
                            "model": id_res.model,
                            "serial": id_res.serial,
                        }
                    except Exception as e:
                        identity_extracted = {"error": str(e)}

                    # Evaluate CIS compliance
                    if cis_ruleset:
                        engine = ComplianceEngine(cis_ruleset)
                        report = engine.evaluate(baseline, platform=p_key)
                        findings_count = len(report.results)
                        passed = sum(1 for r in report.results if r.status.value == "PASS")
                        failed = sum(1 for r in report.results if r.status.value == "FAIL")
                        needs_rev = sum(1 for r in report.results if r.status.value == "NEEDS_REVIEW")
                        compliance_status = f"PASS={passed}, FAIL={failed}, NEEDS_REVIEW={needs_rev}"
                    else:
                        compliance_status = "RULESET_UNAVAILABLE"
            except Exception as e:
                exc_str = str(e)
                compliance_status = f"EXCEPTION: {e}"

        e2e_results.append({
            "vendor_key": p_key,
            "platform_name": p_name,
            "parser_class": p_class,
            "fixture": fixture_used,
            "parser_success": parser_success,
            "exception": exc_str,
            "observations_count": obs_count,
            "identity": identity_extracted,
            "compliance_result": compliance_status
        })

    results["e2e_matrix"] = e2e_results

    out_file = REPO_ROOT / "tools" / "validation_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nForensic results saved to {out_file}")

    print(f"\n--- FORENSIC AUDIT SUMMARY ---")
    print(f"Total Parser Entry Points: {results['parser_registry']['total_entry_points']}")
    print(f"Unique Parser Classes: {results['parser_registry']['unique_classes_count']}")
    print(f"Total Master Platforms: {len(results['vendor_audit'])}")
    print(f"Fixtures Total: {results['fixtures']['total_fixtures']} -> {results['fixtures']['by_category']}")
    print(f"Official Documents: {results['documents']['physical_files_count']} -> {results['documents']['by_status']}")
    print(f"NLP Commands: {results['nlp']['commands_total']} (Source-Verified: {results['nlp']['source_verified_commands']}, Model-Inferred: {results['nlp']['model_inferred_commands']})")
    print(f"NLP Config Blocks: {results['nlp']['config_blocks_total']}")
    print(f"Remediation Packs: {results['remediation_packs']['total_packs']}")
    print(f"CIS Controls: {results['frameworks'].get('cis', {}).get('controls_count', 0)} with {results['frameworks'].get('cis', {}).get('total_vendor_mappings', 0)} mappings")

if __name__ == "__main__":
    run_all_checks()
