import json
import hashlib
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

def inspect_all():
    print("=== 1. MANIFESTS ===")
    rw_path = PROJECT_ROOT / "dataset" / "real_world" / "manifest.json"
    rw_data = json.loads(rw_path.read_text(encoding="utf-8")) if rw_path.exists() else []
    print(f"dataset/real_world/manifest.json total entries: {len(rw_data)}")
    
    rw_real = [r for r in rw_data if (r.get("provenance_classification") or r.get("provenance_class")) == "REAL_PRODUCTION"]
    print(f"REAL_PRODUCTION entries in manifest: {len(rw_real)}")
    by_vendor_rw = {}
    for r in rw_real:
        v = r.get("vendor")
        by_vendor_rw[v] = by_vendor_rw.get(v, 0) + 1
    for v, c in sorted(by_vendor_rw.items()):
        print(f"  {v}: {c}")

    print("\n=== 2. ALL VENDOR VALIDATION V4 JSON ===")
    v4_path = PROJECT_ROOT / "reports" / "all_vendor_pipeline_validation_v4.json"
    if v4_path.exists():
        v4_data = json.loads(v4_path.read_text(encoding="utf-8"))
        results = v4_data.get("all_results", [])
        print(f"all_results total configs evaluated: {len(results)}")
        v4_real = [r for r in results if r.get("provenance") == "REAL_PRODUCTION"]
        print(f"all_results REAL_PRODUCTION configs: {len(v4_real)}")
        by_vendor_v4 = {}
        for r in v4_real:
            v = r.get("vendor_label")
            by_vendor_v4[v] = by_vendor_v4.get(v, 0) + 1
        for v, c in sorted(by_vendor_v4.items()):
            print(f"  {v}: {c}")
            
        print("\nChecking which REAL_PRODUCTION files in manifest were or were not in v4 all_results:")
        manifest_real_paths = {r["local_path"]: r for r in rw_real}
        v4_real_paths = {r["path"]: r for r in v4_real}
        
        print("Manifest real paths count:", len(manifest_real_paths))
        print("V4 real paths count:", len(v4_real_paths))
        for lp, r in sorted(manifest_real_paths.items()):
            full_p = str((PROJECT_ROOT / lp).resolve())
            matched = any(str(Path(vp).resolve()) == full_p for vp in v4_real_paths.keys())
            if not matched:
                print(f"  IN MANIFEST BUT NOT IN V4: {r.get('vendor')} | {r.get('filename')} | {lp}")

        print("\nVendor scorecard in v4:")
        sc = v4_data.get("vendor_scorecard", {})
        total_sc_real = 0
        for k, v in sorted(sc.items()):
            rc = v.get("real_count", 0)
            total_sc_real += rc
            if rc > 0:
                print(f"  {k}: real={rc} ref={v.get('reference_count')} syn={v.get('synthetic_count')}")
        print(f"Total real in scorecard: {total_sc_real}")

    print("\n=== 4. HARD NEGATIVES CHECK ===")
    from auditor.pipeline import select_parser
    from auditor.parsers.base import ParserError

    samples = [
        ("PROSE", "This is a standard network documentation guide explaining BGP."),
        ("SOURCE_CODE", "def configure_router():\n    return {'status': 'active'}"),
        ("JSON_LOGS", '{"timestamp": "2026-08-30", "level": "INFO", "msg": "link up"}'),
        ("MIXED_VENDOR", "router ospf 1\nset protocols bgp group test\nconfig system interface"),
        ("EMPTY_INPUT", "   \n\t  \n"),
        ("BINARY_DATA", "\x00\x01\x02\x03\x04\xff\xfe\xfd"),
    ]

    print("\n=== 5. COMPACT TRUTH TABLE ===")
    d = json.load(open("reports/final_validation_truth.json"))
    sc = d["vendor_scorecard"]
    print("| Vendor | Total | Real | Reference | Synthetic | Detection | Parser | Semantics | Evidence | Compliance | Remediation | Status |")
    print("|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|")
    for v, s in sorted(sc.items()):
        tot = s["total_configs"]
        real = s["real_count"]
        ref = s["reference_count"]
        syn = s["synthetic_count"]
        det = f"{s['detection_pass']}/{tot}"
        par = f"{s['parser_pass']}/{tot}"
        sem = f"{s['semantic_pass']}/{tot}"
        ev = f"{s['evidence_pass']}/{tot}"
        comp = f"{s['compliance_pass']}/{tot}"
        rem = f"{s['remediation_pass']}/{tot}"
        if real > 0:
            status = "VERIFIED_OPERATIONAL"
        elif ref > 0 and s['detection_pass'] > 0:
            status = "PUBLIC_REFERENCE_VERIFIED"
        elif s['detection_pass'] > 0:
            status = "SYNTHETIC_VERIFIED"
        else:
            status = "UNSUPPORTED_NATIVE_FORMAT"
        print(f"| {v:<25} | {tot:>2} | {real:>2} | {ref:>2} | {syn:>2} | {det:>5} | {par:>5} | {sem:>5} | {ev:>5} | {comp:>5} | {rem:>5} | {status} |")

if __name__ == "__main__":
    inspect_all()
