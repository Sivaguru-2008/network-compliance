import json

d = json.load(open('tools/forensic_audit_report.json'))
print("=== SECTION 3: VENDOR CAPABILITY MATRIX ===")
print(f"{'Vendor Key':22} | {'Parser Class':25} | {'Imp':4} | {'Reg':4} | {'Mod':4} | {'CIS':4} | {'Rem':4} | {'Tests':5}")
print("-" * 85)
for x in d['section_3_vendor_matrix']:
    print(f"{x['vendor_key']:22} | {x['parser_class']:25} | {str(x['imports']):4} | {str(x['registered']):4} | {str(x['produces_model']):4} | {x['cis_mappings_count']:4} | {str(x['remediation_pack']):4} | {str(x['has_tests']):5} ({x['test_files_count']})")

print("\n=== SECTION 4: E2E RESULTS ===")
print(f"{'Vendor Key':22} | {'Parser Success':14} | {'Obs':4} | {'Compliance Status'}")
print("-" * 75)
for x in d['section_4_e2e_results']:
    print(f"{x['vendor_key']:22} | {str(x['parser_success']):14} | {x['observations_count']:4} | {x['compliance_result']}")
