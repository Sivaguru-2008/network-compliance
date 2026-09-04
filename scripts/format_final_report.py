import json

with open("d:/sih/dataset/manifest.json", "r", encoding="utf-8") as f:
    manifest = json.load(f)

print("=== REAL_PRODUCTION TABLE ===")
print("| Vendor | File | Source | Provenance Evidence | SHA256 |")
print("|---|---|---|---|---|")
for item in manifest["categories"]["REAL_PRODUCTION"]:
    print(f"| {item['vendor']} | {item['file']} | {item['source']} | {item['provenance']} | `{item['sha256']}` |")

print("\n=== PUBLIC_REFERENCE TABLE ===")
print("| Vendor | File | Source |")
print("|---|---|---|")
for item in manifest["categories"]["PUBLIC_REFERENCE"]:
    print(f"| {item['vendor']} | {item['file']} | {item['source']} |")

print("\n=== NO_PUBLIC_REAL_PRODUCTION_FOUND TABLE ===")
print("| Vendor | Searches Performed | Result |")
print("|---|---|---|")
for item in manifest["no_public_real_production_found"]:
    searches_str = "<br>".join([f"• {q}" for q in item["searches_performed"]])
    print(f"| {item['vendor']} | {searches_str} | {item['result']} |")
