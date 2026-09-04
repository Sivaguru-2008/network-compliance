import os
import hashlib
import json

dataset_root = "d:/sih/dataset"

def get_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

categories = {
    "real_world": {},
    "public_reference": {},
    "synthetic_tests": {}
}

for cat in ["real_world", "public_reference", "synthetic_tests"]:
    cat_dir = os.path.join(dataset_root, cat)
    if not os.path.exists(cat_dir):
        continue
    for root, dirs, files in os.walk(cat_dir):
        for f in files:
            if f.startswith("metadata") or f == "manifest.json":
                continue
            full_path = os.path.join(root, f)
            rel_vendor = os.path.relpath(root, cat_dir)
            vendor = rel_vendor.split(os.sep)[0] if rel_vendor != "." else "root"
            sha = get_sha256(full_path)
            size = os.path.getsize(full_path)
            
            if vendor not in categories[cat]:
                categories[cat][vendor] = []
            
            categories[cat][vendor].append({
                "filename": f,
                "path": full_path,
                "relative_path": os.path.relpath(full_path, dataset_root),
                "sha256": sha,
                "size": size
            })

print("=== REAL_WORLD (REAL_PRODUCTION) ===")
total_real_files = 0
for v, fs in sorted(categories["real_world"].items()):
    print(f"Vendor: {v} ({len(fs)} files)")
    total_real_files += len(fs)
    for item in fs:
        print(f"  {item['filename']} | SHA256: {item['sha256'][:12]}... | {item['size']} bytes")
print(f"Total REAL_PRODUCTION Vendors: {len(categories['real_world'])}")
print(f"Total REAL_PRODUCTION Files: {total_real_files}")

print("\n=== PUBLIC_REFERENCE ===")
total_pub_files = 0
for v, fs in sorted(categories["public_reference"].items()):
    print(f"Vendor: {v} ({len(fs)} files)")
    total_pub_files += len(fs)
print(f"Total PUBLIC_REFERENCE Vendors: {len(categories['public_reference'])}")
print(f"Total PUBLIC_REFERENCE Files: {total_pub_files}")

print("\n=== SYNTHETIC_TESTS ===")
total_syn_files = 0
for v, fs in sorted(categories["synthetic_tests"].items()):
    print(f"Vendor: {v} ({len(fs)} files)")
    total_syn_files += len(fs)
print(f"Total SYNTHETIC_TESTS Vendors: {len(categories['synthetic_tests'])}")
print(f"Total SYNTHETIC_TESTS Files: {total_syn_files}")
