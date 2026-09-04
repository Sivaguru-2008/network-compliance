import os
import shutil

real_world_dir = "d:/sih/dataset/real_world"
public_ref_dir = "d:/sih/dataset/public_reference"
synthetic_dir = "d:/sih/dataset/synthetic_tests"

os.makedirs(public_ref_dir, exist_ok=True)
os.makedirs(synthetic_dir, exist_ok=True)

# List of files in cisco_ios and juniper_junos that are genuine REAL_PRODUCTION (Internet2 / Batfish operational network dataset)
real_production_whitelist = {
    "cisco_ios": [
        "bbra_rtr.cfg", "bbrb_rtr.cfg", "boza_rtr.cfg", "bozb_rtr.cfg",
        "coza_rtr.cfg", "cozb_rtr.cfg", "goza_rtr.cfg", "gozb_rtr.cfg",
        "poza_rtr.cfg", "pozb_rtr.cfg", "roza_rtr.cfg", "rozb_rtr.cfg",
        "soza_rtr.cfg", "sozb_rtr.cfg", "yoza_rtr.cfg", "yozb_rtr.cfg"
    ],
    "juniper_junos": [
        "atla.conf", "chic.conf", "clev.conf", "hous.conf", "kans.conf",
        "losa.conf", "newy32aoa.conf", "salt.conf", "seat.conf", "wash.conf"
    ]
}

# Scan real_world_dir and move any non-REAL_PRODUCTION file to public_reference
for vendor in os.listdir(real_world_dir):
    vendor_path = os.path.join(real_world_dir, vendor)
    if not os.path.isdir(vendor_path):
        continue
    
    # If duplicate folder like juniper or cisco_ios duplicate
    for fname in os.listdir(vendor_path):
        fpath = os.path.join(vendor_path, fname)
        if os.path.isdir(fpath):
            continue
        if fname.endswith(".json") and "metadata" in fname:
            continue
        
        is_real = False
        if vendor in real_production_whitelist and fname in real_production_whitelist[vendor]:
            is_real = True
        
        if not is_real:
            # Move to public_reference
            target_vendor_dir = os.path.join(public_ref_dir, vendor)
            os.makedirs(target_vendor_dir, exist_ok=True)
            target_file = os.path.join(target_vendor_dir, fname)
            print(f"Moving non-real artifact {fpath} -> {target_file}")
            shutil.move(fpath, target_file)

# Clean up empty or non-real directories in real_world
for vendor in os.listdir(real_world_dir):
    vendor_path = os.path.join(real_world_dir, vendor)
    if os.path.isdir(vendor_path):
        remaining_files = [f for f in os.listdir(vendor_path) if not f.startswith("metadata")]
        if not remaining_files:
            print(f"Removing empty/non-real directory: {vendor_path}")
            shutil.rmtree(vendor_path)

print("Reorganization complete.")
