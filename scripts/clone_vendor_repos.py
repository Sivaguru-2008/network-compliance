import subprocess
import os
import shutil

repos_to_check = [
    ("batfish_main", "https://github.com/batfish/batfish.git", ["tests", "test_rigs"]),
    ("intentionet_netconan", "https://github.com/intentionet/netconan.git", []),
    ("napalm_panos", "https://github.com/napalm-automation-community/napalm-panos.git", []),
    ("napalm_fortios", "https://github.com/napalm-automation-community/napalm-fortios.git", []),
    ("napalm_ros", "https://github.com/napalm-automation-community/napalm-ros.git", []),
    ("napalm_eos", "https://github.com/napalm-automation-community/napalm-eos.git", []),
    ("napalm_sros", "https://github.com/napalm-automation-community/napalm-sros.git", []),
    ("napalm_extreme", "https://github.com/napalm-automation-community/napalm-exos.git", []),
    ("napalm_vyos", "https://github.com/napalm-automation-community/napalm-vyos.git", []),
    ("arista_avd", "https://github.com/aristanetworks/netdevops-examples.git", []),
    ("sonic_mgmt", "https://github.com/sonic-net/sonic-mgmt.git", ["ansible/roles/test/templates"]),
]

temp_dir = "d:/sih/temp_repos"
os.makedirs(temp_dir, exist_ok=True)

for name, url, sparse in repos_to_check:
    target = os.path.join(temp_dir, name)
    if not os.path.exists(target):
        print(f"Cloning {name} from {url}...")
        try:
            cmd = ["git", "clone", "--depth", "1", url, target]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0:
                print(f"Successfully cloned {name}")
            else:
                print(f"Failed to clone {name}: {res.stderr}")
        except Exception as e:
            print(f"Error cloning {name}: {e}")
    else:
        print(f"{name} already exists.")
