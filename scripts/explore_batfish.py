import urllib.request
import json
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
headers = {'User-Agent': 'Mozilla/5.0'}

def get_tree(repo, branch='master'):
    url = f'https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1'
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return [x['path'] for x in data.get('tree', []) if x['type'] == 'blob']
    except Exception as e:
        print(f"Error fetching tree for {repo}: {e}")
        return []

pybat_files = get_tree('batfish/pybatfish')
bat_files = get_tree('batfish/batfish')

print(f"pybatfish blobs: {len(pybat_files)}")
print(f"batfish blobs: {len(bat_files)}")

def filter_configs(files):
    return [f for f in files if any(part in f for part in ['/configs/', 'test-configs', 'network', 'fixtures', 'examples']) and f.endswith(('.cfg', '.conf', '.xml', '.json', '.rsc', '.txt'))]

print("\n--- pybatfish configs ---")
for f in filter_configs(pybat_files):
    print(" ", f)

print("\n--- batfish configs (sample) ---")
bat_cfgs = filter_configs(bat_files)
print(f"Total in batfish: {len(bat_cfgs)}")
for f in bat_cfgs[:60]:
    print(" ", f)
