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

if __name__ == '__main__':
    pybat_files = get_tree('batfish/pybatfish')
    print(f"pybatfish blobs count: {len(pybat_files)}")
    cfg_files = [f for f in pybat_files if 'configs' in f or f.endswith(('.cfg', '.conf', '.xml', '.json', '.rsc'))]
    for c in cfg_files[:30]:
        print(" ", c)
