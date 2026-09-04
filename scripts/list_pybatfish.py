import os

base = 'd:/sih/temp_repos/pybatfish'
configs = []
for root, dirs, files in os.walk(base):
    for f in files:
        if any(f.endswith(ext) for ext in ['.cfg', '.conf', '.xml', '.json', '.rsc', '.txt']):
            p = os.path.join(root, f)
            rel = os.path.relpath(p, base)
            if 'networks' in rel or 'tests' in rel or 'configs' in rel:
                configs.append((rel, os.path.getsize(p)))

print(f"Total relevant configs in pybatfish: {len(configs)}")
for rel, sz in sorted(configs):
    print(f"  {rel} ({sz} bytes)")
