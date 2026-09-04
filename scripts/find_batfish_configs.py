import os

base = "d:/sih/temp_repos/batfish_main"

found = []
for root, dirs, files in os.walk(base):
    for f in files:
        if any(f.endswith(ext) for ext in ['.cfg', '.conf', '.xml', '.json', '.rsc', '.boot']):
            p = os.path.join(root, f)
            rel = os.path.relpath(p, base)
            # ignore standard java build configs
            if any(ignore in rel for ignore in ['.git', 'pom.xml', '.idea', 'checkstyle', 'pmd', 'jmh']):
                continue
            found.append((rel, os.path.getsize(p)))

print(f"Total config files in batfish_main: {len(found)}")
for rel, sz in sorted(found):
    print(f"  {rel} ({sz} bytes)")
