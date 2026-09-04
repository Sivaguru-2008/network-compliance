import urllib.request
import json
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

headers = {'User-Agent': 'Mozilla/5.0'}

repos = [
    'batfish/batfish',
    'batfish/pybatfish',
    'Stanford-URI/CAMPUS-ROUTING',
    'stanford-futuredata/fptree',
    'snlab/floc',
    'nsg-ethz/snowcap',
    'alibaba/fast-forwarding',
    'netconan/netconan',
    'intentionet/netconan',
    'napalm-automation/napalm',
    'ansible-collections/arista.eos',
    'ansible-collections/cisco.asa',
    'ansible-collections/fortinet.fortios',
    'ansible-collections/paloaltonetworks.panos',
    'ansible-collections/check_point.mgmt',
    'ansible-collections/community.routeros',
    'ansible-collections/vyos.vyos',
    'sonic-net/sonic-buildimage',
    'sonic-net/sonic-mgmt',
    'pfsense/pfsense',
    'opnsense/core',
    'cloudnative-pg/cloudnative-pg'
]

for repo in repos:
    url = f'https://api.github.com/repos/{repo}'
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            print(f"Repo {repo}: default_branch={data.get('default_branch')}, stars={data.get('stargazers_count')}")
    except Exception as e:
        print(f"Repo {repo} error: {e}")
