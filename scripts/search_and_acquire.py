import urllib.request
import urllib.parse
import re
import json
import ssl
import time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def ddg_search(query, max_results=10):
    url = 'https://html.duckduckgo.com/html/?q=' + urllib.parse.quote(query)
    req = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0'
    })
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            links = re.findall(r'href="//duckduckgo\.com/l/\?uddg=([^"&]+)', html)
            decoded = [urllib.parse.unquote(l) for l in links]
            return decoded[:max_results]
    except Exception as e:
        print(f"DDG Search error for '{query}': {e}")
        return []

def zenodo_search(query, max_results=5):
    url = 'https://zenodo.org/api/records?q=' + urllib.parse.quote(query) + '&size=' + str(max_results)
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            hits = data.get('hits', {}).get('hits', [])
            return [h.get('links', {}).get('self_html') for h in hits]
    except Exception as e:
        print(f"Zenodo error for '{query}': {e}")
        return []

if __name__ == '__main__':
    print("Testing DDG Search:")
    res = ddg_search('site:github.com "transceiver qsfp default-mode" "router bgp" arista')
    for r in res:
        print("  DDG link:", r)
    print("Testing Zenodo Search:")
    zres = zenodo_search('network configuration dataset')
    for z in zres:
        print("  Zenodo link:", z)
