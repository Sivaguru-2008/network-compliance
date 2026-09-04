import urllib.request
import urllib.parse
import re
import ssl
import json
import time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
}

def search_bing(query, max_results=10):
    url = 'https://www.bing.com/search?q=' + urllib.parse.quote(query)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            links = re.findall(r'<li class="b_algo">.*?<h2><a href="([^"]+)"', html, re.DOTALL)
            return links[:max_results]
    except Exception as e:
        print(f"Bing search error: {e}")
        return []

def search_yahoo(query, max_results=10):
    url = 'https://search.yahoo.com/search?p=' + urllib.parse.quote(query)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            links = re.findall(r'<a class="[^"]*algo-title[^"]*"[^>]*href="([^"]+)"', html)
            if not links:
                links = re.findall(r'<a\s+class="thmb[^"]*"[^>]*href="([^"]+)"', html)
            clean_links = []
            for l in links:
                if 'RU=' in l:
                    m = re.search(r'RU=([^/]+)/RK', l)
                    if m:
                        clean_links.append(urllib.parse.unquote(m.group(1)))
                elif l.startswith('http'):
                    clean_links.append(l)
            return clean_links[:max_results]
    except Exception as e:
        print(f"Yahoo search error: {e}")
        return []

if __name__ == '__main__':
    print("Testing Bing search:")
    res_bing = search_bing('site:github.com "router bgp" "interface Ethernet" "arista" "running-config"')
    print(f"Bing found {len(res_bing)}:")
    for r in res_bing:
        print(" ", r)
    
    print("\nTesting Yahoo search:")
    res_yahoo = search_yahoo('site:github.com "router bgp" "interface Ethernet" "arista" "running-config"')
    print(f"Yahoo found {len(res_yahoo)}:")
    for r in res_yahoo:
        print(" ", r)
