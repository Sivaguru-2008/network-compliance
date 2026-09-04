import urllib.request
import urllib.parse
import re
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def test_engines():
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    # Test DDG lite
    try:
        url = 'https://lite.duckduckgo.com/lite/'
        data = urllib.parse.urlencode({'q': 'site:github.com "router bgp" "interface Ethernet" "arista"'}).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            links = re.findall(r'href="([^"]+)"\s+class=\'result-link\'', html)
            print("DDG Lite results:", len(links))
            for l in links[:5]:
                print("  ", l)
    except Exception as e:
        print("DDG Lite err:", e)

    # Test GitHub raw scraping from known public network datasets
    test_urls = [
        'https://raw.githubusercontent.com/batfish/batfish/master/tests/parsing-tests/networks/srx-testbed/configs/as1border1.cfg',
        'https://raw.githubusercontent.com/batfish/pybatfish/master/jupyter_notebooks/networks/example/configs/as1border1.cfg',
        'https://raw.githubusercontent.com/batfish/batfish/master/tests/parsing-tests/networks/example-juniper/configs/as1border1.cfg',
        'https://raw.githubusercontent.com/batfish/batfish/master/tests/parsing-tests/networks/unit-tests/configs/arista_bgp.cfg',
        'https://raw.githubusercontent.com/batfish/batfish/master/tests/parsing-tests/networks/unit-tests/configs/cisco_asa.cfg'
    ]
    for u in test_urls:
        try:
            req = urllib.request.Request(u, headers=headers)
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                content = resp.read()
                print(f"URL: {u} -> Status: 200, Size: {len(content)} bytes")
        except Exception as e:
            print(f"URL: {u} -> Err: {e}")

if __name__ == '__main__':
    test_engines()
