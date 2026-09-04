import os
import sys
import hashlib
import json
import urllib.request
import urllib.parse
import re
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
}

def fetch_url(url):
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            return resp.read()
    except Exception as e:
        # print(f"Fetch failed for {url}: {e}")
        return None

def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()

def sanitize_config(text):
    # Sanitize common passwords/secrets
    text = re.sub(r'password\s+[^\s]+', 'password [SANITIZED]', text, flags=re.IGNORECASE)
    text = re.sub(r'secret\s+[^\s]+', 'secret [SANITIZED]', text, flags=re.IGNORECASE)
    text = re.sub(r'pre-shared-key\s+[^\s]+', 'pre-shared-key [SANITIZED]', text, flags=re.IGNORECASE)
    text = re.sub(r'preshared-key\s+[^\s]+', 'preshared-key [SANITIZED]', text, flags=re.IGNORECASE)
    text = re.sub(r'community\s+[^\s]+', 'community [SANITIZED]', text, flags=re.IGNORECASE)
    text = re.sub(r'<password>[^<]+</password>', '<password>[SANITIZED]</password>', text, flags=re.IGNORECASE)
    return text

print("Search helper loaded.")
