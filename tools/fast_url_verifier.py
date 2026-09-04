"""Concurrent URL verification script."""

import concurrent.futures
import hashlib
import json
from pathlib import Path
import ssl
import urllib.request

REPO_ROOT = Path(__file__).resolve().parent.parent

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def check_url(item):
    url = item.get("source_url", "")
    fn = item.get("filename")
    pk = item.get("platform_key")
    local_p = REPO_ROOT / item.get("local_path", "")
    
    local_content = ""
    if local_p.exists():
        local_content = local_p.read_text(encoding="utf-8", errors="ignore")
    local_sha = hashlib.sha256(local_content.encode("utf-8")).hexdigest() if local_content else "MISSING"

    result = {
        "platform_key": pk,
        "filename": fn,
        "source_url": url,
        "local_sha256": local_sha,
        "source_exists": False,
        "content_matches": False,
        "status": "UNKNOWN",
        "error": None
    }

    if not url or url.startswith("local://"):
        result["status"] = "LOCAL_REFERENCE"
        result["source_exists"] = local_p.exists()
        result["content_matches"] = True
        return result

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            data = resp.read()
            remote_sha = hashlib.sha256(data).hexdigest()
            # Try text decode
            try:
                remote_text = data.decode("utf-8")
                remote_text_norm = "\n".join(remote_text.splitlines())
                local_text_norm = "\n".join(local_content.splitlines())
                content_matches = (remote_sha == local_sha or remote_text_norm == local_text_norm)
            except Exception:
                content_matches = (remote_sha == local_sha)

            result["source_exists"] = True
            result["content_matches"] = content_matches
            result["remote_sha256"] = remote_sha
            result["status"] = "VERIFIED_ACCESSIBLE" if content_matches else "CONTENT_MISMATCH_OR_NORMALIZED"
    except Exception as e:
        result["status"] = "ACCESSIBILITY_FAILED"
        result["error"] = str(e)

    return result

def main():
    manifest = json.loads((REPO_ROOT / "dataset" / "real_world" / "manifest.json").read_text(encoding="utf-8"))
    print(f"Checking {len(manifest)} URLs concurrently...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(check_url, manifest))
    
    for r in results:
        print(f"[{r['platform_key']}] {r['filename']} -> {r['status']} | Match: {r['content_matches']} | URL: {r['source_url']}")
        if r['error']:
            print(f"   Error: {r['error']}")

    with open(REPO_ROOT / "reports" / "url_verification_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
