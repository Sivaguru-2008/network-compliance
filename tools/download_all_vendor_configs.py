#!/usr/bin/env python3
"""
download_all_vendor_configs.py
High-performance, rate-limit friendly scraper and downloader for all network device vendor configs.
"""

import os
import sys
import json
import time
import re
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (SIH-Network-Compliance)"

def make_session(token=None):
    s = requests.Session()
    h = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    s.headers.update(h)
    retry = Retry(total=5, backoff_factor=1.5,
                  status_forcelist=(500, 502, 503, 504, 429),
                  allowed_methods=frozenset(["GET"]))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s

def sanitize_name(name):
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name)

def flat(path):
    return path.strip("/").replace("/", "__").replace("%20", "_").replace(" ", "_") or "root"

def matches(name, include):
    if include == ["*"] or not include:
        return True
    low = name.lower()
    return any(low.endswith(sfx.lower()) or sfx.lower() in low for sfx in include)

class ConfigDownloader:
    def __init__(self, sources_path, out_dir="configs", token=None, max_workers=20):
        self.sources_path = sources_path
        self.out_dir = out_dir
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.max_workers = max_workers
        self.session = make_session(self.token)
        self.tree_cache = {} # (repo, branch) -> list of blob paths

    def get_repo_tree(self, repo, branch):
        key = (repo, branch)
        if key in self.tree_cache:
            return self.tree_cache[key]
        
        print(f"[*] Fetching tree index for {repo} @ {branch}...")
        url = f"{API}/repos/{repo}/git/trees/{branch}?recursive=1"
        try:
            r = self.session.get(url, timeout=30)
            if r.status_code == 200:
                data = r.json()
                blobs = [node["path"] for node in data.get("tree", []) if node.get("type") == "blob"]
                self.tree_cache[key] = blobs
                print(f"    -> Found {len(blobs)} files in {repo}@{branch}")
                return blobs
            elif r.status_code == 403:
                print(f"    [!] Rate limit hit on GitHub API: {r.text[:100]}")
            else:
                print(f"    [!] Error fetching tree for {repo}: HTTP {r.status_code}")
        except Exception as e:
            print(f"    [!] Exception querying tree for {repo}: {e}")
        
        self.tree_cache[key] = []
        return []

    def download_single_file(self, repo, branch, path, dest):
        if os.path.exists(dest) and os.path.getsize(dest) > 0:
            return "skipped_exists", os.path.getsize(dest), path, dest
        
        url = f"{RAW}/{repo}/{branch}/{quote(path)}"
        try:
            r = self.session.get(url, timeout=30)
            if r.status_code == 404:
                return "not_found", 0, path, dest
            r.raise_for_status()
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(r.content)
            return "ok", len(r.content), path, dest
        except Exception as e:
            return f"error:{str(e)[:50]}", 0, path, dest

    def run(self):
        with open(self.sources_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        sources = cfg.get("sources", {})
        
        # Enrich and fix known batfish paths
        corrections = {
            "arista_eos": [
                {"repo":"batfish/batfish","branch":"master","mode":"dir","path":"projects/batfish/src/test/resources/org/batfish/vendor/arista/grammar/testconfigs","include":["*"],"kind":"fixtures","label":"batfish arista grammar"}
            ],
            "checkpoint_gaia": [
                {"repo":"batfish/batfish","branch":"master","mode":"dir","path":"projects/batfish/src/test/resources/org/batfish/vendor/check_point_gateway/grammar/testconfigs","include":["*"],"kind":"fixtures","label":"batfish check_point_gateway grammar"}
            ],
            "a10_acos": [
                {"repo":"batfish/batfish","branch":"master","mode":"dir","path":"projects/batfish/src/test/resources/org/batfish/vendor/a10/grammar/testconfigs","include":["*"],"kind":"fixtures","label":"batfish a10 grammar"}
            ],
            "cisco_asa": [
                {"repo":"batfish/batfish","branch":"master","mode":"dir","path":"projects/batfish/src/test/resources/org/batfish/grammar/cisco_asa/testconfigs","include":["*"],"kind":"fixtures","label":"batfish cisco_asa grammar"}
            ],
            "cisco_ios": [
                {"repo":"batfish/batfish","branch":"master","mode":"dir","path":"projects/batfish/src/test/resources/org/batfish/grammar/cisco_xr/testconfigs","include":["*"],"kind":"fixtures","label":"batfish cisco_xr grammar"},
                {"repo":"batfish/batfish","branch":"master","mode":"dir","path":"projects/batfish/src/test/resources/org/batfish/vendor/cisco_nxos/grammar/testconfigs","include":["*"],"kind":"fixtures","label":"batfish cisco_nxos grammar"}
            ],
            "nokia_sros": [
                {"repo":"batfish/batfish","branch":"master","mode":"dir","path":"projects/batfish/src/test/resources/org/batfish/vendor/sros/grammar/testconfigs","include":["*"],"kind":"fixtures","label":"batfish sros grammar"}
            ],
            "sonic": [
                {"repo":"batfish/batfish","branch":"master","mode":"dir","path":"projects/batfish/src/test/resources/org/batfish/grammar/cumulus_concatenated/testconfigs","include":["*"],"kind":"fixtures","label":"batfish cumulus concatenated configs"},
                {"repo":"batfish/batfish","branch":"master","mode":"dir","path":"projects/batfish/src/test/resources/org/batfish/grammar/cumulus_nclu/testconfigs","include":["*"],"kind":"fixtures","label":"batfish cumulus nclu configs"}
            ],
            "netgate_pfsense": [
                {"repo":"opnsense/core","branch":"master","mode":"file","files":["src/etc/config.xml.sample"],"kind":"full_config","label":"OPNsense/pfSense sample config.xml"}
            ]
        }

        for slug, extra_entries in corrections.items():
            if slug in sources:
                existing_entries = sources[slug].get("entries", [])
                # Filter out broken 404 paths
                clean_entries = [e for e in existing_entries if not (
                    "org/batfish/grammar/arista" in e.get("path", "") or
                    "org/batfish/grammar/check_point_gateway" in e.get("path", "") or
                    "org/batfish/grammar/a10" in e.get("path", "") or
                    "org/batfish/grammar/sonic" in e.get("path", "")
                )]
                clean_entries.extend(extra_entries)
                sources[slug]["entries"] = clean_entries

        # Collect download tasks per slug
        all_download_jobs = [] # list of (slug, repo, branch, path, dest, label)
        planned_per_slug = {}

        print("=== Resolving Targets Across All Vendors ===")
        for slug, spec in sources.items():
            entries = spec.get("entries", [])
            planned_per_slug[slug] = 0
            if not entries:
                continue

            for e in entries:
                repo = e["repo"]
                branch = e["branch"]
                mode = e.get("mode", "tree")
                label = e.get("label", "")
                include = e.get("include", ["*"])

                if mode == "file":
                    files = e.get("files", [])
                    for f_path in files:
                        fname = f_path.rsplit("/", 1)[-1]
                        dest = os.path.join(self.out_dir, slug, f"{sanitize_name(repo)}__{flat(os.path.dirname(f_path))}__{sanitize_name(fname)}")
                        all_download_jobs.append((slug, repo, branch, f_path, dest, label))
                        planned_per_slug[slug] += 1
                else:
                    # mode == dir or tree
                    dir_prefix = e.get("path", "").strip("/")
                    tree_blobs = self.get_repo_tree(repo, branch)
                    for blob_path in tree_blobs:
                        if dir_prefix:
                            if not (blob_path == dir_prefix or blob_path.startswith(dir_prefix + "/")):
                                continue
                        fname = blob_path.rsplit("/", 1)[-1]
                        if matches(fname, include):
                            dest = os.path.join(self.out_dir, slug, f"{sanitize_name(repo)}__{flat(os.path.dirname(blob_path))}__{sanitize_name(fname)}")
                            all_download_jobs.append((slug, repo, branch, blob_path, dest, label))
                            planned_per_slug[slug] += 1

        print(f"\n[+] Total files queued for download: {len(all_download_jobs)}")
        for slug, count in sorted(planned_per_slug.items(), key=lambda x: -x[1]):
            if count > 0:
                print(f"    - {slug:25}: {count:5} files")

        print("\n=== Starting Multithreaded Scraping & Download ===")
        results_per_slug = {slug: {"ok": 0, "bytes": 0, "skipped": 0, "errors": []} for slug in sources}
        total_downloaded = 0
        total_bytes = 0
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_job = {
                executor.submit(self.download_single_file, repo, branch, path, dest): (slug, repo, path, label)
                for (slug, repo, branch, path, dest, label) in all_download_jobs
            }

            completed = 0
            total = len(future_to_job)
            for future in as_completed(future_to_job):
                slug, repo, path, label = future_to_job[future]
                completed += 1
                try:
                    status, size, fpath, dest = future.result()
                    if status == "ok":
                        results_per_slug[slug]["ok"] += 1
                        results_per_slug[slug]["bytes"] += size
                        total_downloaded += 1
                        total_bytes += size
                    elif status == "skipped_exists":
                        results_per_slug[slug]["skipped"] += 1
                        results_per_slug[slug]["bytes"] += size
                        total_downloaded += 1
                        total_bytes += size
                    else:
                        results_per_slug[slug]["errors"].append({"file": path, "status": status})
                except Exception as exc:
                    results_per_slug[slug]["errors"].append({"file": path, "status": str(exc)})

                if completed % 100 == 0 or completed == total:
                    pct = (completed / total) * 100
                    print(f"    Progress: {completed}/{total} ({pct:.1f}%) | Downloaded: {total_downloaded} files ({(total_bytes / (1024*1024)):.2f} MB)")

        elapsed = time.time() - start_time
        print(f"\n=== Download Complete in {elapsed:.2f}s ===")
        print(f"Total files saved/verified: {total_downloaded}")
        print(f"Total data volume: {(total_bytes / (1024*1024)):.2f} MB")

        # Compile report
        report_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_files": total_downloaded,
                "total_bytes": total_bytes,
                "total_mb": round(total_bytes / (1024 * 1024), 2),
                "duration_seconds": round(elapsed, 2),
            },
            "per_slug": {}
        }

        for slug, res in sorted(results_per_slug.items()):
            cov = sources.get(slug, {}).get("coverage", "none")
            report_data["per_slug"][slug] = {
                "coverage": cov,
                "files_count": res["ok"] + res["skipped"],
                "bytes": res["bytes"],
                "errors_count": len(res["errors"]),
                "errors_sample": res["errors"][:5]
            }

        report_file = os.path.join(self.out_dir, "fetch-report.json")
        os.makedirs(self.out_dir, exist_ok=True)
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        print(f"\nSaved comprehensive fetch report to: {report_file}")
        return report_data

if __name__ == "__main__":
    sources_path = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\SIVAGURU R.M\Downloads\config-sources.json"
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "configs"
    downloader = ConfigDownloader(sources_path=sources_path, out_dir=out_dir, max_workers=24)
    downloader.run()
