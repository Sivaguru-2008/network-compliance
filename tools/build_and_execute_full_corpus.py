
import os
import sys
import json
import hashlib
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any, Optional

BASE_DIR = Path.cwd()
sys.path.insert(0, str(BASE_DIR))

from auditor.adapters import adapter_registry
from auditor.engine import ComplianceEngine
from auditor.models.baseline import SecurityBaselineModel
from auditor.training.real_device_dataset import ConfigSanitizer, SecurityConceptExtractor

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_text(t: str) -> str:
    return hashlib.sha256(t.encode('utf-8', errors='replace')).hexdigest()

def download(url: str, timeout: int = 20) -> Optional[bytes]:
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ConfigIQ-Research/2.0'}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return resp.read()
    except Exception as e:
        print(f'Download failed: {url} -> {e}')
    return None

print('Sanitizer & Engine ready.')
